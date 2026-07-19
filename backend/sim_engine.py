"""
SimEngine: owns the MAS lifecycle — starts/stops all five agents, the
traffic generator and message bus, and handles scenario switching
(attack launch/stop, play/pause).
"""

from __future__ import annotations
import asyncio
import logging

from bus.message_bus import MessageBus
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner
from agents.tma import TrafficMonitorAgent, ANOMALY_THRESHOLD
from agents.aca import AnomalyClassifierAgent
from agents.rca import ResponseCoordinatorAgent
from agents.tia import ThreatIntelligenceAgent
from agents.raa import ResourceAllocatorAgent

from dashboard.state_collector import StateCollector
from dashboard.ui_metadata import AGENT_DEFS, SCENARIOS

logger = logging.getLogger(__name__)


class SimEngine:
    """
    Wraps the full MAS stack and handles scenario switching.
    One instance is created at startup and lives for the process lifetime.
    """

    def __init__(self):
        # Per-segment scenario state — segments are independent, so each
        # tracks its own attacker: two segments can be under different
        # attacks (or one attacked while another sits quarantined) at once.
        self.segment_scenarios: dict[str, str] = {}
        self.running  = True

        # Core MAS components (set in start())
        self.bus:  MessageBus | None      = None
        self.clock: SimClock | None       = None
        self.topo:  NetworkTopology | None = None
        self.gen:   TrafficGenerator | None = None
        self.tma_by_seg: dict[str, TrafficMonitorAgent] = {}   # one TMA per segment
        self.aca:   AnomalyClassifierAgent | None = None
        self.rca:   ResponseCoordinatorAgent | None = None
        self.tia:   ThreatIntelligenceAgent | None = None
        self.raa:   ResourceAllocatorAgent | None = None
        self.sc:    StateCollector = StateCollector()

        # Background asyncio tasks
        self._gen_task: asyncio.Task | None = None
        self._atk_tasks: dict[str, asyncio.Task] = {}   # segment_id -> attacker task

    async def start(self):
        """Initialise the MAS and start background tasks."""
        self.bus   = MessageBus()
        self.clock = SimClock()
        self.topo  = NetworkTopology()
        self.gen   = TrafficGenerator(self.topo, self.clock)
        self.sc.gen = self.gen
        self.segment_scenarios = {sid: "calm" for sid in self.topo.segment_ids()}
        await self.bus.start()

        # Agents — one TMA per segment (each only watches its own segment's
        # traffic; see agents/tma.py's segment_id filter). Every other agent
        # is a single process-wide instance.
        self.tma_by_seg = {
            sid: TrafficMonitorAgent(f"TMA:{sid}", self.bus, self.gen, segment_id=sid)
            for sid in self.topo.segment_ids()
        }
        self.aca = AnomalyClassifierAgent("ACA:1", self.bus)

        def _segment_is_normal(seg: str) -> bool:
            # Same live-traffic reading TMA itself alerts on (see
            # TrafficGenerator.quarantine() — the stats window keeps
            # recording real traffic even while blocked), just reused here
            # so RCA can poll a quarantined segment for early release.
            return abs(self.gen.get_stats(seg).deviation) < ANOMALY_THRESHOLD

        self.rca = ResponseCoordinatorAgent("RCA:1", self.bus, segment_is_normal=_segment_is_normal)
        self.tia = ThreatIntelligenceAgent("TIA:1", self.bus)
        self.raa = ResourceAllocatorAgent("RAA:1", self.bus)

        # Start agents
        for agent in [*self.tma_by_seg.values(), self.aca, self.rca, self.tia, self.raa]:
            await agent.start()

        # State collector observes the bus
        self.sc.init(
            list(self.topo.segment_ids()),
            [aid for aid, *_ in AGENT_DEFS],
        )
        self.sc.subscribe(self.bus)

        # Hook traffic samples → bandwidth history
        async def _bw_tap(sample):
            self.sc.record_bandwidth_sample(sample.segment, sample.packets_per_sec)

        self.gen.on_sample(_bw_tap)

        # Hook traffic samples → sampled real packet log
        async def _pkt_tap(sample):
            self.sc.sample_packets(sample.segment, self.gen)

        self.gen.on_sample(_pkt_tap)

        # Start traffic generator as a background task
        self._gen_task = asyncio.create_task(self.gen.run())

        logger.info("SimEngine started")

    async def stop(self):
        self._stop_all_attackers()
        if self.gen:
            self.gen.stop()
        if self._gen_task:
            self._gen_task.cancel()
        for agent in [*self.tma_by_seg.values(), self.aca, self.rca, self.tia, self.raa]:
            if agent:
                await agent.stop()
        if self.bus:
            await self.bus.stop()
        logger.info("SimEngine stopped")

    # ------------------------------------------------------------------
    # Scenario control
    # ------------------------------------------------------------------

    def _stop_attacker(self, segment_id: str) -> None:
        """Stop just this segment's attacker, leaving every other
        segment's attacker (and quarantine/incident state) untouched."""
        task = self._atk_tasks.pop(segment_id, None)
        if task:
            task.cancel()

    def _stop_all_attackers(self) -> None:
        for task in self._atk_tasks.values():
            task.cancel()
        self._atk_tasks.clear()

    def _launch_attacker(self, name: str, target: str) -> None:
        """Start the attacker for scenario `name` on `target` and open the
        detection grace window. Used by set_scenario() and resume()."""
        if name == "ddos":
            atk = DDoSAttacker(
                f"DDoS:{target}", target, self.gen,
                intensity_multiplier=6.0, ramp_seconds=3.0,
            )
            self._atk_tasks[target] = asyncio.create_task(atk.launch(duration=3600))
            self.sc.record_attack_start(target, "DDOS")
        elif name == "scan":
            scanner = PortScanner(
                f"Scan:{target}", target, self.gen,
                src_ip="45.33.32.156", probe_interval=0.3,
            )
            self._atk_tasks[target] = asyncio.create_task(scanner.launch(duration=3600))
            self.sc.record_attack_start(target, "PORT_SCAN")

    async def set_scenario(self, name: str, segment: str | None = None):
        """Set the scenario for ONE segment (falls back to a sensible
        default target per scenario if `segment` is missing or not a real
        segment id). Segments are independent — this never stops or resets
        any other segment's attacker, quarantine, or incidents, so multiple
        segments can be under different attacks (or quarantined) at once."""
        if name not in SCENARIOS:
            name = "calm"

        valid_segments = self.gen.topology.segment_ids()
        default_target = "public-facing" if name != "scan" else "server"
        target = segment if segment in valid_segments else default_target

        self._stop_attacker(target)
        self.sc.reset_segment(target)
        self.segment_scenarios[target] = name

        # Whatever was running on this segment (if anything) ends now —
        # starts the CALM_LINGER_SECS window for FP accounting.
        self.sc.record_attack_end(target)

        if name in ("ddos", "scan"):
            self._launch_attacker(name, target)

    # ------------------------------------------------------------------
    # Play / pause
    # ------------------------------------------------------------------

    async def pause(self) -> None:
        """Freeze the simulation: stop traffic + attackers and the session
        clock, but keep every segment's scenario, quarantine and incident
        state intact so resume() continues the same session."""
        if not self.running:
            return
        self.running = False
        # Attacker tasks are cancelled (their finally-blocks clear the pps
        # overlays); segment_scenarios remembers what to relaunch on resume.
        self._stop_all_attackers()
        if self.gen:
            self.gen.stop()
        if self._gen_task:
            self._gen_task.cancel()
            self._gen_task = None
        self.sc.pause_clock()
        logger.info("SimEngine paused")

    async def resume(self) -> None:
        if self.running:
            return
        self.running = True
        self.sc.resume_clock()
        if self.gen:
            self._gen_task = asyncio.create_task(self.gen.run())
        # Relaunch each segment's attacker. _launch_attacker() refreshes
        # attack_started so the re-ramp after resume gets a fresh grace
        # window instead of being scored as missed detections.
        for seg, name in self.segment_scenarios.items():
            if name in ("ddos", "scan"):
                self._launch_attacker(name, seg)
        logger.info("SimEngine resumed")

    def snapshot(self) -> dict:
        return self.sc.snapshot(self.gen, self.segment_scenarios, self.running)
