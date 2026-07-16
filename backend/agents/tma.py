"""
Traffic Monitor Agent  (SDD §4.2 / SRS FR-01 to FR-04)
========================================================
Two detection modes, one output channel (alerts topic):

  VOLUME_SPIKE  — rolling pps deviates > ANOMALY_THRESHOLD sigma
  PORT_SCAN     — a single source IP hits > PORT_SCAN_THRESHOLD distinct
                  destination ports within PORT_SCAN_WINDOW seconds

Port-scan alerts carry two extra fields the ACA uses to distinguish
a real scanner from legitimate multi-service traffic:
  port_growth_rate  — unique ports / seconds_since_first_seen
  elapsed_scan_secs — how long TMA has been tracking this src IP

BDI roles
----------
Beliefs  : per-segment state, last alert time, port-hit tracker per src IP
Desires  : detect every anomaly; keep false-positive rate low
Intention: _on_sample() — re-evaluated on every new traffic sample
"""

from __future__ import annotations
import logging
import time
from collections import defaultdict
from enum import Enum

from core.messages import Performative, Topic
from core.models import TrafficSample
from bus.message_bus import MessageBus
from simulation.traffic import TrafficGenerator
from agents.base import BaseAgent

logger = logging.getLogger(__name__)

# ── volume detection ──────────────────────────────────────────────────
ANOMALY_THRESHOLD = 2.0
ALERT_COOLDOWN    = 5.0   # seconds before re-alerting same segment

# A ramp-phase alert often fires in the 2-3s band, which ACA's layer-1
# filter (correctly) treats as probable noise. If the deviation then blows
# past this threshold, waiting out the full cooldown would add ~5 s of
# detection latency per attack — so one escalation re-alert is allowed
# through the cooldown per window when the segment crosses this line.
ESCALATION_THRESHOLD = 4.0

# ── port-scan detection ───────────────────────────────────────────────
PORT_SCAN_WINDOW    = 10.0  # sliding window per src IP
PORT_SCAN_THRESHOLD = 3     # unique dst ports from one IP → alert
                            # (lower threshold, ACA decides the confidence)
PORT_SCAN_COOLDOWN  = 10.0  # seconds before re-alerting same scanner IP


class SegmentState(str, Enum):
    NORMAL  = "NORMAL"
    ANOMALY = "ANOMALY"


class TrafficMonitorAgent(BaseAgent):

    def __init__(
        self,
        agent_id:  str,
        bus:       MessageBus,
        generator: TrafficGenerator,
        segment_id: str | None = None,
    ) -> None:
        """
        segment_id=None (default) monitors every segment in one instance —
        this is what the validation suite always uses. The live server
        instead gives each network its own TMA (one instance per segment_id,
        see SimEngine.start()), so this filters _on_sample to just that
        segment; every other segment's traffic is ignored by this instance.
        """
        super().__init__(agent_id, bus)
        self._gen = generator
        self._segment_id = segment_id

        seg_ids = [segment_id] if segment_id else generator.topology.segment_ids()

        # BDI Beliefs: volume state per segment
        self._beliefs: dict[str, dict] = {
            sid: {
                "state":           SegmentState.NORMAL,
                "last_alert_time": 0.0,
                "alert_count":     0,
                "last_alert_dev":  0.0,   # |deviation| at the last alert
                "escalated":       False, # cooldown bypass already used
            }
            for sid in seg_ids
        }

        # BDI Beliefs: port tracker
        # Structure: { segment: { src_ip: { dst_port: last_seen_time } } }
        self._port_tracker: dict[str, dict[str, dict[int, float]]] = {
            sid: defaultdict(dict) for sid in seg_ids
        }
        # When each src_ip was first seen (for growth-rate computation)
        self._first_seen: dict[str, dict[str, float]] = {
            sid: {} for sid in seg_ids
        }
        # Cooldown per (segment, src_ip) pair
        self._scan_alerted: dict[tuple, float] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        await super().start()
        self._gen.on_sample(self._on_sample)
        logger.info("[%s] monitoring %d segment(s) (volume + port-scan)",
                    self.agent_id, len(self._beliefs))

    # ------------------------------------------------------------------
    # Main intention — called every 100 ms per segment
    # ------------------------------------------------------------------

    async def _on_sample(self, sample: TrafficSample) -> None:
        if not self._running:
            return
        if self._segment_id is not None and sample.segment != self._segment_id:
            return
        await self._check_volume(sample)
        await self._check_port_scan(sample)

    # ------------------------------------------------------------------
    # Detection mode 1: volume spike
    # ------------------------------------------------------------------

    async def _check_volume(self, sample: TrafficSample) -> None:
        stats  = self._gen.get_stats(sample.segment)
        belief = self._beliefs[sample.segment]
        now    = time.monotonic()

        is_anomaly  = abs(stats.deviation) >= ANOMALY_THRESHOLD
        cooldown_ok = (now - belief["last_alert_time"]) >= ALERT_COOLDOWN

        # Escalation re-alert: the last alert went out below the escalation
        # line and the deviation has since crossed it — the anomaly sharpened
        # mid-cooldown. One bypass per cooldown window.
        escalation = (
            is_anomaly
            and not cooldown_ok
            and not belief["escalated"]
            and abs(stats.deviation) >= ESCALATION_THRESHOLD
            and belief["last_alert_dev"] < ESCALATION_THRESHOLD
        )

        if is_anomaly and (cooldown_ok or escalation):
            belief["state"]           = SegmentState.ANOMALY
            belief["last_alert_time"] = now
            belief["alert_count"]    += 1
            belief["last_alert_dev"]  = abs(stats.deviation)
            belief["escalated"]       = escalation

            severity = min(1.0, (abs(stats.deviation) - ANOMALY_THRESHOLD)
                           / (10.0 - ANOMALY_THRESHOLD))

            await self.publish(
                topic        = Topic.ALERTS,
                performative = Performative.INFORM,
                content      = {
                    "segment":          sample.segment,
                    "anomaly_type":     "VOLUME_SPIKE",
                    "current_pps":      round(stats.current_pps,   2),
                    "baseline_mean":    round(stats.baseline_mean, 2),
                    "baseline_std":     round(stats.baseline_std,  2),
                    "deviation":        round(stats.deviation,     3),
                    "severity":         round(severity,            3),
                    "sample_count":     stats.sample_count,
                    "port_count":       0,
                    "port_growth_rate": 0.0,
                    "elapsed_scan_secs": 0.0,
                },
            )
            logger.info("[%s] VOLUME ALERT  segment=%-15s  dev=%+.1fs",
                        self.agent_id, sample.segment, stats.deviation)

        elif not is_anomaly:
            if belief["state"] == SegmentState.ANOMALY:
                logger.info("[%s] CLEAR  segment=%s",
                            self.agent_id, sample.segment)
            belief["state"]          = SegmentState.NORMAL
            belief["last_alert_dev"] = 0.0
            belief["escalated"]      = False

    # ------------------------------------------------------------------
    # Detection mode 2: port scan
    # ------------------------------------------------------------------

    async def _check_port_scan(self, sample: TrafficSample) -> None:
        now     = time.monotonic()
        seg     = sample.segment
        tracker = self._port_tracker[seg]
        first   = self._first_seen[seg]

        # Collect any packets the PortScanner deposited this tick
        for pkt in self._gen.drain_attack_packets(seg):
            if pkt.src_ip not in first:
                first[pkt.src_ip] = now
            tracker[pkt.src_ip][pkt.dst_port] = now

        # Expire entries outside the sliding window
        for src_ip in list(tracker.keys()):
            tracker[src_ip] = {
                p: t for p, t in tracker[src_ip].items()
                if now - t <= PORT_SCAN_WINDOW
            }
            if not tracker[src_ip]:
                del tracker[src_ip]
                first.pop(src_ip, None)

        # Check each active src IP for port diversity
        for src_ip, port_hits in tracker.items():
            if len(port_hits) < PORT_SCAN_THRESHOLD:
                continue

            key = (seg, src_ip)
            if now - self._scan_alerted.get(key, 0.0) < PORT_SCAN_COOLDOWN:
                continue

            self._scan_alerted[key] = now

            ports_hit    = sorted(port_hits.keys())
            elapsed      = max(0.01, now - first.get(src_ip, now))
            growth_rate  = round(len(ports_hit) / elapsed, 3)
            severity     = min(1.0, len(ports_hit) / 20.0)

            await self.publish(
                topic        = Topic.ALERTS,
                performative = Performative.INFORM,
                content      = {
                    "segment":           seg,
                    "anomaly_type":      "PORT_SCAN",
                    "src_ip":            src_ip,
                    "ports_scanned":     ports_hit,
                    "port_count":        len(ports_hit),
                    "port_growth_rate":  growth_rate,
                    "elapsed_scan_secs": round(elapsed, 2),
                    "severity":          round(severity, 3),
                    "deviation":         0.0,
                    "sample_count":      sample.packet_count,
                    "current_pps":       sample.packets_per_sec,
                    "baseline_mean":     0.0,
                    "baseline_std":      0.0,
                },
            )
            logger.info(
                "[%s] SCAN ALERT  seg=%-15s  src=%s  ports=%d  rate=%.1f/s",
                self.agent_id, seg, src_ip, len(ports_hit), growth_rate,
            )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def segment_states(self) -> dict[str, str]:
        return {sid: b["state"].value for sid, b in self._beliefs.items()}

    def total_alerts(self) -> int:
        return self._seq

    def alerts_for(self, segment_id: str) -> int:
        return self._beliefs[segment_id]["alert_count"]
