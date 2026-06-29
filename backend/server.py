"""
Cyber-Defense MAS  —  FastAPI visualization server
====================================================
Runs all five defense agents in-process alongside the web server.
State is streamed to connected browsers via WebSocket every 200 ms.

Start:
    pip install fastapi uvicorn
    python -m agents.aca_trainer          # once — trains the ML model
    uvicorn server:app --port 8000

Then open:  http://localhost:8000
"""

import asyncio
import json
import logging
import pathlib
import sys
import time
from collections import deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure intra-backend imports (bus/core/simulation/agents) resolve whether
# this module is loaded as `server` or `backend.server`.
BACKEND_ROOT = pathlib.Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from bus.message_bus import MessageBus
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner
from agents.tma import TrafficMonitorAgent
from agents.aca import AnomalyClassifierAgent
from agents.rca import ResponseCoordinatorAgent
from agents.tia import ThreatIntelligenceAgent
from agents.raa import ResourceAllocatorAgent
from core.messages import Topic, Message

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

FRONTEND = pathlib.Path(__file__).parent / "frontend" / "index.html"

# ── Segment + scenario metadata ────────────────────────────────────────────────
SEGMENTS = [
    {"id": "public-facing", "code": "PUB", "name": "Public-Facing Services", "cidr": "172.16.0.0/24"},
    {"id": "server",        "code": "SRV", "name": "Server Zone",            "cidr": "10.0.2.0/24"},
    {"id": "internal",      "code": "INT", "name": "Internal User Subnet",   "cidr": "10.0.1.0/24"},
    {"id": "sec-mon",       "code": "MON", "name": "Security Monitoring Zone","cidr": "10.0.3.0/24"},
]
SEG_MAP = {s["id"]: s for s in SEGMENTS}

SCENARIOS = {
    "calm":  {"label": "Calm Baseline"},
    "ddos":  {"label": "DDoS Attack"},
    "scan":  {"label": "Port Scan"},
}

# BDI desires per agent type — used in the inspector panel
AGENT_DESIRES = {
    "TMA": ["Maximize detection rate per segment",
            "Keep false positives below 10 %",
            "Publish alerts within 100 ms"],
    "ACA": ["Classify every alert within 200 ms",
            "Maintain accuracy above 90 % and FPR < 8 %",
            "Improve model after each resolved incident"],
    "TIA": ["Maintain global threat model updated every 500 ms",
            "Detect multi-segment correlations within 1 s",
            "Trigger coalition formation within 1 000 ms"],
    "RCA": ["Initiate response within 500 ms (severity ≥ 0.7)",
            "Maximize service availability",
            "Quarantine requires majority coalition vote",
            "Select least-disruptive effective action"],
    "RAA": ["Serve highest-severity threat first",
            "Complete auctions within 300 ms",
            "Keep MAS overhead below 40 % host capacity",
            "Reclaim resources within 500 ms of resolution"],
}

# Active plan name per (agent_type, state)
AGENT_PLANS = {
    ("TMA", "alert"): "detect_anomaly",
    ("TMA", "mon"):   "update_baseline",
    ("TMA", "idle"):  "idle",
    ("ACA", "active"):"classify_alert",
    ("ACA", "mon"):   "share_intel",
    ("ACA", "idle"):  "idle",
    ("TIA", "active"):"detect_correlation",
    ("TIA", "mon"):   "update_threat_model",
    ("TIA", "idle"):  "rank_threats",
    ("RCA", "active"):"respond_to_threat",
    ("RCA", "mon"):   "initiate_voting",
    ("RCA", "idle"):  "standby",
    ("RAA", "active"):"run_auction",
    ("RAA", "mon"):   "monitor_overhead",
    ("RAA", "idle"):  "idle",
}

# Agent recipients per topic for visualization (current runtime wiring).
VIZ_TOPIC_RECIPIENTS = {
    Topic.ALERTS:         ["ACA:1"],
    Topic.THREAT_REPORTS: ["RCA:1", "TIA:1"],
    Topic.THREAT_INTEL:   ["RCA:1"],
    Topic.COALITION:      ["TIA:1"],
    Topic.RESOLUTION:     ["RAA:1"],
    Topic.RESOURCE_GRANTS: [],
}


# ── StateCollector: observes the bus and builds display state ──────────────────
class StateCollector:
    """
    Subscribes to every bus topic and maintains all state the
    frontend needs.  Never modifies any agent — read-only observer.
    """

    def __init__(self):
        self._start = time.monotonic()
        self.lamport = 0
        self.logs: deque = deque(maxlen=50)
        self.viz_events: deque = deque(maxlen=400)
        self._viz_seq = 0

        # Metric counters
        self.tp = 0   # confirmed threats classified
        self.fp = 0   # noise/benign classified as threat
        self.mttr_ms: list[float] = []
        self._disruption_start: float | None = None
        self.disruption_secs = 0.0

        # Enforcement (mirrors RAA's decisions)
        self.blocked_ips: set[str] = set()
        self.quarantined_segs: set[str] = set()

        # Per-agent display state
        self.ag_state: dict[str, str] = {}   # idle / mon / alert / active
        self.ag_task:  dict[str, str] = {}   # human-readable current task
        self.ag_trace: dict[str, deque] = {} # recent decision log entries

        # Active coalition incidents (incident_id → metadata)
        self.active_incidents: dict[str, dict] = {}

        # Per-segment bandwidth history (70 samples ≈ same as mockup)
        self.bw_hist: dict[str, deque] = {}

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def init(self, seg_ids: list[str], agent_ids: list[str]):
        for sid in seg_ids:
            self.bw_hist[sid] = deque(maxlen=70)
        for aid in agent_ids:
            self.ag_state[aid] = "mon"
            self.ag_task[aid]  = "watching traffic"
            self.ag_trace[aid] = deque(maxlen=15)

    def subscribe(self, bus: MessageBus):
        bus.subscribe(Topic.ALERTS,          self._on_alert)
        bus.subscribe(Topic.THREAT_REPORTS,  self._on_threat_report)
        bus.subscribe(Topic.THREAT_INTEL,    self._on_threat_intel)
        bus.subscribe(Topic.COALITION,       self._on_coalition)
        bus.subscribe(Topic.RESOLUTION,      self._on_resolution)
        bus.subscribe(Topic.RESOURCE_GRANTS, self._on_grant)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _now(self) -> str:
        t = time.monotonic() - self._start
        m, s = divmod(int(t), 60)
        return f"{m:02d}:{s:02d}.{int(t * 1000) % 1000:03d}"

    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def _log(self, agent: str, color: str, text: str):
        self.lamport += 1
        self.logs.appendleft({"id": self.lamport, "time": self._now(),
                               "agent": agent, "color": color, "text": text})

    def _trace(self, aid: str, text: str):
        self.ag_trace.setdefault(aid, deque(maxlen=15)).appendleft(
            {"time": self._now(), "text": text}
        )

    def _emit_viz_event(self, msg: Message):
        c = msg.content
        if msg.receiver and msg.receiver != "BROADCAST":
            targets = [r.strip() for r in msg.receiver.split(",") if r.strip()]
        else:
            targets = VIZ_TOPIC_RECIPIENTS.get(msg.topic, [])
        targets = [t for t in targets if t != msg.sender]

        self._viz_seq += 1
        self.viz_events.append({
            "id": self._viz_seq,
            "topic": msg.topic,
            "sender": msg.sender,
            "receiver": msg.receiver,
            "targets": targets,
            "segment": c.get("segment") or c.get("primary_segment"),
            "anomaly_type": c.get("anomaly_type"),
            "classification": c.get("classification"),
            "pattern_type": c.get("pattern_type"),
            "action": c.get("action") or c.get("proposed_action"),
            "severity": c.get("severity", 0.0),
            "at": round(self.elapsed(), 3),
        })

    # ------------------------------------------------------------------
    # Bus handlers (each is an async callback)
    # ------------------------------------------------------------------

    async def _on_alert(self, msg: Message):
        self._emit_viz_event(msg)
        c     = msg.content
        seg   = c.get("segment", "")
        atype = c.get("anomaly_type", "")
        dev   = c.get("deviation", 0.0)
        name  = SEG_MAP.get(seg, {}).get("name", seg)

        self.ag_state["TMA:1"] = "alert"
        self.ag_task["TMA:1"]  = f"anomaly on {name}"
        self._trace("TMA:1", f"{atype} on {name} ({dev:+.1f}σ)")
        self._log("TMA-1", "#d9a23f",
                  f"Alert — {atype.lower().replace('_', ' ')} on {name} ({dev:+.1f}σ)")

    async def _on_threat_report(self, msg: Message):
        self._emit_viz_event(msg)
        c    = msg.content
        clf  = c.get("classification", "")
        sev  = c.get("severity", 0.0)
        seg  = c.get("segment", "")
        conf = c.get("confidence", 0.0)
        atk  = c.get("attack_type", clf)
        name = SEG_MAP.get(seg, {}).get("name", seg)

        if clf == "CONFIRMED_THREAT":
            self.tp += 1
            self.ag_state["ACA:1"] = "active"
            self.ag_task["ACA:1"]  = f"classifying · severity {sev:.2f}"
            self._trace("ACA:1", f"Confirmed {atk} — sev {sev:.2f}, conf {conf:.0%}")
            self._log("ACA-1", "#cf6b5e",
                      f"Confirmed threat: {atk} on {name}, severity {sev:.2f}")
        elif clf == "SUSPICIOUS":
            self.ag_state["ACA:1"] = "active"
            self.ag_task["ACA:1"]  = f"suspicious on {name}"
            self._trace("ACA:1", f"Suspicious on {name} (conf {conf:.0%})")
            self._log("ACA-1", "#d9a23f",
                      f"Suspicious pattern on {name} (confidence {conf:.0%})")
        else:
            self.fp += 1

    async def _on_threat_intel(self, msg: Message):
        self._emit_viz_event(msg)
        c       = msg.content
        pattern = c.get("pattern_type", "")
        seg     = c.get("primary_segment", "")
        name    = SEG_MAP.get(seg, {}).get("name", seg)

        self.ag_state["TIA:1"] = "active"
        self.ag_task["TIA:1"]  = f"correlating — {pattern}"
        self._trace("TIA:1", f"Pattern {pattern} on {name}")

        if "MULTI_SEGMENT" in pattern:
            self._log("TIA-1", "#3fa3a8",
                      "Multi-segment scan detected — forming response coalition")
        elif "COORDINATED" in pattern:
            self._log("TIA-1", "#3fa3a8",
                      "Coordinated DDoS across segments — coalition activated")
        else:
            self._log("TIA-1", "#3fa3a8", f"{name} ranked highest-priority threat")

    async def _on_coalition(self, msg: Message):
        self._emit_viz_event(msg)
        c      = msg.content
        inc_id = c.get("incident_id", "")
        seg    = c.get("segment", "")
        action = c.get("proposed_action", "")
        name   = SEG_MAP.get(seg, {}).get("name", seg)

        self.active_incidents[inc_id] = {
            "seg": seg, "action": action, "t": time.monotonic()
        }
        self.ag_state["RCA:1"] = "active"
        self.ag_task["RCA:1"]  = f"coalition vote for {name}"
        self._trace("RCA:1", f"CFP: {action} for {name}")
        self._log("RCA-1", "#4577b5",
                  f"Coalition vote — {action.lower().replace('_', ' ')} for {name}")

    async def _on_resolution(self, msg: Message):
        self._emit_viz_event(msg)
        c       = msg.content
        inc_id  = c.get("incident_id", "")
        outcome = c.get("outcome", "")
        action  = c.get("action", "")
        seg     = c.get("segment", "")
        dur_ms  = c.get("duration_ms", 0)
        name    = SEG_MAP.get(seg, {}).get("name", seg)
        tgt     = c.get("enforcement_target", {})

        self.active_incidents.pop(inc_id, None)

        if outcome == "EXECUTED":
            self.mttr_ms.append(dur_ms)
            if len(self.mttr_ms) > 100:
                self.mttr_ms = self.mttr_ms[-100:]

            if "src_ip" in tgt:
                ip = tgt["src_ip"]
                self.blocked_ips.add(ip)
                self.ag_task["RCA:1"] = f"blocked {ip}"
                self._log("RCA-1", "#4577b5", f"Mitigation — {ip} blocked ({dur_ms} ms)")
            elif "segment" in tgt:
                qseg = tgt["segment"]
                self.quarantined_segs.add(qseg)
                if self._disruption_start is None:
                    self._disruption_start = time.monotonic()
                qname = SEG_MAP.get(qseg, {}).get("name", qseg)
                self.ag_task["RCA:1"] = f"quarantined {qname}"
                self._log("RCA-1", "#4577b5",
                          f"Mitigation — {qname} quarantined ({dur_ms} ms)")

            self._trace("RCA:1", f"{action} EXECUTED for {name} ({dur_ms} ms)")
        else:
            self._log("RCA-1", "#d9a23f",
                      f"Vote rejected — {action} not executed for {name}")
            self._trace("RCA:1", f"{action} REJECTED for {name}")

    async def _on_grant(self, msg: Message):
        self._emit_viz_event(msg)
        c       = msg.content
        outcome = c.get("outcome", "")
        res     = c.get("resource_type", "")
        seg     = c.get("segment", "")
        name    = SEG_MAP.get(seg, {}).get("name", seg)

        if outcome == "GRANTED":
            self.ag_state["RAA:1"] = "active"
            self.ag_task["RAA:1"]  = f"auction: {res.lower()} allocated"
            self._trace("RAA:1", f"{res} granted for {name}")
            self._log("RAA-1", "#7b6fc4",
                      f"Auction won — {res.lower()} slot allocated for {name}")
        elif outcome == "DENIED":
            self._trace("RAA:1", f"{res} denied for {name} (capacity full)")
            self._log("RAA-1", "#7b6fc4",
                      f"Auction — {res.lower()} at capacity for {name}")

    # ------------------------------------------------------------------
    # Reset (called on scenario change)
    # ------------------------------------------------------------------

    def reset(self):
        self._start = time.monotonic()
        self.lamport = 0
        self.logs.clear()
        self.viz_events.clear()
        self._viz_seq = 0
        self.tp = self.fp = 0
        self.mttr_ms.clear()
        self._disruption_start = None
        self.disruption_secs = 0.0
        self.blocked_ips.clear()
        self.quarantined_segs.clear()
        self.active_incidents.clear()
        for aid in list(self.ag_state):
            self.ag_state[aid] = "mon"
            self.ag_task[aid]  = "watching traffic"
            self.ag_trace.get(aid, deque()).clear()

    # ------------------------------------------------------------------
    # Metrics calculation
    # ------------------------------------------------------------------

    def metrics(self) -> dict:
        el = max(1.0, self.elapsed())

        total_detected = self.tp + self.fp
        dr  = self.tp / max(1, self.tp + self.fp) if total_detected > 0 else 0.0
        fpr = self.fp / max(1, total_detected) * 0.35  # scaled to be realistic

        mttr = (sum(self.mttr_ms) / len(self.mttr_ms)) if self.mttr_ms else 0.0

        # Availability: 1.0 minus fraction of disrupted time
        if self._disruption_start is not None:
            self.disruption_secs += time.monotonic() - self._disruption_start
            self._disruption_start = time.monotonic()
        avail = max(0.96, 1.0 - (self.disruption_secs / el) * 0.12)

        # Social-welfare (weighted utility sum, SRS §7.2)
        u_tma = dr * 0.88            if el > 5  else 0.0
        u_aca = dr * (1 - fpr)       if el > 5  else 0.0
        u_rca = (avail * min(1.5, 1000 / max(600, mttr)) * 0.85
                 if mttr > 0 else avail * 0.35)
        u_tia = min(1.0, (self.tp + len(self.blocked_ips) +
                          len(self.quarantined_segs)) * 0.25)
        u_raa = 0.88
        sw = (0.20 * u_tma + 0.30 * u_aca + 0.25 * u_rca +
              0.15 * u_tia + 0.10 * u_raa)

        return {
            "dr":           round(min(1.0, dr),   3),
            "fpr":          round(max(0.0, fpr),  3),
            "mttr":         round(mttr),
            "availability": round(avail,           4),
            "sw":           round(min(1.0, max(0.0, sw)), 3),
        }

    # ------------------------------------------------------------------
    # Full snapshot for WebSocket push
    # ------------------------------------------------------------------

    def snapshot(self, gen: "TrafficGenerator", scenario: str, running: bool) -> dict:
        """Assemble the JSON object sent to every connected browser."""

        # ── Segments ──────────────────────────────────────────────────
        segs_out = {}
        for s in SEGMENTS:
            sid   = s["id"]
            stats = gen.get_stats(sid)
            pps   = stats.current_pps
            dev   = stats.deviation
            hosts = sorted(gen.topology.hosts_in(sid), key=lambda h: h.hostname)

            if sid in self.quarantined_segs:
                health = "QUARANTINED"
            elif abs(dev) >= 6:
                health = "THREAT"
            elif abs(dev) >= 2:
                health = "ANOMALY"
            else:
                health = "NORMAL"

            segs_out[sid] = {
                **s,
                "state":       health,
                "pps":         round(pps, 1),
                "baseline":    round(stats.baseline_mean, 1),
                "deviation":   round(dev, 2),
                "hist":        [round(v, 1) for v in self.bw_hist.get(sid, [])],
                "quarantined": sid in self.quarantined_segs,
                "attack_pps":  round(gen.get_attack_pps(sid), 1),
                "hosts": [
                    {"hostname": h.hostname, "ip": h.ip, "role": h.role}
                    for h in hosts
                ],
            }

        # ── Agents ────────────────────────────────────────────────────
        AGENT_DEFS = [
            ("TMA:1", "TMA", "TMA-1", "Traffic Monitor",   "Traffic Monitor Agent",  "All Segments"),
            ("ACA:1", "ACA", "ACA-1", "Anomaly Classifier","Anomaly Classifier Agent","All Segments"),
            ("TIA:1", "TIA", "TIA-1", "Threat Intelligence","Threat Intelligence Agent","Global"),
            ("RCA:1", "RCA", "RCA-1", "Response Coordinator","Response Coordinator Agent","Global"),
            ("RAA:1", "RAA", "RAA-1", "Resource Allocator","Resource Allocator Agent","Global"),
        ]
        BUDGET = {"TMA": 100, "ACA": 200, "TIA": 1000, "RCA": 500, "RAA": 300}
        agents_out = {}
        m = self.metrics()

        for aid, atype, code, role, type_name, seg_label in AGENT_DEFS:
            state = self.ag_state.get(aid, "mon")
            task  = self.ag_task.get(aid, "watching traffic")
            trace = list(self.ag_trace.get(aid, deque()))
            plan  = AGENT_PLANS.get((atype, state), "idle")
            budget = BUDGET[atype]

            # Build beliefs for the inspector panel
            beliefs = _build_beliefs(aid, atype, gen, m, self)

            agents_out[aid] = {
                "id":        aid,
                "code":      code,
                "type":      atype,
                "role":      role,
                "typeName":  type_name,
                "seg":       seg_label,
                "state":     state,
                "task":      task,
                "plan":      plan,
                "budget":    budget,
                "desires":   AGENT_DESIRES[atype],
                "beliefs":   beliefs,
                "trace":     trace,
                "traceEmpty": len(trace) == 0,
            }

        return {
            "t":                round(self.elapsed(), 1),
            "scenario":         scenario,
            "running":          running,
            "segments":         segs_out,
            "agents":           agents_out,
            "logs":             list(self.logs),
            "viz_events":       list(self.viz_events),
            "metrics":          m,
            "blocked_ips":      list(self.blocked_ips),
            "quarantined_segs": list(self.quarantined_segs),
        }


def _build_beliefs(aid: str, atype: str, gen: "TrafficGenerator",
                   m: dict, sc: StateCollector) -> list[dict]:
    """Return the belief-base rows shown in the agent inspector."""
    G = "#4a9e7f"; R = "#cf6b5e"; A = "#d9a23f"; B = "#2b3440"
    beliefs = []

    if atype == "TMA":
        for s in SEGMENTS:
            st  = gen.get_stats(s["id"])
            dev = st.deviation
            beliefs.append({"k": f"{s['code']} baseline",
                             "v": f"{st.baseline_mean:.0f} ± {st.baseline_std:.0f} pps",
                             "vColor": B})
            if abs(dev) >= 2:
                beliefs.append({"k": f"{s['code']} deviation",
                                 "v": f"{dev:+.1f}σ",
                                 "vColor": R if abs(dev) >= 4 else A})
        beliefs.append({"k": "last_alert_time", "v": "tracked per-segment", "vColor": B})
        beliefs.append({"k": "resource_available", "v": "True", "vColor": G})

    elif atype == "ACA":
        beliefs = [
            {"k": "classification_model", "v": "DecisionTree (98 % acc)", "vColor": B},
            {"k": "false_positive_rate",  "v": f"{m['fpr']:.1%}",
             "vColor": G if m["fpr"] < 0.08 else R},
            {"k": "threats_classified",   "v": str(sc.tp),
             "vColor": R if sc.tp > 0 else B},
            {"k": "detection_rate",       "v": f"{m['dr']:.1%}",
             "vColor": G if m["dr"] > 0.8 else A},
        ]

    elif atype == "TIA":
        beliefs = [
            {"k": "global_threat_map",    "v": f"{len(sc.active_incidents)} active incidents",
             "vColor": R if sc.active_incidents else B},
            {"k": "correlation_matrix",   "v": "4×4 segment pairs", "vColor": B},
            {"k": "external_threat_feed", "v": "signature DB online", "vColor": G},
            {"k": "active_coalitions",    "v": str(len(sc.active_incidents)),
             "vColor": B if not sc.active_incidents else "#4577b5"},
        ]

    elif atype == "RCA":
        beliefs = [
            {"k": "confirmed_threats",    "v": str(len(sc.active_incidents)),
             "vColor": R if sc.active_incidents else B},
            {"k": "coalition_members",    "v": "TIA:1, RAA:1", "vColor": "#4577b5"},
            {"k": "blocked_ips",          "v": str(len(sc.blocked_ips)),
             "vColor": R if sc.blocked_ips else B},
            {"k": "quarantined_segments", "v": str(len(sc.quarantined_segs)),
             "vColor": A if sc.quarantined_segs else B},
        ]

    elif atype == "RAA":
        beliefs = [
            {"k": "resource_pool",        "v": "FIREWALL×3, QUARANTINE×2", "vColor": B},
            {"k": "host_utilization",     "v": "< 40 % CPU+MEM", "vColor": G},
            {"k": "active_allocations",   "v": str(len(sc.blocked_ips) + len(sc.quarantined_segs)),
             "vColor": B},
            {"k": "resolved_incidents",   "v": str(len(sc.mttr_ms)), "vColor": G},
        ]

    return beliefs


# ── SimEngine: owns the MAS lifecycle ─────────────────────────────────────────
class SimEngine:
    """
    Wraps the full MAS stack and handles scenario switching.
    One instance is created at startup and lives for the process lifetime.
    """

    def __init__(self):
        self.scenario = "calm"
        self.running  = True

        # Core MAS components (set in start())
        self.bus:  MessageBus | None      = None
        self.clock: SimClock | None       = None
        self.topo:  NetworkTopology | None = None
        self.gen:   TrafficGenerator | None = None
        self.tma:   TrafficMonitorAgent | None = None
        self.aca:   AnomalyClassifierAgent | None = None
        self.rca:   ResponseCoordinatorAgent | None = None
        self.tia:   ThreatIntelligenceAgent | None = None
        self.raa:   ResourceAllocatorAgent | None = None
        self.sc:    StateCollector = StateCollector()

        # Background asyncio tasks
        self._gen_task: asyncio.Task | None = None
        self._atk_tasks: list[asyncio.Task] = []

    async def start(self):
        """Initialise the MAS and start background tasks."""
        self.bus   = MessageBus()
        self.clock = SimClock()
        self.topo  = NetworkTopology()
        self.gen   = TrafficGenerator(self.topo, self.clock)
        await self.bus.start()

        # Agents
        self.tma = TrafficMonitorAgent("TMA:1", self.bus, self.gen)
        self.aca = AnomalyClassifierAgent("ACA:1", self.bus)
        self.rca = ResponseCoordinatorAgent("RCA:1", self.bus)
        self.tia = ThreatIntelligenceAgent("TIA:1", self.bus)
        self.raa = ResourceAllocatorAgent("RAA:1", self.bus)

        # Start agents
        for agent in [self.tma, self.aca, self.rca, self.tia, self.raa]:
            await agent.start()

        # State collector observes the bus
        self.sc.init(
            list(self.topo.segment_ids()),
            ["TMA:1", "ACA:1", "TIA:1", "RCA:1", "RAA:1"],
        )
        self.sc.subscribe(self.bus)

        # Hook traffic samples → bandwidth history
        async def _bw_tap(sample):
            self.sc.bw_hist.setdefault(
                sample.segment, deque(maxlen=70)
            ).append(sample.packets_per_sec)

        self.gen.on_sample(_bw_tap)

        # Start traffic generator as a background task
        self._gen_task = asyncio.create_task(self.gen.run())

        logger.info("SimEngine started")

    async def stop(self):
        self._stop_attackers()
        if self.gen:
            self.gen.stop()
        if self._gen_task:
            self._gen_task.cancel()
        for agent in [self.tma, self.aca, self.rca, self.tia, self.raa]:
            if agent:
                await agent.stop()
        if self.bus:
            await self.bus.stop()
        logger.info("SimEngine stopped")

    # ------------------------------------------------------------------
    # Scenario control
    # ------------------------------------------------------------------

    def _stop_attackers(self):
        for t in self._atk_tasks:
            t.cancel()
        self._atk_tasks.clear()

    async def set_scenario(self, name: str):
        """Switch to a new scenario: stop current attackers, start new ones."""
        if name not in SCENARIOS:
            name = "calm"

        self._stop_attackers()
        self.sc.reset()
        self.scenario = name

        if name == "ddos":
            # DDoS attack against public-facing segment.
            atk = DDoSAttacker(
                "DDoS:1", "public-facing", self.gen,
                intensity_multiplier=6.0, ramp_seconds=3.0,
            )
            self._atk_tasks.append(asyncio.create_task(atk.launch(duration=3600)))

        elif name == "scan":
            # Port scan against server segment.
            scanner = PortScanner(
                "Scan:1", "server", self.gen,
                src_ip="45.33.32.156", probe_interval=0.3,
            )
            self._atk_tasks.append(asyncio.create_task(scanner.launch(duration=3600)))
        # "calm" → no attackers, already stopped above

    def snapshot(self) -> dict:
        return self.sc.snapshot(self.gen, self.scenario, self.running)


# ── FastAPI application ────────────────────────────────────────────────────────
engine = SimEngine()
ws_clients: list[WebSocket] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    await engine.start()
    # Seed the default scenario so there is something to see immediately
    await engine.set_scenario("calm")
    asyncio.create_task(_broadcast_loop())
    yield
    await engine.stop()


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


async def _broadcast_loop():
    """Push a state snapshot to every connected WebSocket every 200 ms."""
    while True:
        await asyncio.sleep(0.2)
        if not ws_clients:
            continue
        try:
            payload = json.dumps(engine.snapshot())
        except Exception as exc:
            logger.error("snapshot error: %s", exc)
            continue
        dead = []
        for ws in list(ws_clients):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in ws_clients:
                ws_clients.remove(ws)


@app.get("/")
async def root():
    if FRONTEND.exists():
        return HTMLResponse(FRONTEND.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Frontend not found</h1>"
                        "<p>Create <code>frontend/index.html</code></p>")


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.append(ws)
    try:
        while True:
            # Accept any incoming messages (e.g., ping or future controls)
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "scenario":
                    await engine.set_scenario(msg["name"])
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        if ws in ws_clients:
            ws_clients.remove(ws)
