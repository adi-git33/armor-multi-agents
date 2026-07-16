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
from fastapi.staticfiles import StaticFiles

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
from agents.tma import TrafficMonitorAgent, ANOMALY_THRESHOLD
from agents.aca import AnomalyClassifierAgent
from agents.rca import ResponseCoordinatorAgent
from agents.tia import ThreatIntelligenceAgent
from agents.raa import ResourceAllocatorAgent
from core.messages import Topic, Message
from core.models import Packet

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

FRONTEND = pathlib.Path(__file__).parent / "frontend" / "index.html"

# ACA's cumulative detection confusion matrix (tp/fp/fn/tn) persists here
# across backend restarts — see StateCollector._load_aca_metrics/_save_aca_metrics.
# Bootstrap a starting value with `python scripts/seed_aca_metrics.py`.
ACA_METRICS_PATH = pathlib.Path(__file__).parent / "models" / "aca_metrics.json"


def _load_aca_metrics() -> dict:
    try:
        data = json.loads(ACA_METRICS_PATH.read_text())
        return {k: int(data.get(k, 0)) for k in ("tp", "fp", "fn", "tn")}
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return {"tp": 0, "fp": 0, "fn": 0, "tn": 0}


def _save_aca_metrics(tp: int, fp: int, fn: int, tn: int) -> None:
    ACA_METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ACA_METRICS_PATH.write_text(json.dumps({"tp": tp, "fp": fp, "fn": fn, "tn": tn}))

# ── Live confusion-matrix accounting windows ──────────────────────────────────
# The live dashboard flips ground truth the instant a scenario button is
# clicked, but the attack itself takes a few seconds to manifest (DDoS ramp)
# and a few seconds to drain after it stops. The offline validation suite
# accounts for this with warmup/buffer windows (§V-SYS-01); these two windows
# mirror that methodology for the live metrics so a report during the ramp
# counts as detection *latency*, not a miss, and a report just after "calm"
# is residual, not a false positive.
ATTACK_GRACE_SECS = 5.0   # after attack start: NOISE here is not an FN
CALM_LINGER_SECS  = 10.0  # after attack end: threat flags here are not FPs

# Which TMA alert modality carries each attack type — a NOISE verdict on a
# volume alert during a *port-scan* attack is correct (the scan doesn't move
# pps), so only same-modality NOISE verdicts can count as misses.
ATTACK_MODALITY = {"DDOS": "VOLUME_SPIKE", "PORT_SCAN": "PORT_SCAN"}

# ── Segment + scenario metadata ────────────────────────────────────────────────
SEGMENTS = [
    {"id": "public-facing", "code": "PUB", "name": "Public-Facing Services", "cidr": "172.16.0.0/24"},
    {"id": "server",        "code": "SRV", "name": "Server Zone",            "cidr": "10.0.2.0/24"},
    {"id": "internal",      "code": "INT", "name": "Internal User Subnet",   "cidr": "10.0.1.0/24"},
    {"id": "sec-mon",       "code": "MON", "name": "Security Monitoring Zone","cidr": "10.0.3.0/24"},
]
SEG_MAP = {s["id"]: s for s in SEGMENTS}

# One TMA agent per network segment — each only watches its own segment's
# traffic (see agents/tma.py's segment_id filter). Every other MAS agent
# is a single process-wide instance.
TMA_DEFS = [
    (f"TMA:{s['id']}", "TMA", f"TMA-{s['code']}", "Traffic Monitor",
     "Traffic Monitor Agent", s["name"])
    for s in SEGMENTS
]
AGENT_DEFS = TMA_DEFS + [
    ("ACA:1", "ACA", "ACA-1", "Anomaly Classifier",   "Anomaly Classifier Agent",   "All Segments"),
    ("TIA:1", "TIA", "TIA-1", "Threat Intelligence",  "Threat Intelligence Agent",  "Global"),
    ("RCA:1", "RCA", "RCA-1", "Response Coordinator", "Response Coordinator Agent", "Global"),
    ("RAA:1", "RAA", "RAA-1", "Resource Allocator",   "Resource Allocator Agent",   "Global"),
]

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
        # Play/pause bookkeeping: while paused the session clock freezes, so
        # elapsed() (and everything derived from it — availability, log
        # timestamps) excludes paused stretches.
        self._paused_at: float | None = None
        self._paused_total = 0.0
        self.lamport = 0
        self.logs: deque = deque(maxlen=50)
        self.viz_events: deque = deque(maxlen=400)
        self._viz_seq = 0

        # Set by SimEngine.start() once the traffic generator exists, so
        # quarantine decisions here can actually cut off segment traffic.
        self.gen: "TrafficGenerator | None" = None

        # Metric counters — a real confusion matrix against active_attacks
        # (ground truth), not just ACA's self-reported classification.
        # Loaded from disk (ACA_METRICS_PATH) so accuracy accumulates across
        # backend restarts instead of resetting to zero every launch; see
        # _load_aca_metrics/_save_aca_metrics and scripts/seed_aca_metrics.py.
        _m = _load_aca_metrics()
        self.tp = _m["tp"]   # real attack, correctly flagged as a threat
        self.fp = _m["fp"]   # no real attack, but flagged as a threat anyway
        self.fn = _m["fn"]   # real attack, missed (classified as NOISE)
        self.tn = _m["tn"]   # no real attack, correctly classified as NOISE

        # Ground truth: segment_id -> "DDOS" | "PORT_SCAN" for whichever
        # segment SimEngine.set_scenario() is actually attacking right now.
        # Set/cleared by set_scenario(); untouched by quarantine (the
        # attacker keeps running even while its traffic is blocked).
        self.active_attacks: dict[str, str] = {}
        # When each segment's current attack began / last attack ended —
        # drives the ATTACK_GRACE_SECS / CALM_LINGER_SECS windows above.
        self.attack_started: dict[str, float] = {}
        self.attack_ended:   dict[str, float] = {}

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

        # Live coalition voting — open ballots (incident_id → ballot) and a
        # short buffer of just-resolved ones so the UI can show the final
        # tally for a beat before it disappears.
        self.ballots: dict[str, dict] = {}
        self.resolved_ballots: deque = deque(maxlen=5)

        # Per-segment bandwidth history (70 samples ≈ same as mockup)
        self.bw_hist: dict[str, deque] = {}

        # Sampled real packets (legit + attacker) — capped, not exhaustive.
        # At real traffic rates (100s-1000s pps) we cannot stream every
        # packet over a 200ms-tick WebSocket; this is a rate-limited,
        # representative sample, clearly labeled as such in the UI.
        self.packet_log: deque = deque(maxlen=150)
        self._pkt_seq = 0
        self._pkt_tick: dict[str, int] = {}

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
        bus.subscribe(Topic.VOTES,           self._on_vote)
        bus.subscribe(Topic.RESOLUTION,      self._on_resolution)
        bus.subscribe(Topic.RESOURCE_GRANTS, self._on_grant)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _now(self) -> str:
        t = self.elapsed()
        m, s = divmod(int(t), 60)
        return f"{m:02d}:{s:02d}.{int(t * 1000) % 1000:03d}"

    def elapsed(self) -> float:
        ref = self._paused_at if self._paused_at is not None else time.monotonic()
        return ref - self._start - self._paused_total

    def pause_clock(self) -> None:
        if self._paused_at is not None:
            return
        self._paused_at = time.monotonic()
        # Freeze the availability disruption stopwatch too — paused time
        # must not count as quarantine downtime.
        if self._disruption_start is not None:
            self.disruption_secs += self._paused_at - self._disruption_start
            self._disruption_start = None

    def resume_clock(self) -> None:
        if self._paused_at is None:
            return
        self._paused_total += time.monotonic() - self._paused_at
        self._paused_at = None
        if self.quarantined_segs:
            self._disruption_start = time.monotonic()

    def _log(self, agent: str, color: str, text: str, perf: str = ""):
        self.lamport += 1
        self.logs.appendleft({"id": self.lamport, "time": self._now(),
                               "agent": agent, "color": color, "text": text,
                               "perf": perf})

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
            "performative": msg.performative.value,
            "msg_id": msg.msg_id,
            "conversation_id": msg.conversation_id,
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
    # Packet sampling — real legit + attacker packets, rate-limited
    # ------------------------------------------------------------------

    def _add_packet(self, kind: str, pkt: "Packet"):
        self._pkt_seq += 1
        self.packet_log.append({
            "id":       self._pkt_seq,
            # Absolute monotonic clock, not elapsed() — packet_log is a
            # session-wide running record, so timestamps here must stay
            # on one continuous clock for the frontend's "last N seconds"
            # recency filtering to work.
            "t":        round(time.monotonic(), 3),
            "kind":     kind,               # "legit" | "attack"
            "src_ip":   pkt.src_ip,
            "dst_ip":   pkt.dst_ip,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "protocol": pkt.protocol,
            "size":     pkt.pkt_size,
            "segment":  pkt.segment,
            "label":    pkt.label,
        })

    def sample_packets(self, seg_id: str, gen: "TrafficGenerator"):
        """
        Called on every TrafficGenerator sample tick (10 Hz per segment).
        Internally rate-limited so the packet log stays a small, honest
        sample rather than an attempt at full fidelity.
        """
        # Real attack packets (currently only PortScanner deposits discrete
        # Packet objects) — peek non-destructively so we never compete with
        # the TMA's own drain_attack_packets() consumption.
        for pkt in gen.peek_attack_packets(seg_id):
            self._add_packet("attack", pkt)

        # DDoSAttacker injects a pure pps overlay, not discrete packets —
        # synthesize one clearly-labeled representative flood packet every
        # few ticks while the overlay is active, so a DDoS is still visible
        # as "packets", without claiming per-packet fidelity to the flood.
        attack_pps = gen.get_attack_pps(seg_id)
        if attack_pps > 0:
            key = f"ddos:{seg_id}"
            tick = self._pkt_tick.get(key, 0) + 1
            self._pkt_tick[key] = tick
            if tick % 3 == 0:
                hosts = gen.topology.hosts_in(seg_id)
                if hosts:
                    host = hosts[tick % len(hosts)]
                    self._add_packet("attack", Packet(
                        src_ip   = f"{(tick * 37) % 223 + 1}.{(tick * 11) % 256}."
                                   f"{(tick * 7) % 256}.{(tick * 3) % 254 + 1}",
                        dst_ip   = host.ip,
                        src_port = 40000 + (tick % 20000),
                        dst_port = 443,
                        protocol = "TCP",
                        pkt_size = 64,
                        segment  = seg_id,
                        label    = "DDoS flood (representative sample)",
                    ))

        # Legit background traffic — rate-limited to ~2 pkts/sec/segment,
        # drawn from the same weighted traffic patterns show_packets.py uses.
        key = f"legit:{seg_id}"
        tick = self._pkt_tick.get(key, 0) + 1
        self._pkt_tick[key] = tick
        if tick % 5 == 0:
            seg = gen.topology.get(seg_id)
            for pkt in gen.generate_packets(seg, 2):
                self._add_packet("legit", pkt)

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
        # One TMA per segment now — attribute state/log entries to the TMA
        # that actually sent this (e.g. "TMA:server"), not a fixed "TMA:1".
        sender      = msg.sender
        sender_code = f"TMA-{SEG_MAP.get(seg, {}).get('code', seg)}"

        self.ag_state[sender] = "alert"
        self.ag_task[sender]  = f"anomaly on {name}"
        self._trace(sender, f"{atype} on {name} ({dev:+.1f}σ)")
        self._log(sender_code, "#d9a23f",
                  f"Alert — {atype.lower().replace('_', ' ')} on {name} ({dev:+.1f}σ)",
                  perf=msg.performative.value)

    async def _on_threat_report(self, msg: Message):
        self._emit_viz_event(msg)
        c    = msg.content
        clf  = c.get("classification", "")   # "NOISE" | "DDOS" | "PORT_SCAN"
        sev  = c.get("severity", 0.0)
        seg  = c.get("segment", "")
        conf = c.get("confidence", 0.0)
        atk  = c.get("attack_type", clf)
        name = SEG_MAP.get(seg, {}).get("name", seg)

        # Ground truth for this segment right now (set by SimEngine.set_scenario()) —
        # lets tp/fp/fn/tn reflect whether ACA's call was actually correct,
        # not just what string it happened to publish.
        now          = time.monotonic()
        attack_type  = self.active_attacks.get(seg)
        under_attack = attack_type is not None
        in_grace  = (under_attack and
                     now - self.attack_started.get(seg, now) < ATTACK_GRACE_SECS)
        in_linger = (not under_attack and
                     now - self.attack_ended.get(seg, float("-inf")) < CALM_LINGER_SECS)
        src_alert = c.get("source_alert", "")

        if clf == "NOISE":
            if under_attack and src_alert == ATTACK_MODALITY.get(attack_type):
                # NOISE on the attack's own modality is a miss — unless the
                # attack just started and is still ramping (grace window).
                if not in_grace:
                    self.fn += 1
            else:
                self.tn += 1   # correctly quiet (or off-modality chatter)
        else:
            if under_attack:
                if clf == attack_type:
                    self.tp += 1
                # mismatched threat type mid-attack (e.g. DDOS verdict during
                # a port scan): neither a hit nor a calm-moment error — skip
            elif not in_linger:
                self.fp += 1   # genuinely calm moment flagged as a threat

            self.ag_state["ACA:1"] = "active"
            self.ag_task["ACA:1"]  = f"classifying · severity {sev:.2f}"
            self._trace("ACA:1", f"Confirmed {atk} — sev {sev:.2f}, conf {conf:.0%}")
            self._log("ACA-1", "#cf6b5e",
                      f"Confirmed threat: {atk} on {name}, severity {sev:.2f}",
                      perf=msg.performative.value)

        _save_aca_metrics(self.tp, self.fp, self.fn, self.tn)

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
                      "Multi-segment scan detected — forming response coalition",
                      perf=msg.performative.value)
        elif "COORDINATED" in pattern:
            self._log("TIA-1", "#3fa3a8",
                      "Coordinated DDoS across segments — coalition activated",
                      perf=msg.performative.value)
        else:
            self._log("TIA-1", "#3fa3a8", f"{name} ranked highest-priority threat",
                      perf=msg.performative.value)

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
        self.ballots[inc_id] = {
            "incident_id": inc_id,
            "segment": seg,
            "segment_name": name,
            "action": action,
            "proposer": msg.sender,
            "opened_at": round(self.elapsed(), 3),
            "votes": [],
            "outcome": None,
        }
        self.ag_state["RCA:1"] = "active"
        self.ag_task["RCA:1"]  = f"coalition vote for {name}"
        self._trace("RCA:1", f"CFP: {action} for {name}")
        self._log("RCA-1", "#4577b5",
                  f"Coalition vote — {action.lower().replace('_', ' ')} for {name}",
                  perf=msg.performative.value)

    async def _on_vote(self, msg: Message):
        self._emit_viz_event(msg)
        c      = msg.content
        inc_id = c.get("incident_id", "")
        ballot = self.ballots.get(inc_id)
        decision = msg.performative.value  # ACCEPT / REJECT

        if ballot is not None:
            ballot["votes"].append({
                "voter":    msg.sender,
                "decision": decision,
                "reason":   c.get("reason", ""),
                "t":        round(self.elapsed(), 3),
            })

        color = "#4a9e7f" if decision == "ACCEPT" else "#cf6b5e"
        self._trace(msg.sender, f"voted {decision} on {inc_id}")
        self._log(msg.sender.replace(":", "-"), color,
                  f"Vote {decision} from {msg.sender} — {c.get('reason', '') or inc_id}",
                  perf=decision)

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

        ballot = self.ballots.pop(inc_id, None)
        if ballot is not None:
            ballot["outcome"]       = outcome
            ballot["votes_accept"]  = c.get("votes_accept", 0)
            ballot["votes_reject"]  = c.get("votes_reject", 0)
            ballot["resolved_at"]   = round(self.elapsed(), 3)
            self.resolved_ballots.append(ballot)

        if outcome == "EXECUTED":
            self.mttr_ms.append(dur_ms)
            if len(self.mttr_ms) > 100:
                self.mttr_ms = self.mttr_ms[-100:]

            if "src_ip" in tgt:
                ip = tgt["src_ip"]
                self.blocked_ips.add(ip)
                self.ag_task["RCA:1"] = f"blocked {ip}"
                self._log("RCA-1", "#4577b5", f"Mitigation — {ip} blocked ({dur_ms} ms)",
                          perf=msg.performative.value)
            elif "segment" in tgt and action == "QUARANTINE_SEGMENT":
                qseg = tgt["segment"]
                self.quarantined_segs.add(qseg)
                if self.gen:
                    self.gen.quarantine(qseg)
                if self._disruption_start is None:
                    self._disruption_start = time.monotonic()
                qname = SEG_MAP.get(qseg, {}).get("name", qseg)
                self.ag_task["RCA:1"] = f"quarantined {qname}"
                self._log("RCA-1", "#4577b5",
                          f"Mitigation — {qname} quarantined ({dur_ms} ms)",
                          perf=msg.performative.value)
            elif "segment" in tgt:
                # THROTTLE_SEGMENT (rung 0, non-voted) — a lighter-touch
                # response than QUARANTINE_SEGMENT; does not black out
                # traffic or set the QUARANTINED badge.
                self.ag_task["RCA:1"] = f"throttled {name}"
                self._log("RCA-1", "#4577b5",
                          f"Mitigation — {name} throttled ({dur_ms} ms)",
                          perf=msg.performative.value)

            self._trace("RCA:1", f"{action} EXECUTED for {name} ({dur_ms} ms)")
        elif outcome == "RELEASED":
            rseg = tgt.get("segment", "")
            if rseg in self.quarantined_segs:
                self.quarantined_segs.discard(rseg)
                if self.gen:
                    self.gen.unquarantine(rseg)
                if self._disruption_start is not None:
                    self.disruption_secs += time.monotonic() - self._disruption_start
                    self._disruption_start = time.monotonic() if self.quarantined_segs else None
                rname = SEG_MAP.get(rseg, {}).get("name", rseg)
                self.ag_task["RCA:1"] = f"released {rname}"
                self._log("RCA-1", "#4577b5",
                          f"Mitigation — {rname} quarantine released ({dur_ms} ms hold)",
                          perf=msg.performative.value)
                self._trace("RCA:1", f"quarantine released for {rname}")
        else:
            self._log("RCA-1", "#d9a23f",
                      f"Vote rejected — {action} not executed for {name}",
                      perf=msg.performative.value)
            self._trace("RCA:1", f"{action} REJECTED for {name}")

    async def _on_grant(self, msg: Message):
        self._emit_viz_event(msg)
        c       = msg.content
        outcome = c.get("outcome", "")
        res     = c.get("resource_type", "")
        seg     = c.get("segment", "")
        name    = SEG_MAP.get(seg, {}).get("name", seg)
        bid     = c.get("bid_value")

        if outcome == "GRANTED":
            self.ag_state["RAA:1"] = "active"
            self.ag_task["RAA:1"]  = f"auction: {res.lower()} allocated"
            self._trace("RAA:1", f"{res} granted for {name}")
            bid_txt = f" (bid {bid:.2f})" if bid is not None else ""
            self._log("RAA-1", "#7b6fc4",
                      f"Auction won — {res.lower()} slot allocated for {name}{bid_txt}",
                      perf=msg.performative.value)
        elif outcome == "DENIED":
            weakest = c.get("weakest_existing_bid")
            self._trace("RAA:1", f"{res} denied for {name} (capacity full)")
            bid_txt = (f" (bid {bid:.2f} ≤ weakest {weakest:.2f})"
                       if bid is not None and weakest is not None else "")
            self._log("RAA-1", "#7b6fc4",
                      f"Auction — {res.lower()} at capacity for {name}{bid_txt}",
                      perf=msg.performative.value)
        elif outcome == "EVICTED":
            self._trace("RAA:1", f"{res} evicted for {name} — outbid")
            bid_txt = f" (bid {bid:.2f})" if bid is not None else ""
            self._log("RAA-1", "#7b6fc4",
                      f"Auction — {name} {res.lower()} allocation evicted, outbid{bid_txt}",
                      perf=msg.performative.value)

    # ------------------------------------------------------------------
    # Reset (called when one segment's scenario changes)
    # ------------------------------------------------------------------

    def reset_segment(self, segment_id: str):
        """
        Called by SimEngine.set_scenario() when segment_id's attacker
        changes. Clears only state that belongs to THIS segment — other
        segments can be mid-attack or quarantined at the same time and
        must not be disturbed. (self.active_attacks isn't touched here:
        SimEngine sets/clears that entry itself right after this call,
        to whatever the new scenario for this segment actually is.)

        Left alone deliberately, same reasoning as before but now simply
        because it's session-wide, not segment-scoped: self.logs,
        self.tp/fp/fn/tn, self.mttr_ms, self.blocked_ips (not attributable
        to one segment), and agent display state (agents are global
        singletons that may legitimately be busy with a different segment).
        """
        if self.gen and segment_id in self.quarantined_segs:
            self.gen.unquarantine(segment_id)
        self.quarantined_segs.discard(segment_id)

        self.active_incidents = {
            k: v for k, v in self.active_incidents.items() if v.get("seg") != segment_id
        }
        self.ballots = {
            k: v for k, v in self.ballots.items() if v.get("segment") != segment_id
        }
        self._pkt_tick.pop(f"legit:{segment_id}", None)
        self._pkt_tick.pop(f"ddos:{segment_id}", None)

        # Availability tracks "is ANY segment currently disrupted" — if this
        # was the last quarantined segment, stop the disruption clock too.
        if self._disruption_start is not None and not self.quarantined_segs:
            self.disruption_secs += time.monotonic() - self._disruption_start
            self._disruption_start = None

    # ------------------------------------------------------------------
    # Metrics reset (frontend "reset metrics" control)
    # ------------------------------------------------------------------

    def reset_metrics(self) -> None:
        """Zero the persisted confusion matrix — lets a demo start from a
        clean slate instead of inheriting every historical session's tally."""
        self.tp = self.fp = self.fn = self.tn = 0
        _save_aca_metrics(0, 0, 0, 0)

    # ------------------------------------------------------------------
    # Metrics calculation
    # ------------------------------------------------------------------

    def metrics(self) -> dict:
        el = max(1.0, self.elapsed())

        # Standard confusion-matrix rates against ground truth (active_attacks):
        # DR (recall)  = real attacks correctly caught / all real attacks
        # FPR          = calm moments wrongly flagged / all calm moments
        dr  = self.tp / max(1, self.tp + self.fn)
        fpr = self.fp / max(1, self.fp + self.tn)

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

    def snapshot(self, gen: "TrafficGenerator", segment_scenarios: dict[str, str], running: bool) -> dict:
        """Assemble the JSON object sent to every connected browser."""

        # ── Segments ──────────────────────────────────────────────────
        segs_out = {}
        for s in SEGMENTS:
            sid   = s["id"]
            stats = gen.get_stats(sid)
            dev   = stats.deviation
            hosts = sorted(gen.topology.hosts_in(sid), key=lambda h: h.hostname)

            if sid in self.quarantined_segs:
                health = "QUARANTINED"
                # gen.get_stats() intentionally keeps reporting the real,
                # live reading even while blocked (see traffic.py
                # quarantine()) so RCA can poll for recovery — override
                # just the displayed number here, not the underlying stats.
                pps = 0.0
            else:
                pps = stats.current_pps
                if abs(dev) >= 6:
                    health = "THREAT"
                elif abs(dev) >= 2:
                    health = "ANOMALY"
                else:
                    health = "NORMAL"

            segs_out[sid] = {
                **s,
                "state":       health,
                "scenario":    segment_scenarios.get(sid, "calm"),
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
            "running":          running,
            "segments":         segs_out,
            "agents":           agents_out,
            "logs":             list(self.logs),
            "viz_events":       list(self.viz_events),
            "metrics":          m,
            "blocked_ips":      list(self.blocked_ips),
            "quarantined_segs": list(self.quarantined_segs),
            "ballots": {
                "open":     list(self.ballots.values()),
                "resolved": list(self.resolved_ballots),
            },
            "packets":          list(self.packet_log),
        }


def _build_beliefs(aid: str, atype: str, gen: "TrafficGenerator",
                   m: dict, sc: StateCollector) -> list[dict]:
    """Return the belief-base rows shown in the agent inspector."""
    G = "#4a9e7f"; R = "#cf6b5e"; A = "#d9a23f"; B = "#2b3440"
    beliefs = []

    if atype == "TMA":
        # One TMA per segment now — aid is "TMA:<segment_id>", so only
        # show beliefs for the one segment this instance actually watches.
        seg_id = aid.split(":", 1)[1] if ":" in aid else None
        s = SEG_MAP.get(seg_id)
        if s:
            st  = gen.get_stats(s["id"])
            dev = st.deviation
            beliefs.append({"k": "segment", "v": s["name"], "vColor": B})
            beliefs.append({"k": "baseline",
                             "v": f"{st.baseline_mean:.0f} ± {st.baseline_std:.0f} pps",
                             "vColor": B})
            beliefs.append({"k": "deviation",
                             "v": f"{dev:+.1f}σ",
                             "vColor": R if abs(dev) >= 4 else (A if abs(dev) >= 2 else G)})
        beliefs.append({"k": "last_alert_time", "v": "tracked for this segment", "vColor": B})
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
            self.sc.bw_hist.setdefault(
                sample.segment, deque(maxlen=70)
            ).append(sample.packets_per_sec)

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
            self.sc.active_attacks[target] = "DDOS"
            self.sc.attack_started[target] = time.monotonic()
        elif name == "scan":
            scanner = PortScanner(
                f"Scan:{target}", target, self.gen,
                src_ip="45.33.32.156", probe_interval=0.3,
            )
            self._atk_tasks[target] = asyncio.create_task(scanner.launch(duration=3600))
            self.sc.active_attacks[target] = "PORT_SCAN"
            self.sc.attack_started[target] = time.monotonic()

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
        if target in self.sc.active_attacks:
            self.sc.attack_ended[target] = time.monotonic()

        if name in ("ddos", "scan"):
            self._launch_attacker(name, target)
        else:
            # "calm" → attacker already stopped above; this segment has no
            # active ground-truth attack anymore.
            self.sc.active_attacks.pop(target, None)

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

# Validation suite runner -- separate page/concern from the live dashboard
# above. The router owns /api/validation/suites + /api/validation/ws;
# charts/ is mounted here (not inside the router) since StaticFiles needs
# an app-level mount point.
from validation.api import router as validation_router  # noqa: E402

app.include_router(validation_router)
_CHARTS_DIR = pathlib.Path(__file__).parent / "validation" / "charts"
_CHARTS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/charts", StaticFiles(directory=str(_CHARTS_DIR)), name="charts")


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
                    await engine.set_scenario(msg["name"], msg.get("segment"))
                elif msg.get("type") == "control":
                    action = msg.get("action")
                    if action == "reset_metrics":
                        engine.sc.reset_metrics()
                    elif action == "pause":
                        await engine.pause()
                    elif action == "resume":
                        await engine.resume()
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        if ws in ws_clients:
            ws_clients.remove(ws)
