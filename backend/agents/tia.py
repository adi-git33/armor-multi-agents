"""
Threat Intelligence Agent  (SDD §4.5)
======================================
Correlates threat reports across network segments to detect attack
patterns that no single-segment agent can see, then enriches the shared
threat picture and participates in coalition votes.

Responsibilities
-----------------
1. Subscribe to threat-reports — build a cross-segment threat history.
2. Detect patterns:
     MULTI_SEGMENT_SCAN  — same src_ip appearing in PORT_SCAN alerts on
                           two or more segments within INTEL_WINDOW seconds.
     COORDINATED_DDOS    — DDOS classification on two or more different
                           segments within COORDINATED_DDOS_WINDOW seconds.
3. Publish to threat-intel when a pattern is confirmed.
   The confidence carried in threat-intel is higher than any single
   report, because TIA has cross-corroborated the evidence.
4. Subscribe to coalition (CFPs from RCA) and vote ACCEPT / REJECT based
   on whether the intel database supports or contradicts the proposal.

BDI roles
----------
Beliefs  : _history per segment (60 s window)
           _src_ip_segments: which segments a src_ip has appeared on
           _pattern_cooldown: suppress duplicate pattern publications
Desires  : surface real cross-segment threats; suppress noise
Intention: _on_threat_report → _check_patterns → publish threat-intel
           _on_cfp           → _publish_vote
"""

from __future__ import annotations
import logging
import time
from collections import defaultdict

from agents.base import BaseAgent
from agents._history import append_and_expire, cooldown_ok
from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic

logger = logging.getLogger(__name__)

# ── tuneable constants ─────────────────────────────────────────────────
INTEL_WINDOW               = 60.0   # seconds of threat-report history
MULTI_SEGMENT_THRESHOLD    = 2      # distinct segments same IP must appear on
COORDINATED_DDOS_WINDOW    = 30.0   # seconds for multi-segment DDoS window
COORDINATED_DDOS_THRESHOLD = 2      # distinct segments that must show DDoS
PATTERN_COOLDOWN           = 30.0   # seconds before re-publishing same pattern

# Confidence values for corroborated patterns (higher than individual reports)
PATTERN_CONFIDENCE = {
    "MULTI_SEGMENT_SCAN": 0.93,
    "COORDINATED_DDOS":   0.95,
}


class ThreatIntelligenceAgent(BaseAgent):

    def __init__(self, agent_id: str, bus: MessageBus) -> None:
        super().__init__(agent_id, bus)

        # segment → list of recent threat-report dicts (with "time" key)
        self._history: dict[str, list[dict]] = defaultdict(list)

        # src_ip → {segment: last_seen_time}  — for multi-segment scan detection
        self._src_ip_segments: dict[str, dict[str, float]] = defaultdict(dict)

        # "PATTERN_TYPE:target_key" → monotonic time of last publication
        self._pattern_cooldown: dict[str, float] = {}

        # Completed intel publications (for testing / introspection)
        self.intel_published: list[dict] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        await super().start()
        self.subscribe(Topic.THREAT_REPORTS, self._on_threat_report)
        self.subscribe(Topic.COALITION,      self._on_cfp)
        logger.info("[%s] ready", self.agent_id)

    # ------------------------------------------------------------------
    # Belief update + pattern detection
    # ------------------------------------------------------------------

    async def _on_threat_report(self, msg: Message) -> None:
        c   = msg.content
        seg = c.get("segment", "")
        clf = c.get("classification", "")
        now = time.monotonic()

        # Update per-segment history
        self._history[seg] = append_and_expire(
            self._history[seg], {"time": now, **c}, now, INTEL_WINDOW
        )

        # Track src_ip across segments (carried in ACA's evidence dict)
        evidence = c.get("evidence", {})
        src_ip   = evidence.get("src_ip", "")
        if src_ip and clf == "PORT_SCAN":
            self._src_ip_segments[src_ip][seg] = now
            # Expire stale entries
            self._src_ip_segments[src_ip] = {
                s: t for s, t in self._src_ip_segments[src_ip].items()
                if now - t <= INTEL_WINDOW
            }

        # Pattern checks (order matters: scan first, then DDoS)
        await self._check_multi_segment_scan(src_ip, now)
        await self._check_coordinated_ddos(clf, now)

    # ------------------------------------------------------------------
    # Pattern: MULTI_SEGMENT_SCAN
    # ------------------------------------------------------------------

    async def _check_multi_segment_scan(self, src_ip: str, now: float) -> None:
        if not src_ip:
            return

        active_segments = [
            s for s, t in self._src_ip_segments[src_ip].items()
            if now - t <= INTEL_WINDOW
        ]

        if len(active_segments) < MULTI_SEGMENT_THRESHOLD:
            return

        cooldown_key = f"MULTI_SEGMENT_SCAN:{src_ip}"
        if not cooldown_ok(self._pattern_cooldown.get(cooldown_key, 0.0), now, PATTERN_COOLDOWN):
            return
        self._pattern_cooldown[cooldown_key] = now

        intel = {
            "pattern_type":       "MULTI_SEGMENT_SCAN",
            "classification":     "PORT_SCAN",
            "affected_segments":  active_segments,
            "primary_segment":    active_segments[0],
            "src_ip":             src_ip,
            "confidence":         PATTERN_CONFIDENCE["MULTI_SEGMENT_SCAN"],
            "recommended_action": "BLOCK_SOURCE_IP",
            "evidence": {
                "src_ip":        src_ip,
                "segment_count": len(active_segments),
                "segments":      active_segments,
            },
        }
        self.intel_published.append(intel)

        await self.publish(
            topic        = Topic.THREAT_INTEL,
            performative = Performative.INFORM,
            content      = intel,
        )
        logger.info(
            "[%s] MULTI_SEGMENT_SCAN  ip=%s  segments=%s",
            self.agent_id, src_ip, active_segments,
        )

    # ------------------------------------------------------------------
    # Pattern: COORDINATED_DDOS
    # ------------------------------------------------------------------

    async def _check_coordinated_ddos(self, clf: str, now: float) -> None:
        if clf != "DDOS":
            return

        ddos_segments = [
            s for s, hist in self._history.items()
            if any(
                r.get("classification") == "DDOS"
                and now - r["time"] <= COORDINATED_DDOS_WINDOW
                for r in hist
            )
        ]

        if len(ddos_segments) < COORDINATED_DDOS_THRESHOLD:
            return

        cooldown_key = f"COORDINATED_DDOS:{','.join(sorted(ddos_segments))}"
        if not cooldown_ok(self._pattern_cooldown.get(cooldown_key, 0.0), now, PATTERN_COOLDOWN):
            return
        self._pattern_cooldown[cooldown_key] = now

        intel = {
            "pattern_type":       "COORDINATED_DDOS",
            "classification":     "DDOS",
            "affected_segments":  ddos_segments,
            "primary_segment":    ddos_segments[0],
            "confidence":         PATTERN_CONFIDENCE["COORDINATED_DDOS"],
            "recommended_action": "QUARANTINE_SEGMENT",
            "evidence": {
                "segment_count": len(ddos_segments),
                "segments":      ddos_segments,
                "window_secs":   COORDINATED_DDOS_WINDOW,
            },
        }
        self.intel_published.append(intel)

        await self.publish(
            topic        = Topic.THREAT_INTEL,
            performative = Performative.INFORM,
            content      = intel,
        )
        logger.info(
            "[%s] COORDINATED_DDOS  segments=%s",
            self.agent_id, ddos_segments,
        )

    # ------------------------------------------------------------------
    # Coalition voting
    # ------------------------------------------------------------------

    async def _on_cfp(self, msg: Message) -> None:
        if msg.performative != Performative.CALL_FOR_PROPOSAL:
            return

        c           = msg.content
        incident_id = c.get("incident_id", "")
        segment     = c.get("segment", "")
        now         = time.monotonic()

        # Count how many recent reports TIA has for this segment
        intel_count = sum(
            1 for r in self._history.get(segment, [])
            if now - r["time"] <= INTEL_WINDOW
        )

        # ACCEPT unless TIA has specific reason to doubt (none in current impl).
        # Future: compare proposed_action against known safe IP lists, etc.
        vote   = Performative.ACCEPT
        reason = (
            f"TIA corroborates: {intel_count} report(s) on '{segment}'"
            if intel_count > 0
            else "TIA: no contradicting intel, cooperating"
        )

        await self.publish(
            topic        = Topic.VOTES,
            performative = vote,
            content      = {
                "incident_id": incident_id,
                "reason":      reason,
                "intel_count": intel_count,
            },
        )
        logger.info(
            "[%s] VOTE %s  incident=%s  seg=%s  intel=%d",
            self.agent_id, vote.value, incident_id, segment, intel_count,
        )
