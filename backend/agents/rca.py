"""
Response Coordinator Agent  (SDD §4.4)
=======================================
Coordinates the defensive response once a threat is confirmed.

Responsibilities
-----------------
1. Receive high-confidence threat reports (from ACA via threat-reports topic).
2. Deliberate — check corroborating evidence before acting.
3. Initiate a coalition vote: publish CALL_FOR_PROPOSAL to the coalition topic.
4. Collect ACCEPT / REJECT votes from coalition members (votes topic).
5. Decide by majority, pick a proportional action, publish to resolution topic.
6. Simulate executing the defensive action and log it.

Temporary self-trigger
-----------------------
Until TIA (Part 7) is built, RCA also subscribes to threat-reports directly
and initiates coalitions itself.  When TIA takes over the triggering role,
this path remains as a fallback — two triggers are harmless because the
per-segment cooldown deduplicates them.

BDI roles
----------
Beliefs  : recent threat reports per segment (60 s window)
           cooldown state per segment
           open incidents awaiting votes
Desires  : act on every real threat; suppress noise and duplicates
Intention: _on_threat_report() → _deliberate() → _call_vote() → _resolve()
"""

from __future__ import annotations
import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

from agents.base import BaseAgent
from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic

logger = logging.getLogger(__name__)

# ── thresholds ────────────────────────────────────────────────────────
MIN_CONFIDENCE      = 0.70   # below this → ignored entirely
HIGH_CONFIDENCE     = 0.85   # above this → single report is enough to act
MIN_CORROBORATION   = 2      # below HIGH_CONFIDENCE need this many reports in window
HISTORY_WINDOW      = 60.0   # seconds of threat-report history per segment
VOTE_WINDOW         = 0.3    # seconds to wait for external coalition votes
RESOLUTION_COOLDOWN = 30.0   # seconds before re-escalating the same segment

# Maps classification to proportional action
ACTIONS = {
    "DDOS":      "QUARANTINE_SEGMENT",
    "PORT_SCAN": "BLOCK_SOURCE_IP",
    "NOISE":     "LOG_ONLY",
}


class IncidentState(str, Enum):
    DELIBERATING = "DELIBERATING"
    VOTING       = "VOTING"
    RESOLVED     = "RESOLVED"


@dataclass
class Incident:
    incident_id:    str
    segment:        str
    classification: str
    confidence:     float
    action:         str
    state:          IncidentState = IncidentState.DELIBERATING
    votes_accept:   int = 0
    votes_reject:   int = 0
    opened_at:      float = field(default_factory=time.monotonic)
    resolved_at:    float = 0.0
    source_report:  dict  = field(default_factory=dict)


class ResponseCoordinatorAgent(BaseAgent):

    def __init__(self, agent_id: str, bus: MessageBus) -> None:
        super().__init__(agent_id, bus)

        # BDI Beliefs
        self._history:  dict[str, list[dict]] = {}   # segment → recent reports
        self._cooldown: dict[str, float]      = {}   # segment → last resolution time
        self._incidents: dict[str, Incident]  = {}   # incident_id → Incident

        # Completed resolutions for introspection / testing
        self.resolutions: list[dict] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        await super().start()
        self.bus.subscribe(Topic.THREAT_REPORTS, self._on_threat_report)
        self.bus.subscribe(Topic.THREAT_INTEL,   self._on_threat_intel)
        self.bus.subscribe(Topic.VOTES,          self._on_vote)
        logger.info("[%s] ready", self.agent_id)

    # ------------------------------------------------------------------
    # Intention 1 — receive ACA threat report
    # ------------------------------------------------------------------

    async def _on_threat_report(self, msg: Message) -> None:
        if not self._running:
            return

        c   = msg.content
        seg = c.get("segment", "")
        clf = c.get("classification", "NOISE")
        conf = float(c.get("confidence", 0.0))
        now = time.monotonic()

        # Filter: ignore noise and low-confidence
        if clf == "NOISE" or conf < MIN_CONFIDENCE:
            return

        # Filter: cooldown — already responding to this segment
        if now - self._cooldown.get(seg, 0.0) < RESOLUTION_COOLDOWN:
            logger.debug("[%s] cooldown active for segment %s", self.agent_id, seg)
            return

        # Update history
        if seg not in self._history:
            self._history[seg] = []
        self._history[seg].append({"time": now, **c})
        self._history[seg] = [
            r for r in self._history[seg]
            if now - r["time"] <= HISTORY_WINDOW
        ]

        await self._deliberate(seg, c, conf, now)

    # ------------------------------------------------------------------
    # TIA intel path — corroborated pattern triggers immediate escalation
    # ------------------------------------------------------------------

    async def _on_threat_intel(self, msg: Message) -> None:
        """
        TIA has already cross-corroborated threats across segments.
        Bypass the single-report deliberation threshold and open an
        incident directly.
        """
        if not self._running:
            return

        c   = msg.content
        seg = c.get("primary_segment", "")
        clf = c.get("classification", "")
        conf = float(c.get("confidence", 0.0))
        now = time.monotonic()

        if not seg or not clf or clf == "NOISE":
            return

        # Cooldown — already responding to this segment
        if now - self._cooldown.get(seg, 0.0) < RESOLUTION_COOLDOWN:
            logger.debug(
                "[%s] cooldown active for segment %s (intel path)", self.agent_id, seg
            )
            return

        action = ACTIONS.get(clf, "INVESTIGATE")

        # Carry src_ip into evidence so _resolve can build enforcement_target
        evidence = dict(c.get("evidence", {}))
        if "src_ip" in c:
            evidence["src_ip"] = c["src_ip"]

        source_report = {
            "segment":            seg,
            "classification":     clf,
            "confidence":         conf,
            "recommended_action": action,
            "source_alert":       c.get("pattern_type", "TIA_INTEL"),
            "evidence":           evidence,
        }

        incident = Incident(
            incident_id    = str(uuid.uuid4())[:8],
            segment        = seg,
            classification = clf,
            confidence     = conf,
            action         = action,
            source_report  = source_report,
        )
        self._incidents[incident.incident_id] = incident

        logger.info(
            "[%s] intel-triggered  pattern=%-22s  seg=%-15s  conf=%.2f",
            self.agent_id, c.get("pattern_type", "?"), seg, conf,
        )

        await self._call_vote(incident)

    # ------------------------------------------------------------------
    # Intention 2 — deliberate: enough evidence to act?
    # ------------------------------------------------------------------

    async def _deliberate(
        self, seg: str, report: dict, confidence: float, now: float
    ) -> None:
        history     = self._history.get(seg, [])
        corroborate = len(history)   # includes this report

        act = (confidence >= HIGH_CONFIDENCE) or (corroborate >= MIN_CORROBORATION)

        logger.info(
            "[%s] deliberate  seg=%-15s  conf=%.2f  corroborate=%d  act=%s",
            self.agent_id, seg, confidence, corroborate, act,
        )

        if not act:
            return   # buffer — wait for more evidence

        classification = report.get("classification", "UNKNOWN")
        action         = ACTIONS.get(classification, "INVESTIGATE")

        incident = Incident(
            incident_id    = str(uuid.uuid4())[:8],
            segment        = seg,
            classification = classification,
            confidence     = confidence,
            action         = action,
            source_report  = report,
        )
        self._incidents[incident.incident_id] = incident

        await self._call_vote(incident)

    # ------------------------------------------------------------------
    # Intention 3 — open coalition vote
    # ------------------------------------------------------------------

    async def _call_vote(self, incident: Incident) -> None:
        incident.state = IncidentState.VOTING

        # Cast RCA's own vote immediately (based on deliberation above)
        incident.votes_accept += 1

        # Publish CALL_FOR_PROPOSAL so future agents (TIA, RAA) can vote
        await self.publish(
            topic        = Topic.COALITION,
            performative = Performative.CALL_FOR_PROPOSAL,
            content      = {
                "incident_id":    incident.incident_id,
                "segment":        incident.segment,
                "classification": incident.classification,
                "proposed_action": incident.action,
                "confidence":     incident.confidence,
                "deadline_secs":  VOTE_WINDOW,
            },
        )

        logger.info(
            "[%s] CFP sent  incident=%s  action=%s  waiting %.1fs for votes",
            self.agent_id, incident.incident_id, incident.action, VOTE_WINDOW,
        )

        # Detach the vote timer from the delivery loop so the bus can keep
        # processing other messages while we wait for external votes.
        asyncio.create_task(self._wait_and_resolve(incident))

    async def _wait_and_resolve(self, incident: Incident) -> None:
        await asyncio.sleep(VOTE_WINDOW)
        await self._resolve(incident)

    # ------------------------------------------------------------------
    # Intention 4 — receive external vote
    # ------------------------------------------------------------------

    async def _on_vote(self, msg: Message) -> None:
        if not self._running:
            return

        c           = msg.content
        incident_id = c.get("incident_id", "")
        incident    = self._incidents.get(incident_id)

        if incident is None or incident.state != IncidentState.VOTING:
            return

        if msg.performative == Performative.ACCEPT:
            incident.votes_accept += 1
            logger.info("[%s] vote ACCEPT from %s  incident=%s",
                        self.agent_id, msg.sender, incident_id)
        elif msg.performative == Performative.REJECT:
            incident.votes_reject += 1
            logger.info("[%s] vote REJECT from %s  incident=%s",
                        self.agent_id, msg.sender, incident_id)

    # ------------------------------------------------------------------
    # Intention 5 — resolve and execute
    # ------------------------------------------------------------------

    async def _resolve(self, incident: Incident) -> None:
        incident.state       = IncidentState.RESOLVED
        incident.resolved_at = time.monotonic()

        passed = incident.votes_accept > incident.votes_reject

        if passed:
            # Mark segment in cooldown so we don't re-escalate immediately
            self._cooldown[incident.segment] = incident.resolved_at

            # Build enforcement_target so RAA / EnforcementStub knows exactly
            # which resource to apply the action to
            enforcement_target: dict = {}
            evidence = incident.source_report.get("evidence", {})
            if incident.action == "BLOCK_SOURCE_IP":
                src_ip = evidence.get("src_ip", "")
                if src_ip:
                    enforcement_target["src_ip"] = src_ip
            elif incident.action == "QUARANTINE_SEGMENT":
                enforcement_target["segment"] = incident.segment

            resolution = {
                "incident_id":        incident.incident_id,
                "segment":            incident.segment,
                "classification":     incident.classification,
                "action":             incident.action,
                "confidence":         incident.confidence,
                "votes_accept":       incident.votes_accept,
                "votes_reject":       incident.votes_reject,
                "outcome":            "EXECUTED",
                "decided_by":         self.agent_id,
                "duration_ms":        round(
                    (incident.resolved_at - incident.opened_at) * 1000
                ),
                "enforcement_target": enforcement_target,
            }

            await self.publish(
                topic        = Topic.RESOLUTION,
                performative = Performative.INFORM,
                content      = resolution,
            )

            logger.info(
                "[%s] RESOLVED  incident=%s  action=%-20s  "
                "votes=%d/%d  time=%dms",
                self.agent_id, incident.incident_id, incident.action,
                incident.votes_accept,
                incident.votes_accept + incident.votes_reject,
                resolution["duration_ms"],
            )

        else:
            await self.publish(
                topic        = Topic.RESOLUTION,
                performative = Performative.FAILURE,
                content      = {
                    "incident_id": incident.incident_id,
                    "segment":     incident.segment,
                    "outcome":     "REJECTED",
                    "votes_accept": incident.votes_accept,
                    "votes_reject": incident.votes_reject,
                },
            )
            logger.info("[%s] REJECTED  incident=%s  votes %d/%d",
                        self.agent_id, incident.incident_id,
                        incident.votes_accept,
                        incident.votes_accept + incident.votes_reject)

        self.resolutions.append({
            "incident_id": incident.incident_id,
            "segment":     incident.segment,
            "action":      incident.action,
            "outcome":     "EXECUTED" if passed else "REJECTED",
            "votes_accept": incident.votes_accept,
            "votes_reject": incident.votes_reject,
        })

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def executed_resolutions(self) -> list[dict]:
        return [r for r in self.resolutions if r["outcome"] == "EXECUTED"]

    def total_incidents(self) -> int:
        return len(self._incidents)
