"""
Response Coordinator Agent  (SDD §4.4)
=======================================
Coordinates the defensive response once a threat is confirmed.

Responsibilities
-----------------
1. Receive high-confidence threat reports (from ACA via threat-reports topic).
2. Deliberate — check corroborating evidence before acting.
3. Select a proportional action via the THROTTLE → BLOCK/QUARANTINE
   escalation ladder (FR-13; see _select_action).
4. Voted actions (QUARANTINE only): initiate a coalition vote — publish
   CALL_FOR_PROPOSAL to the coalition topic, collect ACCEPT/REJECT votes,
   decide by majority. Non-voted actions (THROTTLE/BLOCK/LOG) execute
   immediately — no coalition round-trip (SDD 4.3.1 Respond To Threat).
5. Publish the decision to the resolution topic and log it.

Temporary self-trigger
-----------------------
Until TIA (Part 7) is built, RCA also subscribes to threat-reports directly
and initiates coalitions itself.  When TIA takes over the triggering role,
this path remains as a fallback — two triggers are harmless because the
per-segment cooldown deduplicates them.

Proportional response ladder (FR-13)
--------------------------------------
Each classification has a 2-tier escalation ladder (see ESCALATION_ACTIONS).
A segment starts at level 0 (least disruptive) and only climbs to level 1
if a new confirmed threat for the same segment/classification arrives
within ESCALATION_WINDOW of the last action *and* is not weaker than the
last one — i.e., the lower tier visibly failed to stop the attack.

A TIA-corroborated incident (stronger, cross-segment evidence — it only
fires when 2+ segments already show the same pattern) bypasses the ladder
and acts at the top tier immediately. A single-report confidence bypass
was considered but dropped: empirically, ACA's classifier confidence for
DDOS is highly volatile per-sample (observed swinging between 0.68 and
1.00 across consecutive samples of the *same* attack, uncorrelated with
attack intensity), so it is not a controllable or meaningful proxy for
"how severe is this" — using it as an escalation-bypass trigger would
make ladder behavior effectively random rather than proportional.

BDI roles
----------
Beliefs  : recent threat reports per segment (60 s window)
           cooldown state per segment
           per-segment mitigation/escalation state (level, action, when)
           open incidents awaiting votes
Desires  : act on every real threat, at the least disruptive sufficient tier
Intention: _on_threat_report() → _deliberate() → _select_action() →
           _call_vote() | _execute_immediate()
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

# ── proportional response ladder (FR-13) ───────────────────────────────
# Least-disruptive-first escalation per classification. DDoS skips a
# BLOCK tier entirely: FR-24 randomizes botnet source IPs, so blocking a
# single IP is provably ineffective against a distributed attack — the
# only sensible two-tier ladder for DDoS is THROTTLE then QUARANTINE.
ESCALATION_ACTIONS: dict[str, list[str]] = {
    "DDOS":      ["THROTTLE_SEGMENT",   "QUARANTINE_SEGMENT"],
    "PORT_SCAN": ["THROTTLE_SOURCE_IP", "BLOCK_SOURCE_IP"],
    "NOISE":     ["LOG_ONLY"],
}

# Must exceed TMA's own ALERT_COOLDOWN (5.0 s) — that is the earliest a
# second alert for the same segment can even be published, so anything
# at or below it would make escalation structurally impossible to trigger.
ESCALATION_WINDOW = 8.0

# Only the top rung of each ladder is "high-risk" per SRS §6.4 — only
# QUARANTINE requires a coalition vote before executing.
VOTED_ACTIONS = {"QUARANTINE_SEGMENT"}

# Deprecated alias kept for backward compatibility (e.g. validate_rca.py
# imports ACTIONS directly). Resolves to each ladder's level-0 action.
ACTIONS = {cls: ladder[0] for cls, ladder in ESCALATION_ACTIONS.items()}


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
    level:          int = 0          # escalation-ladder rung (0 = least disruptive)
    state:          IncidentState = IncidentState.DELIBERATING
    votes_accept:   int = 0
    votes_reject:   int = 0
    opened_at:      float = field(default_factory=time.monotonic)
    resolved_at:    float = 0.0
    source_report:  dict  = field(default_factory=dict)


class ResponseCoordinatorAgent(BaseAgent):

    def __init__(self, agent_id: str, bus: MessageBus,
                 naive_ladder: bool = False, naive_voting: bool = False) -> None:
        super().__init__(agent_id, bus)

        # Baseline/ablation flags (BASELINE_VS_ADVANCED_VALIDATION_PLAN_V2 §4.1).
        # Both default False → zero behavior change vs. pre-existing code.
        self.naive_ladder = naive_ladder
        self.naive_voting = naive_voting

        # BDI Beliefs
        self._history:  dict[str, list[dict]] = {}   # segment → recent reports
        self._cooldown: dict[str, float]      = {}   # segment → last resolution time
        self._incidents: dict[str, Incident]  = {}   # incident_id → Incident

        # Per-segment escalation/mitigation state for the proportional
        # response ladder (FR-13): {"level", "classification", "confidence",
        # "acted_at"}. Populated by _select_action().
        self._mitigation_state: dict[str, dict] = {}

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

        # Filter: cooldown — but keep listening if the segment hasn't yet
        # reached the top of its escalation ladder (FR-13). A silent,
        # blanket cooldown would prevent proportional escalation from ever
        # being observed; only suppress once nothing higher is left to try.
        if (now - self._cooldown.get(seg, 0.0) < RESOLUTION_COOLDOWN
                and self._at_max_level(seg, clf)):
            logger.debug("[%s] cooldown active (max level) for segment %s",
                         self.agent_id, seg)
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
        TIA has already cross-corroborated threats across segments — this
        is strictly stronger evidence than a single ACA report (it only
        fires when 2+ segments already show the same pattern), so it
        bypasses the escalation ladder outright and acts at the top tier
        immediately, same as a single CRITICAL_CONFIDENCE report.
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

        # Cooldown — but let cross-segment-corroborated intel through if
        # the segment hasn't reached the top of its ladder yet (FR-13).
        if (now - self._cooldown.get(seg, 0.0) < RESOLUTION_COOLDOWN
                and self._at_max_level(seg, clf)):
            logger.debug(
                "[%s] cooldown active (max level) for segment %s (intel path)",
                self.agent_id, seg,
            )
            return

        action, level = self._select_action(seg, clf, conf, now, bypass=True)

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
            level          = level,
            source_report  = source_report,
        )
        self._incidents[incident.incident_id] = incident

        logger.info(
            "[%s] intel-triggered  pattern=%-22s  seg=%-15s  conf=%.2f  action=%s",
            self.agent_id, c.get("pattern_type", "?"), seg, conf, action,
        )

        if action in VOTED_ACTIONS and not self.naive_voting:
            await self._call_vote(incident)
        else:
            await self._execute_immediate(incident)

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
        action, level  = self._select_action(seg, classification, confidence, now)

        incident = Incident(
            incident_id    = str(uuid.uuid4())[:8],
            segment        = seg,
            classification = classification,
            confidence     = confidence,
            action         = action,
            level          = level,
            source_report  = report,
        )
        self._incidents[incident.incident_id] = incident

        logger.info(
            "[%s] action selected  seg=%-15s  classification=%-10s  level=%d  action=%s",
            self.agent_id, seg, classification, level, action,
        )

        if action in VOTED_ACTIONS and not self.naive_voting:
            await self._call_vote(incident)
        else:
            await self._execute_immediate(incident)

    # ------------------------------------------------------------------
    # Proportional response ladder (FR-13)
    # ------------------------------------------------------------------

    def _select_action(
        self, seg: str, classification: str, confidence: float, now: float,
        *, bypass: bool = False,
    ) -> tuple[str, int]:
        """
        Choose the least-disruptive-sufficient action for this segment and
        classification, and record the resulting mitigation state.

        bypass=True (TIA cross-segment corroboration) skips straight to the
        top of the ladder. Otherwise, escalate one level only if the segment
        is already mid-ladder within ESCALATION_WINDOW *and* the new report
        is no weaker than the one that triggered the last action — i.e.
        there is some evidence the lower tier didn't stop the attack, not
        just that another alert happened to arrive.
        """
        ladder = ESCALATION_ACTIONS.get(classification)
        if not ladder:
            return "INVESTIGATE", 0

        if bypass or self.naive_ladder:
            level = len(ladder) - 1
        else:
            state = self._mitigation_state.get(seg)
            if (
                state
                and state["classification"] == classification
                and now - state["acted_at"] <= ESCALATION_WINDOW
                and confidence >= state["confidence"]
            ):
                level = min(state["level"] + 1, len(ladder) - 1)
            else:
                level = 0

        self._mitigation_state[seg] = {
            "level":          level,
            "classification": classification,
            "confidence":     confidence,
            "acted_at":       now,
        }
        return ladder[level], level

    def _at_max_level(self, seg: str, classification: str) -> bool:
        """True if this segment has already escalated to the top of its
        ladder for this classification — nothing left to try, so the
        cooldown should suppress further re-evaluation."""
        ladder = ESCALATION_ACTIONS.get(classification)
        state  = self._mitigation_state.get(seg)
        if not ladder or not state or state["classification"] != classification:
            return False
        return state["level"] >= len(ladder) - 1

    @staticmethod
    def _build_enforcement_target(action: str, segment: str, evidence: dict) -> dict:
        """Build the enforcement_target dict so RAA knows exactly which
        resource (segment or source IP) to apply the action to."""
        target: dict = {}
        if action in ("BLOCK_SOURCE_IP", "THROTTLE_SOURCE_IP"):
            src_ip = evidence.get("src_ip", "")
            if src_ip:
                target["src_ip"] = src_ip
        elif action in ("QUARANTINE_SEGMENT", "THROTTLE_SEGMENT"):
            target["segment"] = segment
        return target

    async def _execute_immediate(self, incident: Incident) -> None:
        """
        Execute a non-voted action (THROTTLE / BLOCK / LOG / INVESTIGATE)
        immediately — no CFP, no coalition round-trip. Per SDD 4.3.1
        Respond To Threat: "if action == QUARANTINE → initiate_voting();
        else → execute_action() immediately." Mirrors _resolve()'s
        EXECUTED branch with a single self-approved vote and ~0 ms duration.
        """
        incident.state        = IncidentState.RESOLVED
        incident.votes_accept = 1
        incident.votes_reject = 0
        incident.resolved_at  = time.monotonic()

        self._cooldown[incident.segment] = incident.resolved_at

        evidence = incident.source_report.get("evidence", {})
        enforcement_target = self._build_enforcement_target(
            incident.action, incident.segment, evidence
        )

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
            "escalation_level":   incident.level,
        }

        await self.publish(
            topic        = Topic.RESOLUTION,
            performative = Performative.INFORM,
            content      = resolution,
        )

        logger.info(
            "[%s] EXECUTED (immediate)  incident=%s  action=%-20s  "
            "level=%d  time=%dms",
            self.agent_id, incident.incident_id, incident.action,
            incident.level, resolution["duration_ms"],
        )

        self.resolutions.append({
            "incident_id": incident.incident_id,
            "segment":     incident.segment,
            "action":      incident.action,
            "outcome":     "EXECUTED",
            "votes_accept": incident.votes_accept,
            "votes_reject": incident.votes_reject,
        })

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
            evidence = incident.source_report.get("evidence", {})
            enforcement_target = self._build_enforcement_target(
                incident.action, incident.segment, evidence
            )

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
                "escalation_level":   incident.level,
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
