"""
Response Coordinator Agent  (SDD §4.4)
=======================================
Coordinates the defensive response once a threat is confirmed.

Responsibilities
-----------------
1. Receive high-confidence threat reports (from ACA via threat-reports topic).
2. Deliberate — check corroborating evidence before acting.
3. Select a proportional action via the THROTTLE → BLOCK/QUARANTINE
   escalation ladder (FR-13; see _pick_action).
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

Escalation ladder (FR-13)
--------------------------
Each classification maps to an ordered list of actions (ESCALATION_ACTIONS).
The first confirmed threat picks rung 0 (least disruptive).  If a second
confirmed threat for the same segment arrives within ESCALATION_WINDOW
seconds, the next rung is used.  The full RESOLUTION_COOLDOWN is only
applied once the max rung is reached and resolved; mid-escalation reports
only need to clear a short MIN_ESCALATION_GAP debounce, so the ladder can
climb during a sustained attack. See _cooldown_allows()/_pick_action().

  DDOS:       THROTTLE_SEGMENT (rung 0) → QUARANTINE_SEGMENT (rung 1, max)
  PORT_SCAN:  BLOCK_SOURCE_IP  (rung 0, max)
  NOISE:      LOG_ONLY         (rung 0, max)

THROTTLE_SEGMENT executes immediately without a coalition vote (minimally
disruptive, must not be delayed). QUARANTINE_SEGMENT goes through the full
VOTE_WINDOW coalition vote (see VOTED_ACTIONS).

A TIA-corroborated incident (stronger, cross-segment evidence — it only
fires when 2+ segments already show the same pattern) bypasses the ladder
outright and acts at the top tier immediately, same as a single
CRITICAL_CONFIDENCE report (see _on_threat_intel / _pick_action bypass=True).

Baseline/ablation flags (BASELINE_VS_ADVANCED_VALIDATION_PLAN_V2 §4.1)
------------------------------------------------------------------------
naive_ladder=True   — _pick_action() always returns the top rung on the
                      first report, reproducing a flat, non-proportional
                      responder (no escalation wait, no "did the lower
                      tier fail" check). Does not affect the debounce/
                      cooldown gating in _cooldown_allows(), which is an
                      orthogonal anti-spam mechanism, not one of the SDD
                      §4.1-4.4 coordination mechanisms.
naive_voting=True   — even QUARANTINE_SEGMENT (the only VOTED_ACTIONS
                      member) resolves via _execute_immediate(), self-
                      approved with no CFP / VOTE_WINDOW wait.

BDI roles
----------
Beliefs  : recent threat reports per segment (60 s window)
           cooldown state per segment (last max-rung resolution time)
           escalation level per segment (ladder rung)
           open incidents awaiting votes
Desires  : act on every real threat; suppress noise and duplicates;
           escalate only when the threat persists; at the least
           disruptive sufficient tier
Intention: _on_threat_report() → _deliberate() → _pick_action() →
           _call_vote() | _execute_immediate() → _resolve()
"""

from __future__ import annotations
import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from agents.base import BaseAgent
from agents._history import append_and_expire
from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic

logger = logging.getLogger(__name__)

# ── thresholds ────────────────────────────────────────────────────────
MIN_CONFIDENCE      = 0.70   # below this → ignored entirely
HIGH_CONFIDENCE     = 0.85   # above this → single report is enough to act
MIN_CORROBORATION   = 2      # below HIGH_CONFIDENCE need this many reports in window
HISTORY_WINDOW      = 60.0   # seconds of threat-report history per segment
VOTE_WINDOW         = 0.3    # seconds to wait for external coalition votes
RESOLUTION_COOLDOWN = 30.0   # seconds before accepting a fresh (level-0) threat

# ── escalation ladder ────────────────────────────────────────────────
ESCALATION_ACTIONS: dict[str, list[str]] = {
    "DDOS":      ["THROTTLE_SEGMENT", "QUARANTINE_SEGMENT"],
    "PORT_SCAN": ["BLOCK_SOURCE_IP"],
    "NOISE":     ["LOG_ONLY"],
}

# Minimum gap between consecutive escalation steps (debounce).
MIN_ESCALATION_GAP = 1.5    # seconds

# Must exceed TMA's own ALERT_COOLDOWN (5.0 s) — that is the earliest a
# second alert for the same segment can even be published, so anything
# at or below it would make escalation structurally impossible to trigger.
ESCALATION_WINDOW = 8.0

# A QUARANTINE_SEGMENT is released as soon as the segment's traffic looks
# normal again (polled every EARLY_RELEASE_CHECK seconds via
# segment_is_normal), or unconditionally once QUARANTINE_HOLD is reached —
# whichever comes first. The hold is a fallback, not a guarantee the threat
# is gone: if it's still live, TMA/ACA will re-flag it right after release
# and RCA re-quarantines.
QUARANTINE_HOLD        = 15.0
EARLY_RELEASE_CHECK    = 1.0

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
                 naive_ladder: bool = False, naive_voting: bool = False,
                 segment_is_normal: Callable[[str], bool] | None = None) -> None:
        super().__init__(agent_id, bus)

        # Baseline/ablation flags (BASELINE_VS_ADVANCED_VALIDATION_PLAN_V2 §4.1).
        # Both default False → zero behavior change vs. pre-existing code.
        self.naive_ladder = naive_ladder
        self.naive_voting = naive_voting

        # Optional probe used only by the auto-release poll (segment →
        # "does its live traffic currently look normal?"). None (default)
        # means "no early-release signal available" — quarantine then
        # simply holds for the full QUARANTINE_HOLD every time.
        self._segment_is_normal = segment_is_normal

        # BDI Beliefs
        self._history:      dict[str, list[dict]] = {}   # segment → recent reports
        self._cooldown:     dict[str, float]      = {}   # segment → last max-rung resolution time
        self._incident_log: dict[str, Incident]   = {}   # incident_id → Incident (all states)

        # Escalation state
        self._esc_level:   dict[str, int]   = {}  # segment → current rung index
        self._last_action: dict[str, float] = {}  # segment → monotonic time of last resolved action

        # Pending auto-release timers for quarantined segments (QUARANTINE_HOLD)
        self._release_tasks: dict[str, asyncio.Task] = {}

        # Completed resolutions for introspection / testing
        self.resolutions: list[dict] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        await super().start()
        self.subscribe(Topic.THREAT_REPORTS, self._on_threat_report)
        self.subscribe(Topic.THREAT_INTEL,   self._on_threat_intel)
        self.subscribe(Topic.VOTES,          self._on_vote)
        logger.info("[%s] ready", self.agent_id)

    # ------------------------------------------------------------------
    # Cooldown helper — escalation-aware
    # ------------------------------------------------------------------

    def _cooldown_allows(self, seg: str, now: float) -> bool:
        """
        Return True if this segment may receive a (possibly escalated) action.

        Level 0 (fresh):
            Enforce the full RESOLUTION_COOLDOWN since the last max-rung action.

        Level > 0 (mid-escalation):
            If within ESCALATION_WINDOW → allow escalation immediately.
            If outside ESCALATION_WINDOW → the attack paused; reset to level 0
            and re-apply the RESOLUTION_COOLDOWN check.

        In every case a MIN_ESCALATION_GAP debounce prevents rapid duplicates.
        This gating is unaffected by naive_ladder — it's an anti-spam
        mechanism, not one of the SDD §4.1-4.4 coordination mechanisms.
        """
        last_act = self._last_action.get(seg, 0.0)

        # Always debounce rapid consecutive reports
        if now - last_act < MIN_ESCALATION_GAP:
            return False

        level = self._esc_level.get(seg, 0)

        if level == 0:
            # Fresh — no active escalation; enforce full cooldown
            return (now - self._cooldown.get(seg, 0.0)) >= RESOLUTION_COOLDOWN

        # Mid-escalation
        if now - last_act <= ESCALATION_WINDOW:
            return True   # still in window → climb the ladder

        # Window expired → treat as fresh attack; reset and re-check cooldown
        self._esc_level[seg] = 0
        return (now - self._cooldown.get(seg, 0.0)) >= RESOLUTION_COOLDOWN

    def _pick_action(self, seg: str, clf: str, *, bypass: bool = False) -> tuple[str, int]:
        """
        Return (action, level) for this segment/classification.

        bypass=True (TIA cross-segment corroboration) or naive_ladder=True
        (BASELINE_VS_ADVANCED_VALIDATION_PLAN_V2 §4.1) both skip straight to
        the top rung. Otherwise use the segment's current escalation rung
        (maintained by _cooldown_allows()/_resolve()).
        """
        levels = ESCALATION_ACTIONS.get(clf, ["LOG_ONLY"])
        if bypass or self.naive_ladder:
            level = len(levels) - 1
        else:
            level = min(self._esc_level.get(seg, 0), len(levels) - 1)
        return levels[level], level

    # ------------------------------------------------------------------
    # Intention 1 — receive ACA threat report
    # ------------------------------------------------------------------

    async def _on_threat_report(self, msg: Message) -> None:
        c   = msg.content
        seg = c.get("segment", "")
        clf = c.get("classification", "NOISE")
        conf = float(c.get("confidence", 0.0))
        now = time.monotonic()

        # Filter: ignore noise and low-confidence
        if clf == "NOISE" or conf < MIN_CONFIDENCE:
            return

        if not self._cooldown_allows(seg, now):
            logger.debug("[%s] cooldown/debounce for segment %s", self.agent_id, seg)
            return

        # Update history
        self._history[seg] = append_and_expire(
            self._history.get(seg, []), {"time": now, **c}, now, HISTORY_WINDOW
        )

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
        c   = msg.content
        seg = c.get("primary_segment", "")
        clf = c.get("classification", "")
        conf = float(c.get("confidence", 0.0))
        now = time.monotonic()

        if not seg or not clf or clf == "NOISE":
            return

        if not self._cooldown_allows(seg, now):
            logger.debug(
                "[%s] cooldown/debounce for segment %s (intel path)", self.agent_id, seg
            )
            return

        action, level = self._pick_action(seg, clf, bypass=True)

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
            incident_id    = self._short_id(),
            segment        = seg,
            classification = clf,
            confidence     = conf,
            action         = action,
            level          = level,
            source_report  = source_report,
        )
        self._incident_log[incident.incident_id] = incident

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
        action, level  = self._pick_action(seg, classification)

        incident = Incident(
            incident_id    = self._short_id(),
            segment        = seg,
            classification = classification,
            confidence     = confidence,
            action         = action,
            level          = level,
            source_report  = report,
        )
        self._incident_log[incident.incident_id] = incident

        logger.info(
            "[%s] action selected  seg=%-15s  classification=%-10s  level=%d  action=%s",
            self.agent_id, seg, classification, level, action,
        )

        if action in VOTED_ACTIONS and not self.naive_voting:
            await self._call_vote(incident)
        else:
            await self._execute_immediate(incident)

    # ------------------------------------------------------------------
    # Shared enforcement-target builder (used by both _execute_immediate
    # and _resolve so the two paths can never disagree on this mapping)
    # ------------------------------------------------------------------

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

        self._last_action[incident.segment] = incident.resolved_at
        self._advance_escalation(incident)

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

        if incident.action == "QUARANTINE_SEGMENT":
            self._schedule_release(incident.segment)

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
    # Escalation-state bookkeeping — shared by _execute_immediate and
    # _resolve so both resolution paths keep _esc_level/_cooldown in sync.
    # ------------------------------------------------------------------

    def _advance_escalation(self, incident: Incident) -> None:
        levels        = ESCALATION_ACTIONS.get(incident.classification, ["LOG_ONLY"])
        current_level = self._esc_level.get(incident.segment, 0)

        if current_level < len(levels) - 1:
            # Non-max rung: advance the ladder; no full cooldown yet so the
            # next threat can trigger the escalation within ESCALATION_WINDOW.
            self._esc_level[incident.segment] = current_level + 1
        else:
            # Max rung reached (or naive_ladder jumped straight there):
            # apply full cooldown and reset for the next attack.
            self._cooldown[incident.segment]  = incident.resolved_at
            self._esc_level[incident.segment] = 0

    # ------------------------------------------------------------------
    # Auto-release — lift a QUARANTINE_SEGMENT as soon as traffic looks
    # normal again, or after QUARANTINE_HOLD regardless
    # ------------------------------------------------------------------

    def _schedule_release(self, segment: str) -> None:
        """(Re)start the auto-release poll for a just-quarantined segment.
        A fresh QUARANTINE_SEGMENT for the same segment restarts it rather
        than stacking timers, so the release always reflects the most
        recent quarantine event."""
        old = self._release_tasks.get(segment)
        if old and not old.done():
            old.cancel()
        self._release_tasks[segment] = asyncio.create_task(
            self._release_after_hold(segment)
        )

    async def _release_after_hold(self, segment: str) -> None:
        """Poll every EARLY_RELEASE_CHECK seconds; release as soon as the
        segment's live traffic (still measured under quarantine — see
        TrafficGenerator.quarantine()) looks normal again, or once
        QUARANTINE_HOLD is reached, whichever comes first."""
        elapsed  = 0.0
        early    = False
        while elapsed < QUARANTINE_HOLD:
            await asyncio.sleep(EARLY_RELEASE_CHECK)
            elapsed += EARLY_RELEASE_CHECK
            if self._segment_is_normal and self._segment_is_normal(segment):
                early = True
                break

        self._release_tasks.pop(segment, None)

        # RESOLUTION_COOLDOWN was stamped when QUARANTINE_SEGMENT executed,
        # to stop the *original* incident from flapping — it was never meant
        # to blackout detection after the segment is already back online.
        # Clear it so a genuinely new attack right after release can be
        # acted on immediately instead of being silently dropped by
        # _cooldown_allows() for up to another RESOLUTION_COOLDOWN seconds.
        self._cooldown.pop(segment, None)

        await self.publish(
            topic        = Topic.RESOLUTION,
            performative = Performative.INFORM,
            content      = {
                "incident_id":        "",
                "segment":            segment,
                "classification":     "",
                "action":             "RELEASE_SEGMENT",
                "outcome":            "RELEASED",
                "decided_by":         self.agent_id,
                "duration_ms":        round(elapsed * 1000),
                "enforcement_target": {"segment": segment},
            },
        )
        logger.info(
            "[%s] releasing %s after %.0fs (%s)",
            self.agent_id, segment, elapsed,
            "traffic normal" if early else "hold expired",
        )

    # ------------------------------------------------------------------
    # Intention 3 — open coalition vote
    # ------------------------------------------------------------------

    async def _call_vote(self, incident: Incident) -> None:
        incident.state = IncidentState.VOTING

        # Cast RCA's own vote immediately
        incident.votes_accept += 1

        # Publish CALL_FOR_PROPOSAL so future agents (TIA, RAA) can vote
        await self.publish(
            topic        = Topic.COALITION,
            performative = Performative.CALL_FOR_PROPOSAL,
            content      = {
                "incident_id":     incident.incident_id,
                "segment":         incident.segment,
                "classification":  incident.classification,
                "proposed_action": incident.action,
                "confidence":      incident.confidence,
                "deadline_secs":   VOTE_WINDOW,
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
        c           = msg.content
        incident_id = c.get("incident_id", "")
        incident    = self._incident_log.get(incident_id)

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
            self._last_action[incident.segment] = incident.resolved_at
            self._advance_escalation(incident)

            evidence           = incident.source_report.get("evidence", {})
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

            if incident.action == "QUARANTINE_SEGMENT":
                self._schedule_release(incident.segment)

            logger.info(
                "[%s] RESOLVED  incident=%s  action=%-20s  "
                "votes=%d/%d  time=%dms  esc_level_now=%d",
                self.agent_id, incident.incident_id, incident.action,
                incident.votes_accept,
                incident.votes_accept + incident.votes_reject,
                resolution["duration_ms"],
                self._esc_level.get(incident.segment, 0),
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
        return len(self._incident_log)
