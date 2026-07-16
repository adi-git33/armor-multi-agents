"""
Part 6 Test  |  Response Coordinator Agent (RCA)
==================================================
Checks:
  1.  RCA publishes a resolution for a high-confidence DDoS threat
  2.  Resolution contains all required fields
  3.  Resolution action is QUARANTINE_SEGMENT for DDoS
  4.  RCA publishes CALL_FOR_PROPOSAL to coalition before resolving
  5.  RCA accepts external ACCEPT votes and counts them
  6.  RCA accepts external REJECT votes and counts them
  7.  NOISE reports are never escalated to resolution
  8.  Low-confidence (< 0.70) reports are not escalated
  9.  Cooldown prevents re-escalation on the same segment within 30 s
  10. Two corroborating moderate-confidence reports trigger escalation

Timeline
--------
  Direct message injection — no traffic generator needed.
  Each check sends crafted threat-report messages directly onto the bus
  and verifies RCA's response on the resolution / coalition topics.
"""

import asyncio
import time

from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic
from agents.rca import (
    ResponseCoordinatorAgent,
    MIN_CONFIDENCE, HIGH_CONFIDENCE, MIN_CORROBORATION,
    RESOLUTION_COOLDOWN, VOTE_WINDOW,
)
from simulation.enforcement import EnforcementStub

REQUIRED_RESOLUTION_FIELDS = {
    "incident_id", "segment", "classification",
    "action", "confidence", "votes_accept", "votes_reject",
    "outcome", "decided_by", "duration_ms", "enforcement_target",
}


def _threat(segment="public-facing", classification="DDOS",
            confidence=0.95, severity=0.9, action="QUARANTINE_SEGMENT",
            evidence: dict | None = None, source_alert: str = "VOLUME_SPIKE"):
    return Message(
        performative = Performative.INFORM,
        sender       = "ACA:1",
        topic        = Topic.THREAT_REPORTS,
        content      = {
            "segment":            segment,
            "classification":     classification,
            "confidence":         confidence,
            "severity":           severity,
            "recommended_action": action,
            "source_alert":       source_alert,
            "evidence":           evidence if evidence is not None
                                           else {"alert_count_30s": 2},
        },
    )


async def main() -> None:
    print("=" * 65)
    print("  Part 6 Test  |  Response Coordinator Agent (RCA)")
    print("=" * 65)

    all_ok = True

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal all_ok
        mark = "PASS" if ok else "FAIL"
        print(f"\n  [{mark}] {label}")
        if detail:
            print(f"         {detail}")
        if not ok:
            all_ok = False

    # ── 1-3: basic resolution for a high-confidence DDoS ─────────────
    print("\n  -- Checks 1-3: high-confidence DDoS resolution --")
    bus = MessageBus()
    rca = ResponseCoordinatorAgent("RCA:1", bus)

    resolutions: list[dict]  = []
    cfps:        list[dict]  = []

    async def on_resolution(msg): resolutions.append(msg.content)
    async def on_coalition(msg):  cfps.append(msg.content)

    await bus.start()
    await rca.start()
    bus.subscribe(Topic.RESOLUTION, on_resolution)
    bus.subscribe(Topic.COALITION,  on_coalition)

    # Escalation ladder (FR-13): the FIRST confirmed DDoS answers with the
    # least-disruptive rung (THROTTLE_SEGMENT, unvoted); a second confirmed
    # report inside ESCALATION_WINDOW climbs to QUARANTINE_SEGMENT.
    from agents.rca import MIN_ESCALATION_GAP

    await bus.publish(_threat(confidence=0.92))
    await asyncio.sleep(MIN_ESCALATION_GAP + 0.5)
    await bus.publish(_threat(confidence=0.92))
    await asyncio.sleep(VOTE_WINDOW + 0.5)

    check(
        "RCA publishes a resolution for a high-confidence DDoS",
        len(resolutions) >= 1,
        f"resolutions received: {len(resolutions)}",
    )
    r = resolutions[0] if resolutions else {}
    check(
        "Resolution contains all required fields",
        REQUIRED_RESOLUTION_FIELDS.issubset(r.keys()),
        f"missing: {REQUIRED_RESOLUTION_FIELDS - r.keys()}",
    )
    check(
        "First resolution is rung 0 (THROTTLE_SEGMENT), then escalates to QUARANTINE_SEGMENT",
        r.get("action") == "THROTTLE_SEGMENT"
        and any(x.get("action") == "QUARANTINE_SEGMENT" for x in resolutions),
        f"actions: {[x.get('action') for x in resolutions]}",
    )

    await rca.stop()
    await bus.stop()

    # ── 4-6: coalition CFP and vote counting ──────────────────────────
    print("\n  -- Checks 4-6: coalition CFP and vote counting --")
    bus = MessageBus()
    rca = ResponseCoordinatorAgent("RCA:2", bus)

    resolutions2: list[dict] = []
    cfps2:        list[dict] = []

    async def on_resolution2(msg): resolutions2.append(msg.content)
    async def on_cfp2(msg):
        cfps2.append(msg.content)
        # Simulate TIA responding with ACCEPT and a second agent with REJECT
        incident_id = msg.content.get("incident_id", "")
        accept_msg = Message(
            performative = Performative.ACCEPT,
            sender       = "TIA:1",
            topic        = Topic.VOTES,
            content      = {"incident_id": incident_id, "reason": "known threat"},
        )
        reject_msg = Message(
            performative = Performative.REJECT,
            sender       = "dummy:1",
            topic        = Topic.VOTES,
            content      = {"incident_id": incident_id, "reason": "test reject"},
        )
        await bus.publish(accept_msg)
        await bus.publish(reject_msg)

    await bus.start()
    await rca.start()
    bus.subscribe(Topic.RESOLUTION, on_resolution2)
    bus.subscribe(Topic.COALITION,  on_cfp2)

    # Two reports to climb the ladder — only the QUARANTINE rung is voted.
    await bus.publish(_threat(segment="server", confidence=0.93))
    await asyncio.sleep(MIN_ESCALATION_GAP + 0.5)
    await bus.publish(_threat(segment="server", confidence=0.93))
    await asyncio.sleep(VOTE_WINDOW + 0.5)

    check(
        "RCA publishes CALL_FOR_PROPOSAL to coalition before resolving",
        len(cfps2) >= 1 and cfps2[0].get("proposed_action") == "QUARANTINE_SEGMENT",
        f"CFPs received: {len(cfps2)}  "
        f"proposed_action: '{cfps2[0].get('proposed_action') if cfps2 else 'none'}'",
    )
    # The unvoted THROTTLE resolution lands first — judge the voted one.
    r2 = next(
        (x for x in resolutions2 if x.get("action") == "QUARANTINE_SEGMENT"), {}
    )
    check(
        "RCA counts external ACCEPT votes (RCA self + TIA = 2 accepts)",
        r2.get("votes_accept", 0) >= 2,
        f"votes_accept={r2.get('votes_accept')}  votes_reject={r2.get('votes_reject')}",
    )
    check(
        "RCA counts external REJECT votes",
        r2.get("votes_reject", 0) >= 1,
        f"votes_reject={r2.get('votes_reject')}",
    )

    await rca.stop()
    await bus.stop()

    # ── 7-8: filtering — noise and low confidence ─────────────────────
    print("\n  -- Checks 7-8: noise and low-confidence filtering --")
    bus = MessageBus()
    rca = ResponseCoordinatorAgent("RCA:3", bus)

    filtered_resolutions: list[dict] = []
    async def on_filtered(msg): filtered_resolutions.append(msg.content)

    await bus.start()
    await rca.start()
    bus.subscribe(Topic.RESOLUTION, on_filtered)

    # Send a NOISE report
    await bus.publish(_threat(
        segment="internal", classification="NOISE",
        confidence=0.85, action="LOG_ONLY",
    ))
    # Send a low-confidence report
    await bus.publish(_threat(
        segment="sec-mon", classification="DDOS",
        confidence=0.55, action="QUARANTINE_SEGMENT",
    ))
    await asyncio.sleep(VOTE_WINDOW + 0.5)

    check(
        "NOISE reports are never escalated to resolution",
        all(r.get("segment") != "internal" for r in filtered_resolutions),
        f"resolutions on 'internal': "
        f"{sum(1 for r in filtered_resolutions if r.get('segment')=='internal')}",
    )
    check(
        f"Low-confidence (< {MIN_CONFIDENCE}) reports are not escalated",
        all(r.get("segment") != "sec-mon" for r in filtered_resolutions),
        f"resolutions on 'sec-mon': "
        f"{sum(1 for r in filtered_resolutions if r.get('segment')=='sec-mon')}",
    )

    await rca.stop()
    await bus.stop()

    # ── 9: cooldown ───────────────────────────────────────────────────
    print("\n  -- Check 9: cooldown prevents re-escalation --")
    bus = MessageBus()
    rca = ResponseCoordinatorAgent("RCA:4", bus)

    cooldown_resolutions: list[dict] = []
    async def on_cooldown(msg): cooldown_resolutions.append(msg.content)

    await bus.start()
    await rca.start()
    bus.subscribe(Topic.RESOLUTION, on_cooldown)

    # First report → should resolve
    await bus.publish(_threat(segment="public-facing", confidence=0.91))
    await asyncio.sleep(VOTE_WINDOW + 0.5)
    first_count = len(cooldown_resolutions)

    # Immediate second report on same segment → cooldown should block it
    await bus.publish(_threat(segment="public-facing", confidence=0.91))
    await asyncio.sleep(VOTE_WINDOW + 0.5)
    second_count = len(cooldown_resolutions)

    check(
        "Cooldown prevents re-escalation on same segment within 30s",
        first_count == 1 and second_count == 1,
        f"resolutions after 1st report={first_count}  after 2nd report={second_count}",
    )

    await rca.stop()
    await bus.stop()

    # ── 10: corroboration ─────────────────────────────────────────────
    print("\n  -- Check 10: two moderate-confidence reports trigger escalation --")
    bus = MessageBus()
    rca = ResponseCoordinatorAgent("RCA:5", bus)

    corroboration_resolutions: list[dict] = []
    async def on_corrob(msg): corroboration_resolutions.append(msg.content)

    await bus.start()
    await rca.start()
    bus.subscribe(Topic.RESOLUTION, on_corrob)

    mid_conf = (MIN_CONFIDENCE + HIGH_CONFIDENCE) / 2   # 0.775 — between thresholds

    # First moderate report — should NOT trigger alone
    await bus.publish(_threat(segment="internal", confidence=mid_conf))
    await asyncio.sleep(0.3)
    after_first = len(corroboration_resolutions)

    # Second corroborating report — should trigger escalation
    await bus.publish(_threat(segment="internal", confidence=mid_conf))
    await asyncio.sleep(VOTE_WINDOW + 0.5)
    after_second = len(corroboration_resolutions)

    check(
        f"Single moderate-confidence ({mid_conf:.2f}) report does not escalate alone",
        after_first == 0,
        f"resolutions after 1st report: {after_first}",
    )

    # The second report should have triggered (corroborate >= MIN_CORROBORATION)
    # Note: due to VOTE_WINDOW the resolution may arrive slightly after sleep
    check(
        f"Two corroborating reports ({MIN_CORROBORATION} needed) trigger escalation",
        after_second >= 1,
        f"resolutions after 2nd report: {after_second}",
    )

    await rca.stop()
    await bus.stop()

    # ── 11-13: PORT_SCAN enforcement and DDOS quarantine ─────────────
    print("\n  -- Checks 11-13: PORT_SCAN + enforcement stub --")
    bus = MessageBus()
    rca = ResponseCoordinatorAgent("RCA:6", bus)
    stub = EnforcementStub(bus)

    scan_resolutions: list[dict] = []
    async def on_scan_res(msg): scan_resolutions.append(msg.content)

    await bus.start()
    await rca.start()
    await stub.start()
    bus.subscribe(Topic.RESOLUTION, on_scan_res)

    SCANNER_IP = "10.0.0.77"

    # High-confidence PORT_SCAN report carrying src_ip in evidence
    await bus.publish(_threat(
        segment        = "server",
        classification = "PORT_SCAN",
        confidence     = 0.91,
        action         = "BLOCK_SOURCE_IP",
        source_alert   = "PORT_SCAN",
        evidence       = {
            "alert_count_30s": 1,
            "src_ip":          SCANNER_IP,
            "port_count":      7,
            "filter":          "layer2_model",
        },
    ))

    # Also test quarantine enforcement. RCA's escalation ladder answers the
    # FIRST DDoS report with rung 0 (THROTTLE_SEGMENT); QUARANTINE_SEGMENT
    # needs a second confirmed report on the same segment inside
    # ESCALATION_WINDOW (and past the MIN_ESCALATION_GAP debounce).
    await bus.publish(_threat(
        segment        = "public-facing",
        classification = "DDOS",
        confidence     = 0.93,
        action         = "QUARANTINE_SEGMENT",
        evidence       = {"alert_count_30s": 2},
    ))
    await asyncio.sleep(MIN_ESCALATION_GAP + 0.5)
    await bus.publish(_threat(
        segment        = "public-facing",
        classification = "DDOS",
        confidence     = 0.93,
        action         = "QUARANTINE_SEGMENT",
        evidence       = {"alert_count_30s": 3},
    ))

    await asyncio.sleep(VOTE_WINDOW + 0.5)

    scan_res = next(
        (r for r in scan_resolutions if r.get("classification") == "PORT_SCAN"), {}
    )
    ddos_res = next(
        (r for r in scan_resolutions if r.get("classification") == "DDOS"), {}
    )

    check(
        "PORT_SCAN resolves with BLOCK_SOURCE_IP action",
        scan_res.get("action") == "BLOCK_SOURCE_IP",
        f"action: '{scan_res.get('action')}'  "
        f"enforcement_target: {scan_res.get('enforcement_target')}",
    )
    check(
        f"EnforcementStub blocks the scanner IP ({SCANNER_IP})",
        stub.is_blocked(SCANNER_IP),
        f"blocked_ips: {stub.blocked_ips}",
    )
    check(
        "EnforcementStub quarantines the segment for DDoS",
        stub.is_quarantined("public-facing"),
        f"quarantined_segments: {stub.quarantined_segments}",
    )

    await rca.stop()
    await bus.stop()

    # ── summary ───────────────────────────────────────────────────────
    print()
    print(f"  Overall: {'ALL PASS' if all_ok else 'SOME FAILURES'}")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(main())
