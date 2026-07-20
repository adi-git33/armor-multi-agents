"""
Part 7 Test  |  Threat Intelligence Agent (TIA)
================================================
Checks:
  1.  TIA detects MULTI_SEGMENT_SCAN — same src_ip on two different segments
  2.  Threat-intel message has all required fields
  3.  TIA auto-votes ACCEPT on a coalition CFP from RCA
  4.  TIA + RCA end-to-end: multi-segment scan escalates to resolution
  5.  Resolution enforcement_target carries the correct src_ip
  6.  TIA detects COORDINATED_DDOS — DDOS on two different segments
  7.  Pattern cooldown prevents re-publishing the same pattern within 30 s
  8.  TIA vote content includes intel_count reflecting known history

Design note
-----------
Checks 1-3 test TIA in isolation (no RCA).
Checks 4-5 test TIA + RCA + EnforcementStub together (full chain).
Checks 6-8 focus on specific TIA behaviours.

All injected threat-reports use confidence=0.75 (above MIN_CONFIDENCE=0.70
but below HIGH_CONFIDENCE=0.85, with only 1 report per segment) so RCA's
own self-trigger does NOT fire alone — escalation must come from TIA.
"""

import asyncio

from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic
from agents.tia import (
    ThreatIntelligenceAgent,
    COORDINATED_DDOS_THRESHOLD,
)
from agents.rca import ResponseCoordinatorAgent, VOTE_WINDOW
from simulation.enforcement import EnforcementStub

REQUIRED_INTEL_FIELDS = {
    "pattern_type", "classification", "affected_segments",
    "primary_segment", "confidence", "recommended_action", "evidence",
}

MID_CONF   = 0.75   # above MIN but below HIGH → RCA alone won't act
SCANNER_IP = "10.0.0.99"


def _scan_report(segment: str, src_ip: str = SCANNER_IP, confidence: float = MID_CONF):
    """Inject a PORT_SCAN threat-report (as ACA would publish)."""
    return Message(
        performative = Performative.INFORM,
        sender       = "ACA:sim",
        topic        = Topic.THREAT_REPORTS,
        content      = {
            "segment":            segment,
            "classification":     "PORT_SCAN",
            "confidence":         confidence,
            "severity":           0.6,
            "recommended_action": "BLOCK_SOURCE_IP",
            "source_alert":       "PORT_SCAN",
            "evidence": {
                "src_ip":          src_ip,
                "port_count":      5,
                "alert_count_30s": 1,
                "filter":          "layer2_model",
            },
        },
    )


def _ddos_report(segment: str, confidence: float = MID_CONF):
    """Inject a DDOS threat-report (as ACA would publish)."""
    return Message(
        performative = Performative.INFORM,
        sender       = "ACA:sim",
        topic        = Topic.THREAT_REPORTS,
        content      = {
            "segment":            segment,
            "classification":     "DDOS",
            "confidence":         confidence,
            "severity":           0.8,
            "recommended_action": "QUARANTINE_SEGMENT",
            "source_alert":       "VOLUME_SPIKE",
            "evidence":           {"alert_count_30s": 1},
        },
    )


async def test_threat_intelligence_agent() -> None:
    print("=" * 65)
    print("  Part 7 Test  |  Threat Intelligence Agent (TIA)")
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

    # ── 1-3: TIA in isolation ─────────────────────────────────────────
    print("\n  -- Checks 1-3: TIA pattern detection and coalition voting --")
    bus = MessageBus()
    tia = ThreatIntelligenceAgent("TIA:1", bus)

    intel_msgs:   list[dict] = []
    vote_msgs:    list[dict] = []
    vote_perfs:   list[Performative] = []

    async def on_intel(msg): intel_msgs.append(msg.content)
    async def on_vote(msg):
        vote_msgs.append(msg.content)
        vote_perfs.append(msg.performative)

    await bus.start()
    await tia.start()
    bus.subscribe(Topic.THREAT_INTEL, on_intel)
    bus.subscribe(Topic.VOTES,        on_vote)

    # Two PORT_SCAN reports from the same IP on different segments
    await bus.publish(_scan_report("seg-alpha"))
    await bus.publish(_scan_report("seg-beta"))
    await asyncio.sleep(0.3)

    multi_scan = next(
        (m for m in intel_msgs if m.get("pattern_type") == "MULTI_SEGMENT_SCAN"), {}
    )

    check(
        "TIA detects MULTI_SEGMENT_SCAN (same src_ip on two segments)",
        bool(multi_scan),
        f"intel_msgs received: {len(intel_msgs)}  "
        f"pattern: '{multi_scan.get('pattern_type')}'  "
        f"segments: {multi_scan.get('affected_segments')}",
    )
    check(
        "Threat-intel has all required fields",
        REQUIRED_INTEL_FIELDS.issubset(multi_scan.keys()),
        f"missing: {REQUIRED_INTEL_FIELDS - multi_scan.keys()}",
    )

    # Simulate RCA sending a CFP for the incident
    fake_cfp = Message(
        performative = Performative.CALL_FOR_PROPOSAL,
        sender       = "RCA:sim",
        topic        = Topic.COALITION,
        content      = {
            "incident_id":     "test-abc",
            "segment":         "seg-alpha",
            "classification":  "PORT_SCAN",
            "proposed_action": "BLOCK_SOURCE_IP",
            "confidence":      0.93,
            "deadline_secs":   2.0,
        },
    )
    await bus.publish(fake_cfp)
    await asyncio.sleep(0.3)

    check(
        "TIA auto-votes ACCEPT on coalition CFP",
        len(vote_perfs) >= 1 and vote_perfs[0] == Performative.ACCEPT,
        f"votes received: {len(vote_perfs)}  "
        f"performative: {vote_perfs[0].value if vote_perfs else 'none'}",
    )

    await tia.stop()
    await bus.stop()

    # ── 4-5: TIA + RCA end-to-end ─────────────────────────────────────
    print("\n  -- Checks 4-5: TIA + RCA full chain (multi-segment scan) --")
    bus = MessageBus()
    tia = ThreatIntelligenceAgent("TIA:2", bus)
    rca = ResponseCoordinatorAgent("RCA:2", bus)
    stub = EnforcementStub(bus)

    resolutions: list[dict] = []
    async def on_res(msg): resolutions.append(msg.content)

    await bus.start()
    await tia.start()
    await rca.start()
    await stub.start()
    bus.subscribe(Topic.RESOLUTION, on_res)

    # Two moderate-confidence PORT_SCAN reports → RCA alone won't act
    # TIA detects multi-segment pattern → threat-intel → RCA escalates
    await bus.publish(_scan_report("net-dmz",      src_ip=SCANNER_IP))
    await bus.publish(_scan_report("net-internal", src_ip=SCANNER_IP))
    await asyncio.sleep(VOTE_WINDOW + 0.5)

    resolution = next(
        (r for r in resolutions if r.get("action") == "BLOCK_SOURCE_IP"), {}
    )

    check(
        "TIA+RCA: multi-segment scan escalates to resolution",
        bool(resolution),
        f"resolutions: {len(resolutions)}  "
        f"outcome: '{resolution.get('outcome')}'  "
        f"action: '{resolution.get('action')}'",
    )
    et = resolution.get("enforcement_target", {})
    check(
        f"Resolution enforcement_target has correct src_ip ({SCANNER_IP})",
        et.get("src_ip") == SCANNER_IP,
        f"enforcement_target: {et}",
    )

    await tia.stop()
    await rca.stop()
    await bus.stop()

    # ── 6: COORDINATED_DDOS ───────────────────────────────────────────
    print("\n  -- Check 6: COORDINATED_DDOS detection --")
    bus = MessageBus()
    tia = ThreatIntelligenceAgent("TIA:3", bus)

    ddos_intel: list[dict] = []
    async def on_ddos_intel(msg):
        if msg.content.get("pattern_type") == "COORDINATED_DDOS":
            ddos_intel.append(msg.content)

    await bus.start()
    await tia.start()
    bus.subscribe(Topic.THREAT_INTEL, on_ddos_intel)

    await bus.publish(_ddos_report("corp-web"))
    await bus.publish(_ddos_report("corp-api"))
    await asyncio.sleep(0.3)

    di = ddos_intel[0] if ddos_intel else {}
    check(
        "TIA detects COORDINATED_DDOS across two segments",
        bool(di) and len(di.get("affected_segments", [])) >= COORDINATED_DDOS_THRESHOLD,
        f"intel received: {len(ddos_intel)}  "
        f"affected_segments: {di.get('affected_segments')}",
    )

    await tia.stop()
    await bus.stop()

    # ── 7: pattern cooldown ───────────────────────────────────────────
    print("\n  -- Check 7: pattern cooldown prevents duplicate publication --")
    bus = MessageBus()
    tia = ThreatIntelligenceAgent("TIA:4", bus)

    cooldown_intel: list[dict] = []
    async def on_cool(msg): cooldown_intel.append(msg.content)

    await bus.start()
    await tia.start()
    bus.subscribe(Topic.THREAT_INTEL, on_cool)

    # First pair → should publish
    await bus.publish(_scan_report("zone-a", src_ip="10.1.1.1"))
    await bus.publish(_scan_report("zone-b", src_ip="10.1.1.1"))
    await asyncio.sleep(0.2)
    count_after_first = len(cooldown_intel)

    # Immediately repeat same IP on same segments → cooldown should suppress
    await bus.publish(_scan_report("zone-a", src_ip="10.1.1.1"))
    await bus.publish(_scan_report("zone-b", src_ip="10.1.1.1"))
    await asyncio.sleep(0.2)
    count_after_second = len(cooldown_intel)

    check(
        "Pattern cooldown suppresses duplicate publication within 30 s",
        count_after_first == 1 and count_after_second == 1,
        f"intel after 1st pair={count_after_first}  after 2nd pair={count_after_second}",
    )

    await tia.stop()
    await bus.stop()

    # ── 8: vote content includes intel_count ─────────────────────────
    print("\n  -- Check 8: TIA vote carries intel_count from its history --")
    bus = MessageBus()
    tia = ThreatIntelligenceAgent("TIA:5", bus)

    votes8: list[dict] = []
    async def on_vote8(msg): votes8.append(msg.content)

    await bus.start()
    await tia.start()
    bus.subscribe(Topic.VOTES, on_vote8)

    # Give TIA some history on "monitored-seg"
    await bus.publish(_scan_report("monitored-seg", src_ip="10.2.2.2"))
    await asyncio.sleep(0.1)

    # Now send a CFP for that segment
    cfp = Message(
        performative = Performative.CALL_FOR_PROPOSAL,
        sender       = "RCA:sim",
        topic        = Topic.COALITION,
        content      = {
            "incident_id":     "intel-check",
            "segment":         "monitored-seg",
            "classification":  "PORT_SCAN",
            "proposed_action": "BLOCK_SOURCE_IP",
            "confidence":      0.90,
            "deadline_secs":   2.0,
        },
    )
    await bus.publish(cfp)
    await asyncio.sleep(0.2)

    v = votes8[0] if votes8 else {}
    check(
        "TIA vote includes intel_count > 0 when it has history for the segment",
        v.get("intel_count", 0) >= 1,
        f"intel_count: {v.get('intel_count')}  reason: '{v.get('reason')}'",
    )

    await tia.stop()
    await bus.stop()

    # ── summary ───────────────────────────────────────────────────────
    print()
    print(f"  Overall: {'ALL PASS' if all_ok else 'SOME FAILURES'}")
    print("=" * 65)
    assert all_ok, "one or more checks failed — see output above"
