"""
Part 8 Test  |  Resource Allocator Agent (RAA)
================================================
Checks:
  1.  Single BLOCK_SOURCE_IP resolution -> RAA grants FIREWALL resource
  2.  Grant message has all required fields
  3.  RAA records the blocked IP in its enforcement state
  4.  Fill FIREWALL capacity (3 grants) — all granted within capacity
  5.  4th request with HIGHER bid than existing -> evicts weakest, gets granted
  6.  4th request with LOWER bid than all existing -> denied
  7.  QUARANTINE_SEGMENT resolution -> granted from QUARANTINE pool (not FIREWALL)
  8.  LOG_ONLY resolution -> always granted, does not consume FIREWALL capacity
  9.  Coalition CFP with free capacity -> RAA votes ACCEPT
  10. Coalition CFP against a full pool -> RAA votes REJECT (would be denied) or
      ACCEPT (would win eviction), matching the same bid comparison as _allocate

Bid value is derived implicitly:
    bid = confidence × (votes_accept / total_votes)

All injected messages are crafted resolution/CFP messages (as RCA would publish).
No traffic generator or full agent stack needed.
"""

import asyncio
import uuid

from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic
from agents.raa import (
    ResourceAllocatorAgent,
    RESOURCE_CAPACITY,
    REQUIRED_GRANT_FIELDS,
)

# ── helper ────────────────────────────────────────────────────────────

def _resolution(
    segment:            str,
    action:             str,
    confidence:         float,
    enforcement_target: dict | None = None,
    votes_accept:       int = 1,
    votes_reject:       int = 0,
) -> Message:
    clf = {
        "BLOCK_SOURCE_IP":    "PORT_SCAN",
        "QUARANTINE_SEGMENT": "DDOS",
        "LOG_ONLY":           "NOISE",
    }.get(action, "UNKNOWN")

    return Message(
        performative = Performative.INFORM,
        sender       = "RCA:sim",
        topic        = Topic.RESOLUTION,
        content      = {
            "incident_id":        str(uuid.uuid4())[:8],
            "segment":            segment,
            "classification":     clf,
            "action":             action,
            "confidence":         confidence,
            "votes_accept":       votes_accept,
            "votes_reject":       votes_reject,
            "outcome":            "EXECUTED",
            "decided_by":         "RCA:sim",
            "duration_ms":        2100,
            "enforcement_target": enforcement_target or {},
        },
    )


def _cfp(incident_id: str, action: str, confidence: float, segment: str = "vote-seg") -> Message:
    return Message(
        performative = Performative.CALL_FOR_PROPOSAL,
        sender       = "RCA:sim",
        topic        = Topic.COALITION,
        content      = {
            "incident_id":     incident_id,
            "segment":         segment,
            "classification":  "DDOS",
            "proposed_action": action,
            "confidence":      confidence,
            "deadline_secs":   0.3,
        },
    )


# ── test ──────────────────────────────────────────────────────────────

async def test_resource_allocator_agent() -> None:
    print("=" * 65)
    print("  Part 8 Test  |  Resource Allocator Agent (RAA)")
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

    # ── 1-3: single grant ─────────────────────────────────────────────
    print("\n  -- Checks 1-3: single BLOCK_SOURCE_IP grant --")
    bus = MessageBus()
    raa = ResourceAllocatorAgent("RAA:1", bus)

    grants1: list[dict] = []
    async def on_grant1(msg):
        if msg.content.get("outcome") == "GRANTED":
            grants1.append(msg.content)

    await bus.start()
    await raa.start()
    bus.subscribe(Topic.RESOURCE_GRANTS, on_grant1)

    SCANNER_IP = "10.5.5.5"
    await bus.publish(_resolution(
        segment            = "public-facing",
        action             = "BLOCK_SOURCE_IP",
        confidence         = 0.90,
        enforcement_target = {"src_ip": SCANNER_IP},
    ))
    await asyncio.sleep(0.3)

    g = grants1[0] if grants1 else {}
    check(
        "Single BLOCK_SOURCE_IP resolution -> RAA grants FIREWALL resource",
        g.get("outcome") == "GRANTED" and g.get("resource_type") == "FIREWALL",
        f"outcome: '{g.get('outcome')}'  resource_type: '{g.get('resource_type')}'  "
        f"bid_value: {g.get('bid_value')}",
    )
    check(
        "Grant message has all required fields",
        REQUIRED_GRANT_FIELDS.issubset(g.keys()),
        f"missing: {REQUIRED_GRANT_FIELDS - g.keys()}",
    )
    check(
        f"RAA records blocked IP ({SCANNER_IP}) in enforcement state",
        raa.is_blocked(SCANNER_IP),
        f"blocked_ips: {raa.blocked_ips}",
    )

    await raa.stop()
    await bus.stop()

    # ── 4: fill FIREWALL capacity (3 grants) ──────────────────────────
    print(f"\n  -- Check 4: fill FIREWALL capacity ({RESOURCE_CAPACITY['FIREWALL']}) --")
    bus = MessageBus()
    raa = ResourceAllocatorAgent("RAA:2", bus)

    all_grants4: list[dict] = []
    async def on_g4(msg):
        if msg.content.get("outcome") == "GRANTED":
            all_grants4.append(msg.content)

    await bus.start()
    await raa.start()
    bus.subscribe(Topic.RESOURCE_GRANTS, on_g4)

    LOW_BID_CONF = 0.80   # bid = 0.80 × 1.0 = 0.80

    for i in range(RESOURCE_CAPACITY["FIREWALL"]):
        await bus.publish(_resolution(
            segment            = f"seg-{i}",
            action             = "BLOCK_SOURCE_IP",
            confidence         = LOW_BID_CONF,
            enforcement_target = {"src_ip": f"10.1.1.{i}"},
        ))

    await asyncio.sleep(0.3)

    check(
        f"All {RESOURCE_CAPACITY['FIREWALL']} BLOCK_SOURCE_IP requests granted "
        f"when within capacity",
        len(all_grants4) == RESOURCE_CAPACITY["FIREWALL"]
        and raa.used_capacity("FIREWALL") == RESOURCE_CAPACITY["FIREWALL"],
        f"grants={len(all_grants4)}  "
        f"used={raa.used_capacity('FIREWALL')}/{RESOURCE_CAPACITY['FIREWALL']}",
    )

    # ── 5: 4th request with HIGHER bid -> evicts weakest ───────────────
    print("\n  -- Check 5: 4th request (high bid) -> evicts weakest existing --")
    evictions5: list[dict] = []
    grants5:    list[dict] = []

    async def on_g5(msg):
        if msg.content.get("outcome") == "GRANTED":
            grants5.append(msg.content)
        elif msg.content.get("outcome") == "EVICTED":
            evictions5.append(msg.content)

    bus.subscribe(Topic.RESOURCE_GRANTS, on_g5)

    HIGH_BID_CONF = 0.95  # bid = 0.95 > 0.80 -> beats all existing

    await bus.publish(_resolution(
        segment            = "priority-seg",
        action             = "BLOCK_SOURCE_IP",
        confidence         = HIGH_BID_CONF,
        enforcement_target = {"src_ip": "10.99.99.99"},
    ))
    await asyncio.sleep(0.3)

    check(
        "4th request with higher bid evicts weakest and is granted",
        len(evictions5) == 1 and len(grants5) == 1
        and grants5[0].get("bid_value", 0) > evictions5[0].get("bid_value", 1),
        f"evictions={len(evictions5)}  new_grants={len(grants5)}  "
        f"new_bid={grants5[0].get('bid_value') if grants5 else '?'}  "
        f"evicted_bid={evictions5[0].get('bid_value') if evictions5 else '?'}",
    )

    await raa.stop()
    await bus.stop()

    # ── 6: 4th request with LOWER bid -> denied ────────────────────────
    print("\n  -- Check 6: 4th request (low bid) -> denied --")
    bus = MessageBus()
    raa = ResourceAllocatorAgent("RAA:3", bus)

    denials6: list[dict] = []
    async def on_g6(msg):
        if msg.content.get("outcome") == "DENIED":
            denials6.append(msg.content)

    await bus.start()
    await raa.start()
    bus.subscribe(Topic.RESOURCE_GRANTS, on_g6)

    # Fill capacity with HIGH bids
    for i in range(RESOURCE_CAPACITY["FIREWALL"]):
        await bus.publish(_resolution(
            segment            = f"hseg-{i}",
            action             = "BLOCK_SOURCE_IP",
            confidence         = 0.92,
            enforcement_target = {"src_ip": f"10.2.2.{i}"},
        ))
    await asyncio.sleep(0.2)

    # 4th with LOW bid -> should be denied
    await bus.publish(_resolution(
        segment            = "low-priority",
        action             = "BLOCK_SOURCE_IP",
        confidence         = 0.71,   # bid = 0.71 < 0.92
        enforcement_target = {"src_ip": "10.0.0.1"},
    ))
    await asyncio.sleep(0.3)

    d = denials6[0] if denials6 else {}
    check(
        "4th request with lower bid is denied (cannot beat existing pool)",
        len(denials6) == 1 and d.get("outcome") == "DENIED",
        f"denials={len(denials6)}  "
        f"denied_bid={d.get('bid_value')}  reason='{d.get('reason', '')[:60]}'",
    )

    await raa.stop()
    await bus.stop()

    # ── 7: QUARANTINE resource (separate pool) ─────────────────────────
    print("\n  -- Check 7: QUARANTINE_SEGMENT uses its own resource pool --")
    bus = MessageBus()
    raa = ResourceAllocatorAgent("RAA:4", bus)

    grants7: list[dict] = []
    async def on_g7(msg):
        if msg.content.get("outcome") == "GRANTED":
            grants7.append(msg.content)

    await bus.start()
    await raa.start()
    bus.subscribe(Topic.RESOURCE_GRANTS, on_g7)

    # Fill FIREWALL completely
    for i in range(RESOURCE_CAPACITY["FIREWALL"]):
        await bus.publish(_resolution(
            segment            = f"fw-{i}",
            action             = "BLOCK_SOURCE_IP",
            confidence         = 0.88,
            enforcement_target = {"src_ip": f"10.3.3.{i}"},
        ))

    # Now send a QUARANTINE — should still be granted (different pool)
    QUARANTINE_SEG = "corp-dmz"
    await bus.publish(_resolution(
        segment            = QUARANTINE_SEG,
        action             = "QUARANTINE_SEGMENT",
        confidence         = 0.91,
        enforcement_target = {"segment": QUARANTINE_SEG},
    ))
    await asyncio.sleep(0.3)

    quarantine_grant = next(
        (g for g in grants7 if g.get("resource_type") == "QUARANTINE"), {}
    )
    check(
        "QUARANTINE_SEGMENT granted from its own pool even when FIREWALL is full",
        quarantine_grant.get("outcome") == "GRANTED"
        and raa.is_quarantined(QUARANTINE_SEG)
        and raa.used_capacity("FIREWALL") == RESOURCE_CAPACITY["FIREWALL"],
        f"quarantine_granted={bool(quarantine_grant)}  "
        f"quarantined={raa.is_quarantined(QUARANTINE_SEG)}  "
        f"firewall_used={raa.used_capacity('FIREWALL')}/{RESOURCE_CAPACITY['FIREWALL']}",
    )

    await raa.stop()
    await bus.stop()

    # ── 8: LOG_ONLY never consumes FIREWALL capacity ───────────────────
    print("\n  -- Check 8: LOG_ONLY granted without touching FIREWALL capacity --")
    bus = MessageBus()
    raa = ResourceAllocatorAgent("RAA:5", bus)

    grants8: list[dict] = []
    async def on_g8(msg):
        if msg.content.get("outcome") == "GRANTED":
            grants8.append(msg.content)

    await bus.start()
    await raa.start()
    bus.subscribe(Topic.RESOURCE_GRANTS, on_g8)

    await bus.publish(_resolution(
        segment    = "noise-seg",
        action     = "LOG_ONLY",
        confidence = 0.90,
    ))
    await asyncio.sleep(0.3)

    log_grant = next(
        (g for g in grants8 if g.get("resource_type") == "LOG"), {}
    )
    check(
        "LOG_ONLY is always granted and uses LOG resource (not FIREWALL)",
        log_grant.get("outcome") == "GRANTED"
        and log_grant.get("resource_type") == "LOG"
        and raa.used_capacity("FIREWALL") == 0,
        f"log_granted={bool(log_grant)}  "
        f"resource_type='{log_grant.get('resource_type')}'  "
        f"firewall_used={raa.used_capacity('FIREWALL')}",
    )

    await raa.stop()
    await bus.stop()

    # ── 9-10: coalition voting on capacity forecast ────────────────────
    print("\n  -- Checks 9-10: RAA votes on coalition CFPs based on capacity forecast --")
    bus = MessageBus()
    raa = ResourceAllocatorAgent("RAA:6", bus)

    votes9: list[dict] = []
    async def on_vote9(msg):
        votes9.append({**msg.content, "performative": msg.performative})

    await bus.start()
    await raa.start()
    bus.subscribe(Topic.VOTES, on_vote9)

    # Free QUARANTINE capacity -> ACCEPT
    await bus.publish(_cfp("VOTE-1", "QUARANTINE_SEGMENT", confidence=0.80))
    await asyncio.sleep(0.3)

    v1 = next((v for v in votes9 if v.get("incident_id") == "VOTE-1"), None)
    check(
        "RAA votes ACCEPT on CFP when the resource pool has free capacity",
        v1 is not None and v1.get("performative") == Performative.ACCEPT,
        f"vote = {v1}",
    )

    # Fill QUARANTINE capacity with high-bid grants
    for i in range(RESOURCE_CAPACITY["QUARANTINE"]):
        await bus.publish(_resolution(
            segment    = f"qseg-{i}",
            action     = "QUARANTINE_SEGMENT",
            confidence = 0.92,
        ))
    await asyncio.sleep(0.2)

    # Low-confidence CFP against a full pool -> would be denied -> REJECT
    await bus.publish(_cfp("VOTE-2", "QUARANTINE_SEGMENT", confidence=0.60))
    await asyncio.sleep(0.3)
    v2 = next((v for v in votes9 if v.get("incident_id") == "VOTE-2"), None)
    check(
        "RAA votes REJECT on CFP when pool is full and proposal would be denied",
        v2 is not None and v2.get("performative") == Performative.REJECT,
        f"vote = {v2}",
    )

    # High-confidence CFP against a full pool -> would win eviction -> ACCEPT
    await bus.publish(_cfp("VOTE-3", "QUARANTINE_SEGMENT", confidence=0.99))
    await asyncio.sleep(0.3)
    v3 = next((v for v in votes9 if v.get("incident_id") == "VOTE-3"), None)
    check(
        "RAA votes ACCEPT on CFP when pool is full but proposal would win eviction",
        v3 is not None and v3.get("performative") == Performative.ACCEPT,
        f"vote = {v3}",
    )

    await raa.stop()
    await bus.stop()

    # ── summary ───────────────────────────────────────────────────────
    print()
    print(f"  Overall: {'ALL PASS' if all_ok else 'SOME FAILURES'}")
    print("=" * 65)
    assert all_ok, "one or more checks failed — see output above"
