"""
TIA Validation Test
====================
Validates the Threat Intelligence Agent across four test sections:

  [A] Core Pattern Detection   - MULTI_SEGMENT_SCAN, COORDINATED_DDOS, isolation checks
  [B] Timing & Boundaries      - 30 s DDoS window expiry, 30 s pattern cooldown
  [C] Intel Content Quality    - confidence, fields, src_ip, recommended_action
  [D] Coalition Voting         - always ACCEPT, intel_count, incident_id round-trip

Expected runtime: ~65 s  (Section B1 performs a real 31 s wait)

Usage
-----
    cd backend
    pytest tests/test_tia.py
"""

from __future__ import annotations
import asyncio
import time

from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic
from agents.tia import (
    ThreatIntelligenceAgent,
    INTEL_WINDOW,
    COORDINATED_DDOS_WINDOW,
    PATTERN_COOLDOWN,
    PATTERN_CONFIDENCE,
)

# ── Segment identifiers (matching the real NetworkTopology) ────────────
SEG_PUBLIC   = "public-facing"
SEG_INTERNAL = "internal"
SEG_SERVER   = "server"
SEG_SECMON   = "sec-mon"

# Synthetic attacker IPs
FAKE_IP_A = "45.33.32.156"   # primary scanner
FAKE_IP_B = "198.51.100.77"  # second scanner (different IP)

W = 68   # output line width


# ── Formatting helpers ─────────────────────────────────────────────────

def sep(char: str = "=") -> None:
    print(char * W)

def header(title: str) -> None:
    print()
    sep()
    print(f"  {title}")
    sep()

def section(letter: str, title: str) -> None:
    print()
    print(f"[{letter}] {title}")
    print("-" * W)

def check(label: str, passed: bool, detail: str = "") -> bool:
    mark = "PASS" if passed else "FAIL"
    print(f"  [{mark}]  {label}")
    if detail:
        print(f"          {detail}")
    return passed

def intel_table(intel_list: list[dict]) -> None:
    if not intel_list:
        print("  (no intel published)")
        return
    hdr = (
        f"  {'#':>2}   {'Pattern':<22s}  {'Conf':5s}  "
        f"{'Segments':<26s}  {'Rec. Action':<20s}  src_ip"
    )
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for i, intel in enumerate(intel_list, 1):
        pattern = intel.get("pattern_type", "?")[:22]
        conf    = intel.get("confidence", 0)
        segs    = str(intel.get("affected_segments", []))[:26]
        action  = intel.get("recommended_action", "?")[:20]
        src_ip  = intel.get("src_ip", "N/A")
        print(
            f"  {i:2d}   {pattern:<22s}  {conf:.2f}   "
            f"{segs:<26s}  {action:<20s}  {src_ip}"
        )


# ── Bus / agent helpers ────────────────────────────────────────────────

async def make_tia() -> tuple[ThreatIntelligenceAgent, MessageBus]:
    bus = MessageBus()
    tia = ThreatIntelligenceAgent("TIA:test", bus)
    await bus.start()
    await tia.start()
    return tia, bus


async def stop_tia(tia: ThreatIntelligenceAgent, bus: MessageBus) -> None:
    await tia.stop()
    await bus.stop()


async def inject_threat(
    bus: MessageBus,
    segment: str,
    classification: str,
    src_ip: str | None = None,
    confidence: float = 0.88,
    severity: float = 0.60,
    sender: str = "ACA:mock",
) -> None:
    """Publish a synthetic ACA threat-report to the bus."""
    evidence: dict = {}
    if src_ip:
        evidence["src_ip"] = src_ip
    msg = Message(
        performative = Performative.INFORM,
        sender       = sender,
        topic        = Topic.THREAT_REPORTS,
        content      = {
            "segment":            segment,
            "classification":     classification,
            "confidence":         confidence,
            "severity":           severity,
            "recommended_action": (
                "BLOCK_SOURCE_IP" if classification == "PORT_SCAN"
                else "QUARANTINE_SEGMENT"
            ),
            "source_alert": classification,
            "evidence":     evidence,
        },
    )
    await bus.publish(msg)


async def inject_cfp(
    bus: MessageBus,
    incident_id: str,
    segment: str,
    action: str = "QUARANTINE_SEGMENT",
    sender: str = "RCA:mock",
) -> None:
    """Publish a synthetic RCA coalition CFP to the bus."""
    msg = Message(
        performative = Performative.CALL_FOR_PROPOSAL,
        sender       = sender,
        topic        = Topic.COALITION,
        content      = {
            "incident_id":    incident_id,
            "segment":        segment,
            "action":         action,
            "classification": "DDOS",
        },
    )
    await bus.publish(msg)


# ── Section A: Core Pattern Detection ─────────────────────────────────

async def run_section_a() -> tuple[int, int, list[dict], list[dict]]:
    """
    Verifies MULTI_SEGMENT_SCAN and COORDINATED_DDOS fire correctly,
    and that single-segment and different-IP scenarios produce no intel.

    Returns (passes, total, scan_intel, ddos_intel).
    """
    section("A", "Core Pattern Detection")
    results: list[bool] = []

    # ── A1: single-segment PORT_SCAN → no intel ────────────────────────
    tia, bus = await make_tia()
    await inject_threat(bus, SEG_PUBLIC, "PORT_SCAN", src_ip=FAKE_IP_A)
    await asyncio.sleep(0.5)
    results.append(check(
        "A1  single-segment PORT_SCAN produces no intel",
        len(tia.intel_published) == 0,
        f"intel count = {len(tia.intel_published)}  (expected 0)",
    ))
    await stop_tia(tia, bus)

    # ── A2: single-segment DDOS → no intel ────────────────────────────
    tia, bus = await make_tia()
    await inject_threat(bus, SEG_PUBLIC, "DDOS")
    await asyncio.sleep(0.5)
    results.append(check(
        "A2  single-segment DDOS produces no intel",
        len(tia.intel_published) == 0,
        f"intel count = {len(tia.intel_published)}  (expected 0)",
    ))
    await stop_tia(tia, bus)

    # ── A3: PORT_SCAN from two *different* IPs on two segments → no intel
    tia, bus = await make_tia()
    await inject_threat(bus, SEG_PUBLIC,   "PORT_SCAN", src_ip=FAKE_IP_A)
    await asyncio.sleep(0.1)
    await inject_threat(bus, SEG_INTERNAL, "PORT_SCAN", src_ip=FAKE_IP_B)
    await asyncio.sleep(0.5)
    results.append(check(
        "A3  different src_IPs on different segments produce no MULTI_SEGMENT_SCAN",
        len(tia.intel_published) == 0,
        f"intel count = {len(tia.intel_published)}  (expected 0 - IPs differ: {FAKE_IP_A} vs {FAKE_IP_B})",
    ))
    await stop_tia(tia, bus)

    # ── A4: same IP PORT_SCAN on 2 segments → MULTI_SEGMENT_SCAN ──────
    tia, bus = await make_tia()
    await inject_threat(bus, SEG_PUBLIC,   "PORT_SCAN", src_ip=FAKE_IP_A)
    await asyncio.sleep(0.1)
    await inject_threat(bus, SEG_INTERNAL, "PORT_SCAN", src_ip=FAKE_IP_A)
    await asyncio.sleep(0.5)
    got_pattern = tia.intel_published[0].get("pattern_type") if tia.intel_published else "—"
    results.append(check(
        "A4  same src_IP on 2 segments fires MULTI_SEGMENT_SCAN",
        len(tia.intel_published) == 1 and got_pattern == "MULTI_SEGMENT_SCAN",
        f"intel count = {len(tia.intel_published)}  pattern = {got_pattern}",
    ))
    scan_intel = list(tia.intel_published)
    await stop_tia(tia, bus)

    # ── A5: DDOS on 2 segments within 30 s → COORDINATED_DDOS ─────────
    tia, bus = await make_tia()
    await inject_threat(bus, SEG_PUBLIC, "DDOS")
    await asyncio.sleep(0.1)
    await inject_threat(bus, SEG_SERVER, "DDOS")
    await asyncio.sleep(0.5)
    got_pattern = tia.intel_published[0].get("pattern_type") if tia.intel_published else "—"
    results.append(check(
        "A5  DDOS on 2 segments within 30 s fires COORDINATED_DDOS",
        len(tia.intel_published) == 1 and got_pattern == "COORDINATED_DDOS",
        f"intel count = {len(tia.intel_published)}  pattern = {got_pattern}",
    ))
    ddos_intel = list(tia.intel_published)
    await stop_tia(tia, bus)

    print()
    print("  Published intel (A4 + A5):")
    intel_table(scan_intel + ddos_intel)

    passes = sum(results)
    total  = len(results)
    print()
    print(f"  Section A: {passes}/{total}  {'PASS' if passes == total else 'FAIL'}")
    return passes, total, scan_intel, ddos_intel


# ── Section B: Timing & Window Boundaries ─────────────────────────────

async def run_section_b() -> tuple[int, int]:
    """
    B1 — COORDINATED_DDOS_WINDOW expiry:
         DDoS on seg1, wait 31 s, DDoS on seg2 → seg1 aged out → no intel.

    B2 — PATTERN_COOLDOWN:
         Same pattern triggered twice within 30 s → only 1 intel published.
    """
    section("B", "Timing & Window Boundaries")
    results: list[bool] = []

    # ── B1: DDoS window expiry ─────────────────────────────────────────
    wait_secs = int(COORDINATED_DDOS_WINDOW) + 1   # 31 s
    print(f"  B1  COORDINATED_DDOS_WINDOW = {int(COORDINATED_DDOS_WINDOW)} s  "
          f"(injecting first DDoS, then waiting {wait_secs} s before second)")
    tia, bus = await make_tia()

    await inject_threat(bus, SEG_PUBLIC, "DDOS")
    await asyncio.sleep(0.5)   # let TIA record the first report

    print(f"      Waiting {wait_secs} s for DDoS window to expire ", end="", flush=True)
    for i in range(wait_secs):
        await asyncio.sleep(1)
        print(".", end="", flush=True)
        if (i + 1) % 10 == 0 and (i + 1) < wait_secs:
            remaining = wait_secs - (i + 1)
            print(f" {remaining}s ", end="", flush=True)
    print()

    await inject_threat(bus, SEG_SERVER, "DDOS")
    await asyncio.sleep(0.5)
    results.append(check(
        "B1  DDoS on seg1, wait 31 s, DDoS on seg2 -> no COORDINATED_DDOS",
        len(tia.intel_published) == 0,
        f"intel count = {len(tia.intel_published)}  "
        f"(expected 0: first DDoS aged out of the {int(COORDINATED_DDOS_WINDOW)} s window)",
    ))
    await stop_tia(tia, bus)

    # ── B2: pattern cooldown ───────────────────────────────────────────
    print(f"\n  B2  PATTERN_COOLDOWN = {int(PATTERN_COOLDOWN)} s  "
          f"(same MULTI_SEGMENT_SCAN triggered twice within 2 s)")
    tia, bus = await make_tia()

    # First trigger
    await inject_threat(bus, SEG_PUBLIC,   "PORT_SCAN", src_ip=FAKE_IP_A)
    await asyncio.sleep(0.1)
    await inject_threat(bus, SEG_INTERNAL, "PORT_SCAN", src_ip=FAKE_IP_A)
    await asyncio.sleep(0.5)
    count_first = len(tia.intel_published)

    # Second trigger — same IP, same segments, within cooldown
    await inject_threat(bus, SEG_PUBLIC,   "PORT_SCAN", src_ip=FAKE_IP_A)
    await asyncio.sleep(0.1)
    await inject_threat(bus, SEG_INTERNAL, "PORT_SCAN", src_ip=FAKE_IP_A)
    await asyncio.sleep(0.5)
    count_second = len(tia.intel_published)

    results.append(check(
        "B2  duplicate pattern within cooldown window published exactly once",
        count_first == 1 and count_second == 1,
        f"after 1st trigger: {count_first}  after 2nd trigger: {count_second}  (expected both = 1)",
    ))
    await stop_tia(tia, bus)

    passes = sum(results)
    total  = len(results)
    print()
    print(f"  Section B: {passes}/{total}  {'PASS' if passes == total else 'FAIL'}")
    return passes, total


# ── Section C: Intel Content Quality ──────────────────────────────────

async def run_section_c(
    scan_intel: list[dict],
    ddos_intel: list[dict],
) -> tuple[int, int]:
    """
    Inspects the intel dicts captured in Section A — no new agent needed.
    Checks confidence values, field presence, src_ip propagation,
    and recommended_action per pattern type.
    """
    section("C", "Intel Content Quality  (from Section A results)")
    results: list[bool] = []

    # ── C1: MULTI_SEGMENT_SCAN confidence ─────────────────────────────
    expected_scan_conf = PATTERN_CONFIDENCE["MULTI_SEGMENT_SCAN"]
    if scan_intel:
        conf = scan_intel[0].get("confidence", -1)
        results.append(check(
            f"C1  MULTI_SEGMENT_SCAN confidence == {expected_scan_conf}",
            abs(conf - expected_scan_conf) < 1e-9,
            f"confidence = {conf}",
        ))
    else:
        results.append(check("C1  MULTI_SEGMENT_SCAN confidence", False,
                             "no scan intel captured in Section A"))

    # ── C2: COORDINATED_DDOS confidence ───────────────────────────────
    expected_ddos_conf = PATTERN_CONFIDENCE["COORDINATED_DDOS"]
    if ddos_intel:
        conf = ddos_intel[0].get("confidence", -1)
        results.append(check(
            f"C2  COORDINATED_DDOS confidence == {expected_ddos_conf}",
            abs(conf - expected_ddos_conf) < 1e-9,
            f"confidence = {conf}",
        ))
    else:
        results.append(check("C2  COORDINATED_DDOS confidence", False,
                             "no ddos intel captured in Section A"))

    # ── C3: affected_segments lists >= 2 segments ──────────────────────
    if scan_intel:
        segs = scan_intel[0].get("affected_segments", [])
        results.append(check(
            "C3a affected_segments contains >= 2 entries for MULTI_SEGMENT_SCAN",
            len(segs) >= 2,
            f"affected_segments = {segs}",
        ))
    if ddos_intel:
        segs = ddos_intel[0].get("affected_segments", [])
        results.append(check(
            "C3b affected_segments contains >= 2 entries for COORDINATED_DDOS",
            len(segs) >= 2,
            f"affected_segments = {segs}",
        ))

    # ── C4: src_ip propagated in MULTI_SEGMENT_SCAN ───────────────────
    if scan_intel:
        src_ip = scan_intel[0].get("src_ip", "")
        results.append(check(
            "C4  src_ip propagated in MULTI_SEGMENT_SCAN intel",
            src_ip == FAKE_IP_A,
            f"src_ip = '{src_ip}'  expected = '{FAKE_IP_A}'",
        ))

    # ── C5: recommended_action per pattern ────────────────────────────
    if scan_intel:
        action = scan_intel[0].get("recommended_action", "")
        results.append(check(
            "C5a recommended_action == BLOCK_SOURCE_IP for MULTI_SEGMENT_SCAN",
            action == "BLOCK_SOURCE_IP",
            f"recommended_action = '{action}'",
        ))
    if ddos_intel:
        action = ddos_intel[0].get("recommended_action", "")
        results.append(check(
            "C5b recommended_action == QUARANTINE_SEGMENT for COORDINATED_DDOS",
            action == "QUARANTINE_SEGMENT",
            f"recommended_action = '{action}'",
        ))

    passes = sum(results)
    total  = len(results)
    print()
    print(f"  Section C: {passes}/{total}  {'PASS' if passes == total else 'FAIL'}")
    return passes, total


# ── Section D: Coalition Voting ────────────────────────────────────────

async def run_section_d() -> tuple[int, int]:
    """
    Verifies TIA always votes ACCEPT, that intel_count reflects the
    actual history depth for a segment, and that the correct incident_id
    is echoed back in the vote.
    """
    section("D", "Coalition Voting")
    results: list[bool] = []

    tia, bus = await make_tia()
    votes: list[dict] = []

    async def on_vote(msg: Message) -> None:
        votes.append(msg.content.copy())

    bus.subscribe(Topic.VOTES, on_vote)

    # Seed 3 DDOS reports on SEG_PUBLIC so TIA builds history there
    for _ in range(3):
        await inject_threat(bus, SEG_PUBLIC, "DDOS")
        await asyncio.sleep(0.1)
    await asyncio.sleep(0.3)

    # ── D1: CFP on segment WITH history ───────────────────────────────
    await inject_cfp(bus, "INC-001", SEG_PUBLIC)
    await asyncio.sleep(0.4)
    vote1 = next((v for v in votes if v.get("incident_id") == "INC-001"), None)
    results.append(check(
        "D1  CFP on segment with intel history -> ACCEPT + intel_count > 0",
        vote1 is not None and vote1.get("intel_count", 0) > 0,
        f"vote = {vote1}",
    ))

    # ── D2: CFP on segment WITHOUT history ────────────────────────────
    await inject_cfp(bus, "INC-002", SEG_SECMON)
    await asyncio.sleep(0.4)
    vote2 = next((v for v in votes if v.get("incident_id") == "INC-002"), None)
    results.append(check(
        "D2  CFP on segment with no history -> ACCEPT + intel_count == 0",
        vote2 is not None and vote2.get("intel_count", 0) == 0,
        f"vote = {vote2}",
    ))

    # ── D3: incident_id round-trips correctly ─────────────────────────
    results.append(check(
        "D3  vote echoes correct incident_id for each CFP",
        (vote1 is not None and vote1.get("incident_id") == "INC-001")
        and (vote2 is not None and vote2.get("incident_id") == "INC-002"),
        f"INC-001 received = {vote1 is not None}  INC-002 received = {vote2 is not None}",
    ))

    # ── D4: intel_count matches seeded history depth ──────────────────
    if vote1 is not None:
        count = vote1.get("intel_count", -1)
        results.append(check(
            "D4  intel_count >= 3  (3 DDOS reports were seeded on that segment)",
            count >= 3,
            f"intel_count = {count}  (seeded 3 reports on '{SEG_PUBLIC}')",
        ))

    await stop_tia(tia, bus)

    passes = sum(results)
    total  = len(results)
    print()
    print(f"  Section D: {passes}/{total}  {'PASS' if passes == total else 'FAIL'}")
    return passes, total


# ── Entry point ────────────────────────────────────────────────────────

async def test_tia_patterns() -> None:
    header("TIA Validation  |  Threat Intelligence Agent Test Suite")
    print(
        f"  INTEL_WINDOW = {int(INTEL_WINDOW)} s   "
        f"COORDINATED_DDOS_WINDOW = {int(COORDINATED_DDOS_WINDOW)} s   "
        f"PATTERN_COOLDOWN = {int(PATTERN_COOLDOWN)} s"
    )
    print(f"  Expected runtime: ~65 s  (Section B1 performs a real 31 s wait)")

    t0 = time.monotonic()

    pa, ta, scan_intel, ddos_intel = await run_section_a()
    pb, tb                         = await run_section_b()
    pc, tc                         = await run_section_c(scan_intel, ddos_intel)
    pd, td                         = await run_section_d()

    elapsed = time.monotonic() - t0
    total_p = pa + pb + pc + pd
    total_t = ta + tb + tc + td
    passed  = total_p == total_t

    print()
    sep()
    print("  FINAL SUMMARY")
    sep()
    col_w = 30
    print(f"  {'Section':<{col_w}}  {'Pass':>4s}  {'Total':>5s}  {'Result':>6s}")
    print(f"  {'-'*col_w}  {'----':>4s}  {'-----':>5s}  {'------':>6s}")
    for letter, p, t in [
        ("A  Core Pattern Detection", pa, ta),
        ("B  Timing & Boundaries",    pb, tb),
        ("C  Intel Content Quality",  pc, tc),
        ("D  Coalition Voting",       pd, td),
    ]:
        mark = "PASS" if p == t else "FAIL"
        print(f"  {letter:<{col_w}}  {p:>4d}  {t:>5d}  {mark:>6s}")
    print(f"  {'-'*col_w}  {'----':>4s}  {'-----':>5s}  {'------':>6s}")
    print(f"  {'TOTAL':<{col_w}}  {total_p:>4d}  {total_t:>5d}  {'PASS' if passed else 'FAIL':>6s}")
    print()
    print(f"  Elapsed: {elapsed:.1f} s")
    sep()

    assert passed, f"{total_p}/{total_t} checks passed — see section breakdown above"
