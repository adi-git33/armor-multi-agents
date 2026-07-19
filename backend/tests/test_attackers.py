"""
Attacker Agent Validation Test
================================
Tests DDoSAttacker and PortScanner behaviours directly — no bus, TMA,
or ACA required.  Attacks are short (2-3 s) so the full suite runs in ~15 s.

  [A] DDoSAttacker Lifecycle    - action_log fields, ramp, sustain, cleanup
  [B] DDoSAttacker Signal       - public source IPs, pps monotonicity, stop()
  [C] PortScanner Lifecycle     - log fields, probe count, unique_ports field
  [D] PortScanner Packets       - src_ip, protocol, pkt_size, port validity, seed shuffle
  [E] Multi-Attacker Stacking   - additive overlays, independent slots, full clear

Expected runtime: ~15 s

Usage
-----
    cd backend
    pytest tests/test_attackers.py
"""

from __future__ import annotations
import asyncio
import time

from simulation.attackers import DDoSAttacker, PortScanner
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator

# ── Segment used throughout ────────────────────────────────────────────
SEGMENT = "public-facing"  # baseline_mean=500, baseline_std=75

W = 68  # output line width


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


# ── Generator factory ──────────────────────────────────────────────────

def make_gen(rng_seed: int = 42) -> tuple[NetworkTopology, TrafficGenerator]:
    """Return a topology + generator.  The generator loop is NOT started —
    attackers only use the overlay dict and topology, not the sample loop."""
    topo  = NetworkTopology()
    clock = SimClock()
    gen   = TrafficGenerator(topo, clock, rng_seed=rng_seed)
    return topo, gen


# ── Section A: DDoSAttacker Lifecycle ─────────────────────────────────

async def run_section_a() -> tuple[int, int, list[dict]]:
    """
    Runs a 3 s DDoS with a 1.5 s ramp and checks the action_log for:
    correct start/end bookmarks, ramp entries, sustained entries, peak
    pps formula, and overlay cleanup.

    Returns (passes, total, action_log) so Section B can reuse the log.
    """
    section("A", "DDoSAttacker Lifecycle")
    results: list[bool] = []

    MULTIPLIER = 5.0
    RAMP_SECS  = 1.5
    DURATION   = 3.0

    topo, gen = make_gen()
    baseline  = topo.get(SEGMENT).baseline_mean       # 500 pps
    expected_peak_extra = baseline * (MULTIPLIER - 1.0)   # 2000 pps

    attacker = DDoSAttacker(
        "ddos:A", SEGMENT, gen,
        intensity_multiplier = MULTIPLIER,
        ramp_seconds         = RAMP_SECS,
        rng_seed             = 10,
    )
    await attacker.launch(DURATION)

    log           = attacker.action_log
    flood_entries = [e for e in log if e.get("action") == "flood"]
    ramp_floods   = [e for e in flood_entries if e.get("ramp_ratio", 1.0) < 1.0]
    peak_floods   = [e for e in flood_entries if e.get("ramp_ratio") == 1.0]

    # A1 — first log entry is attack_start with correct fields
    first = log[0] if log else {}
    results.append(check(
        "A1  action_log starts with attack_start  (has baseline_pps, peak_pps, multiplier)",
        first.get("action") == "attack_start"
        and "baseline_pps" in first
        and "peak_pps"     in first
        and "multiplier"   in first,
        f"first entry action='{first.get('action')}'  "
        f"baseline_pps={first.get('baseline_pps')}  "
        f"peak_pps={first.get('peak_pps')}",
    ))

    # A2 — last log entry is attack_end
    last = log[-1] if log else {}
    results.append(check(
        "A2  action_log ends with attack_end",
        last.get("action") == "attack_end",
        f"last entry action='{last.get('action')}'  "
        f"total log entries={len(log)}",
    ))

    # A3 — ramp phase: flood entries with ramp_ratio < 1.0 exist
    results.append(check(
        "A3  ramp phase: flood entries with ramp_ratio < 1.0 exist",
        len(ramp_floods) > 0,
        f"ramp floods={len(ramp_floods)}  (ramp_secs={RAMP_SECS}, interval=0.1 s)",
    ))

    # A4 — sustained phase: flood entries with ramp_ratio == 1.0 exist
    results.append(check(
        "A4  sustained phase: flood entries with ramp_ratio == 1.0 exist",
        len(peak_floods) > 0,
        f"sustained floods={len(peak_floods)}",
    ))

    # A5 — peak extra_pps matches baseline × (multiplier - 1)
    if peak_floods:
        measured_peak = max(e.get("extra_pps", 0.0) for e in peak_floods)
        results.append(check(
            f"A5  peak extra_pps == baseline x (multiplier - 1)  "
            f"({baseline} x {MULTIPLIER - 1:.0f} = {expected_peak_extra:.0f})",
            abs(measured_peak - expected_peak_extra) < 1.0,
            f"measured peak extra_pps={measured_peak:.1f}  expected={expected_peak_extra:.1f}",
        ))
    else:
        results.append(check("A5  peak extra_pps formula", False,
                             "no sustained flood entries to inspect"))

    # A6 — overlay cleared after launch returns
    residual = gen.get_attack_pps(SEGMENT)
    results.append(check(
        "A6  overlay pps == 0 after launch completes",
        residual == 0.0,
        f"residual overlay pps = {residual}",
    ))

    passes = sum(results)
    total  = len(results)
    print()
    print(f"  Section A: {passes}/{total}  {'PASS' if passes == total else 'FAIL'}")
    return passes, total, log


# ── Section B: DDoSAttacker Signal ────────────────────────────────────

async def run_section_b(section_a_log: list[dict]) -> tuple[int, int]:
    """
    Checks signal quality properties against Section A's log, then
    runs a fresh 2 s DDoS (1 s ramp) to test stop().
    """
    section("B", "DDoSAttacker Signal Integrity")
    results: list[bool] = []

    flood_entries = [e for e in section_a_log if e.get("action") == "flood"]

    # B1 — all src_ip values are in public range (first octet 1-99)
    src_ips     = [e.get("src_ip", "") for e in flood_entries]
    bad_ips     = [ip for ip in src_ips if not _is_valid_botnet_ip(ip)]
    results.append(check(
        "B1  all DDoS flood src_ips have first octet in [1, 99]  (botnet range)",
        len(bad_ips) == 0,
        f"checked {len(src_ips)} IPs  bad={len(bad_ips)}  "
        + (f"examples: {bad_ips[:3]}" if bad_ips else "all valid"),
    ))

    # B2 — extra_pps is non-decreasing during ramp phase
    ramp_entries = sorted(
        [e for e in flood_entries if e.get("ramp_ratio", 1.0) < 1.0],
        key=lambda e: e.get("elapsed_s", 0),
    )
    if len(ramp_entries) >= 2:
        violations = [
            i for i in range(len(ramp_entries) - 1)
            if ramp_entries[i]["extra_pps"] > ramp_entries[i + 1]["extra_pps"] + 1.0
        ]
        results.append(check(
            "B2  extra_pps is non-decreasing during ramp phase",
            len(violations) == 0,
            f"ramp entries checked={len(ramp_entries)}  "
            f"pps range={ramp_entries[0]['extra_pps']:.0f}-{ramp_entries[-1]['extra_pps']:.0f}  "
            f"violations={len(violations)}",
        ))
    else:
        results.append(check("B2  extra_pps monotone during ramp", False,
                             f"not enough ramp entries ({len(ramp_entries)}) to verify"))

    # B3 — stop() terminates launch before duration and clears overlay
    _, gen_b3 = make_gen()
    attacker_b3 = DDoSAttacker(
        "ddos:B3", SEGMENT, gen_b3,
        intensity_multiplier = 3.0,
        ramp_seconds         = 1.0,
        rng_seed             = 20,
    )
    t_start = time.monotonic()

    async def _stop_after_1s():
        await asyncio.sleep(1.0)
        attacker_b3.stop()

    await asyncio.gather(attacker_b3.launch(30.0), _stop_after_1s())
    elapsed = time.monotonic() - t_start

    results.append(check(
        "B3  stop() terminates launch early (elapsed < 30 s) and clears overlay",
        elapsed < 5.0 and gen_b3.get_attack_pps(SEGMENT) == 0.0,
        f"elapsed={elapsed:.2f} s  residual pps={gen_b3.get_attack_pps(SEGMENT):.1f}",
    ))

    passes = sum(results)
    total  = len(results)
    print()
    print(f"  Section B: {passes}/{total}  {'PASS' if passes == total else 'FAIL'}")
    return passes, total


def _is_valid_botnet_ip(ip: str) -> bool:
    """First octet must be in [1, 99] per BaseAttacker._random_public_ip()."""
    try:
        first_octet = int(ip.split(".")[0])
        return 1 <= first_octet <= 99
    except (ValueError, IndexError):
        return False


# ── Section C: PortScanner Lifecycle ──────────────────────────────────

async def run_section_c() -> tuple[int, int, PortScanner]:
    """
    Runs a 3 s normal-speed scan and checks the action_log structure,
    probe count, and scan_end field consistency.

    Returns the scanner for Section D to reuse.
    """
    section("C", "PortScanner Lifecycle")
    results: list[bool] = []

    PROBE_INTERVAL = 0.3
    DURATION       = 3.0
    BURST_SIZE     = 3
    SCANNER_IP     = "45.33.32.156"

    _, gen = make_gen()
    scanner = PortScanner(
        "scan:C", SEGMENT, gen,
        src_ip         = SCANNER_IP,
        burst_size     = BURST_SIZE,
        probe_interval = PROBE_INTERVAL,
        rng_seed       = 77,
    )
    await scanner.launch(DURATION)

    log           = scanner.action_log
    probe_entries = [e for e in log if e.get("action") == "probe"]
    first         = log[0]  if log else {}
    last          = log[-1] if log else {}

    # C1 — scan_start is first entry with src_ip and target_ips
    results.append(check(
        "C1  action_log starts with scan_start  (has src_ip, target_ips, port_order)",
        first.get("action") == "scan_start"
        and "src_ip"     in first
        and "target_ips" in first
        and "port_order" in first,
        f"action='{first.get('action')}'  src_ip='{first.get('src_ip')}'  "
        f"target_ips={first.get('target_ips')}",
    ))

    # C2 — scan_end is last entry with unique_ports and total_probes
    results.append(check(
        "C2  action_log ends with scan_end  (has unique_ports, total_probes)",
        last.get("action") == "scan_end"
        and "unique_ports" in last
        and "total_probes" in last,
        f"action='{last.get('action')}'  "
        f"unique_ports={last.get('unique_ports')}  "
        f"total_probes={last.get('total_probes')}",
    ))

    # C3 — probe entries each have dst_ip and port
    bad_probes = [e for e in probe_entries if "dst_ip" not in e or "port" not in e]
    results.append(check(
        "C3  every probe entry has dst_ip and port",
        len(bad_probes) == 0,
        f"probe entries={len(probe_entries)}  missing fields={len(bad_probes)}",
    ))

    # C4 — probe count is within ±2 of expected  (duration / interval)
    expected_probes = int(DURATION / PROBE_INTERVAL)
    actual_probes   = last.get("total_probes", len(probe_entries))
    results.append(check(
        f"C4  total_probes within +-2 of expected  ({DURATION}s / {PROBE_INTERVAL}s = {expected_probes})",
        abs(actual_probes - expected_probes) <= 2,
        f"total_probes={actual_probes}  expected~={expected_probes}",
    ))

    # C5 — unique_ports in scan_end matches len(set(scanner.scanned_ports))
    computed_unique = len(set(scanner.scanned_ports))
    logged_unique   = last.get("unique_ports", -1)
    results.append(check(
        "C5  unique_ports in scan_end matches len(set(scanned_ports))",
        logged_unique == computed_unique,
        f"scan_end unique_ports={logged_unique}  computed={computed_unique}",
    ))

    passes = sum(results)
    total  = len(results)
    print()
    print(f"  Section C: {passes}/{total}  {'PASS' if passes == total else 'FAIL'}")
    return passes, total, scanner


# ── Section D: PortScanner Packet Properties ──────────────────────────

async def run_section_d(scanner: PortScanner) -> tuple[int, int]:
    """
    Inspects the Packet objects deposited by the scanner from Section C,
    then runs a second 3 s scan with a different seed to verify port
    order shuffling.
    """
    section("D", "PortScanner Packet Properties")
    results: list[bool] = []

    pkts         = scanner.scan_packets
    SCANNER_IP   = "45.33.32.156"
    VALID_PORTS  = set(PortScanner.SCAN_PORTS)

    # D1 — every packet carries the configured scanner src_ip
    wrong_ip = [p for p in pkts if p.src_ip != SCANNER_IP]
    results.append(check(
        f"D1  all scan_packets have src_ip == '{SCANNER_IP}'",
        len(wrong_ip) == 0,
        f"packets checked={len(pkts)}  wrong src_ip={len(wrong_ip)}",
    ))

    # D2 — every packet has protocol=TCP and pkt_size=64 (SYN probe)
    wrong_proto = [p for p in pkts if p.protocol != "TCP"]
    wrong_size  = [p for p in pkts if p.pkt_size  != 64]
    results.append(check(
        "D2  all scan_packets have protocol='TCP' and pkt_size=64",
        len(wrong_proto) == 0 and len(wrong_size) == 0,
        f"wrong protocol={len(wrong_proto)}  wrong size={len(wrong_size)}",
    ))

    # D3 — every probed port comes from PortScanner.SCAN_PORTS
    alien_ports = [p for p in pkts if p.dst_port not in VALID_PORTS]
    results.append(check(
        "D3  all probed dst_ports are in PortScanner.SCAN_PORTS  "
        f"({len(VALID_PORTS)} defined ports)",
        len(alien_ports) == 0,
        f"packets checked={len(pkts)}  alien ports={len(alien_ports)}  "
        f"unique probed={len({p.dst_port for p in pkts})}",
    ))

    # D4 — different rng_seeds produce different port orderings
    _, gen2 = make_gen()
    scanner2 = PortScanner(
        "scan:D4", SEGMENT, gen2,
        src_ip         = SCANNER_IP,
        burst_size     = 3,
        probe_interval = 0.3,
        rng_seed       = 42,       # seed 42 != seed 77 used in Section C
    )
    await scanner2.launch(3.0)
    # Compare first 5 ports of each run
    order1 = scanner.scanned_ports[:5]
    order2 = scanner2.scanned_ports[:5]
    results.append(check(
        "D4  different rng_seeds produce different probe orderings",
        order1 != order2,
        f"seed-77 first 5 ports: {order1}\n"
        f"          seed-42 first 5 ports: {order2}",
    ))

    # D5 — packet count matches probe count in action_log
    scan_end   = next((e for e in scanner.action_log if e.get("action") == "scan_end"), {})
    log_probes = scan_end.get("total_probes", -1)
    results.append(check(
        "D5  len(scan_packets) == total_probes logged in scan_end",
        len(pkts) == log_probes,
        f"scan_packets={len(pkts)}  logged total_probes={log_probes}",
    ))

    passes = sum(results)
    total  = len(results)
    print()
    print(f"  Section D: {passes}/{total}  {'PASS' if passes == total else 'FAIL'}")
    return passes, total


# ── Section E: Multi-Attacker Stacking ────────────────────────────────

async def run_section_e() -> tuple[int, int]:
    """
    Exercises the TrafficGenerator overlay mechanism directly — no need
    for full attack durations.  Tests the additive, independent-slot
    properties that allow multiple attackers to coexist on one segment.
    """
    section("E", "Multi-Attacker Stacking  (overlay mechanism)")
    results: list[bool] = []

    _, gen = make_gen()

    # Set up two DDoS and one scanner overlay manually
    gen.add_attack_traffic(SEGMENT, "ddos:1", 1000.0)
    gen.add_attack_traffic(SEGMENT, "ddos:2",  500.0)
    gen.add_attack_traffic(SEGMENT, "scan:1",    3.0)

    # E1 — combined extra_pps is the sum of all three
    total_pps = gen.get_attack_pps(SEGMENT)
    results.append(check(
        "E1  three attacker overlays stack additively  (1000 + 500 + 3 = 1503 pps)",
        abs(total_pps - 1503.0) < 1e-9,
        f"combined pps = {total_pps:.1f}  expected = 1503.0",
    ))

    # E2 — clearing one DDoS slot leaves the other two intact
    gen.clear_attack_traffic(SEGMENT, "ddos:1")
    remaining = gen.get_attack_pps(SEGMENT)
    results.append(check(
        "E2  clearing ddos:1 leaves ddos:2 and scan:1 intact  (500 + 3 = 503 pps)",
        abs(remaining - 503.0) < 1e-9,
        f"pps after clearing ddos:1 = {remaining:.1f}  expected = 503.0",
    ))

    # E3 — clearing the scanner slot leaves only the second DDoS
    gen.clear_attack_traffic(SEGMENT, "scan:1")
    after_scanner_clear = gen.get_attack_pps(SEGMENT)
    results.append(check(
        "E3  clearing scan:1 leaves only ddos:2  (500 pps)",
        abs(after_scanner_clear - 500.0) < 1e-9,
        f"pps after clearing scan:1 = {after_scanner_clear:.1f}  expected = 500.0",
    ))

    # E4 — clearing the last slot returns pps to 0
    gen.clear_attack_traffic(SEGMENT, "ddos:2")
    final_pps = gen.get_attack_pps(SEGMENT)
    results.append(check(
        "E4  all overlays cleared: attack pps returns to 0",
        final_pps == 0.0,
        f"final pps = {final_pps}",
    ))

    # E5 — concurrent DDoS run: two attackers launch simultaneously,
    #      combined overlay pps > either one alone at peak
    _, gen2 = make_gen()
    baseline  = NetworkTopology().get(SEGMENT).baseline_mean

    ddos_a = DDoSAttacker("ddos:Ea", SEGMENT, gen2, intensity_multiplier=3.0,
                          ramp_seconds=0.5, rng_seed=1)
    ddos_b = DDoSAttacker("ddos:Eb", SEGMENT, gen2, intensity_multiplier=2.0,
                          ramp_seconds=0.5, rng_seed=2)

    peak_samples: list[float] = []

    async def _sample_peak():
        await asyncio.sleep(1.0)  # sample after both have reached peak
        peak_samples.append(gen2.get_attack_pps(SEGMENT))

    await asyncio.gather(
        ddos_a.launch(2.0),
        ddos_b.launch(2.0),
        _sample_peak(),
    )
    # At peak: ddos_a adds baseline×2=1000 pps, ddos_b adds baseline×1=500 pps
    expected_combined = baseline * (3.0 - 1.0) + baseline * (2.0 - 1.0)
    sample = peak_samples[0] if peak_samples else 0.0
    results.append(check(
        f"E5  concurrent DDoS: combined peak pps near {expected_combined:.0f}  "
        f"(baseline={baseline:.0f} x (2 + 1))",
        abs(sample - expected_combined) < 50.0,
        f"sampled combined pps={sample:.1f}  expected~={expected_combined:.1f}  "
        f"tolerance=50 pps",
    ))
    # Verify cleanup after concurrent launch
    residual = gen2.get_attack_pps(SEGMENT)
    results.append(check(
        "E6  overlay fully cleared after both concurrent attacks finish",
        residual == 0.0,
        f"residual pps = {residual}",
    ))

    passes = sum(results)
    total  = len(results)
    print()
    print(f"  Section E: {passes}/{total}  {'PASS' if passes == total else 'FAIL'}")
    return passes, total


# ── Entry point ────────────────────────────────────────────────────────

async def test_attacker_behaviors() -> None:
    header("Attacker Agent Validation  |  DDoSAttacker + PortScanner")
    print(f"  Target segment : '{SEGMENT}'  (baseline 500 pps, std 75)")
    print(f"  Expected runtime: ~15 s")

    t0 = time.monotonic()

    pa, ta, a_log     = await run_section_a()
    pb, tb            = await run_section_b(a_log)
    pc, tc, scanner_c = await run_section_c()
    pd, td            = await run_section_d(scanner_c)
    pe, te            = await run_section_e()

    elapsed = time.monotonic() - t0
    total_p = pa + pb + pc + pd + pe
    total_t = ta + tb + tc + td + te
    passed  = total_p == total_t

    print()
    sep()
    print("  FINAL SUMMARY")
    sep()
    col_w = 34
    print(f"  {'Section':<{col_w}}  {'Pass':>4}  {'Total':>5}  {'Result':>6}")
    print(f"  {'-'*col_w}  {'----':>4}  {'-----':>5}  {'------':>6}")
    for letter, p, t in [
        ("A  DDoSAttacker Lifecycle",   pa, ta),
        ("B  DDoSAttacker Signal",      pb, tb),
        ("C  PortScanner Lifecycle",    pc, tc),
        ("D  PortScanner Packets",      pd, td),
        ("E  Multi-Attacker Stacking",  pe, te),
    ]:
        mark = "PASS" if p == t else "FAIL"
        print(f"  {letter:<{col_w}}  {p:>4}  {t:>5}  {mark:>6}")
    print(f"  {'-'*col_w}  {'----':>4}  {'-----':>5}  {'------':>6}")
    print(f"  {'TOTAL':<{col_w}}  {total_p:>4}  {total_t:>5}  {'PASS' if passed else 'FAIL':>6}")
    print()
    print(f"  Elapsed: {elapsed:.1f} s")
    sep()

    assert passed, f"{total_p}/{total_t} checks passed — see section breakdown above"
