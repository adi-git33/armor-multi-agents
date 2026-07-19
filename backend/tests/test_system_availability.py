"""
System Availability Test  (Validation §V-SYS-01)
==================================================
Metric
------
  Availability = (Total Time - Disrupted Time) / Total Time >= 99.0 %

  Disrupted Time = sum of per-attack exposure windows, where each
  exposure window is the gap between attack injection and the first
  THREAT_REPORT whose classification matches the attack type
  (DDOS or PORT_SCAN).  Once ACA publishes a matching report the
  system is "aware" and the exposure window closes.

  If an attack is never classified correctly within its duration,
  the entire attack duration counts as disrupted time.

Pipeline under test
-------------------
  TrafficGenerator --> TMA (ALERTS) --> ACA (THREAT_REPORTS)

Attack schedule  (staggered across all 4 network segments)
----------------------------------------------------------
  t=  0 s  warmup begins — TMA builds rolling baseline
  t= 10 s  warmup ends
  t= 10-20 s  cooldown buffer — initial noise-alert cooldowns drain
  t≥ 20 s  ATK-1   DDoS 10x   public-facing  (20 s, ramp 1 s)
  t= 46 s  ATK-2   PORT_SCAN  public-facing  (20 s, probe 0.2 s)
  t≥ 72 s  ATK-3   DDoS 12x   internal       (20 s, ramp 1 s)
  t= 98 s  ATK-4   PORT_SCAN  server          (20 s, probe 0.2 s)
  t≥124 s  ATK-5   DDoS 15x   sec-mon         (20 s, ramp 1 s)
  t≤300 s  quiet monitoring period

Expected runtime: 300 s  (5 minutes)

Usage
-----
    cd backend
    pytest tests/test_system_availability.py
"""

from __future__ import annotations

from validation.system_availability import (
    ATTACK_PLAN,
    AVAIL_TARGET,
    BUFFER_SECS,
    TOTAL_TIME,
    WARMUP_SECS,
    run_system_availability_test,
)

import logging
logging.basicConfig(level=logging.WARNING)

W = 70


def sep(char: str = "=") -> None:
    print(char * W)


async def test_system_availability() -> None:
    sep()
    print("  System Availability Test  (Validation §V-SYS-01)")
    sep()
    print(f"  Metric    : (Total - Disrupted) / Total >= {AVAIL_TARGET*100:.0f}%")
    print(f"  Disrupted : attack-start to first matching THREAT_REPORT per attack")
    print(f"  Total Time: {TOTAL_TIME:.0f} s   Warmup: {WARMUP_SECS:.0f} s"
          f"   Cooldown buffer: {BUFFER_SECS:.0f} s")
    print(f"  Attacks   : {len(ATTACK_PLAN)}"
          f"  (DDoS x{sum(1 for a in ATTACK_PLAN if a['type']=='DDOS')},"
          f"  PortScan x{sum(1 for a in ATTACK_PLAN if a['type']=='PORT_SCAN')})")
    print(f"  Pipeline  : TrafficGenerator -> TMA -> ACA")
    sep()
    print()

    result = await run_system_availability_test(verbose=True)

    print()
    sep()
    print("  AVAILABILITY BREAKDOWN")
    sep()
    print()
    print(f"  {'ID':<7} {'Segment':<17} {'Type':<11} {'t_start':>8}"
          f"  {'Dur':>4}  {'Latency':>9}  {'Disrupted':>10}  Status")
    print(f"  {'-'*7} {'-'*17} {'-'*11} {'-'*8}"
          f"  {'-'*4}  {'-'*9}  {'-'*10}  {'-'*11}")

    for atk in result.attacks:
        actual_t = (f"{atk.t_start_offset:5.1f} s"
                    if atk.t_start_offset is not None else "  —")
        if atk.t_start is None:
            row_status = "NOT LAUNCHED"
            row_latency = "—"
            row_disrupt = f"{atk.duration:.1f} s"
        elif atk.detected:
            lag = atk.t_detect - atk.t_start  # type: ignore[operator]
            row_status = "DETECTED"
            row_latency = f"{lag:.3f} s"
            row_disrupt = f"{lag:.3f} s"
        else:
            row_status = "!!! UNDETECTED"
            row_latency = "—"
            row_disrupt = f"{atk.duration:.1f} s  (full)"

        print(f"  {atk.id:<7} {atk.segment:<17} {atk.attack_type:<11}"
              f" {actual_t:>8}"
              f"  {atk.duration:>3.0f}s  {row_latency:>9}  {row_disrupt:>10}  {row_status}")

    print()
    print(f"  {'Total disrupted time':<35}: {result.t_disrupted:.3f} s")
    print(f"  {'Total simulation time':<35}: {result.total_time:.1f} s")
    print(f"  {'Quiet / unattacked time':<35}: "
          f"{result.total_time - sum(a.duration for a in result.attacks):.1f} s")

    print()
    sep()
    print("  AVAILABILITY CALCULATION")
    sep()
    print()
    print(f"  ({result.total_time:.1f} - {result.t_disrupted:.3f}) / {result.total_time:.1f}"
          f"  =  {result.availability*100:.3f} %")
    print()

    mark = "PASS" if result.passed else "FAIL"
    cmp = ">=" if result.passed else "<"
    print(f"  [{mark}]  System availability {result.availability*100:.3f}%"
          f"  {cmp}  {AVAIL_TARGET*100:.1f}% threshold")

    if not result.passed:
        shortfall = AVAIL_TARGET - result.availability
        needed_total = result.t_disrupted / (1.0 - AVAIL_TARGET)
        print()
        print(f"  Shortfall: {shortfall*100:.3f} percentage points")
        print(f"  To reach {AVAIL_TARGET*100:.0f}% with same disrupted time,"
              f" total simulation must be >= {needed_total:.0f} s.")
        print(f"  Alternatively: reduce attack count or increase attack intensity")
        print(f"  to shorten detection latency.")

    print()
    sep()
    assert result.passed, (
        f"availability {result.availability*100:.3f}% < {AVAIL_TARGET*100:.1f}% threshold"
    )
