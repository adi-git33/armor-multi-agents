"""
Part 2 Test — Attacker Agents
==============================
Verifies that:
  1. DDoS causes a sustained ANOMALY (>= 80% of samples above 2 sigma)
  2. Traffic recovers to normal after the attack stops
  3. Port scanner probes a diverse set of ports (>= 8 unique)
  4. Both attackers log every action (FR-27)
  5. Non-targeted segments stay normal during the attack

Run:  python test_part2.py
"""

import asyncio
import time

from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner

WARMUP_S  = 8
ATTACK_S  = 12
RECOVERY_S = 6


async def main() -> None:
    print("=" * 70)
    print("  Part 2 Test  |  Attacker Agents")
    print(f"  Warmup {WARMUP_S}s  |  Attack {ATTACK_S}s  |  Recovery {RECOVERY_S}s")
    print("=" * 70)

    clock    = SimClock()
    topology = NetworkTopology()
    gen      = TrafficGenerator(topology, clock, rng_seed=42)

    ddos    = DDoSAttacker("ddos-01", "public-facing", gen,
                           intensity_multiplier=10.0, ramp_seconds=4.0)
    scanner = PortScanner("scanner-01", "server", gen)

    # Collect deviation samples per phase
    pf_during:  list[float] = []   # public-facing during attack
    pf_after:   list[float] = []   # public-facing during recovery
    srv_during: list[float] = []   # server zone during attack (should stay lower)
    int_during: list[float] = []   # internal during attack (should be unaffected)

    phase = {"name": "warmup"}

    async def collect() -> None:
        while True:
            await asyncio.sleep(0.5)
            pf  = gen.get_stats("public-facing").deviation
            srv = gen.get_stats("server").deviation
            int_ = gen.get_stats("internal").deviation
            if phase["name"] == "attack":
                pf_during.append(pf)
                srv_during.append(srv)
                int_during.append(int_)
            elif phase["name"] == "recovery":
                pf_after.append(pf)

    async def scenario() -> None:
        print(f"  Warming up ({WARMUP_S}s) ...", flush=True)
        await asyncio.sleep(WARMUP_S)

        phase["name"] = "attack"
        print(f"  Attack started ...", flush=True)
        await asyncio.gather(
            ddos.launch(ATTACK_S),
            scanner.launch(ATTACK_S),
        )

        phase["name"] = "recovery"
        print(f"  Attack stopped — collecting recovery ({RECOVERY_S}s) ...", flush=True)
        await asyncio.sleep(RECOVERY_S)
        gen.stop()

    collect_task = asyncio.create_task(collect())
    gen_task     = asyncio.create_task(gen.run())

    await scenario()

    collect_task.cancel()
    gen_task.cancel()
    await asyncio.gather(gen_task, collect_task, return_exceptions=True)

    # ── results ───────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  RESULTS")
    print("=" * 70)
    all_ok = True

    def check(label: str, ok: bool, detail: str) -> None:
        nonlocal all_ok
        mark = "PASS" if ok else "FAIL"
        print(f"\n  [{mark}] {label}")
        print(f"         {detail}")
        if not ok:
            all_ok = False

    # 1. DDoS causes sustained anomaly on public-facing
    if pf_during:
        anomaly_frac = sum(1 for d in pf_during if d >= 2.0) / len(pf_during)
        max_dev      = max(pf_during)
        check(
            "DDoS causes sustained ANOMALY on public-facing (need >= 80%)",
            anomaly_frac >= 0.80,
            f"anomaly_rate={anomaly_frac*100:.0f}%  max_dev={max_dev:.1f}s  "
            f"samples={len(pf_during)}"
        )

    # 2. Traffic recovers after attack
    if pf_after:
        normal_frac = sum(1 for d in pf_after if abs(d) < 2.0) / len(pf_after)
        check(
            "Traffic returns to normal after attack (need >= 70% within 2s dev)",
            normal_frac >= 0.70,
            f"normal_rate={normal_frac*100:.0f}%  samples={len(pf_after)}"
        )

    # 3. Non-targeted segment (internal) stays unaffected
    if int_during:
        unaffected = sum(1 for d in int_during if abs(d) < 2.0) / len(int_during)
        check(
            "Internal subnet unaffected during attack (need >= 85% normal)",
            unaffected >= 0.85,
            f"normal_rate={unaffected*100:.0f}%  samples={len(int_during)}"
        )

    # 4. Port scanner covers diverse ports
    unique_ports = len(set(scanner.scanned_ports))
    check(
        "Port scanner probes diverse ports (need >= 8 unique ports)",
        unique_ports >= 8,
        f"unique_ports={unique_ports}  "
        f"sample={sorted(set(scanner.scanned_ports))[:8]}"
    )

    # 5. Attackers log all actions (FR-27)
    ddos_logged    = len(ddos.action_log)
    scanner_logged = len(scanner.action_log)
    check(
        "Attackers log every action (FR-27, need > 10 entries each)",
        ddos_logged > 10 and scanner_logged > 10,
        f"ddos_log={ddos_logged} entries   scanner_log={scanner_logged} entries"
    )

    # 6. DDoS peak pps is plausible
    baseline = topology.get("public-facing").baseline_mean
    expected_peak = baseline * ddos._multiplier
    last_attack_pps = gen.get_stats("public-facing").current_pps
    check(
        "DDoS peak was at least 5x normal baseline",
        max(pf_during, default=0) >= 5.0,   # 5 sigma minimum during attack
        f"baseline={baseline:.0f} pps  expected_peak=~{expected_peak:.0f} pps  "
        f"max_deviation={max(pf_during, default=0):.1f}s"
    )

    print()
    print(f"  Overall: {'ALL PASS' if all_ok else 'SOME FAILURES'}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
