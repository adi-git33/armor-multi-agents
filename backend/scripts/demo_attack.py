"""
Part 2 Demo — Attack Injection
================================
Timeline:
  0s  – 10s  : warmup — baseline stabilises, all normal
  10s – 30s  : DDoS floods public-facing + port scan on server zone
  30s – 38s  : recovery — attack stops, watch traffic fall back

Run:  python demo_attack.py
"""

import asyncio
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner

SEG_ORDER      = ["public-facing", "server", "internal", "sec-mon"]
WARMUP_S       = 10
ATTACK_S       = 20
RECOVERY_S     = 8
DISPLAY_EVERY  = 1.0   # seconds between table rows


def _status(dev: float) -> str:
    a = abs(dev)
    if a >= 2.0: return "!! ANOMALY !!"
    if a >= 1.5: return "  elevated  "
    return              "   normal   "


async def main() -> None:
    print("=" * 82)
    print("  Part 2 Demo  |  DDoS + Port Scan Attack")
    print(f"  Warmup {WARMUP_S}s  ->  Attack {ATTACK_S}s  ->  Recovery {RECOVERY_S}s")
    print("=" * 82)

    clock    = SimClock()
    topology = NetworkTopology()
    gen      = TrafficGenerator(topology, clock, rng_seed=42)

    ddos    = DDoSAttacker(
        "ddos-01", "public-facing", gen,
        intensity_multiplier=10.0, ramp_seconds=5.0,
    )
    scanner = PortScanner("scanner-01", "server", gen)

    phase   = {"label": "WARMUP"}
    stop_ev = asyncio.Event()

    # ── display loop ──────────────────────────────────────────────────
    async def display() -> None:
        tick = 0
        while not stop_ev.is_set():
            await asyncio.sleep(DISPLAY_EVERY)
            if stop_ev.is_set():
                break
            tick += 1

            if tick % 9 == 1:
                print(
                    f"\n  {'t':>4}  {'Segment':<28} {'pps':>7} "
                    f"{'mean':>7} {'dev':>8}   status          phase"
                )
                print("  " + "-" * 80)

            all_st = gen.get_all_stats()
            ph     = phase["label"]
            for sid in SEG_ORDER:
                st  = all_st[sid]
                seg = topology.get(sid)
                atk = gen.get_attack_pps(sid)
                atk_tag = f" [+{atk:.0f} atk]" if atk > 0 else ""
                print(
                    f"  {tick:>4}  {seg.display_name:<28} "
                    f"{st.current_pps:>7.0f} {st.baseline_mean:>7.0f} "
                    f"{st.deviation:>+7.2f}s   {_status(st.deviation)}"
                    + (f"  {ph}{atk_tag}" if sid == SEG_ORDER[0] else "")
                )

    # ── attack sequence ───────────────────────────────────────────────
    async def sequence() -> None:
        print(f"\n  [warmup]  Letting baseline stabilise for {WARMUP_S}s ...")
        await asyncio.sleep(WARMUP_S)

        phase["label"] = "ATTACK"
        print(f"\n  [ATTACK]  DDoS -> public-facing  |  Port scan -> server zone")
        print(f"            DDoS peak = 10x baseline ({topology.get('public-facing').baseline_mean * 10:.0f} pps)")

        await asyncio.gather(
            ddos.launch(ATTACK_S),
            scanner.launch(ATTACK_S),
        )

        phase["label"] = "RECOVERY"
        print(f"\n  [recovery]  Attack stopped — watching traffic return to baseline ...")
        await asyncio.sleep(RECOVERY_S)

        gen.stop()
        stop_ev.set()

    # ── run everything ────────────────────────────────────────────────
    gen_task     = asyncio.create_task(gen.run())
    display_task = asyncio.create_task(display())

    await sequence()

    await asyncio.sleep(0.3)
    display_task.cancel()
    gen_task.cancel()
    await asyncio.gather(gen_task, display_task, return_exceptions=True)

    # ── summary ───────────────────────────────────────────────────────
    print("\n" + "=" * 82)
    print("  ATTACK SUMMARY")
    print("=" * 82)

    baseline_pf = topology.get("public-facing").baseline_mean
    print(f"\n  DDoS on public-facing:")
    print(f"    Log entries   : {len(ddos.action_log)}")
    print(f"    Baseline pps  : {baseline_pf:.0f}")
    print(f"    Peak attack   : {baseline_pf * ddos._multiplier:.0f}  ({ddos._multiplier:.0f}x baseline)")
    print(f"    Ramp time     : {ddos._ramp}s")

    print(f"\n  Port scan on server zone:")
    print(f"    Log entries   : {len(scanner.action_log)}")
    print(f"    Ports probed  : {len(set(scanner.scanned_ports))} unique ports")
    print(f"    Total probes  : {len(scanner.scanned_ports)}")
    print(f"    Sample ports  : {sorted(set(scanner.scanned_ports))[:10]}")
    print(f"    Scanner IP    : {scanner._src_ip}  (fixed — easy to spot)")

    print()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
