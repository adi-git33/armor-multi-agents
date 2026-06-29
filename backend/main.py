"""
Part 1 — Network Simulation
============================
Runs the four-segment network topology and traffic generator.
Prints a live stats table once per second so you can verify:
  - each segment produces traffic near its configured baseline
  - deviation stays within ±2σ for normal traffic (no attackers yet)

Press Ctrl+C to stop.
"""

import asyncio

from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from core.models import TrafficSample

DISPLAY_INTERVAL = 1.0   # seconds between table refreshes

# Segment display order
SEG_ORDER = ["public-facing", "server", "internal", "sec-mon"]

# Status thresholds (σ)
THRESHOLD_ELEVATED = 1.5
THRESHOLD_ALERT    = 2.0


def _status(deviation: float) -> str:
    a = abs(deviation)
    if a >= THRESHOLD_ALERT:
        return "!! ANOMALY !!"
    if a >= THRESHOLD_ELEVATED:
        return "  ELEVATED  "
    return "   normal   "


async def display_loop(gen: TrafficGenerator, topology: NetworkTopology) -> None:
    tick = 0
    sample_totals: dict[str, int] = {sid: 0 for sid in SEG_ORDER}

    while True:
        await asyncio.sleep(DISPLAY_INTERVAL)
        tick += 1

        # Print header every 10 rows so terminal doesn't scroll away
        if tick % 10 == 1:
            print(
                f"\n{'t':>4}  "
                f"{'Segment':<28} "
                f"{'cur pps':>9} "
                f"{'mean':>7} "
                f"{'std':>6} "
                f"{'dev':>8} "
                f"{'status'}"
            )
            print("-" * 80)

        all_stats = gen.get_all_stats()
        for sid in SEG_ORDER:
            stats = all_stats[sid]
            seg   = topology.get(sid)
            print(
                f"{tick:>4}  "
                f"{seg.display_name:<28} "
                f"{stats.current_pps:>9.1f} "
                f"{stats.baseline_mean:>7.1f} "
                f"{stats.baseline_std:>6.1f} "
                f"{stats.deviation:>+7.2f}s "
                f"{_status(stats.deviation)}"
            )
        print()


async def main() -> None:
    print("=" * 80)
    print("  Cyber-Defense Prototype  |  Part 1: Network Simulation")
    print("  Segments: 4  |  Sample rate: 10 Hz/segment  |  Display: 1 Hz")
    print("  Ctrl+C to stop")
    print("=" * 80)

    clock    = SimClock(speed=1.0)
    topology = NetworkTopology()
    gen      = TrafficGenerator(topology, clock, rng_seed=42)

    # Count total samples as a sanity-check callback
    total: dict[str, int] = {"n": 0}

    async def count_samples(sample: TrafficSample) -> None:
        total["n"] += 1

    gen.on_sample(count_samples)

    try:
        await asyncio.gather(
            gen.run(),
            display_loop(gen, topology),
        )
    except asyncio.CancelledError:
        pass
    finally:
        gen.stop()
        print(f"\n[Stopped]  Total samples received: {total['n']}")
        print(f"           Expected ~{4 * 10} per second (4 segments x 10 Hz)")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
