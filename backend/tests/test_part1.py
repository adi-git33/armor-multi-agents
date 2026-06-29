"""Quick self-terminating test for Part 1 — runs for 5 seconds then exits."""
import asyncio

from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator, SAMPLE_RATE
from core.models import TrafficSample

RUN_SECONDS = 5
DISPLAY_INTERVAL = 1.0
SEG_ORDER = ["public-facing", "server", "internal", "sec-mon"]


async def main():
    print("=" * 70)
    print("  Part 1 Test  |  Running for 5 seconds then auto-stopping")
    print("=" * 70)

    clock    = SimClock(speed=1.0)
    topology = NetworkTopology()
    gen      = TrafficGenerator(topology, clock, rng_seed=42)

    received: dict[str, int] = {sid: 0 for sid in SEG_ORDER}

    async def count(sample: TrafficSample):
        received[sample.segment] = received.get(sample.segment, 0) + 1

    gen.on_sample(count)

    stop_event = asyncio.Event()

    async def display():
        tick = 0
        while not stop_event.is_set():
            await asyncio.sleep(DISPLAY_INTERVAL)
            if stop_event.is_set():
                break
            tick += 1
            if tick % 5 == 1:
                print(
                    f"\n  {'Segment':<28} {'cur pps':>9} "
                    f"{'mean':>7} {'std':>6} {'dev':>8}  status"
                )
                print("  " + "-" * 68)
            all_stats = gen.get_all_stats()
            for sid in SEG_ORDER:
                st  = all_stats[sid]
                seg = topology.get(sid)
                a   = abs(st.deviation)
                status = "ANOMALY" if a >= 2.0 else ("elevated" if a >= 1.5 else "normal")
                print(
                    f"  {seg.display_name:<28} {st.current_pps:>9.1f} "
                    f"{st.baseline_mean:>7.1f} {st.baseline_std:>6.1f} "
                    f"{st.deviation:>+7.2f}s  {status}"
                )

    gen_task     = asyncio.create_task(gen.run())
    display_task = asyncio.create_task(display())

    await asyncio.sleep(RUN_SECONDS)

    gen.stop()
    stop_event.set()
    await asyncio.sleep(0.2)
    display_task.cancel()
    gen_task.cancel()
    await asyncio.gather(gen_task, display_task, return_exceptions=True)

    # ── RESULTS ──────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  RESULTS")
    print("=" * 70)
    all_ok = True

    # 1. Sample counts
    # Allow up to 1 second of startup overhead (10 samples) on top of ±1 jitter.
    # Python + asyncio task creation consistently eats ~400ms before loops start.
    expected     = SAMPLE_RATE * RUN_SECONDS   # ideal: 50
    min_expected = expected - SAMPLE_RATE       # floor: 40  (1 s startup budget)
    print(f"\n  1. Sample counts (expect {min_expected}-{expected} per segment):")
    for sid in SEG_ORDER:
        n    = received[sid]
        ok   = min_expected <= n <= expected + 1   # +1 for timing jitter on fast machines
        mark = "PASS" if ok else "FAIL"
        seg  = topology.get(sid)
        print(f"     [{mark}] {seg.display_name:<28}  samples={n:>3}  valid range [{min_expected}-{expected+1}]")
        if not ok:
            all_ok = False

    # 2. Rolling baselines
    print("\n  2. Rolling baselines (expect within 10% of configured):")
    for sid in SEG_ORDER:
        st    = gen.get_stats(sid)
        seg   = topology.get(sid)
        ratio = abs(st.baseline_mean - seg.baseline_mean) / seg.baseline_mean
        ok    = ratio < 0.10
        mark  = "PASS" if ok else "FAIL"
        print(
            f"     [{mark}] {seg.display_name:<28}  "
            f"rolling={st.baseline_mean:>7.1f}  "
            f"configured={seg.baseline_mean:>7.1f}  drift={ratio*100:.1f}%"
        )
        if not ok:
            all_ok = False

    # 3. Host registry
    print("\n  3. Host registry (expect hosts + patterns in every segment):")
    expected_hosts = {
        "public-facing": 4,    # lb-01, web-01, web-02, api-01
        "server":        5,    # app-01, app-02, db-primary, db-replica, cache-01
        "internal":      9,    # dc-01, fileserver-01, 5 workstations, 2 laptops
        "sec-mon":       3,    # siem-01, ids-01, log-collector
    }
    for sid in SEG_ORDER:
        hosts    = topology.hosts_in(sid)
        patterns = topology.patterns_for(sid)
        exp_h    = expected_hosts[sid]
        ok       = len(hosts) == exp_h and len(patterns) > 0
        mark     = "PASS" if ok else "FAIL"
        seg      = topology.get(sid)
        print(
            f"     [{mark}] {seg.display_name:<28}  "
            f"hosts={len(hosts)} (expect {exp_h})  patterns={len(patterns)}"
        )
        if not ok:
            all_ok = False

    # 4. Packet generation uses real host IPs
    print("\n  4. Packet generation (host-aware IPs):")
    for sid in SEG_ORDER:
        seg     = topology.get(sid)
        packets = gen.generate_packets(seg, 20)
        hosts   = topology.hosts_in(sid)
        host_ips= {h.ip for h in hosts}

        # dst_ip must always be a known host in this segment
        bad_dst = [p for p in packets if p.dst_ip not in host_ips]
        ok      = len(packets) == 20 and len(bad_dst) == 0
        mark    = "PASS" if ok else "FAIL"
        print(
            f"     [{mark}] {seg.display_name:<28}  "
            f"generated={len(packets)}  unknown_dst={len(bad_dst)}"
        )
        if not ok:
            all_ok = False

    print()
    print(f"  Overall: {'ALL PASS' if all_ok else 'SOME FAILURES'}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
