"""
Part 9 Test  |  Traffic Monitor Agent (TMA) 5-Min Metrics
==========================================================
Runs a 5-minute randomized traffic scenario on one segment and prints
packet totals, detection quality metrics, and alert publication latency.
"""

import asyncio
import logging
import os
from pathlib import Path
import random
import statistics
import sys
import time

# Ensure backend/ is importable regardless of current working directory.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agents.tma import TrafficMonitorAgent
from bus.message_bus import MessageBus
from core.messages import Topic
from simulation.attackers import DDoSAttacker, PortScanner
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import SAMPLE_INTERVAL, TrafficGenerator

# Reduce noisy logs so the final metric output is easy to read.
logging.basicConfig(level=logging.WARNING)

TARGET_SEGMENT = "public-facing"
TEST_DURATION_SECONDS = float(os.getenv("TMA_TEST_DURATION_SECONDS", str(5 * 60)))
RNG_SEED = 2026

# Scheduler tuning to avoid attack-dominated runs and produce a more
# production-like blend of benign vs malicious traffic.
SCHEDULER_WEIGHTS = {
    "quiet": 0.70,
    "ddos": 0.12,
    "scan": 0.12,
    "both": 0.06,
}
QUIET_WINDOW_RANGE_SECONDS = (4.0, 14.0)
ATTACK_WINDOW_RANGE_SECONDS = (3.0, 10.0)


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


async def _run_randomized_traffic(
    duration_seconds: float,
    rng: random.Random,
    generator: TrafficGenerator,
    attack_state: dict,
    attack_windows: list[tuple[float, float, str]],
) -> None:
    """
    Randomized scheduler:
      - quiet traffic windows
      - DDoS bursts
      - Port-scan bursts
      - combined bursts (DDoS + PortScan)
    """
    test_end = time.monotonic() + duration_seconds
    seq = 0

    while True:
        remaining = test_end - time.monotonic()
        if remaining <= 0:
            break

        mode = rng.choices(
            population=["quiet", "ddos", "scan", "both"],
            weights=[
                SCHEDULER_WEIGHTS["quiet"],
                SCHEDULER_WEIGHTS["ddos"],
                SCHEDULER_WEIGHTS["scan"],
                SCHEDULER_WEIGHTS["both"],
            ],
            k=1,
        )[0]

        if mode == "quiet":
            quiet_for = min(
                remaining,
                rng.uniform(*QUIET_WINDOW_RANGE_SECONDS),
            )
            await asyncio.sleep(quiet_for)
            continue

        burst_duration = min(
            remaining,
            rng.uniform(*ATTACK_WINDOW_RANGE_SECONDS),
        )
        if burst_duration <= 0:
            break

        seq += 1
        start_ts = time.monotonic()
        attack_state["active"] = True

        tasks: list[asyncio.Task] = []
        try:
            if mode in {"ddos", "both"}:
                ddos = DDoSAttacker(
                    attacker_id=f"ddos-metrics-{seq}",
                    target_segment=TARGET_SEGMENT,
                    generator=generator,
                    intensity_multiplier=rng.uniform(2.2, 5.0),
                    ramp_seconds=min(5.0, burst_duration / 2.0),
                    rng_seed=rng.randint(1, 1_000_000),
                )
                tasks.append(asyncio.create_task(ddos.launch(burst_duration)))

            if mode in {"scan", "both"}:
                scan = PortScanner(
                    attacker_id=f"scan-metrics-{seq}",
                    target_segment=TARGET_SEGMENT,
                    generator=generator,
                    src_ip="45.33.32.156",
                    burst_size=rng.randint(2, 6),
                    probe_interval=rng.uniform(0.20, 0.80),
                    rng_seed=rng.randint(1, 1_000_000),
                )
                tasks.append(asyncio.create_task(scan.launch(burst_duration)))

            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

            end_ts = time.monotonic()
            attack_windows.append((start_ts, end_ts, mode))
            attack_state["active"] = False


async def main() -> None:
    print("=" * 78)
    print("  Part 9 Test  |  TMA 5-Min Metrics")
    print("=" * 78)
    print(f"  Segment: {TARGET_SEGMENT}")
    print(f"  Duration: {TEST_DURATION_SECONDS}s")
    print(f"  Seed: {RNG_SEED}")
    if TEST_DURATION_SECONDS != 300:
        print("  NOTE: non-default duration set via TMA_TEST_DURATION_SECONDS")

    # --- infra ---
    bus = MessageBus()
    clock = SimClock()
    topology = NetworkTopology()
    generator = TrafficGenerator(topology, clock, rng_seed=42)
    tma = TrafficMonitorAgent("TMA:metrics", bus, generator)

    # --- telemetry ---
    rng = random.Random(RNG_SEED)
    attack_state = {"active": False}
    attack_windows: list[tuple[float, float, str]] = []
    sample_records: list[tuple[float, bool, int]] = []  # (ts, attack_present, packet_count)
    alert_times: list[float] = []

    overall_packets = 0
    attack_packets = 0
    legit_packets = 0

    async def on_alert(msg) -> None:
        if msg.content.get("segment") == TARGET_SEGMENT:
            alert_times.append(time.monotonic())

    async def on_sample(sample) -> None:
        nonlocal overall_packets, attack_packets, legit_packets
        if sample.segment != TARGET_SEGMENT:
            return
        now = time.monotonic()
        is_attack = bool(attack_state["active"])

        sample_records.append((now, is_attack, sample.packet_count))
        overall_packets += sample.packet_count
        if is_attack:
            attack_packets += sample.packet_count
        else:
            legit_packets += sample.packet_count

    bus_running = False
    tma_running = False
    gen_task: asyncio.Task | None = None

    test_start = time.monotonic()
    try:
        await bus.start()
        bus_running = True
        bus.subscribe(Topic.ALERTS, on_alert)

        await tma.start()
        tma_running = True
        generator.on_sample(on_sample)

        gen_task = asyncio.create_task(generator.run())
        await _run_randomized_traffic(
            duration_seconds=TEST_DURATION_SECONDS,
            rng=rng,
            generator=generator,
            attack_state=attack_state,
            attack_windows=attack_windows,
        )

        # Flush in-flight bus deliveries before metrics are computed.
        await asyncio.sleep(0.5)
    finally:
        generator.stop()
        if gen_task is not None:
            await asyncio.gather(gen_task, return_exceptions=True)
        if tma_running:
            await tma.stop()
        if bus_running:
            await bus.stop()

    elapsed = time.monotonic() - test_start

    # --- sample-level confusion matrix ---
    total_samples = len(sample_records)
    tp = tn = fp = fn = 0
    alert_idx = 0

    for i, (start_ts, attack_present, _packet_count) in enumerate(sample_records):
        end_ts = (
            sample_records[i + 1][0]
            if i + 1 < total_samples
            else start_ts + SAMPLE_INTERVAL
        )

        while alert_idx < len(alert_times) and alert_times[alert_idx] < start_ts:
            alert_idx += 1
        alert_present = (
            alert_idx < len(alert_times) and alert_times[alert_idx] < end_ts
        )

        if attack_present and alert_present:
            tp += 1
        elif attack_present and not alert_present:
            fn += 1
        elif (not attack_present) and alert_present:
            fp += 1
        else:
            tn += 1

    attack_samples = tp + fn
    detection_rate_attack = _safe_div(tp, attack_samples)

    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)

    # --- episode-level detection + anomaly-to-alert latency ---
    # One latency point per attack window: first alert in/just-after that window.
    latencies: list[float] = []
    idx = 0
    latency_slop = SAMPLE_INTERVAL

    for start_ts, end_ts, _mode in attack_windows:
        while idx < len(alert_times) and alert_times[idx] < start_ts:
            idx += 1
        if idx < len(alert_times) and alert_times[idx] <= (end_ts + latency_slop):
            latencies.append(alert_times[idx] - start_ts)
            idx += 1

    avg_latency = statistics.fmean(latencies) if latencies else 0.0
    median_latency = statistics.median(latencies) if latencies else 0.0
    min_latency = min(latencies) if latencies else 0.0
    max_latency = max(latencies) if latencies else 0.0
    detected_windows = len(latencies)
    total_windows = len(attack_windows)
    window_detection_rate = _safe_div(detected_windows, total_windows)
    missed_windows = max(0, total_windows - detected_windows)

    # --- sanity checks ---
    assert overall_packets == attack_packets + legit_packets, (
        "Packet accounting mismatch: overall != attack + legit"
    )
    assert tp + tn + fp + fn == total_samples, (
        "Confusion matrix mismatch: TP+TN+FP+FN != total_samples"
    )

    # --- output ---
    print("\n" + "-" * 78)
    print("  Requested Metrics")
    print("-" * 78)
    print(f"  Run time (actual): {elapsed:.2f}s")
    print(f"  Attack windows generated: {len(attack_windows)}")
    print(f"  Alerts observed: {len(alert_times)}")
    print()
    print(f"  1. overall packets: {overall_packets}")
    print(f"  2. number of attack packets: {attack_packets}")
    print(f"  3. number of legit packets: {legit_packets}")
    print(
        "  4. detection rate of attack packets "
        f"(sample-based): {detection_rate_attack:.4f} ({detection_rate_attack * 100:.2f}%)"
    )
    print(f"  5. TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    print(
        "  6. Accuracy={:.4f}  Precision={:.4f}  Recall/Sensitivity={:.4f}  "
        "Specificity={:.4f}".format(
            accuracy, precision, recall, specificity
        )
    )
    print(
        "  7. alert publish latency (seconds): "
        f"avg={avg_latency:.4f}  median={median_latency:.4f}  "
        f"min={min_latency:.4f}  max={max_latency:.4f}"
    )
    print()
    print("  Additional interpretation metrics")
    print(
        "  - episode detection rate (attack windows with >=1 alert): "
        f"{window_detection_rate:.4f} ({window_detection_rate * 100:.2f}%)"
    )
    print(
        "  - detected windows: "
        f"{detected_windows}/{total_windows}  (missed={missed_windows})"
    )
    print(
        "  - note: sample-based recall is intentionally strict for cooldown-based "
        "alerting and is best treated as a secondary diagnostic."
    )
    print("-" * 78)


if __name__ == "__main__":
    asyncio.run(main())
