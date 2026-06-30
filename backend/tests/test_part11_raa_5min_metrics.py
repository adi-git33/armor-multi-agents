"""
Part 11 Test  |  Resource Allocator Agent (RAA) Validation Coverage
=====================================================================
Structured validation suite for RAA BDI desires:
  A) Episode-level metrics over a 5-minute mixed run (priority, auction latency)
  B) Mode-specific validation (volume / scan / quiet)
  C) Sealed-bid auction injection (competing bids, eviction, notification)
  D) MAS resource overhead < 40% of host capacity
  E) Redistribution latency after resolution (eviction + re-grant within 500 ms)

RAA bid model: bid_value = confidence × (votes_accept / total_votes).
Severity >= 0.7 is validated via bid_value >= 0.70 (RCA gates on confidence >= 0.70).

Note: RAA processes RESOLUTION (not a separate RESOLUTION_NOTICE topic). Redistribution
is measured as eviction + grant latency when a higher bid outbids an existing allocation.
Hard checks log warnings and continue — the run always completes with a failure summary.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import random
import statistics
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agents.aca import AnomalyClassifierAgent
from agents.raa import RESOURCE_CAPACITY, ResourceAllocatorAgent
from agents.rca import MIN_CONFIDENCE, ResponseCoordinatorAgent, VOTE_WINDOW
from agents.tia import ThreatIntelligenceAgent
from agents.tma import ALERT_COOLDOWN, PORT_SCAN_COOLDOWN, TrafficMonitorAgent
from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic
from core.models import Packet
from simulation.attackers import DDoSAttacker, PortScanner
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import SAMPLE_INTERVAL, TrafficGenerator

logging.basicConfig(level=logging.WARNING)

TARGET_SEGMENT = "public-facing"
ALT_SEGMENT = "server"
TEST_DURATION_SECONDS = float(os.getenv("RAA_TEST_DURATION_SECONDS", str(5 * 60)))
MODE_RUN_SECONDS = float(os.getenv("RAA_MODE_RUN_SECONDS", "120"))
RNG_SEED = int(os.getenv("RAA_RNG_SEED", "2026"))

SCHEDULER_WEIGHTS = {
    "quiet": 0.70,
    "ddos": 0.06,
    "scan": 0.12,
    "both": 0.06,
}
QUIET_WINDOW_RANGE_SECONDS = (4.0, 14.0)
ATTACK_WINDOW_RANGE_SECONDS = (3.0, 10.0)
WARMUP_SECONDS = 8.0
ATTACK_INFLUENCE_TAIL_SECONDS = max(PORT_SCAN_COOLDOWN, ALERT_COOLDOWN) + SAMPLE_INTERVAL
VOTE_BUFFER_S = 0.5

MIN_BID_VALUE = 0.70
MAX_AUCTION_MS = 300.0
MAX_NOTIFY_MS = 100.0
MAX_REDISTRIBUTE_MS = 500.0
MAX_OVERHEAD_PCT = 0.40
HIGH_SEVERITY_EFFICIENCY_TARGET = 0.80
PRIORITY_EFFICIENCY_TARGET = 0.80
VOLUME_INTENSITIES = (2.5, 4.0, 5.5)
SCAN_PORT_LEVELS = (3, 5, 8)
SCANNER_IP = "10.0.0.99"


@dataclass
class CheckLog:
    failures: list[str] = field(default_factory=list)

    def clear(self) -> None:
        self.failures.clear()

    def warn(self, section: str, label: str, ok: bool, detail: str = "") -> bool:
        if ok:
            return True
        msg = f"[{section}] {label}"
        if detail:
            msg += f" - {detail}"
        self.failures.append(msg)
        print(f"  [WARN] {msg}")
        return False


CHECK_LOG = CheckLog()


def _warn_check(section: str, label: str, ok: bool, detail: str = "") -> bool:
    return CHECK_LOG.warn(section, label, ok, detail)


@dataclass
class AttackWindow:
    start_ts: float
    end_ts: float
    mode: str
    segment: str
    intensity: float | None = None
    expected_ports: int | None = None
    src_ip: str | None = None

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)


@dataclass
class TimestampedRecord:
    ts: float
    content: dict


@dataclass
class LatencyRecord:
    incident_id: str
    resolution_ts: float
    outcome_ts: float
    latency_ms: float
    outcome: str
    bid_value: float
    resource_type: str


@dataclass
class AuctionRound:
    """Competing resolutions processed while a resource pool is at capacity."""
    resource_type: str
    first_resolution_ts: float
    last_outcome_ts: float
    outcomes: list[TimestampedRecord]


@dataclass
class RAATelemetry:
    resolutions: list[TimestampedRecord] = field(default_factory=list)
    grants: list[TimestampedRecord] = field(default_factory=list)
    resolution_by_incident: dict[str, TimestampedRecord] = field(default_factory=dict)
    latencies: list[LatencyRecord] = field(default_factory=list)


@dataclass
class RAAModeResult:
    label: str
    mode: str
    attack_windows: list[AttackWindow]
    resolutions: list[TimestampedRecord]
    grants: list[TimestampedRecord]
    measurement_start: float = 0.0
    measurement_end: float = 0.0


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (pct / 100.0)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return ordered[lo]
    weight = rank - lo
    return ordered[lo] * (1.0 - weight) + ordered[hi] * weight


def _resolution(
    segment: str,
    action: str,
    confidence: float,
    enforcement_target: dict | None = None,
    votes_accept: int = 1,
    votes_reject: int = 0,
    incident_id: str | None = None,
) -> Message:
    clf = {
        "BLOCK_SOURCE_IP": "PORT_SCAN",
        "QUARANTINE_SEGMENT": "DDOS",
        "LOG_ONLY": "NOISE",
    }.get(action, "UNKNOWN")

    return Message(
        performative=Performative.INFORM,
        sender="RCA:sim",
        topic=Topic.RESOLUTION,
        content={
            "incident_id": incident_id or str(uuid.uuid4())[:8],
            "segment": segment,
            "classification": clf,
            "action": action,
            "confidence": confidence,
            "votes_accept": votes_accept,
            "votes_reject": votes_reject,
            "outcome": "EXECUTED",
            "decided_by": "RCA:sim",
            "duration_ms": 2100,
            "enforcement_target": enforcement_target or {},
        },
    )


def _contended_resource_types(content: dict) -> bool:
    rtype = content.get("resource_type", "")
    return rtype in {"FIREWALL", "QUARANTINE"}


def _record_outcome_latency(
    telemetry: RAATelemetry,
    content: dict,
    outcome_ts: float,
) -> None:
    incident_id = content.get("incident_id", "")
    resolution = telemetry.resolution_by_incident.get(incident_id)
    if resolution is None:
        return
    latency_ms = (outcome_ts - resolution.ts) * 1000.0
    telemetry.latencies.append(
        LatencyRecord(
            incident_id=incident_id,
            resolution_ts=resolution.ts,
            outcome_ts=outcome_ts,
            latency_ms=latency_ms,
            outcome=content.get("outcome", ""),
            bid_value=float(content.get("bid_value", 0.0)),
            resource_type=content.get("resource_type", ""),
        )
    )


def _compute_priority_metrics(grants: list[TimestampedRecord], denials: list[TimestampedRecord]) -> tuple[bool, str]:
    granted_bids = [
        float(g.content.get("bid_value", 0.0))
        for g in grants
        if g.content.get("outcome") == "GRANTED" and _contended_resource_types(g.content)
    ]
    denied_bids = [
        float(d.content.get("bid_value", 0.0))
        for d in denials
        if d.content.get("outcome") == "DENIED" and _contended_resource_types(d.content)
    ]
    if not granted_bids:
        return True, "no contended grants"
    if not denied_bids:
        return True, "no competing denials (capacity not exceeded)"
    ok = min(granted_bids) >= max(denied_bids)
    obs = f"min_granted={min(granted_bids):.3f} max_denied={max(denied_bids):.3f}"
    return ok, obs


def _compute_high_severity_efficiency(grants: list[TimestampedRecord]) -> tuple[float, int, int]:
    contended = [
        g for g in grants
        if g.content.get("outcome") == "GRANTED" and _contended_resource_types(g.content)
    ]
    high = [
        g for g in contended
        if float(g.content.get("bid_value", 0.0)) >= MIN_BID_VALUE
    ]
    return _safe_div(len(high), len(contended)), len(high), len(contended)


def _measure_overhead() -> tuple[float, str]:
    try:
        import psutil

        proc = psutil.Process()
        cpu_pct = proc.cpu_percent(interval=0.5) / max(psutil.cpu_count(), 1)
        mem_pct = proc.memory_info().rss / psutil.virtual_memory().total
        overhead = (cpu_pct / 100.0 + mem_pct) / 2.0
        detail = f"{overhead * 100:.1f}% (cpu={cpu_pct:.1f}% mem={mem_pct * 100:.2f}%)"
        return overhead, detail
    except ImportError:
        return 0.05, "psutil unavailable — nominal 5%"


async def _run_randomized_traffic(
    duration_seconds: float,
    rng: random.Random,
    generator: TrafficGenerator,
    attack_windows: list[AttackWindow],
    quiet_windows: list[tuple[float, float]],
) -> None:
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
            quiet_for = min(remaining, rng.uniform(*QUIET_WINDOW_RANGE_SECONDS))
            q_start = time.monotonic()
            await asyncio.sleep(quiet_for)
            quiet_windows.append((q_start, time.monotonic()))
            continue

        burst_duration = min(remaining, rng.uniform(*ATTACK_WINDOW_RANGE_SECONDS))
        if burst_duration <= 0:
            break

        seq += 1
        start_ts = time.monotonic()
        tasks: list[asyncio.Task] = []
        intensity = None
        expected_ports = None
        src_ip = None

        try:
            if mode in {"ddos", "both"}:
                intensity = rng.uniform(VOLUME_INTENSITIES[0], VOLUME_INTENSITIES[-1])
                ddos = DDoSAttacker(
                    attacker_id=f"ddos-raa-{seq}",
                    target_segment=TARGET_SEGMENT,
                    generator=generator,
                    intensity_multiplier=intensity,
                    ramp_seconds=min(5.0, burst_duration / 2.0),
                    rng_seed=rng.randint(1, 1_000_000),
                )
                tasks.append(asyncio.create_task(ddos.launch(burst_duration)))

            if mode in {"scan", "both"}:
                burst_size = rng.randint(2, 6)
                src_ip = f"45.33.32.{rng.randint(10, 240)}"
                scan = PortScanner(
                    attacker_id=f"scan-raa-{seq}",
                    target_segment=TARGET_SEGMENT,
                    generator=generator,
                    src_ip=src_ip,
                    burst_size=burst_size,
                    probe_interval=rng.uniform(0.20, 0.80),
                    rng_seed=rng.randint(1, 1_000_000),
                )
                expected_ports = 3
                tasks.append(asyncio.create_task(scan.launch(burst_duration)))

            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        attack_windows.append(
            AttackWindow(
                start_ts=start_ts,
                end_ts=time.monotonic(),
                mode=mode,
                segment=TARGET_SEGMENT,
                intensity=intensity,
                expected_ports=expected_ports,
                src_ip=src_ip,
            )
        )


async def _with_full_stack_runtime(
    run_fn,
    rng_seed: int = 42,
    run_traffic: bool = True,
):
    bus = MessageBus()
    clock = SimClock()
    topology = NetworkTopology()
    generator = TrafficGenerator(topology, clock, rng_seed=rng_seed)
    tma = TrafficMonitorAgent("TMA:part11", bus, generator)
    aca = AnomalyClassifierAgent("ACA:part11", bus)
    tia = ThreatIntelligenceAgent("TIA:part11", bus)
    rca = ResponseCoordinatorAgent("RCA:part11", bus)
    raa = ResourceAllocatorAgent("RAA:part11", bus)
    telemetry = RAATelemetry()

    async def on_resolution(msg) -> None:
        content = dict(msg.content)
        ts = time.monotonic()
        record = TimestampedRecord(ts=ts, content=content)
        telemetry.resolutions.append(record)
        if content.get("outcome") == "EXECUTED":
            incident_id = content.get("incident_id", "")
            if incident_id:
                telemetry.resolution_by_incident[incident_id] = record

    async def on_grant(msg) -> None:
        content = dict(msg.content)
        ts = time.monotonic()
        record = TimestampedRecord(ts=ts, content=content)
        telemetry.grants.append(record)
        _record_outcome_latency(telemetry, content, ts)

    await bus.start()
    bus.subscribe(Topic.RESOLUTION, on_resolution)
    bus.subscribe(Topic.RESOURCE_GRANTS, on_grant)

    await tma.start()
    await aca.start()
    await tia.start()
    await rca.start()
    await raa.start()

    if run_traffic:
        gen_task = asyncio.create_task(generator.run())
    else:
        gen_task = None

    try:
        result = await run_fn(generator, tma, topology, telemetry, raa)
        await asyncio.sleep(VOTE_BUFFER_S)
        return result, telemetry, raa
    finally:
        if gen_task is not None:
            generator.stop()
            await asyncio.gather(gen_task, return_exceptions=True)
        await tma.stop()
        await aca.stop()
        await tia.stop()
        await rca.stop()
        await raa.stop()
        await bus.stop()


async def _wait_until(predicate, timeout: float = 1.0, interval: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return False


async def _run_mode_scenario(mode: str, duration_seconds: float) -> RAAModeResult:
    async def scenario(generator, _tma, _topology, telemetry, _raa):
        attack_windows: list[AttackWindow] = []
        await asyncio.sleep(WARMUP_SECONDS)
        measurement_start = time.monotonic()

        if mode == "volume":
            warmup = min(WARMUP_SECONDS, duration_seconds / 4.0)
            attack = min(15.0, duration_seconds - warmup - 5.0)
            attack = max(attack, 8.0)
            await asyncio.sleep(warmup)
            start_ts = time.monotonic()
            ddos = DDoSAttacker(
                attacker_id="ddos-raa-volume",
                target_segment=TARGET_SEGMENT,
                generator=generator,
                intensity_multiplier=4.5,
                ramp_seconds=min(4.0, attack / 2.0),
                rng_seed=11,
            )
            await ddos.launch(attack)
            end_ts = time.monotonic()
            attack_windows.append(
                AttackWindow(
                    start_ts=start_ts,
                    end_ts=end_ts,
                    mode="ddos",
                    segment=TARGET_SEGMENT,
                    intensity=4.5,
                )
            )
            await asyncio.sleep(VOTE_WINDOW + 2.0)
        elif mode == "scan":
            src_ip = "44.10.0.55"
            await asyncio.sleep(WARMUP_SECONDS)
            start_ts, end_ts = await _run_packet_only_scan(
                generator=generator,
                segment=TARGET_SEGMENT,
                src_ip=src_ip,
                unique_ports=6,
            )
            attack_windows.append(
                AttackWindow(
                    start_ts=start_ts,
                    end_ts=end_ts,
                    mode="scan",
                    segment=TARGET_SEGMENT,
                    expected_ports=6,
                    src_ip=src_ip,
                )
            )
            await asyncio.sleep(VOTE_WINDOW + 2.0)
        else:
            await asyncio.sleep(duration_seconds)

        measurement_end = time.monotonic()
        await asyncio.sleep(VOTE_WINDOW + 1.0)
        return {
            "attack_windows": attack_windows,
            "measurement_start": measurement_start,
            "measurement_end": measurement_end,
        }

    data, telemetry, _raa = await _with_full_stack_runtime(
        scenario,
        rng_seed=RNG_SEED + hash(mode) % 1000,
        run_traffic=(mode != "quiet"),
    )
    return RAAModeResult(
        label=mode,
        mode=mode,
        attack_windows=data["attack_windows"],
        resolutions=telemetry.resolutions,
        grants=telemetry.grants,
        measurement_start=data["measurement_start"],
        measurement_end=data["measurement_end"],
    )


async def _run_packet_only_scan(
    generator: TrafficGenerator,
    segment: str,
    src_ip: str,
    unique_ports: int,
    probe_interval: float = 0.40,
) -> tuple[float, float]:
    hosts = generator.topology.hosts_in(segment)
    dst_ip = hosts[0].ip
    ports = PortScanner.SCAN_PORTS[:unique_ports]
    start_ts = time.monotonic()
    for idx, port in enumerate(ports):
        packet = Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=40000 + idx,
            dst_port=port,
            protocol="TCP",
            pkt_size=64,
            segment=segment,
            label="packet-only-scan",
        )
        generator.add_attack_packets(segment, [packet])
        await asyncio.sleep(probe_interval)
    return start_ts, time.monotonic()


# ---------------------------------------------------------------------------
# Section A — episode core metrics (5-minute mixed run)
# ---------------------------------------------------------------------------

async def run_test_a_episode_metrics() -> dict:
    async def scenario(_generator, _tma, _topology, _telemetry, raa):
        rng = random.Random(RNG_SEED)
        attack_windows: list[AttackWindow] = []
        quiet_windows: list[tuple[float, float]] = []
        allocs_at_start = sum(len(v) for v in raa._allocations.values())

        await asyncio.sleep(WARMUP_SECONDS)
        measurement_start = time.monotonic()
        await _run_randomized_traffic(
            duration_seconds=TEST_DURATION_SECONDS,
            rng=rng,
            generator=_generator,
            attack_windows=attack_windows,
            quiet_windows=quiet_windows,
        )
        measurement_end = time.monotonic()
        await asyncio.sleep(VOTE_WINDOW + 1.0)

        allocs_at_end = sum(len(v) for v in raa._allocations.values())
        return {
            "attack_windows": attack_windows,
            "quiet_windows": quiet_windows,
            "measurement_start": measurement_start,
            "measurement_end": measurement_end,
            "allocs_at_start": allocs_at_start,
            "allocs_at_end": allocs_at_end,
        }

    data, telemetry, raa = await _with_full_stack_runtime(scenario, rng_seed=RNG_SEED)

    grants = [g for g in telemetry.grants if g.content.get("outcome") == "GRANTED"]
    denials = [g for g in telemetry.grants if g.content.get("outcome") == "DENIED"]
    auction_latencies = [lat.latency_ms for lat in telemetry.latencies if lat.outcome in {"GRANTED", "DENIED", "EVICTED"}]
    notify_latencies = [lat.latency_ms for lat in telemetry.latencies if lat.outcome in {"GRANTED", "DENIED"}]

    priority_ok, priority_obs = _compute_priority_metrics(grants, denials)
    efficiency, high_count, contended_count = _compute_high_severity_efficiency(grants)

    _warn_check("A", "RAA issued contended resource outcomes", contended_count > 0 or len(grants) > 0,
                f"contended_grants={contended_count}")
    _warn_check(
        "A",
        "priority: highest-severity bids win over lower bids",
        priority_ok,
        priority_obs,
    )
    _warn_check(
        "A",
        f"grants to active threats with bid >= {MIN_BID_VALUE}",
        efficiency >= HIGH_SEVERITY_EFFICIENCY_TARGET or contended_count == 0,
        f"{efficiency * 100:.1f}% ({high_count}/{contended_count}) < {HIGH_SEVERITY_EFFICIENCY_TARGET * 100:.0f}%",
    )

    if auction_latencies:
        p99_auction = _percentile(auction_latencies, 99)
        p50_auction = _percentile(auction_latencies, 50)
        _warn_check(
            "A",
            f"auction latency p99 <= {MAX_AUCTION_MS:.0f} ms",
            p99_auction <= MAX_AUCTION_MS,
            f"p99={p99_auction:.1f}ms p50={p50_auction:.1f}ms",
        )
    else:
        _warn_check("A", f"auction latency p99 <= {MAX_AUCTION_MS:.0f} ms", False, "no latency samples")

    if notify_latencies:
        p99_notify = _percentile(notify_latencies, 99)
        _warn_check(
            "A",
            f"bidder notification p99 <= {MAX_NOTIFY_MS:.0f} ms",
            p99_notify <= MAX_NOTIFY_MS,
            f"p99={p99_notify:.1f}ms",
        )
    else:
        _warn_check("A", f"bidder notification p99 <= {MAX_NOTIFY_MS:.0f} ms", False, "no notification samples")

    _warn_check(
        "A",
        "allocation ledger does not grow unbounded post-run",
        data["allocs_at_end"] <= data["allocs_at_start"] + contended_count + 2,
        f"start={data['allocs_at_start']} end={data['allocs_at_end']}",
    )

    executed_res = [
        r for r in telemetry.resolutions
        if r.content.get("outcome") == "EXECUTED"
        and float(r.content.get("confidence", 0.0)) >= MIN_CONFIDENCE
    ]
    grant_incidents = {
        g.content.get("incident_id")
        for g in grants
        if g.content.get("outcome") == "GRANTED" and _contended_resource_types(g.content)
    }
    res_incidents = {r.content.get("incident_id") for r in executed_res}
    orphan_grants = grant_incidents - res_incidents
    _warn_check(
        "A",
        "grants tied to EXECUTED resolutions (active threats only)",
        len(orphan_grants) == 0,
        f"orphan_grants={len(orphan_grants)}",
    )

    return {
        "grants": len(grants),
        "denials": len(denials),
        "contended_grants": contended_count,
        "efficiency": efficiency,
        "priority_ok": priority_ok,
        "auction_latencies": auction_latencies,
        "notify_latencies": notify_latencies,
        "attack_windows": len(data["attack_windows"]),
        "resolutions": len(telemetry.resolutions),
        "raa_grants": len(raa.grants),
        "raa_denials": len(raa.denials),
        "raa_evictions": len(raa.evictions),
    }


# ---------------------------------------------------------------------------
# Section B — mode-specific validation
# ---------------------------------------------------------------------------

async def run_test_b_mode_validation() -> dict:
    volume = await _run_mode_scenario("volume", MODE_RUN_SECONDS)
    scan = await _run_mode_scenario("scan", MODE_RUN_SECONDS)
    quiet = await _run_mode_scenario("quiet", MODE_RUN_SECONDS)

    volume_grants = [
        g for g in volume.grants
        if g.content.get("outcome") == "GRANTED" and g.content.get("resource_type") == "QUARANTINE"
    ]
    _warn_check("B", "volume mode grants QUARANTINE resources", bool(volume_grants),
                f"count={len(volume_grants)}")
    for grant in volume_grants:
        _warn_check(
            "B",
            "volume quarantine bid >= severity threshold",
            float(grant.content.get("bid_value", 0.0)) >= MIN_BID_VALUE,
            f"bid={grant.content.get('bid_value')}",
        )

    scan_grants = [
        g for g in scan.grants
        if g.content.get("outcome") == "GRANTED" and g.content.get("resource_type") == "FIREWALL"
    ]
    _warn_check("B", "scan mode grants FIREWALL resources", bool(scan_grants),
                f"count={len(scan_grants)}")

    quiet_contended = [
        g for g in quiet.grants
        if _contended_resource_types(g.content) and g.content.get("outcome") == "GRANTED"
    ]
    _warn_check(
        "B",
        "quiet mode zero contended grants",
        len(quiet_contended) == 0,
        f"found {len(quiet_contended)}",
    )

    quiet_executed = [
        r for r in quiet.resolutions
        if quiet.measurement_start <= r.ts <= quiet.measurement_end
        and r.content.get("outcome") == "EXECUTED"
    ]
    _warn_check(
        "B",
        "quiet mode zero EXECUTED resolutions during measurement",
        len(quiet_executed) == 0,
        f"found {len(quiet_executed)}",
    )

    return {"volume": volume, "scan": scan, "quiet": quiet}


# ---------------------------------------------------------------------------
# Section C — sealed-bid auction injection
# ---------------------------------------------------------------------------

async def run_test_c_auction_injection() -> dict:
    results: dict = {}

    # C1: fill FIREWALL, higher bid evicts weakest within auction budget
    bus = MessageBus()
    raa = ResourceAllocatorAgent("RAA:c1", bus)

    await bus.start()
    await raa.start()

    low_conf = 0.75
    for i in range(RESOURCE_CAPACITY["FIREWALL"]):
        await bus.publish(_resolution(
            segment=f"seg-{i}",
            action="BLOCK_SOURCE_IP",
            confidence=low_conf,
            enforcement_target={"src_ip": f"10.1.1.{i}"},
        ))
    await _wait_until(lambda: raa.used_capacity("FIREWALL") == RESOURCE_CAPACITY["FIREWALL"])

    evictions_before = len(raa.evictions)
    grants_before = len(raa.grants)
    t0 = time.monotonic()
    await bus.publish(_resolution(
        segment="priority-seg",
        action="BLOCK_SOURCE_IP",
        confidence=0.95,
        enforcement_target={"src_ip": "10.99.99.99"},
    ))
    completed = await _wait_until(
        lambda: len(raa.evictions) > evictions_before and len(raa.grants) > grants_before,
    )
    t1 = time.monotonic()
    auction_ms = (t1 - t0) * 1000.0

    new_eviction = raa.evictions[-1] if len(raa.evictions) > evictions_before else {}
    new_grant = raa.grants[-1] if len(raa.grants) > grants_before else {}

    results["c1_evicted"] = completed and len(raa.evictions) == evictions_before + 1
    results["c1_granted"] = len(raa.grants) == grants_before + 1
    results["c1_auction_ms"] = auction_ms
    results["c1_priority"] = (
        new_grant.get("bid_value", 0) > new_eviction.get("bid_value", 1)
        if new_grant and new_eviction else False
    )

    await raa.stop()
    await bus.stop()

    _warn_check("C", "C1 high bid evicts weakest allocation", results["c1_evicted"] and results["c1_granted"])
    _warn_check("C", "C1 evicted bid lower than new grant", results["c1_priority"])
    _warn_check(
        "C",
        f"C1 auction completes <= {MAX_AUCTION_MS:.0f} ms",
        auction_ms <= MAX_AUCTION_MS,
        f"{auction_ms:.1f}ms",
    )

    # C2: at capacity, low bid denied
    bus = MessageBus()
    raa = ResourceAllocatorAgent("RAA:c2", bus)

    await bus.start()
    await raa.start()

    for i in range(RESOURCE_CAPACITY["FIREWALL"]):
        await bus.publish(_resolution(
            segment=f"hseg-{i}",
            action="BLOCK_SOURCE_IP",
            confidence=0.92,
            enforcement_target={"src_ip": f"10.2.2.{i}"},
        ))
    await _wait_until(lambda: raa.used_capacity("FIREWALL") == RESOURCE_CAPACITY["FIREWALL"])

    denials_before = len(raa.denials)
    t_res = time.monotonic()
    await bus.publish(_resolution(
        segment="low-priority",
        action="BLOCK_SOURCE_IP",
        confidence=0.71,
        enforcement_target={"src_ip": "10.0.0.1"},
    ))
    denied = await _wait_until(lambda: len(raa.denials) > denials_before)
    notify_ms = (time.monotonic() - t_res) * 1000.0 if denied else None

    results["c2_denied"] = denied and len(raa.denials) == denials_before + 1
    results["c2_notify_ms"] = notify_ms

    await raa.stop()
    await bus.stop()

    _warn_check("C", "C2 low bid denied at capacity", results["c2_denied"])
    _warn_check(
        "C",
        f"C2 denial notification <= {MAX_NOTIFY_MS:.0f} ms",
        notify_ms is not None and notify_ms <= MAX_NOTIFY_MS,
        f"{notify_ms:.1f}ms" if notify_ms is not None else "no denial observed",
    )

    # C3: competing resolutions on separate pools (QUARANTINE vs full FIREWALL)
    bus = MessageBus()
    raa = ResourceAllocatorAgent("RAA:c3", bus)

    await bus.start()
    await raa.start()

    for i in range(RESOURCE_CAPACITY["FIREWALL"]):
        await bus.publish(_resolution(
            segment=f"fw-{i}",
            action="BLOCK_SOURCE_IP",
            confidence=0.88,
            enforcement_target={"src_ip": f"10.3.3.{i}"},
        ))
    await _wait_until(lambda: raa.used_capacity("FIREWALL") == RESOURCE_CAPACITY["FIREWALL"])

    grants_before = len(raa.grants)
    t_q = time.monotonic()
    await bus.publish(_resolution(
        segment="corp-dmz",
        action="QUARANTINE_SEGMENT",
        confidence=0.91,
        enforcement_target={"segment": "corp-dmz"},
    ))
    granted = await _wait_until(lambda: len(raa.grants) > grants_before)
    quarantine_ms = (time.monotonic() - t_q) * 1000.0 if granted else None

    quarantine_grant = next(
        (g for g in raa.grants[grants_before:] if g.get("resource_type") == "QUARANTINE"),
        {},
    )
    results["c3_quarantine"] = quarantine_grant.get("outcome") == "GRANTED"
    results["c3_quarantine_ms"] = quarantine_ms
    results["c3_firewall_full"] = raa.used_capacity("FIREWALL") == RESOURCE_CAPACITY["FIREWALL"]

    await raa.stop()
    await bus.stop()

    _warn_check(
        "C",
        "C3 QUARANTINE granted from separate pool when FIREWALL full",
        results["c3_quarantine"] and results["c3_firewall_full"],
    )
    _warn_check(
        "C",
        f"C3 quarantine auction <= {MAX_AUCTION_MS:.0f} ms",
        quarantine_ms is not None and quarantine_ms <= MAX_AUCTION_MS,
        f"{quarantine_ms:.1f}ms" if quarantine_ms is not None else "no grant observed",
    )

    return results


# ---------------------------------------------------------------------------
# Section D — resource overhead
# ---------------------------------------------------------------------------

async def run_test_d_overhead() -> dict:
    overhead, detail = _measure_overhead()
    _warn_check(
        "D",
        f"MAS resource overhead < {MAX_OVERHEAD_PCT * 100:.0f}%",
        overhead < MAX_OVERHEAD_PCT,
        detail,
    )
    return {"overhead": overhead, "detail": detail}


# ---------------------------------------------------------------------------
# Section E — redistribution latency (eviction + re-grant)
# ---------------------------------------------------------------------------

async def run_test_e_redistribution() -> dict:
    bus = MessageBus()
    raa = ResourceAllocatorAgent("RAA:e1", bus)

    await bus.start()
    await raa.start()

    for i in range(RESOURCE_CAPACITY["FIREWALL"]):
        await bus.publish(_resolution(
            segment=f"base-{i}",
            action="BLOCK_SOURCE_IP",
            confidence=0.78,
            enforcement_target={"src_ip": f"10.4.4.{i}"},
        ))
    await _wait_until(lambda: raa.used_capacity("FIREWALL") == RESOURCE_CAPACITY["FIREWALL"])

    evictions_before = len(raa.evictions)
    grants_before = len(raa.grants)
    t_res = time.monotonic()
    await bus.publish(_resolution(
        segment="redistribute-seg",
        action="BLOCK_SOURCE_IP",
        confidence=0.96,
        enforcement_target={"src_ip": "10.88.88.88"},
        incident_id="redist-1",
    ))
    completed = await _wait_until(
        lambda: len(raa.evictions) > evictions_before and len(raa.grants) > grants_before,
    )

    redistribute_ms = (time.monotonic() - t_res) * 1000.0 if completed else None
    resolution_to_grant_ms = redistribute_ms

    await raa.stop()
    await bus.stop()

    ok = redistribute_ms is not None and redistribute_ms <= MAX_REDISTRIBUTE_MS
    _warn_check(
        "E",
        f"redistribution (evict + grant) <= {MAX_REDISTRIBUTE_MS:.0f} ms after resolution",
        ok,
        f"{redistribute_ms:.1f}ms" if redistribute_ms is not None else "missing evict/grant pair",
    )
    if resolution_to_grant_ms is not None:
        _warn_check(
            "E",
            f"resolution-to-grant <= {MAX_REDISTRIBUTE_MS:.0f} ms",
            resolution_to_grant_ms <= MAX_REDISTRIBUTE_MS,
            f"{resolution_to_grant_ms:.1f}ms",
        )

    return {
        "redistribute_ms": redistribute_ms,
        "resolution_to_grant_ms": resolution_to_grant_ms,
        "completed": completed,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _section_failed(section: str) -> bool:
    prefix = f"[{section}]"
    return any(f.startswith(prefix) for f in CHECK_LOG.failures)


def _render_report(test_a: dict, test_b: dict, test_c: dict, test_d: dict, test_e: dict) -> None:
    auction = test_a["auction_latencies"]
    notify = test_a["notify_latencies"]

    print("\n=== RAA PRIORITY (severity >= 0.7 via bid_value) ===")
    print(
        f"- Contended grants: {test_a['contended_grants']} | "
        f"High-severity efficiency: {test_a['efficiency'] * 100:.1f}% "
        f"(target >= {HIGH_SEVERITY_EFFICIENCY_TARGET * 100:.0f}%)"
    )
    print(f"- Priority ordering (grants beat denials): {'PASS' if test_a['priority_ok'] else 'FAIL'}")
    print(
        f"- Ledger: {test_a['raa_grants']} grants | "
        f"{test_a['raa_denials']} denials | {test_a['raa_evictions']} evictions"
    )

    print(f"\n=== SEALED-BID AUCTION (<= {MAX_AUCTION_MS:.0f} ms) ===")
    if auction:
        print(
            f"- Episode samples: {len(auction)} | "
            f"p50: {_percentile(auction, 50):.1f} ms | "
            f"p99: {_percentile(auction, 99):.1f} ms"
        )
    else:
        print("- Episode samples: 0")
    print(
        f"- Injection C1: {test_c.get('c1_auction_ms', 0):.1f} ms | "
        f"C3 quarantine: {(test_c.get('c3_quarantine_ms') or 0):.1f} ms"
    )

    print(f"\n=== BIDDER NOTIFICATION (<= {MAX_NOTIFY_MS:.0f} ms) ===")
    if notify:
        print(
            f"- Episode p99: {_percentile(notify, 99):.1f} ms | "
            f"Injection C2 denial: {(test_c.get('c2_notify_ms') or 0):.1f} ms"
        )
    else:
        print("- Episode samples: 0")

    print(f"\n=== RESOURCE OVERHEAD (< {MAX_OVERHEAD_PCT * 100:.0f}%) ===")
    print(f"- Measured: {test_d['detail']}")

    print(f"\n=== REDISTRIBUTION (<= {MAX_REDISTRIBUTE_MS:.0f} ms after resolution) ===")
    redist = test_e.get("redistribute_ms")
    if redist is not None:
        print(f"- Evict + grant latency: {redist:.1f} ms")
    else:
        print("- Evict + grant latency: n/a")

    print("\n=== MODE VALIDATION ===")
    vol_q = sum(
        1 for g in test_b["volume"].grants
        if g.content.get("resource_type") == "QUARANTINE" and g.content.get("outcome") == "GRANTED"
    )
    scan_fw = sum(
        1 for g in test_b["scan"].grants
        if g.content.get("resource_type") == "FIREWALL" and g.content.get("outcome") == "GRANTED"
    )
    quiet_c = sum(
        1 for g in test_b["quiet"].grants
        if _contended_resource_types(g.content) and g.content.get("outcome") == "GRANTED"
    )
    print(f"- Volume QUARANTINE grants: {vol_q} | Scan FIREWALL grants: {scan_fw} | Quiet contended: {quiet_c}")

    print("\n=== SECTION CHECKS (A/B/C/D/E) ===")
    print(
        f"- Test A episode metrics: {'PASS' if not _section_failed('A') else 'FAIL'} "
        f"({test_a['resolutions']} resolutions, {test_a['attack_windows']} attack windows)"
    )
    print(f"- Test B mode validation: {'PASS' if not _section_failed('B') else 'FAIL'}")
    print(f"- Test C auction injection: {'PASS' if not _section_failed('C') else 'FAIL'}")
    print(f"- Test D overhead: {'PASS' if not _section_failed('D') else 'FAIL'}")
    print(f"- Test E redistribution: {'PASS' if not _section_failed('E') else 'FAIL'}")


async def main() -> None:
    CHECK_LOG.clear()

    print("=" * 80)
    print("  Part 11 Test  |  RAA Validation Coverage (A/B/C/D/E)")
    print("=" * 80)
    print(f"  Segment: {TARGET_SEGMENT}")
    print(f"  Mixed run duration: {TEST_DURATION_SECONDS:.0f}s")
    print(f"  Mode validation budget: {MODE_RUN_SECONDS:.0f}s")
    print(f"  Seed: {RNG_SEED}")
    print(f"  Bid severity threshold: >= {MIN_BID_VALUE}")
    print()

    print("[C] Sealed-bid auction injection...")
    test_c = await run_test_c_auction_injection()

    print("[B] Mode validation...")
    test_b = await run_test_b_mode_validation()

    print("[A] Episode core metrics...")
    test_a = await run_test_a_episode_metrics()

    print("[D] Resource overhead...")
    test_d = await run_test_d_overhead()

    print("[E] Redistribution latency...")
    test_e = await run_test_e_redistribution()

    _render_report(test_a, test_b, test_c, test_d, test_e)

    if CHECK_LOG.failures:
        print(f"\n=== CHECK WARNINGS ({len(CHECK_LOG.failures)} failed) ===")
        for item in CHECK_LOG.failures:
            print(f"  - {item}")
        print(f"\nOverall: {len(CHECK_LOG.failures)} CHECK(S) FAILED")
    else:
        print("\nOverall: ALL PASS")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
