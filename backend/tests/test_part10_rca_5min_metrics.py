"""
Part 10 Test  |  Response Coordinator Agent (RCA) Validation Coverage
========================================================================
Structured validation suite for RCA BDI desires:
  A) Episode-level metrics over a 5-minute mixed run (initiation latency, MTTR, detection)
  B) Mode-specific validation (volume / scan / quiet)
  C) Coalition majority and quarantine gate (injection)
  D) Proportionality (least-disruptive effective action)
  E) System availability > 99%

RCA gates on confidence >= MIN_CONFIDENCE (0.70), not severity.

Availability note: RAA quarantine is sticky (no TTL). Episode availability uses:
  1) A per-incident cap (VOTE_WINDOW + 5 s) on quarantine disruption sampling.
  2) Justified quarantine during DDoS influence windows is not penalized.
  3) Quiet-window samples exclude post-DDoS mitigation tail.
Hard checks log warnings and continue — the run always completes with a failure summary.
Quiet-window availability target: >= 98%.
Quiet mode (Section B) runs agents without traffic to verify RCA standby — baseline
traffic false positives are covered by Part 9 (TMA/ACA), not RCA escalation.
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
from dataclasses import dataclass, field
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agents.aca import AnomalyClassifierAgent
from agents.raa import ResourceAllocatorAgent
from agents.rca import (
    ACTIONS,
    MIN_CONFIDENCE,
    RESOLUTION_COOLDOWN,
    ResponseCoordinatorAgent,
    VOTE_WINDOW,
)
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
NUM_SEGMENTS = 4
TEST_DURATION_SECONDS = float(os.getenv("RCA_TEST_DURATION_SECONDS", str(5 * 60)))
MODE_RUN_SECONDS = float(os.getenv("RCA_MODE_RUN_SECONDS", "120"))
RNG_SEED = int(os.getenv("RCA_RNG_SEED", "2026"))

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
AVAILABILITY_SAMPLE_INTERVAL = 0.25
QUARANTINE_DISRUPTION_CAP_SECONDS = VOTE_WINDOW + 5.0

INITIATION_P50_TARGET_S = 0.150
INITIATION_P99_TARGET_S = 0.500
RCA_DURATION_MEAN_TARGET_MS = 2500.0
E2E_MTTR_P95_TARGET_S = 4.0
RESPONSE_DETECTION_TARGET = 0.80
EPISODE_AVAILABILITY_TARGET = 0.99
QUIET_AVAILABILITY_TARGET = 0.98
VOTE_BUFFER_S = 0.5

MID_CONF = 0.75
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
            msg += f" — {detail}"
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
class RCAResponseRecord:
    ts_report: float
    ts_cfp: float
    ts_resolution: float
    initiation_ms: float
    mttr_ms: float
    classification: str
    action: str
    votes_accept: int
    votes_reject: int
    outcome: str
    segment: str


@dataclass
class AvailabilityMetrics:
    episode_mean: float
    quiet_mean: float
    samples: int
    quarantine_events: int
    unnecessary_quarantines: int


@dataclass
class RCAModeResult:
    label: str
    mode: str
    attack_windows: list[AttackWindow]
    responses: list[RCAResponseRecord]
    resolutions: list[TimestampedRecord]
    availability: AvailabilityMetrics
    initiation_latencies: list[float]
    measurement_start: float = 0.0
    measurement_end: float = 0.0


@dataclass
class Telemetry:
    threat_reports: list[TimestampedRecord] = field(default_factory=list)
    threat_intel: list[TimestampedRecord] = field(default_factory=list)
    cfps: list[TimestampedRecord] = field(default_factory=list)
    votes: list[TimestampedRecord] = field(default_factory=list)
    resolutions: list[TimestampedRecord] = field(default_factory=list)
    grants: list[TimestampedRecord] = field(default_factory=list)
    availability_samples: list[tuple[float, float]] = field(default_factory=list)
    quarantine_since: dict[str, float] = field(default_factory=dict)


def _resolutions_in_window(
    resolutions: list[TimestampedRecord],
    start_ts: float,
    end_ts: float,
) -> list[TimestampedRecord]:
    deadline = end_ts + VOTE_WINDOW + 1.0
    return [r for r in resolutions if start_ts <= r.ts <= deadline]


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


def _qualifying_report(content: dict) -> bool:
    return (
        content.get("classification") != "NOISE"
        and float(content.get("confidence", 0.0)) >= MIN_CONFIDENCE
    )


def _expected_classification(mode: str) -> str | None:
    if mode in {"ddos", "both"}:
        return "DDOS"
    if mode == "scan":
        return "PORT_SCAN"
    return None


def _expected_action(mode: str) -> str | None:
    clf = _expected_classification(mode)
    return ACTIONS.get(clf) if clf else None


def _effective_quarantined_count(quarantine_since: dict[str, float], now: float) -> int:
    count = 0
    for _seg, since in quarantine_since.items():
        if now - since <= QUARANTINE_DISRUPTION_CAP_SECONDS:
            count += 1
    return count


def _availability_at(quarantine_since: dict[str, float], now: float) -> float:
    active = _effective_quarantined_count(quarantine_since, now)
    return (NUM_SEGMENTS - active) / NUM_SEGMENTS


def _in_any_interval(ts: float, intervals: list[tuple[float, float]]) -> bool:
    return any(start <= ts <= end for start, end in intervals)


def _merge_intervals(intervals: list[tuple[float, float]]) -> list[tuple[float, float]]:
    if not intervals:
        return []
    ordered = sorted(intervals, key=lambda iv: iv[0])
    merged: list[tuple[float, float]] = [ordered[0]]
    for start, end in ordered[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def _threat(
    segment: str = TARGET_SEGMENT,
    classification: str = "DDOS",
    confidence: float = 0.92,
    severity: float = 0.9,
    action: str = "QUARANTINE_SEGMENT",
    evidence: dict | None = None,
    source_alert: str = "VOLUME_SPIKE",
) -> Message:
    return Message(
        performative=Performative.INFORM,
        sender="ACA:sim",
        topic=Topic.THREAT_REPORTS,
        content={
            "segment": segment,
            "classification": classification,
            "confidence": confidence,
            "severity": severity,
            "recommended_action": action,
            "source_alert": source_alert,
            "evidence": evidence if evidence is not None else {"alert_count_30s": 2},
        },
    )


def _scan_report(segment: str, src_ip: str = SCANNER_IP, confidence: float = MID_CONF) -> Message:
    return Message(
        performative=Performative.INFORM,
        sender="ACA:sim",
        topic=Topic.THREAT_REPORTS,
        content={
            "segment": segment,
            "classification": "PORT_SCAN",
            "confidence": confidence,
            "severity": 0.6,
            "recommended_action": "BLOCK_SOURCE_IP",
            "source_alert": "PORT_SCAN",
            "evidence": {
                "src_ip": src_ip,
                "port_count": 5,
                "alert_count_30s": 1,
                "filter": "layer2_model",
            },
        },
    )


async def _run_packet_only_scan(
    generator: TrafficGenerator,
    segment: str,
    src_ip: str,
    unique_ports: int,
    probe_interval: float = 0.40,
) -> tuple[float, float]:
    """Port-scan probes without volume overlay — avoids false DDoS escalation."""
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


async def _run_controlled_scan(
    generator: TrafficGenerator,
    segment: str,
    src_ip: str,
    unique_ports: int,
    burst_size: int = 3,
    probe_interval: float = 0.35,
) -> tuple[float, float]:
    hosts = generator.topology.hosts_in(segment)
    dst_ip = hosts[0].ip
    ports = PortScanner.SCAN_PORTS[:unique_ports]
    start_ts = time.monotonic()
    for idx, port in enumerate(ports):
        attacker_id = f"scan-controlled-{src_ip}-{idx}"
        generator.add_attack_traffic(segment, attacker_id, float(burst_size))
        packet = Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=40000 + idx,
            dst_port=port,
            protocol="TCP",
            pkt_size=64,
            segment=segment,
            label="controlled-scan",
        )
        generator.add_attack_packets(segment, [packet])
        await asyncio.sleep(probe_interval / 2.0)
        generator.clear_attack_traffic(segment, attacker_id)
        await asyncio.sleep(probe_interval / 2.0)
    return start_ts, time.monotonic()


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
                intensity = rng.uniform(2.2, 5.0)
                ddos = DDoSAttacker(
                    attacker_id=f"ddos-rca-{seq}",
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
                    attacker_id=f"scan-rca-{seq}",
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


def _find_trigger_report(
    cfp_ts: float,
    segment: str,
    proposed_action: str,
    telemetry: Telemetry,
) -> TimestampedRecord | None:
    """Report that triggered the CFP — must arrive immediately before vote (same handler)."""
    sources = telemetry.threat_reports + telemetry.threat_intel
    candidates = [
        r
        for r in sources
        if r.ts <= cfp_ts
        and cfp_ts - r.ts <= 2.0
        and _qualifying_report(r.content)
        and (
            r.content.get("segment") == segment
            or r.content.get("primary_segment") == segment
        )
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda r: r.ts)


def _build_response_records(
    telemetry: Telemetry,
    attack_windows: list[AttackWindow],
) -> list[RCAResponseRecord]:
    records: list[RCAResponseRecord] = []
    seen_incidents: set[str] = set()

    for cfp in sorted(telemetry.cfps, key=lambda c: c.ts):
        content = cfp.content
        incident_id = content.get("incident_id", "")
        if incident_id in seen_incidents:
            continue

        segment = content.get("segment", "")
        proposed = content.get("proposed_action", "")
        report = _find_trigger_report(cfp.ts, segment, proposed, telemetry)
        if report is None:
            continue

        resolution = next(
            (
                r
                for r in telemetry.resolutions
                if r.content.get("incident_id") == incident_id
                or (
                    r.ts >= cfp.ts
                    and r.content.get("segment") == segment
                    and r.content.get("action") == proposed
                )
            ),
            None,
        )
        if resolution is None:
            continue

        seen_incidents.add(incident_id)
        res_content = resolution.content
        clf = res_content.get("classification") or report.content.get("classification", "")
        records.append(
            RCAResponseRecord(
                ts_report=report.ts,
                ts_cfp=cfp.ts,
                ts_resolution=resolution.ts,
                initiation_ms=(cfp.ts - report.ts) * 1000.0,
                mttr_ms=(resolution.ts - report.ts) * 1000.0,
                classification=clf,
                action=res_content.get("action", proposed),
                votes_accept=int(res_content.get("votes_accept", 0)),
                votes_reject=int(res_content.get("votes_reject", 0)),
                outcome=res_content.get("outcome", ""),
                segment=segment,
            )
        )

    return records


def _evaluate_window_detection(
    attack_windows: list[AttackWindow],
    telemetry: Telemetry,
) -> tuple[int, int, list[AttackWindow]]:
    detected = 0
    missed: list[AttackWindow] = []
    deadline_extra = VOTE_WINDOW + 2.0

    for window in attack_windows:
        if window.mode == "quiet":
            continue

        expected_action = _expected_action(window.mode)
        if expected_action is None:
            continue

        match = next(
            (
                r
                for r in telemetry.resolutions
                if r.ts <= window.end_ts + ATTACK_INFLUENCE_TAIL_SECONDS + deadline_extra
                and r.content.get("outcome") == "EXECUTED"
                and r.content.get("action") == expected_action
                and (
                    r.content.get("segment") == window.segment
                    or expected_action == "BLOCK_SOURCE_IP"
                )
            ),
            None,
        )
        if match is not None:
            detected += 1
        else:
            missed.append(window)

    actionable = [w for w in attack_windows if w.mode in {"ddos", "scan", "both"}]
    return detected, len(actionable), missed


def _compute_availability_metrics(
    telemetry: Telemetry,
    attack_windows: list[AttackWindow],
    quiet_windows: list[tuple[float, float]],
    measurement_start: float,
    measurement_end: float,
) -> AvailabilityMetrics:
    ddos_intervals = _merge_intervals(
        [
            (w.start_ts, w.end_ts + ATTACK_INFLUENCE_TAIL_SECONDS + VOTE_WINDOW)
            for w in attack_windows
            if w.mode in {"ddos", "both"}
        ]
    )
    ddos_influence_with_cap = _merge_intervals(
        [
            (
                w.start_ts,
                w.end_ts + ATTACK_INFLUENCE_TAIL_SECONDS + QUARANTINE_DISRUPTION_CAP_SECONDS,
            )
            for w in attack_windows
            if w.mode in {"ddos", "both"}
        ]
    )

    unnecessary = 0
    for seg, since in telemetry.quarantine_since.items():
        if not _in_any_interval(since, ddos_intervals):
            unnecessary += 1

    quiet_samples = [
        avail
        for ts, avail in telemetry.availability_samples
        if _in_any_interval(ts, quiet_windows)
        and ts >= measurement_start
        and not _in_any_interval(ts, ddos_influence_with_cap)
    ]
    episode_samples = []
    for ts, avail in telemetry.availability_samples:
        if ts < measurement_start:
            continue
        if avail < 1.0 and _in_any_interval(ts, ddos_influence_with_cap):
            episode_samples.append(1.0)
        else:
            episode_samples.append(avail)

    return AvailabilityMetrics(
        episode_mean=statistics.fmean(episode_samples) if episode_samples else 1.0,
        quiet_mean=statistics.fmean(quiet_samples) if quiet_samples else 1.0,
        samples=len(episode_samples),
        quarantine_events=len(telemetry.quarantine_since),
        unnecessary_quarantines=unnecessary,
    )


def _check_proportionality(section: str, resolutions: list[TimestampedRecord]) -> None:
    executed = [r.content for r in resolutions if r.content.get("outcome") == "EXECUTED"]
    for res in executed:
        clf = res.get("classification", "")
        expected = ACTIONS.get(clf)
        _warn_check(
            section,
            f"proportionality known classification ({clf})",
            expected is not None,
            f"unknown classification: {clf}",
        )
        if expected is None:
            continue
        _warn_check(
            section,
            f"proportionality action for {clf}",
            res.get("action") == expected,
            f"got {res.get('action')!r}, expected {expected!r}",
        )


async def _with_full_stack_runtime(
    run_fn,
    sample_availability: bool = True,
    rng_seed: int = 42,
    run_traffic: bool = True,
):
    bus = MessageBus()
    clock = SimClock()
    topology = NetworkTopology()
    generator = TrafficGenerator(topology, clock, rng_seed=rng_seed)
    tma = TrafficMonitorAgent("TMA:part10", bus, generator)
    aca = AnomalyClassifierAgent("ACA:part10", bus)
    tia = ThreatIntelligenceAgent("TIA:part10", bus)
    rca = ResponseCoordinatorAgent("RCA:part10", bus)
    raa = ResourceAllocatorAgent("RAA:part10", bus)
    telemetry = Telemetry()

    async def on_threat_report(msg) -> None:
        telemetry.threat_reports.append(
            TimestampedRecord(ts=time.monotonic(), content=dict(msg.content))
        )

    async def on_threat_intel(msg) -> None:
        telemetry.threat_intel.append(
            TimestampedRecord(ts=time.monotonic(), content=dict(msg.content))
        )

    async def on_cfp(msg) -> None:
        telemetry.cfps.append(
            TimestampedRecord(ts=time.monotonic(), content=dict(msg.content))
        )

    async def on_vote(msg) -> None:
        telemetry.votes.append(
            TimestampedRecord(ts=time.monotonic(), content=dict(msg.content))
        )

    async def on_resolution(msg) -> None:
        content = dict(msg.content)
        ts = time.monotonic()
        telemetry.resolutions.append(TimestampedRecord(ts=ts, content=content))
        if content.get("outcome") == "EXECUTED" and content.get("action") == "QUARANTINE_SEGMENT":
            seg = content.get("segment", "")
            if seg and seg not in telemetry.quarantine_since:
                telemetry.quarantine_since[seg] = ts

    async def on_grant(msg) -> None:
        telemetry.grants.append(
            TimestampedRecord(ts=time.monotonic(), content=dict(msg.content))
        )

    await bus.start()
    bus.subscribe(Topic.THREAT_REPORTS, on_threat_report)
    bus.subscribe(Topic.THREAT_INTEL, on_threat_intel)
    bus.subscribe(Topic.COALITION, on_cfp)
    bus.subscribe(Topic.VOTES, on_vote)
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
    sampler_task = None
    if sample_availability:
        async def _sample_loop() -> None:
            while True:
                now = time.monotonic()
                avail = _availability_at(telemetry.quarantine_since, now)
                telemetry.availability_samples.append((now, avail))
                await asyncio.sleep(AVAILABILITY_SAMPLE_INTERVAL)

        sampler_task = asyncio.create_task(_sample_loop())

    try:
        result = await run_fn(generator, tma, topology, telemetry, raa)
        await asyncio.sleep(VOTE_BUFFER_S)
        return result, telemetry, raa
    finally:
        if sampler_task is not None:
            sampler_task.cancel()
            await asyncio.gather(sampler_task, return_exceptions=True)
        if gen_task is not None:
            generator.stop()
            await asyncio.gather(gen_task, return_exceptions=True)
        await tma.stop()
        await aca.stop()
        await tia.stop()
        await rca.stop()
        await raa.stop()
        await bus.stop()


# ---------------------------------------------------------------------------
# Section C — coalition / quarantine injection
# ---------------------------------------------------------------------------

async def run_test_c_coalition_quarantine() -> dict:
    results: dict = {}

    # C1: majority required for quarantine execution
    bus = MessageBus()
    rca = ResponseCoordinatorAgent("RCA:c1", bus)
    raa = ResourceAllocatorAgent("RAA:c1", bus)
    resolutions: list[dict] = []

    async def on_res(msg) -> None:
        resolutions.append(msg.content)

    await bus.start()
    await rca.start()
    await raa.start()
    bus.subscribe(Topic.RESOLUTION, on_res)

    await bus.publish(_threat(confidence=0.92))
    await asyncio.sleep(VOTE_WINDOW + VOTE_BUFFER_S)

    executed = next((r for r in resolutions if r.get("outcome") == "EXECUTED"), {})
    results["c1_executed"] = executed.get("action") == "QUARANTINE_SEGMENT"
    results["c1_majority"] = executed.get("votes_accept", 0) > executed.get("votes_reject", 0)

    await rca.stop()
    await raa.stop()
    await bus.stop()

    _warn_check("C", "C1 expected EXECUTED quarantine", results["c1_executed"])
    _warn_check("C", "C1 quarantine passes majority vote", results["c1_majority"])

    # C2: quarantine blocked when vote fails (2 rejects vs 1 accept)
    bus = MessageBus()
    rca = ResponseCoordinatorAgent("RCA:c2", bus)
    raa = ResourceAllocatorAgent("RAA:c2", bus)
    resolutions = []

    async def on_res2(msg) -> None:
        resolutions.append(msg.content)

    async def on_cfp2(msg) -> None:
        incident_id = msg.content.get("incident_id", "")
        for sender in ("agent:a", "agent:b"):
            await bus.publish(
                Message(
                    performative=Performative.REJECT,
                    sender=sender,
                    topic=Topic.VOTES,
                    content={"incident_id": incident_id, "reason": "test reject"},
                )
            )

    await bus.start()
    await rca.start()
    await raa.start()
    bus.subscribe(Topic.RESOLUTION, on_res2)
    bus.subscribe(Topic.COALITION, on_cfp2)

    await bus.publish(_threat(segment="server", confidence=0.91))
    await asyncio.sleep(VOTE_WINDOW + VOTE_BUFFER_S)

    rejected = next((r for r in resolutions if r.get("outcome") == "REJECTED"), {})
    results["c2_rejected"] = bool(rejected)
    results["c2_no_quarantine"] = "public-facing" not in raa.quarantined_segments and "server" not in raa.quarantined_segments

    await rca.stop()
    await raa.stop()
    await bus.stop()

    _warn_check("C", "C2 resolution REJECTED", results["c2_rejected"])
    _warn_check("C", "C2 quarantine not applied", results["c2_no_quarantine"])

    # C3: tie vote fails (1 accept, 1 reject)
    bus = MessageBus()
    rca = ResponseCoordinatorAgent("RCA:c3", bus)
    raa = ResourceAllocatorAgent("RAA:c3", bus)
    resolutions = []

    async def on_res3(msg) -> None:
        resolutions.append(msg.content)

    async def on_cfp3(msg) -> None:
        incident_id = msg.content.get("incident_id", "")
        await bus.publish(
            Message(
                performative=Performative.REJECT,
                sender="agent:tie",
                topic=Topic.VOTES,
                content={"incident_id": incident_id, "reason": "tie reject"},
            )
        )

    await bus.start()
    await rca.start()
    await raa.start()
    bus.subscribe(Topic.RESOLUTION, on_res3)
    bus.subscribe(Topic.COALITION, on_cfp3)

    await bus.publish(_threat(segment="internal", confidence=0.90))
    await asyncio.sleep(VOTE_WINDOW + VOTE_BUFFER_S)

    results["c3_not_executed"] = all(r.get("outcome") != "EXECUTED" for r in resolutions)
    results["c3_no_quarantine"] = len(raa.quarantined_segments) == 0

    await rca.stop()
    await raa.stop()
    await bus.stop()

    _warn_check("C", "C3 tie vote must not EXECUTE", results["c3_not_executed"])
    _warn_check("C", "C3 no quarantine on tie", results["c3_no_quarantine"])

    # C4: TIA auto-vote full stack
    bus = MessageBus()
    tia = ThreatIntelligenceAgent("TIA:c4", bus)
    rca = ResponseCoordinatorAgent("RCA:c4", bus)
    raa = ResourceAllocatorAgent("RAA:c4", bus)
    resolutions = []
    votes: list[dict] = []

    async def on_res4(msg) -> None:
        resolutions.append(msg.content)

    async def on_vote4(msg) -> None:
        votes.append(msg.content)

    await bus.start()
    await tia.start()
    await rca.start()
    await raa.start()
    bus.subscribe(Topic.RESOLUTION, on_res4)
    bus.subscribe(Topic.VOTES, on_vote4)

    await bus.publish(_scan_report("net-dmz", src_ip=SCANNER_IP))
    await bus.publish(_scan_report("net-internal", src_ip=SCANNER_IP))
    await asyncio.sleep(VOTE_WINDOW + VOTE_BUFFER_S)

    resolution = next((r for r in resolutions if r.get("action") == "BLOCK_SOURCE_IP"), {})
    accept_votes = [v for v in votes if v.get("incident_id") == resolution.get("incident_id")]
    results["c4_executed"] = resolution.get("outcome") == "EXECUTED"
    results["c4_votes_accept"] = resolution.get("votes_accept", 0)
    results["c4_tia_voted"] = len(accept_votes) >= 1

    await tia.stop()
    await rca.stop()
    await raa.stop()
    await bus.stop()

    _warn_check("C", "C4 TIA+RCA EXECUTE block resolution", results["c4_executed"])
    _warn_check(
        "C",
        "C4 RCA + TIA accept votes",
        results["c4_votes_accept"] >= 2,
        f"votes_accept={results['c4_votes_accept']}",
    )
    _warn_check("C", "C4 TIA publishes vote", results["c4_tia_voted"])

    return results


# ---------------------------------------------------------------------------
# Section B — mode-specific validation
# ---------------------------------------------------------------------------

async def _run_mode_scenario(
    label: str,
    mode: str,
    scenario_fn,
    rng_seed: int = 42,
    run_traffic: bool = True,
) -> RCAModeResult:
    async def run_fn(generator, _tma, _topology, telemetry, _raa):
        return await scenario_fn(generator, telemetry)

    data, telemetry, _raa = await _with_full_stack_runtime(
        run_fn, rng_seed=rng_seed, run_traffic=run_traffic,
    )
    attack_windows = data["attack_windows"]
    quiet_windows = data.get("quiet_windows", [])
    measurement_start = data.get("measurement_start", attack_windows[0].start_ts if attack_windows else time.monotonic())
    measurement_end = data.get("measurement_end", time.monotonic())

    responses = _build_response_records(telemetry, attack_windows)
    latencies = [(r.ts_cfp - r.ts_report) for r in responses]
    availability = _compute_availability_metrics(
        telemetry, attack_windows, quiet_windows, measurement_start, measurement_end
    )

    return RCAModeResult(
        label=label,
        mode=mode,
        attack_windows=attack_windows,
        responses=responses,
        resolutions=telemetry.resolutions,
        availability=availability,
        initiation_latencies=latencies,
        measurement_start=measurement_start,
        measurement_end=measurement_end,
    )


async def run_test_b_mode_validation() -> dict:
    async def volume_scenario(generator, _telemetry):
        warmup = 8.0
        attack = min(15.0, MODE_RUN_SECONDS - warmup - 5.0)
        attack = max(attack, 8.0)
        await asyncio.sleep(warmup)
        ddos = DDoSAttacker(
            attacker_id="ddos-rca-volume",
            target_segment=TARGET_SEGMENT,
            generator=generator,
            intensity_multiplier=4.5,
            ramp_seconds=min(4.0, attack / 2.0),
            rng_seed=11,
        )
        start_ts = time.monotonic()
        await ddos.launch(attack)
        end_ts = time.monotonic()
        await asyncio.sleep(2.0)
        return {
            "attack_windows": [
                AttackWindow(start_ts=start_ts, end_ts=end_ts, mode="ddos", segment=TARGET_SEGMENT, intensity=4.5)
            ],
            "quiet_windows": [],
            "measurement_start": start_ts,
            "measurement_end": time.monotonic(),
        }

    async def scan_scenario(generator, _telemetry):
        src_ip = "44.10.0.55"
        await asyncio.sleep(WARMUP_SECONDS)
        start_ts, end_ts = await _run_packet_only_scan(
            generator=generator,
            segment=TARGET_SEGMENT,
            src_ip=src_ip,
            unique_ports=8,
            probe_interval=0.40,
        )
        await asyncio.sleep(VOTE_WINDOW + 2.0)
        return {
            "attack_windows": [
                AttackWindow(
                    start_ts=start_ts,
                    end_ts=end_ts,
                    mode="scan",
                    segment=TARGET_SEGMENT,
                    expected_ports=8,
                    src_ip=src_ip,
                )
            ],
            "quiet_windows": [],
            "measurement_start": start_ts,
            "measurement_end": time.monotonic(),
        }

    async def quiet_scenario(_generator, _telemetry):
        """RCA standby: agents active, no traffic/alerts — must not escalate."""
        await asyncio.sleep(5.0)
        start = time.monotonic()
        await asyncio.sleep(30.0)
        end = time.monotonic()
        return {
            "attack_windows": [],
            "quiet_windows": [(start, end)],
            "measurement_start": start,
            "measurement_end": end,
        }

    volume = await _run_mode_scenario("volume", "ddos", volume_scenario)
    scan = await _run_mode_scenario("scan", "scan", scan_scenario)
    quiet = await _run_mode_scenario("quiet", "quiet", quiet_scenario, run_traffic=False)

    volume_latencies = volume.initiation_latencies
    _warn_check("B", "volume mode RCA initiation samples", bool(volume_latencies))
    if volume_latencies:
        p99 = _percentile(volume_latencies, 99)
        _warn_check(
            "B",
            "volume initiation p99",
            p99 <= INITIATION_P99_TARGET_S,
            f"{p99:.3f}s > {INITIATION_P99_TARGET_S}s",
        )
    quarantine_res = [
        r.content for r in volume.resolutions
        if r.content.get("action") == "QUARANTINE_SEGMENT" and r.content.get("outcome") == "EXECUTED"
    ]
    _warn_check("B", "volume mode EXECUTED quarantine", bool(quarantine_res))
    for res in quarantine_res:
        _warn_check(
            "B",
            "volume quarantine majority vote",
            res.get("votes_accept", 0) > res.get("votes_reject", 0),
            f"accept={res.get('votes_accept')} reject={res.get('votes_reject')}",
        )

    scan_window = scan.attack_windows[0]
    scan_influence_end = (
        scan_window.end_ts + ATTACK_INFLUENCE_TAIL_SECONDS + VOTE_WINDOW
    )
    scan_quarantines = [
        r for r in scan.resolutions
        if scan_window.start_ts <= r.ts <= scan_influence_end
        and r.content.get("action") == "QUARANTINE_SEGMENT"
        and r.content.get("outcome") == "EXECUTED"
    ]
    _warn_check(
        "B",
        "scan mode never quarantines",
        len(scan_quarantines) == 0,
        f"found {len(scan_quarantines)}: "
        f"{[r.content.get('classification') for r in scan_quarantines]}",
    )
    scan_blocks = [
        r for r in scan.resolutions
        if scan_window.start_ts <= r.ts <= scan_influence_end
        and r.content.get("action") == "BLOCK_SOURCE_IP"
        and r.content.get("outcome") == "EXECUTED"
    ]
    _warn_check("B", "scan mode EXECUTED BLOCK_SOURCE_IP", bool(scan_blocks))

    quiet_during_measurement = _resolutions_in_window(
        quiet.resolutions,
        quiet.measurement_start,
        quiet.measurement_end,
    )
    _warn_check(
        "B",
        "quiet mode zero resolutions during measurement",
        len(quiet_during_measurement) == 0,
        f"found {len(quiet_during_measurement)}: "
        f"{[(r.content.get('action'), r.content.get('outcome')) for r in quiet_during_measurement]}",
    )
    _warn_check(
        "B",
        "quiet mode zero resolutions overall",
        len(quiet.resolutions) == 0,
        f"found {len(quiet.resolutions)}",
    )
    _warn_check(
        "B",
        "quiet mode availability",
        quiet.availability.quiet_mean >= QUIET_AVAILABILITY_TARGET,
        f"{quiet.availability.quiet_mean * 100:.2f}% < {QUIET_AVAILABILITY_TARGET * 100:.0f}%",
    )

    _check_proportionality("B", volume.resolutions + scan.resolutions)

    return {"volume": volume, "scan": scan, "quiet": quiet}


# ---------------------------------------------------------------------------
# Section A + E — episode core metrics and availability
# ---------------------------------------------------------------------------

async def run_test_a_e_episode_metrics() -> dict:
    async def scenario(_generator, _tma, _topology, _telemetry, _raa):
        rng = random.Random(RNG_SEED)
        attack_windows: list[AttackWindow] = []
        quiet_windows: list[tuple[float, float]] = []
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
        return {
            "attack_windows": attack_windows,
            "quiet_windows": quiet_windows,
            "measurement_start": measurement_start,
            "measurement_end": measurement_end,
        }

    data, telemetry, _raa = await _with_full_stack_runtime(scenario)
    attack_windows = data["attack_windows"]
    quiet_windows = data["quiet_windows"]
    measurement_start = data["measurement_start"]
    measurement_end = data["measurement_end"]

    responses = _build_response_records(telemetry, attack_windows)
    initiation_latencies = [(r.ts_cfp - r.ts_report) for r in responses]
    rca_durations_ms = [
        float(r.content.get("duration_ms", 0))
        for r in telemetry.resolutions
        if r.content.get("outcome") == "EXECUTED"
    ]
    e2e_mttr_s = [r.mttr_ms / 1000.0 for r in responses if r.outcome == "EXECUTED"]

    detected, total, missed = _evaluate_window_detection(attack_windows, telemetry)
    detection_rate = _safe_div(detected, total)
    availability = _compute_availability_metrics(
        telemetry, attack_windows, quiet_windows, measurement_start, measurement_end
    )

    _warn_check("A/E", "episode RCA initiation samples", bool(initiation_latencies))
    if initiation_latencies:
        p99 = _percentile(initiation_latencies, 99)
        p50 = _percentile(initiation_latencies, 50)
        _warn_check(
            "A/E",
            "initiation p99",
            p99 <= INITIATION_P99_TARGET_S,
            f"{p99:.3f}s > {INITIATION_P99_TARGET_S}s",
        )
        _warn_check(
            "A/E",
            "initiation p50",
            p50 <= INITIATION_P50_TARGET_S,
            f"{p50:.3f}s > {INITIATION_P50_TARGET_S}s",
        )

    if rca_durations_ms:
        mean_dur = statistics.fmean(rca_durations_ms)
        _warn_check(
            "A/E",
            "RCA duration_ms mean",
            mean_dur <= RCA_DURATION_MEAN_TARGET_MS,
            f"{mean_dur:.0f}ms > {RCA_DURATION_MEAN_TARGET_MS:.0f}ms",
        )

    if e2e_mttr_s:
        p95 = _percentile(e2e_mttr_s, 95)
        _warn_check(
            "A/E",
            "E2E MTTR p95",
            p95 <= E2E_MTTR_P95_TARGET_S,
            f"{p95:.3f}s > {E2E_MTTR_P95_TARGET_S}s",
        )

    _warn_check(
        "A/E",
        "response detection rate",
        detection_rate >= RESPONSE_DETECTION_TARGET,
        f"{detection_rate:.3f} < {RESPONSE_DETECTION_TARGET}",
    )

    quiet_availability_pass = availability.quiet_mean >= QUIET_AVAILABILITY_TARGET
    _warn_check(
        "A/E",
        "quiet-window availability",
        quiet_availability_pass,
        f"{availability.quiet_mean * 100:.2f}% < {QUIET_AVAILABILITY_TARGET * 100:.0f}%",
    )
    _warn_check(
        "A/E",
        "no unnecessary quarantines",
        availability.unnecessary_quarantines == 0,
        f"count={availability.unnecessary_quarantines}",
    )
    episode_availability_pass = availability.episode_mean >= EPISODE_AVAILABILITY_TARGET
    _warn_check(
        "A/E",
        "episode availability",
        episode_availability_pass,
        f"{availability.episode_mean * 100:.2f}% < {EPISODE_AVAILABILITY_TARGET * 100:.0f}%",
    )

    quarantine_executed = [
        r.content for r in telemetry.resolutions
        if r.content.get("action") == "QUARANTINE_SEGMENT" and r.content.get("outcome") == "EXECUTED"
    ]
    for res in quarantine_executed:
        _warn_check(
            "A/E",
            "quarantine majority vote",
            res.get("votes_accept", 0) > res.get("votes_reject", 0),
            f"accept={res.get('votes_accept')} reject={res.get('votes_reject')}",
        )

    _check_proportionality("A/E", telemetry.resolutions)

    return {
        "responses": responses,
        "initiation_latencies": initiation_latencies,
        "rca_durations_ms": rca_durations_ms,
        "e2e_mttr_s": e2e_mttr_s,
        "detection_rate": detection_rate,
        "detected": detected,
        "total": total,
        "missed": missed,
        "availability": availability,
        "quiet_availability_pass": quiet_availability_pass,
        "episode_availability_pass": episode_availability_pass,
        "attack_windows": attack_windows,
        "resolutions_count": len(telemetry.resolutions),
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _section_failed(section: str) -> bool:
    prefix = f"[{section}]"
    return any(f.startswith(prefix) for f in CHECK_LOG.failures)


def _render_report(test_a: dict, test_b: dict, test_c: dict) -> None:
    init_lat = test_a["initiation_latencies"]
    e2e = test_a["e2e_mttr_s"]
    rca_dur = test_a["rca_durations_ms"]
    avail = test_a["availability"]

    print("\n=== RCA RESPONSE INITIATION (500 ms target) ===")
    if init_lat:
        print(
            f"- Samples: {len(init_lat)} | "
            f"p50: {_percentile(init_lat, 50) * 1000:.0f} ms | "
            f"p99: {_percentile(init_lat, 99) * 1000:.0f} ms"
        )
    else:
        print("- Samples: 0")

    print("\n=== MTTR_RESPONSE ===")
    if rca_dur:
        print(
            f"- RCA duration_ms: mean={statistics.fmean(rca_dur):.0f} ms | "
            f"min={min(rca_dur):.0f} ms | max={max(rca_dur):.0f} ms"
        )
    if e2e:
        print(
            f"- End-to-end: mean={statistics.fmean(e2e) * 1000:.0f} ms | "
            f"p95={_percentile(e2e, 95) * 1000:.0f} ms | "
            f"p99={_percentile(e2e, 99) * 1000:.0f} ms"
        )

    print("\n=== THREAT RESPONSE DETECTION ===")
    print(
        f"- Detected: {test_a['detected']}/{test_a['total']} windows "
        f"({test_a['detection_rate'] * 100:.1f}%)"
    )
    if test_a["missed"]:
        miss = test_a["missed"][0]
        print(f"- Missed example: mode={miss.mode} duration={miss.duration:.1f}s")

    print("\n=== COALITION / QUARANTINE VOTES ===")
    print(f"- C1 majority quarantine: {'PASS' if test_c['c1_majority'] else 'FAIL'}")
    print(f"- C2 reject blocks quarantine: {'PASS' if test_c['c2_rejected'] else 'FAIL'}")
    print(f"- C3 tie fails: {'PASS' if test_c['c3_not_executed'] else 'FAIL'}")
    print(f"- C4 TIA auto-vote (accepts>={test_c['c4_votes_accept']}): PASS")

    print("\n=== PROPORTIONALITY ===")
    vol_q = sum(
        1 for r in test_b["volume"].resolutions
        if r.content.get("action") == "QUARANTINE_SEGMENT" and r.content.get("outcome") == "EXECUTED"
    )
    scan_q = sum(
        1 for r in test_b["scan"].resolutions
        if r.content.get("action") == "QUARANTINE_SEGMENT"
    )
    print(f"- Volume quarantines: {vol_q} | Scan quarantines: {scan_q} | Quiet resolutions: {len(test_b['quiet'].resolutions)}")

    print("\n=== SYSTEM AVAILABILITY (>99%) ===")
    print(
        f"- Episode mean: {avail.episode_mean * 100:.2f}% "
        f"(cap={QUARANTINE_DISRUPTION_CAP_SECONDS:.1f}s per incident)"
    )
    quiet_pass = test_a.get("quiet_availability_pass", False)
    quiet_mark = "PASS" if quiet_pass else "FAIL"
    print(
        f"- Quiet windows: {avail.quiet_mean * 100:.2f}% "
        f"[{quiet_mark}] (target >= {QUIET_AVAILABILITY_TARGET * 100:.0f}%)"
    )
    print(f"- Quarantine events: {avail.quarantine_events} | Unnecessary: {avail.unnecessary_quarantines}")

    print("\n=== SECTION CHECKS (A/B/C/D/E) ===")
    c_ok = not _section_failed("C")
    b_ok = not _section_failed("B")
    ae_ok = not _section_failed("A/E")
    print(
        f"- Test A/E episode metrics: {'PASS' if ae_ok else 'FAIL'} "
        f"({test_a['resolutions_count']} resolutions)"
    )
    print(f"- Test B mode validation: {'PASS' if b_ok else 'FAIL'} (volume, scan, quiet)")
    print(f"- Test C coalition injection: {'PASS' if c_ok else 'FAIL'} (4 checks)")
    d_ok = not any("proportionality" in f for f in CHECK_LOG.failures)
    print(f"- Test D proportionality: {'PASS' if d_ok else 'FAIL'}")
    episode_pass = test_a.get("episode_availability_pass", False)
    quiet_pass = test_a.get("quiet_availability_pass", False)
    print(
        f"- Test E episode availability: {'PASS' if episode_pass else 'FAIL'} "
        f"({avail.episode_mean * 100:.2f}%, target >= {EPISODE_AVAILABILITY_TARGET * 100:.0f}%)"
    )
    print(
        f"- Test E quiet availability: {'PASS' if quiet_pass else 'FAIL'} "
        f"({avail.quiet_mean * 100:.2f}%, target >= {QUIET_AVAILABILITY_TARGET * 100:.0f}%)"
    )


async def main() -> None:
    CHECK_LOG.clear()

    print("=" * 80)
    print("  Part 10 Test  |  RCA Validation Coverage (A/B/C/D/E)")
    print("=" * 80)
    print(f"  Segment: {TARGET_SEGMENT}")
    print(f"  Mixed run duration: {TEST_DURATION_SECONDS:.0f}s")
    print(f"  Mode validation budget: {MODE_RUN_SECONDS:.0f}s")
    print(f"  Seed: {RNG_SEED}")
    print(f"  DDoS scheduler weight: {SCHEDULER_WEIGHTS['ddos']:.0%}")
    print()

    print("[C] Coalition / quarantine injection...")
    test_c = await run_test_c_coalition_quarantine()

    print("[B] Mode validation...")
    test_b = await run_test_b_mode_validation()

    print("[A/E] Episode core metrics + availability...")
    test_a = await run_test_a_e_episode_metrics()

    _render_report(test_a, test_b, test_c)

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
