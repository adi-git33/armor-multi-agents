"""
System availability simulation (Validation §V-SYS-01 / FR-31).

Metric
------
  Availability = (Total Time - Disrupted Time) / Total Time >= 99.0 %

  Disrupted Time = sum of per-attack exposure windows: attack injection
  to the first matching THREAT_REPORT (DDOS or PORT_SCAN).  If an attack
  is never classified correctly, its full duration counts as disrupted.

Pipeline: TrafficGenerator --> TMA (ALERTS) --> ACA (THREAT_REPORTS)
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable

from bus.message_bus import MessageBus
from core.messages import Topic
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner
from agents.tma import TrafficMonitorAgent, ALERT_COOLDOWN
from agents.aca import AnomalyClassifierAgent

TOTAL_TIME = 300.0
AVAIL_TARGET = 0.99
WARMUP_SECS = 10.0
BUFFER_SECS = 10.0

ATTACK_PLAN: list[dict] = [
    {
        "id": "ATK-1", "segment": "public-facing", "type": "DDOS",
        "delay": 20, "dur": 20,
        "mult": 10.0, "ramp": 1.0, "interval": None, "seed": 201,
        "desc": "10x baseline, ramp 1 s",
    },
    {
        "id": "ATK-2", "segment": "public-facing", "type": "PORT_SCAN",
        "delay": 46, "dur": 20,
        "mult": None, "ramp": None, "interval": 0.2, "seed": 202,
        "desc": "probe interval 0.2 s",
    },
    {
        "id": "ATK-3", "segment": "internal", "type": "DDOS",
        "delay": 72, "dur": 20,
        "mult": 12.0, "ramp": 1.0, "interval": None, "seed": 203,
        "desc": "12x baseline, ramp 1 s",
    },
    {
        "id": "ATK-4", "segment": "server", "type": "PORT_SCAN",
        "delay": 98, "dur": 20,
        "mult": None, "ramp": None, "interval": 0.2, "seed": 204,
        "desc": "probe interval 0.2 s",
    },
    {
        "id": "ATK-5", "segment": "sec-mon", "type": "DDOS",
        "delay": 124, "dur": 20,
        "mult": 15.0, "ramp": 1.0, "interval": None, "seed": 205,
        "desc": "15x baseline, ramp 1 s",
    },
]


@dataclass
class AttackResult:
    id: str
    segment: str
    attack_type: str
    duration: float
    t_start: float | None
    t_start_offset: float | None
    t_detect: float | None
    disrupted: float
    detected: bool


@dataclass
class AvailabilityResult:
    availability: float
    passed: bool
    total_time: float
    t_disrupted: float
    target: float = AVAIL_TARGET
    attacks: list[AttackResult] = field(default_factory=list)

    @property
    def detected_count(self) -> int:
        return sum(1 for a in self.attacks if a.detected)

    @property
    def undetected_count(self) -> int:
        return sum(1 for a in self.attacks if a.t_start is not None and not a.detected)


def _attack_disrupted(atk: dict) -> float:
    if atk["t_start"] is None:
        return 0.0
    if atk["t_detect"] is not None:
        return atk["t_detect"] - atk["t_start"]
    return float(atk["dur"])


async def run_system_availability_test(
    *,
    verbose: bool = False,
    log: Callable[[str], None] | None = None,
) -> AvailabilityResult:
    """Run the 300 s TMA→ACA availability simulation."""
    emit = log if log is not None else (print if verbose else lambda _msg: None)

    bus = MessageBus()
    topo = NetworkTopology()
    clock = SimClock()
    gen = TrafficGenerator(topo, clock, rng_seed=42)
    tma = TrafficMonitorAgent("TMA:avail", bus, gen)
    aca = AnomalyClassifierAgent("ACA:avail", bus)

    attacks: list[dict] = [
        {**a, "t_start": None, "t_detect": None}
        for a in ATTACK_PLAN
    ]
    active_by_seg: dict[str, dict] = {}
    t0 = time.monotonic()

    def ts() -> str:
        return f"t={time.monotonic() - t0:6.1f}s"

    async def on_report(msg) -> None:
        seg = msg.content.get("segment", "")
        cls = msg.content.get("classification", "")
        now = time.monotonic()

        atk = active_by_seg.get(seg)
        if atk is None or atk["t_detect"] is not None:
            return

        expected = atk["type"]
        if cls != expected:
            return

        atk["t_detect"] = now
        lag = now - atk["t_start"]
        emit(f"  [DETECTED]   {ts()}  {atk['id']}"
             f"  {cls:<10}  {seg:<16}  latency={lag:.3f} s")

    await bus.start()
    bus.subscribe(Topic.THREAT_REPORTS, on_report)
    await tma.start()
    await aca.start()

    gen_task = asyncio.create_task(gen.run())

    async def run_attack(atk: dict) -> None:
        await asyncio.sleep(atk["delay"])

        if atk["type"] == "DDOS":
            seg = atk["segment"]
            while True:
                belief = tma._beliefs.get(seg, {})
                since_last = time.monotonic() - belief.get("last_alert_time", 0.0)
                remaining = ALERT_COOLDOWN - since_last
                if remaining <= 0.05:
                    break
                await asyncio.sleep(min(remaining - 0.04, 0.05))

        atk["t_start"] = time.monotonic()
        active_by_seg[atk["segment"]] = atk

        emit(f"  [ATK START]  {ts()}  {atk['id']}"
             f"  {atk['type']:<10}  {atk['segment']:<16}  ({atk['desc']})")

        if atk["type"] == "DDOS":
            aggressor = DDoSAttacker(
                atk["id"], atk["segment"], gen,
                intensity_multiplier=atk["mult"],
                ramp_seconds=atk["ramp"],
                rng_seed=atk["seed"],
            )
            await aggressor.launch(atk["dur"])
        else:
            scanner = PortScanner(
                atk["id"], atk["segment"], gen,
                probe_interval=atk["interval"],
                rng_seed=atk["seed"],
            )
            await scanner.launch(atk["dur"])

        active_by_seg.pop(atk["segment"], None)
        status = "detected" if atk["t_detect"] is not None else "!!! UNDETECTED"
        emit(f"  [ATK END]    {ts()}  {atk['id']}  ended  ({status})")

    async def heartbeat() -> None:
        while True:
            await asyncio.sleep(30)
            elapsed = time.monotonic() - t0
            if elapsed < TOTAL_TIME - 2:
                emit(f"  [heartbeat]  {ts()}  / {TOTAL_TIME:.0f} s  monitoring ...")

    async def warmup_announce() -> None:
        emit(f"\n  [WARMUP]     {ts()}  building TMA rolling baseline ({WARMUP_SECS:.0f} s) ...")
        await asyncio.sleep(WARMUP_SECS)
        emit(f"  [BUFFER]     {ts()}  clearing noise cooldowns ({BUFFER_SECS:.0f} s) ...")
        await asyncio.sleep(BUFFER_SECS)
        emit(f"  [READY]      {ts()}  attacks may begin")

    hb_task = asyncio.create_task(heartbeat())
    await asyncio.gather(
        warmup_announce(),
        *[asyncio.create_task(run_attack(a)) for a in attacks],
        asyncio.sleep(TOTAL_TIME),
        return_exceptions=True,
    )
    hb_task.cancel()
    try:
        await hb_task
    except asyncio.CancelledError:
        pass

    gen.stop()
    await tma.stop()
    await aca.stop()
    await bus.stop()
    await asyncio.gather(gen_task, return_exceptions=True)

    t_disrupted = sum(_attack_disrupted(atk) for atk in attacks)
    availability = (TOTAL_TIME - t_disrupted) / TOTAL_TIME

    attack_results = [
        AttackResult(
            id=atk["id"],
            segment=atk["segment"],
            attack_type=atk["type"],
            duration=float(atk["dur"]),
            t_start=atk["t_start"],
            t_start_offset=(atk["t_start"] - t0) if atk["t_start"] is not None else None,
            t_detect=atk["t_detect"],
            disrupted=_attack_disrupted(atk),
            detected=atk["t_detect"] is not None,
        )
        for atk in attacks
    ]

    return AvailabilityResult(
        availability=availability,
        passed=availability >= AVAIL_TARGET,
        total_time=TOTAL_TIME,
        t_disrupted=t_disrupted,
        attacks=attack_results,
    )
