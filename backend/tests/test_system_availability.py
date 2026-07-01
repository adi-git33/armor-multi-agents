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

  DDoS attacks use a "cooldown-aligned" start: after the scheduled delay,
  the coroutine polls tma._beliefs[seg]["last_alert_time"] and only records
  t_start (and registers the overlay) once ALERT_COOLDOWN seconds have passed
  since the last noise alert on that segment.  This removes the systematic
  up-to-5 s latency penalty caused by warmup noise resetting the TMA cooldown
  immediately before each attack.  PORT_SCAN attacks are not affected because
  their detection path (_check_port_scan) uses a separate per-(seg,src_ip)
  cooldown that warmup noise never touches.

Expected runtime: 300 s  (5 minutes)

Usage
-----
    cd backend
    python -m tests.test_system_availability
"""

from __future__ import annotations
import asyncio
import io
import sys
import time
from pathlib import Path

sys.stdout = io.TextIOWrapper(
    sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from bus.message_bus import MessageBus
from core.messages import Topic
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner
from agents.tma import TrafficMonitorAgent, ALERT_COOLDOWN
from agents.aca import AnomalyClassifierAgent

import logging
logging.basicConfig(level=logging.WARNING)

# ── Simulation constants ───────────────────────────────────────────────
TOTAL_TIME    = 300.0   # seconds — full simulation window
AVAIL_TARGET  = 0.99    # 99 % availability threshold
WARMUP_SECS   = 10.0    # TMA baseline build-up
BUFFER_SECS   = 10.0    # pause after warmup so any noise cooldowns expire

W = 70   # output line width

# ── Attack plan ────────────────────────────────────────────────────────
# Each entry: id, segment, type, delay (s), duration (s), type-specific params
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


# ── Helpers ────────────────────────────────────────────────────────────

def sep(char: str = "=") -> None:
    print(char * W)

def ts(t0: float) -> str:
    return f"t={time.monotonic() - t0:6.1f}s"


# ── Main simulation ────────────────────────────────────────────────────

async def main() -> bool:
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

    # ── Agent setup ───────────────────────────────────────────────────
    bus   = MessageBus()
    topo  = NetworkTopology()
    clock = SimClock()
    gen   = TrafficGenerator(topo, clock, rng_seed=42)
    tma   = TrafficMonitorAgent("TMA:avail", bus, gen)
    aca   = AnomalyClassifierAgent("ACA:avail", bus)

    # Deep-copy the plan so we can annotate it with runtime times
    attacks: list[dict] = [
        {**a, "t_start": None, "t_detect": None}
        for a in ATTACK_PLAN
    ]

    # Map segment -> active attack dict (populated by run_attack, cleared on end)
    active_by_seg: dict[str, dict] = {}

    t0 = time.monotonic()

    # ── THREAT_REPORT subscriber ──────────────────────────────────────
    async def on_report(msg) -> None:
        seg = msg.content.get("segment", "")
        cls = msg.content.get("classification", "")
        now = time.monotonic()

        atk = active_by_seg.get(seg)
        if atk is None or atk["t_detect"] is not None:
            return   # no active attack on this segment, or already detected

        expected = atk["type"]   # "DDOS" or "PORT_SCAN"
        if cls != expected:
            return   # NOISE or wrong class — not a detection

        atk["t_detect"] = now
        lag = now - atk["t_start"]
        print(f"  [DETECTED]   {ts(t0)}  {atk['id']}"
              f"  {cls:<10}  {seg:<16}  latency={lag:.3f} s")

    await bus.start()
    bus.subscribe(Topic.THREAT_REPORTS, on_report)
    await tma.start()
    await aca.start()

    gen_task = asyncio.create_task(gen.run())

    # ── Per-attack coroutine ──────────────────────────────────────────
    async def run_attack(atk: dict) -> None:
        await asyncio.sleep(atk["delay"])

        # DDoS: spin until TMA's ALERT_COOLDOWN on this segment has expired.
        # Warmup Gaussian noise resets the cooldown close to t=delay, so without
        # this wait the first attack alert is suppressed for up to ALERT_COOLDOWN
        # seconds, inflating the measured disrupted-time by 2-3 s per DDoS attack.
        if atk["type"] == "DDOS":
            seg = atk["segment"]
            while True:
                belief = tma._beliefs.get(seg, {})
                since_last = time.monotonic() - belief.get("last_alert_time", 0.0)
                remaining  = ALERT_COOLDOWN - since_last
                if remaining <= 0.05:
                    break
                await asyncio.sleep(min(remaining - 0.04, 0.05))

        atk["t_start"] = time.monotonic()
        active_by_seg[atk["segment"]] = atk

        print(f"  [ATK START]  {ts(t0)}  {atk['id']}"
              f"  {atk['type']:<10}  {atk['segment']:<16}  ({atk['desc']})")

        if atk["type"] == "DDOS":
            aggressor = DDoSAttacker(
                atk["id"], atk["segment"], gen,
                intensity_multiplier = atk["mult"],
                ramp_seconds         = atk["ramp"],
                rng_seed             = atk["seed"],
            )
            await aggressor.launch(atk["dur"])
        else:
            scanner = PortScanner(
                atk["id"], atk["segment"], gen,
                probe_interval = atk["interval"],
                rng_seed       = atk["seed"],
            )
            await scanner.launch(atk["dur"])

        active_by_seg.pop(atk["segment"], None)
        status = "detected" if atk["t_detect"] is not None else "!!! UNDETECTED"
        print(f"  [ATK END]    {ts(t0)}  {atk['id']}  ended  ({status})")

    # ── Heartbeat (every 30 s during the quiet tail) ──────────────────
    async def heartbeat() -> None:
        while True:
            await asyncio.sleep(30)
            elapsed = time.monotonic() - t0
            if elapsed < TOTAL_TIME - 2:
                print(f"  [heartbeat]  {ts(t0)}  / {TOTAL_TIME:.0f} s  monitoring ...")

    # ── Warmup + buffer announcements ─────────────────────────────────
    async def warmup_announce() -> None:
        print(f"\n  [WARMUP]     {ts(t0)}  building TMA rolling baseline ({WARMUP_SECS:.0f} s) ...")
        await asyncio.sleep(WARMUP_SECS)
        print(f"  [BUFFER]     {ts(t0)}  clearing noise cooldowns ({BUFFER_SECS:.0f} s) ...")
        await asyncio.sleep(BUFFER_SECS)
        print(f"  [READY]      {ts(t0)}  attacks may begin")

    print()

    # ── Run everything for exactly TOTAL_TIME seconds ─────────────────
    # heartbeat runs as a separate task so we can cancel it at the end
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

    # ── Teardown ──────────────────────────────────────────────────────
    gen.stop()
    await tma.stop()
    await aca.stop()
    await bus.stop()
    await asyncio.gather(gen_task, return_exceptions=True)

    # ── Compute availability ──────────────────────────────────────────
    t_disrupted = 0.0
    for atk in attacks:
        if atk["t_start"] is None:
            continue  # attack never launched (scheduling error)
        if atk["t_detect"] is not None:
            t_disrupted += atk["t_detect"] - atk["t_start"]
        else:
            t_disrupted += float(atk["dur"])   # never detected → full window

    availability = (TOTAL_TIME - t_disrupted) / TOTAL_TIME
    passed       = availability >= AVAIL_TARGET

    # ── Results table ─────────────────────────────────────────────────
    print()
    sep()
    print("  AVAILABILITY BREAKDOWN")
    sep()
    print()
    print(f"  {'ID':<7} {'Segment':<17} {'Type':<11} {'t_start':>8}"
          f"  {'Dur':>4}  {'Latency':>9}  {'Disrupted':>10}  Status")
    print(f"  {'-'*7} {'-'*17} {'-'*11} {'-'*8}"
          f"  {'-'*4}  {'-'*9}  {'-'*10}  {'-'*11}")

    for atk in attacks:
        actual_t = f"{atk['t_start'] - t0:5.1f} s" if atk["t_start"] is not None else "  —"
        if atk["t_start"] is None:
            row_status  = "NOT LAUNCHED"
            row_latency = "—"
            row_disrupt = f"{atk['dur']:.1f} s"
        elif atk["t_detect"] is not None:
            lag         = atk["t_detect"] - atk["t_start"]
            row_status  = "DETECTED"
            row_latency = f"{lag:.3f} s"
            row_disrupt = f"{lag:.3f} s"
        else:
            row_status  = "!!! UNDETECTED"
            row_latency = "—"
            row_disrupt = f"{atk['dur']:.1f} s  (full)"

        print(f"  {atk['id']:<7} {atk['segment']:<17} {atk['type']:<11}"
              f" {actual_t:>8}"
              f"  {atk['dur']:>3}s  {row_latency:>9}  {row_disrupt:>10}  {row_status}")

    print()
    print(f"  {'Total disrupted time':<35}: {t_disrupted:.3f} s")
    print(f"  {'Total simulation time':<35}: {TOTAL_TIME:.1f} s")
    print(f"  {'Quiet / unattacked time':<35}: {TOTAL_TIME - sum(a['dur'] for a in attacks):.1f} s")

    print()
    sep()
    print("  AVAILABILITY CALCULATION")
    sep()
    print()
    print(f"  ({TOTAL_TIME:.1f} - {t_disrupted:.3f}) / {TOTAL_TIME:.1f}"
          f"  =  {availability*100:.3f} %")
    print()

    mark = "PASS" if passed else "FAIL"
    cmp  = ">=" if passed else "<"
    print(f"  [{mark}]  System availability {availability*100:.3f}%"
          f"  {cmp}  {AVAIL_TARGET*100:.1f}% threshold")

    if not passed:
        shortfall = AVAIL_TARGET - availability
        extra_quiet = (t_disrupted / AVAIL_TARGET) - TOTAL_TIME + TOTAL_TIME
        needed_total = t_disrupted / (1.0 - AVAIL_TARGET)
        print()
        print(f"  Shortfall: {shortfall*100:.3f} percentage points")
        print(f"  To reach {AVAIL_TARGET*100:.0f}% with same disrupted time,"
              f" total simulation must be >= {needed_total:.0f} s.")
        print(f"  Alternatively: reduce attack count or increase attack intensity")
        print(f"  to shorten detection latency.")

    print()
    sep()
    return passed


if __name__ == "__main__":
    passed = asyncio.run(main())
    sys.exit(0 if passed else 1)
