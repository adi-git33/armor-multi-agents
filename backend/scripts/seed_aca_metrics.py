"""
seed_aca_metrics.py — Bootstrap models/aca_metrics.json with a real,
ground-truth-checked confusion matrix (tp/fp/fn/tn) for ACA, so the live
dashboard's Detection Rate / False Positive Rate start from a measured
baseline instead of 0/0 on first launch.

Unlike validation/validate_aca.py (which reports FR-level pass/fail
checks), this script tallies the exact same tp/fp/fn/tn the live server
computes in server.py's StateCollector._on_threat_report: every threat
report is compared against a known ground-truth window (calm / DDoS /
port-scan) to see whether ACA's classification was actually correct.

The live server then loads this file on startup and keeps accumulating
on top of it — this is a one-time seed, not a replacement for live data.

Run:  cd backend && python scripts/seed_aca_metrics.py
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from agents.aca import AnomalyClassifierAgent
from agents.tma import TrafficMonitorAgent
from bus.message_bus import MessageBus
from core.messages import Topic
from simulation.attackers import DDoSAttacker, PortScanner
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator

METRICS_PATH = _HERE.parent / "models" / "aca_metrics.json"

CALM_SEC     = 30
DDOS_SEC     = 20
SCAN_SEC     = 20
COOLDOWN_SEC = 5
DDOS_SEG     = "public-facing"
SCAN_SEG     = "server"

# Keep in sync with server.py's live accounting (ATTACK_GRACE_SECS /
# CALM_LINGER_SECS / ATTACK_MODALITY) — this script's whole purpose is to
# produce the exact tally the live StateCollector would.
ATTACK_GRACE_SECS = 5.0
CALM_LINGER_SECS  = 10.0
ATTACK_MODALITY   = {"DDOS": "VOLUME_SPIKE", "PORT_SCAN": "PORT_SCAN"}


async def main() -> None:
    tally = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    active_attacks: dict[str, str] = {}   # mirrors StateCollector.active_attacks
    attack_started: dict[str, float] = {}
    attack_ended:   dict[str, float] = {}

    clock    = SimClock(speed=1.0)
    topology = NetworkTopology()
    bus      = MessageBus()
    gen      = TrafficGenerator(topology, clock, rng_seed=123)
    tma      = TrafficMonitorAgent("TMA:1", bus, gen)
    aca      = AnomalyClassifierAgent("ACA:1", bus)
    await bus.start()
    await tma.start()
    await aca.start()

    async def on_report(msg) -> None:
        c     = msg.content
        seg   = c.get("segment", "")
        clf   = c.get("classification", "")   # "NOISE" | "DDOS" | "PORT_SCAN"
        src   = c.get("source_alert", "")
        now   = time.monotonic()
        truth = active_attacks.get(seg)
        in_grace  = (truth is not None and
                     now - attack_started.get(seg, now) < ATTACK_GRACE_SECS)
        in_linger = (truth is None and
                     now - attack_ended.get(seg, float("-inf")) < CALM_LINGER_SECS)

        if clf == "NOISE":
            if truth is not None and src == ATTACK_MODALITY.get(truth):
                if not in_grace:
                    tally["fn"] += 1
            else:
                tally["tn"] += 1
        elif truth is not None:
            if clf == truth:
                tally["tp"] += 1
        elif not in_linger:
            tally["fp"] += 1

    bus.subscribe(Topic.THREAT_REPORTS, on_report)

    gen_task = asyncio.create_task(gen.run())

    print(f"[seed] calm window: {CALM_SEC}s")
    await asyncio.sleep(CALM_SEC)

    print(f"[seed] DDoS window on {DDOS_SEG}: {DDOS_SEC}s")
    active_attacks[DDOS_SEG] = "DDOS"
    attack_started[DDOS_SEG] = time.monotonic()
    atk = DDoSAttacker("Seed-DDoS", DDOS_SEG, gen, intensity_multiplier=6.0, ramp_seconds=3.0)
    atk_task = asyncio.create_task(atk.launch(DDOS_SEC))
    await asyncio.sleep(DDOS_SEC + 0.5)
    await asyncio.gather(atk_task, return_exceptions=True)
    del active_attacks[DDOS_SEG]
    attack_ended[DDOS_SEG] = time.monotonic()

    print(f"[seed] cooldown: {COOLDOWN_SEC}s")
    await asyncio.sleep(COOLDOWN_SEC)

    print(f"[seed] port-scan window on {SCAN_SEG}: {SCAN_SEC}s")
    active_attacks[SCAN_SEG] = "PORT_SCAN"
    attack_started[SCAN_SEG] = time.monotonic()
    scanner = PortScanner("Seed-Scan", SCAN_SEG, gen, src_ip="45.33.32.156", probe_interval=0.3)
    scan_task = asyncio.create_task(scanner.launch(SCAN_SEC))
    await asyncio.sleep(SCAN_SEC + 0.5)
    await asyncio.gather(scan_task, return_exceptions=True)
    del active_attacks[SCAN_SEG]
    attack_ended[SCAN_SEG] = time.monotonic()

    gen.stop()
    gen_task.cancel()
    await asyncio.gather(gen_task, return_exceptions=True)

    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(tally, indent=2))

    dr  = tally["tp"] / max(1, tally["tp"] + tally["fn"])
    fpr = tally["fp"] / max(1, tally["fp"] + tally["tn"])
    print(f"[seed] tally: {tally}")
    print(f"[seed] DR={dr:.3f}  FPR={fpr:.3f}")
    print(f"[seed] wrote {METRICS_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
