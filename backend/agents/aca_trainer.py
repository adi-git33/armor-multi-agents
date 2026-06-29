"""
ACA Trainer
===========
Generates realistic labelled training data across varied attack scenarios,
trains a DecisionTreeClassifier, and saves the model to disk.

Scenarios
---------
DDoS  (4 intensities × N seeds)
  subtle    2.2×  — deviation ~10s, overlaps with strong Gaussian noise
  moderate  2.5×  — deviation ~13s, moderately ambiguous
  strong    4.0×  — deviation ~23s, clearly above noise
  extreme  10.0×  — deviation ~60s, unmistakable

Port scan  (2 speeds × N seeds)
  normal    probe every 0.3s — port_growth_rate ~3.3/s
  stealthy  probe every 0.7s — port_growth_rate ~1.4/s

Noise
  pure       — only natural Gaussian traffic
  legit_multi — legitimate client hitting 3 fixed ports slowly
                fires TMA alert (port_count=3) but should be NOISE

Per-alert labelling (not per-scenario):
  PORT_SCAN  — anomaly_type=="PORT_SCAN"  AND scenario is a scan run
  DDOS       — anomaly_type=="VOLUME_SPIKE" AND scenario is DDoS AND deviation >= DDOS_DEV_FLOOR
  NOISE      — everything else

Run once before the ACA:
    python -m agents.aca_trainer
"""

from __future__ import annotations
import asyncio
import pickle
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Ensure intra-backend imports (bus/core/simulation/agents) resolve whether
# this module is run as `python -m agents.aca_trainer` or `python -m backend.agents.aca_trainer`.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from bus.message_bus import MessageBus
from core.messages import Topic
from core.models import Packet
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner
from agents.tma import TrafficMonitorAgent

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "aca_model.pkl"

FEATURE_NAMES = [
    "anomaly_type_enc",     # 0 = VOLUME_SPIKE,  1 = PORT_SCAN
    "deviation",
    "severity",
    "port_count",
    "port_growth_rate",     # unique ports / seconds since IP first seen
    "elapsed_scan_secs",    # seconds since this src IP appeared in the tracker
    "recent_alert_count",   # TMA alerts on this segment in last 30 s
    "max_deviation_30s",    # highest deviation across that window
    "cross_segment_count",  # other segments also alerting in last 5 s
]

LABEL_NOISE     = 0
LABEL_DDOS      = 1
LABEL_PORT_SCAN = 2
LABEL_NAMES     = ["NOISE", "DDOS", "PORT_SCAN"]

# Alerts during a DDoS scenario above this deviation are labelled DDOS.
# Set at 3s so there is genuine overlap with Gaussian noise (which can reach
# 4-5s), but the early-ramp 2-3s portion is excluded as noise.
# Result: ~80-90 % accuracy — realistic without being impossible.
DDOS_DEV_FLOOR = 3.0


# ──────────────────────────────────────────────────────────────────────
# Scenario descriptors
# ──────────────────────────────────────────────────────────────────────

@dataclass
class Scenario:
    name:           str
    base_label:     int    # DDOS / PORT_SCAN / NOISE
    ddos_mult:      float = 0.0   # intensity multiplier (DDoS only)
    ddos_ramp:      float = 3.0   # ramp seconds
    probe_interval: float = 0.3   # port scan probe interval
    attack_duration: float = 10.0


SCENARIOS = [
    # ── DDoS variants ─────────────────────────────────────────────────
    Scenario("ddos_subtle",   LABEL_DDOS, ddos_mult=2.2,  ddos_ramp=5.0, attack_duration=12.0),
    Scenario("ddos_moderate", LABEL_DDOS, ddos_mult=2.5,  ddos_ramp=4.0, attack_duration=12.0),
    Scenario("ddos_strong",   LABEL_DDOS, ddos_mult=4.0,  ddos_ramp=3.0, attack_duration=12.0),
    Scenario("ddos_extreme",  LABEL_DDOS, ddos_mult=10.0, ddos_ramp=2.0, attack_duration=12.0),
    # ── Port-scan variants ────────────────────────────────────────────
    Scenario("scan_normal",   LABEL_PORT_SCAN, probe_interval=0.3, attack_duration=12.0),
    Scenario("scan_stealthy", LABEL_PORT_SCAN, probe_interval=0.7, attack_duration=12.0),
    # ── Noise variants ────────────────────────────────────────────────
    Scenario("noise_pure",    LABEL_NOISE, attack_duration=10.0),
    Scenario("noise_legit",   LABEL_NOISE, attack_duration=12.0),  # legit multi-port
]


# ──────────────────────────────────────────────────────────────────────
# Legitimate multi-port injector (creates TMA false positives)
# ──────────────────────────────────────────────────────────────────────

async def _inject_legit_multiport(
    gen: TrafficGenerator,
    segment_id: str,
    duration: float,
    rng: np.random.Generator,
) -> None:
    """
    Simulates a legitimate client visiting 3 fixed ports on a server slowly.
    This fires a TMA PORT_SCAN alert (port_count=3) but at a very low
    port_growth_rate, teaching the ACA that not every 3-port alert is a scan.
    """
    hosts     = gen.topology.hosts_in(segment_id)
    target_ip = hosts[0].ip if hosts else "10.0.1.10"
    src_ip    = "10.0.1.100"          # internal workstation
    legit_ports = [80, 443, 8080]     # fixed — no new ports ever added

    start     = time.monotonic()
    port_idx  = 0
    while time.monotonic() - start < duration:
        port = legit_ports[port_idx % len(legit_ports)]
        pkt  = Packet(
            src_ip   = src_ip,
            dst_ip   = target_ip,
            src_port = int(rng.integers(1024, 65535)),
            dst_port = port,
            protocol = "TCP",
            pkt_size = int(rng.integers(200, 1400)),
            segment  = segment_id,
            label    = f"legit-{src_ip}->{port}",
        )
        gen.add_attack_packets(segment_id, [pkt])
        port_idx += 1
        await asyncio.sleep(2.5)   # slow — one visit every 2.5 s


# ──────────────────────────────────────────────────────────────────────
# Per-alert label
# ──────────────────────────────────────────────────────────────────────

def _assign_label(content: dict, scenario: Scenario) -> int:
    """
    Assign a per-alert true label based on the alert content and the
    scenario it came from, not just the scenario label alone.

    This prevents e.g. a 2.3s Gaussian spike during a DDoS run being
    mislabelled as DDOS when it is really just noise.
    """
    atype = content.get("anomaly_type", "")

    if atype == "PORT_SCAN":
        # Legitimate multi-port scenario fires PORT_SCAN alerts that are NOISE
        if scenario.base_label == LABEL_NOISE:
            return LABEL_NOISE
        return LABEL_PORT_SCAN

    if scenario.base_label == LABEL_DDOS:
        dev = abs(content.get("deviation", 0.0))
        return LABEL_DDOS if dev >= DDOS_DEV_FLOOR else LABEL_NOISE

    return LABEL_NOISE


# ──────────────────────────────────────────────────────────────────────
# Single scenario runner
# ──────────────────────────────────────────────────────────────────────

async def _run_scenario(
    scenario: Scenario,
    seed:     int,
    warmup:   float = 5.0,
) -> list[tuple[list[float], int]]:

    bus   = MessageBus()
    clock = SimClock()
    topo  = NetworkTopology()
    gen   = TrafficGenerator(topo, clock, rng_seed=seed)
    tma   = TrafficMonitorAgent("TMA:trainer", bus, gen)
    rng   = np.random.default_rng(seed + 1000)

    alert_history: dict[str, list[dict]] = {sid: [] for sid in topo.segment_ids()}
    samples: list[tuple[list[float], int]] = []
    collection_start: float = float("inf")

    async def on_alert(msg):
        c   = msg.content
        seg = c["segment"]
        now = time.monotonic()
        alert_history[seg].append({"time": now, **c})

        if now < collection_start:
            return

        # features
        enc  = 1.0 if c["anomaly_type"] == "PORT_SCAN" else 0.0
        dev  = float(c.get("deviation",         0.0))
        sev  = float(c.get("severity",          0.0))
        pc   = float(c.get("port_count",        0))
        pgr  = float(c.get("port_growth_rate",  0.0))
        esc  = float(c.get("elapsed_scan_secs", 0.0))

        window = [a for a in alert_history[seg] if now - a["time"] <= 30.0]
        recent = float(len(window))
        maxdev = float(max((a.get("deviation", 0.0) for a in window), default=dev))
        cross  = float(sum(
            1 for s, h in alert_history.items()
            if s != seg and any(now - a["time"] <= 5.0 for a in h)
        ))

        features = [enc, dev, sev, pc, pgr, esc, recent, maxdev, cross]
        samples.append((features, _assign_label(c, scenario)))

    await bus.start()
    await tma.start()
    bus.subscribe(Topic.ALERTS, on_alert)
    gen_task = asyncio.create_task(gen.run())

    await asyncio.sleep(warmup)
    collection_start = time.monotonic()

    if scenario.base_label == LABEL_DDOS:
        attacker = DDoSAttacker(
            f"ddos-{scenario.name}", "public-facing", gen,
            intensity_multiplier = scenario.ddos_mult,
            ramp_seconds         = scenario.ddos_ramp,
            rng_seed             = seed,
        )
        await attacker.launch(scenario.attack_duration)

    elif scenario.base_label == LABEL_PORT_SCAN:
        scanner = PortScanner(
            f"scan-{scenario.name}", "public-facing", gen,
            probe_interval = scenario.probe_interval,
            rng_seed       = seed,
        )
        await scanner.launch(scenario.attack_duration)

    elif scenario.name == "noise_legit":
        await _inject_legit_multiport(gen, "public-facing",
                                      scenario.attack_duration, rng)
    else:
        await asyncio.sleep(scenario.attack_duration)

    await asyncio.sleep(0.5)

    gen.stop()
    await tma.stop()
    await bus.stop()
    await asyncio.gather(gen_task, return_exceptions=True)
    return samples


# ──────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────

async def generate_and_train(n_seeds: int = 6) -> None:
    print("=" * 65)
    print("  ACA Trainer  |  generating synthetic training data")
    print(f"  Scenarios: {len(SCENARIOS)}   Seeds per scenario: {n_seeds}")
    print("=" * 65)

    all_X: list[list[float]] = []
    all_y: list[int]         = []

    for sc in SCENARIOS:
        raw = 0
        for seed in range(n_seeds):
            samples = await _run_scenario(sc, seed=seed * 19 + sc.base_label)
            for features, lbl in samples:
                all_X.append(features)
                all_y.append(lbl)
                raw += 1
        print(f"  {sc.name:18s}  {raw:4d} raw samples")

    X = np.array(all_X, dtype=float)
    y = np.array(all_y, dtype=int)

    print(f"\n  After per-alert labelling:")
    print(f"    NOISE     = {sum(y == LABEL_NOISE)}")
    print(f"    DDOS      = {sum(y == LABEL_DDOS)}")
    print(f"    PORT_SCAN = {sum(y == LABEL_PORT_SCAN)}")
    print(f"    Total     = {len(y)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    clf = DecisionTreeClassifier(max_depth=5, random_state=42,
                                 class_weight="balanced")
    clf.fit(X_train, y_train)

    print("\n  Classification report on held-out 20%:")
    print(classification_report(
        y_test, clf.predict(X_test),
        target_names=LABEL_NAMES, zero_division=0,
    ))

    # Print the top splitting features
    importances = clf.feature_importances_
    ranked = sorted(zip(FEATURE_NAMES, importances),
                    key=lambda x: x[1], reverse=True)
    print("  Feature importances (top 5):")
    for name, imp in ranked[:5]:
        bar = "#" * int(imp * 40)
        print(f"    {name:22s}  {imp:.3f}  {bar}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": clf, "features": FEATURE_NAMES,
                     "labels": LABEL_NAMES}, f)

    print(f"\n  Model saved -> {MODEL_PATH}")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(generate_and_train())
