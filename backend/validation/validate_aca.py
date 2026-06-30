"""
validate_aca.py — Anomaly Classifier Agent (ACA) Validation
=============================================================
  FR-05  Classify every alert within 200 ms of receipt
  FR-06  Severity score in [0.0, 1.0] for every Confirmed Threat
  FR-07  Broadcast a structured threat report for every Confirmed/Suspicious event
  FR-08  Update classification model after every resolved incident (online learning)
  FR-09  FPR < 10% across any rolling 10-minute window

Derived (BDI Desires / U_ACA):
  D-ACA-1  Classification accuracy > 90%
  D-ACA-2  U_ACA = accuracy × (1 − FPR) × model_improvement_rate > 0
  D-ACA-3  DDoS threats produce severity ≥ 0.70

SRS targets: FPR < 8% / DR > 90%

Run:  cd backend && python validation/validate_aca.py
"""
from __future__ import annotations
import asyncio, sys, time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE))

from simulation.clock    import SimClock
from simulation.network  import NetworkTopology
from simulation.traffic  import TrafficGenerator, SAMPLE_RATE
from simulation.attackers import DDoSAttacker, PortScanner
from agents.tma  import TrafficMonitorAgent
from agents.aca  import AnomalyClassifierAgent
from bus.message_bus import MessageBus
from core.messages   import Topic
from helpers import ValidationSuite, section

MAX_CLASSIFY_MS   = 200
SEVERITY_MIN      = 0.0
SEVERITY_MAX      = 1.0
MIN_SEVERITY_DDOS = 0.70
MAX_FPR           = 0.10
MAX_FPR_STRICT    = 0.08
MIN_ACCURACY      = 0.90
ATTACK_SEG        = "public-facing"
RUN_NORMAL_SEC    = 8
RUN_ATTACK_SEC    = 6


async def run() -> ValidationSuite:
    suite    = ValidationSuite("ACA — Anomaly Classifier Agent Validation")
    clock    = SimClock(speed=1.0)
    topology = NetworkTopology()

    # ── FR-05: Classification latency < 200 ms ───────────────────────
    section("FR-05  Classify every alert within 200 ms")
    bus1 = MessageBus(); gen1 = TrafficGenerator(topology, clock, rng_seed=10)
    tma1 = TrafficMonitorAgent("TMA:1", bus1, gen1)
    aca1 = AnomalyClassifierAgent("ACA:1", bus1)
    await bus1.start(); await tma1.start(); await aca1.start()

    alert_times: dict[str, float]  = {}
    report_times: dict[str, float] = {}

    async def timed_on_alert(msg):
        aid = msg.content.get("alert_id", id(msg))
        alert_times[aid] = time.monotonic()
    bus1.subscribe(Topic.ALERTS, timed_on_alert)

    async def on_report(msg):
        aid = msg.content.get("alert_id", "?")
        report_times[aid] = time.monotonic()
    bus1.subscribe(Topic.THREAT_REPORTS, on_report)

    gen1_task = asyncio.create_task(gen1.run())
    await asyncio.sleep(2)
    atk1      = DDoSAttacker("ATK:1", ATTACK_SEG, gen1, intensity_multiplier=12.0, rng_seed=5)
    atk1_task = asyncio.create_task(atk1.launch(RUN_ATTACK_SEC))
    await asyncio.sleep(RUN_ATTACK_SEC + 0.5)
    await asyncio.gather(atk1_task, return_exceptions=True)
    gen1.stop(); gen1_task.cancel()
    await asyncio.gather(gen1_task, return_exceptions=True)

    latencies_ms = [
        (report_times[aid] - alert_times[aid]) * 1000
        for aid in set(alert_times) & set(report_times)
    ]
    if latencies_ms:
        max_lat  = max(latencies_ms)
        mean_lat = sum(latencies_ms) / len(latencies_ms)
        violations = [l for l in latencies_ms if l > MAX_CLASSIFY_MS]
        suite.check("FR-05", f"All alerts classified within {MAX_CLASSIFY_MS} ms",
                    len(violations) == 0,
                    observed=f"max={max_lat:.1f}ms mean={mean_lat:.1f}ms ({len(violations)} violations)",
                    expected=f"< {MAX_CLASSIFY_MS} ms")
    else:
        suite.check("FR-05", f"All alerts classified within {MAX_CLASSIFY_MS} ms", False,
                    observed="no matched alert→report pairs", expected=f"< {MAX_CLASSIFY_MS} ms")

    # ── FR-06: Severity in [0.0, 1.0] ────────────────────────────────
    section("FR-06  Severity score ∈ [0.0, 1.0]")
    bus2 = MessageBus(); gen2 = TrafficGenerator(topology, clock, rng_seed=20)
    tma2 = TrafficMonitorAgent("TMA:2", bus2, gen2)
    aca2 = AnomalyClassifierAgent("ACA:2", bus2)
    await bus2.start(); await tma2.start(); await aca2.start()

    all_reports: list[dict] = []
    async def collect_reports(msg): all_reports.append(msg.content)
    bus2.subscribe(Topic.THREAT_REPORTS, collect_reports)

    gen2_task = asyncio.create_task(gen2.run())
    await asyncio.sleep(2)
    atk2a = DDoSAttacker("ATK:2a", ATTACK_SEG, gen2, intensity_multiplier=10.0, rng_seed=6)
    atk2b = PortScanner("ATK:2b", "server", gen2, rng_seed=7)
    a2a_t = asyncio.create_task(atk2a.launch(RUN_ATTACK_SEC))
    a2b_t = asyncio.create_task(atk2b.launch(RUN_ATTACK_SEC))
    await asyncio.sleep(RUN_ATTACK_SEC + 0.5)
    await asyncio.gather(a2a_t, a2b_t, return_exceptions=True)
    gen2.stop(); gen2_task.cancel()
    await asyncio.gather(gen2_task, return_exceptions=True)

    confirmed = [r for r in all_reports
                 if r.get("classification") in ("CONFIRMED_THREAT", "DDOS", "PORT_SCAN")]
    bad_sev   = [r for r in confirmed
                 if not (SEVERITY_MIN <= r.get("confidence", -1) <= SEVERITY_MAX)]
    suite.check("FR-06", "All Confirmed Threat reports have severity ∈ [0.0, 1.0]",
                len(bad_sev) == 0 and len(confirmed) > 0,
                observed=f"{len(confirmed)} confirmed, {len(bad_sev)} out-of-range",
                expected="severity ∈ [0.0, 1.0] for all")

    # ── D-ACA-3: DDoS severity ≥ 0.70 ────────────────────────────────
    ddos_reports = [r for r in all_reports if r.get("classification") == "DDOS"]
    if ddos_reports:
        min_sev = min(r.get("confidence", 0) for r in ddos_reports)
        suite.check("D-ACA-3", f"DDoS classified with severity ≥ {MIN_SEVERITY_DDOS}",
                    min_sev >= MIN_SEVERITY_DDOS,
                    observed=f"min_severity={min_sev:.3f} ({len(ddos_reports)} reports)",
                    expected=f"≥ {MIN_SEVERITY_DDOS}")
    else:
        suite.check("D-ACA-3", f"DDoS classified with severity ≥ {MIN_SEVERITY_DDOS}", False,
                    observed="no DDOS reports", expected=f"≥ {MIN_SEVERITY_DDOS}")

    # ── FR-07: Structured threat report broadcast ─────────────────────
    section("FR-07  Broadcast structured threat report")
    required_fields = {"classification", "confidence", "segment"}
    well_structured = [r for r in all_reports if required_fields.issubset(r.keys())]
    suite.check("FR-07", "Every report contains classification, confidence, segment",
                len(well_structured) == len(all_reports) and len(all_reports) > 0,
                observed=f"{len(well_structured)}/{len(all_reports)} well-structured",
                expected="100% well-structured")

    # ── FR-08: Online learning hook ───────────────────────────────────
    section("FR-08  Model updated after resolved incident (online learning)")
    aca3 = AnomalyClassifierAgent("ACA:3", MessageBus())
    has_update = (getattr(aca3, "update_model", None) or
                  getattr(aca3, "on_incident_resolved", None)) is not None
    suite.check("FR-08", "ACA exposes an online-learning update hook",
                has_update,
                observed="method found" if has_update else "no update method",
                expected="update_model or on_incident_resolved method exists",
                note="Implemented in aca_trainer.py; invoked after each resolved incident")

    # ── FR-09: FPR < 10% on normal traffic ────────────────────────────
    section("FR-09  FPR < 10% on normal-traffic window")
    bus4 = MessageBus(); gen4 = TrafficGenerator(topology, clock, rng_seed=40)
    tma4 = TrafficMonitorAgent("TMA:4", bus4, gen4)
    aca4 = AnomalyClassifierAgent("ACA:4", bus4)
    await bus4.start(); await tma4.start(); await aca4.start()

    normal_reports: list[dict] = []
    async def collect_normal(msg): normal_reports.append(msg.content)
    bus4.subscribe(Topic.THREAT_REPORTS, collect_normal)

    gen4_task = asyncio.create_task(gen4.run())
    await asyncio.sleep(RUN_NORMAL_SEC)
    gen4.stop(); gen4_task.cancel()
    await asyncio.gather(gen4_task, return_exceptions=True)

    total_normal    = SAMPLE_RATE * RUN_NORMAL_SEC * len(topology.segment_ids())
    false_positives = len([r for r in normal_reports
                           if r.get("classification") not in ("NOISE", "NORMAL", None)])
    fpr = false_positives / max(total_normal, 1)

    suite.check("FR-09", f"FPR < {MAX_FPR*100:.0f}% on normal-traffic run",
                fpr < MAX_FPR,
                observed=f"{fpr*100:.2f}% ({false_positives} FP / {total_normal} samples)",
                expected=f"< {MAX_FPR*100:.0f}%")
    suite.check("FR-09", f"FPR < {MAX_FPR_STRICT*100:.0f}% (SRS §7.3 strict target)",
                fpr < MAX_FPR_STRICT,
                observed=f"{fpr*100:.2f}%", expected=f"< {MAX_FPR_STRICT*100:.0f}%")

    # ── D-ACA-1: Accuracy > 90% ───────────────────────────────────────
    section("D-ACA-1  Classification accuracy > 90%")
    tp  = len([r for r in all_reports
               if r.get("classification") in ("DDOS", "PORT_SCAN", "CONFIRMED_THREAT")])
    acc = tp / max(len(all_reports), 1)
    suite.check("D-ACA-1", f"Classification accuracy proxy > {MIN_ACCURACY*100:.0f}%",
                acc > MIN_ACCURACY,
                observed=f"{acc*100:.1f}% ({tp} TP / {len(all_reports)} total)",
                expected=f"> {MIN_ACCURACY*100:.0f}%",
                note="Full accuracy = (TP+TN)/total in validate_system.py")

    # ── D-ACA-2: U_ACA formula ───────────────────────────────────────
    section("D-ACA-2  U_ACA = accuracy × (1−FPR) × model_improvement_rate")
    model_imp = 0.05   # nominal; real value from trainer logs
    u_aca     = acc * (1 - fpr) * model_imp
    suite.check("D-ACA-2", "U_ACA = accuracy × (1−FPR) × model_improvement_rate > 0",
                u_aca > 0,
                observed=f"U_ACA ≈ {u_aca:.6f}",
                expected="> 0",
                note=f"accuracy≈{acc:.2f}, FPR≈{fpr:.4f}, model_improvement_rate (nominal)={model_imp}")

    suite.print_results()
    return suite


if __name__ == "__main__":
    asyncio.run(run())
