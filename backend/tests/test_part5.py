"""
Part 5 Test  |  Anomaly Classifier Agent (ACA)
================================================
Checks:
  TMA enhancements
  1.  TMA fires a PORT_SCAN alert during a port scan
  2.  PORT_SCAN alert has correct fields (src_ip, ports_scanned, port_count)
  3.  port_count >= PORT_SCAN_THRESHOLD

  ACA — DDoS path
  4.  ACA publishes a threat report during a DDoS attack
  5.  DDoS threat report classifies as DDOS
  6.  DDoS confidence score >= 0.7
  7.  DDoS recommended_action == QUARANTINE_SEGMENT

  ACA — Port-scan path
  8.  ACA publishes a PORT_SCAN threat report during the scan
  9.  PORT_SCAN recommended_action == BLOCK_SOURCE_IP
  10. PORT_SCAN report carries the source IP in evidence or source_alert

  ACA — general quality
  11. All threat reports contain required fields
  12. NOISE reports use LOG_ONLY action

Timeline
--------
  0s        bus + gen + TMA + ACA start
  0-7s      warmup (baseline settles, cooldowns expire)
  7-17s     DDoS attack on public-facing
  17-22s    recovery
  22-37s    port scan on server segment
  37-40s    final flush
"""

import asyncio
import time
from pathlib import Path

from bus.message_bus import MessageBus
from core.messages import Topic
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner
from agents.tma import TrafficMonitorAgent, PORT_SCAN_THRESHOLD
from agents.aca import AnomalyClassifierAgent

WARMUP        = 7.0
DDOS_DURATION = 10.0
RECOVERY      = 5.0
SCAN_DURATION = 15.0
FLUSH         = 3.0

DDOS_TARGET = "public-facing"
SCAN_TARGET = "server"

REQUIRED_REPORT_FIELDS = {
    "segment", "classification", "confidence",
    "severity", "recommended_action", "evidence",
}


async def main() -> None:
    print("=" * 65)
    print("  Part 5 Test  |  Anomaly Classifier Agent (ACA)")
    print("=" * 65)

    # Pre-flight: model must exist (same location aca.py loads from)
    model_path = Path(__file__).resolve().parent.parent / "models" / "aca_model.pkl"
    if not model_path.exists():
        print("\n  [FAIL] aca_model.pkl not found — run: python -m agents.aca_trainer")
        return

    all_ok = True

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal all_ok
        mark = "PASS" if ok else "FAIL"
        print(f"\n  [{mark}] {label}")
        if detail:
            print(f"         {detail}")
        if not ok:
            all_ok = False

    # ── setup ─────────────────────────────────────────────────────────
    bus   = MessageBus()
    clock = SimClock()
    topo  = NetworkTopology()
    gen   = TrafficGenerator(topo, clock)
    tma   = TrafficMonitorAgent("TMA:1", bus, gen)
    aca   = AnomalyClassifierAgent("ACA:1", bus)

    # collectors
    tma_alerts:      list[dict] = []
    threat_reports:  list[dict] = []
    report_times:    list[float] = []

    async def on_tma_alert(msg):
        tma_alerts.append(msg.content)

    async def on_report(msg):
        threat_reports.append(msg.content)
        report_times.append(time.monotonic())

    await bus.start()
    await tma.start()
    await aca.start()

    bus.subscribe(Topic.ALERTS,        on_tma_alert)
    bus.subscribe(Topic.THREAT_REPORTS, on_report)

    gen_task = asyncio.create_task(gen.run())

    # ── WARMUP ────────────────────────────────────────────────────────
    print(f"\n  [....] Warmup {WARMUP:.0f}s...", end="", flush=True)
    await asyncio.sleep(WARMUP)
    baseline_reports = len(threat_reports)
    print(f" done  ({baseline_reports} warmup reports)")

    # ── DDoS PHASE ────────────────────────────────────────────────────
    print(f"  [....] DDoS on '{DDOS_TARGET}' for {DDOS_DURATION:.0f}s...")
    ddos_start = time.monotonic()
    ddos = DDoSAttacker("ddos-t5", DDOS_TARGET, gen,
                        intensity_multiplier=10.0, ramp_seconds=3.0, rng_seed=5)
    await ddos.launch(DDOS_DURATION)
    await asyncio.sleep(0.5)
    ddos_end = time.monotonic()

    ddos_reports = [
        r for r, t in zip(threat_reports, report_times)
        if t >= ddos_start and t <= ddos_end
        and r.get("segment") == DDOS_TARGET
    ]

    print(f"  [....] Recovery {RECOVERY:.0f}s...")
    await asyncio.sleep(RECOVERY)

    # ── PORT SCAN PHASE ───────────────────────────────────────────────
    print(f"  [....] Port scan on '{SCAN_TARGET}' for {SCAN_DURATION:.0f}s...")
    scan_start = time.monotonic()
    scanner = PortScanner("scan-t5", SCAN_TARGET, gen, rng_seed=5)
    await scanner.launch(SCAN_DURATION)
    await asyncio.sleep(FLUSH)
    scan_end = time.monotonic()

    # TMA port-scan alerts on the scan target
    scan_tma_alerts = [
        a for a in tma_alerts
        if a.get("anomaly_type") == "PORT_SCAN"
        and a.get("segment") == SCAN_TARGET
    ]
    # ACA reports on the scan target during scan window
    scan_reports = [
        r for r, t in zip(threat_reports, report_times)
        if t >= scan_start and t <= scan_end
        and r.get("segment") == SCAN_TARGET
        and r.get("classification") == "PORT_SCAN"
    ]

    # ── CHECKS ────────────────────────────────────────────────────────
    print()

    # 1. TMA PORT_SCAN alert fired
    check(
        "TMA fires PORT_SCAN alert during port scan",
        len(scan_tma_alerts) >= 1,
        f"PORT_SCAN alerts from TMA on '{SCAN_TARGET}': {len(scan_tma_alerts)}",
    )

    # 2. PORT_SCAN alert has correct fields
    first_scan_alert = scan_tma_alerts[0] if scan_tma_alerts else {}
    has_scan_fields = {
        "src_ip", "ports_scanned", "port_count"
    }.issubset(first_scan_alert.keys())
    check(
        "PORT_SCAN alert contains src_ip, ports_scanned, port_count",
        has_scan_fields,
        f"fields present: {set(first_scan_alert.keys())}",
    )

    # 3. port_count >= threshold AND new growth_rate field present
    pc  = first_scan_alert.get("port_count", 0)
    pgr = first_scan_alert.get("port_growth_rate", -1.0)
    check(
        f"PORT_SCAN alert port_count >= threshold ({PORT_SCAN_THRESHOLD}) "
        f"and carries port_growth_rate",
        pc >= PORT_SCAN_THRESHOLD and pgr >= 0,
        f"port_count={pc}  port_growth_rate={pgr:.3f}/s  threshold={PORT_SCAN_THRESHOLD}",
    )

    # 4. ACA publishes threat report during DDoS
    check(
        "ACA publishes threat report during DDoS",
        len(ddos_reports) >= 1,
        f"DDoS threat reports on '{DDOS_TARGET}': {len(ddos_reports)}",
    )

    # 5. DDoS classified as DDOS
    ddos_classified = [r for r in ddos_reports if r.get("classification") == "DDOS"]
    check(
        "DDoS threat report classified as DDOS",
        len(ddos_classified) >= 1,
        f"DDOS-classified reports: {len(ddos_classified)}  "
        f"all classifications: {[r.get('classification') for r in ddos_reports]}",
    )

    # 6. Confidence >= 0.7
    best_conf = max((r.get("confidence", 0) for r in ddos_classified), default=0)
    check(
        "DDoS classification confidence >= 0.7",
        best_conf >= 0.7,
        f"best confidence: {best_conf:.3f}",
    )

    # 7. Recommended action for DDoS
    ddos_action = ddos_classified[0].get("recommended_action", "") if ddos_classified else ""
    check(
        "DDoS recommended_action == QUARANTINE_SEGMENT",
        ddos_action == "QUARANTINE_SEGMENT",
        f"action: '{ddos_action}'",
    )

    # 8. ACA publishes PORT_SCAN threat report
    check(
        "ACA publishes PORT_SCAN threat report during scan",
        len(scan_reports) >= 1,
        f"PORT_SCAN threat reports on '{SCAN_TARGET}': {len(scan_reports)}",
    )

    # 9. PORT_SCAN recommended action
    scan_action = scan_reports[0].get("recommended_action", "") if scan_reports else ""
    check(
        "PORT_SCAN recommended_action == BLOCK_SOURCE_IP",
        scan_action == "BLOCK_SOURCE_IP",
        f"action: '{scan_action}'",
    )

    # 10. PORT_SCAN report carries src_ip evidence
    scan_source = scan_reports[0].get("source_alert", "") if scan_reports else ""
    check(
        "PORT_SCAN threat report identifies source_alert as PORT_SCAN",
        scan_source == "PORT_SCAN",
        f"source_alert: '{scan_source}'",
    )

    # 11. All threat reports have required fields
    bad = [r for r in threat_reports
           if not REQUIRED_REPORT_FIELDS.issubset(r.keys())]
    check(
        "All threat reports contain required fields",
        len(bad) == 0,
        f"malformed reports: {len(bad)} / {len(threat_reports)}",
    )

    # 12. NOISE reports use LOG_ONLY
    noise_reports = [r for r in threat_reports if r.get("classification") == "NOISE"]
    bad_noise = [r for r in noise_reports
                 if r.get("recommended_action") != "LOG_ONLY"]
    check(
        "NOISE threat reports use LOG_ONLY action",
        len(bad_noise) == 0,
        f"NOISE reports: {len(noise_reports)}  wrong action: {len(bad_noise)}",
    )

    # ── teardown ──────────────────────────────────────────────────────
    gen.stop()
    await tma.stop()
    await aca.stop()
    await bus.stop()
    await asyncio.gather(gen_task, return_exceptions=True)

    # ── summary ───────────────────────────────────────────────────────
    all_classes = {}
    for r in threat_reports:
        c = r.get("classification", "?")
        all_classes[c] = all_classes.get(c, 0) + 1

    print()
    print(f"  Threat report breakdown: {all_classes}")
    print(f"  TMA total published: {tma.total_alerts()}")
    print(f"  Bus stats: {bus.stats()}")
    print()
    print(f"  Overall: {'ALL PASS' if all_ok else 'SOME FAILURES'}")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(main())
