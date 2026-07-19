"""
ACA Detection Rate Test  (Validation §V-ACA-01)
================================================
Validates that the full TMA → ACA pipeline achieves >= 90% detection rate
across five attack scenarios: DDoS (moderate / strong / extreme) and
Port Scan (normal / stealthy).

Detection rate definition
--------------------------
Denominator — qualifying attack alerts:
  DDoS      VOLUME_SPIKE from TMA with |deviation| >= DDOS_DEV_FLOOR (3.0 sigma).
             Alerts below the floor are early-ramp signals genuinely
             indistinguishable from strong Gaussian noise; the trainer
             labels them NOISE, so we exclude them from the denominator.
  PORT_SCAN every PORT_SCAN alert from TMA (none are ambiguous)

Numerator — correctly detected:
  DDoS      ACA classification == "DDOS"
  PORT_SCAN ACA classification == "PORT_SCAN"

Pairing guarantee
------------------
ACA processes alerts FIFO and emits exactly one THREAT_REPORT per ALERT.
We subscribe our on_alert listener BEFORE aca.start() so the alert is
captured in `pending` before ACA's handler runs and publishes its report.
matched_pairs[i] = (alert_i, report_i) by insertion order.

Each scenario runs with a fresh TMA + ACA to prevent history carryover.

Expected runtime: ~90 s  (5 scenarios x ~18 s each)
"""

from __future__ import annotations
import asyncio
import logging
import time

from bus.message_bus import MessageBus
from core.messages import Topic
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner
from agents.tma import TrafficMonitorAgent
from agents.aca import AnomalyClassifierAgent

logging.basicConfig(level=logging.WARNING)

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

DDOS_DEV_FLOOR      = 3.0   # sigma — mirrors aca_trainer.py DDOS_DEV_FLOOR
DETECTION_THRESHOLD = 0.90  # overall rate must meet this to PASS
WARMUP_SECS         = 5.0   # s — build a stable rolling baseline
DRAIN_SECS          = 0.5   # s — flush stale warmup messages before collecting
SETTLE_SECS         = 1.5   # s — let ACA finish queued alerts after attack ends

W = 72   # print width for separators

SCENARIOS = [
    {
        "name":       "ddos_moderate",
        "type":       "ddos",
        "segment":    "public-facing",
        "params":     "2.5x baseline, ramp 4 s",
        "multiplier": 2.5,
        "ramp":       4.0,
        "interval":   None,
        "duration":   12.0,
        "seed":       11,
    },
    {
        "name":       "ddos_strong",
        "type":       "ddos",
        "segment":    "public-facing",
        "params":     "4.0x baseline, ramp 3 s",
        "multiplier": 4.0,
        "ramp":       3.0,
        "interval":   None,
        "duration":   12.0,
        "seed":       22,
    },
    {
        "name":       "ddos_extreme",
        "type":       "ddos",
        "segment":    "public-facing",
        "params":     "10.0x baseline, ramp 2 s",
        "multiplier": 10.0,
        "ramp":       2.0,
        "interval":   None,
        "duration":   12.0,
        "seed":       33,
    },
    {
        "name":       "scan_normal",
        "type":       "scan",
        "segment":    "public-facing",
        "params":     "probe every 0.3 s",
        "multiplier": None,
        "ramp":       None,
        "interval":   0.3,
        "duration":   12.0,
        "seed":       44,
    },
    {
        "name":       "scan_stealthy",
        "type":       "scan",
        "segment":    "public-facing",
        "params":     "probe every 0.7 s (stealthy)",
        "multiplier": None,
        "ramp":       None,
        "interval":   0.7,
        "duration":   12.0,
        "seed":       55,
    },
]


# ---------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------

async def run_scenario(sc: dict) -> tuple[list[tuple], dict]:
    """
    Spin up a fresh TMA + ACA, run one attack, return matched pairs.

    Returns
    -------
    matched_pairs : list of (alert_content, report_content) dicts
    stats         : bus counters + attack_elapsed_s
    """
    bus   = MessageBus()
    topo  = NetworkTopology()
    clock = SimClock()
    gen   = TrafficGenerator(topo, clock, rng_seed=sc["seed"] * 7 + 3)
    tma   = TrafficMonitorAgent("TMA:test", bus, gen)
    aca   = AnomalyClassifierAgent("ACA:test", bus)

    pending : list[dict]  = []   # alerts waiting to be paired with a report
    pairs   : list[tuple] = []   # (alert_content, report_content)
    orphan_r: list[dict]  = []   # reports that arrived with no preceding alert
    state = {"collecting": False}

    async def on_alert(msg) -> None:
        if not state["collecting"]:
            return
        pending.append(msg.content.copy())

    async def on_report(msg) -> None:
        if not state["collecting"]:
            return
        rpt = msg.content.copy()
        if pending:
            pairs.append((pending.pop(0), rpt))
        else:
            orphan_r.append(rpt)

    # Subscribe our listeners BEFORE aca.start() so on_alert always fires
    # before ACA._on_alert — the alert is in `pending` before the report arrives.
    await bus.start()
    bus.subscribe(Topic.ALERTS,         on_alert)
    bus.subscribe(Topic.THREAT_REPORTS, on_report)
    await tma.start()
    await aca.start()
    gen_task = asyncio.create_task(gen.run())

    # Warmup: let the rolling baseline stabilise
    print(f"    warmup {WARMUP_SECS:.0f} s ...", end="", flush=True)
    await asyncio.sleep(WARMUP_SECS)

    # Drain any alerts still queued from the warmup period
    print(f"  draining ...", end="", flush=True)
    await asyncio.sleep(DRAIN_SECS)
    state["collecting"] = True
    print(f"  collecting")

    # Launch attack
    print(f"    attack running ...", flush=True)
    t_start = time.monotonic()

    if sc["type"] == "ddos":
        atk = DDoSAttacker(
            "ddos-test", sc["segment"], gen,
            intensity_multiplier=sc["multiplier"],
            ramp_seconds=sc["ramp"],
            rng_seed=sc["seed"],
        )
        await atk.launch(sc["duration"])
    else:
        atk = PortScanner(
            "scan-test", sc["segment"], gen,
            probe_interval=sc["interval"],
            rng_seed=sc["seed"],
        )
        await atk.launch(sc["duration"])

    # Let ACA finish processing any alerts still in the queue
    await asyncio.sleep(SETTLE_SECS)
    elapsed = round(time.monotonic() - t_start, 1)

    gen.stop()
    await tma.stop()
    await aca.stop()
    stats = {**bus.stats(), "attack_elapsed_s": elapsed}
    await bus.stop()
    await asyncio.gather(gen_task, return_exceptions=True)

    # Warn about unexpected pairing mismatches
    if orphan_r:
        print(f"    !! {len(orphan_r)} report(s) arrived with no preceding alert")
    if pending:
        print(f"    !! {len(pending)} alert(s) received no report — appended as (alert, None)")
        for a in pending:
            pairs.append((a, None))

    return pairs, stats


# ---------------------------------------------------------------------
# Pair classifier
# ---------------------------------------------------------------------

def classify_pair(pair: tuple, sc: dict) -> dict:
    """
    Decide how this (alert, report) pair contributes to the detection metric.

    outcome
    -------
    detected    qualifying attack alert, ACA correct  -> counts in num + denom
    missed      qualifying attack alert, ACA wrong    -> counts in denom only
    skipped     VOLUME_SPIKE below DDOS_DEV_FLOOR     -> excluded (ambiguous)
    off_segment alert from a segment not under attack -> excluded
    noise_alert non-attack alert type on attack seg   -> excluded
    no_report   ACA emitted no report (unexpected)    -> excluded, logged
    """
    alert, report = pair

    if report is None:
        return {
            "outcome": "no_report",
            "seg":   alert.get("segment", "?"),
            "atype": alert.get("anomaly_type", "?"),
            "dev": 0.0, "dev_raw": 0.0, "cls": "?", "conf": 0.0,
            "sev": 0.0, "filter": "?", "pc": 0, "pgr": 0.0, "esc": 0.0,
        }

    seg     = alert.get("segment",          "")
    atype   = alert.get("anomaly_type",     "")
    dev_raw = alert.get("deviation",        0.0)
    dev     = abs(dev_raw)
    cls     = report.get("classification",  "?")
    conf    = report.get("confidence",      0.0)
    sev     = report.get("severity",        0.0)
    fltr    = report.get("evidence", {}).get("filter", "?")
    pc      = alert.get("port_count",        0)
    pgr     = alert.get("port_growth_rate",  0.0)
    esc     = alert.get("elapsed_scan_secs", 0.0)

    base = {
        "seg": seg, "atype": atype, "dev": dev, "dev_raw": dev_raw,
        "cls": cls, "conf": conf, "sev": sev, "filter": fltr,
        "pc": pc, "pgr": pgr, "esc": esc,
    }

    if seg != sc["segment"]:
        return {**base, "outcome": "off_segment"}

    if sc["type"] == "ddos":
        if atype != "VOLUME_SPIKE":
            return {**base, "outcome": "noise_alert"}
        if dev < DDOS_DEV_FLOOR:
            return {**base, "outcome": "skipped",
                    "reason": f"|dev|={dev:.2f}s < floor {DDOS_DEV_FLOOR}s"}
        return {**base, "outcome": "detected" if cls == "DDOS" else "missed"}

    else:  # scan
        if atype != "PORT_SCAN":
            return {**base, "outcome": "noise_alert"}
        return {**base, "outcome": "detected" if cls == "PORT_SCAN" else "missed"}


# ---------------------------------------------------------------------
# Per-scenario alert table
# ---------------------------------------------------------------------

def print_alert_table(sc: dict, classified: list[dict]) -> tuple[int, int]:
    """Print one row per pair. Returns (qualifying, detected)."""

    is_ddos = sc["type"] == "ddos"

    if is_ddos:
        print(f"\n    {'#':>3}  {'Segment':<15} {'Type':<13} {'Dev':>8}  "
              f"{'ACA Class':<11} {'Conf':>5}  {'Sev':>5}  {'Filter':<14}  Result")
        print(f"    {'-'*3}  {'-'*15} {'-'*13} {'-'*8}  "
              f"{'-'*11} {'-'*5}  {'-'*5}  {'-'*14}  {'-'*22}")
    else:
        print(f"\n    {'#':>3}  {'Segment':<15} {'Type':<13} {'Ports':>5} "
              f"{'Rate/s':>6}  {'Elapsed':>7}  "
              f"{'ACA Class':<11} {'Conf':>5}  {'Filter':<14}  Result")
        print(f"    {'-'*3}  {'-'*15} {'-'*13} {'-'*5} "
              f"{'-'*6}  {'-'*7}  "
              f"{'-'*11} {'-'*5}  {'-'*14}  {'-'*22}")

    qualifying = detected = 0

    for i, c in enumerate(classified, 1):
        outcome = c["outcome"]

        if outcome == "detected":
            result = "DETECTED"
            qualifying += 1
            detected   += 1
        elif outcome == "missed":
            result = "*** MISSED ***"
            qualifying += 1
        elif outcome == "skipped":
            result = f"skip  {c.get('reason', '')}"
        elif outcome == "off_segment":
            result = f"off-seg ({c['seg']})"
        elif outcome == "no_report":
            result = "[no report from ACA]"
        else:
            result = f"excluded ({c.get('atype', '?')})"

        if is_ddos:
            dev_s = f"{c['dev_raw']:+.2f}s"
            print(f"    {i:>3}  {c['seg']:<15} {c['atype']:<13} {dev_s:>8}  "
                  f"{c['cls']:<11} {c['conf']:>5.2f}  {c['sev']:>5.3f}  "
                  f"{c['filter']:<14}  {result}")
        else:
            pgr_s = f"{c['pgr']:.2f}"
            esc_s = f"{c['esc']:.2f}s"
            print(f"    {i:>3}  {c['seg']:<15} {c['atype']:<13} {c['pc']:>5} "
                  f"{pgr_s:>6}  {esc_s:>7}  "
                  f"{c['cls']:<11} {c['conf']:>5.2f}  "
                  f"{c['filter']:<14}  {result}")

    return qualifying, detected


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

async def test_aca_detection_rate() -> None:
    print("=" * W)
    print("  ACA Detection Rate Test  (Validation §V-ACA-01)")
    print("  Pipeline : TMA -> ALERTS bus -> ACA -> THREAT_REPORTS bus")
    print(f"  Threshold: detection rate >= {DETECTION_THRESHOLD*100:.0f}%")
    print(f"  DDoS floor: |deviation| >= {DDOS_DEV_FLOOR} sigma to count as qualifying")
    print(f"  Scenarios: {len(SCENARIOS)}  (DDoS x3, PortScan x2)")
    print(f"  Warmup: {WARMUP_SECS:.0f}s per scenario   Settle: {SETTLE_SECS:.1f}s post-attack")
    print("=" * W)

    results    : list[dict] = []
    all_missed : list[dict] = []

    for idx, sc in enumerate(SCENARIOS, 1):
        print(f"\n  -- Scenario {idx}/{len(SCENARIOS)}: {sc['name']}  [{sc['params']}] --")
        if sc["type"] == "ddos":
            print(f"     segment={sc['segment']}  multiplier={sc['multiplier']}x"
                  f"  ramp={sc['ramp']}s  duration={sc['duration']}s  seed={sc['seed']}")
        else:
            print(f"     segment={sc['segment']}  interval={sc['interval']}s"
                  f"  duration={sc['duration']}s  seed={sc['seed']}")
        print()

        pairs, stats = await run_scenario(sc)
        classified   = [classify_pair(p, sc) for p in pairs]

        qualifying, detected = print_alert_table(sc, classified)

        for c in classified:
            if c["outcome"] == "missed":
                all_missed.append({**c, "scenario": sc["name"]})

        n_off   = sum(1 for c in classified if c["outcome"] == "off_segment")
        n_skip  = sum(1 for c in classified if c["outcome"] == "skipped")
        n_excl  = sum(1 for c in classified if c["outcome"] in ("noise_alert", "no_report"))
        rate    = detected / qualifying if qualifying > 0 else 0.0
        sc_pass = (rate >= DETECTION_THRESHOLD) or (qualifying == 0)
        mark    = "PASS" if sc_pass else "FAIL"

        print()
        print(f"    {'-' * 66}")
        print(f"    Total (alert, report) pairs        : {len(pairs)}")
        print(f"    Off-segment (other segs, excluded) : {n_off}")
        print(f"    Skipped (below {DDOS_DEV_FLOOR}sigma DDoS floor) : {n_skip}")
        print(f"    Other excluded (noise/no-report)   : {n_excl}")
        print(f"    Qualifying attack alerts           : {qualifying}")
        print(f"    Correctly detected                 : {detected}")
        print(f"    Missed (mis-classified)            : {qualifying - detected}")
        if qualifying > 0:
            print(f"    Detection rate                     : "
                  f"{detected}/{qualifying} = {rate*100:.1f}%")
        else:
            print(f"    Detection rate                     : "
                  f"N/A  (no qualifying alerts — attack may not have ramped up enough)")
        print(f"    Bus  published={stats['published']:3d}"
              f"  delivered={stats['delivered']:3d}"
              f"  dropped={stats['dropped']:3d}"
              f"  attack_elapsed={stats['attack_elapsed_s']}s")
        print(f"    [{mark}] {sc['name']}: "
              + (f"{rate*100:.1f}%" if qualifying > 0 else "N/A"))

        results.append({
            "sc": sc, "qualifying": qualifying, "detected": detected,
            "rate": rate, "pass": sc_pass, "stats": stats,
        })

    # -- Combined summary -----------------------------------------------

    print()
    print("=" * W)
    print("  COMBINED DETECTION RATE SUMMARY")
    print("=" * W)
    print()

    nc = 17   # name column width
    pc = 28   # params column width
    print(f"  {'Scenario':<{nc}} {'Params':<{pc}} {'Q':>3} {'D':>3} {'Rate':>7}  Result")
    print(f"  {'-'*nc} {'-'*pc} {'-'*3} {'-'*3} {'-'*7}  {'-'*6}")

    total_q = total_d = 0
    any_sc_fail = False

    for r in results:
        sc   = r["sc"]
        q, d = r["qualifying"], r["detected"]
        rt   = r["rate"]
        total_q += q
        total_d += d
        if not r["pass"]:
            any_sc_fail = True
        mark   = "PASS" if r["pass"] else "FAIL"
        rate_s = f"{rt*100:.1f}%" if q > 0 else "N/A"
        print(f"  {sc['name']:<{nc}} {sc['params']:<{pc}} {q:>3} {d:>3} {rate_s:>7}  [{mark}]")

    print(f"  {'-'*nc} {'-'*pc} {'-'*3} {'-'*3} {'-'*7}")
    overall = total_d / total_q if total_q > 0 else 0.0
    print(f"  {'TOTAL':<{nc}} {'':<{pc}} {total_q:>3} {total_d:>3} {overall*100:>6.1f}%")

    # -- Missed alerts breakdown ----------------------------------------

    print()
    if all_missed:
        print(f"  Missed alerts breakdown  ({len(all_missed)} total):")
        print()
        print(f"  {'Scenario':<17} {'Seg':<15} {'Type':<13} "
              f"{'Dev':>8}  {'Classified':>12} {'Conf':>5}  "
              f"{'Sev':>5}  Filter")
        print(f"  {'-'*17} {'-'*15} {'-'*13} "
              f"{'-'*8}  {'-'*12} {'-'*5}  "
              f"{'-'*5}  {'-'*14}")
        for m in all_missed:
            dev_s = f"{m['dev_raw']:+.2f}s" if "dev_raw" in m else "  —"
            print(f"  {m['scenario']:<17} {m.get('seg','?'):<15} "
                  f"{m.get('atype','?'):<13} {dev_s:>8}  "
                  f"{m.get('cls','?'):>12} {m.get('conf',0.0):>5.2f}  "
                  f"{m.get('sev',0.0):>5.3f}  {m.get('filter','?')}")
        print()
        print("  Diagnostics:")
        print("    layer1_noise filter + low confidence -> early ramp or borderline")
        print("    layer2_model + NOISE classification  -> model boundary case")
        print("    Check port_count / port_growth_rate for PORT_SCAN misses")
    else:
        print("  No missed alerts — every qualifying attack alert correctly classified.")

    # -- Per-scenario failures note -------------------------------------

    if any_sc_fail:
        print()
        print("  Note: one or more individual scenarios failed the 90% threshold.")
        print("  Review the missed breakdown above and the per-scenario tables.")

    # -- Final verdict --------------------------------------------------

    print()
    overall_pass = overall >= DETECTION_THRESHOLD
    mark = "PASS" if overall_pass else "FAIL"
    cmp  = ">=" if overall_pass else "<"
    print(f"  [{mark}] Overall detection rate {overall*100:.1f}%"
          f" {cmp} {DETECTION_THRESHOLD*100:.0f}% threshold"
          f"  ({total_d}/{total_q} qualifying alerts detected)")

    if not overall_pass and total_q > 0:
        need = int(total_q * DETECTION_THRESHOLD) + 1 - total_d
        print(f"         Need {need} more correct classification(s) to reach threshold.")

    print()
    print("=" * W)
    assert overall_pass, (
        f"detection rate {overall*100:.1f}% < {DETECTION_THRESHOLD*100:.0f}% threshold "
        f"({total_d}/{total_q} qualifying alerts detected)"
    )
