"""
validate_stress.py — High-Stress Load Validation (degradation source)
=======================================================================
Runs the full five-agent system under the heaviest concurrent load the
SRS contemplates — five simultaneous attacks across the topology, two of
them stacked on the same segment — and MEASURES the six metrics shown in
Figure 6 (Degradation Analysis). Until this suite existed the figure's
"High Stress" column was a fixed illustrative constant; now every run
writes stress_results.json and visualize_results.py picks the measured
values up for both the PNG figure and the frontend's live chart.

Load profile (12 s, all concurrent):
  public-facing  DDoS 10x  +  port scan   (stacked — two attack types)
  server         DDoS 8x   +  port scan   (stacked)
  sec-mon        DDoS 12x
  internal       calm                      (false-positive control)

Checks:
  ST-01  Detection Rate ≥ 90%  (every attack instance correctly typed)
  ST-02  Report-level FPR ≤ 10% during calm contexts
  ST-03  MTTR_Response < 1000 ms under contention
  ST-04  Social Welfare ≥ 0.80 under stress
  ST-05  Resource overhead < 40%
  ST-06  Auction priority ordering holds under contention

Run:  cd backend && python validation/validate_stress.py
"""
from __future__ import annotations
import asyncio, json, sys, time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE))

from simulation.clock     import SimClock
from simulation.network   import NetworkTopology
from simulation.traffic   import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner
from agents.tma  import TrafficMonitorAgent
from agents.aca  import AnomalyClassifierAgent
from agents.rca  import ResponseCoordinatorAgent
from agents.raa  import ResourceAllocatorAgent
from agents.tia  import ThreatIntelligenceAgent
from bus.message_bus import MessageBus
from core.messages   import Topic
from helpers import ValidationSuite, section
from scenario_lib import priority_ok_label, _sw, measure_resource_overhead

RESULTS_PATH = _HERE / "stress_results.json"

MIN_DR       = 0.90
MAX_FPR      = 0.10
MAX_MTTR_MS  = 1000
MIN_SW       = 0.80
MAX_OVERHEAD = 0.40

WARMUP_SEC = 10.0   # TMA rolling-baseline build + cooldown drain
ATTACK_SEC = 12.0   # long enough for RCA's escalation ladder + votes
DRAIN_SEC  = 3.0    # let in-flight reports/votes/grants settle

# Post-attack linger: TMA's rolling window stays elevated briefly after an
# attack stops, so threat flags in this window are residual, not FPs —
# same convention as the live dashboard's CALM_LINGER_SECS.
LINGER_SEC = 5.0

# (attack_id, segment, type, kwargs)
ATTACK_PLAN = [
    ("ST-DDOS-PF",  "public-facing", "DDOS",      {"intensity_multiplier": 10.0, "ramp_seconds": 1.0, "rng_seed": 301}),
    ("ST-SCAN-PF",  "public-facing", "PORT_SCAN", {"probe_interval": 0.25, "rng_seed": 302, "src_ip": "203.0.113.66"}),
    ("ST-DDOS-SRV", "server",        "DDOS",      {"intensity_multiplier": 8.0,  "ramp_seconds": 1.0, "rng_seed": 303}),
    ("ST-SCAN-SRV", "server",        "PORT_SCAN", {"probe_interval": 0.25, "rng_seed": 304, "src_ip": "198.51.100.23"}),
    ("ST-DDOS-MON", "sec-mon",       "DDOS",      {"intensity_multiplier": 12.0, "ramp_seconds": 1.0, "rng_seed": 305}),
]

# TMA alert modality that carries each attack type (a NOISE verdict on a
# volume alert during a port scan is correct — the scan doesn't move pps).
ATTACK_MODALITY = {"DDOS": "VOLUME_SPIKE", "PORT_SCAN": "PORT_SCAN"}


async def run() -> ValidationSuite:
    suite = ValidationSuite("High-Stress Load Validation (Figure 6 degradation source)")

    section("Building full 5-agent system under 5-attack concurrent load")
    clock    = SimClock(speed=1.0)
    topology = NetworkTopology()
    bus      = MessageBus()
    gen      = TrafficGenerator(topology, clock, rng_seed=777)
    agents = {
        "TMA": TrafficMonitorAgent("TMA:stress", bus, gen),
        "ACA": AnomalyClassifierAgent("ACA:stress", bus),
        "RCA": ResponseCoordinatorAgent("RCA:stress", bus),
        "RAA": ResourceAllocatorAgent("RAA:stress", bus),
        "TIA": ThreatIntelligenceAgent("TIA:stress", bus),
    }
    await bus.start()
    for a in agents.values():
        await a.start()

    # ── ground truth + observation state ──────────────────────────────
    active: dict[str, set[str]] = {}          # segment -> {attack types now}
    last_end: dict[str, float] = {}           # segment -> when last attack ended
    detect_t: dict[str, float | None] = {aid: None for aid, *_ in ATTACK_PLAN}
    attack_t0: dict[str, float] = {}
    first_report: dict[str, float] = {}       # segment -> first threat-report ts
    first_resolution: dict[str, float] = {}   # segment -> first resolution ts
    tp = fp = fn = tn = 0

    async def on_report(msg) -> None:
        nonlocal tp, fp, fn, tn
        c    = msg.content
        seg  = c.get("segment", "")
        clf  = c.get("classification", "")
        src  = c.get("source_alert", "")
        now  = time.monotonic()
        types = active.get(seg, set())
        in_linger = not types and (now - last_end.get(seg, float("-inf")) < LINGER_SEC)

        if clf == "NOISE":
            if any(ATTACK_MODALITY.get(t) == src for t in types):
                fn += 1
            else:
                tn += 1
            return

        first_report.setdefault(seg, now)
        if clf in types:
            tp += 1
            for aid, aseg, atype, _kw in ATTACK_PLAN:
                if aseg == seg and atype == clf and detect_t[aid] is None:
                    detect_t[aid] = now
        elif not types and not in_linger:
            fp += 1
        # mismatched type mid-attack / linger residue: neither hit nor FP

    async def on_resolution(msg) -> None:
        c = msg.content
        # FR-30 definition: threat confirmed → first EXECUTED response.
        # Rung-0 THROTTLE_SEGMENT counts — it IS the first mitigation; the
        # later escalation to a voted quarantine is response *policy*
        # (escalation ladder), not response *time*.
        if c.get("outcome") == "EXECUTED":
            first_resolution.setdefault(c.get("segment", ""), time.monotonic())

    bus.subscribe(Topic.THREAT_REPORTS, on_report)
    bus.subscribe(Topic.RESOLUTION,     on_resolution)

    gen_task = asyncio.create_task(gen.run())
    print(f"  warmup {WARMUP_SEC:.0f}s (baseline build) ...")
    await asyncio.sleep(WARMUP_SEC)

    # ── launch all five attacks concurrently ──────────────────────────
    print(f"  launching {len(ATTACK_PLAN)} concurrent attacks for {ATTACK_SEC:.0f}s ...")
    tasks = []
    for aid, seg, atype, kw in ATTACK_PLAN:
        if atype == "DDOS":
            atk = DDoSAttacker(aid, seg, gen, **kw)
        else:
            atk = PortScanner(aid, seg, gen, **kw)
        active.setdefault(seg, set()).add(atype)
        attack_t0[aid] = time.monotonic()
        tasks.append(asyncio.create_task(atk.launch(ATTACK_SEC)))

    await asyncio.sleep(ATTACK_SEC + 0.5)
    await asyncio.gather(*tasks, return_exceptions=True)
    now = time.monotonic()
    for seg in list(active):
        active[seg] = set()
        last_end[seg] = now

    print(f"  drain {DRAIN_SEC:.0f}s (in-flight votes/grants settle) ...")
    await asyncio.sleep(DRAIN_SEC)

    raa = agents["RAA"]
    all_grants  = list(raa.grants)
    all_denials = list(raa.denials)

    gen.stop(); gen_task.cancel()
    for a in agents.values():
        await a.stop()
    await bus.stop()
    await asyncio.gather(gen_task, return_exceptions=True)

    # ── ST-01: Detection Rate ──────────────────────────────────────────
    section("ST-01  Detection Rate ≥ 90% (5 concurrent attack instances)")
    detected = sum(1 for v in detect_t.values() if v is not None)
    dr = detected / len(ATTACK_PLAN)
    per_attack = "  ".join(
        f"{aid}={'%.2fs' % (detect_t[aid] - attack_t0[aid]) if detect_t[aid] else 'MISS'}"
        for aid, *_ in ATTACK_PLAN
    )
    suite.check("ST-01",
                f"DR ≥ {MIN_DR:.0%} — every concurrent attack correctly typed",
                dr >= MIN_DR,
                observed=f"{detected}/{len(ATTACK_PLAN)} detected  ({per_attack})",
                expected=f"≥ {MIN_DR:.0%}")

    # ── ST-02: report-level FPR ────────────────────────────────────────
    section("ST-02  Report-level FPR ≤ 10% during calm contexts")
    fpr = fp / max(1, fp + tn)
    suite.check("ST-02",
                f"FPR ≤ {MAX_FPR:.0%} (threat flags in genuinely calm contexts)",
                fpr <= MAX_FPR,
                observed=f"{fpr:.1%}  (fp={fp} tn={tn} tp={tp} fn={fn})",
                expected=f"≤ {MAX_FPR:.0%}",
                note="internal segment is the untouched control")

    # ── ST-03: MTTR under contention ───────────────────────────────────
    section("ST-03  MTTR_Response < 1000 ms under contention")
    lat = [
        (first_resolution[s] - first_report[s]) * 1000
        for s in first_resolution if s in first_report
    ]
    mttr_ms = (sum(lat) / len(lat)) if lat else None
    suite.check("ST-03",
                f"MTTR < {MAX_MTTR_MS} ms (first threat-report → first executed response, per segment)",
                mttr_ms is not None and mttr_ms < MAX_MTTR_MS,
                observed=f"{mttr_ms:.1f} ms over {len(lat)} segment(s)" if mttr_ms is not None else "no executed responses",
                expected=f"< {MAX_MTTR_MS} ms",
                note="rung-0 THROTTLE executes in-tick; escalation to voted quarantine is policy, not latency")

    # ── ST-05 (computed early — SW needs overhead): resource overhead ──
    overhead, cpu_pct, mem_pct = measure_resource_overhead(interval=0.5)

    # ── ST-04: Social Welfare ──────────────────────────────────────────
    section("ST-04  Social Welfare ≥ 0.80 under stress")
    # Same per-agent utility construction as validate_system.py, fed with
    # the values MEASURED under stress instead of the standard-load ones.
    accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
    total_window = WARMUP_SEC + ATTACK_SEC + DRAIN_SEC
    disrupted = sum(
        (detect_t[aid] - attack_t0[aid]) if detect_t[aid] is not None else ATTACK_SEC
        for aid, *_ in ATTACK_PLAN
    )
    avail  = max(0.0, (total_window - disrupted) / total_window)
    mttr_r = mttr_ms if mttr_ms is not None else float(MAX_MTTR_MS)

    u_tma = min(dr * (1 - fpr) * (1.0 / 100) * 1000, 1.0)
    u_aca = min(accuracy * (1 - fpr) * 0.05 * 20, 1.0)
    u_rca = min(avail * (1.0 / max(mttr_r / 1000, 0.001)) * 0.90, 1.0)
    u_raa = 0.85 * (1 - overhead)
    u_tia = min(0.80 * 0.90 * (1.0 / 0.80), 1.0)
    sw = _sw(u_tma, u_aca, u_rca, u_raa, u_tia)

    suite.check("ST-04",
                f"Social Welfare ≥ {MIN_SW} under 5-attack concurrent load",
                sw >= MIN_SW,
                observed=f"SW = {sw:.4f}",
                expected=f"≥ {MIN_SW}",
                note=(f"U_TMA={u_tma:.3f} U_ACA={u_aca:.3f} U_RCA={u_rca:.3f} "
                      f"U_RAA={u_raa:.3f} U_TIA={u_tia:.3f}"))

    # ── ST-05: overhead check ──────────────────────────────────────────
    section("ST-05  Resource overhead < 40%")
    suite.check("ST-05",
                f"CPU+RAM overhead < {MAX_OVERHEAD:.0%} under stress",
                overhead < MAX_OVERHEAD,
                observed=f"{overhead:.1%}",
                expected=f"< {MAX_OVERHEAD:.0%}")

    # ── ST-06: auction priority ordering ───────────────────────────────
    section("ST-06  Auction priority ordering under contention")
    granted_bids = [g.get("bid_value", 0) for g in all_grants]
    denied_bids  = [d.get("bid_value", 0) for d in all_denials]
    priority = priority_ok_label(False, granted_bids, denied_bids, denials=all_denials)
    auction_ok = priority is True
    suite.check("ST-06",
                "Every denial was genuinely outbid by the pool it lost to",
                auction_ok,
                observed=(f"grants={len(all_grants)} denials={len(all_denials)}  "
                          f"priority={'correct' if auction_ok else priority}"),
                expected="all denials ≤ weakest existing bid",
                note="priority_ok_label() per-decision check (scenario_lib §5.4)")

    # ── persist for Figure 6 / frontend degradation chart ─────────────
    results = {
        "dr": round(dr, 4),
        "fpr": round(fpr, 4),
        "mttr_ms": round(mttr_r, 1),
        "sw": round(sw, 4),
        "overhead": round(overhead, 4),
        "auction_ok": 1.0 if auction_ok else 0.0,
        "attacks": len(ATTACK_PLAN),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "grants": len(all_grants),
        "denials": len(all_denials),
    }
    RESULTS_PATH.write_text(json.dumps(results, indent=2))
    print(f"\n  measured stress results written → {RESULTS_PATH.name}")

    suite.set_metrics({"stress": results})
    suite.print_results()
    return suite


if __name__ == "__main__":
    asyncio.run(run())
