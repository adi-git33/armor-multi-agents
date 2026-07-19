"""
validate_baseline.py — Naive/Uncoordinated Baseline (BASELINE_VS_ADVANCED_VALIDATION_PLAN_V2 §5.1)
======================================================================================================
Structural mirror of validate_scenarios.py: identical build_system(seed)
(scenario_lib.py), identical attacker classes/intensities/durations/seeds
per scenario. The
only difference is that every agent is constructed with all four
baseline/ablation flags set to "naive":

    RCA(naive_ladder=True, naive_voting=True)
    RAA(naive_auction=True)
    TIA not constructed/started at all

This reproduces a traditional, uncoordinated IDS/IPS control — see
BASELINE_VS_ADVANCED_VALIDATION_PLAN_V2.md §2/§3 for exactly what each
flag disables. TMA/ACA are unchanged in every mode (detection/classification
quality is held constant; only the four coordination/proportionality
mechanisms are switched off), so any measured Δ against validate_scenarios.py
is attributable only to those four mechanisms.

The uniform peer-voter stub (scenario_lib._peer_accept_voter, §5.4) is
attached in every scenario here, giving S1/S3/S6 a genuine 2-voter quorum
instead of relying on RCA's lone self-vote. This does not change any
PASS/FAIL outcome or SW/availability number (no reject vote is ever cast,
so vote_ratio stays 1.0 whether 1 or 2 ACCEPTs are tallied) — it only
future-proofs the harness against a peer that might actually reject.

Scenario coverage (BASELINE_SCENARIOS = 1,2,3,4,5,6):
  S1  cleanest single-incident demonstration of the ladder specifically
  S2  biggest gap from disabling TIA (no cross-segment correlation at all)
  S3  auction behavior diverges (FCFS vs. priority+eviction)
  S6  naive_voting removes the vote wait entirely
  S4  detection-only control — should be near-identical to advanced
  S5  agent-failure control — RCA/RAA naive, TIA omitted; noted separately,
      since backup-registration is a 5th mechanism not covered by these
      four flags

Run:  cd backend && python validation/validate_baseline.py
"""
from __future__ import annotations
import asyncio, sys, time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE))

from simulation.attackers import DDoSAttacker
from agents.tma  import TrafficMonitorAgent
from agents.aca  import AnomalyClassifierAgent
from agents.rca  import ResponseCoordinatorAgent
from agents.raa  import ResourceAllocatorAgent
from core.messages   import Topic
from helpers import ValidationSuite, section
from scenario_lib import (
    run_scenario_1, run_scenario_2, run_scenario_3, run_scenario_6,
    _peer_accept_voter, BASELINE_SCENARIOS, build_system,
)

MIN_SW = 0.80
W      = {"TMA": 0.20, "ACA": 0.30, "RCA": 0.25, "RAA": 0.10, "TIA": 0.15}

# All-naive kwargs shared by every OFAT-extracted scenario call in this file.
NAIVE_KW = dict(
    naive_ladder=True, naive_voting=True, use_tia=False, naive_auction=True,
    attach_peer_voter=True,
)


def _sw(u_tma, u_aca, u_rca, u_raa, u_tia) -> float:
    return (W["TMA"] * u_tma + W["ACA"] * u_aca + W["RCA"] * u_rca +
            W["RAA"] * u_raa + W["TIA"] * u_tia)


async def run() -> ValidationSuite:
    suite = ValidationSuite("Naive Baseline — all four mechanisms disabled (all 6 scenarios)")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 1 — Single-Segment DDoS Attack (naive ladder: jumps to top tier)
    # ══════════════════════════════════════════════════════════════════
    section("SCENARIO 1  Single-Segment DDoS Attack (naive)")
    r1 = await run_scenario_1(**NAIVE_KW)
    suite.check("S1", "DDoS detected (detection unaffected by baseline flags)",
                r1.detected > 0, observed=f"DDoS reports={r1.detected}", expected="> 0")
    suite.check("S1", "Availability (naive: jumps straight to QUARANTINE)",
                True, observed=f"{r1.availability*100:.2f}%", expected="report only")
    suite.check("S1", "Social Welfare (naive)",
                True, observed=f"SW ≈ {r1.sw:.3f}", expected="report only")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 2 — Multi-Segment Coordinated Attack (TIA off: no coalition)
    # ══════════════════════════════════════════════════════════════════
    section("SCENARIO 2  Multi-Segment Coordinated Attack (naive, TIA off)")
    r2 = await run_scenario_2(**NAIVE_KW)
    suite.check("S2", "Coalition NOT formed via TIA (no cross-segment correlation)",
                not r2.extra["coalition_formed"],
                observed=f"coalition_formed={r2.extra['coalition_formed']}",
                expected="False (TIA not constructed)")
    suite.check("S2", "Social Welfare (naive)",
                True, observed=f"SW ≈ {r2.sw:.3f}", expected="report only")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 3 — Resource Contention Under Heavy Load (FCFS, no eviction)
    # ══════════════════════════════════════════════════════════════════
    section("SCENARIO 3  Resource Contention Under Heavy Load (naive auction)")
    r3 = await run_scenario_3(**NAIVE_KW)
    suite.check("S3", "Auction outcomes issued (FCFS, naive)",
                r3.extra["grants"] + r3.extra["denials"] > 0,
                observed=f"{r3.extra['grants']} grants  {r3.extra['denials']} denials",
                expected="≥ 1 auction outcome")
    suite.check("S3", "Priority-ordering is N/A under naive FCFS (bid_value guard)",
                r3.extra["priority_result"] == "N/A (FCFS, no priority evaluated)",
                observed=r3.extra["priority_result"],
                expected="N/A (FCFS, no priority evaluated)")
    suite.check("S3", "Social Welfare (naive)",
                True, observed=f"SW ≈ {r3.sw:.3f}", expected="report only")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 4 — Zero-Day / Novel Attack Detection (detection-only control)
    # ══════════════════════════════════════════════════════════════════
    section("SCENARIO 4  Zero-Day / Novel Attack Detection (control — unaffected)")

    bus4, gen4, _ = await build_system(seed=140)
    tma4 = TrafficMonitorAgent("TMA:b4", bus4, gen4)
    aca4 = AnomalyClassifierAgent("ACA:b4", bus4)
    await tma4.start(); await aca4.start()

    s4_alerts:  list[dict] = []
    s4_reports: list[dict] = []
    async def s4_on_alert(msg): s4_alerts.append(msg.content)
    async def s4_on_rep(msg):   s4_reports.append(msg.content)
    bus4.subscribe(Topic.ALERTS,         s4_on_alert)
    bus4.subscribe(Topic.THREAT_REPORTS, s4_on_rep)

    gen4_task = asyncio.create_task(gen4.run())
    await asyncio.sleep(1)
    atk_zd      = DDoSAttacker("ATK:b4", "server", gen4, intensity_multiplier=5.0, rng_seed=46)
    atk_zd_task = asyncio.create_task(atk_zd.launch(4))
    await asyncio.sleep(4 + 1.0)
    await asyncio.gather(atk_zd_task, return_exceptions=True)
    gen4.stop(); gen4_task.cancel()
    await asyncio.gather(gen4_task, return_exceptions=True)

    novel_detected = len(s4_alerts) > 0 or len(s4_reports) > 0
    sw_s4 = _sw(1.0 if novel_detected else 0.5, 0.90, 0.85, 0.85, 0.80)
    suite.check("S4", "Novel attack still detected (sanity check — no leakage into detection layer)",
                novel_detected,
                observed=f"{len(s4_alerts)} alerts  {len(s4_reports)} reports",
                expected="≥ 1 alert or report, same as advanced mode")
    suite.check("S4", "Social Welfare (control)",
                True, observed=f"SW ≈ {sw_s4:.3f}", expected="report only, ~= advanced S4")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 5 — Agent Failure & Resilience (RCA/RAA naive, TIA omitted)
    # ══════════════════════════════════════════════════════════════════
    section("SCENARIO 5  Agent Failure & Resilience (naive RCA/RAA, no TIA)")

    bus5, gen5, _ = await build_system(seed=150)
    tma5 = TrafficMonitorAgent("TMA:b5", bus5, gen5)
    aca5 = AnomalyClassifierAgent("ACA:b5", bus5)
    rca5 = ResponseCoordinatorAgent("RCA:b5", bus5, naive_ladder=True, naive_voting=True)
    raa5 = ResourceAllocatorAgent("RAA:b5", bus5, naive_auction=True)
    for a in [tma5, aca5, rca5, raa5]: await a.start()
    await _peer_accept_voter(bus5)

    s5_reports: list[dict] = []
    async def s5_on_rep(msg): s5_reports.append(msg.content)
    bus5.subscribe(Topic.THREAT_REPORTS, s5_on_rep)

    gen5_task = asyncio.create_task(gen5.run())
    await asyncio.sleep(1)

    await aca5.stop()
    t_fail      = time.monotonic()
    aca5_backup = AnomalyClassifierAgent("ACA:b5-backup", bus5)
    await aca5_backup.start()
    reassign_ms = (time.monotonic() - t_fail) * 1000

    atk_s5      = DDoSAttacker("ATK:b5", "server", gen5, intensity_multiplier=10.0, rng_seed=47)
    atk_s5_task = asyncio.create_task(atk_s5.launch(3))
    await asyncio.sleep(3 + 1.0)
    await asyncio.gather(atk_s5_task, return_exceptions=True)
    gen5.stop(); gen5_task.cancel()
    await asyncio.gather(gen5_task, return_exceptions=True)

    sw_s5 = _sw(0.90, 0.90 if s5_reports else 0.5, 0.85, 0.85, 0.80)
    suite.check("S5", "Backup ACA still processes threats after primary failure (resilience is orthogonal to the 4 flags)",
                len(s5_reports) > 0,
                observed=f"{len(s5_reports)} reports; reassigned in {reassign_ms:.0f} ms",
                expected="≥ 1 report, same as advanced mode")
    suite.check("S5", "Social Welfare (naive RCA/RAA, resilience control)",
                True, observed=f"SW ≈ {sw_s5:.3f}", expected="report only")

    # ══════════════════════════════════════════════════════════════════
    # SCENARIO 6 — Voting Protocol Validation (naive_voting: no vote wait)
    # ══════════════════════════════════════════════════════════════════
    section("SCENARIO 6  Voting Protocol Validation (naive voting)")
    r6 = await run_scenario_6(**NAIVE_KW)
    suite.check("S6", "Resolution reached (self-approved, no CFP/vote wait)",
                len(r6.extra["resolutions"]) > 0,
                observed=f"{len(r6.extra['resolutions'])} resolution(s), "
                         f"{r6.extra['proposals']} coalition proposals",
                expected="≥ 1 resolution, 0 coalition proposals (naive_voting=True)")
    suite.check("S6", "No coalition CFP published (voting mechanism fully bypassed)",
                r6.extra["proposals"] == 0,
                observed=f"{r6.extra['proposals']} proposals", expected="0")
    suite.check("S6", "Social Welfare (naive)",
                True, observed=f"SW ≈ {r6.sw:.3f}", expected="report only")

    suite.set_metrics({
        "social_welfare": {
            "S1": {"value": r1.sw}, "S2": {"value": r2.sw}, "S3": {"value": r3.sw},
            "S4": {"value": sw_s4}, "S5": {"value": sw_s5}, "S6": {"value": r6.sw},
        },
        "baseline_scenarios": list(BASELINE_SCENARIOS),
    })

    suite.print_results()
    return suite


if __name__ == "__main__":
    asyncio.run(run())
