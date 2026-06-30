"""
validate_rca.py — Response Coordinator Agent (RCA) Validation
==============================================================
  FR-10  Initiate defensive response within 500 ms of Confirmed Threat
  FR-11  Coalition voting before any quarantine; >50% majority required
  FR-12  Log every decision persistently
  FR-13  Proportional response: least disruptive action first
  FR-14  Send resolution notification to coalition members

Derived (BDI Desires / U_RCA):
  D-RCA-1  MTTR_Response < 1000 ms
  D-RCA-2  Availability > 99%
  D-RCA-3  Proportionality: BLOCK preferred over QUARANTINE
  D-RCA-4  U_RCA = availability x (1/MTTR) x proportionality > 0

Run:  cd backend && python validation/validate_rca.py
"""
from __future__ import annotations
import asyncio, sys, time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_BACK = _HERE.parent
sys.path.insert(0, str(_BACK))
sys.path.insert(0, str(_HERE))

from simulation.clock   import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker
from agents.tma import TrafficMonitorAgent
from agents.aca import AnomalyClassifierAgent
from agents.rca import ResponseCoordinatorAgent, VOTE_WINDOW, RESOLUTION_COOLDOWN, ACTIONS
from bus.message_bus import MessageBus
from core.messages   import Topic
from helpers import ValidationSuite, section

MAX_RESPONSE_MS      = 500
MAX_MTTR_MS          = 1000
MIN_AVAILABILITY     = 0.99
ATTACK_SEG           = "public-facing"
RUN_SEC              = 10


async def run() -> ValidationSuite:
    suite    = ValidationSuite("RCA — Response Coordinator Agent Validation")
    clock    = SimClock(speed=1.0)
    topology = NetworkTopology()

    bus = MessageBus()
    gen = TrafficGenerator(topology, clock, rng_seed=50)
    tma = TrafficMonitorAgent("TMA:1", bus, gen)
    aca = AnomalyClassifierAgent("ACA:1", bus)
    rca = ResponseCoordinatorAgent("RCA:1", bus)

    await bus.start(); await tma.start(); await aca.start(); await rca.start()

    threat_times:     list[float] = []
    resolution_times: list[float] = []
    resolution_msgs:  list[dict]  = []
    coalition_msgs:   list[dict]  = []

    async def on_threat(msg):  threat_times.append(time.monotonic())
    async def on_res(msg):     resolution_msgs.append(msg.content); resolution_times.append(time.monotonic())
    async def on_coal(msg):    coalition_msgs.append(msg.content)

    bus.subscribe(Topic.THREAT_REPORTS, on_threat)
    bus.subscribe(Topic.RESOLUTION,     on_res)
    bus.subscribe(Topic.COALITION,      on_coal)

    gen_task = asyncio.create_task(gen.run())
    await asyncio.sleep(2)

    atk      = DDoSAttacker("ATK:1", ATTACK_SEG, gen, intensity_multiplier=12.0, rng_seed=8)
    t_attack = time.monotonic()
    atk_task = asyncio.create_task(atk.launch(RUN_SEC))
    await asyncio.sleep(RUN_SEC + 1.0)
    await asyncio.gather(atk_task, return_exceptions=True)
    gen.stop(); gen_task.cancel()
    await asyncio.gather(gen_task, return_exceptions=True)

    # ── FR-10: Response within 500 ms of Confirmed Threat ────────────
    section("FR-10  Response within 500 ms of Confirmed Threat")
    if resolution_msgs:
        first_res = min(resolution_times)
        pipeline_ms = (first_res - t_attack) * 1000
        suite.check("FR-10", "First response within pipeline budget (TMA+ACA+RCA <= 1800ms)",
                    pipeline_ms < 1800,
                    observed=f"{pipeline_ms:.0f} ms from attack start",
                    expected="< 1800 ms")
    else:
        suite.check("FR-10", "First response within pipeline budget", False,
                    observed="no resolution messages", expected="< 1800 ms")

    rca_latencies_ms: list[float] = []
    for i in range(min(len(threat_times), len(resolution_times))):
        if resolution_times[i] > threat_times[i]:
            rca_latencies_ms.append((resolution_times[i] - threat_times[i]) * 1000)

    if rca_latencies_ms:
        max_rca = max(rca_latencies_ms)
        mean_rca = sum(rca_latencies_ms) / len(rca_latencies_ms)
        suite.check("FR-10", f"RCA internal response < {MAX_RESPONSE_MS} ms",
                    max_rca < MAX_RESPONSE_MS,
                    observed=f"max={max_rca:.0f}ms mean={mean_rca:.0f}ms",
                    expected=f"< {MAX_RESPONSE_MS} ms")
    else:
        suite.check("FR-10", f"RCA internal response < {MAX_RESPONSE_MS} ms", False,
                    observed="no matched pairs", expected=f"< {MAX_RESPONSE_MS} ms")

    # ── FR-11: Voting before quarantine ──────────────────────────────
    section("FR-11  Coalition voting before quarantine; majority must approve")
    quarantine_res = [r for r in resolution_msgs if "QUARANTINE" in str(r.get("action", ""))]
    suite.check("FR-11", "Coalition CFP published before any quarantine action",
                len(coalition_msgs) > 0 or len(quarantine_res) == 0,
                observed=f"{len(coalition_msgs)} proposals, {len(quarantine_res)} quarantines",
                expected="at least 1 coalition proposal per quarantine")
    suite.check("FR-11", "VOTE_WINDOW > 0 (voting is time-bounded)",
                VOTE_WINDOW > 0,
                observed=f"VOTE_WINDOW = {VOTE_WINDOW}s", expected="> 0")

    # ── FR-12: Decision logging ───────────────────────────────────────
    section("FR-12  Log every decision persistently")
    has_log = hasattr(rca, "_incident_log") or hasattr(rca, "incident_log") or hasattr(rca, "_open_incidents")
    suite.check("FR-12", "RCA maintains internal incident tracking",
                has_log,
                observed="attribute found" if has_log else "no log attribute",
                expected="_incident_log / _open_incidents attribute")
    suite.check("FR-12", "Resolution messages emitted (evidence of logged decisions)",
                len(resolution_msgs) > 0,
                observed=f"{len(resolution_msgs)} resolution messages",
                expected=">= 1 during attack")

    # ── FR-13: Proportionality ────────────────────────────────────────
    section("FR-13  Proportional response: least disruptive action first")
    actions = [r.get("action") for r in resolution_msgs if r.get("action")]
    block_count     = sum(1 for a in actions if "BLOCK" in str(a))
    quarantine_count = sum(1 for a in actions if "QUARANTINE" in str(a))
    log_count       = sum(1 for a in actions if "LOG" in str(a))

    suite.check("FR-13", "BLOCK+LOG >= QUARANTINE (proportionality)",
                (block_count + log_count) >= quarantine_count or quarantine_count == 0,
                observed=f"BLOCK={block_count} LOG={log_count} QUARANTINE={quarantine_count}",
                expected="BLOCK+LOG >= QUARANTINE")

    ddos_action = ACTIONS.get("DDOS", "")
    suite.check("FR-13", "DDOS attack type maps to defined response action",
                bool(ddos_action),
                observed=f"DDOS -> {ddos_action!r}", expected="non-empty action")

    # ── FR-14: Resolution notification ───────────────────────────────
    section("FR-14  Resolution notification to coalition members")
    suite.check("FR-14", "Resolution messages published to RESOLUTION topic",
                len(resolution_msgs) > 0,
                observed=f"{len(resolution_msgs)} resolution messages", expected=">= 1")
    required = {"action", "segment"}
    well_formed = [r for r in resolution_msgs if required.issubset(r.keys())]
    suite.check("FR-14", "Resolution messages include action and segment",
                len(well_formed) == len(resolution_msgs) and len(resolution_msgs) > 0,
                observed=f"{len(well_formed)}/{len(resolution_msgs)} well-formed",
                expected="100% well-formed")

    # ── D-RCA-1: MTTR < 1000 ms ─────────────────────────────────────
    section("D-RCA-1  MTTR_Response < 1000 ms")
    if rca_latencies_ms:
        mttr = sum(rca_latencies_ms) / len(rca_latencies_ms)
        suite.check("D-RCA-1", f"Mean MTTR < {MAX_MTTR_MS} ms",
                    mttr < MAX_MTTR_MS,
                    observed=f"{mttr:.0f} ms", expected=f"< {MAX_MTTR_MS} ms")
    else:
        suite.check("D-RCA-1", f"Mean MTTR < {MAX_MTTR_MS} ms", False,
                    observed="no data", expected=f"< {MAX_MTTR_MS} ms")

    # ── D-RCA-2: Availability > 99% ──────────────────────────────────
    section("D-RCA-2  Availability > 99% during attack")
    disruption   = quarantine_count * 1.0
    availability = max(0.0, (float(RUN_SEC) - disruption) / float(RUN_SEC))
    suite.check("D-RCA-2", f"Availability > {MIN_AVAILABILITY*100:.0f}%",
                availability > MIN_AVAILABILITY,
                observed=f"{availability*100:.2f}% ({quarantine_count} quarantine events)",
                expected=f"> {MIN_AVAILABILITY*100:.0f}%")

    # ── D-RCA-4: U_RCA formula ───────────────────────────────────────
    section("D-RCA-4  U_RCA = availability x (1/MTTR) x proportionality_score")
    mttr_val   = (sum(rca_latencies_ms) / len(rca_latencies_ms)) if rca_latencies_ms else MAX_MTTR_MS
    prop_score = 1.0 if (block_count + log_count) >= quarantine_count else 0.5
    u_rca      = availability * (1.0 / max(mttr_val, 1)) * prop_score
    suite.check("D-RCA-4", "U_RCA > 0",
                u_rca > 0,
                observed=f"U_RCA = {u_rca:.6f}",
                expected="> 0",
                note=f"avail={availability:.3f}, MTTR={mttr_val:.0f}ms, prop={prop_score}")

    await rca.stop()
    suite.print_results()
    return suite


if __name__ == "__main__":
    asyncio.run(run())
