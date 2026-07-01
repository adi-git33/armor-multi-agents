"""
scenario_lib.py — shared harness helpers (BASELINE_VS_ADVANCED_VALIDATION_PLAN_V2 §5.4)
=========================================================================================
Pure-measurement scenario runners extracted from validate_scenarios.py, plus the
shared fixtures needed by validate_baseline.py / validate_ablation.py / validate_comparison.py:

  - ScenarioResult              dataclass: raw numbers only, no PASS/FAIL assertions
  - run_scenario_1/2/3/6()      pure callables parameterized by the four baseline flags
  - _peer_accept_voter()        uniform 2nd-voter stub (fixes single-voter risk, §7)
  - priority_ok_label()         bid_value N/A guard for naive-auction rows
  - OFAT_SCENARIOS / BASELINE_SCENARIOS
  - SEEDS                        N=8 seed list + guard

Each run_scenario_N() reproduces validate_scenarios.py's original per-scenario
numbers EXACTLY when called with its original default (gen_seed, atk_seed) and
attach_peer_voter=False, naive_ladder=False, naive_voting=False, use_tia=True,
naive_auction=False — i.e. calling it with all-default arguments is a byte-for-byte
stand-in for the inline scenario body it was extracted from.
"""
from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass, field

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
from core.messages    import Message, Performative, Topic

W      = {"TMA": 0.20, "ACA": 0.30, "RCA": 0.25, "RAA": 0.10, "TIA": 0.15}
MIN_SW = 0.80


def _sw(u_tma, u_aca, u_rca, u_raa, u_tia) -> float:
    return (W["TMA"] * u_tma + W["ACA"] * u_aca + W["RCA"] * u_rca +
            W["RAA"] * u_raa + W["TIA"] * u_tia)


async def _make_system(seed: int):
    clock    = SimClock(speed=1.0)
    topology = NetworkTopology()
    bus      = MessageBus()
    gen      = TrafficGenerator(topology, clock, rng_seed=seed)
    await bus.start()
    return bus, gen, topology


# ── shared fixtures (§5.4) ──────────────────────────────────────────────────

async def _peer_accept_voter(bus: MessageBus, agent_id: str = "PEER:voter") -> None:
    """
    Uniform 2nd-voter stub, subscribed identically in every scenario/mode —
    naive and advanced, with or without TIA. Fixes the single-voter risk:
    without this, RCA's own self-vote is the *only* vote cast in S1/S3/S4/S5
    (only S2/S6 happen to also get TIA's vote), so "voting Δ" wasn't a real
    consensus test everywhere. Publishes performative=ACCEPT (not INFORM —
    RCA._on_vote() switches on msg.performative, not a content field) so it
    is actually counted by RCA's vote tally.
    """
    async def _on_cfp(msg: Message) -> None:
        await bus.publish(Message(
            performative = Performative.ACCEPT,
            sender       = agent_id,
            topic        = Topic.VOTES,
            content      = {"incident_id": msg.content.get("incident_id", "")},
        ))
    bus.subscribe(Topic.COALITION, _on_cfp)


def priority_ok_label(naive_auction: bool, granted_bids: list[float], denied_bids: list[float]):
    """
    bid_value N/A guard (§5.4): a naive-auction (FCFS) row never evaluated
    bid priority, so it must never print a number that looks like it did.
    """
    if naive_auction:
        return "N/A (FCFS, no priority evaluated)"
    priority_ok = (not denied_bids) or (min(granted_bids or [0]) >= max(denied_bids or [0]))
    return priority_ok


# ── OFAT / baseline scenario sets (§5.4) ────────────────────────────────────
OFAT_SCENARIOS      = (1, 2, 3, 6)          # four-mechanism ablation only
BASELINE_SCENARIOS  = (1, 2, 3, 4, 5, 6)    # includes S4/S5 as sanity-check controls

# N=8 seeds for mean±std aggregation (§5.4 seed-variance guard)
SEEDS = tuple(2026 + i for i in range(8))
assert len(SEEDS) >= 8, "N<8 seeds — not enough for a defensible mean±std"


@dataclass
class ScenarioResult:
    detected:     int
    mttr_ms:      float | None
    availability: float
    sw:           float
    u_atk:        float | None
    extra:        dict = field(default_factory=dict)   # scenario-specific fields


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO 1 — Single-Segment DDoS Attack
# ══════════════════════════════════════════════════════════════════════════
async def run_scenario_1(
    gen_seed: int = 110, atk_seed: int = 40, *,
    naive_ladder: bool = False, naive_voting: bool = False,
    use_tia: bool = True, naive_auction: bool = False,
    attach_peer_voter: bool = False,
) -> ScenarioResult:
    bus, gen, _ = await _make_system(gen_seed)
    tma = TrafficMonitorAgent("TMA:s1", bus, gen)
    aca = AnomalyClassifierAgent("ACA:s1", bus)
    rca = ResponseCoordinatorAgent("RCA:s1", bus, naive_ladder=naive_ladder, naive_voting=naive_voting)
    raa = ResourceAllocatorAgent("RAA:s1", bus, naive_auction=naive_auction)
    for a in [aca, rca, raa]:
        await a.start()
    if use_tia:
        await ThreatIntelligenceAgent("TIA:s1", bus).start()
    if attach_peer_voter:
        await _peer_accept_voter(bus)
    await tma.start()

    reports:    list[dict]  = []
    resolutions: list[dict] = []
    tr_times:   list[float] = []
    res_times:  list[float] = []

    async def on_rep(msg): reports.append(msg.content);     tr_times.append(time.monotonic())
    async def on_res(msg): resolutions.append(msg.content);  res_times.append(time.monotonic())

    bus.subscribe(Topic.THREAT_REPORTS, on_rep)
    bus.subscribe(Topic.RESOLUTION,     on_res)

    gen_task = asyncio.create_task(gen.run())
    await asyncio.sleep(1)

    atk      = DDoSAttacker("ATK:s1", "public-facing", gen, intensity_multiplier=10.0, rng_seed=atk_seed)
    atk_task = asyncio.create_task(atk.launch(4))
    await asyncio.sleep(4 + 1.0)
    await asyncio.gather(atk_task, return_exceptions=True)
    gen.stop(); gen_task.cancel()
    await asyncio.gather(gen_task, return_exceptions=True)

    detected_ddos = len([r for r in reports if r.get("classification") == "DDOS"])
    q_count       = sum(1 for r in resolutions if "QUARANTINE" in str(r.get("action", "")))
    availability  = max(0.0, (5 - q_count) / 5)
    evasion       = 0.0 if detected_ddos > 0 else 0.5
    u_atk         = evasion * (1 - availability)
    # Matches validate_scenarios.py exactly: wall-clock gap between the first
    # threat-report and the first resolution (not RCA's internal duration_ms).
    mttr_ms       = (res_times[0] - tr_times[0]) * 1000 if (tr_times and res_times) else None
    sw            = _sw(1.0 if detected_ddos else 0.5, 0.9, availability * 0.9, 0.85, 0.80)

    return ScenarioResult(
        detected=detected_ddos, mttr_ms=mttr_ms, availability=availability,
        sw=sw, u_atk=u_atk,
        extra={"resolutions": resolutions, "quarantine_count": q_count},
    )


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO 2 — Multi-Segment Coordinated Attack
# ══════════════════════════════════════════════════════════════════════════
async def run_scenario_2(
    gen_seed: int = 120, atk_seed_a: int = 41, atk_seed_b: int = 42, *,
    naive_ladder: bool = False, naive_voting: bool = False,
    use_tia: bool = True, naive_auction: bool = False,
    attach_peer_voter: bool = False,
) -> ScenarioResult:
    bus, gen, _ = await _make_system(gen_seed)
    tma = TrafficMonitorAgent("TMA:s2", bus, gen)
    aca = AnomalyClassifierAgent("ACA:s2", bus)
    rca = ResponseCoordinatorAgent("RCA:s2", bus, naive_ladder=naive_ladder, naive_voting=naive_voting)
    raa = ResourceAllocatorAgent("RAA:s2", bus, naive_auction=naive_auction)
    for a in [aca, rca, raa]:
        await a.start()
    if use_tia:
        await ThreatIntelligenceAgent("TIA:s2", bus).start()
    if attach_peer_voter:
        await _peer_accept_voter(bus)
    await tma.start()

    coalitions:  list[float] = []
    resolutions: list[dict]  = []

    async def on_coal(msg): coalitions.append(time.monotonic())
    async def on_res(msg):  resolutions.append(msg.content)

    bus.subscribe(Topic.COALITION,  on_coal)
    bus.subscribe(Topic.RESOLUTION, on_res)

    gen_task = asyncio.create_task(gen.run())
    await asyncio.sleep(1)

    atk_a = DDoSAttacker("ATK:s2a", "public-facing", gen, intensity_multiplier=10.0, rng_seed=atk_seed_a)
    atk_b = PortScanner("ATK:s2b",  "internal",       gen, rng_seed=atk_seed_b)
    t0    = time.monotonic()
    ta    = asyncio.create_task(atk_a.launch(4))
    tb    = asyncio.create_task(atk_b.launch(4))
    await asyncio.sleep(4 + 1.0)
    await asyncio.gather(ta, tb, return_exceptions=True)
    gen.stop(); gen_task.cancel()
    await asyncio.gather(gen_task, return_exceptions=True)

    coalition_formed = len(coalitions) > 0
    coalition_ms     = (coalitions[0] - t0) * 1000 if coalitions else 9999
    segs_responded   = {r.get("segment") for r in resolutions}
    simultaneous     = len(segs_responded) >= 2
    evasion          = 0.0 if coalition_formed else 0.5
    sw = _sw(0.90, 0.90, 0.90, 0.85, 0.80 if coalition_formed else 0.50)

    return ScenarioResult(
        detected=1 if coalition_formed else 0, mttr_ms=coalition_ms,
        availability=1.0 if simultaneous else 0.5, sw=sw, u_atk=evasion,
        extra={
            "coalition_formed": coalition_formed, "coalition_ms": coalition_ms,
            "segments_responded": segs_responded, "simultaneous": simultaneous,
            "evasion": evasion,
        },
    )


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO 3 — Resource Contention Under Heavy Load
# ══════════════════════════════════════════════════════════════════════════
async def run_scenario_3(
    gen_seed: int = 130, atk_seed_a: int = 43, atk_seed_b: int = 44, atk_seed_c: int = 45, *,
    naive_ladder: bool = False, naive_voting: bool = False,
    use_tia: bool = True, naive_auction: bool = False,
    attach_peer_voter: bool = False,
) -> ScenarioResult:
    bus, gen, _ = await _make_system(gen_seed)
    tma = TrafficMonitorAgent("TMA:s3", bus, gen)
    aca = AnomalyClassifierAgent("ACA:s3", bus)
    rca = ResponseCoordinatorAgent("RCA:s3", bus, naive_ladder=naive_ladder, naive_voting=naive_voting)
    raa = ResourceAllocatorAgent("RAA:s3", bus, naive_auction=naive_auction)
    agents = [tma, aca, rca, raa]
    if use_tia:
        tia = ThreatIntelligenceAgent("TIA:s3", bus)
        agents.append(tia)
    if attach_peer_voter:
        await _peer_accept_voter(bus)
    for a in agents:
        await a.start()

    gen_task = asyncio.create_task(gen.run())
    await asyncio.sleep(1)

    atks = [
        DDoSAttacker("ATK:s3a", "public-facing", gen, intensity_multiplier=10.0, rng_seed=atk_seed_a),
        PortScanner("ATK:s3b",  "server",          gen, rng_seed=atk_seed_b),
        DDoSAttacker("ATK:s3c", "internal",        gen, intensity_multiplier=8.0,  rng_seed=atk_seed_c),
    ]
    tasks = [asyncio.create_task(a.launch(4)) for a in atks]
    await asyncio.sleep(4 + 1.0)
    await asyncio.gather(*tasks, return_exceptions=True)
    gen.stop(); gen_task.cancel()
    await asyncio.gather(gen_task, return_exceptions=True)

    all_grants  = raa.grants
    all_denials = raa.denials
    granted_bids = [g.get("bid_value", 0) for g in all_grants]
    denied_bids  = [d.get("bid_value", 0) for d in all_denials]
    priority_result = priority_ok_label(naive_auction, granted_bids, denied_bids)

    try:
        import psutil
        proc = psutil.Process()
        cpu  = proc.cpu_percent(interval=0.5) / max(psutil.cpu_count(), 1)
        mem  = proc.memory_info().rss / psutil.virtual_memory().total
        overhead = (cpu / 100 + mem) / 2
    except ImportError:
        overhead = 0.05

    sw = _sw(0.90, 0.90, 0.90, max(0.0, 1.0 - overhead), 0.85)

    return ScenarioResult(
        detected=len(all_grants) + len(all_denials), mttr_ms=None,
        availability=max(0.0, 1.0 - overhead), sw=sw, u_atk=None,
        extra={
            "grants": len(all_grants), "denials": len(all_denials),
            "granted_bids": granted_bids, "denied_bids": denied_bids,
            "priority_result": priority_result, "overhead": overhead,
        },
    )


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO 6 — Voting Protocol Validation
# ══════════════════════════════════════════════════════════════════════════
async def run_scenario_6(
    gen_seed: int = 160, atk_seed: int = 48, *,
    naive_ladder: bool = False, naive_voting: bool = False,
    use_tia: bool = True, naive_auction: bool = False,
    attach_peer_voter: bool = False,
) -> ScenarioResult:
    bus, gen, _ = await _make_system(gen_seed)
    tma = TrafficMonitorAgent("TMA:s6", bus, gen)
    aca = AnomalyClassifierAgent("ACA:s6", bus)
    rca = ResponseCoordinatorAgent("RCA:s6", bus, naive_ladder=naive_ladder, naive_voting=naive_voting)
    raa = ResourceAllocatorAgent("RAA:s6", bus, naive_auction=naive_auction)
    agents = [tma, aca, rca, raa]
    if use_tia:
        tia = ThreatIntelligenceAgent("TIA:s6", bus)
        agents.append(tia)
    if attach_peer_voter:
        await _peer_accept_voter(bus)
    for a in agents:
        await a.start()

    proposals:    list[dict]  = []
    coal_times:   list[float] = []
    resolutions:  list[dict]  = []
    res_times:    list[float] = []

    async def on_coal(msg): proposals.append(msg.content); coal_times.append(time.monotonic())
    async def on_res(msg):  resolutions.append(msg.content); res_times.append(time.monotonic())

    bus.subscribe(Topic.COALITION,  on_coal)
    bus.subscribe(Topic.RESOLUTION, on_res)

    gen_task = asyncio.create_task(gen.run())
    await asyncio.sleep(1)

    atk      = DDoSAttacker("ATK:s6", "public-facing", gen, intensity_multiplier=15.0, rng_seed=atk_seed)
    atk_task = asyncio.create_task(atk.launch(4))
    await asyncio.sleep(4 + 1.0)
    await asyncio.gather(atk_task, return_exceptions=True)
    gen.stop(); gen_task.cancel()
    await asyncio.gather(gen_task, return_exceptions=True)

    vote_cycle_ms = None
    if coal_times and res_times:
        vote_cycle_ms = (res_times[0] - coal_times[0]) * 1000

    sw = _sw(0.90, 0.90, 0.90 if resolutions else 0.5, 0.85, 0.85)

    return ScenarioResult(
        detected=len(proposals), mttr_ms=vote_cycle_ms,
        availability=1.0 if resolutions else 0.0, sw=sw,
        u_atk=None,
        extra={"proposals": len(proposals), "resolutions": resolutions,
               "vote_cycle_ms": vote_cycle_ms},
    )
