"""
Full System Integration Test
=============================
Runs all five agents together against three realistic attack scenarios
and verifies the complete detection-to-enforcement chain.

Agents under test
-----------------
  TMA  — detects volume spikes and port scans
  ACA  — classifies alerts with ML model
  TIA  — correlates threats across segments
  RCA  — coordinates coalition and decides response
  RAA  — allocates defensive resources (sealed-bid auction)

Scenarios
---------
  Phase 1  DDoS on 'public-facing'          (6x baseline, 8 s)
  Phase 3  Multi-segment port scan           (same IP on server + internal, 10 s)
  Phase 4  DDoS on 'sec-mon'                (5x baseline, 7 s)
            └─ triggers COORDINATED_DDOS via TIA cross-window (public-facing
               DDOS reports from Phase 1 still in TIA's 60 s history)

Checks (15 total)
-----------------
  TMA  (1-2)  : volume-spike and port-scan alerts fire
  ACA  (3-5)  : DDOS and PORT_SCAN classified; confidence gate
  TIA  (6-8)  : MULTI_SEGMENT_SCAN and COORDINATED_DDOS intel; TIA votes
  RCA  (9-11) : DDoS and PORT_SCAN resolutions; NOISE never escalates
  RAA  (12-15): QUARANTINE and BLOCK grants; enforcement state correct

Expected runtime: ~38 s
"""

import asyncio
import logging

from bus.message_bus import MessageBus
from core.messages import Topic
from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator
from simulation.attackers import DDoSAttacker, PortScanner
from agents.tma import TrafficMonitorAgent
from agents.aca import AnomalyClassifierAgent
from agents.tia import ThreatIntelligenceAgent
from agents.rca import ResponseCoordinatorAgent, VOTE_WINDOW
from agents.raa import ResourceAllocatorAgent

# Suppress agent log noise during the test
logging.basicConfig(level=logging.WARNING)

# ── timing ─────────────────────────────────────────────────────────────
WARMUP   = 7.0   # s — build a stable baseline before attacking
DDOS1    = 8.0   # s — Phase 1: DDoS on public-facing
RECOVERY = 3.0   # s — brief pause between scenarios
SCAN     = 10.0  # s — Phase 3: multi-segment port scan
DDOS2    = 7.0   # s — Phase 4: DDoS on sec-mon
COLLECT  = 3.0   # s — allow final messages to settle

SCANNER_IP = "45.33.32.156"   # PortScanner's fixed src_ip


async def main() -> None:
    print("=" * 70)
    print("  Full System Integration Test")
    print("  TMA | ACA | TIA | RCA | RAA")
    print("=" * 70)

    # ── telemetry ─────────────────────────────────────────────────────
    alerts:      list[dict] = []
    threat_rpts: list[dict] = []
    intel_msgs:  list[dict] = []
    vote_msgs:   list[dict] = []
    resolutions: list[dict] = []
    grants:      list[dict] = []

    # ── infrastructure ─────────────────────────────────────────────────
    bus      = MessageBus()
    topology = NetworkTopology()
    clock    = SimClock()
    gen      = TrafficGenerator(topology, clock, rng_seed=42)

    # ── agents ─────────────────────────────────────────────────────────
    tma = TrafficMonitorAgent("TMA:1",  bus, gen)
    aca = AnomalyClassifierAgent("ACA:1", bus)
    tia = ThreatIntelligenceAgent("TIA:1", bus)
    rca = ResponseCoordinatorAgent("RCA:1", bus)
    raa = ResourceAllocatorAgent("RAA:1",  bus)

    # ── wire up telemetry ──────────────────────────────────────────────
    async def on_alert(msg):      alerts.append(msg.content)
    async def on_threat(msg):     threat_rpts.append(msg.content)
    async def on_intel(msg):      intel_msgs.append(msg.content)
    async def on_vote(msg):       vote_msgs.append(msg.content)
    async def on_resolution(msg): resolutions.append(msg.content)
    async def on_grant(msg):      grants.append(msg.content)

    await bus.start()
    bus.subscribe(Topic.ALERTS,          on_alert)
    bus.subscribe(Topic.THREAT_REPORTS,  on_threat)
    bus.subscribe(Topic.THREAT_INTEL,    on_intel)
    bus.subscribe(Topic.VOTES,           on_vote)
    bus.subscribe(Topic.RESOLUTION,      on_resolution)
    bus.subscribe(Topic.RESOURCE_GRANTS, on_grant)

    await tma.start()
    await aca.start()
    await tia.start()
    await rca.start()
    await raa.start()

    gen_task = asyncio.create_task(gen.run())

    # ══ Phase 0: Warmup ═══════════════════════════════════════════════
    print(f"\n  [Phase 0] Warmup {WARMUP:.0f}s  — building baselines on all segments")
    await asyncio.sleep(WARMUP)
    print(f"            baseline ready  (alerts so far: {len(alerts)})")

    # ══ Phase 1: DDoS on public-facing ════════════════════════════════
    print(f"\n  [Phase 1] DDoS on 'public-facing'  6x baseline  {DDOS1:.0f}s")
    ddos1 = DDoSAttacker(
        "ddos-pf", "public-facing", gen,
        intensity_multiplier=6.0, ramp_seconds=3.0, rng_seed=11,
    )
    await asyncio.create_task(ddos1.launch(DDOS1))
    await asyncio.sleep(VOTE_WINDOW + 0.5)   # let RCA resolve before moving on

    snap1_alerts = sum(1 for a in alerts if a.get("anomaly_type") == "VOLUME_SPIKE"
                                         and a.get("segment") == "public-facing")
    snap1_ddos   = sum(1 for t in threat_rpts if t.get("classification") == "DDOS")
    snap1_res    = sum(1 for r in resolutions if r.get("action") == "QUARANTINE_SEGMENT")
    print(f"            alerts={snap1_alerts}  ddos_classified={snap1_ddos}"
          f"  quarantine_resolutions={snap1_res}")

    # ══ Phase 2: Brief recovery ════════════════════════════════════════
    print(f"\n  [Phase 2] Recovery {RECOVERY:.0f}s")
    await asyncio.sleep(RECOVERY)

    # ══ Phase 3: Multi-segment port scan (same IP) ═════════════════════
    print(f"\n  [Phase 3] Port scan  same IP ({SCANNER_IP})"
          f"  on 'server' + 'internal'  {SCAN:.0f}s")
    scan_svr = PortScanner(
        "scan-svr", "server", gen,
        src_ip=SCANNER_IP, probe_interval=0.3, rng_seed=31,
    )
    scan_int = PortScanner(
        "scan-int", "internal", gen,
        src_ip=SCANNER_IP, probe_interval=0.3, rng_seed=31,
    )
    await asyncio.gather(
        asyncio.create_task(scan_svr.launch(SCAN)),
        asyncio.create_task(scan_int.launch(SCAN)),
    )
    await asyncio.sleep(VOTE_WINDOW + 0.5)

    snap3_portscan = sum(1 for a in alerts if a.get("anomaly_type") == "PORT_SCAN")
    snap3_clf      = sum(1 for t in threat_rpts if t.get("classification") == "PORT_SCAN")
    snap3_intel    = sum(1 for m in intel_msgs if m.get("pattern_type") == "MULTI_SEGMENT_SCAN")
    snap3_block    = sum(1 for r in resolutions if r.get("action") == "BLOCK_SOURCE_IP")
    print(f"            port_scan_alerts={snap3_portscan}"
          f"  classified={snap3_clf}"
          f"  multi_seg_intel={snap3_intel}"
          f"  block_resolutions={snap3_block}")

    # ══ Phase 4: DDoS on sec-mon (triggers COORDINATED_DDOS via TIA) ══
    print(f"\n  [Phase 4] DDoS on 'sec-mon'  5x baseline  {DDOS2:.0f}s")
    print(f"            (public-facing DDoS still in TIA's 60 s history"
          f" -> COORDINATED_DDOS expected)")
    ddos2 = DDoSAttacker(
        "ddos-sm", "sec-mon", gen,
        intensity_multiplier=5.0, ramp_seconds=2.0, rng_seed=22,
    )
    await asyncio.create_task(ddos2.launch(DDOS2))
    await asyncio.sleep(VOTE_WINDOW + 0.5)

    snap4_coord = sum(1 for m in intel_msgs if m.get("pattern_type") == "COORDINATED_DDOS")
    print(f"            coordinated_ddos_intel={snap4_coord}")

    # ══ Phase 5: Final collection ══════════════════════════════════════
    print(f"\n  [Phase 5] Final collection {COLLECT:.0f}s")
    await asyncio.sleep(COLLECT)

    gen.stop()
    await gen_task

    await tma.stop()
    await aca.stop()
    await tia.stop()
    await rca.stop()
    await raa.stop()
    await bus.stop()

    # ══ Summary ════════════════════════════════════════════════════════
    print("\n  -- Message counts across all phases --")
    print(f"     TMA alerts        : {len(alerts)}")
    print(f"     ACA threat-reports: {len(threat_rpts)}")
    print(f"     TIA intel         : {len(intel_msgs)}")
    print(f"     Coalition votes   : {len(vote_msgs)}")
    print(f"     RCA resolutions   : {len(resolutions)}")
    print(f"     RAA grants        : {len(grants)}")
    print(f"     Blocked IPs       : {raa.blocked_ips}")
    print(f"     Quarantined segs  : {raa.quarantined_segments}")

    # ══ Checks ═════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("  Checks")
    print("=" * 70)

    all_ok = True

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal all_ok
        mark = "PASS" if ok else "FAIL"
        print(f"\n  [{mark}] {label}")
        if detail:
            print(f"         {detail}")
        if not ok:
            all_ok = False

    # ── TMA ───────────────────────────────────────────────────────────
    print("\n  -- TMA --")

    volume_alerts = [a for a in alerts if a.get("anomaly_type") == "VOLUME_SPIKE"]
    scan_alerts   = [a for a in alerts if a.get("anomaly_type") == "PORT_SCAN"]

    check(
        "TMA fires VOLUME_SPIKE alerts during DDoS phases",
        len(volume_alerts) >= 1,
        f"VOLUME_SPIKE count: {len(volume_alerts)}",
    )
    check(
        "TMA fires PORT_SCAN alerts during port-scan phase",
        len(scan_alerts) >= 1,
        f"PORT_SCAN count: {len(scan_alerts)}  "
        f"segments: {list({a.get('segment') for a in scan_alerts})}",
    )

    # ── ACA ───────────────────────────────────────────────────────────
    print("\n  -- ACA --")

    ddos_reports = [t for t in threat_rpts if t.get("classification") == "DDOS"]
    scan_reports = [t for t in threat_rpts if t.get("classification") == "PORT_SCAN"]

    check(
        "ACA classifies at least 1 alert as DDOS",
        len(ddos_reports) >= 1,
        f"DDOS reports: {len(ddos_reports)}",
    )
    check(
        "ACA classifies at least 1 alert as PORT_SCAN",
        len(scan_reports) >= 1,
        f"PORT_SCAN reports: {len(scan_reports)}",
    )
    min_ddos_conf = min((r.get("confidence", 0) for r in ddos_reports), default=0)
    check(
        "DDOS classifications have confidence >= 0.70",
        len(ddos_reports) > 0 and min_ddos_conf >= 0.70,
        f"min confidence across DDOS reports: {min_ddos_conf:.2f}",
    )

    # ── TIA ───────────────────────────────────────────────────────────
    print("\n  -- TIA --")

    multi_seg = [m for m in intel_msgs if m.get("pattern_type") == "MULTI_SEGMENT_SCAN"]
    coord_ddos = [m for m in intel_msgs if m.get("pattern_type") == "COORDINATED_DDOS"]

    check(
        "TIA detects MULTI_SEGMENT_SCAN (same IP on server + internal)",
        len(multi_seg) >= 1,
        f"intel count: {len(multi_seg)}  "
        f"segments: {multi_seg[0].get('affected_segments') if multi_seg else 'none'}  "
        f"src_ip: {multi_seg[0].get('src_ip') if multi_seg else 'none'}",
    )
    check(
        "TIA detects COORDINATED_DDOS (public-facing + sec-mon within 30 s window)",
        len(coord_ddos) >= 1,
        f"intel count: {len(coord_ddos)}  "
        f"segments: {coord_ddos[0].get('affected_segments') if coord_ddos else 'none'}",
    )
    check(
        "TIA participates in coalition voting",
        len(vote_msgs) >= 1,
        f"total votes cast by TIA: {len(vote_msgs)}",
    )

    # ── RCA ───────────────────────────────────────────────────────────
    print("\n  -- RCA --")

    quarantine_res = [r for r in resolutions if r.get("action") == "QUARANTINE_SEGMENT"
                                             and r.get("outcome") == "EXECUTED"]
    block_res      = [r for r in resolutions if r.get("action") == "BLOCK_SOURCE_IP"
                                             and r.get("outcome") == "EXECUTED"]
    noise_res      = [r for r in resolutions if r.get("classification") == "NOISE"]

    check(
        "RCA publishes QUARANTINE_SEGMENT resolution for DDoS",
        len(quarantine_res) >= 1,
        f"QUARANTINE resolutions: {len(quarantine_res)}  "
        f"segments: {[r.get('segment') for r in quarantine_res]}",
    )
    check(
        "RCA publishes BLOCK_SOURCE_IP resolution for PORT_SCAN",
        len(block_res) >= 1,
        f"BLOCK_SOURCE_IP resolutions: {len(block_res)}  "
        f"segments: {[r.get('segment') for r in block_res]}",
    )
    check(
        "No NOISE classification ever reaches resolution",
        len(noise_res) == 0,
        f"NOISE resolutions: {len(noise_res)}",
    )

    # ── RAA ───────────────────────────────────────────────────────────
    print("\n  -- RAA --")

    granted = [g for g in grants if g.get("outcome") == "GRANTED"]
    quarantine_grants = [g for g in granted if g.get("resource_type") == "QUARANTINE"]
    firewall_grants   = [g for g in granted if g.get("resource_type") == "FIREWALL"]
    denied  = [g for g in grants if g.get("outcome") == "DENIED"]
    evicted = [g for g in grants if g.get("outcome") == "EVICTED"]

    check(
        "RAA grants at least 1 QUARANTINE resource (DDoS response)",
        len(quarantine_grants) >= 1,
        f"QUARANTINE grants: {len(quarantine_grants)}  "
        f"total grants: {len(granted)}  "
        f"denials: {len(denied)}  evictions: {len(evicted)}",
    )
    check(
        "RAA grants at least 1 FIREWALL resource (PORT_SCAN response)",
        len(firewall_grants) >= 1,
        f"FIREWALL grants: {len(firewall_grants)}",
    )
    check(
        f"RAA enforcement: scanner IP ({SCANNER_IP}) added to blocked_ips",
        raa.is_blocked(SCANNER_IP),
        f"blocked_ips: {raa.blocked_ips}",
    )
    check(
        "RAA enforcement: at least 1 segment quarantined",
        len(raa.quarantined_segments) >= 1,
        f"quarantined_segments: {raa.quarantined_segments}",
    )

    # ── final ─────────────────────────────────────────────────────────
    print()
    print(f"  Overall: {'ALL PASS' if all_ok else 'SOME FAILURES'}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
