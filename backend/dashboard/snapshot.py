"""
JSON view-model assembly for the WebSocket broadcast — the shape the
frontend dashboard actually consumes, built from a StateCollector's state.
"""

from __future__ import annotations
from collections import deque

from dashboard.beliefs import build_beliefs
from dashboard.ui_metadata import SEGMENTS, AGENT_DEFS, AGENT_PLANS, AGENT_DESIRES

BUDGET = {"TMA": 100, "ACA": 200, "TIA": 1000, "RCA": 500, "RAA": 300}


def build_snapshot(sc, gen, segment_scenarios: dict[str, str], running: bool) -> dict:
    """Assemble the JSON object sent to every connected browser."""

    # ── Segments ──────────────────────────────────────────────────
    segs_out = {}
    for s in SEGMENTS:
        sid   = s["id"]
        stats = gen.get_stats(sid)
        dev   = stats.deviation
        hosts = sorted(gen.topology.hosts_in(sid), key=lambda h: h.hostname)

        if sid in sc.quarantined_segs:
            health = "QUARANTINED"
            # gen.get_stats() intentionally keeps reporting the real,
            # live reading even while blocked (see traffic.py
            # quarantine()) so RCA can poll for recovery — override
            # just the displayed number here, not the underlying stats.
            pps = 0.0
        else:
            pps = stats.current_pps
            if abs(dev) >= 6:
                health = "THREAT"
            elif abs(dev) >= 2:
                health = "ANOMALY"
            else:
                health = "NORMAL"

        segs_out[sid] = {
            **s,
            "state":       health,
            "scenario":    segment_scenarios.get(sid, "calm"),
            "pps":         round(pps, 1),
            "baseline":    round(stats.baseline_mean, 1),
            "deviation":   round(dev, 2),
            "hist":        [round(v, 1) for v in sc.bw_hist.get(sid, [])],
            "quarantined": sid in sc.quarantined_segs,
            "attack_pps":  round(gen.get_attack_pps(sid), 1),
            "hosts": [
                {"hostname": h.hostname, "ip": h.ip, "role": h.role}
                for h in hosts
            ],
        }

    # ── Agents ────────────────────────────────────────────────────
    agents_out = {}
    m = sc.metrics()

    for aid, atype, code, role, type_name, seg_label in AGENT_DEFS:
        state = sc.ag_state.get(aid, "mon")
        task  = sc.ag_task.get(aid, "watching traffic")
        trace = list(sc.ag_trace.get(aid, deque()))
        plan  = AGENT_PLANS.get((atype, state), "idle")
        budget = BUDGET[atype]

        beliefs = build_beliefs(aid, atype, gen, m, sc)

        agents_out[aid] = {
            "id":        aid,
            "code":      code,
            "type":      atype,
            "role":      role,
            "typeName":  type_name,
            "seg":       seg_label,
            "state":     state,
            "task":      task,
            "plan":      plan,
            "budget":    budget,
            "desires":   AGENT_DESIRES[atype],
            "beliefs":   beliefs,
            "trace":     trace,
            "traceEmpty": len(trace) == 0,
        }

    return {
        "t":                round(sc.elapsed(), 1),
        "running":          running,
        "segments":         segs_out,
        "agents":           agents_out,
        "logs":             list(sc.logs),
        "viz_events":       list(sc.viz_events),
        "metrics":          m,
        "blocked_ips":      list(sc.blocked_ips),
        "quarantined_segs": list(sc.quarantined_segs),
        "ballots": {
            "open":     list(sc.ballots.values()),
            "resolved": list(sc.resolved_ballots),
        },
        "packets":          list(sc.packet_log),
    }
