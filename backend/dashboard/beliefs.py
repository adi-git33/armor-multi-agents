"""Agent-inspector belief-base presentation (BDI beliefs panel)."""

from __future__ import annotations

from dashboard.ui_metadata import SEG_MAP


def build_beliefs(aid: str, atype: str, gen, m: dict, sc) -> list[dict]:
    """Return the belief-base rows shown in the agent inspector."""
    G = "#4a9e7f"; R = "#cf6b5e"; A = "#d9a23f"; B = "#2b3440"
    beliefs = []

    if atype == "TMA":
        # One TMA per segment now — aid is "TMA:<segment_id>", so only
        # show beliefs for the one segment this instance actually watches.
        seg_id = aid.split(":", 1)[1] if ":" in aid else None
        s = SEG_MAP.get(seg_id)
        if s:
            st  = gen.get_stats(s["id"])
            dev = st.deviation
            beliefs.append({"k": "segment", "v": s["name"], "vColor": B})
            beliefs.append({"k": "baseline",
                             "v": f"{st.baseline_mean:.0f} ± {st.baseline_std:.0f} pps",
                             "vColor": B})
            beliefs.append({"k": "deviation",
                             "v": f"{dev:+.1f}σ",
                             "vColor": R if abs(dev) >= 4 else (A if abs(dev) >= 2 else G)})
        beliefs.append({"k": "last_alert_time", "v": "tracked for this segment", "vColor": B})
        beliefs.append({"k": "resource_available", "v": "True", "vColor": G})

    elif atype == "ACA":
        beliefs = [
            {"k": "classification_model", "v": "RandomForest (94 % acc)", "vColor": B},
            {"k": "false_positive_rate",  "v": f"{m['fpr']:.1%}",
             "vColor": G if m["fpr"] < 0.08 else R},
            {"k": "threats_classified",   "v": str(sc.tp),
             "vColor": R if sc.tp > 0 else B},
            {"k": "detection_rate",       "v": f"{m['dr']:.1%}",
             "vColor": G if m["dr"] > 0.8 else A},
        ]

    elif atype == "TIA":
        beliefs = [
            {"k": "global_threat_map",    "v": f"{len(sc.active_incidents)} active incidents",
             "vColor": R if sc.active_incidents else B},
            {"k": "correlation_matrix",   "v": "4×4 segment pairs", "vColor": B},
            {"k": "external_threat_feed", "v": "signature DB online", "vColor": G},
            {"k": "active_coalitions",    "v": str(len(sc.active_incidents)),
             "vColor": B if not sc.active_incidents else "#4577b5"},
        ]

    elif atype == "RCA":
        beliefs = [
            {"k": "confirmed_threats",    "v": str(len(sc.active_incidents)),
             "vColor": R if sc.active_incidents else B},
            {"k": "coalition_members",    "v": "TIA:1, RAA:1", "vColor": "#4577b5"},
            {"k": "blocked_ips",          "v": str(len(sc.blocked_ips)),
             "vColor": R if sc.blocked_ips else B},
            {"k": "quarantined_segments", "v": str(len(sc.quarantined_segs)),
             "vColor": A if sc.quarantined_segs else B},
        ]

    elif atype == "RAA":
        beliefs = [
            {"k": "resource_pool",        "v": "FIREWALL×3, QUARANTINE×2", "vColor": B},
            {"k": "host_utilization",     "v": "< 40 % CPU+MEM", "vColor": G},
            {"k": "active_allocations",   "v": str(len(sc.blocked_ips) + len(sc.quarantined_segs)),
             "vColor": B},
            {"k": "resolved_incidents",   "v": str(len(sc.mttr_ms)), "vColor": G},
        ]

    return beliefs
