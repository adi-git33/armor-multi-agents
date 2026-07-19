"""
Static display/domain metadata for the live dashboard — segment
definitions, per-agent display config, BDI desire/plan tables, and the
topic -> visualization-recipient map. Pure data, no behavior.
"""

from __future__ import annotations

from core.messages import Topic

SEGMENTS = [
    {"id": "public-facing", "code": "PUB", "name": "Public-Facing Services", "cidr": "172.16.0.0/24"},
    {"id": "server",        "code": "SRV", "name": "Server Zone",            "cidr": "10.0.2.0/24"},
    {"id": "internal",      "code": "INT", "name": "Internal User Subnet",   "cidr": "10.0.1.0/24"},
    {"id": "sec-mon",       "code": "MON", "name": "Security Monitoring Zone","cidr": "10.0.3.0/24"},
]
SEG_MAP = {s["id"]: s for s in SEGMENTS}

# One TMA agent per network segment — each only watches its own segment's
# traffic (see agents/tma.py's segment_id filter). Every other MAS agent
# is a single process-wide instance.
TMA_DEFS = [
    (f"TMA:{s['id']}", "TMA", f"TMA-{s['code']}", "Traffic Monitor",
     "Traffic Monitor Agent", s["name"])
    for s in SEGMENTS
]
AGENT_DEFS = TMA_DEFS + [
    ("ACA:1", "ACA", "ACA-1", "Anomaly Classifier",   "Anomaly Classifier Agent",   "All Segments"),
    ("TIA:1", "TIA", "TIA-1", "Threat Intelligence",  "Threat Intelligence Agent",  "Global"),
    ("RCA:1", "RCA", "RCA-1", "Response Coordinator", "Response Coordinator Agent", "Global"),
    ("RAA:1", "RAA", "RAA-1", "Resource Allocator",   "Resource Allocator Agent",   "Global"),
]

SCENARIOS = {
    "calm":  {"label": "Calm Baseline"},
    "ddos":  {"label": "DDoS Attack"},
    "scan":  {"label": "Port Scan"},
}

# BDI desires per agent type — used in the inspector panel
AGENT_DESIRES = {
    "TMA": ["Maximize detection rate per segment",
            "Keep false positives below 10 %",
            "Publish alerts within 100 ms"],
    "ACA": ["Classify every alert within 200 ms",
            "Maintain accuracy above 90 % and FPR < 8 %",
            "Improve model after each resolved incident"],
    "TIA": ["Maintain global threat model updated every 500 ms",
            "Detect multi-segment correlations within 1 s",
            "Trigger coalition formation within 1 000 ms"],
    "RCA": ["Initiate response within 500 ms (severity ≥ 0.7)",
            "Maximize service availability",
            "Quarantine requires majority coalition vote",
            "Select least-disruptive effective action"],
    "RAA": ["Serve highest-severity threat first",
            "Complete auctions within 300 ms",
            "Keep MAS overhead below 40 % host capacity",
            "Reclaim resources within 500 ms of resolution"],
}

# Active plan name per (agent_type, state)
AGENT_PLANS = {
    ("TMA", "alert"): "detect_anomaly",
    ("TMA", "mon"):   "update_baseline",
    ("TMA", "idle"):  "idle",
    ("ACA", "active"):"classify_alert",
    ("ACA", "mon"):   "share_intel",
    ("ACA", "idle"):  "idle",
    ("TIA", "active"):"detect_correlation",
    ("TIA", "mon"):   "update_threat_model",
    ("TIA", "idle"):  "rank_threats",
    ("RCA", "active"):"respond_to_threat",
    ("RCA", "mon"):   "initiate_voting",
    ("RCA", "idle"):  "standby",
    ("RAA", "active"):"run_auction",
    ("RAA", "mon"):   "monitor_overhead",
    ("RAA", "idle"):  "idle",
}

# Agent recipients per topic for visualization (current runtime wiring).
VIZ_TOPIC_RECIPIENTS = {
    Topic.ALERTS:         ["ACA:1"],
    Topic.THREAT_REPORTS: ["RCA:1", "TIA:1"],
    Topic.THREAT_INTEL:   ["RCA:1"],
    Topic.COALITION:      ["TIA:1"],
    Topic.RESOLUTION:     ["RAA:1"],
    Topic.RESOURCE_GRANTS: [],
}
