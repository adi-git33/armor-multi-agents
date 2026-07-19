"""
ACA feature vector — single source of truth.

Both the live classifier (agents/aca.py) and the offline trainer
(agents/aca_trainer.py) must build the exact same vector, in the exact
same order, or the trained model silently misclassifies live traffic.
This module is the one place that vector is defined.
"""

from __future__ import annotations

FEATURE_NAMES = [
    "anomaly_type_enc",     # 0 = VOLUME_SPIKE,  1 = PORT_SCAN
    "deviation",
    "severity",
    "port_count",
    "port_growth_rate",     # unique ports / seconds since IP first seen
    "elapsed_scan_secs",    # seconds since this src IP appeared in the tracker
    "recent_alert_count",   # TMA alerts on this segment in last 30 s
    "max_deviation_30s",    # highest deviation across that window
    "cross_segment_count",  # other segments also alerting in last 5 s
]

RECENT_WINDOW = 30.0   # seconds — recent_alert_count / max_deviation_30s
CROSS_WINDOW  = 5.0    # seconds — cross_segment_count


def extract_features(
    content: dict,
    segment: str,
    now: float,
    history: dict[str, list[dict]],
) -> list[float]:
    """Build the FEATURE_NAMES vector for one alert.

    `history` is segment -> list of past alert dicts, each carrying a
    "time" key — the shape both aca.py and aca_trainer.py already keep.
    """
    enc = 1.0 if content["anomaly_type"] == "PORT_SCAN" else 0.0
    dev = float(content.get("deviation",         0.0))
    sev = float(content.get("severity",          0.0))
    pc  = float(content.get("port_count",        0))
    pgr = float(content.get("port_growth_rate",  0.0))
    esc = float(content.get("elapsed_scan_secs", 0.0))

    seg_history  = history.get(segment, [])
    recent       = [a for a in seg_history if now - a["time"] <= RECENT_WINDOW]
    recent_count = float(len(recent))
    max_dev      = float(max((a.get("deviation", 0.0) for a in recent), default=dev))
    cross_count  = float(sum(
        1 for s, h in history.items()
        if s != segment and any(now - a["time"] <= CROSS_WINDOW for a in h)
    ))

    return [enc, dev, sev, pc, pgr, esc, recent_count, max_dev, cross_count]
