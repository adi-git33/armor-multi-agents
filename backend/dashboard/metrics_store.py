"""
Persistence for ACA's cumulative detection confusion matrix (tp/fp/fn/tn)
across backend restarts, so the live dashboard's Detection Rate / False
Positive Rate accumulate instead of resetting to zero every launch.
Bootstrap a starting value with scripts/seed_aca_metrics.py.
"""

from __future__ import annotations
import json
import pathlib

ACA_METRICS_PATH = (
    pathlib.Path(__file__).resolve().parent.parent / "models" / "aca_metrics.json"
)


def load_aca_metrics() -> dict:
    try:
        data = json.loads(ACA_METRICS_PATH.read_text())
        return {k: int(data.get(k, 0)) for k in ("tp", "fp", "fn", "tn")}
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return {"tp": 0, "fp": 0, "fn": 0, "tn": 0}


def save_aca_metrics(tp: int, fp: int, fn: int, tn: int) -> None:
    ACA_METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ACA_METRICS_PATH.write_text(json.dumps({"tp": tp, "fp": fp, "fn": fn, "tn": tn}))
