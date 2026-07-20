"""
ACA Model Comparison
====================
Compare two saved ACA classifier checkpoints (same pickle format as
aca_model.pkl — {"model", "labels", ...}) on a shared, freshly generated
evaluation set.

Why not just diff the "accuracy" field each model was saved with?
Each aca_trainer.py run draws its own random train/test split over
whatever data it was given (synthetic only, or synthetic + feedback), so
two accuracy numbers from two separate runs are not measured on the same
data and are not directly comparable.

Two evaluation slices:
  1. Synthetic scenarios — same SCENARIOS as aca_trainer.py, but a seed
     range reserved for evaluation (EVAL_SEED_BASE) so it cannot overlap
     with aca_trainer.py's default training seeds. Same data, both models,
     neither has seen it.
  2. Operator feedback (models/aca_feedback.jsonl), if any exist. Real
     EXECUTED-confirmed ground truth from live traffic. CAVEAT: if either
     model was retrained with --with-feedback, it may have trained on
     exactly these samples — treat a strong score there as optimistic,
     not held-out, for that model.

Usage:
    python -m agents.aca_compare <model_a.pkl> <model_b.pkl>
    python -m agents.aca_compare models/aca_model.pkl.bak models/aca_model.pkl --seeds 4
"""

from __future__ import annotations
import argparse
import asyncio
import pickle
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agents.aca_trainer import SCENARIOS, _run_scenario, LABEL_NAMES, _load_feedback_samples
from agents.aca_trainer import FEEDBACK_PATH

# Clear of aca_trainer.py's default training seed range (n_seeds * 19 + label,
# n_seeds defaults to 8 -> seeds 0..133) so the eval set can't have been
# seen by a normally-trained model.
EVAL_SEED_BASE = 5000


async def _build_eval_set(n_seeds: int) -> tuple[np.ndarray, np.ndarray]:
    all_X: list[list[float]] = []
    all_y: list[int]         = []
    for sc in SCENARIOS:
        for seed in range(n_seeds):
            samples = await _run_scenario(
                sc, seed=EVAL_SEED_BASE + seed * 19 + sc.base_label
            )
            for features, lbl in samples:
                all_X.append(features)
                all_y.append(lbl)
    return np.array(all_X, dtype=float), np.array(all_y, dtype=int)


def _load_model(path: Path) -> dict:
    with open(path, "rb") as f:
        return pickle.load(f)


def _evaluate(clf, X: np.ndarray, y: np.ndarray) -> dict:
    if len(X) == 0:
        return {"n": 0}
    y_pred = clf.predict(X)
    proba  = clf.predict_proba(X)
    return {
        "n":               len(X),
        "accuracy":        accuracy_score(y, y_pred),
        "report":          classification_report(
                                y, y_pred, labels=[0, 1, 2],
                                target_names=LABEL_NAMES,
                                zero_division=0, output_dict=True,
                            ),
        "confusion":       confusion_matrix(y, y_pred, labels=[0, 1, 2]),
        "mean_confidence": float(proba.max(axis=1).mean()),
    }


def _print_side_by_side(name_a: str, res_a: dict, name_b: str, res_b: dict, title: str) -> None:
    print(f"\n  {title}")
    if res_a["n"] == 0 or res_b["n"] == 0:
        print("    (skipped — no samples)")
        return

    print(f"    {'':22s} {name_a:>16s} {name_b:>16s} {'delta':>10s}   (n={res_a['n']})")
    acc_a, acc_b = res_a["accuracy"], res_b["accuracy"]
    print(f"    {'accuracy':22s} {acc_a*100:15.2f}% {acc_b*100:15.2f}% "
          f"{(acc_b-acc_a)*100:+9.2f}pp")
    conf_a, conf_b = res_a["mean_confidence"], res_b["mean_confidence"]
    print(f"    {'mean confidence':22s} {conf_a:16.3f} {conf_b:16.3f} {conf_b-conf_a:+10.3f}")
    for label in LABEL_NAMES:
        fa = res_a["report"].get(label, {}).get("f1-score", 0.0)
        fb = res_b["report"].get(label, {}).get("f1-score", 0.0)
        print(f"    {label+' F1':22s} {fa:16.3f} {fb:16.3f} {fb-fa:+10.3f}")

    print(f"\n    Confusion matrices (rows=true, cols=predicted; order {LABEL_NAMES}):")
    for name, res in ((name_a, res_a), (name_b, res_b)):
        print(f"      {name}:")
        for row in res["confusion"]:
            print(f"        {row.tolist()}")


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare two ACA model checkpoints on a shared evaluation set")
    parser.add_argument("model_a", type=Path)
    parser.add_argument("model_b", type=Path)
    parser.add_argument("--seeds", type=int, default=2,
                         help="seeds per scenario for the synthetic eval set (default 2)")
    args = parser.parse_args()

    payload_a, payload_b = _load_model(args.model_a), _load_model(args.model_b)
    clf_a, clf_b = payload_a["model"], payload_b["model"]
    name_a, name_b = args.model_a.name, args.model_b.name

    print("=" * 70)
    print("  ACA Model Comparison")
    print(f"  A = {args.model_a}  (self-reported accuracy: {payload_a.get('accuracy', '?')})")
    print(f"  B = {args.model_b}  (self-reported accuracy: {payload_b.get('accuracy', '?')})")
    print("=" * 70)

    print(f"\n  Generating shared synthetic eval set "
          f"({len(SCENARIOS)} scenarios x {args.seeds} seeds, reserved seed range)...")
    X_eval, y_eval = await _build_eval_set(args.seeds)
    print(f"  {len(X_eval)} synthetic eval samples generated")

    res_a_syn = _evaluate(clf_a, X_eval, y_eval)
    res_b_syn = _evaluate(clf_b, X_eval, y_eval)
    _print_side_by_side(
        name_a, res_a_syn, name_b, res_b_syn,
        "Synthetic eval set (fresh, reserved seeds — unseen by either model's training)",
    )

    fb_X, fb_y = _load_feedback_samples()
    if fb_X:
        fb_X_arr, fb_y_arr = np.array(fb_X, dtype=float), np.array(fb_y, dtype=int)
        res_a_fb = _evaluate(clf_a, fb_X_arr, fb_y_arr)
        res_b_fb = _evaluate(clf_b, fb_X_arr, fb_y_arr)
        _print_side_by_side(
            name_a, res_a_fb, name_b, res_b_fb,
            f"Operator feedback slice ({FEEDBACK_PATH.name}) — CAVEAT: a model "
            f"retrained with --with-feedback may have trained on exactly these "
            f"samples, inflating its score here",
        )
    else:
        print(f"\n  No persisted feedback samples found at {FEEDBACK_PATH} — skipping feedback slice")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
