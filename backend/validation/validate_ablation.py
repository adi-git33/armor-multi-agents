"""
validate_ablation.py — One-Factor-At-A-Time (OFAT) Mechanism Ablation
(BASELINE_VS_ADVANCED_VALIDATION_PLAN_V2 §5.2 / §3.2 of the Validation Report)
================================================================================
With 4 independent flags there are 16 possible combinations — impractical
and unnecessary. This sweeps 6 rows instead, matching the SDD's own
four-mechanism structure (§4.1–4.4): start from full baseline, flip on one
mechanism at a time, end at full advanced. Each row differs from "Full
baseline" by exactly one flag, so its Δ vs. the baseline row is directly
attributable to that single mechanism.

    Row               naive_ladder  naive_voting  TIA started  naive_auction   Isolates
    Full baseline     naive         naive         off          naive           — (floor)
    + proportionality off           naive         off          naive           §4.1
    + voting          naive         off           off          naive           §4.4
    + coalition       naive         naive         on           naive           §4.3
    + auction         naive         naive         off          off             §4.2
    Full advanced     off           off           on           off             — (ceiling)

Iterates only over OFAT_SCENARIOS = (1, 2, 3, 6) — S4/S5 are excluded by
construction (scenario_lib.OFAT_SCENARIOS), not by convention someone could
forget. Uses the same run_scenario_N() pure callables as validate_baseline.py
/ validate_scenarios.py (scenario_lib.py, §5.4), each run with the uniform
peer-voter stub attached.

Usage:
    cd backend && python validation/validate_ablation.py
    cd backend && python validation/validate_ablation.py --seeds 2 --quick   # smoke test

Output:
    validation/results/ablation_ofat.json  — mean±std per scenario per row + raw per-seed values
    printed §3.2-style table
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE))

from scenario_lib import OFAT_SCENARIOS, SEEDS, ROWS, run_row_scenario
from helpers import section


async def run(seeds: list[int] | None = None) -> dict:
    seeds = seeds or list(SEEDS)
    assert len(seeds) >= 1, "need at least one seed"

    section(f"OFAT Mechanism Ablation — {len(seeds)} seed(s) {seeds}")

    table: dict[str, dict] = {}
    for row_name, flags, isolates in ROWS:
        row_result: dict[int, dict] = {}
        t0 = time.monotonic()
        for scenario_id in OFAT_SCENARIOS:
            row_result[scenario_id] = await run_row_scenario(scenario_id, seeds, flags)
        elapsed = time.monotonic() - t0
        table[row_name] = {"flags": flags, "isolates": isolates, "scenarios": row_result}
        print(f"  {row_name:<20} {isolates:<24}  "
              + "  ".join(f"S{sid}_SW={row_result[sid]['mean']:.3f}±{row_result[sid]['std']:.3f}"
                          for sid in OFAT_SCENARIOS)
              + f"   ({elapsed:.1f}s)")

    output = {
        "seeds": seeds,
        "ofat_scenarios": list(OFAT_SCENARIOS),
        "rows": table,
    }

    out_path = _HERE / "results" / "ablation_ofat.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, default=str))
    print(f"\n  wrote {out_path}")

    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=len(SEEDS),
                         help="number of seeds to use (default: full N=8 sweep)")
    parser.add_argument("--quick", action="store_true",
                         help="alias for --seeds 1 (smoke test)")
    args = parser.parse_args()

    n = 1 if args.quick else args.seeds
    seed_list = list(SEEDS[:n])
    asyncio.run(run(seed_list))
