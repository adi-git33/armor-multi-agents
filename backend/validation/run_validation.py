"""
run_validation.py — Master Validation Runner
=============================================
Executes all validation suites in sequence and prints a consolidated
PASS / FAIL summary table comparing observed values against SRS/SDD targets.

Usage:
    cd backend
    python validation/run_validation.py [--quick] [--suite SUITE]

Options:
    --quick          Skip slow stress-test suites (TIA, RAA, scenarios)
    --suite SUITE    Run only one suite: tma | aca | rca | tia | raa | system | scenarios

Output:
    ┌─────────────────────────────────────────────────────────────────┐
    │ ARMOR MAS — Validation Summary                                  │
    │ Total checks: N    Passed: N    Failed: N                       │
    │ ─────────────────────────────────────────────────────────────── │
    │ [PASS] FR-01  TMA sample rate ≥ 10 Hz …                       │
    │ [FAIL] FR-30  MTTR_Response < 1000 ms  observed=1450ms …       │
    │  …                                                              │
    └─────────────────────────────────────────────────────────────────┘

Exit code: 0 if all checks pass, 1 if any fail.
"""

from __future__ import annotations
import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from validation.helpers import ValidationSuite, ValidationResult, GREEN, RED, BOLD, RESET, YELLOW, CYAN

# ── suite registry ─────────────────────────────────────────────────────
SUITES = {
    "tma":       ("validate_tma",       "TMA  (Traffic Monitor Agent)"),
    "aca":       ("validate_aca",       "ACA  (Anomaly Classifier Agent)"),
    "rca":       ("validate_rca",       "RCA  (Response Coordinator Agent)"),
    "tia":       ("validate_tia",       "TIA  (Threat Intelligence Agent)"),
    "raa":       ("validate_raa",       "RAA  (Resource Allocator Agent)"),
    "system":    ("validate_system",    "System-Level  (FR-29..FR-34 + SW)"),
    "scenarios": ("validate_scenarios", "Scenarios  (SRS §8, all 6)"),
}

QUICK_SUITES = ["tma", "aca", "rca", "system"]


async def run_suite(module_name: str) -> ValidationSuite:
    import importlib
    mod = importlib.import_module(module_name)
    return await mod.run()


def _print_master_summary(
    suites_run: list[tuple[str, ValidationSuite]],
    total_wall: float,
) -> None:
    all_results: list[tuple[str, ValidationResult]] = []
    for label, suite in suites_run:
        for r in suite.results:
            all_results.append((label, r))

    total   = len(all_results)
    passed  = sum(1 for _, r in all_results if r.passed)
    failed  = total - passed
    all_ok  = failed == 0

    w = 80

    print("\n")
    print("=" * w)
    print(f"  {BOLD}ARMOR MAS — VALIDATION SUMMARY{RESET}")
    print(f"  {'ALL PASS' if all_ok else 'SOME FAILURES'}   "
          f"total={total}  passed={GREEN}{passed}{RESET}  "
          f"failed={RED}{failed}{RESET}   "
          f"wall time={total_wall:.1f}s")
    print("=" * w)

    # Group by suite
    for label, suite in suites_run:
        s_pass = suite.pass_count
        s_tot  = suite.total_count
        s_ok   = s_pass == s_tot
        color  = GREEN if s_ok else RED
        print(f"\n  {color}{BOLD}{'✓' if s_ok else '✗'}{RESET}  "
              f"{CYAN}{label}{RESET}  "
              f"({s_pass}/{s_tot})")

        for r in suite.results:
            mark   = f"{GREEN}PASS{RESET}" if r.passed else f"{RED}FAIL{RESET}"
            req    = f"{CYAN}{r.req_id:<6}{RESET}"
            label2 = r.label[:52] + "…" if len(r.label) > 52 else r.label
            obs    = ""
            if r.observed is not None:
                obs = f"  observed={str(r.observed)[:35]}"
            exp = ""
            if r.expected is not None:
                exp = f"  expected={str(r.expected)[:25]}"
            print(f"    [{mark}] {req}  {label2}{obs}{exp}")

    # ── Final verdict table matching Validation Report §1 ─────────────
    print("\n")
    print("=" * w)
    print(f"  {BOLD}VALIDATION REPORT — TABLE 1 RESULT MAPPING (SRS §7.3){RESET}")
    print("=" * w)
    print(f"  {'Target / Constraint':<35} {'Threshold':<22} {'Observed':<22} {'Verdict'}")
    print("  " + "─" * 76)

    targets = [
        ("Detection Rate (DR)",          "> 90%",      _find(all_results, "FR-29", "DR")),
        ("False Positive Rate (FPR)",     "< 8% / 10%", _find(all_results, "FR-09", "FPR")),
        ("MTTR (Response)",               "< 1000 ms",  _find(all_results, "FR-30", "MTTR")),
        ("System Availability",           "> 99%",      _find(all_results, "FR-31", "avail")),
        ("Resource Overhead",             "< 40% host", _find(all_results, "FR-23", "overhead")),
        ("Auction completion",            "< 300 ms",   _find(all_results, "FR-19", "auction")),
        ("Vote cycle",                    "< 300 ms",   _find(all_results, "S6",    "vote")),
        ("Coalition formation",           "< 1 s",      _find(all_results, "S2",    "coalition")),
        ("Agent failure coverage reassign","< 2 s",     _find(all_results, "S5",    "reassign")),
        ("Social Welfare (SW)",           "≥ 0.80",     _find(all_results, "SW",    "Social Welfare")),
    ]

    for name, threshold, result in targets:
        if result:
            obs     = str(result.observed)[:20] if result.observed else "—"
            verdict = f"{GREEN}PASS{RESET}" if result.passed else f"{RED}FAIL{RESET}"
        else:
            obs     = "not run"
            verdict = f"{YELLOW}SKIP{RESET}"
        print(f"  {name:<35} {threshold:<22} {obs:<22} [{verdict}]")

    print("\n" + "=" * w)
    print(f"  Final verdict: {GREEN + BOLD if all_ok else RED + BOLD}"
          f"{'ALL REQUIREMENTS MET' if all_ok else 'ONE OR MORE REQUIREMENTS NOT MET'}{RESET}")
    print("=" * w + "\n")

    return all_ok


def _find(
    all_results: list[tuple[str, ValidationResult]],
    req_id: str,
    keyword: str,
) -> ValidationResult | None:
    """Return the first result matching req_id AND keyword in label."""
    kw = keyword.lower()
    for _, r in all_results:
        if r.req_id == req_id and kw in r.label.lower():
            return r
    # Fallback: match only req_id
    for _, r in all_results:
        if r.req_id == req_id:
            return r
    return None


async def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="ARMOR MAS validation runner")
    parser.add_argument("--quick",  action="store_true",
                        help="Run only fast suites (tma, aca, rca, system)")
    parser.add_argument("--suite",  choices=list(SUITES), default=None,
                        help="Run a single suite")
    args = parser.parse_args(argv)

    if args.suite:
        keys = [args.suite]
    elif args.quick:
        keys = QUICK_SUITES
    else:
        keys = list(SUITES)

    print("\n")
    print("=" * 80)
    print(f"  {BOLD}ARMOR MAS — Starting Validation Runner{RESET}")
    print(f"  Suites: {', '.join(keys)}")
    print("=" * 80)

    t_start      = time.monotonic()
    suites_run: list[tuple[str, ValidationSuite]] = []

    for key in keys:
        module_name, label = SUITES[key]
        print(f"\n  ▶  Running {BOLD}{label}{RESET} …")
        try:
            suite = await run_suite(module_name)
            suites_run.append((label, suite))
        except Exception as exc:
            print(f"  {RED}ERROR in {label}: {exc}{RESET}")
            # Create a failed stub suite so it shows in the summary
            stub = ValidationSuite(label)
            stub.check(key.upper(), f"Suite {label} raised an exception", False,
                       observed=str(exc), expected="no exception")
            suites_run.append((label, stub))

    total_wall = time.monotonic() - t_start
    all_ok = _print_master_summary(suites_run, total_wall)

    return 0 if all_ok else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
