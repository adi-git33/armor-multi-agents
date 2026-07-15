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
    --no-charts      Skip matplotlib chart export
    --chart-dir DIR  Directory for PNG charts (default: validation/charts/)

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
# Also put backend/validation/ itself on sys.path. Only matters when this
# module is *imported* (e.g. by validation/api.py) rather than run as the
# __main__ script — Python auto-prepends a script's own directory, but not
# a plain import's. Every SUITES module below is imported by bare name
# ("validate_tma", not "validation.validate_tma"), so it must resolve here.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validation.helpers import ValidationSuite, ValidationResult, GREEN, RED, BOLD, RESET, YELLOW, CYAN
from validation.visualize_results import export_charts, print_chart_summary

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


def _apply_vote_window_ms(ms: float) -> None:
    """Patch RCA vote window; reload validation modules that bind VOTE_WINDOW at import."""
    import importlib
    import agents.rca as rca_mod

    rca_mod.VOTE_WINDOW = ms / 1000.0
    for name in sorted(sys.modules):
        mod_base = name.rsplit(".", 1)[-1]
        if mod_base.startswith("validate_"):
            importlib.reload(sys.modules[name])


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

    for row in build_srs_target_table(all_results):
        color   = {"PASS": GREEN, "FAIL": RED, "SKIP": YELLOW}[row["verdict"]]
        verdict = f"{color}{row['verdict']}{RESET}"
        print(f"  {row['name']:<35} {row['threshold']:<22} {row['observed']:<22} [{verdict}]")

    print("\n" + "=" * w)
    print(f"  Final verdict: {GREEN + BOLD if all_ok else RED + BOLD}"
          f"{'ALL REQUIREMENTS MET' if all_ok else 'ONE OR MORE REQUIREMENTS NOT MET'}{RESET}")
    print("=" * w + "\n")

    return all_ok


def _print_vote_window_comparison(
    runs: list[tuple[int, list[tuple[str, ValidationSuite]], float]],
) -> None:
    """Side-by-side summary for vote-window-sensitive checks."""
    labels = [f"{ms} ms" for ms, _, _ in runs]
    w = 88

    print("\n")
    print("=" * w)
    print(f"  {BOLD}VOTE WINDOW COMPARISON{RESET}")
    print("=" * w)
    print(f"  {'Check':<42} {'Expected':<18} " + "  ".join(f"{lbl:>14}" for lbl in labels))
    print("  " + "─" * (w - 4))

    sensitive = (
        ("FR-30", "mttr"),
        ("FR-31", "avail"),
        ("S1", "mttr"),
        ("S1", "avail"),
        ("S6", "cycle"),
        ("SW", "social welfare"),
        ("D-RCA-1", "mttr"),
    )

    for req_id, keyword in sensitive:
        row_label = f"{req_id} ({keyword})"
        cells: list[str] = []
        expected = "—"
        for _, suites_run, _ in runs:
            all_results = [(lbl, r) for lbl, suite in suites_run for r in suite.results]
            r = _find(all_results, req_id, keyword)
            if r is None:
                cells.append(f"{YELLOW}SKIP{RESET}".rjust(14 + len(YELLOW) + len(RESET)))
                continue
            if expected == "—" and r.expected is not None:
                expected = str(r.expected)[:16]
            mark = f"{GREEN}PASS{RESET}" if r.passed else f"{RED}FAIL{RESET}"
            obs = str(r.observed)[:12] if r.observed is not None else "—"
            cells.append(f"{mark} {obs}")

        print(f"  {row_label:<42} {expected:<18} " + "  ".join(cells))

    print("\n  " + "─" * (w - 6))
    for ms, suites_run, wall in runs:
        total = sum(s.total_count for _, s in suites_run)
        passed = sum(s.pass_count for _, s in suites_run)
        failed = total - passed
        color = GREEN if failed == 0 else RED
        print(f"  VOTE_WINDOW={ms} ms:  "
              f"{color}{passed}/{total} passed{RESET}  "
              f"wall={wall:.1f}s")
    print("=" * w + "\n")


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


# SRS §7.3 target mapping — the 10-row headline table. Defined once here so
# the CLI (_print_master_summary) and the web API (validation/api.py) build
# the exact same rows from the exact same results, instead of two hand-kept
# copies drifting apart.
SRS_TARGETS: list[tuple[str, str, str, str]] = [
    # (display name, threshold text, req_id, label keyword for _find)
    ("Detection Rate (DR)",              "> 90%",      "FR-29", "DR"),
    ("False Positive Rate (FPR)",         "< 8% / 10%", "FR-09", "FPR"),
    ("MTTR (Response)",                   "< 1000 ms",  "FR-30", "MTTR"),
    ("System Availability",               "> 99%",      "FR-31", "avail"),
    ("Resource Overhead",                 "< 40% host", "FR-23", "overhead"),
    ("Auction completion",                "< 300 ms",   "FR-19", "auction"),
    ("Vote cycle",                        "< 300 ms",   "S6",    "vote"),
    ("Coalition formation",               "< 1 s",      "S2",    "coalition"),
    ("Agent failure coverage reassign",   "< 2 s",      "S5",    "reassign"),
    ("Social Welfare (SW)",               "≥ 0.80",     "SW",    "Social Welfare"),
]


def build_srs_target_table(
    all_results: list[tuple[str, ValidationResult]],
) -> list[dict]:
    """Build the 10-row SRS §7.3 target-mapping table as plain dicts
    (name / threshold / observed / verdict / req_id), independent of any
    print formatting. Single source of truth for both the CLI summary and
    the /api/validation WebSocket's run-completed event."""
    rows: list[dict] = []
    for name, threshold, req_id, keyword in SRS_TARGETS:
        result = _find(all_results, req_id, keyword)
        if result is not None:
            rows.append({
                "name":      name,
                "threshold": threshold,
                "observed":  str(result.observed)[:20] if result.observed is not None else "—",
                "verdict":   "PASS" if result.passed else "FAIL",
                "req_id":    req_id,
            })
        else:
            rows.append({
                "name":      name,
                "threshold": threshold,
                "observed":  "not run",
                "verdict":   "SKIP",
                "req_id":    req_id,
            })
    return rows


async def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="ARMOR MAS validation runner")
    parser.add_argument("--quick",  action="store_true",
                        help="Run only fast suites (tma, aca, rca, system)")
    parser.add_argument("--suite",  choices=list(SUITES), default=None,
                        help="Run a single suite")
    parser.add_argument("--vote-window-ms", type=float, default=None, metavar="MS",
                        help="Override RCA VOTE_WINDOW (milliseconds)")
    parser.add_argument("--compare-vote-windows", action="store_true",
                        help="Run full validation at 2000 ms and 3 ms, then compare")
    parser.add_argument("--no-charts", action="store_true",
                        help="Skip matplotlib chart export")
    parser.add_argument("--chart-dir", default=None, metavar="DIR",
                        help="Output directory for PNG charts (default: validation/charts/)")
    args = parser.parse_args(argv)

    if args.suite:
        keys = [args.suite]
    elif args.quick:
        keys = QUICK_SUITES
    else:
        keys = list(SUITES)

    vote_windows: list[float | None]
    if args.compare_vote_windows:
        vote_windows = [2000.0, 3.0]
    elif args.vote_window_ms is not None:
        vote_windows = [args.vote_window_ms]
    else:
        vote_windows = [None]

    compare_runs: list[tuple[int, list[tuple[str, ValidationSuite]], float]] = []
    last_all_ok = True

    for vw_ms in vote_windows:
        if vw_ms is not None:
            _apply_vote_window_ms(vw_ms)
            vw_label = f"VOTE_WINDOW={vw_ms:.0f} ms"
        else:
            vw_label = "default VOTE_WINDOW"

        print("\n")
        print("=" * 80)
        print(f"  {BOLD}ARMOR MAS — Starting Validation Runner{RESET}")
        print(f"  Suites: {', '.join(keys)}")
        print(f"  {vw_label}")
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
                stub = ValidationSuite(label)
                stub.check(key.upper(), f"Suite {label} raised an exception", False,
                           observed=str(exc), expected="no exception")
                suites_run.append((label, stub))

        total_wall = time.monotonic() - t_start
        last_all_ok = _print_master_summary(suites_run, total_wall)
        if not args.no_charts:
            try:
                chart_paths = export_charts(suites_run, args.chart_dir)
                print_chart_summary(chart_paths)
            except ImportError as exc:
                print(f"\n  {YELLOW}Charts skipped: {exc} "
                      f"(pip install matplotlib){RESET}")
        if args.compare_vote_windows and vw_ms is not None:
            compare_runs.append((int(vw_ms), suites_run, total_wall))

    if compare_runs:
        _print_vote_window_comparison(compare_runs)

    return 0 if last_all_ok else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
