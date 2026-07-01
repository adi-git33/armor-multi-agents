"""
visualize_results.py — Matplotlib charts for ARMOR MAS validation runs
========================================================================
Generates five report figures from structured suite metrics (and result
parsing fallbacks):

  fig1_per_agent_utility.png      §4.1 Per-Agent Utility
  fig2_social_welfare.png         §4.2 Social Welfare by validation stage
  fig3_defense_metrics.png        §4.3 Defense Performance Metrics
  fig4_attacker_utility.png       §4.4 Attacker Utility / Evasion
  fig5_resource_utilization.png   §4.5 Resource Utilization
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.patches as mpatches  # noqa: E402

from validation.helpers import ValidationSuite, GREEN, BOLD, RESET, YELLOW

_PASS = "#2ca02c"
_FAIL = "#d62728"
_TARGET = "#1f77b4"
_NEUTRAL = "#7f7f7f"

_SW_ORDER = ["System", "S1", "S2", "S3", "S4", "S5", "S6"]
_AGENT_ORDER = ["TMA", "ACA", "RCA", "RAA", "TIA"]


def _deep_merge(base: dict, extra: dict) -> dict:
    out = dict(base)
    for key, val in extra.items():
        if key in out and isinstance(out[key], dict) and isinstance(val, dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def _parse_sw(observed: Any) -> float | None:
    if observed is None:
        return None
    m = re.search(r"SW\s*(?:=|≈)\s*([\d.]+)", str(observed))
    return float(m.group(1)) if m else None


def _parse_utility(observed: Any) -> float | None:
    if observed is None:
        return None
    m = re.search(r"U_\w+\s*(?:=|≈)\s*([\d.]+)", str(observed))
    return float(m.group(1)) if m else None



def aggregate_metrics(
    suites_run: list[tuple[str, ValidationSuite]],
) -> dict[str, Any]:
    """Merge metrics from all suites; fill gaps from ValidationResult observations."""
    merged: dict[str, Any] = {
        "agent_utilities": {},
        "social_welfare": {},
        "defense": {},
        "attacker_utility": {},
        "resource": {},
    }

    for _, suite in suites_run:
        merged = _deep_merge(merged, suite.metrics)

    all_results = [r for _, suite in suites_run for r in suite.results]

    if not merged["agent_utilities"]:
        for agent in _AGENT_ORDER:
            for r in all_results:
                if r.req_id == "SW" and f"U_{agent}" in str(r.observed):
                    val = _parse_utility(r.observed)
                    if val is not None:
                        merged["agent_utilities"][agent] = {
                            "value": val, "passed": r.passed,
                        }
                        break

    if "System" not in merged["social_welfare"]:
        for r in all_results:
            if r.req_id == "SW" and "Social Welfare" in r.label:
                val = _parse_sw(r.observed)
                if val is not None:
                    merged["social_welfare"]["System"] = {
                        "value": val, "target": 0.80, "passed": r.passed,
                    }
                break

    for sid in ("S1", "S2", "S3", "S4", "S5", "S6"):
        if sid in merged["social_welfare"]:
            continue
        for r in all_results:
            if r.req_id == sid and "Social Welfare" in r.label:
                val = _parse_sw(r.observed)
                if val is not None:
                    merged["social_welfare"][sid] = {
                        "value": val, "target": 0.80, "passed": r.passed,
                    }
                break

    if "S1" not in merged["attacker_utility"]:
        for r in all_results:
            if r.req_id == "S1" and "U_ATK" in r.label:
                m = re.search(r"U_ATK\s*=\s*([\d.]+)", str(r.observed))
                if m:
                    val = float(m.group(1))
                    merged["attacker_utility"]["S1"] = {
                        "value": val, "target": 0.2, "passed": r.passed,
                        "label": "U_ATK",
                    }
                break

    if "S2" not in merged["attacker_utility"]:
        for r in all_results:
            if r.req_id == "S2" and "Evasion" in r.label:
                m = re.search(r"evasion\s*≈\s*([\d.]+)", str(r.observed))
                if m:
                    val = float(m.group(1))
                    merged["attacker_utility"]["S2"] = {
                        "value": val, "target": 0.15, "passed": r.passed,
                        "label": "Evasion rate",
                    }
                break

    return merged


def _bar_colors(entries: list[dict]) -> list[str]:
    return [_PASS if e.get("passed", True) else _FAIL for e in entries]


def _fig1_per_agent_utility(metrics: dict, out: Path) -> Path | None:
    agents = metrics.get("agent_utilities", {})
    if not agents:
        return None

    labels, values, colors = [], [], []
    for name in _AGENT_ORDER:
        if name not in agents:
            continue
        entry = agents[name]
        labels.append(name)
        values.append(float(entry["value"]))
        colors.append(_PASS if entry.get("passed", True) else _FAIL)

    if not labels:
        return None

    fig, ax = plt.subplots(figsize=(9, 5))
    y_pos = range(len(labels))
    ax.barh(list(y_pos), values, color=colors, edgecolor="white", height=0.6)
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(labels)
    ax.set_xlabel("Utility Value")
    ax.set_title("Figure 1 — Per-Agent Utility (System-Level Validation)")
    ax.axvline(0, color=_NEUTRAL, linewidth=0.8)
    ax.grid(axis="x", alpha=0.3)
    fig.legend(
        handles=[
            mpatches.Patch(color=_PASS, label="PASS"),
            mpatches.Patch(color=_FAIL, label="FAIL"),
        ],
        loc="lower right",
    )
    fig.tight_layout()
    path = out / "fig1_per_agent_utility.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _fig2_social_welfare(metrics: dict, out: Path) -> Path | None:
    sw = metrics.get("social_welfare", {})
    if not sw:
        return None

    labels, values, colors = [], [], []
    for key in _SW_ORDER:
        if key not in sw:
            continue
        entry = sw[key]
        labels.append(key)
        values.append(float(entry["value"]))
        colors.append(_PASS if entry.get("passed", True) else _FAIL)

    if not labels:
        return None

    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(labels))
    ax.plot(x, values, marker="o", color=_TARGET, linewidth=2, markersize=8, zorder=3)
    ax.bar(x, values, color=colors, alpha=0.35, edgecolor="white", zorder=2)
    ax.axhline(0.80, color=_TARGET, linestyle="--", linewidth=1.5,
               label="Target SW ≥ 0.80")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("Social Welfare (SW)")
    ax.set_xlabel("Validation Stage")
    ax.set_title("Figure 2 — Social Welfare Across Validation Stages")
    ax.set_ylim(0, max(max(values) * 1.1, 0.85))
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    path = out / "fig2_social_welfare.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _fig3_defense_metrics(metrics: dict, out: Path) -> Path | None:
    defense = metrics.get("defense", {})
    if not defense:
        return None

    # Normalise heterogeneous metrics to 0–1 scale for one chart.
    specs = [
        ("DR", "Detection Rate", False, lambda v, t: v / t if t else v),
        ("FPR", "False Positive Rate", True, lambda v, t: v / t if t else v),
        ("FPR_ACA", "ACA FPR", True, lambda v, t: v / t if t else v),
        ("FPR_TMA", "TMA FPR", True, lambda v, t: v / t if t else v),
        ("MTTR_ms", "MTTR Response (norm.)", True,
         lambda v, t: v / t if t else v / 1000.0),
        ("availability", "Availability", False, lambda v, t: v),
        ("accuracy", "ACA Accuracy", False, lambda v, t: v),
    ]

    labels, observed_norm, target_norm, colors = [], [], [], []
    for key, label, lower_better, norm_fn in specs:
        if key not in defense:
            continue
        entry = defense[key]
        val = float(entry["value"])
        tgt = float(entry.get("target", 1.0))
        labels.append(label)
        observed_norm.append(min(norm_fn(val, tgt), 1.5))
        target_norm.append(1.0)
        passed = entry.get("passed", True)
        if lower_better:
            passed = passed and val <= tgt
        else:
            passed = passed and val >= tgt
        colors.append(_PASS if passed else _FAIL)

    if not labels:
        return None

    fig, ax = plt.subplots(figsize=(11, 5))
    x = range(len(labels))
    width = 0.35
    ax.bar([i - width / 2 for i in x], observed_norm, width,
           label="Observed (normalised)", color=colors, edgecolor="white")
    ax.bar([i + width / 2 for i in x], target_norm, width,
           label="Target (normalised = 1.0)", color=_TARGET, alpha=0.45,
           edgecolor="white")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.set_ylabel("Normalised Score (1.0 = at target)")
    ax.set_title("Figure 3 — Defense Performance Metrics")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    path = out / "fig3_defense_metrics.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _fig4_attacker_utility(metrics: dict, out: Path) -> Path | None:
    atk = metrics.get("attacker_utility", {})
    if not atk:
        return None

    labels, values, targets, colors = [], [], [], []
    for key in ("S1", "S2"):
        if key not in atk:
            continue
        entry = atk[key]
        labels.append(f"{key}\n{entry.get('label', 'U_ATK')}")
        values.append(float(entry["value"]))
        targets.append(float(entry.get("target", 0.2)))
        colors.append(_PASS if entry.get("passed", True) else _FAIL)

    if not labels:
        return None

    fig, ax = plt.subplots(figsize=(7, 5))
    x = range(len(labels))
    width = 0.35
    ax.bar([i - width / 2 for i in x], values, width,
           label="Observed", color=colors, edgecolor="white")
    ax.bar([i + width / 2 for i in x], targets, width,
           label="Target (max)", color=_TARGET, alpha=0.45, edgecolor="white")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("Attacker Utility / Evasion Rate")
    ax.set_title("Figure 4 — Attacker Utility (Scenarios S1–S2)")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    path = out / "fig4_attacker_utility.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _fig5_resource_utilization(metrics: dict, out: Path) -> Path | None:
    resource = metrics.get("resource", {})
    overhead = resource.get("overhead")
    efficiency = resource.get("efficiency")
    if not overhead and not efficiency:
        return None

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.5))

    if overhead:
        val = float(overhead["value"])
        cap = float(overhead.get("target", 0.40))
        passed = overhead.get("passed", val < cap)
        color = _PASS if passed else _FAIL
        axes[0].bar(["MAS Overhead"], [val * 100], color=color, edgecolor="white")
        axes[0].axhline(cap * 100, color=_TARGET, linestyle="--",
                       label=f"Cap {cap*100:.0f}%")
        axes[0].set_ylabel("Host Overhead (%)")
        axes[0].set_title("CPU + RAM Overhead")
        axes[0].legend()
        axes[0].grid(axis="y", alpha=0.3)

    if efficiency:
        val = float(efficiency["value"])
        tgt = float(efficiency.get("target", 0.80))
        passed = efficiency.get("passed", val >= tgt)
        color = _PASS if passed else _FAIL
        axes[1].bar(["Resource Efficiency"], [val * 100], color=color, edgecolor="white")
        axes[1].axhline(tgt * 100, color=_TARGET, linestyle="--",
                        label=f"Target {tgt*100:.0f}%")
        axes[1].set_ylabel("Efficiency (%)")
        axes[1].set_title("High-Severity Allocation Efficiency")
        axes[1].legend()
        axes[1].grid(axis="y", alpha=0.3)

    fig.suptitle("Figure 5 — Resource Utilization", fontsize=12, y=1.02)
    fig.tight_layout()
    path = out / "fig5_resource_utilization.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


def export_charts(
    suites_run: list[tuple[str, ValidationSuite]],
    output_dir: Path | str | None = None,
) -> list[Path]:
    """
    Generate all validation charts. Returns paths of files written.
    """
    if output_dir is None:
        output_dir = Path(__file__).resolve().parent / "charts"
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    metrics = aggregate_metrics(suites_run)
    writers = (
        _fig1_per_agent_utility,
        _fig2_social_welfare,
        _fig3_defense_metrics,
        _fig4_attacker_utility,
        _fig5_resource_utilization,
    )
    paths: list[Path] = []
    for fn in writers:
        path = fn(metrics, out)
        if path is not None:
            paths.append(path)
    return paths


def print_chart_summary(paths: list[Path]) -> None:
    if not paths:
        print(f"\n  {YELLOW}No charts generated — run system/scenarios suites for full figures.{RESET}")
        return
    print(f"\n  {BOLD}Validation charts exported:{RESET}")
    for p in paths:
        print(f"    {GREEN}✓{RESET}  {p}")
