// Static metadata for the Validation page. Suite id/label/title come from
// the backend (/api/validation/suites, sourced from SUITES in
// run_validation.py) — this file only holds pure-frontend display info
// that has no backend equivalent: chart captions/grouping and the
// SRS §7.3 table's column order (the rows themselves are server-built).

export const CHART_INFO = {
  fig1_per_agent_utility: {
    title: "Per-Agent Utility",
    group: "System / Agent Utility",
  },
  fig2_social_welfare: {
    title: "Social Welfare by Validation Stage",
    group: "System / Agent Utility",
  },
  fig3_defense_metrics: {
    title: "Defense Performance Metrics",
    group: "Defense Metrics",
  },
  fig4_attacker_utility: {
    title: "Attacker Evasion Rate vs. Target",
    group: "Attacker Utility",
  },
  fig5_resource_utilization: {
    title: "Resource Utilization",
    group: "Resource Utilization",
  },
  fig6_degradation_analysis: {
    title: "Degradation Analysis — Baseline vs. High-Stress",
    group: "Degradation Analysis",
  },
};

export function chartInfoFor(path) {
  const base = path.split("/").pop().replace(/\.png$/, "");
  return CHART_INFO[base] || { title: base, group: "Charts" };
}
