import { Tooltip } from "@mui/material";
import { C, SCENARIOS } from "../../dashboard/constants";
import { fmt } from "../../dashboard/utils";
import {
  Clock,
  MetricCell,
  MetricLabel,
  MetricsBarWrap,
  MetricsPanel,
  MetricValue,
  ScenarioButton,
  ScenarioLabel,
  ScenarioPanel,
} from "./ScenarioMetricsBar.styled";

function ScenarioMetricsBar({ scenario, elapsed, metrics, wsReady, sendScenario, selectedSeg }) {
  const metricRows = [
    {
      label: "DETECTION RATE",
      value: `${(metrics.dr * 100).toFixed(1)} %`,
      color: metrics.dr > 0.9 ? C.green : metrics.dr > 0.7 ? C.amber : C.red,
      info: "Real attacks correctly caught, out of every real attack that happened (missed attacks count against this too).",
    },
    {
      label: "FALSE POSITIVE",
      value: `${(metrics.fpr * 100).toFixed(1)} %`,
      color: metrics.fpr < 0.08 ? C.green : C.amber,
      info: "Genuinely calm moments that ACA wrongly flagged as a threat, out of all genuinely calm moments.",
    },
    {
      label: "MTTR",
      value: metrics.mttr > 0 ? `${metrics.mttr} ms` : "— ms",
      color: metrics.mttr > 0 && metrics.mttr < 1000 ? C.green : metrics.mttr > 1000 ? C.red : "#9aa4b0",
      info: "Mean time from RCA opening an incident to it being resolved (executed or rejected), averaged over the last 100 resolutions.",
    },
    {
      label: "AVAILABILITY",
      value: `${(metrics.availability * 100).toFixed(2)} %`,
      color: metrics.availability > 0.99 ? C.green : C.amber,
      info: "1 minus the fraction of elapsed time spent with a segment quarantined.",
    },
    {
      label: "SOCIAL WELFARE",
      value: metrics.sw > 0 ? metrics.sw.toFixed(3) : "—",
      color: metrics.sw >= 0.8 ? C.green : metrics.sw >= 0.5 ? C.amber : "#9aa4b0",
      info: "Weighted sum of per-agent utility (TMA 20% / ACA 30% / RCA 25% / TIA 15% / RAA 10%), same weights used in the offline validation suite.",
    },
  ];

  return (
    <MetricsBarWrap>
      <ScenarioPanel>
        <ScenarioLabel>SCENARIO</ScenarioLabel>
        {SCENARIOS.map((sc) => {
          const active = scenario === sc.id;
          return (
            <ScenarioButton
              key={sc.id}
              onClick={() => sendScenario(sc.id, selectedSeg)}
              disabled={!wsReady}
              size="small"
              active={active ? 1 : 0}
            >
              {sc.label}
            </ScenarioButton>
          );
        })}
        <Clock>{fmt(elapsed)}</Clock>
      </ScenarioPanel>

      <MetricsPanel>
        {metricRows.map((m, i) => (
          <MetricCell key={m.label} showleftborder={i > 0 ? 1 : 0}>
            <Tooltip title={m.info} arrow placement="top">
              <MetricLabel>{m.label}</MetricLabel>
            </Tooltip>
            <MetricValue valuecolor={m.color}>{m.value}</MetricValue>
          </MetricCell>
        ))}
      </MetricsPanel>
    </MetricsBarWrap>
  );
}

export default ScenarioMetricsBar;
