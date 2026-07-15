import AgentUtilityChart from "./AgentUtilityChart";
import AttackerUtilityChart from "./AttackerUtilityChart";
import DefenseMetricsChart from "./DefenseMetricsChart";
import DegradationAnalysisChart from "./DegradationAnalysisChart";
import ResourceUtilizationChart from "./ResourceUtilizationChart";
import SocialWelfareChart from "./SocialWelfareChart";
import { ChartsGrid } from "./ValidationCharts.styled";

// Each chart component returns null when its slice of `metrics` is empty
// (e.g. only S1 ran, so there's no "defense" data) — same graceful
// degradation the old per-figure PNG export had, just without ever
// generating an image.
function ValidationCharts({ metrics }) {
  if (!metrics) return null;

  return (
    <ChartsGrid>
      <AgentUtilityChart metrics={metrics} />
      <SocialWelfareChart metrics={metrics} />
      <AttackerUtilityChart metrics={metrics} />
      <DefenseMetricsChart metrics={metrics} />
      <ResourceUtilizationChart metrics={metrics} />
      <DegradationAnalysisChart metrics={metrics} />
    </ChartsGrid>
  );
}

export default ValidationCharts;
