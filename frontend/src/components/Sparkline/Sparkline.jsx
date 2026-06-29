import { useMemo } from "react";
import { buildAreaPath, buildLinePath, healthColor } from "../../dashboard/utils";
import { StyledSvg } from "./Sparkline.styled";

function Sparkline({ hist, baseline, health, width = 320, height = 46 }) {
  const peak = useMemo(() => {
    const max = Math.max(...(hist || [baseline * 2]), baseline * 2);
    return max * 1.1;
  }, [hist, baseline]);

  const baseY = useMemo(() => height - (baseline / peak) * (height - 4), [baseline, peak, height]);
  const lineColor = healthColor(health);
  const areaFill =
    health === "NORMAL"
      ? "rgba(74,158,127,.12)"
      : health === "ANOMALY"
        ? "rgba(217,162,63,.15)"
        : health === "THREAT"
          ? "rgba(207,107,94,.15)"
          : "rgba(139,92,246,.15)";

  const linePath = buildLinePath(hist, width, height, peak);
  const areaPath = buildAreaPath(hist, width, height, peak);

  return (
    <StyledSvg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" width="100%" height={height}>
      <line x1="0" y1={baseY} x2={width} y2={baseY} stroke="#d6dce2" strokeWidth="1" strokeDasharray="3 4" />
      <path d={areaPath} fill={areaFill} stroke="none" />
      <path d={linePath} fill="none" stroke={lineColor} strokeWidth="1.6" />
    </StyledSvg>
  );
}

export default Sparkline;
