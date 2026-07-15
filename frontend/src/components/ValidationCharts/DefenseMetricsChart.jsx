import { useTheme } from "@mui/material/styles";
import { Bar, BarChart, CartesianGrid, Cell, LabelList, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import ChartTooltip from "./ChartTooltip";
import { FAIL, FONT_FAMILY, PASS, TARGET, chromeFromTheme, statusColor } from "./chartTheme";
import { ChartCard, ChartSub, ChartTitle, LegendItem, LegendLine, LegendRow } from "./ValidationCharts.styled";

// (key, label, lower_better, normalize(value, target) -> fraction of target, 1.0 = exactly at target)
const SPECS = [
  ["DR", "Detection Rate", false, (v, t) => (t ? v / t : v)],
  ["FPR", "False Positive Rate", true, (v, t) => (t ? v / t : v)],
  ["FPR_ACA", "ACA FPR", true, (v, t) => (t ? v / t : v)],
  ["FPR_TMA", "TMA FPR", true, (v, t) => (t ? v / t : v)],
  ["MTTR_ms", "MTTR Response (norm.)", true, (v, t) => (t ? v / t : v / 1000)],
  ["availability", "Availability", false, (v) => v],
  ["accuracy", "ACA Accuracy", false, (v) => v],
];

function DefenseMetricsChart({ metrics }) {
  const theme = useTheme();
  const c = chromeFromTheme(theme);
  const defense = metrics?.defense || {};

  const data = SPECS.filter(([key]) => defense[key]).map(([key, label, lowerBetter, norm]) => {
    const entry = defense[key];
    const val = entry.value;
    const tgt = entry.target ?? 1.0;
    const normalized = Math.min(norm(val, tgt), 1.5);
    const passed = lowerBetter ? val <= tgt : val >= tgt;
    return { key, label, normalized, passed, raw: val, target: tgt };
  });

  if (data.length === 0) return null;

  return (
    <ChartCard>
      <ChartTitle>DEFENSE PERFORMANCE METRICS</ChartTitle>
      <ChartSub>normalised so 1.0 = at target</ChartSub>
      <ResponsiveContainer width="100%" height={Math.max(180, 34 * data.length + 30)}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 40, left: 4, bottom: 4 }}>
          <CartesianGrid horizontal={false} stroke={c.grid} />
          <XAxis
            type="number"
            domain={[0, (max) => Math.max(Math.ceil(max * 11) / 10, 1.3)]}
            tickFormatter={(v) => v.toFixed(1)}
            tick={{ fontSize: 10, fontFamily: FONT_FAMILY, fill: c.axisText }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
          />
          <YAxis
            type="category"
            dataKey="label"
            width={130}
            tick={{ fontSize: 10.5, fontFamily: FONT_FAMILY, fill: c.labelText }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
          />
          <Tooltip
            cursor={{ fill: c.grid, opacity: 0.5 }}
            content={
              <ChartTooltip
                formatter={(_v, entry) => `${entry.payload.raw.toFixed(3)} (target ${entry.payload.target})`}
              />
            }
          />
          <ReferenceLine x={1.0} stroke={TARGET} strokeDasharray="4 3" strokeWidth={1.5} />
          <Bar dataKey="normalized" name="Observed" radius={[0, 4, 4, 0]} maxBarSize={18} isAnimationActive={false}>
            {data.map((d) => (
              <Cell key={d.key} fill={statusColor(d.passed)} />
            ))}
            <LabelList
              dataKey="raw"
              position="right"
              formatter={(v) => v.toFixed(2)}
              style={{ fontSize: 10, fontFamily: FONT_FAMILY, fill: c.labelText }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <LegendRow>
        <LegendItem swatchColor={PASS}>Passed</LegendItem>
        <LegendItem swatchColor={FAIL}>Failed</LegendItem>
        <LegendLine lineColor={TARGET}>Target (normalised = 1.0)</LegendLine>
      </LegendRow>
    </ChartCard>
  );
}

export default DefenseMetricsChart;
