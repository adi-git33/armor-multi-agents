import { useTheme } from "@mui/material/styles";
import { Bar, BarChart, CartesianGrid, Cell, LabelList, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import ChartTooltip from "./ChartTooltip";
import { FAIL, FONT_FAMILY, PASS, TARGET, chromeFromTheme, fmtValue } from "./chartTheme";
import { ChartCardWide, ChartSub, ChartTitle, LegendItem, LegendRow, MicroPanel, MicroPanelTitle, PanelsGrid2x3 } from "./ValidationCharts.styled";

function DegradationPanel({ panel, c }) {
  const { title, std, stress, target, higher_better: higherBetter, y_max: yMax, fmt, tgt_annotation: tgtAnnotation } = panel;
  const floor = fmt === "yn" ? 0.04 * yMax : 0;
  const rows = [
    { name: "Baseline", raw: std, plot: Math.max(std, floor) },
    { name: "High Stress", raw: stress, plot: Math.max(stress, floor) },
  ].map((r) => ({ ...r, passed: higherBetter ? r.raw >= target : r.raw <= target }));

  return (
    <MicroPanel>
      <MicroPanelTitle>{title}</MicroPanelTitle>
      <ResponsiveContainer width="100%" height={150}>
        <BarChart data={rows} margin={{ top: 16, right: 8, left: 0, bottom: 4 }}>
          <CartesianGrid vertical={false} stroke={c.grid} />
          <XAxis
            dataKey="name"
            tick={{ fontSize: 9.5, fontFamily: FONT_FAMILY, fill: c.axisText }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
          />
          <YAxis
            domain={[0, yMax]}
            tickFormatter={(v) => (Number.isInteger(v) ? v.toLocaleString() : v.toFixed(2))}
            tick={{ fontSize: 9, fontFamily: FONT_FAMILY, fill: c.axisText }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
            width={44}
          />
          <Tooltip cursor={{ fill: c.grid, opacity: 0.5 }} content={<ChartTooltip formatter={(_v, entry) => fmtValue(entry.payload.raw, fmt)} />} />
          <ReferenceLine
            y={target}
            stroke={TARGET}
            strokeDasharray="4 3"
            strokeWidth={1.3}
            label={{ value: tgtAnnotation, position: "insideTopRight", fontSize: 8.5, fill: TARGET, fontFamily: FONT_FAMILY }}
          />
          <Bar dataKey="plot" name={title} radius={[3, 3, 0, 0]} maxBarSize={38} isAnimationActive={false}>
            {rows.map((r) => (
              <Cell key={r.name} fill={r.passed ? PASS : FAIL} />
            ))}
            <LabelList dataKey="raw" position="top" formatter={(v) => fmtValue(v, fmt)} style={{ fontSize: 9, fontFamily: FONT_FAMILY, fill: c.labelText }} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </MicroPanel>
  );
}

function DegradationAnalysisChart({ metrics }) {
  const theme = useTheme();
  const c = chromeFromTheme(theme);
  const panels = metrics?.degradation || [];

  if (panels.length === 0) return null;

  return (
    <ChartCardWide>
      <ChartTitle>DEGRADATION ANALYSIS — BASELINE VS. HIGH-STRESS LOAD</ChartTitle>
      <ChartSub>fixed illustrative comparison, not tied to whichever suites just ran — §5.2</ChartSub>
      <PanelsGrid2x3>
        {panels.map((p) => (
          <DegradationPanel key={p.title} panel={p} c={c} />
        ))}
      </PanelsGrid2x3>
      <LegendRow>
        <LegendItem swatchColor={PASS}>Within target</LegendItem>
        <LegendItem swatchColor={FAIL}>Outside target</LegendItem>
      </LegendRow>
    </ChartCardWide>
  );
}

export default DegradationAnalysisChart;
