import { useTheme } from "@mui/material/styles";
import { Bar, BarChart, CartesianGrid, Cell, LabelList, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import ChartTooltip from "./ChartTooltip";
import { FAIL, FONT_FAMILY, PASS, TARGET, chromeFromTheme, statusColor } from "./chartTheme";
import { ChartCard, ChartTitle, LegendItem, LegendLine, LegendRow } from "./ValidationCharts.styled";

const ORDER = ["System", "S1", "S2", "S3", "S4", "S5", "S6"];
const MIN_SW = 0.8;

function SocialWelfareChart({ metrics }) {
  const theme = useTheme();
  const c = chromeFromTheme(theme);
  const sw = metrics?.social_welfare || {};

  const data = ORDER.filter((k) => sw[k]).map((k) => ({
    stage: k,
    value: sw[k].value,
    passed: sw[k].passed !== false,
  }));

  if (data.length === 0) return null;

  return (
    <ChartCard>
      <ChartTitle>SOCIAL WELFARE BY VALIDATION STAGE</ChartTitle>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 4 }}>
          <CartesianGrid vertical={false} stroke={c.grid} />
          <XAxis
            dataKey="stage"
            tick={{ fontSize: 10, fontFamily: FONT_FAMILY, fill: c.axisText }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
          />
          <YAxis
            domain={[0, (max) => Math.max(Math.ceil(max * 11) / 10, 0.9)]}
            tickFormatter={(v) => v.toFixed(1)}
            tick={{ fontSize: 10, fontFamily: FONT_FAMILY, fill: c.axisText }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
            width={34}
          />
          <Tooltip cursor={{ fill: c.grid, opacity: 0.5 }} content={<ChartTooltip formatter={(v) => v.toFixed(3)} />} />
          <ReferenceLine y={MIN_SW} stroke={TARGET} strokeDasharray="4 3" strokeWidth={1.5} />
          <Bar dataKey="value" name="SW" radius={[4, 4, 0, 0]} maxBarSize={26} isAnimationActive={false}>
            {data.map((d) => (
              <Cell key={d.stage} fill={statusColor(d.passed)} />
            ))}
            <LabelList
              dataKey="value"
              position="top"
              formatter={(v) => v.toFixed(2)}
              style={{ fontSize: 10, fontFamily: FONT_FAMILY, fill: c.labelText }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <LegendRow>
        <LegendItem swatchColor={PASS}>Passed</LegendItem>
        <LegendItem swatchColor={FAIL}>Failed</LegendItem>
        <LegendLine lineColor={TARGET}>Target ≥ {MIN_SW.toFixed(2)}</LegendLine>
      </LegendRow>
    </ChartCard>
  );
}

export default SocialWelfareChart;
