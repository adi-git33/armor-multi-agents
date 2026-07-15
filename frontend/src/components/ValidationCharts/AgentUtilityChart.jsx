import { useTheme } from "@mui/material/styles";
import { Bar, BarChart, CartesianGrid, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import ChartTooltip from "./ChartTooltip";
import { FAIL, FONT_FAMILY, PASS, chromeFromTheme, statusColor } from "./chartTheme";
import { ChartCard, ChartTitle, LegendItem, LegendRow } from "./ValidationCharts.styled";

const ORDER = ["TMA", "ACA", "RCA", "RAA", "TIA"];

function AgentUtilityChart({ metrics }) {
  const theme = useTheme();
  const c = chromeFromTheme(theme);
  const agents = metrics?.agent_utilities || {};

  const data = ORDER.filter((name) => agents[name]).map((name) => ({
    name,
    value: agents[name].value,
    passed: agents[name].passed !== false,
  }));

  if (data.length === 0) return null;

  return (
    <ChartCard>
      <ChartTitle>PER-AGENT UTILITY</ChartTitle>
      <ResponsiveContainer width="100%" height={36 * data.length + 30}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 34, left: 4, bottom: 4 }}>
          <CartesianGrid horizontal={false} stroke={c.grid} />
          <XAxis
            type="number"
            tickFormatter={(v) => v.toFixed(2)}
            tick={{ fontSize: 10, fontFamily: FONT_FAMILY, fill: c.axisText }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
          />
          <YAxis
            type="category"
            dataKey="name"
            width={38}
            tick={{ fontSize: 11, fontFamily: FONT_FAMILY, fill: c.labelText, fontWeight: 600 }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
          />
          <Tooltip
            cursor={{ fill: c.grid, opacity: 0.5 }}
            content={<ChartTooltip formatter={(v) => v.toFixed(3)} />}
          />
          <Bar dataKey="value" name="Utility" radius={[0, 4, 4, 0]} maxBarSize={20} isAnimationActive={false}>
            {data.map((d) => (
              <Cell key={d.name} fill={statusColor(d.passed)} />
            ))}
            <LabelList
              dataKey="value"
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
      </LegendRow>
    </ChartCard>
  );
}

export default AgentUtilityChart;
