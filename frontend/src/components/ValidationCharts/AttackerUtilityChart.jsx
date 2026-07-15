import { useTheme } from "@mui/material/styles";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import ChartTooltip from "./ChartTooltip";
import { FAIL, FONT_FAMILY, PASS, TARGET, chromeFromTheme, statusColor } from "./chartTheme";
import { ChartCard, ChartTitle, LegendItem, LegendRow } from "./ValidationCharts.styled";

const ORDER = ["S1", "S2", "S3", "S4", "S5", "S6"];

function AttackerUtilityChart({ metrics }) {
  const theme = useTheme();
  const c = chromeFromTheme(theme);
  const atk = metrics?.attacker_utility || {};

  const data = ORDER.filter((k) => atk[k]).map((k) => ({
    scenario: k,
    label: atk[k].label || k,
    observed: atk[k].value,
    target: atk[k].target ?? 0.5,
    passed: atk[k].passed !== false,
  }));

  if (data.length === 0) return null;

  return (
    <ChartCard>
      <ChartTitle>ATTACKER EVASION RATE VS. TARGET</ChartTitle>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 4 }} barGap={2}>
          <CartesianGrid vertical={false} stroke={c.grid} />
          <XAxis
            dataKey="scenario"
            tick={{ fontSize: 10, fontFamily: FONT_FAMILY, fill: c.axisText }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
          />
          <YAxis
            domain={[0, 1]}
            tick={{ fontSize: 10, fontFamily: FONT_FAMILY, fill: c.axisText }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
            width={30}
          />
          <Tooltip
            cursor={{ fill: c.grid, opacity: 0.5 }}
            content={<ChartTooltip formatter={(v) => v.toFixed(2)} />}
          />
          <Bar dataKey="observed" name="Observed evasion" radius={[3, 3, 0, 0]} maxBarSize={20} isAnimationActive={false}>
            {data.map((d) => (
              <Cell key={d.scenario} fill={statusColor(d.passed)} />
            ))}
          </Bar>
          <Bar dataKey="target" name="Target (max tolerated)" fill={TARGET} fillOpacity={0.35} radius={[3, 3, 0, 0]} maxBarSize={20} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
      <LegendRow>
        <LegendItem swatchColor={PASS}>Under target</LegendItem>
        <LegendItem swatchColor={FAIL}>Over target</LegendItem>
        <LegendItem swatchColor={TARGET}>Target (max tolerated)</LegendItem>
      </LegendRow>
    </ChartCard>
  );
}

export default AttackerUtilityChart;
