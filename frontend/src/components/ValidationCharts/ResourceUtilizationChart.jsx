import { useTheme } from "@mui/material/styles";
import { Bar, BarChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import ChartTooltip from "./ChartTooltip";
import { FONT_FAMILY, TARGET, chromeFromTheme, statusColor } from "./chartTheme";
import { ChartCard, ChartTitle, MicroPanel, MicroPanelTitle, PanelsGrid2x3 } from "./ValidationCharts.styled";

function MiniGauge({ label, valuePct, capPct, capLabel, passed, c }) {
  const data = [{ name: label, value: valuePct }];
  return (
    <MicroPanel>
      <MicroPanelTitle>{label}</MicroPanelTitle>
      <ResponsiveContainer width="100%" height={90}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 30, left: 4, bottom: 4 }}>
          <CartesianGrid horizontal={false} stroke={c.grid} />
          <XAxis
            type="number"
            domain={[0, (max) => Math.ceil((Math.max(max, capPct) * 1.2) / 5) * 5]}
            tickFormatter={(v) => `${Math.round(v)}`}
            tick={{ fontSize: 9, fontFamily: FONT_FAMILY, fill: c.axisText }}
            axisLine={{ stroke: c.axisLine }}
            tickLine={false}
            unit="%"
          />
          <YAxis type="category" dataKey="name" width={0} tick={false} axisLine={false} tickLine={false} />
          <Tooltip cursor={{ fill: c.grid, opacity: 0.5 }} content={<ChartTooltip formatter={(v) => `${v.toFixed(1)}%`} />} />
          <ReferenceLine x={capPct} stroke={TARGET} strokeDasharray="4 3" strokeWidth={1.5} label={{ value: capLabel, position: "top", fontSize: 9, fill: TARGET, fontFamily: FONT_FAMILY }} />
          <Bar dataKey="value" name={label} fill={statusColor(passed)} radius={[0, 4, 4, 0]} maxBarSize={22} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </MicroPanel>
  );
}

function ResourceUtilizationChart({ metrics }) {
  const theme = useTheme();
  const c = chromeFromTheme(theme);
  const resource = metrics?.resource || {};
  const overhead = resource.overhead;
  // The system suite reports a structured {value,target,passed} dict under
  // "efficiency"; the S3 scenario only has the raw fraction under
  // "efficiency_s3" (no target of its own — reuse the same 80% target the
  // system suite uses for the same metric).
  const efficiency = resource.efficiency
    ?? (resource.efficiency_s3 != null
      ? { value: resource.efficiency_s3, target: 0.8, passed: resource.efficiency_s3 >= 0.8 }
      : null);

  if (!overhead && !efficiency) return null;

  return (
    <ChartCard>
      <ChartTitle>RESOURCE UTILIZATION</ChartTitle>
      <PanelsGrid2x3>
        {overhead && (
          <MiniGauge
            label="MAS Overhead"
            valuePct={overhead.value * 100}
            capPct={(overhead.target ?? 0.4) * 100}
            capLabel={`Cap ${((overhead.target ?? 0.4) * 100).toFixed(0)}%`}
            passed={overhead.passed !== false}
            c={c}
          />
        )}
        {efficiency && (
          <MiniGauge
            label="High-Severity Allocation Efficiency"
            valuePct={efficiency.value * 100}
            capPct={(efficiency.target ?? 0.8) * 100}
            capLabel={`Target ${((efficiency.target ?? 0.8) * 100).toFixed(0)}%`}
            passed={efficiency.passed !== false}
            c={c}
          />
        )}
      </PanelsGrid2x3>
    </ChartCard>
  );
}

export default ResourceUtilizationChart;
