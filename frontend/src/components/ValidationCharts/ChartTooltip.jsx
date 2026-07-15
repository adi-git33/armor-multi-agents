import { TooltipBox, TooltipKey, TooltipRow, TooltipTitle, TooltipValue } from "./ValidationCharts.styled";

// Shared Recharts tooltip content — "values lead, labels follow": the
// number is the strong element, the series name is secondary, keyed by a
// short line stroke (not a filled swatch) per the dataviz interaction spec.
function ChartTooltip({ active, payload, label, formatter }) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <TooltipBox>
      {label != null && <TooltipTitle>{label}</TooltipTitle>}
      {payload.map((entry, i) => (
        <TooltipRow key={`${entry.dataKey}-${i}`}>
          <TooltipKey swatchColor={entry.color}>{entry.name}</TooltipKey>
          <TooltipValue>
            {formatter ? formatter(entry.value, entry) : entry.value}
          </TooltipValue>
        </TooltipRow>
      ))}
    </TooltipBox>
  );
}

export default ChartTooltip;
