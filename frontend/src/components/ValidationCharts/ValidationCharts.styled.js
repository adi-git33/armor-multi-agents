import { Box, Typography } from "@mui/material";
import { styled } from "@mui/material/styles";

export const ChartsGrid = styled(Box)({
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))",
  gap: "14px",
});

export const ChartCard = styled(Box)(({ theme }) => ({
  border: `1px solid ${theme.customDashboard.panelBorderLight}`,
  borderRadius: "8px",
  backgroundColor: theme.customDashboard.panelSubtleSurface,
  padding: "12px 14px 10px",
  display: "flex",
  flexDirection: "column",
  gap: "6px",
  minWidth: 0,
}));

export const ChartCardWide = styled(ChartCard)({
  gridColumn: "1 / -1",
});

export const ChartTitle = styled(Typography)(({ theme }) => ({
  fontSize: 12,
  fontWeight: 700,
  letterSpacing: ".04em",
  color: theme.customDashboard.textSecondary,
}));

export const ChartSub = styled(Typography)(({ theme }) => ({
  fontSize: 11,
  color: theme.customDashboard.textMuted,
  marginTop: "-4px",
}));

export const LegendRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  flexWrap: "wrap",
  gap: "12px",
  marginTop: "2px",
});

export const LegendItem = styled(Box, {
  shouldForwardProp: (prop) => prop !== "swatchColor",
})(({ theme, swatchColor }) => ({
  display: "inline-flex",
  alignItems: "center",
  gap: "5px",
  fontSize: 10,
  letterSpacing: ".03em",
  color: theme.customDashboard.textMuted,
  "&::before": {
    content: '""',
    width: 9,
    height: 9,
    borderRadius: "2px",
    backgroundColor: swatchColor,
    flexShrink: 0,
  },
}));

export const LegendLine = styled(Box, {
  shouldForwardProp: (prop) => prop !== "lineColor",
})(({ theme, lineColor }) => ({
  display: "inline-flex",
  alignItems: "center",
  gap: "5px",
  fontSize: 10,
  letterSpacing: ".03em",
  color: theme.customDashboard.textMuted,
  "&::before": {
    content: '""',
    width: 12,
    height: 0,
    borderTop: `2px dashed ${lineColor}`,
    flexShrink: 0,
  },
}));

export const TooltipBox = styled(Box)(({ theme }) => ({
  backgroundColor: theme.customDashboard.panelBackground,
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: "6px",
  padding: "7px 10px",
  boxShadow: theme.customDashboard.shadowSoft,
  fontSize: 12,
  minWidth: 120,
}));

export const TooltipTitle = styled(Typography)(({ theme }) => ({
  fontSize: 11,
  fontWeight: 700,
  color: theme.customDashboard.textSecondary,
  marginBottom: "3px",
}));

export const TooltipRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "10px",
});

export const TooltipKey = styled(Box, {
  shouldForwardProp: (prop) => prop !== "swatchColor",
})(({ theme, swatchColor }) => ({
  display: "inline-flex",
  alignItems: "center",
  gap: "5px",
  fontSize: 11,
  color: theme.customDashboard.textMuted,
  "&::before": {
    content: '""',
    width: 8,
    height: 2,
    backgroundColor: swatchColor,
    flexShrink: 0,
  },
}));

export const TooltipValue = styled(Typography)(({ theme }) => ({
  fontSize: 12,
  fontWeight: 700,
  color: theme.customDashboard.textPrimary,
}));

export const PanelsGrid2x3 = styled(Box)({
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
  gap: "10px",
});

export const MicroPanel = styled(Box)(({ theme }) => ({
  border: `1px solid ${theme.customDashboard.panelBorderLight}`,
  borderRadius: "7px",
  backgroundColor: theme.customDashboard.panelBackground,
  padding: "8px 10px 4px",
}));

export const MicroPanelTitle = styled(Typography)(({ theme }) => ({
  fontSize: 10.5,
  fontWeight: 700,
  color: theme.customDashboard.textSecondary,
  marginBottom: "2px",
}));
