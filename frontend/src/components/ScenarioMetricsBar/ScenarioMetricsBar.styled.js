import { Box, Button, Paper, Typography } from "@mui/material";
import { styled } from "@mui/material/styles";

export const MetricsBarWrap = styled(Box)(({ theme }) => ({
  display: "grid",
  gridTemplateColumns: "auto minmax(0, 1fr)",
  gap: "12px",
  padding: "12px 16px",
  [theme.breakpoints.down("lg")]: {
    gridTemplateColumns: "1fr",
  },
  [theme.breakpoints.down("sm")]: {
    padding: "10px 10px",
    gap: "10px",
  },
}));

export const ScenarioPanel = styled(Paper)(({ theme }) => ({
  padding: "10px 14px",
  borderRadius: "9px",
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  display: "flex",
  alignItems: "center",
  gap: "10px",
  flexWrap: "wrap",
}));

export const ScenarioLabel = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  letterSpacing: ".14em",
  color: theme.customDashboard.textMuted,
}));

export const ScenarioButton = styled(Button, {
  shouldForwardProp: (prop) => prop !== "active",
})(({ theme, active }) => ({
  textTransform: "none",
  minWidth: "unset",
  fontSize: 11,
  fontWeight: 500,
  letterSpacing: ".02em",
  padding: "5px 12px",
  borderRadius: "6px",
  backgroundColor: active ? theme.palette.primary.main : theme.customDashboard.panelMutedSurface,
  color: active ? theme.palette.primary.contrastText : theme.customDashboard.textSecondary,
  border: `1px solid ${active ? theme.palette.primary.main : theme.customDashboard.panelBorder}`,
  "&:hover": {
    backgroundColor: active ? theme.customDashboard.communicationHover : theme.customDashboard.panelMutedSurfaceHover,
  },
}));

export const Clock = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "paused",
})(({ theme, paused }) => ({
  marginLeft: "12px",
  fontSize: 14,
  fontWeight: 500,
  color: paused ? "#d9a23f" : theme.customDashboard.textMuted,
  minWidth: 56,
}));

export const ControlButton = styled(Button)(({ theme }) => ({
  textTransform: "none",
  minWidth: 34,
  width: 34,
  height: 28,
  padding: 0,
  fontSize: 13,
  lineHeight: 1,
  borderRadius: "6px",
  backgroundColor: theme.customDashboard.panelMutedSurface,
  color: theme.customDashboard.textSecondary,
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  "&:hover": {
    backgroundColor: theme.customDashboard.panelMutedSurfaceHover,
  },
}));

export const MetricsPanel = styled(Paper)(({ theme }) => ({
  flex: 1,
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: "9px",
  display: "flex",
  alignItems: "stretch",
  [theme.breakpoints.down("sm")]: {
    display: "grid",
    gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
  },
}));

export const MetricCell = styled(Box, {
  shouldForwardProp: (prop) => prop !== "showleftborder",
})(({ theme, showleftborder }) => ({
  flex: 1,
  padding: "9px 16px",
  display: "flex",
  flexDirection: "column",
  justifyContent: "center",
  borderLeft: showleftborder ? `1px solid ${theme.customDashboard.panelBorderLight}` : "none",
}));

export const MetricLabel = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  letterSpacing: ".1em",
  color: theme.customDashboard.textMuted,
}));

export const MetricValue = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "valuecolor",
})(({ valuecolor }) => ({
  fontSize: 20,
  fontWeight: 600,
  color: valuecolor,
  lineHeight: 1,
}));
