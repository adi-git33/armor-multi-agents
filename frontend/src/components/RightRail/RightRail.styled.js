import { Box, Paper, Typography } from "@mui/material";
import { styled } from "@mui/material/styles";

export const RailWrap = styled(Box)({
  flex: 1,
  height: "100%",
  minWidth: 0,
  minHeight: 0,
  display: "flex",
  flexDirection: "column",
  gap: "12px",
});

export const Panel = styled(Paper)(({ theme }) => ({
  flex: 1,
  minHeight: 0,
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: "11px",
  display: "flex",
  flexDirection: "column",
  overflowY: "auto",
}));

export const LogPanel = styled(Paper)(({ theme }) => ({
  flex: 1,
  minHeight: 0,
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: "11px",
  display: "flex",
  flexDirection: "column",
  overflow: "hidden",
}));

export const PanelHeader = styled(Box)(({ theme }) => ({
  height: 34,
  padding: "0 14px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  borderBottom: `1px solid ${theme.customDashboard.panelBorderLight}`,
}));

export const HeaderTitle = styled(Typography)(({ theme }) => ({
  fontSize: 10,
  fontWeight: 600,
  letterSpacing: ".14em",
  color: theme.customDashboard.textSecondary,
}));

export const HeaderMeta = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  letterSpacing: ".06em",
  color: theme.customDashboard.textSoft,
}));

export const EventCount = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  color: theme.customDashboard.textMuted,
}));

export const SegmentRow = styled(Box, {
  shouldForwardProp: (prop) => prop !== "active",
})(({ theme, active }) => ({
  padding: "11px 14px",
  borderTop: `1px solid ${theme.customDashboard.panelBorderSoft}`,
  cursor: "pointer",
  backgroundColor: active ? theme.customDashboard.panelHoverSurface : "transparent",
}));

export const SegmentMetaRow = styled(Box)({
  display: "flex",
  alignItems: "baseline",
  justifyContent: "space-between",
  marginBottom: "5px",
});

export const SegmentLabel = styled(Typography)(({ theme }) => ({
  fontSize: 10,
  fontWeight: 600,
  color: theme.customDashboard.textSecondary,
}));

export const SegmentName = styled("span")(({ theme }) => ({
  color: theme.customDashboard.textFaint,
  fontWeight: 400,
}));

export const SegmentValues = styled(Box)({
  display: "flex",
  alignItems: "baseline",
  gap: "7px",
});

export const SegmentPps = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "valuecolor",
})(({ valuecolor }) => ({
  fontSize: 13,
  fontWeight: 600,
  color: valuecolor,
}));

export const AttackPps = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "textcolor",
})(({ theme, textcolor }) => ({
  fontSize: 9,
  fontWeight: 500,
  color: textcolor || theme.palette.error.main,
}));

export const LogList = styled(Box)({
  flex: 1,
  minHeight: 0,
  overflowY: "auto",
});

export const EmptyLogs = styled(Typography)(({ theme }) => ({
  padding: "20px 14px",
  fontSize: 9,
  color: theme.customDashboard.textFaint,
  textAlign: "center",
}));

export const LogItem = styled(Box)(({ theme }) => ({
  padding: "9px 14px",
  borderTop: `1px solid ${theme.customDashboard.panelBorderSoft}`,
  display: "flex",
  gap: "9px",
}));

export const LogDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 6,
  height: 6,
  borderRadius: "50%",
  backgroundColor: dotcolor,
  marginTop: "5px",
  flexShrink: 0,
}));

export const LogTextWrap = styled(Box)({
  minWidth: 0,
  flex: 1,
});

export const LogText = styled(Typography)(({ theme }) => ({
  fontSize: 10,
  lineHeight: 1.4,
  color: theme.customDashboard.textBody,
}));

export const LogHeaderRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  gap: "6px",
  marginBottom: "2px",
});

export const PerfTag = styled("span", {
  shouldForwardProp: (prop) => prop !== "tagcolor",
})(({ theme, tagcolor }) => ({
  fontSize: 8,
  fontWeight: 700,
  letterSpacing: ".04em",
  color: tagcolor,
  border: `1px solid ${tagcolor}`,
  borderRadius: "3px",
  padding: "1px 4px",
  lineHeight: 1.5,
  whiteSpace: "nowrap",
  opacity: 0.9,
}));

export const FilterRow = styled(Box)(({ theme }) => ({
  display: "flex",
  gap: "4px",
  padding: "6px 14px",
  borderBottom: `1px solid ${theme.customDashboard.panelBorderLight}`,
  flexWrap: "wrap",
}));

export const FilterChip = styled("button", {
  shouldForwardProp: (prop) => prop !== "active",
})(({ theme, active }) => ({
  fontSize: 8,
  fontWeight: 600,
  letterSpacing: ".03em",
  padding: "2px 7px",
  borderRadius: "9px",
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  background: active ? theme.customDashboard.panelHoverSurface : "transparent",
  color: active ? theme.customDashboard.textBody : theme.customDashboard.textFaint,
  cursor: "pointer",
}));

export const LogMeta = styled(Typography)(({ theme }) => ({
  fontSize: 8,
  letterSpacing: ".03em",
  color: theme.customDashboard.textFaint,
}));
