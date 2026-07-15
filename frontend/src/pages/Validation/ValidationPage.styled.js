import { Box, Paper, Typography } from "@mui/material";
import { styled } from "@mui/material/styles";

export const PageWrap = styled(Box)(({ theme }) => ({
  padding: "16px",
  display: "flex",
  flexDirection: "column",
  gap: "12px",
  minHeight: "100%",
  backgroundColor: theme.customDashboard.appBackground,
}));

// ── control bar ─────────────────────────────────────────────────────
export const ControlBar = styled(Paper)(({ theme }) => ({
  padding: "12px 14px",
  borderRadius: "9px",
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  display: "flex",
  alignItems: "center",
  gap: "10px",
  flexWrap: "wrap",
}));

export const ControlLabel = styled(Typography)(({ theme }) => ({
  fontSize: 12,
  letterSpacing: ".14em",
  color: theme.customDashboard.textMuted,
  marginRight: "2px",
}));

export const SuiteButton = styled("button", {
  shouldForwardProp: (prop) => !["active", "toneColor"].includes(prop),
})(({ theme, active, toneColor }) => ({
  fontFamily: "inherit",
  textAlign: "left",
  minWidth: "unset",
  fontSize: 16,
  fontWeight: 600,
  letterSpacing: ".02em",
  padding: "6px 12px",
  borderRadius: "6px",
  cursor: "pointer",
  display: "flex",
  alignItems: "center",
  gap: "7px",
  backgroundColor: active ? theme.palette.primary.main : theme.customDashboard.panelMutedSurface,
  color: active ? theme.palette.primary.contrastText : theme.customDashboard.textSecondary,
  border: `1px solid ${active ? theme.palette.primary.main : theme.customDashboard.panelBorder}`,
  transition: "background-color .15s, opacity .15s",
  "&:hover:not(:disabled)": {
    backgroundColor: active ? theme.customDashboard.communicationHover : theme.customDashboard.panelMutedSurfaceHover,
  },
  "&:disabled": {
    cursor: "default",
    opacity: active ? 1 : 0.55,
  },
  "&::before": toneColor
    ? {
        content: '""',
        width: 6,
        height: 6,
        borderRadius: "50%",
        backgroundColor: toneColor,
        flexShrink: 0,
      }
    : undefined,
}));

export const RunAllButton = styled("button")(({ theme, disabled }) => ({
  fontFamily: "inherit",
  fontSize: 16,
  fontWeight: 700,
  letterSpacing: ".06em",
  padding: "7px 18px",
  borderRadius: "7px",
  border: "none",
  cursor: disabled ? "default" : "pointer",
  backgroundColor: theme.palette.primary.main,
  color: theme.palette.primary.contrastText,
  opacity: disabled ? 0.5 : 1,
  marginLeft: "auto",
  "&:hover:not(:disabled)": {
    backgroundColor: theme.customDashboard.communicationHover,
  },
}));

export const ConnDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 7,
  height: 7,
  borderRadius: "50%",
  backgroundColor: dotcolor,
}));

export const ConnRow = styled(Box)(({ theme }) => ({
  display: "flex",
  alignItems: "center",
  gap: "6px",
  fontSize: 12,
  letterSpacing: ".05em",
  color: theme.customDashboard.textMuted,
}));

// ── live progress panel ─────────────────────────────────────────────
export const ProgressPanel = styled(Paper)(({ theme }) => ({
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: "9px",
  overflow: "hidden",
}));

export const ProgressHeader = styled(Box)(({ theme }) => ({
  height: 34,
  padding: "0 14px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  borderBottom: `1px solid ${theme.customDashboard.panelBorderLight}`,
}));

export const ProgressTitle = styled(Typography)(({ theme }) => ({
  fontSize: 14,
  fontWeight: 600,
  letterSpacing: ".14em",
  color: theme.customDashboard.textSecondary,
}));

export const ProgressMeta = styled(Typography)(({ theme }) => ({
  fontSize: 12,
  color: theme.customDashboard.textSoft,
}));

export const ProgressBody = styled(Box)({
  padding: "12px 14px",
  display: "flex",
  flexDirection: "column",
  gap: "10px",
});

export const IdleNote = styled(Typography)(({ theme }) => ({
  fontSize: 12,
  color: theme.customDashboard.textFaint,
  padding: "6px 0",
}));

export const TallyRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  gap: "18px",
  flexWrap: "wrap",
});

export const TallyCell = styled(Box)({
  display: "flex",
  flexDirection: "column",
  gap: "2px",
});

export const TallyLabel = styled(Typography)(({ theme }) => ({
  fontSize: 11,
  letterSpacing: ".1em",
  color: theme.customDashboard.textMuted,
}));

export const TallyValue = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "valuecolor",
})(({ valuecolor }) => ({
  fontSize: 20,
  fontWeight: 700,
  color: valuecolor,
  lineHeight: 1,
}));

export const LiveFeedList = styled(Box)({
  maxHeight: 220,
  overflowY: "auto",
  display: "flex",
  flexDirection: "column",
  border: "1px solid transparent",
});

export const FeedRow = styled(Box)(({ theme }) => ({
  display: "flex",
  alignItems: "flex-start",
  gap: "8px",
  padding: "5px 2px",
  borderTop: `1px solid ${theme.customDashboard.panelBorderSoft}`,
  fontSize: 14,
}));

export const FeedDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 6,
  height: 6,
  borderRadius: "50%",
  backgroundColor: dotcolor,
  marginTop: "4px",
  flexShrink: 0,
}));

export const FeedReqId = styled("span")(({ theme }) => ({
  fontWeight: 700,
  color: theme.customDashboard.textSecondary,
  marginRight: "6px",
}));

export const FeedText = styled("span")(({ theme }) => ({
  color: theme.customDashboard.textBody,
}));

export const FeedKey = styled("span")(({ theme }) => ({
  color: theme.customDashboard.textFaint,
  marginLeft: "auto",
  paddingLeft: "8px",
  flexShrink: 0,
  letterSpacing: ".06em",
}));

// ── per-suite summary chips ─────────────────────────────────────────
export const SummaryGrid = styled(Box)({
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
  gap: "10px",
});

export const SummaryCard = styled(Paper, {
  shouldForwardProp: (prop) => !["bordercolor", "clickable"].includes(prop),
})(({ theme, bordercolor, clickable }) => ({
  padding: "10px 12px",
  borderRadius: "9px",
  border: `1px solid ${bordercolor || theme.customDashboard.panelBorder}`,
  cursor: clickable ? "pointer" : "default",
  display: "flex",
  flexDirection: "column",
  gap: "4px",
}));

export const SummaryCode = styled(Typography)(({ theme }) => ({
  fontSize: 14,
  fontWeight: 700,
  letterSpacing: ".06em",
  color: theme.customDashboard.textPrimary,
}));

export const SummaryTitle = styled(Typography)(({ theme }) => ({
  fontSize: 12,
  color: theme.customDashboard.textMuted,
}));

export const SummaryFraction = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "valuecolor",
})(({ valuecolor }) => ({
  fontSize: 18,
  fontWeight: 700,
  color: valuecolor,
}));

export const SummaryStatusTag = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "valuecolor",
})(({ valuecolor }) => ({
  fontSize: 12,
  fontWeight: 700,
  letterSpacing: ".1em",
  color: valuecolor,
}));

// ── detail (collapsible per-suite table) ────────────────────────────
export const DetailSection = styled(Paper)(({ theme }) => ({
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: "9px",
  overflow: "hidden",
}));

export const DetailHeader = styled("button")(({ theme }) => ({
  width: "100%",
  fontFamily: "inherit",
  border: "none",
  background: "transparent",
  cursor: "pointer",
  height: 38,
  padding: "0 14px",
  display: "flex",
  alignItems: "center",
  gap: "10px",
  borderBottom: `1px solid transparent`,
  "&:hover": {
    backgroundColor: theme.customDashboard.panelHoverSurface,
  },
}));

export const DetailTitle = styled(Typography)(({ theme }) => ({
  fontSize: 14,
  fontWeight: 600,
  letterSpacing: ".1em",
  color: theme.customDashboard.textSecondary,
}));

export const DetailMeta = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "valuecolor",
})(({ theme, valuecolor }) => ({
  fontSize: 14,
  fontWeight: 700,
  color: valuecolor || theme.customDashboard.textMuted,
  marginLeft: "auto",
}));

export const Chevron = styled("span", {
  shouldForwardProp: (prop) => prop !== "open",
})(({ theme, open }) => ({
  fontSize: 12,
  color: theme.customDashboard.textFaint,
  transform: open ? "rotate(90deg)" : "rotate(0deg)",
  transition: "transform .15s",
}));

export const Table = styled("table")({
  width: "100%",
  borderCollapse: "collapse",
});

export const Th = styled("th")(({ theme }) => ({
  fontSize: 12,
  fontWeight: 700,
  letterSpacing: ".1em",
  textAlign: "left",
  color: theme.customDashboard.textMuted,
  padding: "6px 14px",
  borderTop: `1px solid ${theme.customDashboard.panelBorderLight}`,
  borderBottom: `1px solid ${theme.customDashboard.panelBorderLight}`,
  backgroundColor: theme.customDashboard.panelSubtleSurface,
}));

export const Td = styled("td")(({ theme }) => ({
  fontSize: 14,
  color: theme.customDashboard.textBody,
  padding: "7px 14px",
  borderBottom: `1px solid ${theme.customDashboard.panelBorderSoft}`,
  verticalAlign: "top",
}));

export const ReqCell = styled("span")(({ theme }) => ({
  fontWeight: 700,
  color: theme.customDashboard.textSecondary,
}));

export const Badge = styled("span", {
  shouldForwardProp: (prop) => prop !== "tone",
})(({ theme, tone }) => {
  const map = {
    pass: { bg: `${theme.customDashboard.communicationHover}00`, fg: theme.palette.success.main, border: theme.palette.success.main },
    fail: { fg: theme.palette.error.main, border: theme.palette.error.main },
    skip: { fg: theme.palette.warning.main, border: theme.palette.warning.main },
  };
  const c = map[tone] || map.skip;
  return {
    fontSize: 12,
    fontWeight: 700,
    letterSpacing: ".06em",
    color: c.fg,
    border: `1px solid ${c.border}`,
    borderRadius: "4px",
    padding: "1px 6px",
    whiteSpace: "nowrap",
  };
});

export const EmptyRow = styled(Typography)(({ theme }) => ({
  fontSize: 14,
  color: theme.customDashboard.textFaint,
  padding: "16px 14px",
  textAlign: "center",
}));

// ── SRS §7.3 headline table ──────────────────────────────────────────
export const TargetPanel = styled(Paper)(({ theme }) => ({
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderTop: `3px solid ${theme.palette.primary.main}`,
  borderRadius: "9px",
  overflow: "hidden",
}));

export const TargetHeader = styled(Box)(({ theme }) => ({
  padding: "12px 16px 6px",
}));

export const TargetTitle = styled(Typography)(({ theme }) => ({
  fontSize: 14,
  fontWeight: 700,
  letterSpacing: ".1em",
  color: theme.customDashboard.textPrimary,
}));

export const TargetSub = styled(Typography)(({ theme }) => ({
  fontSize: 12,
  color: theme.customDashboard.textMuted,
  marginTop: "2px",
}));

export const VerdictBanner = styled(Box, {
  shouldForwardProp: (prop) => prop !== "ok",
})(({ theme, ok }) => ({
  margin: "0 16px 12px",
  padding: "8px 12px",
  borderRadius: "7px",
  fontSize: 14,
  fontWeight: 700,
  letterSpacing: ".05em",
  color: ok ? theme.palette.success.main : theme.palette.error.main,
  backgroundColor: ok ? `${theme.palette.success.main}14` : theme.customDashboard.dangerSurface,
  border: `1px solid ${ok ? theme.palette.success.main : theme.palette.error.main}`,
}));

// ── charts gallery ───────────────────────────────────────────────────
export const ChartsPanel = styled(Paper)(({ theme }) => ({
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: "9px",
  padding: "14px 16px",
  display: "flex",
  flexDirection: "column",
  gap: "12px",
}));

export const ChartsHeaderRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
});

export const ChartsGrid = styled(Box)({
  display: "grid",
  gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
  gap: "14px",
});

export const ChartCard = styled(Box)(({ theme }) => ({
  border: `1px solid ${theme.customDashboard.panelBorderLight}`,
  borderRadius: "8px",
  overflow: "hidden",
  backgroundColor: theme.customDashboard.panelSubtleSurface,
}));

export const ChartImg = styled("img")({
  width: "100%",
  display: "block",
  backgroundColor: "#ffffff",
});

export const ChartCaption = styled(Typography)(({ theme }) => ({
  fontSize: 12,
  color: theme.customDashboard.textSecondary,
  padding: "7px 10px",
  borderTop: `1px solid ${theme.customDashboard.panelBorderLight}`,
}));
