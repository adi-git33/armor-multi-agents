import { Box, Paper, Typography } from "@mui/material";
import { styled } from "@mui/material/styles";

export const StagePaper = styled(Paper)(({ theme }) => ({
  width: "100%",
  height: "100%",
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: "11px",
  display: "flex",
  flexDirection: "column",
  minWidth: 0,
  minHeight: 0,
}));

export const StageHeader = styled(Box)(({ theme }) => ({
  height: 34,
  padding: "0 16px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  borderBottom: `1px solid ${theme.customDashboard.panelBorderLight}`,
}));

export const StageTitle = styled(Typography)(({ theme }) => ({
  fontSize: 10,
  fontWeight: 600,
  letterSpacing: ".14em",
  color: theme.customDashboard.textSecondary,
}));

export const StageHint = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  letterSpacing: ".08em",
  color: theme.customDashboard.textSoft,
  [theme.breakpoints.down("md")]: {
    display: "none",
  },
}));

export const StageViewport = styled(Box)({
  flex: 1,
  minHeight: 0,
  width: "100%",
  display: "flex",
  justifyContent: "center",
  alignItems: "flex-start",
});

export const StageScaleFrame = styled(Box, {
  shouldForwardProp: (prop) => prop !== "yscale",
})(({ yscale }) => ({
  width: 1180,
  height: 700 * yscale,
  position: "relative",
  flexShrink: 0,
}));

export const StageSurface = styled(Box, {
  shouldForwardProp: (prop) => prop !== "yscale",
})(({ theme, yscale }) => ({
  position: "relative",
  width: 1180,
  height: 700,
  flexShrink: 0,
  transform: `scale(1, ${yscale})`,
  transformOrigin: "top left",
  backgroundColor: theme.customDashboard.stageBackground,
  backgroundImage: `radial-gradient(circle, ${theme.customDashboard.stageGridDot} 1px, transparent 1px)`,
  backgroundSize: "24px 24px",
}));

export const LayerSvg = styled("svg")({
  position: "absolute",
  left: 0,
  top: 0,
  zIndex: 0,
});

export const PacketCanvas = styled("canvas")({
  position: "absolute",
  left: 0,
  top: 0,
  zIndex: 1,
  pointerEvents: "none",
});

export const AttackerNode = styled(Box, {
  shouldForwardProp: (prop) => prop !== "activeattack",
})(({ theme, activeattack }) => ({
  position: "absolute",
  left: 106,
  top: 86,
  width: 68,
  height: 68,
  zIndex: 2,
  borderRadius: "14px",
  backgroundColor: activeattack ? theme.customDashboard.dangerSurface : theme.customDashboard.stageBackground,
  border: `1.5px dashed ${activeattack ? theme.palette.error.main : theme.customDashboard.neutralBorder}`,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
}));

export const LegitNode = styled(Box)(({ theme }) => ({
  position: "absolute",
  left: 266,
  top: 86,
  width: 68,
  height: 68,
  zIndex: 2,
  borderRadius: "14px",
  backgroundColor: `${theme.palette.success.main}1A`,
  border: `1.5px dashed ${theme.palette.success.main}`,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
}));

export const EdgeNode = styled(Box)(({ theme }) => ({
  position: "absolute",
  left: 186,
  top: 296,
  width: 68,
  height: 68,
  zIndex: 2,
  borderRadius: "50%",
  backgroundColor: theme.customDashboard.panelBackground,
  border: `1.5px solid ${theme.customDashboard.neutralBorder}`,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  boxShadow: theme.customDashboard.shadowNode,
}));

export const CoreNode = styled(Box)(({ theme }) => ({
  position: "absolute",
  left: 392,
  top: 298,
  width: 76,
  height: 64,
  zIndex: 2,
  borderRadius: "11px",
  backgroundColor: theme.customDashboard.panelBackground,
  border: `1.5px solid ${theme.customDashboard.neutralBorder}`,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  boxShadow: theme.customDashboard.shadowNode,
}));

export const LabelGroup = styled(Box, {
  shouldForwardProp: (prop) => !["leftpos", "toppos", "widthval", "textcolor"].includes(prop),
})(({ leftpos, toppos, widthval, textcolor }) => ({
  position: "absolute",
  left: leftpos,
  top: toppos,
  width: widthval,
  textAlign: "center",
  zIndex: 2,
  lineHeight: 1.35,
  color: textcolor || "inherit",
}));

export const LabelTitle = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "titlecolor",
})(({ theme, titlecolor }) => ({
  fontSize: 11,
  fontWeight: 600,
  color: titlecolor || theme.customDashboard.textPrimary,
}));

export const LabelSub = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  color: theme.customDashboard.textMuted,
}));

export const LabelSubLight = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  color: theme.customDashboard.textSoft,
}));

export const TmaChip = styled(Box, {
  shouldForwardProp: (prop) => prop !== "selected",
})(({ theme, selected }) => ({
  position: "absolute",
  left: 350,
  top: 476,
  width: 160,
  height: 48,
  zIndex: 2,
  borderRadius: "9px",
  backgroundColor: selected ? theme.customDashboard.panelSelectedSurface : theme.customDashboard.panelBackground,
  border: `1px solid ${selected ? theme.palette.primary.main : theme.customDashboard.panelBorder}`,
  display: "flex",
  alignItems: "center",
  gap: "9px",
  padding: "0 12px",
  cursor: "pointer",
}));

export const TmaIconWrap = styled(Box, {
  shouldForwardProp: (prop) => prop !== "iconbg",
})(({ iconbg }) => ({
  width: 26,
  height: 26,
  borderRadius: "7px",
  backgroundColor: iconbg,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
}));

export const HostCard = styled(Box, {
  shouldForwardProp: (prop) => !["leftpos", "toppos", "bordercolor"].includes(prop),
})(({ theme, leftpos, toppos, bordercolor }) => ({
  position: "absolute",
  left: leftpos,
  top: toppos,
  width: 212,
  height: 66,
  zIndex: 2,
  borderRadius: "10px",
  backgroundColor: theme.customDashboard.panelBackground,
  border: `1px solid ${bordercolor}`,
  display: "flex",
  alignItems: "center",
  gap: "11px",
  padding: "0 13px",
  boxShadow: theme.customDashboard.shadowSoft,
}));

export const HostIconWrap = styled(Box, {
  shouldForwardProp: (prop) => prop !== "iconbg",
})(({ iconbg }) => ({
  width: 34,
  height: 34,
  borderRadius: "8px",
  backgroundColor: iconbg,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
}));

export const HostInfo = styled(Box)({
  lineHeight: 1.32,
});

export const HostTitleRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  gap: "6px",
});

export const HostTitle = styled(Typography)(({ theme }) => ({
  fontSize: 12,
  fontWeight: 600,
  color: theme.customDashboard.textPrimary,
}));

export const HostDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 7,
  height: 7,
  borderRadius: "50%",
  backgroundColor: dotcolor,
}));

export const HostMeta = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  color: theme.customDashboard.textMuted,
}));

export const HostMetaLight = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  color: theme.customDashboard.textSoft,
}));

export const BusLabelWrap = styled(Box)({
  position: "absolute",
  left: 14,
  top: 566,
  width: 1180,
  textAlign: "center",
  zIndex: 2,
});

export const BusLabel = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  fontWeight: 600,
  letterSpacing: ".18em",
  color: theme.customDashboard.textFaint,
}));

export const AgentChip = styled(Box, {
  shouldForwardProp: (prop) => !["leftpos", "selected", "accent"].includes(prop),
})(({ theme, leftpos, selected, accent }) => ({
  position: "absolute",
  left: leftpos,
  top: 630,
  width: 152,
  height: 52,
  zIndex: 2,
  borderRadius: "9px",
  backgroundColor: selected ? theme.customDashboard.panelSelectedSurface : theme.customDashboard.panelBackground,
  border: `1px solid ${selected ? theme.palette.primary.main : theme.customDashboard.panelBorder}`,
  borderTop: `3px solid ${accent}`,
  display: "flex",
  flexDirection: "column",
  justifyContent: "center",
  padding: "0 13px",
  cursor: "pointer",
}));

export const AgentChipTitleRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  gap: "7px",
});

export const AgentChipDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 7,
  height: 7,
  borderRadius: "50%",
  backgroundColor: dotcolor,
}));

export const AgentChipTitle = styled(Typography)(({ theme }) => ({
  fontSize: 11,
  fontWeight: 600,
  color: theme.customDashboard.textPrimary,
}));

export const AgentChipMeta = styled(Typography)(({ theme }) => ({
  fontSize: 8,
  color: theme.customDashboard.textMuted,
  marginTop: "1px",
}));

export const LegendRow = styled(Box)(({ theme }) => ({
  display: "flex",
  alignItems: "center",
  flexWrap: "wrap",
  gap: "10px",
  padding: "7px 12px",
  borderTop: `1px solid ${theme.customDashboard.panelBorderLight}`,
}));

export const LegendLabel = styled(Typography)(({ theme }) => ({
  fontSize: 8,
  letterSpacing: ".12em",
  color: theme.customDashboard.textFaint,
}));

export const LegendItem = styled(Box)(({ theme }) => ({
  display: "inline-flex",
  alignItems: "center",
  gap: "5px",
  fontSize: 8,
  color: theme.customDashboard.textSecondary,
}));

export const LegendDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 7,
  height: 7,
  borderRadius: "50%",
  backgroundColor: dotcolor,
}));
