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
  fontSize: 12,
  fontWeight: 600,
  letterSpacing: ".14em",
  color: theme.customDashboard.textSecondary,
}));

export const StageHint = styled(Typography)(({ theme }) => ({
  fontSize: 10,
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
  overflow: "hidden",
  display: "flex",
  justifyContent: "center",
  alignItems: "flex-start",
});

export const StageScaleFrame = styled(Box, {
  shouldForwardProp: (prop) => prop !== "yscale" && prop !== "xscale",
})(({ yscale, xscale }) => ({
  width: 1180 * xscale,
  height: 780 * yscale,
  position: "relative",
  flexShrink: 0,
  overflow: "hidden",
}));

export const StageSurface = styled(Box, {
  shouldForwardProp: (prop) => prop !== "yscale" && prop !== "xscale",
})(({ theme, yscale, xscale }) => ({
  position: "relative",
  width: 1180,
  height: 780,
  flexShrink: 0,
  transform: `scale(${xscale}, ${yscale})`,
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
  left: 96,
  top: 76,
  width: 88,
  height: 88,
  zIndex: 2,
  borderRadius: "16px",
  backgroundColor: activeattack ? theme.customDashboard.dangerSurface : theme.customDashboard.stageBackground,
  border: `1.5px dashed ${activeattack ? theme.palette.error.main : theme.customDashboard.neutralBorder}`,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
}));

export const LegitNode = styled(Box)(({ theme }) => ({
  position: "absolute",
  left: 256,
  top: 76,
  width: 88,
  height: 88,
  zIndex: 2,
  borderRadius: "16px",
  backgroundColor: `${theme.palette.success.main}1A`,
  border: `1.5px dashed ${theme.palette.success.main}`,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
}));

export const EdgeNode = styled(Box)(({ theme }) => ({
  position: "absolute",
  left: 176,
  top: 286,
  width: 88,
  height: 88,
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
  left: 382,
  top: 290,
  width: 96,
  height: 80,
  zIndex: 2,
  borderRadius: "13px",
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
  fontSize: 13,
  fontWeight: 600,
  color: titlecolor || theme.customDashboard.textPrimary,
}));

export const LabelSub = styled(Typography)(({ theme }) => ({
  fontSize: 11,
  color: theme.customDashboard.textMuted,
}));

export const LabelSubLight = styled(Typography)(({ theme }) => ({
  fontSize: 11,
  color: theme.customDashboard.textSoft,
}));

export const TmaChip = styled(Box, {
  shouldForwardProp: (prop) => prop !== "selected",
})(({ theme, selected }) => ({
  position: "absolute",
  left: 335,
  top: 470,
  width: 190,
  height: 60,
  zIndex: 2,
  borderRadius: "10px",
  backgroundColor: selected ? theme.customDashboard.panelSelectedSurface : theme.customDashboard.panelBackground,
  border: `1px solid ${selected ? theme.palette.primary.main : theme.customDashboard.panelBorder}`,
  display: "flex",
  alignItems: "center",
  gap: "11px",
  padding: "0 14px",
  cursor: "pointer",
}));

export const TmaIconWrap = styled(Box, {
  shouldForwardProp: (prop) => prop !== "iconbg",
})(({ iconbg }) => ({
  width: 32,
  height: 32,
  borderRadius: "8px",
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
  width: 246,
  height: 80,
  zIndex: 2,
  borderRadius: "11px",
  backgroundColor: theme.customDashboard.panelBackground,
  border: `1px solid ${bordercolor}`,
  display: "flex",
  alignItems: "center",
  gap: "13px",
  padding: "0 15px",
  boxShadow: theme.customDashboard.shadowSoft,
}));

export const HostIconWrap = styled(Box, {
  shouldForwardProp: (prop) => prop !== "iconbg",
})(({ iconbg }) => ({
  width: 40,
  height: 40,
  borderRadius: "9px",
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
  fontSize: 14,
  fontWeight: 600,
  color: theme.customDashboard.textPrimary,
}));

export const HostDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 8,
  height: 8,
  borderRadius: "50%",
  backgroundColor: dotcolor,
}));

export const HostMeta = styled(Typography)(({ theme }) => ({
  fontSize: 11,
  color: theme.customDashboard.textMuted,
}));

export const HostMetaLight = styled(Typography)(({ theme }) => ({
  fontSize: 11,
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
  fontSize: 11,
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
  width: 176,
  height: 64,
  zIndex: 2,
  borderRadius: "10px",
  backgroundColor: selected ? theme.customDashboard.panelSelectedSurface : theme.customDashboard.panelBackground,
  border: `1px solid ${selected ? theme.palette.primary.main : theme.customDashboard.panelBorder}`,
  borderTop: `3px solid ${accent}`,
  display: "flex",
  flexDirection: "column",
  justifyContent: "center",
  padding: "0 15px",
  cursor: "pointer",
}));

export const AgentChipTitleRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  gap: "8px",
});

export const AgentChipDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 8,
  height: 8,
  borderRadius: "50%",
  backgroundColor: dotcolor,
}));

export const AgentChipTitle = styled(Typography)(({ theme }) => ({
  fontSize: 13,
  fontWeight: 600,
  color: theme.customDashboard.textPrimary,
}));

export const AgentChipMeta = styled(Typography)(({ theme }) => ({
  fontSize: 10,
  color: theme.customDashboard.textMuted,
  marginTop: "2px",
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
  fontSize: 10,
  letterSpacing: ".12em",
  color: theme.customDashboard.textFaint,
}));

export const LegendItem = styled(Box)(({ theme }) => ({
  display: "inline-flex",
  alignItems: "center",
  gap: "6px",
  fontSize: 10,
  color: theme.customDashboard.textSecondary,
}));

export const LegendDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 8,
  height: 8,
  borderRadius: "50%",
  backgroundColor: dotcolor,
}));
