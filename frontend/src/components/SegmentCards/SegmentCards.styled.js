import { Box, Paper, Typography } from "@mui/material";
import { styled } from "@mui/material/styles";

export const SegmentGrid = styled(Box)(({ theme }) => ({
  display: "grid",
  gridTemplateColumns: "repeat(4, 1fr)",
  gap: "12px",
  padding: "14px 16px 0",
  [theme.breakpoints.down("lg")]: {
    gridTemplateColumns: "repeat(2, 1fr)",
  },
  [theme.breakpoints.down("sm")]: {
    gridTemplateColumns: "1fr",
    padding: "10px 10px 0",
    gap: "10px",
  },
}));

export const SegmentCard = styled(Paper, {
  shouldForwardProp: (prop) => prop !== "activeborder" && prop !== "activeglow",
})(({ theme, activeborder, activeglow }) => ({
  padding: "11px 14px",
  borderRadius: "9px",
  border: `1px solid ${activeborder}`,
  boxShadow: activeglow || theme.customDashboard.shadowSoft,
  cursor: "pointer",
  display: "flex",
  alignItems: "center",
  gap: "11px",
  transition: "border-color .2s, box-shadow .2s",
}));

export const StatusDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 9,
  height: 9,
  borderRadius: "50%",
  backgroundColor: dotcolor,
  flexShrink: 0,
}));

export const SegmentCode = styled(Box, {
  shouldForwardProp: (prop) => prop !== "bgcolorcustom" && prop !== "textcolorcustom",
})(({ bgcolorcustom, textcolorcustom }) => ({
  fontSize: 10,
  fontWeight: 600,
  letterSpacing: ".05em",
  padding: "2px 6px",
  borderRadius: "4px",
  backgroundColor: bgcolorcustom,
  color: textcolorcustom,
}));

export const SegmentInfo = styled(Box)({
  minWidth: 0,
  flex: 1,
  lineHeight: 1.3,
});

export const SegmentName = styled(Typography)(({ theme }) => ({
  fontSize: 12,
  fontWeight: 600,
  color: theme.customDashboard.textPrimary,
}));

export const SegmentCidr = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  color: theme.customDashboard.textMuted,
}));

export const SegmentState = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "statecolor",
})(({ statecolor }) => ({
  fontSize: 9,
  fontWeight: 600,
  letterSpacing: ".09em",
  color: statecolor,
  flexShrink: 0,
}));
