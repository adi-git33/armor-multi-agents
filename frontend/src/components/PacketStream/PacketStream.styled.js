import { Box, Typography } from "@mui/material";
import { styled } from "@mui/material/styles";

export const StreamList = styled(Box)({
  flex: 1,
  minHeight: 0,
  overflowY: "auto",
});

export const Caption = styled(Typography)(({ theme }) => ({
  fontSize: 8,
  color: theme.customDashboard.textFaint,
  padding: "5px 14px",
  borderBottom: `1px solid ${theme.customDashboard.panelBorderLight}`,
}));

export const EmptyStream = styled(Typography)(({ theme }) => ({
  padding: "20px 14px",
  fontSize: 9,
  color: theme.customDashboard.textFaint,
  textAlign: "center",
}));

export const PktRow = styled(Box)(({ theme }) => ({
  padding: "6px 14px",
  borderTop: `1px solid ${theme.customDashboard.panelBorderSoft}`,
  display: "flex",
  alignItems: "center",
  gap: "8px",
}));

export const KindBadge = styled("span", {
  shouldForwardProp: (prop) => prop !== "tagcolor",
})(({ tagcolor }) => ({
  fontSize: 8,
  fontWeight: 700,
  letterSpacing: ".03em",
  color: tagcolor,
  border: `1px solid ${tagcolor}`,
  borderRadius: "3px",
  padding: "1px 4px",
  flexShrink: 0,
}));

export const PktFlow = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  fontFamily: "monospace",
  color: theme.customDashboard.textBody,
  flex: 1,
  minWidth: 0,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
}));

export const PktMeta = styled(Typography)(({ theme }) => ({
  fontSize: 8,
  color: theme.customDashboard.textFaint,
  flexShrink: 0,
}));
