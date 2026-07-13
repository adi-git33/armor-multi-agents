import { Box, Typography } from "@mui/material";
import { styled } from "@mui/material/styles";

export const BallotList = styled(Box)({
  flex: 1,
  minHeight: 0,
  overflowY: "auto",
  padding: "10px 14px",
  display: "flex",
  flexDirection: "column",
  gap: "10px",
});

export const EmptyBallots = styled(Typography)(({ theme }) => ({
  padding: "16px 0",
  fontSize: 9,
  color: theme.customDashboard.textFaint,
  textAlign: "center",
}));

export const BallotCard = styled(Box, {
  shouldForwardProp: (prop) => prop !== "resolved",
})(({ theme, resolved }) => ({
  padding: "10px 12px",
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: 8,
  backgroundColor: theme.customDashboard.panelSubtleSurface,
  opacity: resolved ? 0.72 : 1,
}));

export const BallotHeaderRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  marginBottom: "6px",
});

export const BallotAction = styled(Typography)(({ theme }) => ({
  fontSize: 11,
  fontWeight: 600,
  color: theme.customDashboard.textPrimary,
}));

export const BallotSeg = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  color: theme.customDashboard.textMuted,
}));

export const OutcomeBadge = styled("span", {
  shouldForwardProp: (prop) => prop !== "tagcolor",
})(({ tagcolor }) => ({
  fontSize: 8,
  fontWeight: 700,
  letterSpacing: ".04em",
  color: tagcolor,
  border: `1px solid ${tagcolor}`,
  borderRadius: "3px",
  padding: "1px 5px",
}));

export const VoterRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "3px 0",
});

export const VoterName = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  color: theme.customDashboard.textSecondary,
}));

export const VoterDecision = styled("span", {
  shouldForwardProp: (prop) => prop !== "tagcolor",
})(({ tagcolor }) => ({
  fontSize: 8,
  fontWeight: 700,
  color: tagcolor,
}));

export const TallyRow = styled(Typography)(({ theme }) => ({
  fontSize: 8,
  color: theme.customDashboard.textFaint,
  marginTop: "4px",
}));
