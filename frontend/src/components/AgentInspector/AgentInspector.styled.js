import { Box, IconButton, LinearProgress, List, ListItem, Typography } from "@mui/material";
import { styled } from "@mui/material/styles";

export const DrawerContent = styled(Box)({
  width: 420,
  height: "100%",
  display: "flex",
  flexDirection: "column",
});

export const Header = styled(Box)(({ theme }) => ({
  height: 56,
  padding: "0 18px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  borderBottom: `1px solid ${theme.customDashboard.panelBorder}`,
}));

export const StatusDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== "dotcolor",
})(({ dotcolor }) => ({
  width: 9,
  height: 9,
  borderRadius: "50%",
  backgroundColor: dotcolor,
}));

export const AgentTitle = styled(Typography)(({ theme }) => ({
  fontSize: 13,
  fontWeight: 600,
  color: theme.customDashboard.textPrimary,
  lineHeight: 1.3,
}));

export const AgentSubtitle = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  letterSpacing: ".07em",
  color: theme.customDashboard.textMuted,
  lineHeight: 1.3,
}));

export const CloseButton = styled(IconButton)(({ theme }) => ({
  backgroundColor: theme.customDashboard.panelMutedSurface,
  border: `1px solid ${theme.customDashboard.panelBorder}`,
}));

export const CloseGlyph = styled(Typography)({
  fontSize: 13,
  lineHeight: 1,
});

export const Content = styled(Box)({
  padding: "18px",
  overflowY: "auto",
  display: "flex",
  flexDirection: "column",
  gap: "18px",
});

export const SectionTitle = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  fontWeight: 600,
  letterSpacing: ".16em",
  color: theme.palette.primary.main,
  marginBottom: "9px",
}));

export const IntentionCard = styled(Box)(({ theme }) => ({
  padding: "13px 14px",
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: 7,
  backgroundColor: theme.customDashboard.panelSubtleSurface,
}));

export const IntentionRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  marginBottom: "8px",
});

export const PlanText = styled(Typography)({
  fontSize: 12,
  fontWeight: 600,
});

export const StateText = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "statecolor",
})(({ statecolor }) => ({
  fontSize: 9,
  fontWeight: 600,
  color: statecolor,
}));

export const TaskText = styled(Typography)(({ theme }) => ({
  fontSize: 10,
  color: theme.customDashboard.textSecondary,
  marginBottom: "10px",
}));

export const BudgetMetaRow = styled(Box)({
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  marginBottom: 5,
});

export const BudgetLabel = styled(Typography)(({ theme }) => ({
  fontSize: 8,
  letterSpacing: ".08em",
  color: theme.customDashboard.textMuted,
}));

export const BudgetValue = styled(Typography)(({ theme }) => ({
  fontSize: 9,
  color: theme.customDashboard.textSecondary,
}));

export const BudgetProgress = styled(LinearProgress, {
  shouldForwardProp: (prop) => prop !== "barcolor",
})(({ theme, barcolor }) => ({
  height: 4,
  borderRadius: 2,
  backgroundColor: theme.customDashboard.panelBorder,
  "& .MuiLinearProgress-bar": {
    backgroundColor: barcolor,
  },
}));

export const BeliefsList = styled(List)(({ theme }) => ({
  padding: 0,
  border: `1px solid ${theme.customDashboard.panelBorder}`,
  borderRadius: 7,
}));

export const BeliefItem = styled(ListItem, {
  shouldForwardProp: (prop) => prop !== "showborder",
})(({ theme, showborder }) => ({
  padding: "8px 14px",
  borderTop: showborder ? `1px solid ${theme.customDashboard.panelBorderSoft}` : "none",
}));

export const BeliefRow = styled(Box)({
  width: "100%",
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
});

export const BeliefKey = styled(Typography)(({ theme }) => ({
  fontSize: 10,
  color: theme.customDashboard.textSecondary,
}));

export const BeliefValue = styled(Typography, {
  shouldForwardProp: (prop) => prop !== "valuecolor",
})(({ theme, valuecolor }) => ({
  fontSize: 10,
  fontWeight: 500,
  color: valuecolor || theme.customDashboard.textPrimary,
}));

export const GoalsList = styled(Box)({
  display: "flex",
  flexDirection: "column",
  gap: "7px",
});

export const GoalText = styled(Typography)(({ theme }) => ({
  fontSize: 10,
  color: theme.customDashboard.textSecondary,
}));
