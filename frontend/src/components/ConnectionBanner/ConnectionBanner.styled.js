import { Alert } from "@mui/material";
import { styled } from "@mui/material/styles";

export const ConnectionAlert = styled(Alert)(({ theme }) => ({
  backgroundColor: theme.customDashboard.overlayBackground,
  color: theme.palette.common.white,
  border: `1px solid ${theme.customDashboard.overlayBorder}`,
}));
