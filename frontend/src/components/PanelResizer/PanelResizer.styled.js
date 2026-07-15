import { Box } from "@mui/material";
import { styled } from "@mui/material/styles";

export const ResizerTrack = styled(Box, {
  shouldForwardProp: (prop) => prop !== "active",
})(({ theme, active }) => ({
  position: "relative",
  width: 12,
  cursor: "col-resize",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  touchAction: "none",
  "&::before": {
    content: '""',
    position: "absolute",
    top: 0,
    bottom: 0,
    left: "50%",
    width: 2,
    transform: "translateX(-50%)",
    borderRadius: 2,
    backgroundColor: active ? theme.palette.primary.main : theme.customDashboard.panelBorder,
    transition: active ? "none" : "background-color .12s ease",
  },
  "&:hover::before": {
    backgroundColor: theme.palette.primary.main,
  },
}));

export const ResizerGrip = styled(Box, {
  shouldForwardProp: (prop) => prop !== "active",
})(({ theme, active }) => ({
  position: "relative",
  zIndex: 1,
  width: 5,
  height: 28,
  borderRadius: 3,
  backgroundColor: active ? theme.palette.primary.main : theme.customDashboard.neutralBorder,
  border: `1px solid ${theme.customDashboard.panelBackground}`,
  transition: active ? "none" : "background-color .12s ease",
}));
