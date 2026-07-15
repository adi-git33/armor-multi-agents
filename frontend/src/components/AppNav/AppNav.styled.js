// import { Box, Tabs, Tab } from "@mui/material";
// import { styled } from "@mui/material/styles";

// export const HeaderContainer = styled(Box)(() => ({
//   display: "flex",
//   width: "100%",
//   gap: "3%",
//   justifyContent: "flex-start",
//   alignItems: "center",
//   padding: "10px 16px 0px 16px",
// }));

// export const NavBar = styled(Box)(() => ({
//   display: "flex",
//   alignItems: "center",
//   position: "relative",
//   flexFlow: "row",
// }));

// export const LogoStyle = styled("img")(() => ({
//   display: "block",
//   width: "120px",
//   height: "40px",
// }));

// export const NavTabs = styled(Tabs)(({ theme }) => ({
//   display: "flex",
//   gap: "14px",
//   "& .MuiTabs-indicator": {
//     backgroundColor: theme.palette.primary.main,
//   },
// }));

// export const NavTab = styled(Tab)(({ theme }) => ({
//   textTransform: "none",
//   fontSize: "0.95rem",
//   fontWeight: 500,
//   letterSpacing: ".08em",
//   cursor: "pointer",
//   whiteSpace: "nowrap",
//   padding: "6px 14px",
//   color: theme.customDashboard.textPrimary,
//   transition: "color 0.3s ease-in-out, font-weight 0.3s ease-in-out",
//   "&.Mui-selected": {
//     color: theme.customDashboard.textPrimary,
//   },
//   "&:hover": {
//     color: theme.customDashboard.textSecondary,
//     fontWeight: 500,
//   },
// }));

import { Box } from "@mui/material";
import { styled } from "@mui/material/styles";

export const HeaderContainer = styled(Box)(({ theme }) => ({
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  background: theme.customDashboard.panelBackground,
  // border: `1px solid ${theme.customDashboard.panelBorder}`,
  // borderRadius: "9px",
  // boxShadow: theme.customDashboard.shadowSoft,
  padding: "12px 20px",
  // margin: "10px 16px 0 16px",
  // boxSizing: "border-box",
}));

export const LogoStyle = styled("img")(() => ({
  display: "block",
  width: "112px",
  height: "auto",
}));

export const NavBar = styled(Box)(() => ({
  display: "flex",
  alignItems: "center",
  gap: "8px",
}));

export const NavChip = styled(Box, {
  shouldForwardProp: (prop) => prop !== "active",
})(({ theme, active }) => ({
  display: "flex",
  alignItems: "center",
  gap: "8px",
  padding: "7px 14px 7px 10px",
  borderRadius: "20px",
  cursor: "pointer",
  backgroundColor: active ? theme.customDashboard.panelSelectedSurface : "transparent",
  transition: "background-color .2s ease-in-out",
  "&:hover": {
    backgroundColor: active
      ? theme.customDashboard.panelSelectedSurface
      : theme.customDashboard.panelHoverSurface,
  },
}));

export const NavGlyph = styled(Box, {
  shouldForwardProp: (prop) => prop !== "active",
})(({ theme, active }) => ({
  width: "14px",
  height: "14px",
  borderRadius: "4px",
  flexShrink: 0,
  backgroundColor: active ? theme.palette.primary.main : theme.customDashboard.neutralBorder,
}));

export const NavLabel = styled(Box, {
  shouldForwardProp: (prop) => prop !== "active",
})(({ theme, active }) => ({
  fontSize: "12px",
  fontWeight: active ? 600 : 500,
  letterSpacing: ".04em",
  color: active ? theme.palette.primary.main : theme.customDashboard.textSecondary,
}));
