import { createTheme } from "@mui/material/styles";

const theme = createTheme({
  palette: {
    mode: "light",
    background: {
      default: "#fafafa",
      paper: "#fafafa",
    },
    text: {
      primary: "#1c1c1c",
      secondary: "#1c1c1c",
    },
    success: {
      main: "#229954", // Legitimate
      contrastText: "#fafafa",
    },
    error: {
      main: "#c0392b", // Attack
      contrastText: "#fafafa",
    },
    info: {
      main: "#2471a3", // Communication
      contrastText: "#fafafa",
    },
    warning: {
      main: "#d68910",
      contrastText: "#1c1c1c",
    },
    primary: {
      main: "#2471a3", // Communication as primary UI tone
      contrastText: "#fafafa",
    },
  },
  customStatus: {
    legitimate: "#229954",
    attack: "#c0392b",
    communication: "#2471a3",
    warning: "#d68910",
    text: "#1c1c1c",
    background: "#fafafa",
  },
  customDashboard: {
    appBackground: "#eaedf1",
    appText: "#3a4452",
    panelBackground: "#ffffff",
    panelBorder: "#e2e7ec",
    panelBorderLight: "#eef1f4",
    panelBorderSoft: "#f2f4f7",
    panelMutedSurface: "#f3f5f7",
    panelMutedSurfaceHover: "#edf1f4",
    panelSubtleSurface: "#f6f8fa",
    panelSelectedSurface: "#f0f4ff",
    panelHoverSurface: "#f9fbff",
    stageBackground: "#f7f9fb",
    stageGridDot: "#dde3e9",
    dangerSurface: "#fff5f5",
    neutralBorder: "#cdd5dd",
    textPrimary: "#2b3440",
    textSecondary: "#6b7685",
    textMuted: "#9aa4b0",
    textSoft: "#b8c0c9",
    textFaint: "#aab3bd",
    textBody: "#3a4452",
    shadowSoft: "0 1px 3px rgba(40,55,75,.05)",
    shadowNode: "0 1px 3px rgba(40,55,75,.06)",
    overlayBackground: "#2b3440",
    overlayBorder: "#3b4858",
    communicationHover: "#3f6da7",
  },
});

export default theme;
