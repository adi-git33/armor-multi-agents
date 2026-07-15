// Shared color/format tokens for the validation charts.
//
// PASS/FAIL/TARGET are validated as a CVD-safe categorical set
// (scripts/validate_palette.js "#229954,#c0392b,#2471a3" --mode light — all
// checks pass; the green/red pair sits in the 6-8 dE "floor" band, which the
// dataviz skill requires secondary encoding for. Every chart here pairs the
// color with a direct value label and a legend, never color alone.
export const PASS = "#229954";
export const FAIL = "#c0392b";
export const TARGET = "#2471a3";

export const statusColor = (passed) => (passed ? PASS : FAIL);

export function fmtValue(value, fmt) {
  switch (fmt) {
    case "pct":
      return `${(value * 100).toFixed(1)}%`;
    case "pct0":
      return `${(value * 100).toFixed(0)}%`;
    case "ms":
      return `${value.toLocaleString()} ms`;
    case "yn":
      return value >= 1 ? "Correct" : "Violated";
    case "f3":
    default:
      return value.toFixed(3);
  }
}

// Chart chrome (axes/grid/text) reads off the app's own theme so charts sit
// in the page rather than looking like an embedded foreign widget.
export function chromeFromTheme(theme) {
  return {
    grid: theme.customDashboard.panelBorderLight,
    axisText: theme.customDashboard.textMuted,
    axisLine: theme.customDashboard.panelBorder,
    labelText: theme.customDashboard.textSecondary,
    surface: theme.customDashboard.panelBackground,
    tooltipBg: theme.customDashboard.panelBackground,
    tooltipBorder: theme.customDashboard.panelBorder,
  };
}

export const FONT_FAMILY = '"IBM Plex Mono", monospace';
