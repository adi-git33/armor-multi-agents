import { C } from "./constants";

export function getWsUrl() {
  const backendOrigin = import.meta.env.VITE_BACKEND_ORIGIN || "http://localhost:8000";
  const url = new URL(backendOrigin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/ws";
  return url.toString();
}

export function stateColor(st) {
  return { alert: C.amber, active: C.blue, mon: C.green, idle: C.idle, down: C.red }[st] || C.idle;
}

export function healthColor(health) {
  return { NORMAL: C.green, ANOMALY: C.amber, THREAT: C.red, QUARANTINED: "#8b5cf6" }[health] || C.green;
}

export function healthBorder(health) {
  return { NORMAL: "#e6eaee", ANOMALY: "#e7c070", THREAT: "#e7b6b0", QUARANTINED: "#c4b5fd" }[health] || "#e6eaee";
}

export function fmt(t) {
  const m = Math.floor(t / 60);
  const s = Math.floor(t % 60);
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

export function lerp(a, b, t) {
  return a + (b - a) * t;
}

export function buildLinePath(vals, W, H, peak) {
  if (!vals || vals.length < 2) return "";
  const step = W / (vals.length - 1);
  return vals
    .map((v, i) => {
      const x = i * step;
      const y = H - (v / peak) * (H - 4);
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

export function buildAreaPath(vals, W, H, peak) {
  if (!vals || vals.length < 2) return "";
  const step = W / (vals.length - 1);
  const top = vals
    .map((v, i) => {
      const x = i * step;
      const y = H - (v / peak) * (H - 4);
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return `${top} L${W},${H} L0,${H} Z`;
}
