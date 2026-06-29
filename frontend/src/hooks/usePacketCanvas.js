import { useEffect, useRef } from "react";
import { C, POS } from "../dashboard/constants";
import { lerp } from "../dashboard/utils";

const SENDER_NODE = {
  "TMA:1": "tma",
  "ACA:1": "aca1",
  "TIA:1": "tia1",
  "RCA:1": "rca1",
  "RAA:1": "raa1",
};

function colorForEvent(ev) {
  if (ev.topic === "alerts") return C.amber;
  if (ev.topic === "threat-reports") return C.red;
  if (ev.topic === "threat-intel") return C.teal;
  if (ev.topic === "coalition") return C.blue;
  if (ev.topic === "resolution") return C.green;
  if (ev.topic === "resource-grants") return C.purple;
  return C.blue;
}

const BUS_Y = 605;

function pointAlongPolyline(points, t) {
  if (!points.length) return null;
  if (points.length === 1) return points[0];

  const segLens = [];
  let total = 0;
  for (let i = 0; i < points.length - 1; i += 1) {
    const a = points[i];
    const b = points[i + 1];
    const len = Math.hypot(b.x - a.x, b.y - a.y);
    segLens.push(len);
    total += len;
  }
  if (total <= 0) return points[0];

  let dist = Math.max(0, Math.min(1, t)) * total;
  for (let i = 0; i < segLens.length; i += 1) {
    const len = segLens[i];
    if (dist <= len || i === segLens.length - 1) {
      const a = points[i];
      const b = points[i + 1];
      const localT = len > 0 ? dist / len : 0;
      return {
        x: lerp(a.x, b.x, localT),
        y: lerp(a.y, b.y, localT),
      };
    }
    dist -= len;
  }
  return points[points.length - 1];
}

export function usePacketCanvas(canvasRef, state) {
  const animRef = useRef(null);
  const busRef = useRef([]);
  const seenEventIds = useRef(new Set());
  const stateRef = useRef(state);
  const lastRef = useRef(0);

  useEffect(() => {
    stateRef.current = state;
  }, [state]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;

    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = 1180 * dpr;
    canvas.height = 700 * dpr;
    canvas.style.width = "1180px";
    canvas.style.height = "700px";
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    function enqueueBackendEvents() {
      const events = stateRef.current?.viz_events || [];
      for (const ev of events) {
        if (!ev?.id || seenEventIds.current.has(ev.id)) continue;
        seenEventIds.current.add(ev.id);

        const from = SENDER_NODE[ev.sender] || "tma";
        const targets = (ev.targets || []).map((agentId) => SENDER_NODE[agentId]).filter(Boolean);
        const color = colorForEvent(ev);
        for (const to of targets) {
          if (to === from) continue;
          const fromPos = POS[from];
          const toPos = POS[to];
          if (!fromPos || !toPos) continue;
          const path = [
            { x: fromPos.x, y: fromPos.y },
            { x: fromPos.x, y: BUS_Y },
            { x: toPos.x, y: BUS_Y },
            { x: toPos.x, y: toPos.y },
          ];
          busRef.current.push({
            from,
            to,
            path,
            t: 0,
            speed: 0.06,
            color,
          });
        }
      }
    }

    function draw() {
      ctx.clearRect(0, 0, 1180, 700);

      busRef.current.forEach((m) => {
        const pos = pointAlongPolyline(m.path || [], m.t);
        if (!pos) return;
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, 4, 0, Math.PI * 2);
        ctx.fillStyle = m.color;
        ctx.globalAlpha = 0.9;
        ctx.fill();
        ctx.globalAlpha = 1;
      });
    }

    function loop(ts) {
      const dt = Math.min(3, (ts - lastRef.current) / 16.67);
      lastRef.current = ts;
      const running = stateRef.current?.running !== false;

      if (running) {
        enqueueBackendEvents();

        busRef.current.forEach((m) => {
          m.t += m.speed * dt;
        });
        busRef.current = busRef.current.filter((m) => m.t < 1);
      }

      draw();
      animRef.current = requestAnimationFrame(loop);
    }

    animRef.current = requestAnimationFrame(loop);
    return () => {
      if (animRef.current) cancelAnimationFrame(animRef.current);
    };
  }, [canvasRef]);
}
