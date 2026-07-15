import { useEffect, useRef } from "react";
import { C, POS } from "../dashboard/constants";
import { lerp } from "../dashboard/utils";

// One TMA agent per segment now (TMA:<segment_id>) — they all render at
// the same "tma" screen position, since the topology view only ever shows
// whichever segment's TMA corresponds to the currently selected network.
const SENDER_NODE = {
  "TMA:public-facing": "tma",
  "TMA:server":        "tma",
  "TMA:internal":       "tma",
  "TMA:sec-mon":        "tma",
  "ACA:1": "aca1",
  "TIA:1": "tia1",
  "RCA:1": "rca1",
  "RAA:1": "raa1",
};

const HOST_SLOTS = ["A", "B", "C", "D", "E"];

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
// Both lanes travel the same fraction-of-path-per-second, so a message takes
// roughly the same, easily-followable ~0.9s to cross the stage regardless of
// how long its particular path is.
const BUS_SPEED = 0.021;
const NET_SPEED = 0.021;
const TRAIL_STEPS = 6;
const TRAIL_STEP_T = 0.028;
const RIPPLE_MAX_AGE = 26; // ~frames at 60fps

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

export function usePacketCanvas(canvasRef, state, topology) {
  const animRef = useRef(null);
  const markersRef = useRef([]); // both bus (agent) messages and net (attacker/legit) packets
  const ripplesRef = useRef([]);
  const seenEventIds = useRef(new Set());
  const seenPacketIds = useRef(new Set());
  const stateRef = useRef(state);
  const topoRef = useRef(topology);
  const lastRef = useRef(0);

  useEffect(() => {
    stateRef.current = state;
  }, [state]);

  useEffect(() => {
    topoRef.current = topology;
  }, [topology]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;

    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = 1180 * dpr;
    canvas.height = 780 * dpr;
    canvas.style.width = "1180px";
    canvas.style.height = "780px";
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
          markersRef.current.push({
            kind: "bus",
            from,
            to,
            path,
            t: 0,
            speed: BUS_SPEED,
            color,
          });
        }
      }
    }

    // Real network packets sampled by the backend (legit + attacker),
    // routed attacker/legit -> edge -> core -> destination host, so the
    // topology view actually shows traffic moving through the network
    // instead of just the agent coordination bus below it.
    function enqueueBackendPackets() {
      const packets = stateRef.current?.packets || [];
      const topo = topoRef.current || {};
      const hosts = topo.hosts || [];
      for (const pkt of packets) {
        if (!pkt?.id || seenPacketIds.current.has(pkt.id)) continue;
        seenPacketIds.current.add(pkt.id);

        // Only animate packets for whichever segment is currently on
        // screen — other segments' hosts/edge/core aren't rendered here.
        if (pkt.segment !== topo.selectedSeg) continue;

        const isAttack = pkt.kind === "attack";
        const fromPos = isAttack ? POS.attacker : POS.legit;
        const hostIdx = hosts.findIndex((h) => h.ip === pkt.dst_ip);
        const slotKey = hostIdx >= 0 && hostIdx < HOST_SLOTS.length ? HOST_SLOTS[hostIdx] : null;
        const toPos = slotKey ? POS[slotKey] : POS.core;
        if (!fromPos || !toPos) continue;

        const path = [
          { x: fromPos.x, y: fromPos.y },
          { x: POS.edge.x, y: POS.edge.y },
          { x: POS.core.x, y: POS.core.y },
          { x: toPos.x, y: toPos.y },
        ];
        markersRef.current.push({
          kind: "net",
          path,
          t: 0,
          speed: NET_SPEED,
          color: isAttack ? C.red : C.green,
        });
      }
    }

    function drawArrowhead(pos, dir, color) {
      const angle = Math.atan2(dir.y, dir.x);
      const size = 6;
      ctx.save();
      ctx.translate(pos.x, pos.y);
      ctx.rotate(angle);
      ctx.beginPath();
      ctx.moveTo(size, 0);
      ctx.lineTo(-size * 0.7, size * 0.6);
      ctx.lineTo(-size * 0.7, -size * 0.6);
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.globalAlpha = 0.95;
      ctx.fill();
      ctx.restore();
      ctx.globalAlpha = 1;
    }

    function draw() {
      ctx.clearRect(0, 0, 1180, 780);

      // Ripples first so markers render on top of them.
      ripplesRef.current.forEach((r) => {
        const life = r.age / RIPPLE_MAX_AGE;
        ctx.beginPath();
        ctx.arc(r.x, r.y, 4 + life * 14, 0, Math.PI * 2);
        ctx.strokeStyle = r.color;
        ctx.lineWidth = 2;
        ctx.globalAlpha = Math.max(0, 0.55 * (1 - life));
        ctx.stroke();
        ctx.globalAlpha = 1;
      });

      markersRef.current.forEach((m) => {
        const headPos = pointAlongPolyline(m.path || [], m.t);
        if (!headPos) return;

        // Fading comet trail behind the head — makes travel direction and
        // speed readable at a glance instead of a static dot popping around.
        for (let i = TRAIL_STEPS; i >= 1; i -= 1) {
          const trailT = m.t - i * TRAIL_STEP_T;
          if (trailT < 0) continue;
          const tp = pointAlongPolyline(m.path, trailT);
          if (!tp) continue;
          const alpha = 0.35 * (1 - i / (TRAIL_STEPS + 1));
          const r = m.kind === "net" ? 3.2 : 3;
          ctx.beginPath();
          ctx.arc(tp.x, tp.y, r, 0, Math.PI * 2);
          ctx.fillStyle = m.color;
          ctx.globalAlpha = alpha;
          ctx.fill();
        }
        ctx.globalAlpha = 1;

        // Direction arrow — computed from a short lookback along the path
        // so it points the way the marker is actually travelling.
        const prevPos = pointAlongPolyline(m.path, Math.max(0, m.t - 0.02)) || headPos;
        const dir = { x: headPos.x - prevPos.x, y: headPos.y - prevPos.y };
        const dirLen = Math.hypot(dir.x, dir.y) || 1;
        drawArrowhead(headPos, { x: dir.x / dirLen, y: dir.y / dirLen }, m.color);

        // Bright head dot.
        ctx.beginPath();
        ctx.arc(headPos.x, headPos.y, m.kind === "net" ? 4.5 : 4, 0, Math.PI * 2);
        ctx.fillStyle = m.color;
        ctx.shadowColor = m.color;
        ctx.shadowBlur = 6;
        ctx.globalAlpha = 0.95;
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.globalAlpha = 1;
      });
    }

    function loop(ts) {
      const dt = Math.min(3, (ts - lastRef.current) / 16.67);
      lastRef.current = ts;
      const running = stateRef.current?.running !== false;

      if (running) {
        enqueueBackendEvents();
        enqueueBackendPackets();

        const arrived = [];
        markersRef.current.forEach((m) => {
          const wasBelow = m.t < 1;
          m.t += m.speed * dt;
          if (wasBelow && m.t >= 1) {
            const endPos = m.path[m.path.length - 1];
            arrived.push({ x: endPos.x, y: endPos.y, color: m.color, age: 0 });
          }
        });
        if (arrived.length) ripplesRef.current.push(...arrived);
        markersRef.current = markersRef.current.filter((m) => m.t < 1);

        ripplesRef.current.forEach((r) => { r.age += dt; });
        ripplesRef.current = ripplesRef.current.filter((r) => r.age < RIPPLE_MAX_AGE);
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
