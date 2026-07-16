import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import AgentInspector from "../../components/AgentInspector/AgentInspector";
import ConnectionBanner from "../../components/ConnectionBanner/ConnectionBanner";
import PanelResizer from "../../components/PanelResizer/PanelResizer";
import RightRail from "../../components/RightRail/RightRail";
import ScenarioMetricsBar from "../../components/ScenarioMetricsBar/ScenarioMetricsBar";
import SegmentCards from "../../components/SegmentCards/SegmentCards";
import TopologyStage from "../../components/TopologyStage/TopologyStage";
import { POS } from "../../dashboard/constants";
import { useDashboardSocket } from "../../hooks/useDashboardSocket";
import { usePacketCanvas } from "../../hooks/usePacketCanvas";

const RESIZER_WIDTH = 12;
const MIN_TOPOLOGY_WIDTH = 520;
const MIN_RIGHT_RAIL_WIDTH = 320;
const TOPOLOGY_WIDTH_STORAGE_KEY = "armor.dashboard.topologyWidth";

// Unchanged from the original App.jsx — moved verbatim so it can live
// alongside the new ValidationPage behind a lightweight top-level nav
// toggle (see App.jsx). No behavior here was touched.
function LiveDashboardPage() {
  const [selectedSeg, setSelSeg] = useState("public-facing");
  const [selAgent, setSelAgent] = useState(null);
  const { state, connected, wsReady, sendScenario, sendControl } = useDashboardSocket();
  const canvasRef = useRef(null);

  const mainRef = useRef(null);
  const [topologyWidth, setTopologyWidth] = useState(() => {
    const saved = Number(localStorage.getItem(TOPOLOGY_WIDTH_STORAGE_KEY));
    return Number.isFinite(saved) && saved > 0 ? saved : null;
  });
  const [isResizing, setIsResizing] = useState(false);

  const clampTopologyWidth = useCallback((width) => {
    const container = mainRef.current;
    if (!container) return width;
    const maxWidth = container.getBoundingClientRect().width - RESIZER_WIDTH - MIN_RIGHT_RAIL_WIDTH;
    return Math.min(Math.max(width, MIN_TOPOLOGY_WIDTH), Math.max(MIN_TOPOLOGY_WIDTH, maxWidth));
  }, []);

  // Keep the split within bounds if the window is resized (e.g. a saved
  // pixel width from a wider screen shouldn't push the right rail off-screen).
  useEffect(() => {
    const handleResize = () => {
      setTopologyWidth((w) => (w === null ? w : clampTopologyWidth(w)));
    };
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [clampTopologyWidth]);

  const handleResizeStart = useCallback(
    (e) => {
      e.preventDefault();
      const container = mainRef.current;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const startWidth = topologyWidth ?? rect.width * (2 / 3) - RESIZER_WIDTH / 2;
      setIsResizing(true);

      const handleMove = (moveEvent) => {
        const next = clampTopologyWidth(startWidth + (moveEvent.clientX - e.clientX));
        setTopologyWidth(next);
      };
      const handleUp = (upEvent) => {
        window.removeEventListener("pointermove", handleMove);
        window.removeEventListener("pointerup", handleUp);
        setIsResizing(false);
        const finalWidth = clampTopologyWidth(startWidth + (upEvent.clientX - e.clientX));
        localStorage.setItem(TOPOLOGY_WIDTH_STORAGE_KEY, String(finalWidth));
      };
      window.addEventListener("pointermove", handleMove);
      window.addEventListener("pointerup", handleUp);
    },
    [topologyWidth, clampTopologyWidth]
  );

  const segs = state?.segments ? Object.values(state.segments) : [];
  const agents = state?.agents || {};
  const logs = state?.logs || [];
  const ballots = state?.ballots || { open: [], resolved: [] };
  const packets = state?.packets || [];
  const metrics = state?.metrics || { dr: 0, fpr: 0, mttr: 0, availability: 0, sw: 0 };
  const elapsed = state?.t || 0;
  const segMap = Object.fromEntries(segs.map((s) => [s.id, s]));

  const activeSegId = segMap[selectedSeg] ? selectedSeg : segs[0]?.id;
  const selectedSegData = (activeSegId && segMap[activeSegId]) || segs[0] || {};

  const packetTopology = useMemo(
    () => ({ selectedSeg: activeSegId || selectedSeg, hosts: selectedSegData?.hosts || [] }),
    [activeSegId, selectedSeg, selectedSegData?.hosts]
  );
  usePacketCanvas(canvasRef, state, packetTopology);
  // Each segment tracks its own scenario independently — switching which
  // network you're viewing never starts/stops/resets anything, it just
  // changes what you're looking at.
  const scenario = selectedSegData.scenario || "calm";
  const scenarioAtk = ["ddos", "scan"].includes(scenario);

  const links = useMemo(() => {
    const hostSlotKeys = ["A", "B", "C", "D", "E"].slice(0, Math.min(5, selectedSegData?.hosts?.length || 0));
    const base = [
      { x1: POS.attacker.x, y1: POS.attacker.y, x2: POS.edge.x, y2: POS.edge.y },
      { x1: POS.legit.x, y1: POS.legit.y, x2: POS.edge.x, y2: POS.edge.y },
      { x1: POS.edge.x, y1: POS.edge.y, x2: POS.core.x, y2: POS.core.y },
    ];
    hostSlotKeys.forEach((k) => {
      base.push({ x1: POS.core.x, y1: POS.core.y, x2: POS[k].x, y2: POS[k].y });
    });
    base.push({ x1: POS.core.x, y1: POS.core.y, x2: POS.tma.x, y2: POS.tma.y });
    return base.map((l) => {
      const attacked = scenarioAtk && selectedSegData.state !== "NORMAL";
      const color = l.x2 === POS.attacker.x || (attacked && l.x1 === POS.edge.x) ? "#e7b6b0" : "#d3dae1";
      return { ...l, color, w: 3 };
    });
  }, [scenarioAtk, selectedSegData.state, selectedSegData.hosts]);

  return (
    <div className="dashboard-app" data-screen-label="Live Dashboard">
      <ConnectionBanner connected={connected} />

      <SegmentCards segments={segs} selectedSeg={activeSegId || selectedSeg} setSelectedSeg={setSelSeg} segMap={segMap} />

      <ScenarioMetricsBar
        scenario={scenario}
        elapsed={elapsed}
        metrics={metrics}
        wsReady={wsReady}
        sendScenario={sendScenario}
        sendControl={sendControl}
        running={state?.running ?? true}
        selectedSeg={activeSegId || selectedSeg}
      />

      <div
        className={`dashboard-main${isResizing ? " is-resizing" : ""}`}
        ref={mainRef}
        style={topologyWidth !== null ? { "--topology-width": `${topologyWidth}px` } : undefined}
      >
        <TopologyStage
          selectedSeg={activeSegId || selectedSeg}
          selectedSegData={selectedSegData}
          scenarioAtk={scenarioAtk}
          links={links}
          agents={agents}
          selAgent={selAgent}
          setSelAgent={setSelAgent}
          canvasRef={canvasRef}
        />

        <PanelResizer onPointerDown={handleResizeStart} active={isResizing} />

        <RightRail
          segments={segs}
          segMap={segMap}
          selectedSeg={activeSegId || selectedSeg}
          setSelectedSeg={setSelSeg}
          logs={logs}
          ballots={ballots}
          packets={packets}
        />
      </div>

      <div className="dashboard-spacer" />

      {selAgent && agents[selAgent] && <AgentInspector agent={agents[selAgent]} onClose={() => setSelAgent(null)} />}
    </div>
  );
}

export default LiveDashboardPage;
