import { useMemo, useRef, useState } from "react";
import "./App.css";
import AgentInspector from "./components/AgentInspector/AgentInspector";
import ConnectionBanner from "./components/ConnectionBanner/ConnectionBanner";
import RightRail from "./components/RightRail/RightRail";
import ScenarioMetricsBar from "./components/ScenarioMetricsBar/ScenarioMetricsBar";
import SegmentCards from "./components/SegmentCards/SegmentCards";
import TopologyStage from "./components/TopologyStage/TopologyStage";
import { POS } from "./dashboard/constants";
import { useDashboardSocket } from "./hooks/useDashboardSocket";
import { usePacketCanvas } from "./hooks/usePacketCanvas";

function App() {
  const [selectedSeg, setSelSeg] = useState("public-facing");
  const [selAgent, setSelAgent] = useState(null);
  const { state, connected, wsReady, sendScenario } = useDashboardSocket();
  const canvasRef = useRef(null);

  usePacketCanvas(canvasRef, state);

  const segs = state?.segments ? Object.values(state.segments) : [];
  const agents = state?.agents || {};
  const logs = state?.logs || [];
  const metrics = state?.metrics || { dr: 0, fpr: 0, mttr: 0, availability: 0, sw: 0 };
  const scenario = state?.scenario || "calm";
  const elapsed = state?.t || 0;
  const segMap = Object.fromEntries(segs.map((s) => [s.id, s]));

  const activeSegId = segMap[selectedSeg] ? selectedSeg : segs[0]?.id;
  const selectedSegData = (activeSegId && segMap[activeSegId]) || segs[0] || {};
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
    <div className="dashboard-app">
      <ConnectionBanner connected={connected} />

      <SegmentCards segments={segs} selectedSeg={activeSegId || selectedSeg} setSelectedSeg={setSelSeg} segMap={segMap} />

      <ScenarioMetricsBar scenario={scenario} elapsed={elapsed} metrics={metrics} wsReady={wsReady} sendScenario={sendScenario} />

      <div className="dashboard-main">
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

        <RightRail segments={segs} segMap={segMap} selectedSeg={activeSegId || selectedSeg} setSelectedSeg={setSelSeg} logs={logs} />
      </div>

      <div className="dashboard-spacer" />

      {selAgent && agents[selAgent] && <AgentInspector agent={agents[selAgent]} onClose={() => setSelAgent(null)} />}
    </div>
  );
}

export default App;
