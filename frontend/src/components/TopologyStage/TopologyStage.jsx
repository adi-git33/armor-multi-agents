import { useEffect, useRef, useState } from "react";
import { BUS_AGENTS, C, HOSTLEFT, HOSTTOP, LEGEND } from "../../dashboard/constants";
import { healthBorder, healthColor, stateColor } from "../../dashboard/utils";
import {
  AgentChip,
  AgentChipDot,
  AgentChipMeta,
  AgentChipTitle,
  AgentChipTitleRow,
  AttackerNode,
  BusLabel,
  BusLabelWrap,
  CoreNode,
  EdgeNode,
  HostCard,
  HostDot,
  HostIconWrap,
  HostInfo,
  HostMeta,
  HostMetaLight,
  HostTitle,
  HostTitleRow,
  LegitNode,
  LabelGroup,
  LabelSub,
  LabelSubLight,
  LabelTitle,
  LayerSvg,
  LegendDot,
  LegendItem,
  LegendLabel,
  LegendRow,
  PacketCanvas,
  StageHeader,
  StageHint,
  StagePaper,
  StageSurface,
  StageTitle,
  StageViewport,
  StageScaleFrame,
  TmaChip,
  TmaIconWrap,
} from "./TopologyStage.styled";

function TopologyStage({
  selectedSeg,
  selectedSegData,
  scenarioAtk,
  links,
  agents,
  selAgent,
  setSelAgent,
  canvasRef,
}) {
  const viewportRef = useRef(null);
  const [stageYScale, setStageYScale] = useState(1);
  const [stageXScale, setStageXScale] = useState(1);

  useEffect(() => {
    const BASE_HEIGHT = 700;
    const BASE_WIDTH = 1180;
    const MIN_SCALE = 0.5;

    const recalc = () => {
      if (!viewportRef.current) return;
      const rect = viewportRef.current.getBoundingClientRect();
      const heightScale = rect.height / BASE_HEIGHT;
      const widthScale = rect.width / BASE_WIDTH;
      setStageYScale(Math.max(MIN_SCALE, Math.min(1, heightScale)));
      setStageXScale(Math.max(MIN_SCALE, Math.min(1, widthScale)));
    };

    const observer = new ResizeObserver(recalc);
    if (viewportRef.current) observer.observe(viewportRef.current);
    window.addEventListener("resize", recalc);
    recalc();

    return () => {
      observer.disconnect();
      window.removeEventListener("resize", recalc);
    };
  }, []);

  const formatRole = (role) => role.replaceAll("-", " ");
  const hosts = selectedSegData?.hosts || [];
  const visibleHosts = hosts.slice(0, 5).map((h, idx) => {
    const slotKey = ["A", "B", "C", "D", "E"][idx];
    return {
      slotKey,
      name: formatRole(h.role),
      host: h.hostname,
      ip: h.ip,
    };
  });

  return (
    <StagePaper>
      <StageHeader>
        <StageTitle>
          NETWORK TOPOLOGY · {selectedSegData?.name || selectedSeg}
        </StageTitle>
        <StageHint>
          click agent or host to inspect · pub/sub bus below
        </StageHint>
      </StageHeader>

      <StageViewport ref={viewportRef}>
      <StageScaleFrame yscale={stageYScale} xscale={stageXScale}>
      <StageSurface yscale={stageYScale} xscale={stageXScale}>
        <LayerSvg width="1180" height="700" viewBox="0 0 1180 700">
          {links.map((l, i) => (
            <line key={i} x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} stroke={l.color} strokeWidth={l.w} strokeLinecap="round" />
          ))}
          <line x1="60" y1="605" x2="1120" y2="605" stroke="#cfd6dd" strokeWidth="1.5" />
          {/* Connect TMA node into the bus layer */}
          <line x1="430" y1="500" x2="430" y2="605" stroke="#cfd6dd" strokeWidth="1.5" />
          {/* Connect bus layer into each agent chip */}
          <line x1="226" y1="605" x2="226" y2="630" stroke="#cfd6dd" strokeWidth="1.5" />
          <line x1="486" y1="605" x2="486" y2="630" stroke="#cfd6dd" strokeWidth="1.5" />
          <line x1="716" y1="605" x2="716" y2="630" stroke="#cfd6dd" strokeWidth="1.5" />
          <line x1="966" y1="605" x2="966" y2="630" stroke="#cfd6dd" strokeWidth="1.5" />
        </LayerSvg>

        <PacketCanvas ref={canvasRef} />

        <AttackerNode activeattack={scenarioAtk ? 1 : 0}>
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke={scenarioAtk ? C.red : "#cdd5dd"} strokeWidth="1.6">
            <path d="M6 17h11a3.5 3.5 0 0 0 .5-6.96A5 5 0 0 0 8 9.2 4 4 0 0 0 6 17z" />
          </svg>
        </AttackerNode>
        <LabelGroup leftpos={60} toppos={158} widthval={160}>
          <LabelTitle titlecolor={scenarioAtk ? C.red : "#2b3440"}>Attacker / WAN</LabelTitle>
          <LabelSubLight>0.0.0.0/0</LabelSubLight>
        </LabelGroup>

        <LegitNode>
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke={C.green} strokeWidth="1.6">
            <path d="M6 17h11a3.5 3.5 0 0 0 .5-6.96A5 5 0 0 0 8 9.2 4 4 0 0 0 6 17z" />
          </svg>
        </LegitNode>
        <LabelGroup leftpos={220} toppos={158} widthval={160}>
          <LabelTitle titlecolor={C.green}>Legitimate Clients</LabelTitle>
          <LabelSubLight>trusted internet traffic</LabelSubLight>
        </LabelGroup>

        <EdgeNode>
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#5b6675" strokeWidth="1.5">
            <circle cx="12" cy="12" r="3" />
            <path d="M12 2v4M12 18v4M2 12h4M18 12h4M5 5l2.5 2.5M16.5 16.5L19 19M19 5l-2.5 2.5M7.5 16.5L5 19" />
          </svg>
        </EdgeNode>
        <LabelGroup leftpos={134} toppos={368} widthval={172}>
          <LabelTitle>Edge Router</LabelTitle>
          <LabelSub>segment gateway</LabelSub>
          <LabelSubLight>{selectedSegData?.cidr || "—"}</LabelSubLight>
        </LabelGroup>

        <CoreNode>
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#5b6675" strokeWidth="1.5">
            <rect x="3" y="8" width="18" height="9" rx="2" />
            <path d="M7 12h.01M11 12h.01M15 12h.01" />
          </svg>
        </CoreNode>
        <LabelGroup leftpos={344} toppos={366} widthval={172}>
          <LabelTitle>Core Switch</LabelTitle>
          <LabelSub>switch fabric</LabelSub>
        </LabelGroup>

        {(() => {
          const tma = agents["TMA:1"];
          const sc2 = stateColor(tma?.state || "mon");
          return (
            <TmaChip
              onClick={() => setSelAgent(selAgent === "TMA:1" ? null : "TMA:1")}
              selected={selAgent === "TMA:1" ? 1 : 0}
            >
              <TmaIconWrap iconbg={`${sc2}18`}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={sc2} strokeWidth="1.8">
                  <circle cx="11" cy="11" r="7" />
                  <path d="M21 21l-4.3-4.3" />
                </svg>
              </TmaIconWrap>
              <HostInfo>
                <HostTitle>TMA-1</HostTitle>
                <HostMeta>Traffic Monitor · SPAN</HostMeta>
              </HostInfo>
            </TmaChip>
          );
        })()}

        {visibleHosts.map((slot) => {
          const segState = selectedSegData.state || "NORMAL";
          const hc = healthColor(segState);
          const hb = healthBorder(segState);
          return (
            <HostCard
              key={slot.slotKey}
              leftpos={HOSTLEFT[slot.slotKey]}
              toppos={HOSTTOP[slot.slotKey]}
              bordercolor={hb}
            >
              <HostIconWrap iconbg={`${hc}14`}>
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke={hc} strokeWidth="1.5">
                  <rect x="4" y="3" width="16" height="7" rx="1.5" />
                  <rect x="4" y="14" width="16" height="7" rx="1.5" />
                  <path d="M8 6.5h.01M8 17.5h.01" />
                </svg>
              </HostIconWrap>
              <HostInfo>
                <HostTitleRow>
                  <HostTitle>{slot.name}</HostTitle>
                  <HostDot dotcolor={hc} />
                </HostTitleRow>
                <HostMeta>{slot.host}</HostMeta>
                <HostMetaLight>{slot.ip}</HostMetaLight>
              </HostInfo>
            </HostCard>
          );
        })}

        <BusLabelWrap>
          <BusLabel>PUB / SUB MESSAGE BUS · MAS COORDINATION LAYER</BusLabel>
        </BusLabelWrap>

        {BUS_AGENTS.map((ba) => {
          const ag = agents[ba.id];
          const sc2 = stateColor(ag?.state || "idle");
          const posX = { "ACA:1": 150, "TIA:1": 410, "RCA:1": 640, "RAA:1": 890 }[ba.id] || 0;
          const selected = selAgent === ba.id;
          return (
            <AgentChip
              key={ba.id}
              onClick={() => setSelAgent(selected ? null : ba.id)}
              leftpos={posX}
              selected={selected ? 1 : 0}
              accent={ba.accent}
            >
              <AgentChipTitleRow>
                <AgentChipDot dotcolor={sc2} />
                <AgentChipTitle>{ba.code}</AgentChipTitle>
              </AgentChipTitleRow>
              <AgentChipMeta>{ba.role}</AgentChipMeta>
            </AgentChip>
          );
        })}
      </StageSurface>
      </StageScaleFrame>
      </StageViewport>

      <LegendRow>
        <LegendLabel>LEGEND</LegendLabel>
        {LEGEND.map((l) => (
          <LegendItem key={l.label}>
            <LegendDot dotcolor={l.color} />
            {l.label}
          </LegendItem>
        ))}
      </LegendRow>
    </StagePaper>
  );
}

export default TopologyStage;
