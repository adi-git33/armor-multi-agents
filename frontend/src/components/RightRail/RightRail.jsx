import { C } from "../../dashboard/constants";
import { healthColor } from "../../dashboard/utils";
import Sparkline from "../Sparkline/Sparkline";
import {
  AttackPps,
  EmptyLogs,
  EventCount,
  HeaderMeta,
  HeaderTitle,
  LogDot,
  LogItem,
  LogList,
  LogMeta,
  LogPanel,
  LogText,
  LogTextWrap,
  Panel,
  PanelHeader,
  RailWrap,
  SegmentLabel,
  SegmentName,
  SegmentMetaRow,
  SegmentPps,
  SegmentRow,
  SegmentValues,
} from "./RightRail.styled";

function RightRail({ segments, segMap, selectedSeg, setSelectedSeg, logs }) {
  return (
    <RailWrap>
      <Panel>
        <PanelHeader>
          <HeaderTitle>BANDWIDTH</HeaderTitle>
          <HeaderMeta>pps · live</HeaderMeta>
        </PanelHeader>
        {segments.map((seg) => {
          const sd = segMap[seg.id] || { hist: [], pps: 0, state: "NORMAL" };
          const bl = sd.baseline || 400;
          const active = selectedSeg === seg.id;
          const hc = healthColor(sd.state || "NORMAL");
          return (
            <SegmentRow key={seg.id} onClick={() => setSelectedSeg(seg.id)} active={active ? 1 : 0}>
              <SegmentMetaRow>
                <SegmentLabel>
                  {seg.code} <SegmentName>{seg.name}</SegmentName>
                </SegmentLabel>
                <SegmentValues>
                  <SegmentPps valuecolor={hc}>{(sd.pps || 0).toFixed(0)} pps</SegmentPps>
                  {sd.attack_pps > 0 && (
                    <AttackPps textcolor={C.red}>+{sd.attack_pps.toFixed(0)} atk</AttackPps>
                  )}
                </SegmentValues>
              </SegmentMetaRow>
              <Sparkline hist={sd.hist || []} baseline={bl} health={sd.state || "NORMAL"} />
            </SegmentRow>
          );
        })}
      </Panel>

      <LogPanel>
        <PanelHeader>
          <HeaderTitle>ACTIVITY LOG</HeaderTitle>
          <EventCount>{logs.length} events</EventCount>
        </PanelHeader>
        <LogList>
          {logs.length === 0 ? (
            <EmptyLogs>Waiting for events...</EmptyLogs>
          ) : (
            logs.map((ev) => (
              <LogItem key={ev.id}>
                <LogDot dotcolor={ev.color} />
                <LogTextWrap>
                  <LogText>{ev.text}</LogText>
                  <LogMeta>
                    {ev.time} · {ev.agent}
                  </LogMeta>
                </LogTextWrap>
              </LogItem>
            ))
          )}
        </LogList>
      </LogPanel>
    </RailWrap>
  );
}

export default RightRail;
