import { useMemo, useState } from "react";
import { C, PERF_COLOR } from "../../dashboard/constants";
import { healthColor } from "../../dashboard/utils";
import PacketStream from "../PacketStream/PacketStream";
import Sparkline from "../Sparkline/Sparkline";
import VotingPanel from "../VotingPanel/VotingPanel";
import {
  AttackPps,
  EmptyLogs,
  EventCount,
  FilterChip,
  FilterRow,
  HeaderMeta,
  HeaderTitle,
  LogDot,
  LogHeaderRow,
  LogItem,
  LogList,
  LogMeta,
  LogPanel,
  LogText,
  LogTextWrap,
  Panel,
  PanelHeader,
  PerfTag,
  RailWrap,
  SegmentLabel,
  SegmentName,
  SegmentMetaRow,
  SegmentPps,
  SegmentRow,
  SegmentValues,
} from "./RightRail.styled";

const PERF_FILTERS = ["ALL", "INFORM", "CALL-FOR-PROPOSAL", "ACCEPT", "REJECT", "FAILURE"];

function RightRail({ segments, segMap, selectedSeg, setSelectedSeg, logs, ballots, packets }) {
  const [perfFilter, setPerfFilter] = useState("ALL");

  const filteredLogs = useMemo(() => {
    if (perfFilter === "ALL") return logs;
    return logs.filter((ev) => ev.perf === perfFilter);
  }, [logs, perfFilter]);

  const segName = segMap[selectedSeg]?.name || segMap[selectedSeg]?.code;

  return (
    <RailWrap>
      <Panel sx={{ flex: "0 1 190px" }}>
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

      <LogPanel sx={{ flex: "1.4 1 0" }}>
        <PanelHeader>
          <HeaderTitle>ACTIVITY LOG</HeaderTitle>
          <EventCount>{filteredLogs.length} events</EventCount>
        </PanelHeader>
        <FilterRow>
          {PERF_FILTERS.map((p) => (
            <FilterChip key={p} active={perfFilter === p ? 1 : 0} onClick={() => setPerfFilter(p)}>
              {p}
            </FilterChip>
          ))}
        </FilterRow>
        <LogList>
          {filteredLogs.length === 0 ? (
            <EmptyLogs>Waiting for events...</EmptyLogs>
          ) : (
            filteredLogs.map((ev) => (
              <LogItem key={ev.id}>
                <LogDot dotcolor={ev.color} />
                <LogTextWrap>
                  {ev.perf && (
                    <LogHeaderRow>
                      <PerfTag tagcolor={PERF_COLOR[ev.perf] || C.idle}>{ev.perf}</PerfTag>
                    </LogHeaderRow>
                  )}
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

      <VotingPanel ballots={ballots} selectedSeg={selectedSeg} segName={segName} sx={{ flex: "1 1 0" }} />
      <PacketStream
        packets={packets}
        selectedSeg={selectedSeg}
        segName={segName}
        quarantined={segMap[selectedSeg]?.state === "QUARANTINED"}
        sx={{ flex: "1 1 0" }}
      />
    </RailWrap>
  );
}

export default RightRail;
