import { useMemo } from "react";
import { C } from "../../dashboard/constants";
import { EventCount, HeaderMeta, HeaderTitle, LogPanel, PanelHeader } from "../RightRail/RightRail.styled";
import { Caption, EmptyStream, KindBadge, PktFlow, PktMeta, PktRow, StreamList } from "./PacketStream.styled";

const KIND_COLOR = { legit: C.green, attack: C.red };
const WINDOW_SECS = 2;

function PacketStream({ packets, selectedSeg, segName, quarantined, sx }) {
  const list = packets || [];

  const scoped = useMemo(() => {
    if (quarantined) return [];
    const forSeg = selectedSeg ? list.filter((p) => p.segment === selectedSeg) : list;
    if (forSeg.length === 0) return forSeg;
    // Always show a rolling last-2-seconds window for the selected network,
    // so switching networks reliably shows recent activity rather than
    // whatever happened to survive in the shared, longer-lived buffer.
    const latestT = forSeg[forSeg.length - 1].t;
    return forSeg.filter((p) => p.t >= latestT - WINDOW_SECS);
  }, [list, selectedSeg, quarantined]);

  // Newest first — packets arrive in send order from the backend.
  const ordered = scoped.slice().reverse();

  return (
    <LogPanel sx={sx}>
      <PanelHeader>
        <HeaderTitle>PACKET STREAM · {segName || "ALL"}</HeaderTitle>
        <EventCount>{ordered.length} in last {WINDOW_SECS}s</EventCount>
      </PanelHeader>
      <Caption>Sampled, not every packet — real traffic patterns, rate-limited for display.</Caption>
      <StreamList>
        {quarantined ? (
          <EmptyStream>Segment quarantined — no traffic permitted.</EmptyStream>
        ) : ordered.length === 0 ? (
          <EmptyStream>No recent traffic on this network.</EmptyStream>
        ) : (
          ordered.map((p) => (
            <PktRow key={p.id}>
              <KindBadge tagcolor={KIND_COLOR[p.kind] || C.idle}>{p.kind === "attack" ? "ATK" : "OK"}</KindBadge>
              <PktFlow title={p.label}>
                {p.src_ip}:{p.src_port} → {p.dst_ip}:{p.dst_port}
              </PktFlow>
              <PktMeta>
                {p.protocol} · {p.size}b
              </PktMeta>
            </PktRow>
          ))
        )}
      </StreamList>
    </LogPanel>
  );
}

export default PacketStream;
