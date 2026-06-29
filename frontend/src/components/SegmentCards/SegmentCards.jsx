import { healthBorder, healthColor } from "../../dashboard/utils";
import {
  SegmentCard,
  SegmentCidr,
  SegmentCode,
  SegmentGrid,
  SegmentInfo,
  SegmentName,
  SegmentState,
  StatusDot,
} from "./SegmentCards.styled";

function SegmentCards({ segments, selectedSeg, setSelectedSeg, segMap }) {
  return (
    <SegmentGrid>
      {segments.map((seg) => {
        const sd = segMap[seg.id] || seg;
        const hc = healthColor(sd.state || "NORMAL");
        const hb = healthBorder(sd.state || "NORMAL");
        const active = selectedSeg === seg.id;
        return (
          <SegmentCard
            key={seg.id}
            onClick={() => setSelectedSeg(seg.id)}
            activeborder={active ? hc : hb}
            activeglow={active ? `0 0 0 2px ${hc}22` : undefined}
          >
            <StatusDot dotcolor={hc} />
            <SegmentCode bgcolorcustom={active ? `${hc}18` : "#f3f5f7"} textcolorcustom={active ? hc : "#6b7685"}>
              {seg.code}
            </SegmentCode>
            <SegmentInfo>
              <SegmentName noWrap>{seg.name}</SegmentName>
              <SegmentCidr>{seg.cidr}</SegmentCidr>
            </SegmentInfo>
            <SegmentState statecolor={hc}>{sd.state || "NORMAL"}</SegmentState>
          </SegmentCard>
        );
      })}
    </SegmentGrid>
  );
}

export default SegmentCards;
