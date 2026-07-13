import { C } from "../../dashboard/constants";
import { EventCount, HeaderMeta, HeaderTitle, LogPanel, PanelHeader } from "../RightRail/RightRail.styled";
import {
  BallotAction,
  BallotCard,
  BallotHeaderRow,
  BallotList,
  BallotSeg,
  EmptyBallots,
  OutcomeBadge,
  TallyRow,
  VoterDecision,
  VoterName,
  VoterRow,
} from "./VotingPanel.styled";

const OUTCOME_COLOR = { EXECUTED: C.green, REJECTED: C.red };
const DECISION_COLOR = { ACCEPT: C.green, REJECT: C.red };

function VoterList({ ballot }) {
  const rows = [
    // RCA casts its own vote the instant it calls the CFP (agents/rca.py
    // _call_vote) — that self-vote never travels over Topic.VOTES as a
    // separate message, so it's rendered here explicitly rather than
    // waiting for a bus event that will never arrive.
    { voter: ballot.proposer, decision: "ACCEPT", self: true },
    ...ballot.votes.map((v) => ({ voter: v.voter, decision: v.decision, self: false })),
  ];

  return rows.map((r, i) => (
    <VoterRow key={`${r.voter}-${i}`}>
      <VoterName>
        {r.voter}
        {r.self ? " (proposer)" : ""}
      </VoterName>
      <VoterDecision tagcolor={DECISION_COLOR[r.decision] || C.idle}>{r.decision}</VoterDecision>
    </VoterRow>
  ));
}

function VotingPanel({ ballots, selectedSeg, segName, sx }) {
  const openAll = ballots?.open || [];
  const resolvedAll = ballots?.resolved || [];
  const open = selectedSeg ? openAll.filter((b) => b.segment === selectedSeg) : openAll;
  const resolved = selectedSeg ? resolvedAll.filter((b) => b.segment === selectedSeg) : resolvedAll;
  const all = [...open, ...resolved.slice().reverse()];

  return (
    <LogPanel sx={sx}>
      <PanelHeader>
        <HeaderTitle>COALITION VOTES · {segName || "ALL"}</HeaderTitle>
        <HeaderMeta>{open.length} open</HeaderMeta>
      </PanelHeader>
      <BallotList>
        {all.length === 0 ? (
          <EmptyBallots>No coalition votes yet for this network — only QUARANTINE_SEGMENT requires one.</EmptyBallots>
        ) : (
          all.map((b) => {
            const isResolved = b.outcome != null;
            return (
              <BallotCard key={b.incident_id} resolved={isResolved ? 1 : 0}>
                <BallotHeaderRow>
                  <div>
                    <BallotAction>{b.action}</BallotAction>
                    <BallotSeg>{b.segment_name || b.segment}</BallotSeg>
                  </div>
                  {isResolved ? (
                    <OutcomeBadge tagcolor={OUTCOME_COLOR[b.outcome] || C.idle}>{b.outcome}</OutcomeBadge>
                  ) : (
                    <OutcomeBadge tagcolor={C.amber}>VOTING</OutcomeBadge>
                  )}
                </BallotHeaderRow>
                <VoterList ballot={b} />
                {isResolved && (
                  <TallyRow>
                    {b.votes_accept} accept / {b.votes_reject} reject
                  </TallyRow>
                )}
              </BallotCard>
            );
          })
        )}
      </BallotList>
    </LogPanel>
  );
}

export default VotingPanel;
