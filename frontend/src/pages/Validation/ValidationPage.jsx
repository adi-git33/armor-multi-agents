import { useEffect, useMemo, useState } from "react";
import { Tooltip } from "@mui/material";
import ValidationCharts from "../../components/ValidationCharts/ValidationCharts";
import { C } from "../../dashboard/constants";
import { useValidationSocket } from "../../hooks/useValidationSocket";
import {
  Badge,
  ChartsHeaderRow,
  ChartsPanel,
  Chevron,
  ConnDot,
  ConnRow,
  ControlBar,
  ControlLabel,
  DetailHeader,
  DetailMeta,
  DetailSection,
  DetailTitle,
  EmptyRow,
  FeedDot,
  FeedKey,
  FeedReqId,
  FeedRow,
  FeedText,
  IdleNote,
  LiveFeedList,
  PageWrap,
  ProgressBody,
  ProgressHeader,
  ProgressMeta,
  ProgressPanel,
  ProgressTitle,
  ReqCell,
  RunAllButton,
  SuiteButton,
  SummaryCard,
  SummaryCode,
  SummaryFraction,
  SummaryGrid,
  SummaryStatusTag,
  SummaryTitle,
  TallyCell,
  TallyLabel,
  TallyRow,
  TallyValue,
  Table,
  TargetHeader,
  TargetPanel,
  TargetSub,
  TargetTitle,
  Td,
  Th,
  VerdictBanner,
} from "./ValidationPage.styled";

function badgeTone(verdict) {
  if (verdict === "PASS") return "pass";
  if (verdict === "FAIL") return "fail";
  return "skip";
}

function useElapsed(running) {
  const [, force] = useState(0);
  const [startedAt, setStartedAt] = useState(null);

  useEffect(() => {
    if (running && startedAt === null) setStartedAt(Date.now());
    if (!running) setStartedAt(null);
  }, [running, startedAt]);

  useEffect(() => {
    if (!running) return undefined;
    const id = setInterval(() => force((n) => n + 1), 500);
    return () => clearInterval(id);
  }, [running]);

  if (!running || startedAt === null) return 0;
  return (Date.now() - startedAt) / 1000;
}

function ValidationPage() {
  const {
    connected,
    suites,
    running,
    runningKey,
    perSuite,
    liveFeed,
    targetTable,
    overallVerdict,
    metrics,
    lastRunAt,
    lastError,
    runSuite,
    runAll,
    runAllScenarios,
  } = useValidationSocket();

  const [expanded, setExpanded] = useState({});
  const elapsed = useElapsed(running);

  const allKeys = useMemo(() => suites.map((s) => s.id), [suites]);
  const agentSuites = useMemo(() => suites.filter((s) => s.group !== "scenario"), [suites]);
  const scenarioSuites = useMemo(() => suites.filter((s) => s.group === "scenario"), [suites]);
  const scenarioKeys = useMemo(() => scenarioSuites.map((s) => s.id), [scenarioSuites]);

  const liveTally = useMemo(() => {
    let pass = 0;
    let fail = 0;
    for (const key of Object.keys(perSuite)) {
      for (const r of perSuite[key].results || []) {
        if (r.passed) pass += 1;
        else fail += 1;
      }
    }
    return { pass, fail, total: pass + fail };
  }, [perSuite]);

  const toggleExpanded = (key) => setExpanded((e) => ({ ...e, [key]: !e[key] }));

  const runningLabel = runningKey ? perSuite[runningKey]?.label || runningKey.toUpperCase() : null;

  const renderSuiteButton = (s) => {
    const suiteState = perSuite[s.id];
    const isRunningThis = runningKey === s.id;
    let toneColor = C.idle;
    if (suiteState?.status === "done") toneColor = suiteState.allPassed ? C.green : C.red;
    else if (suiteState?.status === "error") toneColor = C.red;
    else if (isRunningThis) toneColor = C.amber;
    return (
      <Tooltip key={s.id} title={s.title} arrow placement="top">
        <SuiteButton
          active={isRunningThis ? 1 : 0}
          toneColor={toneColor}
          disabled={running}
          onClick={() => runSuite(s.id)}
        >
          {s.label}
        </SuiteButton>
      </Tooltip>
    );
  };

  return (
    <PageWrap data-screen-label="Validation">
      <ControlBar>
        <ControlLabel>AGENT SUITES</ControlLabel>
        {agentSuites.map(renderSuiteButton)}
        <ConnRow>
          <ConnDot dotcolor={connected ? C.green : C.red} />
          {connected ? "connected" : "reconnecting…"}
        </ConnRow>
        <RunAllButton disabled={running || !connected} onClick={() => runAll(allKeys)}>
          RUN ALL
        </RunAllButton>
      </ControlBar>

      <ControlBar>
        <ControlLabel>SCENARIOS · SRS §8</ControlLabel>
        {scenarioSuites.map(renderSuiteButton)}
        <RunAllButton disabled={running || !connected} onClick={() => runAllScenarios(scenarioKeys)}>
          RUN ALL SCENARIOS
        </RunAllButton>
      </ControlBar>

      <ProgressPanel>
        <ProgressHeader>
          <ProgressTitle>LIVE PROGRESS</ProgressTitle>
          <ProgressMeta>
            {running
              ? `${runningLabel} · ${elapsed.toFixed(1)}s elapsed`
              : lastRunAt
              ? `last run ${new Date(lastRunAt).toLocaleTimeString()}`
              : "idle"}
          </ProgressMeta>
        </ProgressHeader>
        <ProgressBody>
          {!running && liveFeed.length === 0 && !lastRunAt && (
            <IdleNote>
              {lastError ? `Error: ${lastError}` : "No validation run yet — pick a suite above, or Run All."}
            </IdleNote>
          )}

          {!running && liveFeed.length === 0 && lastRunAt && (
            <IdleNote>
              Showing the last validation run ({new Date(lastRunAt).toLocaleString()}) — pick a suite above to run a fresh one.
            </IdleNote>
          )}

          {(running || liveFeed.length > 0) && (
            <TallyRow>
              <TallyCell>
                <TallyLabel>RUNNING</TallyLabel>
                <TallyValue valuecolor={running ? C.amber : C.idle}>{running ? runningLabel : "—"}</TallyValue>
              </TallyCell>
              <TallyCell>
                <TallyLabel>CHECKS SO FAR</TallyLabel>
                <TallyValue valuecolor="inherit">{liveTally.total}</TallyValue>
              </TallyCell>
              <TallyCell>
                <TallyLabel>PASS</TallyLabel>
                <TallyValue valuecolor={C.green}>{liveTally.pass}</TallyValue>
              </TallyCell>
              <TallyCell>
                <TallyLabel>FAIL</TallyLabel>
                <TallyValue valuecolor={liveTally.fail > 0 ? C.red : "inherit"}>{liveTally.fail}</TallyValue>
              </TallyCell>
            </TallyRow>
          )}

          {liveFeed.length > 0 && (
            <LiveFeedList>
              {liveFeed.slice(0, 12).map((r, i) => (
                <FeedRow key={`${r.key}-${r.req_id}-${i}`}>
                  <FeedDot dotcolor={r.passed ? C.green : C.red} />
                  <FeedReqId>{r.req_id}</FeedReqId>
                  <FeedText>{r.label}</FeedText>
                  <FeedKey>{r.key.toUpperCase()}</FeedKey>
                </FeedRow>
              ))}
            </LiveFeedList>
          )}
        </ProgressBody>
      </ProgressPanel>

      {Object.keys(perSuite).length > 0 && (
        <SummaryGrid>
          {suites
            .filter((s) => perSuite[s.id])
            .map((s) => {
              const suiteState = perSuite[s.id];
              const done = suiteState.status === "done";
              const border = done ? (suiteState.allPassed ? C.green : C.red) : suiteState.status === "error" ? C.red : undefined;
              return (
                <SummaryCard
                  key={s.id}
                  bordercolor={border}
                  clickable
                  onClick={() => toggleExpanded(s.id)}
                >
                  <SummaryCode>{s.label}</SummaryCode>
                  <SummaryTitle>{s.title}</SummaryTitle>
                  {done ? (
                    <SummaryFraction valuecolor={suiteState.allPassed ? C.green : C.red}>
                      {suiteState.passCount}/{suiteState.totalCount}
                    </SummaryFraction>
                  ) : suiteState.status === "error" ? (
                    <SummaryStatusTag valuecolor={C.red}>ERROR</SummaryStatusTag>
                  ) : (
                    <SummaryStatusTag valuecolor={C.amber}>
                      {suiteState.status === "running" ? "RUNNING…" : "QUEUED"}
                    </SummaryStatusTag>
                  )}
                </SummaryCard>
              );
            })}
        </SummaryGrid>
      )}

      {suites
        .filter((s) => perSuite[s.id]?.results?.length > 0)
        .map((s) => {
          const suiteState = perSuite[s.id];
          const isOpen = !!expanded[s.id];
          return (
            <DetailSection key={s.id}>
              <DetailHeader onClick={() => toggleExpanded(s.id)}>
                <Chevron open={isOpen ? 1 : 0}>▸</Chevron>
                <DetailTitle>{s.label} — {s.title}</DetailTitle>
                {suiteState.status === "done" && (
                  <DetailMeta valuecolor={suiteState.allPassed ? C.green : C.red}>
                    {suiteState.passCount}/{suiteState.totalCount} · {suiteState.wallSec}s
                  </DetailMeta>
                )}
              </DetailHeader>
              {isOpen && (
                <Table>
                  <thead>
                    <tr>
                      <Th style={{ width: 70 }}>REQ ID</Th>
                      <Th>CHECK</Th>
                      <Th style={{ width: 60 }}>STATUS</Th>
                      <Th>OBSERVED</Th>
                      <Th>EXPECTED</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {suiteState.results.map((r, i) => (
                      <tr key={`${r.req_id}-${i}`}>
                        <Td><ReqCell>{r.req_id}</ReqCell></Td>
                        <Td>
                          {r.note ? (
                            <Tooltip title={r.note} arrow placement="top">
                              <span style={{ borderBottom: "1px dotted currentColor", cursor: "help" }}>{r.label}</span>
                            </Tooltip>
                          ) : (
                            r.label
                          )}
                        </Td>
                        <Td><Badge tone={r.passed ? "pass" : "fail"}>{r.passed ? "PASS" : "FAIL"}</Badge></Td>
                        <Td>{r.observed ?? "—"}</Td>
                        <Td>{r.expected ?? "—"}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </DetailSection>
          );
        })}

      {targetTable && (
        <TargetPanel>
          <TargetHeader>
            <TargetTitle>SRS §7.3 — TARGET MAPPING</TargetTitle>
            <TargetSub>Headline result: every SRS/SDD performance target vs. what the last run actually observed.</TargetSub>
          </TargetHeader>
          {overallVerdict && (
            <VerdictBanner ok={overallVerdict.allOk}>
              {overallVerdict.allOk ? "ALL REQUIREMENTS MET" : "ONE OR MORE REQUIREMENTS NOT MET"} — {overallVerdict.passed}/{overallVerdict.total} checks passed · {overallVerdict.wallSec}s wall time
            </VerdictBanner>
          )}
          <Table>
            <thead>
              <tr>
                <Th>TARGET / CONSTRAINT</Th>
                <Th style={{ width: 110 }}>THRESHOLD</Th>
                <Th style={{ width: 140 }}>OBSERVED</Th>
                <Th style={{ width: 70 }}>VERDICT</Th>
              </tr>
            </thead>
            <tbody>
              {targetTable.map((row) => (
                <tr key={row.req_id + row.name}>
                  <Td>{row.name}</Td>
                  <Td>{row.threshold}</Td>
                  <Td>{row.observed}</Td>
                  <Td><Badge tone={badgeTone(row.verdict)}>{row.verdict}</Badge></Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </TargetPanel>
      )}

      <ChartsPanel>
        <ChartsHeaderRow>
          <DetailTitle>VALIDATION CHARTS</DetailTitle>
        </ChartsHeaderRow>
        {metrics ? (
          <ValidationCharts metrics={metrics} />
        ) : (
          <EmptyRow>No chart data yet — run a suite above.</EmptyRow>
        )}
      </ChartsPanel>
    </PageWrap>
  );
}

export default ValidationPage;
