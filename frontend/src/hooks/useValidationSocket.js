import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { getBackendOrigin, getValidationWsUrl } from "../dashboard/utils";

const WS_URL = getValidationWsUrl();
const MAX_LIVE_FEED = 250;

const initialState = {
  running: false,
  runningKey: null,
  perSuite: {},       // key -> { label, status, results[], passCount, totalCount, wallSec, errorMessage }
  liveFeed: [],        // most-recent-first, capped
  targetTable: null,
  overallVerdict: null,
  metrics: null,
  lastRunAt: null,
  lastError: null,
};

function reducer(state, action) {
  switch (action.type) {
    case "run-start": {
      const perSuite = { ...state.perSuite };
      for (const key of action.keys) {
        perSuite[key] = { ...(perSuite[key] || {}), status: "queued", results: [] };
      }
      return { ...state, running: true, runningKey: null, lastError: null, perSuite };
    }
    case "suite-started": {
      const perSuite = { ...state.perSuite };
      perSuite[action.key] = { ...(perSuite[action.key] || {}), label: action.label, status: "running", results: [] };
      return { ...state, runningKey: action.key, perSuite };
    }
    case "check-completed": {
      const perSuite = { ...state.perSuite };
      const cur = perSuite[action.key] || { results: [] };
      perSuite[action.key] = { ...cur, results: [...cur.results, action.result] };
      const liveFeed = [{ ...action.result, key: action.key }, ...state.liveFeed].slice(0, MAX_LIVE_FEED);
      return { ...state, perSuite, liveFeed };
    }
    case "suite-completed": {
      const perSuite = { ...state.perSuite };
      perSuite[action.key] = {
        ...(perSuite[action.key] || {}),
        label: action.label,
        status: "done",
        passCount: action.passCount,
        totalCount: action.totalCount,
        allPassed: action.allPassed,
        wallSec: action.wallSec,
      };
      return { ...state, perSuite };
    }
    case "suite-error": {
      const perSuite = { ...state.perSuite };
      perSuite[action.key] = { ...(perSuite[action.key] || {}), label: action.label, status: "error", errorMessage: action.message };
      return { ...state, perSuite };
    }
    case "suite-cancelled": {
      const perSuite = { ...state.perSuite };
      perSuite[action.key] = { ...(perSuite[action.key] || {}), label: action.label, status: "cancelled" };
      return { ...state, perSuite };
    }
    case "run-cancelled": {
      return { ...state, running: false, runningKey: null };
    }
    case "run-completed": {
      return {
        ...state,
        running: false,
        runningKey: null,
        targetTable: action.targetTable,
        overallVerdict: {
          total: action.total,
          passed: action.passed,
          failed: action.failed,
          allOk: action.allOk,
          wallSec: action.wallSec,
        },
        metrics: action.metrics,
        lastRunAt: Date.now(),
      };
    }
    case "run-error": {
      return { ...state, running: false, runningKey: null, lastError: action.message };
    }
    case "hydrate": {
      // Only applies before the user has run (or started running) anything
      // in this session — a fetched-on-mount snapshot must never clobber
      // live/just-finished results.
      if (state.running || state.lastRunAt !== null) return state;
      const perSuite = {};
      for (const [key, s] of Object.entries(action.data.per_suite || {})) {
        perSuite[key] = {
          label: s.label,
          status: s.status,
          results: s.results || [],
          passCount: s.pass_count,
          totalCount: s.total_count,
          allPassed: s.all_passed,
          wallSec: s.wall_sec,
          errorMessage: s.error_message,
        };
      }
      return {
        ...state,
        perSuite,
        targetTable: action.data.target_table || null,
        overallVerdict: {
          total: action.data.total,
          passed: action.data.passed,
          failed: action.data.failed,
          allOk: action.data.all_ok,
          wallSec: action.data.wall_sec,
        },
        metrics: action.data.metrics || null,
        lastRunAt: action.data.timestamp ? action.data.timestamp * 1000 : Date.now(),
      };
    }
    default:
      return state;
  }
}

export function useValidationSocket() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [connected, setConnected] = useState(false);
  const [suites, setSuites] = useState([]);
  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);

  useEffect(() => {
    fetch(`${getBackendOrigin()}/api/validation/suites`)
      .then((r) => r.json())
      .then((d) => setSuites(d.suites || []))
      .catch(() => setSuites([]));
  }, []);

  // Reload whatever the last validation run (from any previous session)
  // produced, so reopening the page doesn't start from a blank slate.
  useEffect(() => {
    fetch(`${getBackendOrigin()}/api/validation/last`)
      .then((r) => r.json())
      .then((d) => {
        if (d && d.available) dispatch({ type: "hydrate", data: d });
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        reconnectTimerRef.current = setTimeout(connect, 2000);
      };
      ws.onerror = () => ws.close();

      ws.onmessage = (e) => {
        let evt;
        try {
          evt = JSON.parse(e.data);
        } catch {
          return;
        }
        switch (evt.type) {
          case "suite-started":
            dispatch({ type: "suite-started", key: evt.key, label: evt.label });
            break;
          case "check-completed":
            dispatch({
              type: "check-completed",
              key: evt.key,
              result: {
                req_id: evt.req_id,
                label: evt.label,
                passed: evt.passed,
                observed: evt.observed,
                expected: evt.expected,
                note: evt.note,
              },
            });
            break;
          case "suite-completed":
            dispatch({
              type: "suite-completed",
              key: evt.key,
              label: evt.label,
              passCount: evt.pass_count,
              totalCount: evt.total_count,
              allPassed: evt.all_passed,
              wallSec: evt.wall_sec,
            });
            break;
          case "suite-error":
            dispatch({ type: "suite-error", key: evt.key, label: evt.label, message: evt.message });
            break;
          case "suite-cancelled":
            dispatch({ type: "suite-cancelled", key: evt.key, label: evt.label });
            break;
          case "run-cancelled":
            dispatch({ type: "run-cancelled" });
            break;
          case "run-completed":
            dispatch({
              type: "run-completed",
              total: evt.total,
              passed: evt.passed,
              failed: evt.failed,
              allOk: evt.all_ok,
              wallSec: evt.wall_sec,
              targetTable: evt.target_table,
              metrics: evt.metrics || null,
            });
            break;
          case "error":
            dispatch({ type: "run-error", message: evt.message });
            break;
          default:
            break;
        }
      };
    }

    connect();
    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const runSuite = useCallback(
    (key) => {
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN || state.running) return;
      dispatch({ type: "run-start", keys: [key] });
      ws.send(JSON.stringify({ type: "run", suite: key }));
    },
    [state.running]
  );

  const runAll = useCallback(
    (allKeys) => {
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN || state.running) return;
      dispatch({ type: "run-start", keys: allKeys });
      ws.send(JSON.stringify({ type: "run", suite: "all" }));
    },
    [state.running]
  );

  const runAllScenarios = useCallback(
    (scenarioKeys) => {
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN || state.running) return;
      dispatch({ type: "run-start", keys: scenarioKeys });
      ws.send(JSON.stringify({ type: "run", suite: "all_scenarios" }));
    },
    [state.running]
  );

  const cancelRun = useCallback(() => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN || !state.running) return;
    ws.send(JSON.stringify({ type: "cancel" }));
  }, [state.running]);

  return { ...state, connected, suites, runSuite, runAll, runAllScenarios, cancelRun };
}
