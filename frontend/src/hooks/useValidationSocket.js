import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
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
  charts: [],
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
        charts: action.charts,
        lastRunAt: Date.now(),
      };
    }
    case "run-error": {
      return { ...state, running: false, runningKey: null, lastError: action.message };
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
          case "run-completed":
            dispatch({
              type: "run-completed",
              total: evt.total,
              passed: evt.passed,
              failed: evt.failed,
              allOk: evt.all_ok,
              wallSec: evt.wall_sec,
              targetTable: evt.target_table,
              charts: evt.charts || [],
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

  const chartUrls = useMemo(
    () => state.charts.map((path) => `${getBackendOrigin()}${path}?t=${state.lastRunAt || 0}`),
    [state.charts, state.lastRunAt]
  );

  return { ...state, connected, suites, runSuite, runAll, chartUrls };
}
