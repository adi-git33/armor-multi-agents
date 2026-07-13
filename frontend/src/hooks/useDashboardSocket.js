import { useCallback, useEffect, useRef, useState } from "react";
import { getWsUrl } from "../dashboard/utils";

const WS_URL = getWsUrl();

export function useDashboardSocket() {
  const [state, setState] = useState(null);
  const [connected, setConnected] = useState(false);
  const [wsReady, setWsReady] = useState(false);

  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);

  useEffect(() => {
    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setWsReady(true);
      };

      ws.onclose = () => {
        setConnected(false);
        setWsReady(false);
        reconnectTimerRef.current = setTimeout(connect, 2000);
      };

      ws.onerror = () => {
        ws.close();
      };

      ws.onmessage = (e) => {
        const data = JSON.parse(e.data);
        setState(data);
      };
    }

    connect();
    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const sendScenario = useCallback((name, segment) => {
    const payload = JSON.stringify({ type: "scenario", name, segment });
    const ws = wsRef.current;

    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
      return;
    }

    const tempWs = new WebSocket(WS_URL);
    tempWs.onopen = () => {
      tempWs.send(payload);
      setTimeout(() => tempWs.close(), 300);
    };
  }, []);

  return { state, connected, wsReady, sendScenario };
}
