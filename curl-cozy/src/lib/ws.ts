import { websocketProtocols } from '@/lib/api-auth';
import { useEffect, useRef, useState, useCallback } from "react";
import { WS_URL, type ApiTrafficEntry, type HeldItem, type InterceptSettings } from "./api";
import { mapApiEntry, type Traffic } from "./traffic";

export type ConnectionStatus = "connecting" | "connected" | "disconnected";

/** Changes to the interceptor's queue or switches, pushed by the proxy. */
export type InterceptEvent =
  | { type: "queued"; item: HeldItem }
  | { type: "resolved"; id: string }
  | { type: "settings"; settings: InterceptSettings };

/**
 * React hook that connects to the Rust proxy WebSocket and streams
 * traffic events in real-time.
 *
 * Returns:
 * - `status` — current connection state
 * - `connect()` / `disconnect()` — manual control
 *
 * Calls `onNewEntry` whenever a new traffic entry arrives from the proxy.
 */
export function useTrafficStream(
  onNewEntry: (entry: Traffic) => void,
  onCleared?: (workspaceId?: string) => void,
  onWorkspacesChanged?: () => void,
  onIntercept?: (event: InterceptEvent) => void,
) {
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const onNewEntryRef = useRef(onNewEntry);
  const onClearedRef = useRef(onCleared);
  const onWorkspacesChangedRef = useRef(onWorkspacesChanged);
  const onInterceptRef = useRef(onIntercept);

  // Keep callback refs up to date without re-triggering effects
  useEffect(() => {
    onNewEntryRef.current = onNewEntry;
  }, [onNewEntry]);
  useEffect(() => {
    onClearedRef.current = onCleared;
  }, [onCleared]);
  useEffect(() => {
    onWorkspacesChangedRef.current = onWorkspacesChanged;
  }, [onWorkspacesChanged]);
  useEffect(() => {
    onInterceptRef.current = onIntercept;
  }, [onIntercept]);

  const connect = useCallback(() => {
    // Don't connect on the server side
    if (typeof window === "undefined") return;

    // Clean up previous connection
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setStatus("connecting");

    try {
      const ws = new WebSocket(WS_URL, websocketProtocols());
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus("connected");
        console.log("[ws] Connected to proxy");
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === "new_entry" && data.entry) {
            const mapped = mapApiEntry(data.entry as ApiTrafficEntry);
            onNewEntryRef.current(mapped);
          } else if (data.type === "entry_updated" && data.entry) {
            const mapped = mapApiEntry(data.entry as ApiTrafficEntry);
            onNewEntryRef.current(mapped);
          } else if (data.type === "entry_deleted") {
            window.dispatchEvent(new CustomEvent("slurp:traffic-deleted", {detail:data}));
          } else if (data.type === "cleared") {
            onClearedRef.current?.();
          } else if (data.type === "workspace_cleared") {
            onClearedRef.current?.(data.workspace_id as string);
          } else if (data.type === "workspaces_changed") {
            onWorkspacesChangedRef.current?.();
          } else if (data.type === "intercept_queued" && data.item) {
            onInterceptRef.current?.({ type: "queued", item: data.item as HeldItem });
          } else if (data.type === "intercept_resolved") {
            onInterceptRef.current?.({ type: "resolved", id: data.id as string });
          } else if (data.type === "intercept_settings") {
            onInterceptRef.current?.({
              type: "settings",
              settings: { requests: !!data.requests, responses: !!data.responses },
            });
          } else if (data.type === "annotation_changed") {
            window.dispatchEvent(new CustomEvent("httpdebugger:annotation", { detail: data }));
          } else if (data.type === "scope_changed") {
            window.dispatchEvent(new CustomEvent("httpdebugger:scope", { detail: data.scope }));
          } else if (data.type === "replay_changed" || data.type === "replay_result") {
            window.dispatchEvent(new CustomEvent("httpdebugger:replay", { detail: data }));
          } else if (data.type === "lagged") {
            console.warn(`[ws] Lagged by ${data.count} messages`);
          }
        } catch (e) {
          console.warn("[ws] Failed to parse message:", e);
        }
      };

      ws.onclose = (event) => {
        setStatus("disconnected");
        wsRef.current = null;
        console.log(`[ws] Disconnected (code: ${event.code})`);

        // Auto-reconnect after 3 seconds (unless intentionally closed)
        if (event.code !== 1000) {
          reconnectTimer.current = setTimeout(() => {
            console.log("[ws] Reconnecting...");
            connect();
          }, 3000);
        }
      };

      ws.onerror = (event) => {
        console.warn("[ws] WebSocket error:", event);
        // onclose will fire after this
      };
    } catch (e) {
      setStatus("disconnected");
      // Retry after a delay
      reconnectTimer.current = setTimeout(connect, 5000);
    }
  }, []);

  const disconnect = useCallback(() => {
    clearTimeout(reconnectTimer.current);
    if (wsRef.current) {
      wsRef.current.close(1000, "User disconnect");
      wsRef.current = null;
    }
    setStatus("disconnected");
  }, []);

  // Auto-connect on mount, disconnect on unmount
  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.close(1000, "Component unmount");
        wsRef.current = null;
      }
    };
  }, [connect]);

  return { status, connect, disconnect };
}
