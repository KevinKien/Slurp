import { useOptionalScan } from "@/lib/scan-context";
import { useIntruder } from "@/lib/intruder-context";
import type { ReactElement } from "react";
import { Link } from "@tanstack/react-router";
import { ArrowUpRight, Copy, ScanLine } from "lucide-react";
import { toast } from "sonner";
import {
  ContextMenu,
  ContextMenuTrigger,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
} from "@/components/ui/context-menu";
import { useInspector } from "@/components/inspector";
import type { HttpRequest } from "@/lib/traffic";
import { isWebSocketRequest, websocketRequest } from "@/lib/websocket-request";
import { nextReplayTabId } from "@/lib/replay-tabs";
import { toCurl } from "@/lib/request-actions";

export function RequestMenu({
  request,
  children,
  disabled = false,
  websocketKind,
}: {
  request: HttpRequest | (() => HttpRequest | Promise<HttpRequest>);
  children: ReactElement;
  disabled?: boolean;
  websocketKind?: "text" | "binary";
}) {
  const { sessions, setSessions, setActive } = useInspector();
  const intruder = useIntruder();
  const scan = useOptionalScan();
  const read = () => (typeof request === "function" ? request() : request);
  const report = (error: unknown) =>
    toast.error(error instanceof Error ? error.message : "Request action failed");
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
      <ContextMenuContent className="w-56">
        <ContextMenuItem asChild disabled={disabled}>
          <Link
            to="/replay"
            className="gap-2"
            onClick={(event) => {
              const send = (source: HttpRequest) => {
                const url = new URL(source.url);
                if (!["http:", "https:", "ws:", "wss:"].includes(url.protocol))
                  throw new Error("Use an HTTP(S) or WS(S) URL.");
                const id = nextReplayTabId(sessions);
                const request = isWebSocketRequest(source) ? websocketRequest(source) : { ...source, headers: { ...source.headers } };
                setSessions((previous) => [...previous, { id, name: url.pathname, request, ...(isWebSocketRequest(request)&&websocketKind?{wsKind:websocketKind}:{}) }]);
                setActive(id);
              };
              try {
                const source = read();
                if (source instanceof Promise) void source.then(send).catch(report);
                else send(source);
              } catch (error) {
                event.preventDefault();
                report(error);
              }
            }}
          >
            <ArrowUpRight className="size-4" />
            Send to Replay
          </Link>
        </ContextMenuItem>
        <ContextMenuItem
          disabled={disabled}
          className="gap-2"
          onSelect={() => {
            void (async () => {
              try {
                await navigator.clipboard.writeText(toCurl(await read()));
                toast.success("cURL copied");
              } catch (error) {
                report(error);
              }
            })();
          }}
        >
          <Copy className="size-4" />
          Copy cURL
        </ContextMenuItem>
        {intruder && (
          <ContextMenuItem asChild disabled={disabled}>
            <Link
              to="/intruder"
              onClick={() => {
                void Promise.resolve().then(read).then(intruder.receive).catch(report);
              }}
            >
              {" "}
              <ArrowUpRight className="size-4" />
              Send to Intruder
            </Link>
          </ContextMenuItem>
        )}
        <ContextMenuSeparator />
        <ContextMenuItem asChild disabled={disabled || !scan}>
          <Link
            to="/dashboard"
            className="gap-2"
            onClick={(event) => {
              if (disabled || !scan) {
                event.preventDefault();
                return;
              }
              void scan.prepare(read).catch(report);
            }}
          >
            <ScanLine className="size-4" />
            Scan
          </Link>
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}
