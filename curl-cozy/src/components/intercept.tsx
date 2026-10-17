import { isWebSocketRequest } from "@/lib/websocket-request";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowUpRight,
  Hand,
  Send,
  Trash2,
  Undo2,
  Search,
  ChevronUp,
  ChevronDown,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { HeldItem } from "@/lib/api";
import { BINARY_BODY_NOTE, formatHeld, isUnedited, parseHeld } from "@/lib/intercept";
import { sizeLabel } from "@/lib/traffic";
import { RequestMenu } from "@/components/request-menu";
import { requestFromHeld } from "@/lib/request-actions";
import { useInspector } from "@/components/inspector";

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : "Something went wrong");

function Switch({
  label,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="flex items-center gap-2 rounded px-2 py-1.5 text-xs hover:bg-secondary disabled:opacity-50"
    >
      <span
        className={cn(
          "relative h-4 w-7 rounded-full transition-colors",
          checked ? "bg-primary" : "bg-muted",
        )}
      >
        <span
          className={cn(
            "absolute top-0.5 size-3 rounded-full bg-background transition-all",
            checked ? "left-3.5" : "left-0.5",
          )}
        />
      </span>
      {label}
    </button>
  );
}

const PhaseBadge = ({ phase }: { phase: HeldItem["phase"] }) => (
  <span
    className={cn(
      "rounded px-1.5 py-0.5 font-mono text-[9px] font-medium",
      phase === "request" ? "bg-primary/10 text-primary" : "bg-warning/10 text-warning",
    )}
  >
    {phase === "request" ? "REQ" : "RES"}
  </span>
);

function HeldRow({
  item,
  selected,
  edited,
  onSelect,
  draft,
}: {
  item: HeldItem;
  selected: boolean;
  edited: boolean;
  onSelect: () => void;
  draft?: string | undefined;
}) {
  return (
    <RequestMenu websocketKind={item.websocket?.text===null?"binary":"text"} request={() => requestFromHeld(item, draft)}>
      <li>
        <button
          type="button"
          aria-current={selected}
          onClick={onSelect}
          className={cn(
            "flex w-full flex-col gap-1 border-b border-border/50 px-4 py-2.5 text-left hover:bg-muted",
            selected && "bg-accent",
          )}
        >
          <span className="flex items-center gap-2">
            <span className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[9px]">{item.websocket||isWebSocketRequest({url:item.url,headers:Object.fromEntries(item.phase==='response'&&item.request?item.request.headers:item.headers)})?'WS':'HTTP'}</span>
            <PhaseBadge phase={item.phase} />
            <span className="font-mono text-[11px] font-medium">{item.websocket?({0:"Continuation",1:"Text",2:"Binary",8:"Close",9:"Ping",10:"Pong"}[item.websocket.opcode]??"Frame"):item.method}</span>
            {item.status !== null && (
              <span className="font-mono text-[11px] text-muted-foreground">{item.status}</span>
            )}
            {edited && <span className="ml-auto text-[9px] text-primary">EDITED</span>}
          </span>
          <span className="truncate font-mono text-[11px]">
            <span className="text-muted-foreground">{item.host}</span>
            {item.path}
          </span>
          <span className="font-mono text-[10px] text-muted-foreground">
            {new Date(item.created_at).toLocaleTimeString("en-GB")}
          </span>
        </button>
      </li>
    </RequestMenu>
  );
}

/** Editor for the selected held item. Remounted per item (via key) so each keeps its own draft. */
function HeldEditor({
  item,
  draft,
  onDraft,
}: {
  item: HeldItem;
  draft: string | undefined;
  onDraft: (text: string | undefined) => void;
}) {
  const { forwardHeld, dropHeld } = useInspector();
  const [busy, setBusy] = useState(false);
  const original = useMemo(() => formatHeld(item), [item]);
  const text = draft ?? original;
  const parsed = useMemo(() => {
    try {
      return { edit: parseHeld(item, text) };
    } catch (e) {
      return { error: errorMessage(e) };
    }
  }, [item, text]);
  const edited = !isUnedited(item, text);
  const noun = item.phase === "request" ? "request" : "response";
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [matchCase, setMatchCase] = useState(false);
  const [selection, setSelection] = useState({ text: "", query: "", matchCase: false, index: 0 });
  const editorRef = useRef<HTMLTextAreaElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const toggleRef = useRef<HTMLButtonElement>(null);
  const matches = useMemo(() => {
    const found: number[] = [];
    if (!query) return found;
    const pattern = new RegExp(
      query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
      matchCase ? "g" : "gi",
    );
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text))) {
      found.push(match.index);
    }
    return found;
  }, [text, query, matchCase]);
  const active =
    selection.text === text && selection.query === query && selection.matchCase === matchCase
      ? Math.min(selection.index, Math.max(0, matches.length - 1))
      : 0;
  useEffect(() => {
    if (searchOpen) {
      searchRef.current?.focus();
      searchRef.current?.select();
    }
  }, [searchOpen]);
  useEffect(() => {
    const editor = editorRef.current;
    const start = matches[active];
    if (!editor || start === undefined) return;
    editor.setSelectionRange(start, start + query.length);
    const before = text.slice(0, start);
    const line = before.split("\n").length - 1;
    const column = start - (before.lastIndexOf("\n") + 1);
    editor.scrollTop = Math.max(0, line * 24 - editor.clientHeight / 2 + 12);
    editor.scrollLeft = Math.max(0, column * 7.2 - editor.clientWidth / 2 + 20);
  }, [matches, active, query, text]);
  const closeSearch = () => {
    setSearchOpen(false);
    setQuery("");
    toggleRef.current?.focus();
  };
  const navigate = (direction: number) => {
    if (!matches.length) return;
    setSelection({
      text,
      query,
      matchCase,
      index: (active + direction + matches.length) % matches.length,
    });
    editorRef.current?.focus();
  };

  const run = async (action: () => Promise<void>, done: string) => {
    setBusy(true);
    try {
      await action();
      onDraft(undefined);
      toast.success(done);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <RequestMenu
      request={() => requestFromHeld(item, text)}
      disabled={item.phase === "request" && !!parsed.error}
    >
      <div
        className="flex min-h-0 min-w-0 flex-1 flex-col"
        onKeyDown={(event) => {
          if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
            event.preventDefault();
            setSearchOpen(true);
            searchRef.current?.focus();
            searchRef.current?.select();
          } else if (searchOpen && event.key === "Escape") {
            event.preventDefault();
            closeSearch();
          }
        }}
      >
        <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-border px-4 py-2">
          <PhaseBadge phase={item.phase} />
          <span title={item.url} className="min-w-0 flex-1 truncate font-mono text-xs">
            {item.phase === "response" ? `Response to ${item.method} ` : ""}
            {item.url}
          </span>
          <div className="ml-auto flex max-w-full shrink-0 flex-wrap items-center gap-2">
            <Button
              ref={toggleRef}
              variant="ghost"
              size="icon"
              className={cn(
                "size-8 shrink-0",
                searchOpen ? "text-primary" : "text-muted-foreground",
              )}
              aria-label="Toggle intercept search"
              aria-expanded={searchOpen}
              title="Search held message (Ctrl/Cmd+F)"
              onClick={() => (searchOpen ? closeSearch() : setSearchOpen(true))}
            >
              <Search />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 shrink-0 text-xs"
              disabled={busy || !edited}
              onClick={() => onDraft(undefined)}
            >
              <Undo2 />
              Reset
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-8 shrink-0 text-xs text-destructive"
              disabled={busy}
              onClick={() => run(() => dropHeld(item.id), `Dropped ${noun}`)}
            >
              <Trash2 />
              Drop
            </Button>
            <Button
              size="sm"
              className="h-8 shrink-0 text-xs"
              disabled={busy || !!parsed.error}
              onClick={() =>
                run(
                  () => forwardHeld(item.id, edited && parsed.edit ? parsed.edit : undefined),
                  edited ? `Forwarded edited ${noun}` : `Forwarded ${noun}`,
                )
              }
            >
              <Send />
              {edited ? "Forward edited" : "Forward"}
            </Button>
          </div>
        </div>
        {searchOpen && (
          <div className="flex shrink-0 flex-wrap items-center gap-1 border-b border-border px-3 py-2">
            <div className="relative min-w-28 flex-1">
              <Search className="pointer-events-none absolute left-2 top-2 size-3.5 text-muted-foreground" />
              <input
                ref={searchRef}
                aria-label="Search intercept"
                placeholder={`Search ${noun}…`}
                className="inspector-input h-8 w-full pl-7 text-xs"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    navigate(event.shiftKey ? -1 : 1);
                    searchRef.current?.focus();
                  }
                }}
              />
            </div>
            <span
              role="status"
              aria-label="Intercept search results"
              className="min-w-12 text-center font-mono text-[10px] text-muted-foreground"
            >
              {query ? `${matches.length ? active + 1 : 0}/${matches.length}` : "—"}
            </span>
            <Button
              variant="ghost"
              size="icon"
              className="size-7 text-xs"
              aria-label="Match case"
              aria-pressed={matchCase}
              onClick={() => setMatchCase(!matchCase)}
            >
              Aa
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label="Previous match"
              title="Previous match (Shift+Enter)"
              disabled={!matches.length}
              onClick={() => navigate(-1)}
            >
              <ChevronUp />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label="Next match"
              title="Next match (Enter)"
              disabled={!matches.length}
              onClick={() => navigate(1)}
            >
              <ChevronDown />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label="Close intercept search"
              title="Close search (Escape)"
              onClick={closeSearch}
            >
              <X />
            </Button>
          </div>
        )}
        <textarea
          ref={editorRef}
          aria-label={`Held ${noun}`}
          aria-invalid={!!parsed.error}
          className="min-h-0 flex-1 resize-none bg-background px-5 py-3 font-mono text-xs leading-6 outline-none"
          value={text}
          onChange={(e) => onDraft(e.target.value === original ? undefined : e.target.value)}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          wrap="off"
        />
        {parsed.error ? (
          <p
            role="alert"
            className="shrink-0 border-t border-destructive/40 bg-destructive/10 px-5 py-2 text-xs text-destructive"
          >
            {parsed.error} Forward is disabled until this is fixed.
          </p>
        ) : (
          <div className="shrink-0 space-y-1 border-t border-border px-5 py-2 text-[10px] text-muted-foreground">
            {!item.body_editable && item.body_size > 0 && (
              <p>
                {BINARY_BODY_NOTE} ({sizeLabel(item.body_size)})
              </p>
            )}
            <p>
              {item.phase === "request"
                ? `Edits go to the original server (${item.host}); the Host header is sent as written. `
                : "Edits are what the client receives. "}
              Content-Length is recalculated. Held items wait until you forward or drop them; there
              is no automatic timeout.
            </p>
          </div>
        )}
      </div>
    </RequestMenu>
  );
}

function WebSocketHeldEditor({item}:{item:HeldItem}) {
 const {forwardHeld,dropHeld}=useInspector();const [busy,setBusy]=useState(false);const frame=item.websocket!;
 const resolve=async(drop:boolean)=>{setBusy(true);try{await(drop?dropHeld(item.id):forwardHeld(item.id));}catch(e){toast.error(errorMessage(e));}finally{setBusy(false);}};
 return <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label="Held WebSocket frame">
  <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border p-4"><span className="text-xs font-semibold">WS · {frame.direction==='client_to_server'?'Client → Server':'Server → Client'}</span><span className="min-w-0 flex-1 break-all font-mono text-xs">{item.url}</span><Button disabled={busy} onClick={()=>void resolve(false)}>Forward</Button><Button variant="destructive" disabled={busy} onClick={()=>void resolve(true)}>Drop</Button></div>
  <div className="border-b border-border px-4 py-3 text-xs text-muted-foreground">Opcode {frame.opcode} · {frame.size} bytes · {frame.fin?'Final frame':'Fragment'}{frame.compressed?' · Compressed (hex)':''}{frame.truncated?' · Preview limited to 64 KiB':''}<p className="mt-1">Frame is held. Forward sends it unchanged; Drop removes it from this connection. Use Replay to send an edited message.</p></div>
  <pre aria-label="WebSocket frame payload" tabIndex={0} className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all p-4 font-mono text-xs">{frame.text??frame.hex.match(/.{1,2}/g)?.join(' ')??''}</pre>
 </section>;
}

function HttpInterceptView() {
  const { held, intercept, setIntercept, forwardAllHeld, proxyStatus, scope, scopeEnabled } =
    useInspector();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const offline = proxyStatus !== "connected";

  // Keep the selection on a real item, and forget drafts of items that are gone (forwarded or dropped).
  const selected = held.find((h) => h.id === selectedId) ?? held[0];
  useEffect(() => {
    setDrafts((prev) => {
      const ids = new Set(held.map((h) => h.id));
      const kept = Object.entries(prev).filter(([id]) => ids.has(id));
      return kept.length === Object.keys(prev).length ? prev : Object.fromEntries(kept);
    });
  }, [held]);

  const toggle = async (update: { requests?: boolean; responses?: boolean }) => {
    try {
      await setIntercept(update);
    } catch (e) {
      toast.error(errorMessage(e));
    }
  };

  return (
    <>
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-6 py-4">
        <div className="mr-auto">
          <h1 className="text-xl font-semibold">Intercept</h1>
          <p className="mt-1 text-xs text-muted-foreground">
            Hold traffic, review or edit it, then forward it on.
          </p>
          {scopeEnabled && scope.trim() && (
            <p className="mt-1 max-w-xl break-all text-xs text-primary">
              In-scope only: {scope.split("\n").join(", ")}
            </p>
          )}
        </div>
        <Switch
          label="Intercept requests"
          checked={intercept.requests}
          disabled={offline}
          onChange={(v) => toggle({ requests: v })}
        />
        <Switch
          label="Intercept responses"
          checked={intercept.responses}
          disabled={offline}
          onChange={(v) => toggle({ responses: v })}
        />
        <Button
          variant="outline"
          size="sm"
          disabled={!held.length}
          onClick={() =>
            forwardAllHeld().then(
              () => toast.success("Forwarded all held items"),
              (e) => toast.error(errorMessage(e)),
            )
          }
        >
          <ArrowUpRight />
          Forward all{held.length ? ` (${held.length})` : ""}
        </Button>
      </div>

      {offline && (
        <div
          role="status"
          className="m-6 rounded border border-border bg-card p-4 text-sm text-muted-foreground"
        >
          Interception runs inside the proxy. Start it with{" "}
          <code className="font-mono text-foreground">slurp</code> and this page will
          connect automatically.
        </div>
      )}

      {!offline && (
        <div className="flex min-h-0 min-w-0 flex-1">
          <aside
            className="flex w-72 shrink-0 flex-col border-r border-border max-md:w-52"
            aria-label="Held items"
          >
            <div className="flex h-9 shrink-0 items-center justify-between border-b border-border px-4 text-[10px] tracking-[1.5px] text-muted-foreground">
              HELD
              <span className="font-mono">{held.length}</span>
            </div>
            <ul className="min-h-0 flex-1 overflow-auto">
              {held.map((item) => (
                <HeldRow
                  draft={drafts[item.id]}
                  key={item.id}
                  item={item}
                  selected={item.id === selected?.id}
                  edited={item.id in drafts}
                  onSelect={() => setSelectedId(item.id)}
                />
              ))}
            </ul>
          </aside>

          {selected?.websocket ? <WebSocketHeldEditor key={selected.id} item={selected}/> : selected ? (
            <HeldEditor
              key={selected.id}
              item={selected}
              draft={drafts[selected.id]}
              onDraft={(text) =>
                setDrafts((prev) => {
                  if (text === undefined) {
                    const { [selected.id]: _gone, ...rest } = prev;
                    return rest;
                  }
                  return { ...prev, [selected.id]: text };
                })
              }
            />
          ) : (
            <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center text-muted-foreground">
              <Hand className="size-8" strokeWidth={1.2} />
              <p className="text-sm text-foreground">
                {intercept.requests || intercept.responses
                  ? "Waiting for traffic…"
                  : "Interception is off"}
              </p>
              <p className="max-w-md text-xs leading-5">
                Turn on <strong>Intercept requests</strong> and/or{" "}
                <strong>Intercept responses</strong>, then send traffic through the proxy (default{" "}
                <code className="font-mono">127.0.0.1:8888</code>). Matching requests stop here
                until you forward or drop them. Only decrypted traffic is held; HTTPS needs the CA
                certificate installed.
              </p>
            </div>
          )}
        </div>
      )}
    </>
  );
}

export function InterceptView() { return <HttpInterceptView/>; }
