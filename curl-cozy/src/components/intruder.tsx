import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { useIntruder } from "./intruder-provider";
import { ProfileSelector } from "./auth-profiles";
import { Button } from "./ui/button";
import {
  applyPayload,
  encodePayload,
  payloadAt,
  type PayloadFile,
  type IntruderResult,
  type IntruderResultSummary,
  type IntruderRunSummary,
} from "@/lib/intruder";
import * as api from "@/lib/intruder-api";
import { csvColumns, selectedPayloads } from "@/lib/intruder-import";
import { useAuthProfiles } from "./auth-profiles-provider";
import { useInspector } from "./inspector";
import { resolveReplayRequest } from "@/lib/replay-features";
import { ResponseDiffButton } from "./response-diff";
import { RequestMenu } from "./request-menu";
const input = "rounded border border-border bg-background p-2 text-sm min-w-0";
const report = (e: unknown) => toast.error(e instanceof Error ? e.message : String(e));
export function IntruderView() {
  const ctx = useIntruder()!;
  const { config, workspace } = ctx;
  const auth = useAuthProfiles();
  const { variables } = useInspector();
  const [files, setFiles] = useState<PayloadFile[]>([]),
    [file, setFile] = useState<File | null>(null),
    [columns, setColumns] = useState<string[]>([]),
    [column, setColumn] = useState(0),
    [header, setHeader] = useState(true),
    [skip, setSkip] = useState(true),
    [progress, setProgress] = useState<string>(""),
    [preview, setPreview] = useState("");
  const generation = useRef(0),
    cancel = useRef(false),
    selection = useRef<{ field: "url" | "body" | string; start: number; end: number } | null>(null);
  useEffect(() => {
    generation.current++;
    const gen = generation.current;
    setPreview("");
    cancel.current = true;
    setFile(null);
    setFiles([]);
    setProgress("");
    if (workspace)
      void api
        .fetchPayloadFiles(workspace)
        .then((v) => {
          if (gen === generation.current) setFiles(v.data);
        })
        .catch(report);
    return () => {
      generation.current++;
      cancel.current = true;
    };
  }, [workspace]);
  const update = (patch: Partial<typeof config>) => ctx.update({ ...config, ...patch });
  const remember = (field: string, el: HTMLInputElement | HTMLTextAreaElement) => {
    selection.current = { field, start: el.selectionStart ?? 0, end: el.selectionEnd ?? 0 };
  };
  const mark = () => {
    const sel = selection.current;
    if (!sel) {
      toast.error("Select text in the URL, body or a header value.");
      return;
    }
    const value =
      sel.field === "url"
        ? config.request.url
        : sel.field === "body"
          ? config.request.body
          : config.request.headers[sel.field];
    if (value === undefined) return;
    const marked =
      value.slice(0, sel.start) +
      "§" +
      value.slice(sel.start, sel.end) +
      "§" +
      value.slice(sel.end);
    update({
      request: {
        ...config.request,
        ...(sel.field === "url"
          ? { url: marked }
          : sel.field === "body"
            ? { body: marked }
            : { headers: { ...config.request.headers, [sel.field]: marked } }),
      },
    });
  };
  const importFile = async () => {
    if (!file || !workspace) return;
    const gen = generation.current;
    cancel.current = false;
    let id = "";
    try {
      setProgress("Importing…");
      id = (await api.createPayloadFile(workspace, file.name)).id;
      let count = 0,
        batch: string[] = [],
        bytes = 0;
      const flush = async () => {
        if (!batch.length) return;
        await api.appendPayloads(workspace, id, count, batch);
        count += batch.length;
        batch = [];
        bytes = 0;
        if (gen === generation.current) setProgress(`Imported ${count.toLocaleString()} payloads`);
      };
      for await (const value of selectedPayloads(
        file,
        file.name.toLowerCase().endsWith(".csv") ? "csv" : "txt",
        column,
        header,
        skip,
      )) {
        if (cancel.current || gen !== generation.current) throw Error("Import cancelled");
        const size = new TextEncoder().encode(value).length;
        if (batch.length >= 128 || bytes + size > 500000) await flush();
        batch.push(value);
        bytes += size;
      }
      await flush();
      if (cancel.current || gen !== generation.current) throw Error("Import cancelled");
      await api.finalizePayloadFile(workspace, id);
      const next = await api.fetchPayloadFiles(workspace);
      if (gen === generation.current) {
        setFiles(next.data);
        update({ source: { kind: "file", id, name: file.name, count } });
        setProgress(`Ready: ${count.toLocaleString()} payloads`);
      }
    } catch (e) {
      if (id)
        try {
          await api.deletePayloadFile(workspace, id);
        } catch (cleanup) {
          report(cleanup);
        }
      if (gen === generation.current) {
        setProgress("");
        report(e);
      }
    }
  };
  const makePreview = async () => {
    try {
      const value =
        config.source.kind === "file"
          ? (
              await api.fetchPayloadPage(
                workspace!,
                config.source.id,
                Math.floor(config.start / 128) * 128,
              )
            ).values[config.start % 128]
          : payloadAt(config.source, config.start);
      if (value === undefined) throw Error("No payload at this offset");
      setPreview(
        JSON.stringify(
          {
            payload: value,
            encoded: encodePayload(value, config.encoding),
            request: applyPayload(
              auth
                ? (() => {
                    const session = auth.createSession(undefined, variables);
                    return session.resolve(config.request, session.variables);
                  })()
                : resolveReplayRequest(config.request, variables),
              value,
              config.encoding,
            ),
          },
          null,
          2,
        ),
      );
    } catch (e) {
      report(e);
    }
  };
  if (!ctx.ready)
    return (
      <div className="p-6">
        {ctx.error || "Loading Intruder…"}
        <Button onClick={ctx.retry}>Retry</Button>
      </div>
    );
  return (
    <div className="h-full overflow-auto p-4 space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold">Intruder</h1>
        <ProfileSelector />
        <a
          className="text-sm text-primary underline"
          href="/docs/intruder.html"
          target="_blank"
          rel="noreferrer"
        >
          Documentation
        </a>
      </div>
      <p className="text-sm text-muted-foreground">
        Select text and mark one payload position with §value§. Runs use the Replay HTTPS sender.
      </p>
      {ctx.error && (
        <p role="alert" className="text-destructive">
          {ctx.error} <Button onClick={ctx.retry}>Retry save</Button>
          <Button onClick={ctx.reload}>Reload</Button>
        </p>
      )}
      <fieldset disabled={ctx.active || ctx.starting} className="space-y-3 disabled:opacity-60">
        <div className="flex gap-2">
          <select
            aria-label="Method"
            className={input}
            value={config.request.method}
            onChange={(e) =>
              update({
                request: {
                  ...config.request,
                  method: e.target.value as typeof config.request.method,
                },
              })
            }
          >
            {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
          <input
            aria-label="Request URL"
            className={input + " flex-1"}
            value={config.request.url}
            placeholder="https://example.com/items/§1§"
            onSelect={(e) => remember("url", e.currentTarget)}
            onChange={(e) => update({ request: { ...config.request, url: e.target.value } })}
          />
          <Button onClick={mark}>Mark selection</Button>
        </div>
        <div className="space-y-2">
          {Object.entries(config.request.headers).map(([name, value]) => (
            <div key={name} className="flex gap-2 items-center">
              <span className="w-40 truncate">{name}</span>
              <input
                aria-label={`${name} header`}
                className={input + " flex-1"}
                value={value}
                onSelect={(e) => remember(name, e.currentTarget)}
                onChange={(e) =>
                  update({
                    request: {
                      ...config.request,
                      headers: { ...config.request.headers, [name]: e.target.value },
                    },
                  })
                }
              />
              <Button
                variant="ghost"
                onClick={() => {
                  const headers = { ...config.request.headers };
                  delete headers[name];
                  update({ request: { ...config.request, headers } });
                }}
              >
                Remove
              </Button>
            </div>
          ))}
          <Button
            variant="outline"
            onClick={() => {
              const name = window.prompt("Header name");
              if (name)
                update({
                  request: {
                    ...config.request,
                    headers: { ...config.request.headers, [name]: "" },
                  },
                });
            }}
          >
            Add header
          </Button>
        </div>
        <textarea
          aria-label="Request body"
          className={input + " w-full font-mono h-28"}
          placeholder="Request body"
          value={config.request.body}
          onSelect={(e) => remember("body", e.currentTarget)}
          onChange={(e) => update({ request: { ...config.request, body: e.target.value } })}
        />
        <div className="flex flex-wrap gap-2 items-center">
          <label>
            Payload source{" "}
            <select
              className={input}
              value={config.source.kind}
              onChange={(e) =>
                update({
                  source:
                    e.target.value === "numbers"
                      ? { kind: "numbers", from: "1", to: "100", step: "1", pad: 0 }
                      : e.target.value === "file"
                        ? { kind: "file", id: "", name: "", count: 0 }
                        : { kind: "list", values: [] },
                })
              }
            >
              <option value="list">Manual list</option>
              <option value="numbers">Numbers</option>
              <option value="file">TXT / CSV file</option>
            </select>
          </label>
          <label>
            Encoding{" "}
            <select
              className={input}
              value={config.encoding}
              onChange={(e) => update({ encoding: e.target.value as typeof config.encoding })}
            >
              {["none", "url", "base64", "hex", "html"].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </label>
        </div>
        {config.source.kind === "list" && (
          <textarea
            aria-label="Payload list"
            className={input + " w-full h-28 font-mono"}
            placeholder="One payload per line"
            value={config.source.values.join("\n")}
            onChange={(e) =>
              update({ source: { kind: "list", values: e.target.value.split("\n") } })
            }
          />
        )}
        {config.source.kind === "numbers" && (
          <div className="flex flex-wrap gap-2">
            {(["from", "to", "step", "pad"] as const).map((field) => (
              <label key={field}>
                {field}{" "}
                <input
                  className={input + " w-32"}
                  value={config.source.kind === "numbers" ? config.source[field] : ""}
                  onChange={(e) => {
                    if (config.source.kind === "numbers")
                      update({
                        source: {
                          ...config.source,
                          [field]: field === "pad" ? Number(e.target.value) : e.target.value,
                        },
                      });
                  }}
                />
              </label>
            ))}
          </div>
        )}
        {config.source.kind === "file" && (
          <div className="space-y-2">
            <p className="text-xs text-muted-foreground">
              Files stream into local workspace storage. Select a saved workspace to import. UTF-8,
              up to 256 MB and 1 million payloads.
            </p>
            <select
              aria-label="Saved payload file"
              className={input}
              value={config.source.id}
              onChange={(e) => {
                const f = files.find((f) => f.id === e.target.value);
                if (f) update({ source: { kind: "file", id: f.id, name: f.name, count: f.count } });
              }}
            >
              <option value="">Select imported file</option>
              {files
                .filter((f) => f.ready)
                .map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.name} ({f.count})
                  </option>
                ))}
            </select>
            <input
              aria-label="Import payload file"
              type="file"
              accept=".txt,.csv"
              disabled={!workspace || progress.startsWith("Import")}
              onChange={(e) => {
                const f = e.target.files?.[0] ?? null;
                setFile(f);
                setColumn(0);
                setColumns([]);
                if (f?.name.toLowerCase().endsWith(".csv"))
                  void csvColumns(f).then(setColumns).catch(report);
              }}
            />
            {columns.length > 0 && (
              <>
                <select
                  aria-label="CSV column"
                  className={input}
                  value={column}
                  onChange={(e) => setColumn(Number(e.target.value))}
                >
                  {columns.map((v, i) => (
                    <option key={i} value={i}>
                      {i + 1}: {v.slice(0, 100)}
                    </option>
                  ))}
                </select>
                <label>
                  <input
                    type="checkbox"
                    checked={header}
                    onChange={(e) => setHeader(e.target.checked)}
                  />{" "}
                  First row is a header
                </label>
              </>
            )}
            <label>
              <input type="checkbox" checked={skip} onChange={(e) => setSkip(e.target.checked)} />{" "}
              Skip empty payloads
            </label>
            <Button
              disabled={!file || !workspace || progress.startsWith("Import")}
              onClick={() => void importFile()}
            >
              Import
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                cancel.current = true;
              }}
            >
              Cancel import
            </Button>
            <span>{progress}</span>
            {files.map((f) => (
              <div key={f.id} className="text-xs">
                {f.name} — {f.count} {!f.ready && "(incomplete)"}{" "}
                <button
                  className="underline"
                  onClick={() => {
                    if (workspace)
                      void api
                        .deletePayloadFile(workspace, f.id)
                        .then(() => setFiles((prev) => prev.filter((v) => v.id !== f.id)))
                        .catch(report);
                  }}
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        )}
        <div className="flex flex-wrap gap-3">
          {(["start", "limit", "concurrency", "rate", "delay"] as const).map((field) => (
            <label className="text-xs" key={field}>
              {
                {
                  start: "Start offset (0-based)",
                  limit: "Request limit",
                  concurrency: "Concurrency",
                  rate: "Requests / second",
                  delay: "Minimum delay (ms)",
                }[field]
              }
              <input
                type="number"
                className={input + " block w-36"}
                value={config[field]}
                onChange={(e) => update({ [field]: Number(e.target.value) })}
              />
            </label>
          ))}
          <label className="text-xs">
            Match response text
            <input
              className={input + " block"}
              value={config.matchText}
              onChange={(e) => update({ matchText: e.target.value })}
            />
          </label>
        </div>
        <Button variant="outline" onClick={() => void makePreview()}>
          Preview payload substitution
        </Button>
        {preview && (
          <pre className="max-h-56 overflow-auto text-xs whitespace-pre-wrap">{preview}</pre>
        )}
      </fieldset>
      <div className="flex flex-wrap gap-2 items-center">
        <Button
          disabled={ctx.active || ctx.starting}
          onClick={() => void ctx.start().catch(report)}
        >
          Start
        </Button>
        <Button
          variant="outline"
          disabled={!ctx.active}
          onClick={ctx.run?.status === "paused" ? ctx.resume : ctx.pause}
        >
          {ctx.run?.status === "paused" ? "Resume" : "Pause"}
        </Button>
        <Button variant="destructive" disabled={!ctx.active} onClick={ctx.stop}>
          Stop
        </Button>
        <span>
          {ctx.run &&
            `${ctx.run.status}: ${ctx.run.completed} / ${ctx.run.count} (${ctx.run.inFlight} in flight)`}
        </span>
      </div>
      {ctx.run?.message && <p role="status">{ctx.run.message}</p>}
      {ctx.runError && (
        <p role="alert">
          {ctx.runError}{" "}
          <Button onClick={() => void ctx.retryEvidence().catch(report)}>
            Retry evidence saving
          </Button>
        </p>
      )}
      <IntruderResults />
    </div>
  );
}
function IntruderResults() {
  const ctx = useIntruder()!;
  const [runs, setRuns] = useState<IntruderRunSummary[]>([]),
    [runId, setRunId] = useState(""),
    [offset, setOffset] = useState(0),
    [runOffset, setRunOffset] = useState(0),
    [moreRuns, setMoreRuns] = useState(false),
    [query, setQuery] = useState(""),
    [status, setStatus] = useState(0),
    [matched, setMatched] = useState(false),
    [errors, setErrors] = useState(false),
    [sort, setSort] = useState("index"),
    [descending, setDescending] = useState(false),
    [rows, setRows] = useState<IntruderResultSummary[]>([]),
    [total, setTotal] = useState(0),
    [selected, setSelected] = useState<IntruderResult | null>(null),
    [baseline, setBaseline] = useState<IntruderResult | null>(null),
    [deleted, setDeleted] = useState<Set<string>>(new Set()),
    [error, setError] = useState("");
  const selectedId = runId || (ctx.run && !deleted.has(ctx.run.id) ? ctx.run.id : "");
  const viewRef = useRef("");
  viewRef.current = `${ctx.workspace}:${selectedId}`;
  const openVersion = useRef(0);
  useEffect(() => {
    setRunId("");
    setDeleted(new Set());
    setBaseline(null);
    setOffset(0);
    setSelected(null);
    setRuns([]);
    setRunOffset(0);
  }, [ctx.workspace]);
  useEffect(() => {
    setSelected(null);
    setOffset(0);
  }, [selectedId, query, status, matched, errors, sort, descending]);
  useEffect(() => {
    let current = true;
    const load = async () => {
      try {
        if (ctx.workspace) {
          const list = await api.fetchIntruderRuns(ctx.workspace, runOffset);
          if (current) {
            setRuns(list.data);
            setMoreRuns(list.has_more);
          }
          if (selectedId) {
            const result = await api.fetchIntruderResults(ctx.workspace, selectedId, {
              offset,
              q: query,
              status,
              matched,
              errors,
              sort,
              descending,
            });
            if (current) {
              setRows(result.data);
              setTotal(result.total);
            }
          } else if (current) {
            setRows([]);
            setTotal(0);
          }
        } else {
          const filtered = ctx
            .getLocalResults(selectedId)
            .filter(
              (r) =>
                (!query || r.payload.toLowerCase().includes(query.toLowerCase())) &&
                (!status || r.status === status) &&
                (!matched || r.matched) &&
                (!errors || r.error),
            );
          filtered.sort((a, b) => {
            const key = sort as "index" | "status" | "size" | "duration";
            return ((a[key] ?? 0) - (b[key] ?? 0)) * (descending ? -1 : 1);
          });
          if (current) {
            setRows(filtered.slice(offset, offset + 100));
            setTotal(filtered.length);
          }
        }
        if (current) setError("");
      } catch (e) {
        if (current) setError(e instanceof Error ? e.message : String(e));
      }
    };
    void load();
    const timer = setInterval(() => void load(), 2000);
    return () => {
      current = false;
      clearInterval(timer);
    };
  }, [
    ctx.workspace,
    selectedId,
    offset,
    query,
    status,
    matched,
    errors,
    sort,
    descending,
    runOffset,
    ctx.run?.completed,
  ]);
  const open = async (row: IntruderResultSummary) => {
    const view = viewRef.current,
      version = ++openVersion.current;
    try {
      const value = ctx.workspace
        ? await api.fetchIntruderResult(ctx.workspace, selectedId, row.index)
        : (ctx.getLocalResults(selectedId).find((r) => r.index === row.index) ?? null);
      if (viewRef.current === view && openVersion.current === version) setSelected(value);
    } catch (e) {
      report(e);
    }
  };
  return (
    <section className="space-y-3 border-t pt-4">
      <h2 className="font-medium">Run history & results</h2>
      <div className="flex flex-wrap gap-2">
        <select
          aria-label="Intruder run"
          className={input}
          value={runId}
          onChange={(e) => setRunId(e.target.value)}
        >
          <option value="">Current run</option>
          {(ctx.workspace ? runs : ctx.localRuns).map((r) => (
            <option key={r.id} value={r.id}>
              {new Date(r.startedAt).toLocaleString()} — {r.status} ({r.completed}/{r.count})
            </option>
          ))}
        </select>
        {ctx.workspace && (
          <>
            <Button
              variant="outline"
              disabled={!runOffset}
              onClick={() => setRunOffset(Math.max(0, runOffset - 50))}
            >
              Previous runs
            </Button>
            <Button
              variant="outline"
              disabled={!moreRuns}
              onClick={() => setRunOffset(runOffset + 50)}
            >
              Older runs
            </Button>
            <Button
              variant="outline"
              disabled={!selectedId || ctx.active}
              onClick={() =>
                void api
                  .deleteIntruderRun(ctx.workspace!, selectedId)
                  .then(() => {
                    setRunId("");
                    setRuns((prev) => prev.filter((r) => r.id !== selectedId));
                    setDeleted((prev) => new Set([...prev, selectedId]));
                    setSelected(null);
                    setBaseline(null);
                    setRows([]);
                    setTotal(0);
                  })
                  .catch(report)
              }
            >
              Delete run
            </Button>
          </>
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        Runs require this browser to remain open. After a reload, unfinished runs are interrupted
        and never resume automatically.
      </p>
      <div className="flex flex-wrap gap-3">
        <input
          aria-label="Search payloads"
          className={input}
          placeholder="Search payloads"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <input
          aria-label="Filter status"
          type="number"
          className={input + " w-28"}
          placeholder="Status"
          value={status || ""}
          onChange={(e) => setStatus(Number(e.target.value))}
        />
        <label>
          <input type="checkbox" checked={matched} onChange={(e) => setMatched(e.target.checked)} />{" "}
          Matched
        </label>
        <label>
          <input type="checkbox" checked={errors} onChange={(e) => setErrors(e.target.checked)} />{" "}
          Errors
        </label>
        <select
          aria-label="Sort results"
          className={input}
          value={sort}
          onChange={(e) => setSort(e.target.value)}
        >
          {["index", "status", "size", "duration"].map((v) => (
            <option key={v}>{v}</option>
          ))}
        </select>
        <label>
          <input
            type="checkbox"
            checked={descending}
            onChange={(e) => setDescending(e.target.checked)}
          />{" "}
          Descending
        </label>
      </div>
      {error && (
        <p role="alert" className="text-destructive">
          {error}
        </p>
      )}
      <div className="overflow-auto">
        <table className="w-full text-sm">
          <thead>
            <tr>
              {["#", "Payload", "Status", "Size", "Time (ms)", "Match / error"].map((v) => (
                <th key={v} className="p-2 text-left">
                  {v}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.index}
                className="border-t cursor-pointer hover:bg-accent"
                onClick={() => void open(row)}
              >
                <td className="p-2">{row.index + 1}</td>
                <td className="p-2 max-w-64 truncate">{row.payload}</td>
                <td>{row.status ?? "—"}</td>
                <td>{row.size}</td>
                <td>{row.duration}</td>
                <td className="max-w-64 truncate">
                  {row.error || (row.matched ? "Matched" : "—")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex gap-2 items-center">
        <Button
          variant="outline"
          disabled={!offset}
          onClick={() => setOffset(Math.max(0, offset - 100))}
        >
          Previous
        </Button>
        <span>
          {total ? `${offset + 1}–${Math.min(offset + 100, total)} of ${total}` : "No results"}
        </span>
        <Button
          variant="outline"
          disabled={offset + 100 >= total}
          onClick={() => setOffset(offset + 100)}
        >
          Next
        </Button>
      </div>
      {selected && (
        <div className="space-y-2">
          <h3>Result #{selected.index + 1}</h3>
          <Button variant="outline" onClick={() => setBaseline(selected)}>
            Use as comparison baseline
          </Button>
          {baseline && baseline.index !== selected.index && (
            <div className="text-xs">
              Baseline #{baseline.index + 1}: status {baseline.status}, size {baseline.size}.{" "}
              {baseline.bodyHash && selected.bodyHash
                ? baseline.bodyHash === selected.bodyHash
                  ? "Body hashes match."
                  : "Body hashes differ."
                : ""}
              {baseline.response &&
                selected.response &&
                !baseline.truncated &&
                !selected.truncated && (
                  <ResponseDiffButton left={baseline.response} right={selected.response} />
                )}
            </div>
          )}
          {selected.truncated ? (
            <p className="text-amber-500">
              Response preview truncated. Full response size: {selected.size} bytes.
            </p>
          ) : null}
          {selected.bodyHash && (
            <p className="text-xs break-all">Response body SHA-256: {selected.bodyHash}</p>
          )}
          {selected.error && <p>{selected.error}</p>}
          {selected.request && (
            <RequestMenu request={selected.request}>
              <pre className="max-h-64 overflow-auto rounded border p-3 text-xs whitespace-pre-wrap">
                {JSON.stringify(selected.request, null, 2)}
              </pre>
            </RequestMenu>
          )}
          <pre className="max-h-96 overflow-auto rounded border p-3 text-xs whitespace-pre-wrap">
            {JSON.stringify(selected.response, null, 2)}
          </pre>
        </div>
      )}
    </section>
  );
}
