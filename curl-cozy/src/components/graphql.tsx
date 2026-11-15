import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { ArrowUpRight, Copy, Download, FileJson, Play, Wand2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { GraphqlExplorer } from "@/components/graphql-explorer";
import { useInspector } from "@/components/inspector";
import { cn } from "@/lib/utils";
import { sendHttpRequest, type SendResult } from "@/lib/replay.functions";
import { toCurl } from "@/lib/request-actions";
import { nextReplayTabId } from "@/lib/replay-tabs";
import { buildOperation } from "@/lib/graphql/builder";
import { formatQuery } from "@/lib/graphql/format";
import { INTROSPECTION_QUERY } from "@/lib/graphql/introspection";
import {
  SEED_EVENT,
  buildGraphqlRequest,
  formatHeaderLines,
  fromCapturedRequest,
  parseHeaderLines,
  takeGraphqlSeed,
} from "@/lib/graphql/request";
import { parseIntrospection, printSchema, type Operation, type Schema } from "@/lib/graphql/schema";

const DRAFT_KEY = "slurp-graphql-draft";
const TIMEOUT = 30_000;
/** Schemas stay loaded while navigating within the app; they can be large, so they are not persisted. */
const schemaCache = new Map<string, Schema>();

type Draft = {
  endpoint: string;
  headers: string;
  query: string;
  variables: string;
  operationName: string;
};
const emptyDraft: Draft = {
  endpoint: "",
  headers: "",
  query: "",
  variables: "",
  operationName: "",
};
type Outcome = Extract<SendResult, { ok: true }> | { ok: false; error: string };

function loadDraft(): Draft {
  try {
    return {
      ...emptyDraft,
      ...(JSON.parse(sessionStorage.getItem(DRAFT_KEY) ?? "{}") as Partial<Draft>),
    };
  } catch {
    return emptyDraft;
  }
}

const pretty = (text: string) => {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
};

function graphqlErrors(body: string): string[] {
  try {
    const errors = (JSON.parse(body) as { errors?: unknown }).errors;
    return Array.isArray(errors)
      ? errors
          .map((e) => String((e as { message?: unknown })?.message ?? JSON.stringify(e)))
          .slice(0, 10)
      : [];
  } catch {
    return [];
  }
}

const area = "inspector-input w-full flex-1 resize-none font-mono text-xs leading-5";

export function GraphqlView() {
  const { sessions, setSessions, setActive } = useInspector();
  const navigate = useNavigate();
  const [draft, setDraft] = useState<Draft>(() => loadDraft());
  const [schema, setSchema] = useState<Schema | undefined>(() =>
    schemaCache.get(loadDraft().endpoint),
  );
  const [schemaStatus, setSchemaStatus] = useState<{ loading: boolean; error: string }>({
    loading: false,
    error: "",
  });
  const [editorTab, setEditorTab] = useState<"query" | "variables" | "headers">("query");
  const [outputTab, setOutputTab] = useState<"response" | "headers">("response");
  const [outcome, setOutcome] = useState<Outcome | undefined>();
  const [sending, setSending] = useState(false);
  const importInput = useRef<HTMLInputElement>(null);
  const update = (patch: Partial<Draft>) => setDraft((previous) => ({ ...previous, ...patch }));

  useEffect(() => {
    try {
      sessionStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
    } catch {
      /* the draft is just not remembered */
    }
  }, [draft]);

  // A request opened from History fills the editor, whether it was ready before the page opened or not.
  useEffect(() => {
    const apply = () => {
      const seed = takeGraphqlSeed();
      if (!seed) return;
      try {
        const { draft: captured, isGraphql } = fromCapturedRequest(seed);
        setDraft({
          endpoint: captured.endpoint,
          headers: formatHeaderLines(captured.headers),
          query: captured.query ?? "",
          variables: captured.variables ?? "",
          operationName: captured.operationName ?? "",
        });
        setSchema(schemaCache.get(captured.endpoint));
        setOutcome(undefined);
        if (!isGraphql)
          toast.message(
            "This request does not look like GraphQL; the endpoint and headers were copied.",
          );
      } catch (error) {
        toast.error(error instanceof Error ? error.message : "Could not read the request");
      }
    };
    apply();
    window.addEventListener(SEED_EVENT, apply);
    return () => window.removeEventListener(SEED_EVENT, apply);
  }, []);

  const headerMap = useCallback(() => {
    const { headers, invalid } = parseHeaderLines(draft.headers);
    if (invalid.length) throw new Error(`Invalid header line: ${invalid[0]}`);
    return headers;
  }, [draft.headers]);

  const loadSchema = async () => {
    setSchemaStatus({ loading: true, error: "" });
    try {
      const request = buildGraphqlRequest({
        endpoint: draft.endpoint.trim(),
        headers: headerMap(),
        query: INTROSPECTION_QUERY,
        variables: "",
        operationName: "IntrospectionQuery",
      });
      const result = await sendHttpRequest({
        data: { ...request, method: "POST", timeout: TIMEOUT },
      });
      if (!result.ok) throw new Error(result.error);
      let parsed: unknown;
      try {
        parsed = JSON.parse(result.responseBody);
      } catch {
        throw new Error(`The endpoint answered ${result.status} with something that is not JSON.`);
      }
      const loaded = parseIntrospection(parsed);
      schemaCache.set(draft.endpoint.trim(), loaded);
      setSchema(loaded);
      setSchemaStatus({ loading: false, error: "" });
      toast.success(`Schema loaded: ${loaded.types.size} types`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Could not load the schema";
      setSchemaStatus({
        loading: false,
        error: /introspection|not allowed|disabled|forbidden/i.test(message)
          ? `${message} Introspection looks disabled; import a schema JSON you saved elsewhere instead.`
          : message,
      });
    }
  };

  const importSchema = async (file: File | undefined) => {
    if (!file) return;
    try {
      const loaded = parseIntrospection(JSON.parse(await file.text()));
      if (draft.endpoint.trim()) schemaCache.set(draft.endpoint.trim(), loaded);
      setSchema(loaded);
      setSchemaStatus({ loading: false, error: "" });
      toast.success(`Schema imported: ${loaded.types.size} types`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not read the schema file");
    } finally {
      if (importInput.current) importInput.current.value = "";
    }
  };

  const send = async () => {
    setSending(true);
    try {
      const request = buildGraphqlRequest({
        endpoint: draft.endpoint.trim(),
        headers: headerMap(),
        query: draft.query,
        variables: draft.variables,
        operationName: draft.operationName,
      });
      const result = await sendHttpRequest({
        data: {
          method: "POST",
          url: request.url,
          headers: request.headers,
          body: request.body,
          timeout: TIMEOUT,
        },
      });
      setOutcome(result);
      setOutputTab("response");
    } catch (error) {
      setOutcome({ ok: false, error: error instanceof Error ? error.message : "Request failed" });
    } finally {
      setSending(false);
    }
  };

  const currentRequest = () =>
    buildGraphqlRequest({
      endpoint: draft.endpoint.trim(),
      headers: headerMap(),
      query: draft.query,
      variables: draft.variables,
      operationName: draft.operationName,
    });

  const use = (operation: Operation, field: string) => {
    if (!schema) return;
    try {
      const built = buildOperation(schema, operation, field);
      update({
        query: built.query,
        variables: Object.keys(built.variables).length
          ? JSON.stringify(built.variables, null, 2)
          : "",
        operationName: "",
      });
      setEditorTab("query");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not build the operation");
    }
  };

  const prettify = () => {
    update({
      query: formatQuery(draft.query),
      variables: draft.variables.trim() ? pretty(draft.variables) : "",
    });
  };

  const guard = (action: () => void | Promise<void>) => () => {
    try {
      void Promise.resolve(action()).catch((e) =>
        toast.error(e instanceof Error ? e.message : "Something went wrong"),
      );
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Something went wrong");
    }
  };

  const toReplay = () => {
    const request = currentRequest();
    const id = nextReplayTabId(sessions);
    setSessions((previous) => [
      ...previous,
      { id, name: `GraphQL ${new URL(request.url).pathname}`, request },
    ]);
    setActive(id);
    void navigate({ to: "/replay" });
  };

  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`${label} copied`);
    } catch {
      toast.error("Could not copy");
    }
  };

  const errors = outcome?.ok ? graphqlErrors(outcome.responseBody) : [];

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-4 py-3">
        <h1 className="mr-2 text-sm font-semibold">GraphQL</h1>
        <input
          aria-label="GraphQL endpoint"
          className="inspector-input h-9 min-w-64 flex-1 text-sm"
          placeholder="https://api.example.com/graphql"
          value={draft.endpoint}
          onChange={(e) => update({ endpoint: e.target.value })}
        />
        <Button
          variant="outline"
          size="sm"
          className="h-9"
          disabled={!draft.endpoint.trim() || schemaStatus.loading}
          onClick={guard(loadSchema)}
        >
          <FileJson />
          {schemaStatus.loading ? "Loading…" : schema ? "Reload schema" : "Load schema"}
        </Button>
        <input
          ref={importInput}
          type="file"
          accept=".json,application/json"
          className="hidden"
          aria-label="Import schema JSON"
          onChange={(e) => void importSchema(e.target.files?.[0])}
        />
        <Button
          variant="ghost"
          size="sm"
          className="h-9"
          title="Import the JSON result of an introspection query"
          onClick={() => importInput.current?.click()}
        >
          <Download />
          Import schema
        </Button>
      </div>
      {schemaStatus.error && (
        <div
          role="alert"
          className="border-b border-border bg-destructive/5 px-4 py-2 text-xs text-destructive"
        >
          {schemaStatus.error}
        </div>
      )}
      <div className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[minmax(280px,360px)_1fr]">
        <aside className="flex min-h-64 flex-col border-b border-border lg:border-b-0 lg:border-r">
          {schema ? (
            <GraphqlExplorer
              schema={schema}
              onUse={use}
              onCopySdl={() => void copy(printSchema(schema), "Schema SDL")}
            />
          ) : (
            <p className="p-4 text-xs leading-5 text-muted-foreground">
              Enter an endpoint (add authentication under Headers) and choose <b>Load schema</b>, or
              open a GraphQL request from HTTP History with right-click → <b>Open in GraphQL</b>.
              The schema explorer lists every query, mutation and type; <b>Use</b> turns a field
              into a ready-to-send operation.
            </p>
          )}
        </aside>
        <section className="flex min-h-0 flex-col">
          <div className="flex min-h-64 flex-1 flex-col border-b border-border p-3">
            <div className="mb-2 flex flex-wrap items-center gap-1 text-xs" role="tablist">
              {(["query", "variables", "headers"] as const).map((id) => (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={editorTab === id}
                  className={cn(
                    "rounded px-2 py-1 capitalize",
                    editorTab === id
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-secondary/40",
                  )}
                  onClick={() => setEditorTab(id)}
                >
                  {id}
                </button>
              ))}
              <input
                aria-label="Operation name"
                className="inspector-input ml-2 h-7 w-40 text-xs"
                placeholder="Operation name (auto)"
                value={draft.operationName}
                onChange={(e) => update({ operationName: e.target.value })}
              />
              <div className="ml-auto flex gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 gap-1 px-2 text-xs"
                  onClick={prettify}
                >
                  <Wand2 className="size-3" />
                  Prettify
                </Button>
                <Button
                  size="sm"
                  className="h-7 gap-1 px-3 text-xs"
                  disabled={sending || !draft.endpoint.trim()}
                  onClick={guard(send)}
                >
                  <Play className="size-3" />
                  {sending ? "Sending…" : "Send"}
                </Button>
              </div>
            </div>
            {editorTab === "query" && (
              <textarea
                aria-label="GraphQL query"
                className={area}
                spellCheck={false}
                placeholder={"query {\n  __typename\n}"}
                value={draft.query}
                onChange={(e) => update({ query: e.target.value })}
                onKeyDown={(e) => {
                  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                    e.preventDefault();
                    guard(send)();
                  }
                }}
              />
            )}
            {editorTab === "variables" && (
              <textarea
                aria-label="GraphQL variables"
                className={area}
                spellCheck={false}
                placeholder={'{\n  "id": "1"\n}'}
                value={draft.variables}
                onChange={(e) => update({ variables: e.target.value })}
              />
            )}
            {editorTab === "headers" && (
              <textarea
                aria-label="GraphQL headers"
                className={area}
                spellCheck={false}
                placeholder={"Authorization: Bearer …\nX-Api-Key: …"}
                value={draft.headers}
                onChange={(e) => update({ headers: e.target.value })}
              />
            )}
          </div>
          <div className="flex min-h-64 flex-1 flex-col p-3">
            <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
              <div className="flex gap-1" role="tablist">
                {(["response", "headers"] as const).map((id) => (
                  <button
                    key={id}
                    type="button"
                    role="tab"
                    aria-selected={outputTab === id}
                    className={cn(
                      "rounded px-2 py-1",
                      outputTab === id
                        ? "bg-primary/10 text-primary"
                        : "text-muted-foreground hover:bg-secondary/40",
                    )}
                    onClick={() => setOutputTab(id)}
                  >
                    {id === "response" ? "Response" : "Response headers"}
                  </button>
                ))}
              </div>
              {outcome?.ok && (
                <span className="font-mono text-muted-foreground">
                  {outcome.status} {outcome.statusText} · {outcome.duration} ms · {outcome.size} B
                </span>
              )}
              <div className="ml-auto flex gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 gap-1 px-2 text-xs"
                  onClick={guard(() => copy(toCurl(currentRequest()), "cURL"))}
                >
                  <Copy className="size-3" />
                  Copy cURL
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 gap-1 px-2 text-xs"
                  onClick={guard(toReplay)}
                >
                  <ArrowUpRight className="size-3" />
                  Send to Replay
                </Button>
              </div>
            </div>
            {!outcome ? (
              <p className="text-xs text-muted-foreground">
                The response appears here. Press Ctrl/⌘+Enter in the query to send.
              </p>
            ) : !outcome.ok ? (
              <p role="alert" className="text-xs text-destructive">
                {outcome.error}
              </p>
            ) : outputTab === "headers" ? (
              <pre className="min-h-0 flex-1 overflow-auto rounded border border-border bg-background p-2 font-mono text-[11px]">
                {Object.entries(outcome.responseHeaders)
                  .map(([name, value]) => `${name}: ${value}`)
                  .join("\n")}
              </pre>
            ) : (
              <>
                {errors.length > 0 && (
                  <ul
                    role="alert"
                    className="mb-2 space-y-0.5 rounded border border-destructive/30 bg-destructive/5 p-2 text-xs text-destructive"
                  >
                    {errors.map((message, i) => (
                      <li key={i}>{message}</li>
                    ))}
                  </ul>
                )}
                <pre
                  aria-label="GraphQL response"
                  className="min-h-0 flex-1 overflow-auto rounded border border-border bg-background p-2 font-mono text-[11px]"
                >
                  {pretty(outcome.responseBody)}
                </pre>
              </>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
