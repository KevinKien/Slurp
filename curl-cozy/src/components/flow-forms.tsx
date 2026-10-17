import { useEffect, useState } from "react";
import { Plus, X } from "lucide-react";
import { Button } from "./ui/button";
import { methods } from "@/lib/traffic";
import {
  validateFlowVariables,
  type FlowStep,
  type FlowExtractor,
  type FlowAssertion,
} from "@/lib/flows";
import type { ReplayVariables } from "@/lib/replay-features";
export function FlowVariablesForm({
  variables,
  onApply,
  label = "Flow",
  action = "Apply variables",
}: {
  variables: ReplayVariables;
  onApply: (value: ReplayVariables) => void | Promise<void>;
  label?: string;
  action?: string;
}) {
  const [rows, setRows] = useState<[string, string][]>(Object.entries(variables)),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const apply = async () => {
    try {
      setError("");
      const value = Object.fromEntries(rows);
      if (Object.keys(value).length !== rows.length) throw Error("Duplicate variable names.");
      validateFlowVariables(value);
      setBusy(true);
      await onApply(value);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Could not apply variables");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Use {"{{variable}}"} in URL, headers and body. These values belong to{" "}
        {label === "Run" ? "this run only" : "this flow; each new run receives its own copy"}.
      </p>
      {rows.map(([key, value], i) => (
        <div key={i} className="grid grid-cols-[1fr_2fr_28px] gap-2">
          <input
            aria-label={`${label} variable name ${i + 1}`}
            className="inspector-input min-w-0 text-xs"
            value={key}
            maxLength={100}
            onChange={(e) =>
              setRows((prev) => prev.map((r, n) => (n === i ? [e.target.value, r[1]] : r)))
            }
          />
          <input
            aria-label={`${label} variable value ${i + 1}`}
            className="inspector-input min-w-0 font-mono text-xs"
            value={value}
            onChange={(e) =>
              setRows((prev) => prev.map((r, n) => (n === i ? [r[0], e.target.value] : r)))
            }
          />
          <Button
            variant="ghost"
            size="icon"
            aria-label={`Remove ${label.toLowerCase()} variable ${i + 1}`}
            onClick={() => setRows((prev) => prev.filter((_, n) => n !== i))}
          >
            <X />
          </Button>
        </div>
      ))}
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={rows.length >= 100 || busy}
          onClick={() => setRows((prev) => [...prev, ["", ""]])}
        >
          <Plus />
          Add variable
        </Button>
        <Button size="sm" disabled={busy} onClick={() => void apply()}>
          {action}
        </Button>
      </div>
    </div>
  );
}
export function FlowStepEditor({
  step,
  onSave,
}: {
  step: FlowStep;
  onSave: (step: FlowStep) => void;
}) {
  const [draft, setDraft] = useState(() => structuredClone(step)),
    [headers, setHeaders] = useState(JSON.stringify(step.request.headers, null, 2)),
    [error, setError] = useState(""),
    [saved, setSaved] = useState(false);
  useEffect(() => {
    setDraft(structuredClone(step));
    setHeaders(JSON.stringify(step.request.headers, null, 2));
    setError("");
    setSaved(false);
  }, [step]);
  const change = (patch: Partial<FlowStep>) => {
    setDraft((prev) => ({ ...prev, ...patch }));
    setSaved(false);
  };
  const request = (patch: Partial<FlowStep["request"]>) =>
    change({ request: { ...draft.request, ...patch } });
  const save = () => {
    try {
      const parsed: unknown = JSON.parse(headers);
      if (
        !parsed ||
        typeof parsed !== "object" ||
        Array.isArray(parsed) ||
        Object.values(parsed).some((v) => typeof v !== "string")
      )
        throw Error("Headers must be a JSON object with string values.");
      onSave({
        ...draft,
        request: { ...draft.request, headers: parsed as Record<string, string> },
      });
      setError("");
      setSaved(true);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Could not save step");
    }
  };
  const extractor = (i: number, patch: Partial<FlowExtractor>) =>
    change({
      extractors: draft.extractors.map((row, n) => (n === i ? { ...row, ...patch } : row)),
    });
  const assertion = (i: number, patch: Partial<FlowAssertion>) =>
    change({
      assertions: draft.assertions.map((row, n) => (n === i ? { ...row, ...patch } : row)),
    });
  return (
    <div className="space-y-4 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="font-medium">Step editor</h2>
        <div className="flex items-center gap-2">
          {saved && <span className="text-muted-foreground">Applied</span>}
          <Button size="sm" onClick={save}>
            Apply step changes
          </Button>
        </div>
      </div>
      <label className="block space-y-1">
        <span>Step name</span>
        <input
          aria-label="Step name"
          className="inspector-input w-full"
          maxLength={200}
          value={draft.name}
          onChange={(e) => change({ name: e.target.value })}
        />
      </label>
      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={draft.enabled}
          onChange={(e) => change({ enabled: e.target.checked })}
        />
        Enabled (disable to test skipping this step)
      </label>
      <div className="flex gap-2">
        <select
          aria-label="Flow request method"
          className="inspector-input w-24 shrink-0"
          value={draft.request.method}
          onChange={(e) => request({ method: e.target.value })}
        >
          {methods.map((m) => (
            <option key={m}>{m}</option>
          ))}
        </select>
        <input
          aria-label="Flow request URL"
          className="inspector-input min-w-0 flex-1 font-mono"
          placeholder="https://api.example.com/login"
          value={draft.request.url}
          maxLength={4096}
          onChange={(e) => request({ url: e.target.value })}
        />
      </div>
      <label className="block space-y-1">
        <span>Headers (JSON object)</span>
        <textarea
          aria-label="Flow request headers"
          className="inspector-input min-h-24 w-full font-mono"
          spellCheck={false}
          value={headers}
          onChange={(e) => {
            setHeaders(e.target.value);
            setSaved(false);
          }}
        />
      </label>
      <label className="block space-y-1">
        <span>Request body</span>
        <textarea
          aria-label="Flow request body"
          className="inspector-input min-h-36 w-full font-mono"
          spellCheck={false}
          value={draft.request.body}
          onChange={(e) => request({ body: e.target.value })}
        />
      </label>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="space-y-1">
          <span>Expected HTTP status</span>
          <input
            aria-label="Expected HTTP status"
            className="inspector-input w-full font-mono"
            placeholder="2xx, 200,201 or empty for any"
            value={draft.expectedStatus}
            onChange={(e) => change({ expectedStatus: e.target.value })}
          />
        </label>
        <label className="space-y-1">
          <span>On failure</span>
          <select
            aria-label="On step failure"
            className="inspector-input w-full"
            value={draft.onFailure}
            onChange={(e) => change({ onFailure: e.target.value as FlowStep["onFailure"] })}
          >
            <option value="stop">Stop flow</option>
            <option value="continue">Continue to next step</option>
          </select>
        </label>
      </div>
      <div className="space-y-2 rounded border border-border p-3">
        <label className="flex items-center gap-2">
          <input
            aria-label="Pause before step"
            type="checkbox"
            checked={draft.pauseBefore}
            onChange={(e) => change({ pauseBefore: e.target.checked })}
          />
          Pause before sending this step (OTP or manual edits)
        </label>
        {draft.pauseBefore && (
          <input
            aria-label="Pause instructions"
            className="inspector-input w-full"
            maxLength={2000}
            value={draft.pauseMessage}
            onChange={(e) => change({ pauseMessage: e.target.value })}
          />
        )}
      </div>
      <div className="space-y-2">
        <h3 className="font-medium">Extract variables after response</h3>
        <p className="text-muted-foreground">
          JSON paths: data.access_token, items[0].id or /data/id. Extracted values are available to
          the script below and subsequent steps.
        </p>
        {draft.extractors.map((row, i) => (
          <div key={i} className="flex flex-wrap gap-2">
            <input
              aria-label={`Extract variable ${i + 1}`}
              className="inspector-input min-w-24 flex-1"
              placeholder="token"
              value={row.variable}
              onChange={(e) => extractor(i, { variable: e.target.value })}
            />
            <select
              aria-label={`Extract source ${i + 1}`}
              className="inspector-input w-24"
              value={row.source}
              onChange={(e) => extractor(i, { source: e.target.value as FlowExtractor["source"] })}
            >
              <option value="json">JSON</option>
              <option value="header">Header</option>
              <option value="text">Text body</option>
            </select>
            <input
              aria-label={`Extract path ${i + 1}`}
              className="inspector-input min-w-28 flex-1 font-mono"
              placeholder={row.source === "header" ? "x-request-id" : "data.access_token"}
              disabled={row.source === "text"}
              value={row.path}
              onChange={(e) => extractor(i, { path: e.target.value })}
            />
            <Button
              variant="ghost"
              size="icon"
              aria-label={`Remove extractor ${i + 1}`}
              onClick={() => change({ extractors: draft.extractors.filter((_, n) => n !== i) })}
            >
              <X />
            </Button>
          </div>
        ))}
        <Button
          variant="outline"
          size="sm"
          disabled={draft.extractors.length >= 20}
          onClick={() =>
            change({
              extractors: [...draft.extractors, { variable: "token", source: "json", path: "" }],
            })
          }
        >
          <Plus />
          Add extractor
        </Button>
      </div>
      <div className="space-y-2">
        <h3 className="font-medium">JSON response checks</h3>
        <p className="text-muted-foreground">
          Equals accepts JSON literals (true, 42, "text") or plain text. Contains checks a string
          value.
        </p>
        {draft.assertions.map((row, i) => (
          <div key={i} className="flex flex-wrap gap-2">
            <input
              aria-label={`Check path ${i + 1}`}
              className="inspector-input min-w-28 flex-1 font-mono"
              placeholder="data.verified"
              value={row.path}
              onChange={(e) => assertion(i, { path: e.target.value })}
            />
            <select
              aria-label={`Check operator ${i + 1}`}
              className="inspector-input w-28"
              value={row.operator}
              onChange={(e) =>
                assertion(i, { operator: e.target.value as FlowAssertion["operator"] })
              }
            >
              <option value="exists">Exists</option>
              <option value="equals">Equals</option>
              <option value="contains">Contains</option>
            </select>
            <input
              aria-label={`Check expected ${i + 1}`}
              className="inspector-input min-w-24 flex-1"
              disabled={row.operator === "exists"}
              value={row.expected}
              onChange={(e) => assertion(i, { expected: e.target.value })}
            />
            <Button
              variant="ghost"
              size="icon"
              aria-label={`Remove check ${i + 1}`}
              onClick={() => change({ assertions: draft.assertions.filter((_, n) => n !== i) })}
            >
              <X />
            </Button>
          </div>
        ))}
        <Button
          variant="outline"
          size="sm"
          disabled={draft.assertions.length >= 20}
          onClick={() =>
            change({
              assertions: [...draft.assertions, { path: "", operator: "exists", expected: "" }],
            })
          }
        >
          <Plus />
          Add check
        </Button>
      </div>
      <details>
        <summary className="cursor-pointer font-medium">After response script</summary>
        <p className="my-2 text-muted-foreground">
          Uses the same API as Replay Scripts, with variables isolated to this run.{" "}
          <a
            className="text-primary underline"
            href="/docs/replay-scripts.html"
            target="_blank"
            rel="noopener noreferrer"
          >
            Script documentation
          </a>
        </p>
        <textarea
          aria-label="Flow after response script"
          className="inspector-input min-h-40 w-full font-mono"
          value={draft.afterResponse}
          maxLength={32000}
          spellCheck={false}
          onChange={(e) => change({ afterResponse: e.target.value })}
        />
      </details>
      {error && (
        <p role="alert" className="text-destructive">
          {error}
        </p>
      )}
      <p className="text-muted-foreground">
        Apply changes before running or selecting another step. Sending uses Replay's public HTTPS
        and timeout rules.
      </p>
    </div>
  );
}
