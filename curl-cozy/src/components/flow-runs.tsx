import { ResponseDiffButton } from './response-diff';
import { useEffect, useState } from "react";
import { Button } from "./ui/button";
import { CodePane } from "./code-pane";
import { FlowVariablesForm } from "./flow-forms";
import { fetchFlowRun, fetchFlowRuns } from "@/lib/flows-api";
import { flowRunSummary, type Flow, type FlowRun, type FlowRunSummary } from "@/lib/flows";
import type { FlowRunOptions } from "@/lib/flow-runner";
import { requestText, responseText } from "@/lib/traffic";
import { useFlows } from "./flows-provider";
export function FlowRuns({
  onStart,
  onClone,
}: {
  onStart: (flow: Flow, options?: FlowRunOptions) => void;
  onClone: (run: FlowRun) => void;
}) {
  const { workspace, activeRun, localRuns, resume, skip, stop, runSaveError, retryRunSave } =
    useFlows();
  const [summaries, setSummaries] = useState<FlowRunSummary[]>([]),
    [more, setMore] = useState(false),
    [offset, setOffset] = useState(0),
    [loading, setLoading] = useState(false),
    [error, setError] = useState(""),
    [retry, setRetry] = useState(0),
    [selected, setSelected] = useState(""),
    [saved, setSaved] = useState<FlowRun | null>(null),
    [compareId, setCompareId] = useState(""),
    [baseline, setBaseline] = useState<FlowRun | null>(null),
    [resultIndex, setResultIndex] = useState(0),
    [pane, setPane] = useState<"response" | "request">("response");
  useEffect(() => {
    setSummaries([]);
    setOffset(0);
    setMore(false);
    setSelected("");
    setSaved(null);
    setCompareId("");
    setBaseline(null);
    setError("");
    if (!workspace) return;
    let cancelled = false;
    setLoading(true);
    void fetchFlowRuns(workspace)
      .then(
        (page) => {
          if (!cancelled) {
            setSummaries(page.data);
            setOffset(page.data.length);
            setMore(page.has_more);
          }
        },
        (error) => {
          if (!cancelled)
            setError(error instanceof Error ? error.message : "Could not load flow history");
        },
      )
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [workspace, retry]);
  useEffect(() => {
    if (activeRun) setSelected(activeRun.id);
  }, [activeRun?.id]);
  const local = localRuns.find((run) => run.id === selected);
  useEffect(() => {
    setSaved(null);
    setError("");
    if (!selected || local || !workspace) return;
    let cancelled = false;
    setLoading(true);
    void fetchFlowRun(workspace, selected)
      .then(
        (run) => {
          if (!cancelled) setSaved(run);
        },
        (error) => {
          if (!cancelled) setError(error instanceof Error ? error.message : "Could not load run");
        },
      )
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected, workspace, !!local]);
  const run = local ?? saved;
  useEffect(() => {
    setResultIndex(Math.max(0, (run?.results.length ?? 1) - 1));
  }, [run?.id, run?.results.length]);
  useEffect(() => {
    setBaseline(null);
    if (!compareId) return;
    const cached = localRuns.find((r) => r.id === compareId);
    if (cached) {
      setBaseline(cached);
      return;
    }
    if (!workspace) return;
    let cancelled = false;
    void fetchFlowRun(workspace, compareId).then(
      (run) => {
        if (!cancelled) setBaseline(run);
      },
      (error) => {
        if (!cancelled)
          setError(error instanceof Error ? error.message : "Could not load comparison run");
      },
    );
    return () => {
      cancelled = true;
    };
  }, [compareId, workspace, localRuns]);
  const combined = new Map(summaries.map((summary) => [summary.id, summary]));
  for (const local of localRuns) combined.set(local.id, flowRunSummary(local));
  const list = [...combined.values()].sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  const live =
    run?.id === activeRun?.id &&
    (["running", "paused"].includes(activeRun?.status ?? "") || activeRun?.sendingIndex !== null);
  const busy =
    !!activeRun &&
    (["running", "paused"].includes(activeRun.status) || activeRun.sendingIndex !== null);
  const result = run?.results[resultIndex],
    other = result
      ? (baseline?.results.find((r) => r.stepId === result.stepId) ??
        baseline?.results.find((r) => r.index === result.index))
      : undefined;
  const loadMore = async () => {
    if (!workspace || loading) return;
    setLoading(true);
    try {
      const page = await fetchFlowRuns(workspace, offset);
      setSummaries((prev) => [...prev, ...page.data]);
      setOffset(offset + page.data.length);
      setMore(page.has_more);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Could not load runs");
    } finally {
      setLoading(false);
    }
  };
  return (
    <div className="space-y-4 p-4 text-xs">
      <div className="flex flex-wrap gap-2">
        <select
          aria-label="Flow run"
          className="inspector-input min-w-0 flex-1"
          value={selected}
          onChange={(e) => {
            setSelected(e.target.value);
            setCompareId("");
          }}
        >
          <option value="">Select a run ({list.length} loaded)</option>
          {list.map((item) => (
            <option key={item.id} value={item.id}>
              {new Date(item.startedAt).toLocaleString()} · {item.name} · {item.status} ·{" "}
              {item.steps} steps
            </option>
          ))}
        </select>
        {more && (
          <Button variant="outline" size="sm" disabled={loading} onClick={() => void loadMore()}>
            Load older runs
          </Button>
        )}
        <Button variant="ghost" size="sm" onClick={() => setRetry((n) => n + 1)}>
          Refresh history
        </Button>
      </div>
      {loading && <p role="status">Loading flow history…</p>}
      {error && (
        <p role="alert" className="text-destructive">
          {error}
        </p>
      )}
      {runSaveError && (
        <p role="alert" className="text-destructive">
          {runSaveError}{" "}
          <Button variant="ghost" size="sm" onClick={retryRunSave}>
            Retry saving run
          </Button>
        </p>
      )}
      {!workspace && (
        <p className="text-muted-foreground">
          Temporary runs are kept in memory and lost on reload.
        </p>
      )}
      {!run && !loading && (
        <p className="text-muted-foreground">
          Run a flow to inspect each step, pause for input, and compare results.
        </p>
      )}
      {run && (
        <>
          <div className="flex flex-wrap items-center gap-3 rounded border border-border p-3">
            <strong>{run.flow.name}</strong>{run.profileName&&<span>Profile: {run.profileName}</span>}
            <span
              role="status"
              className={run.status === "failed" ? "text-destructive" : "text-primary"}
            >
              {!live && run.status === "running" ? "Interrupted browser session" : run.status}
            </span>
            <span>
              {run.duration} ms · {run.results.length} recorded steps
            </span>
            {run.sendingIndex !== null && live && (
              <span>Sending {run.flow.steps[run.sendingIndex]?.name}…</span>
            )}
            <div className="ml-auto flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={() => onClone(run)}>
                Clone run to flow
              </Button>
              {live && (
                <Button variant="destructive" size="sm" onClick={stop}>
                  Stop run
                </Button>
              )}
            </div>
          </div>
          {run.message && <p className="text-muted-foreground">{run.message}</p>}
          {live && run.status === "paused" && (
            <section className="space-y-3 rounded border border-primary/40 p-4">
              <h3 className="font-medium">
                Paused before step {run.nextIndex + 1}: {run.flow.steps[run.nextIndex]?.name}
              </h3>
              <p>{run.flow.steps[run.nextIndex]?.pauseMessage}</p>
              <FlowVariablesForm
                key={`${run.id}:${run.nextIndex}`}
                label="Run"
                variables={run.variables}
                action="Continue run"
                onApply={resume}
              />
              <Button
                variant="outline"
                size="sm"
                onClick={() => void skip().catch((error) => setError(String(error)))}
              >
                Skip paused step
              </Button>
            </section>
          )}
          {!live && run.nextIndex < run.endIndex && (
            <Button
              variant="outline"
              size="sm"
              disabled={busy}
              onClick={() =>
                onStart(run.flow, {
                  variables: run.variables,
                  startIndex: run.nextIndex,
                  endIndex: run.endIndex,
                  parentRunId: run.id,
                  ...(run.profileId&&{profileId:run.profileId}),
                })
              }
            >
              Continue checkpoint as new run
            </Button>
          )}
          <details>
            <summary className="cursor-pointer">
              Run variables ({Object.keys(run.variables).length})
            </summary>
            <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words rounded bg-secondary p-3">
              {JSON.stringify(run.variables, null, 2)}
            </pre>
          </details>
          <label className="flex flex-wrap items-center gap-2">
            <span>Compare with</span>
            <select
              aria-label="Compare flow run"
              className="inspector-input min-w-0 flex-1"
              value={compareId}
              onChange={(e) => setCompareId(e.target.value)}
            >
              <option value="">No comparison</option>
              {list
                .filter((item) => item.id !== run.id)
                .map((item) => (
                  <option key={item.id} value={item.id}>
                    {new Date(item.startedAt).toLocaleString()} · {item.name} · {item.status}
                  </option>
                ))}
            </select>
          </label>
          {baseline && (
            <div className="overflow-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-border">
                    <th className="p-2">Step</th>
                    <th>Selected run</th>
                    <th>Compared run</th>
                    <th>Request / response changed</th>
                  </tr>
                </thead>
                <tbody>
                  {run.results.map((row) => {
                    const other =
                      baseline.results.find((r) => r.stepId === row.stepId) ??
                      baseline.results.find((r) => r.index === row.index);
                    return (
                      <tr key={row.index} className="border-b border-border">
                        <td className="p-2">
                          {row.index + 1}. {row.name}
                        </td>
                        <td>
                          {row.status} · HTTP {row.response?.status ?? "—"} · {row.duration} ms
                        </td>
                        <td>
                          {other
                            ? `${other.status} · HTTP ${other.response?.status ?? "—"} · ${other.duration} ms`
                            : "Not run"}
                        </td>
                        <td>
                          {other
                            ? `${JSON.stringify(row.request) !== JSON.stringify(other.request) ? "Request changed" : "Request unchanged"} / ${JSON.stringify([row.response?.status, row.response?.responseHeaders, row.response?.responseBody]) !== JSON.stringify([other.response?.status, other.response?.responseHeaders, other.response?.responseBody]) ? "Response changed" : "Response unchanged"}`
                            : "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            <select
              aria-label="Flow step result"
              className="inspector-input min-w-0 flex-1"
              value={resultIndex}
              onChange={(e) => setResultIndex(Number(e.target.value))}
            >
              {run.results.map((result, i) => (
                <option key={i} value={i}>
                  {result.index + 1}. {result.name} · {result.status} · HTTP {result.response?.status ?? '—'} · {result.duration} ms
                </option>
              ))}
            </select>
            {result && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy}
                  onClick={() =>
                    onStart(run.flow, {
                      variables: result.variablesBefore,
                      startIndex: result.index,
                      endIndex: result.index + 1,
                      parentRunId: run.id,
                      ...(run.profileId&&{profileId:run.profileId}),
                    })
                  }
                >
                  Re-run this step
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy}
                  onClick={() =>
                    onStart(run.flow, {
                      variables: result.variablesBefore,
                      startIndex: result.index,
                      parentRunId: run.id,
                      ...(run.profileId&&{profileId:run.profileId}),
                    })
                  }
                >
                  Run from this step
                </Button>
              </>
            )}
          </div>
          {result && (
            <>
              {result.error && (
                <p role="alert" className="text-destructive">
                  {result.error}
                </p>
              )}
              <ul className="space-y-1">
                {result.checks.map((check, i) => (
                  <li key={i} className={check.passed ? "text-primary" : "text-destructive"}>
                    {check.passed ? "Pass" : "Fail"} · {check.message}
                  </li>
                ))}
              </ul>
              {result.scriptResult && (
                <details open={!!result.scriptResult.error}>
                  <summary className="cursor-pointer">
                    After response script {result.scriptResult.error ? "· Failed" : ""}
                  </summary>
                  {result.scriptResult.error && (
                    <p className="text-destructive">{result.scriptResult.error}</p>
                  )}
                  <pre className="max-h-40 overflow-auto whitespace-pre-wrap">
                    {result.scriptResult.logs.join("\n")}
                  </pre>
                </details>
              )}
              <details>
                <summary className="cursor-pointer">Variables before / after step</summary>
                <div className="grid gap-2 sm:grid-cols-2">
                  <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words bg-secondary p-2">
                    {JSON.stringify(result.variablesBefore, null, 2)}
                  </pre>
                  <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words bg-secondary p-2">
                    {JSON.stringify(result.variablesAfter, null, 2)}
                  </pre>
                </div>
              </details>
              {result.response&&other?.response&&<ResponseDiffButton left={other.response} right={result.response} label="Compare step responses"/>}
              <div className="flex gap-2">
                <Button
                  variant={pane === "request" ? "secondary" : "ghost"}
                  size="sm"
                  onClick={() => setPane("request")}
                >
                  Sent request
                </Button>
                <Button
                  variant={pane === "response" ? "secondary" : "ghost"}
                  size="sm"
                  onClick={() => setPane("response")}
                >
                  Response
                </Button>
              </div>
              <div className={`grid gap-3 ${baseline ? "lg:grid-cols-2" : ""}`}>
                {[result, ...(baseline ? [other] : [])].map((row, i) => (
                  <div
                    key={i}
                    className="flex h-[380px] min-w-0 flex-col overflow-hidden rounded border border-border"
                  >
                    {pane === "request" && row?.request ? (
                      <CodePane
                        title={i ? "Compared request" : "Sent request"}
                        body={requestText(row.request)}
                        raw={requestText(row.request)}
                        headers={row.request.headers}
                      />
                    ) : pane === "response" && row?.response ? (
                      <CodePane
                        title={i ? "Compared response" : "Response"}
                        body={row.response.responseBody}
                        raw={responseText(row.response)}
                        headers={row.response.responseHeaders}
                      />
                    ) : (
                      <p className="p-4 text-muted-foreground">
                        {row?.error || "No recorded data for this step."}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
          <p className="text-muted-foreground">
            Re-running a step sends another real request. Checkpoints restore client variables; they
            do not roll back server state.
          </p>
        </>
      )}
    </div>
  );
}
