import { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { useScan } from "@/lib/scan-context";
import {
  scanChecks,
  parameterKey,
  type ScanPlan,
  type ScanRun,
  type ScanEvidence,
} from "@/lib/scan";
import { scanParameters } from "@/lib/scan-selection";
import { fetchScanRuns, fetchScanRun, deleteScanRun, type ScanSummary } from "@/lib/scan-api";
import { Button } from "./ui/button";
import { ProfileSelector } from "./auth-profiles";
import { RequestMenu } from "./request-menu";
import { CodePane } from "./code-pane";
import { ScanDashboard } from "./scan-dashboard";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "./ui/dialog";
import { ResponseDiffButton } from "./response-diff";
const input = "rounded border border-border bg-background p-2 text-sm";
const report = (e: unknown) => toast.error(e instanceof Error ? e.message : String(e));
export function ScanView() {
  const scan = useScan(),
    plan = scan.draft;
  const [history, setHistory] = useState<ScanSummary[]>([]),
    [offset, setOffset] = useState(0),
    [more, setMore] = useState(false),
    [selectedId, setSelectedId] = useState(""),
    [saved, setSaved] = useState<ScanRun | null>(null),
    [historyError, setHistoryError] = useState(""),
    [loading, setLoading] = useState(false),
    [refresh, setRefresh] = useState(0),
    [filter, setFilter] = useState("all"),
    [focusFinding, setFocusFinding] = useState("");
  const view = useRef("");
  view.current = `${scan.workspace}:${selectedId}`;
  useEffect(() => {
    setSelectedId("");
    setSaved(null);
    setHistory([]);
    setOffset(0);
    setHistoryError("");
  }, [scan.workspace]);
  useEffect(() => {
    let current = true;
    if (!scan.workspace) return;
    void fetchScanRuns(scan.workspace, offset)
      .then((v) => {
        if (current) {
          setHistory(v.data);
          setMore(v.has_more);
          setHistoryError("");
        }
      })
      .catch((e) => {
        if (current) setHistoryError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      current = false;
    };
  }, [scan.workspace, offset, scan.run?.status, scan.busy, refresh]);
  const local = scan.localRuns.find((r) => r.id === selectedId);
  useEffect(() => {
    setSaved(null);
    if (!selectedId || local || !scan.workspace) {
      setLoading(false);
      return;
    }
    let current = true;
    setLoading(true);
    void fetchScanRun(scan.workspace, selectedId)
      .then((r) => {
        if (current) {
          setSaved(r);
          setHistoryError("");
        }
      })
      .catch((e) => {
        if (current) setHistoryError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [scan.workspace, selectedId, local, refresh]);
  const run = selectedId ? (local ?? saved) : null;
  const options = Array.from(
    new Map([...history, ...scan.localRuns].map((r) => [r.id, r])).values(),
  );
  const candidates = useMemo(() => (plan ? scanParameters(plan.request) : []), [plan?.request]);
  const update = (patch: Partial<ScanPlan>) => {
    if (plan) scan.updateDraft({ ...plan, ...patch });
  };
  const mode = (value: ScanPlan["mode"]) => {
    if (plan)
      update({
        mode: value,
        allowSending: false,
        checks:
          value === "passive"
            ? plan.checks.filter((id) => !scanChecks.find((c) => c.id === id)?.active)
            : plan.checks,
      });
  };
  const remove = async () => {
    if (!run || !scan.workspace) return;
    const snapshot = view.current,
      id = run.id;
    try {
      await deleteScanRun(scan.workspace, id);
      if (view.current === snapshot) {
        setSelectedId("");
        setSaved(null);
        setRefresh((v) => v + 1);
        scan.forget(id);
      }
    } catch (e) {
      report(e);
    }
  };
  return (
    <div className="h-full overflow-auto p-5 space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <div className="mr-auto">
          <h1 className="text-xl font-semibold">Dashboard</h1>
          <p className="mt-1 text-xs text-muted-foreground">
            Monitor scan tasks and review findings in this workspace.
          </p>
        </div>
        {plan && (
          <Button variant="outline" onClick={() => scan.setConfiguring(true)}>
            Configure scan
          </Button>
        )}
        <a
          href="/docs/scan.html"
          target="_blank"
          rel="noreferrer"
          className="text-xs text-primary underline"
        >
          Documentation
        </a>
      </div>
      {scan.preparing && <p role="status">Loading the selected request…</p>}
      <ScanDashboard
        tasks={options}
        offset={offset}
        more={more}
        onPage={setOffset}
        onRefresh={() => setRefresh((v) => v + 1)}
        onSelect={(id, finding) => {
          setSelectedId(id);
          setFocusFinding(finding ?? "");
          setFilter("all");
        }}
      />
      {historyError && (
        <p role="alert" className="text-sm text-destructive">
          {historyError}
        </p>
      )}
      <Dialog open={scan.configuring} onOpenChange={scan.setConfiguring}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Configure scan</DialogTitle>
            <DialogDescription>
              Choose checks and request limits for the selected endpoint.
            </DialogDescription>
          </DialogHeader>
          {scan.preparing ? (
            <p role="status">Loading the selected request…</p>
          ) : plan ? (
            <section className="space-y-3 rounded border p-4">
              <div className="flex gap-2 min-w-0 items-center">
                <strong>{plan.request.method}</strong>
                <span className="break-all font-mono text-xs">{plan.request.url}</span>
              </div>
              <details>
                <summary className="cursor-pointer text-sm">Request to scan</summary>
                <pre className="max-h-52 overflow-auto whitespace-pre-wrap text-xs">
                  {JSON.stringify(plan.request, null, 2)}
                </pre>
              </details>
              <fieldset disabled={scan.busy} className="space-y-4 disabled:opacity-60">
                <div className="flex flex-wrap items-center gap-4">
                  <label className="text-sm">
                    Mode{" "}
                    <select
                      aria-label="Scan mode"
                      className={input}
                      value={plan.mode}
                      onChange={(e) => mode(e.target.value as ScanPlan["mode"])}
                    >
                      <option value="passive" disabled={!plan.observed}>
                        Passive — inspect captured response
                      </option>
                      <option value="active">Active — send requests</option>
                    </select>
                  </label>
                  {plan.mode === "active" && <ProfileSelector />}
                </div>
                <p className="text-xs text-muted-foreground">
                  {plan.mode === "passive"
                    ? "Inspects the captured response without sending requests. Cookie checks need separate Set-Cookie fields; collapsed history headers can be inconclusive."
                    : "Uses the selected profile and the Replay HTTP(S) sender (including localhost and LAN). Requests run sequentially. Repeated requests may change server state."}
                </p>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {scanChecks.map((check) => (
                    <label key={check.id} className="flex gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={plan.checks.includes(check.id)}
                        disabled={plan.mode === "passive" && check.active}
                        onChange={(e) =>
                          update({
                            checks: e.target.checked
                              ? [...plan.checks, check.id]
                              : plan.checks.filter((id) => id !== check.id),
                          })
                        }
                      />
                      {check.name}
                      {check.active && (
                        <span className="text-xs text-muted-foreground">Active</span>
                      )}
                    </label>
                  ))}
                </div>
                {plan.mode === "active" && (
                  <>
                    <div>
                      <h2 className="text-sm font-medium">
                        Parameters to test ({plan.parameters.length}/10)
                      </h2>
                      <p className="text-xs text-muted-foreground">
                        Reflection and input-error checks require an explicit parameter selection.
                      </p>
                      <div className="max-h-48 overflow-auto space-y-2 py-2">
                        {candidates.length ? (
                          candidates.map((parameter) => {
                            const key = parameterKey(parameter),
                              checked = plan.parameters.some((p) => parameterKey(p) === key);
                            return (
                              <label key={key} className="flex gap-2 text-xs font-mono">
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  disabled={!checked && plan.parameters.length >= 10}
                                  onChange={(e) =>
                                    update({
                                      parameters: e.target.checked
                                        ? [...plan.parameters, parameter]
                                        : plan.parameters.filter((p) => parameterKey(p) !== key),
                                    })
                                  }
                                />
                                {parameter.kind === "query"
                                  ? `Query: ${parameter.name} (occurrence ${parameter.occurrence + 1})`
                                  : `JSON: ${parameter.pointer}`}
                              </label>
                            );
                          })
                        ) : (
                          <p className="text-xs text-muted-foreground">
                            No supported query or JSON scalar parameters found. CORS and response
                            checks can still run.
                          </p>
                        )}
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-3">
                      {(["baselineSamples", "maxRequests", "rate", "delay"] as const).map(
                        (field) => (
                          <label key={field} className="text-xs">
                            {
                              {
                                baselineSamples: "Baseline samples (2–3)",
                                maxRequests: "Maximum requests (1–100)",
                                rate: "Requests / second (1–20)",
                                delay: "Minimum delay (ms)",
                              }[field]
                            }
                            <input
                              aria-label={field}
                              type="number"
                              className={input + " block w-40"}
                              value={plan[field]}
                              min={field === "delay" ? 0 : field === "baselineSamples" ? 2 : 1}
                              max={
                                field === "baselineSamples"
                                  ? 3
                                  : field === "maxRequests"
                                    ? 100
                                    : field === "rate"
                                      ? 20
                                      : 60000
                              }
                              onChange={(e) => update({ [field]: Number(e.target.value) })}
                            />
                          </label>
                        ),
                      )}
                    </div>
                    <label className="block text-xs">
                      Ignore dynamic JSON paths (one per line)
                      <textarea
                        aria-label="Ignored JSON paths"
                        className={input + " block w-full h-20 font-mono"}
                        value={plan.diffOptions.ignoredPaths.join("\n")}
                        onChange={(e) =>
                          update({
                            diffOptions: {
                              ...plan.diffOptions,
                              ignoredPaths: e.target.value.split("\n").filter(Boolean),
                            },
                          })
                        }
                      />
                    </label>
                    <label className="flex items-start gap-2 text-sm">
                      <input
                        aria-label="Allow sending scan requests"
                        type="checkbox"
                        checked={plan.allowSending}
                        onChange={(e) => update({ allowSending: e.target.checked })}
                      />
                      I allow this scan to send up to {plan.maxRequests} requests to this endpoint,
                      including repeated baseline and control requests.
                    </label>
                  </>
                )}
              </fieldset>
              <div className="flex gap-2 flex-wrap">
                <Button
                  disabled={
                    scan.busy ||
                    !plan.checks.length ||
                    (plan.mode === "active" && !plan.allowSending)
                  }
                  onClick={() => {
                    try {
                      scan.start(plan);
                      scan.setConfiguring(false);
                      setSelectedId("");
                      setFilter("all");
                    } catch (e) {
                      report(e);
                    }
                  }}
                >
                  {plan.mode === "passive" ? "Inspect response" : "Start scan"}
                </Button>
                <Button
                  variant="outline"
                  disabled={!scan.busy}
                  onClick={scan.run?.status === "paused" ? scan.resume : scan.pause}
                >
                  {scan.run?.status === "paused" ? "Resume" : "Pause"}
                </Button>
                <Button variant="destructive" disabled={!scan.busy} onClick={scan.stop}>
                  Stop
                </Button>
              </div>
            </section>
          ) : (
            <p className="text-sm text-muted-foreground">
              Right-click a request in HTTP History, Replay or Intercept and choose Scan to
              configure a scan.
            </p>
          )}
        </DialogContent>
      </Dialog>
      {scan.error && (
        <div role="alert" className="text-sm text-destructive">
          {scan.error}
          <Button
            variant="outline"
            disabled={scan.busy}
            onClick={() => void scan.retrySave().catch(report)}
          >
            Retry evidence saving
          </Button>
        </div>
      )}
      <Dialog
        open={!!selectedId}
        onOpenChange={(open) => {
          if (!open) setSelectedId("");
        }}
      >
        <DialogContent className="max-w-5xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Scan task details</DialogTitle>
            <DialogDescription>
              Findings, verification results and request / response evidence.
            </DialogDescription>
          </DialogHeader>
          <section className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <select
                aria-label="Scan run"
                className={input}
                value={selectedId}
                onChange={(e) => {
                  setSelectedId(e.target.value);
                  setFilter("all");
                }}
              >
                <option value="">Select a task</option>
                {options.map((r) => (
                  <option key={r.id} value={r.id}>
                    {new Date(r.startedAt).toLocaleString()} — {r.status} (
                    {Array.isArray(r.findings) ? r.findings.length : r.findings} findings)
                  </option>
                ))}
              </select>
              {scan.workspace && (
                <>
                  <Button
                    variant="outline"
                    disabled={!offset}
                    onClick={() => setOffset(Math.max(0, offset - 50))}
                  >
                    Newer
                  </Button>
                  <Button variant="outline" disabled={!more} onClick={() => setOffset(offset + 50)}>
                    Older
                  </Button>
                  <Button variant="outline" onClick={() => setRefresh((v) => v + 1)}>
                    Refresh
                  </Button>
                  <Button
                    variant="outline"
                    disabled={!run || scan.busy}
                    onClick={() => void remove()}
                  >
                    Delete run
                  </Button>
                </>
              )}
            </div>
            {historyError && (
              <p role="alert" className="text-sm text-destructive">
                {historyError}
              </p>
            )}
            {loading ? (
              <p role="status">Loading scan evidence…</p>
            ) : run ? (
              <>
                <div className="flex flex-wrap gap-4 text-sm">
                  <strong>{run.status}</strong>
                  <span>{run.sent} requests sent</span>
                  <span>{run.findings.length} findings</span>
                  <span>
                    Baseline:{" "}
                    {run.baselineStable === null
                      ? "Not compared"
                      : run.baselineStable
                        ? "Stable"
                        : "Changed"}
                  </span>
                  {run.profileName && <span>Profile: {run.profileName}</span>}
                </div>
                {run.message && (
                  <p role="status" className="text-sm">
                    {run.message}
                  </p>
                )}
                <p className="text-xs text-muted-foreground">
                  Verified refers to the stated observation and its verification method. Reflection
                  does not establish XSS; CORS findings require browser review. A completed scan
                  with no findings does not prove the endpoint is secure.
                </p>
                <label className="text-xs">
                  Finding status{" "}
                  <select
                    aria-label="Finding status"
                    className={input}
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                  >
                    {["all", "verified", "suspected", "needs_review", "false_positive"].map((v) => (
                      <option key={v}>{v}</option>
                    ))}
                  </select>
                </label>
                {run.findings
                  .filter((f) => filter === "all" || f.status === filter)
                  .map((f) => (
                    <details
                      key={f.id}
                      open={focusFinding === f.id ? true : undefined}
                      className="rounded border p-3"
                    >
                      <summary className="cursor-pointer text-sm">
                        <span className="mr-2 uppercase text-xs">{f.severity}</span>
                        {f.title}
                        <span className="ml-3 text-xs text-muted-foreground">
                          {f.status} · {f.confidence} confidence
                        </span>
                      </summary>
                      <div className="pt-3 space-y-3 text-sm">
                        <p>{f.summary}</p>
                        {f.parameter && (
                          <p className="font-mono text-xs">{parameterKey(f.parameter)}</p>
                        )}
                        <p>
                          <strong>Verification: </strong>
                          {f.verification.method} — {f.verification.outcome}
                        </p>
                        <p>{f.verification.reason}</p>
                        <pre className="overflow-auto whitespace-pre-wrap text-xs">
                          {f.excerpts.join("\n")}
                        </pre>
                        <p>
                          <strong>Remediation: </strong>
                          {f.remediation}
                        </p>
                        <EvidenceList run={run} ids={f.evidenceIds} />
                      </div>
                    </details>
                  ))}
                {!run.findings.length && (
                  <p className="text-sm">
                    No findings recorded. Check the results below for skipped or inconclusive
                    checks.
                  </p>
                )}
                <details>
                  <summary className="cursor-pointer text-sm">
                    Check results ({run.checks.length})
                  </summary>
                  <ul className="space-y-2 py-3 text-xs">
                    {run.checks.map((check, i) => (
                      <li key={i}>
                        <strong>
                          {check.checkId}
                          {check.parameter ? ` · ${parameterKey(check.parameter)}` : ""}:{" "}
                          {check.status}
                        </strong>{" "}
                        — {check.message}
                      </li>
                    ))}
                  </ul>
                </details>
                <details>
                  <summary className="cursor-pointer text-sm">
                    All request / response evidence ({run.evidence.length})
                  </summary>
                  <EvidenceList run={run} ids={run.evidence.map((e) => e.id)} />
                </details>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No scan results selected.</p>
            )}
          </section>
        </DialogContent>
      </Dialog>
    </div>
  );
}
function EvidenceList({ run, ids }: { run: ScanRun; ids: string[] }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const baseline = run.evidence.find((e) => run.baselineIds.includes(e.id) && e.response);
  return (
    <div className="space-y-2 pt-2">
      {ids
        .map((id) => run.evidence.find((e) => e.id === id))
        .filter((e): e is ScanEvidence => !!e)
        .map((e) => (
          <details
            key={e.id}
            className="rounded border p-2"
            onToggle={(event) => {
              const open = event.currentTarget.open;
              setExpanded((prev) => {
                const next = new Set(prev);
                if (open) next.add(e.id);
                else next.delete(e.id);
                return next;
              });
            }}
          >
            <summary className="cursor-pointer text-xs">
              {e.label} — {e.response?.status ?? "Error"} · {e.duration} ms · {e.size} bytes ·{" "}
              {new Date(e.timestamp).toLocaleString()}
            </summary>
            {expanded.has(e.id) && (
              <div className="space-y-2 py-2">
                {e.error && <p className="text-destructive text-xs">{e.error}</p>}
                {e.truncated && (
                  <p className="text-xs text-amber-500">
                    Evidence preview truncated; inspect the full response in Replay.
                  </p>
                )}
                {e.bodyHash && <p className="break-all text-[10px]">Body SHA-256: {e.bodyHash}</p>}
                {baseline?.response &&
                  e.response &&
                  baseline.id !== e.id &&
                  !baseline.truncated &&
                  !e.truncated && (
                    <ResponseDiffButton
                      left={baseline.response}
                      right={e.response}
                      label="Compare baseline"
                    />
                  )}
                <RequestMenu request={e.request}>
                  <div className="h-60 overflow-hidden rounded border">
                    <CodePane
                      title="Request"
                      body={JSON.stringify(e.request, null, 2)}
                      raw={JSON.stringify(e.request, null, 2)}
                      headers={e.request.headers}
                    />
                  </div>
                </RequestMenu>
                {e.response && (
                  <div className="h-72 overflow-hidden rounded border">
                    <CodePane
                      title="Response"
                      body={e.response.responseBody}
                      raw={JSON.stringify(e.response, null, 2)}
                      headers={e.response.responseHeaders}
                    />
                  </div>
                )}
              </div>
            )}
          </details>
        ))}
    </div>
  );
}
