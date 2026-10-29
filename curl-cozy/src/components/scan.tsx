import { OastStatus } from "./oast-status";
import { ScanFindingsReport } from "./scan-findings-report";
import { DomAuditReport } from "./dom-audit-report";
import { ScanProfilePicker } from "./scan-profiles";
import { ScanCoverage } from "./scan-coverage";
import { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { useScan } from "@/lib/scan-context";
import { scanChecks, parameterKey, type ScanPlan, type ScanRun } from "@/lib/scan";
import { scanParameters } from "@/lib/scan-selection";
import { fetchScanRuns, fetchScanRun, deleteScanRun, type ScanSummary } from "@/lib/scan-api";
import { Button } from "./ui/button";
import { ProfileSelector } from "./auth-profiles";
import { ScanDashboard } from "./scan-dashboard";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "./ui/dialog";
import { AutomaticAudit } from "./automatic-audit";
const input = "rounded border border-border bg-background p-2 text-sm";
const report = (e: unknown) => toast.error(e instanceof Error ? e.message : String(e));
export function ScanView() {
  const scan = useScan(),
    plan = scan.draft;
  const backendWorkspace = scan.workspace ?? "temporary";
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
    const update = () => setRefresh((v) => v + 1);
    window.addEventListener("slurp:scan-changed", update);
    const timer = setInterval(update, 5000);
    return () => {
      window.removeEventListener("slurp:scan-changed", update);
      clearInterval(timer);
    };
  }, []);
  useEffect(() => {
    setSelectedId("");
    setSaved(null);
    setHistory([]);
    setOffset(0);
    setHistoryError("");
  }, [scan.workspace]);
  useEffect(() => {
    let current = true;
    void fetchScanRuns(backendWorkspace, offset)
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
    if (!selectedId || local) {
      setLoading(false);
      return;
    }
    let current = true;
    setLoading(true);
    void fetchScanRun(backendWorkspace, selectedId)
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
  }, [scan.workspace, selectedId, local]);
  const run = selectedId ? (local ?? saved) : null;
  const options = Array.from(
    new Map([...history, ...scan.localRuns].map((r) => [r.id, r])).values(),
  );
  const candidates = useMemo(() => (plan ? scanParameters(plan.request) : []), [plan?.request]);
  const update = (patch: Partial<ScanPlan>) => {
    if (plan) scan.updateDraft({ ...plan, ...patch });
  };
  const remove = async () => {
    if (!run) return;
    const snapshot = view.current,
      id = run.id;
    try {
      await deleteScanRun(backendWorkspace, id);
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
      <AutomaticAudit />
      <ScanCoverage run={run ?? scan.run} />
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
            <DialogDescription>Select a scan profile for the selected endpoint.</DialogDescription>
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
              <fieldset className="space-y-4">
                <ScanProfilePicker plan={plan} onChange={scan.updateDraft} />
                <div className="space-y-3 rounded border p-3">
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      aria-label="Crawl before scanning"
                      checked={plan.crawlBeforeScan ?? false}
                      onChange={(e) => update({ crawlBeforeScan: e.target.checked })}
                    />
                    Crawl before scanning
                  </label>
                  {plan.crawlBeforeScan && (
                    <>
                      <p className="text-xs text-muted-foreground">
                        Discover same-origin links, scripts and GET forms within Target Scope, then
                        scan the collected responses/endpoints with this profile. GET requests can
                        change server state. Scripts are not executed and POST forms are not
                        submitted.
                      </p>
                      <div className="flex flex-wrap gap-3">
                        <label className="text-xs">
                          Maximum URLs (including start URL)
                          <input
                            aria-label="Crawl maximum URLs"
                            className={`${input} block w-28`}
                            type="number"
                            min={1}
                            max={50}
                            value={plan.crawlOptions?.maxUrls ?? 20}
                            onChange={(e) =>
                              update({
                                crawlOptions: {
                                  maxUrls: Number(e.target.value),
                                  maxDepth: plan.crawlOptions?.maxDepth ?? 2,
                                },
                              })
                            }
                          />
                        </label>
                        <label className="text-xs">
                          Maximum depth
                          <input
                            aria-label="Crawl maximum depth"
                            className={`${input} block w-28`}
                            type="number"
                            min={0}
                            max={5}
                            value={plan.crawlOptions?.maxDepth ?? 2}
                            onChange={(e) =>
                              update({
                                crawlOptions: {
                                  maxUrls: plan.crawlOptions?.maxUrls ?? 20,
                                  maxDepth: Number(e.target.value),
                                },
                              })
                            }
                          />
                        </label>
                      </div>
                      <label className="flex items-center gap-2 text-sm">
                        <input
                          type="checkbox"
                          aria-label="Allow crawl requests"
                          checked={plan.allowSending}
                          onChange={(e) => update({ allowSending: e.target.checked })}
                        />
                        I allow crawling and the selected scan checks on discovered endpoints.
                      </label>
                    </>
                  )}
                </div>
                <div className="space-y-3 rounded border p-3">
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      aria-label="Scan JavaScript endpoints"
                      checked={plan.jsEndpointScan ?? false}
                      disabled={plan.mode === "passive"}
                      onChange={(e) => update({ jsEndpointScan: e.target.checked })}
                    />
                    Scan endpoints discovered in JavaScript
                  </label>
                  {plan.mode === "passive" && (
                    <p className="text-xs text-muted-foreground">
                      Requires an active scan profile.
                    </p>
                  )}
                  {plan.jsEndpointScan && plan.mode !== "passive" && (
                    <>
                      <p className="text-xs text-muted-foreground">
                        Uses the endpoint candidates the automatic JavaScript audit already extracted
                        in the open workspace. Each endpoint is checked for hidden parameters and
                        anonymous access, then the selected parameter checks run against every
                        discovered parameter. The endpoint's own origin is the only host contacted;
                        cross-origin endpoints are scanned without the session's credentials.
                      </p>
                      <label className="text-xs">
                        Maximum endpoints
                        <input
                          aria-label="JavaScript endpoint limit"
                          className={`${input} block w-28`}
                          type="number"
                          min={1}
                          max={20}
                          value={plan.jsEndpointOptions?.maxEndpoints ?? 10}
                          onChange={(e) =>
                            update({
                              jsEndpointOptions: { maxEndpoints: Number(e.target.value) },
                            })
                          }
                        />
                      </label>
                      {!plan.allowSending && (
                        <p className="text-xs text-destructive">
                          Enable sending requests below to scan JavaScript endpoints.
                        </p>
                      )}
                    </>
                  )}
                </div>
                {plan.checks.includes("jwt-confusion") && (
                  <label className="block space-y-2 text-sm">
                    <span>JWT RSA public key or certificate (PEM)</span>
                    <textarea
                      aria-label="JWT RSA public key"
                      className={`${input} w-full min-h-32 font-mono text-xs`}
                      placeholder="-----BEGIN PUBLIC KEY-----"
                      maxLength={16000}
                      value={plan.jwtPublicKey ?? ""}
                      onChange={(e) => update({ jwtPublicKey: e.target.value })}
                    />
                    <p className="text-xs text-muted-foreground">
                      Optional: provide the server's RSA public key or certificate, or leave empty
                      for same-origin JWKS discovery. Slurp verifies the original JWT first. Private
                      keys are not accepted.
                    </p>
                  </label>
                )}
                {plan.checks.some((id) => id.startsWith("business-")) && (
                  <details className="space-y-2 rounded border p-3">
                    <summary className="cursor-pointer text-sm">
                      Business read-back verification (optional)
                    </summary>
                    <p className="text-xs text-muted-foreground">
                      Configure a same-origin GET endpoint returning the existing resource. Uses the
                      captured credentials. Select one input and the exact JSON pointer to its saved
                      value. Replaying the original request attempts restoration but cannot undo
                      other side effects.
                    </p>
                    <label className="block text-sm">
                      Read-back GET URL
                      <input
                        aria-label="Business read-back URL"
                        className={`${input} w-full`}
                        placeholder="https://target.example/api/resource/123"
                        value={plan.businessReadback?.url ?? ""}
                        onChange={(e) =>
                          update({
                            businessReadback: e.target.value
                              ? {
                                  url: e.target.value,
                                  parameter: plan.businessReadback?.parameter ?? "",
                                  pointer: plan.businessReadback?.pointer ?? "",
                                }
                              : undefined,
                          })
                        }
                      />
                    </label>
                    {plan.businessReadback && (
                      <>
                        <label className="block text-sm">
                          Input to verify
                          <select
                            aria-label="Business read-back input"
                            className={`${input} w-full`}
                            value={plan.businessReadback.parameter}
                            onChange={(e) =>
                              update({
                                businessReadback: {
                                  ...plan.businessReadback!,
                                  parameter: e.target.value,
                                },
                              })
                            }
                          >
                            <option value="">Select an input</option>
                            {scanParameters(plan.request).map((p) => (
                              <option key={parameterKey(p)} value={parameterKey(p)}>
                                {parameterKey(p)}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label className="block text-sm">
                          Response JSON pointer
                          <input
                            aria-label="Business read-back JSON pointer"
                            className={`${input} w-full`}
                            placeholder="/data/quantity"
                            value={plan.businessReadback.pointer}
                            onChange={(e) =>
                              update({
                                businessReadback: {
                                  ...plan.businessReadback!,
                                  pointer: e.target.value,
                                },
                              })
                            }
                          />
                        </label>
                      </>
                    )}
                  </details>
                )}
                {plan.checks.some(
                  (id) => id.startsWith("oast-") || id === "jwt-jku" || id === "jwt-x5u",
                ) && <OastStatus />}
                {plan.mode !== "passive" && <ProfileSelector />}
                {plan.mode !== "passive" && (
                  <>
                    {plan.checks.some((id) => id.startsWith("business-")) && (
                      <p className="text-xs text-muted-foreground">
                        Business checks automatically test all detected numeric/date fields (up to
                        100), regardless of their names or the selections below.
                      </p>
                    )}
                    <div>
                      <h2 className="text-sm font-medium">
                        Parameters to test ({plan.parameters.length}/10)
                      </h2>
                      <p className="text-xs text-muted-foreground">
                        Select inputs for parameter-based checks such as SQLi, command/code, XML,
                        redirect and reflection.
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
                                {parameter.kind !== "json"
                                  ? `${parameter.kind === "form" ? "Form" : "Query"}: ${parameter.name} (occurrence ${parameter.occurrence + 1})`
                                  : `JSON: ${parameter.pointer}`}
                              </label>
                            );
                          })
                        ) : (
                          <p className="text-xs text-muted-foreground">
                            No supported query, form or JSON scalar parameters found. Header and
                            XML-body checks can still run when their prerequisites are met.
                          </p>
                        )}
                      </div>
                    </div>
                    <details>
                      <summary className="cursor-pointer text-sm">
                        Advanced request settings
                      </summary>
                      <div className="flex flex-wrap gap-3">
                        {(["maxDurationMs", "requestTimeoutMs"] as const).map((field) => (
                          <label key={field} className="text-xs">
                            {field === "maxDurationMs"
                              ? "Duration limit (seconds)"
                              : "Request timeout (seconds)"}
                            <input
                              type="number"
                              className={input + " block w-40"}
                              min={1}
                              max={field === "maxDurationMs" ? 3600 : 30}
                              value={
                                (plan.policy?.[field] ??
                                  (field === "maxDurationMs" ? 300000 : 15000)) / 1000
                              }
                              onChange={(e) =>
                                update({
                                  policy: {
                                    ...plan.policy!,
                                    [field]: Number(e.target.value) * 1000,
                                  },
                                })
                              }
                            />
                          </label>
                        ))}
                        {(["baselineSamples", "rate", "delay"] as const).map((field) => (
                          <label key={field} className="text-xs">
                            {
                              {
                                baselineSamples: "Baseline samples (2–3)",
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
                              max={field === "baselineSamples" ? 3 : field === "rate" ? 20 : 60000}
                              onChange={(e) => update({ [field]: Number(e.target.value) })}
                            />
                          </label>
                        ))}
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
                    </details>
                    <label className="flex items-start gap-2 text-sm">
                      <input
                        aria-label="Allow sending scan requests"
                        type="checkbox"
                        checked={plan.allowSending}
                        onChange={(e) => update({ allowSending: e.target.checked })}
                      />
                      I allow this scan to send requests for all selected checks to{" "}
                      {plan.crawlBeforeScan
                        ? "the original and crawled endpoints"
                        : plan.jsEndpointScan
                          ? "this endpoint and the JavaScript-discovered endpoints"
                          : "this endpoint"}
                      , including repeated baseline and control requests.
                    </label>
                  </>
                )}
              </fieldset>
              <div className="flex gap-2 flex-wrap">
                <Button
                  disabled={
                    !plan.checks.length ||
                    ((plan.mode !== "passive" || plan.crawlBeforeScan) && !plan.allowSending)
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
                  {plan.crawlBeforeScan
                    ? "Crawl and scan"
                    : plan.jsEndpointScan
                      ? "Scan endpoints"
                      : plan.mode === "passive"
                        ? "Inspect response"
                        : "Start scan"}
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
          <Button variant="outline" onClick={() => void scan.retrySave().catch(report)}>
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
        <DialogContent className="w-[96vw] max-w-[96vw] max-h-[94vh] overflow-y-auto">
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
                    disabled={
                      !run ||
                      ["running", "paused"].includes(run.status) ||
                      scan.pendingRunIds?.includes(run.id)
                    }
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
                {run.crawl && (
                  <details className="rounded border p-3 text-sm">
                    <summary className="cursor-pointer">
                      Crawl: {run.crawl.fetched} URLs fetched · {run.crawl.phase}
                    </summary>
                    <ul className="max-h-48 overflow-auto break-all py-2 font-mono text-xs">
                      {run.crawl.urls.map((url) => (
                        <li key={url}>{url}</li>
                      ))}
                    </ul>
                  </details>
                )}
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
                <ScanFindingsReport
                  key={run.id}
                  run={run}
                  filter={filter}
                  focusFinding={focusFinding}
                />
                <DomAuditReport audits={run.domAudits} />
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
                        {check.endpoint && (
                          <div className="break-all font-mono text-muted-foreground">
                            {check.endpoint}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
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
