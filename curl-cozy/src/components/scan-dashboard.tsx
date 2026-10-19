import { useEffect, useRef, useState } from "react";
import { useScan } from "@/lib/scan-context";
import { fetchScanFindings, type DashboardFinding, type ScanSummary } from "@/lib/scan-api";
import type { ScanRun } from "@/lib/scan";
import { Button } from "./ui/button";
const input = "rounded border border-border bg-background p-2 text-xs";
export function ScanDashboard({
  tasks,
  offset,
  more,
  onPage,
  onRefresh,
  onSelect,
}: {
  tasks: (ScanSummary | ScanRun)[];
  offset: number;
  more: boolean;
  onPage: (offset: number) => void;
  onRefresh: () => void;
  onSelect: (runId: string, findingId?: string) => void;
}) {
  const scan = useScan();
  const [taskPage, setTaskPage] = useState(0);
  const pendingTaskPage = useRef(0);
  useEffect(() => {
    setTaskPage(pendingTaskPage.current);
    pendingTaskPage.current = 0;
  }, [offset, scan.workspace]);

  const backendWorkspace = scan.workspace ?? "temporary";
  useEffect(() => {
    const update = () => setRefresh((v) => v + 1);
    window.addEventListener("slurp:scan-changed", update);
    const timer = setInterval(update, 5000);
    return () => {
      window.removeEventListener("slurp:scan-changed", update);
      clearInterval(timer);
    };
  }, []);
  const [rows, setRows] = useState<DashboardFinding[]>([]),
    [total, setTotal] = useState(0),
    [page, setPage] = useState(0),
    [moreFindings, setMoreFindings] = useState(false),
    [query, setQuery] = useState(""),
    [status, setStatus] = useState(""),
    [severity, setSeverity] = useState(""),
    [error, setError] = useState(""),
    [refresh, setRefresh] = useState(0),
    [loading, setLoading] = useState(false);
  useEffect(() => {
    setRows([]);
    setLoading(false);
    setMoreFindings(false);
    setTotal(0);
    setPage(0);
    setError("");
  }, [scan.workspace]);
  useEffect(() => {
    setPage(0);
  }, [query, status, severity]);
  useEffect(() => {
    let current = true;
    setLoading(true);
    const timer = setTimeout(() => {
      void fetchScanFindings(backendWorkspace, page, query, status, severity)
        .then((v) => {
          if (current) {
            setRows(v.data);
            setTotal(v.total);
            setMoreFindings(v.has_more);
            setError("");
          }
        })
        .catch((e) => {
          if (current) setError(e instanceof Error ? e.message : String(e));
        })
        .finally(() => {
          if (current) setLoading(false);
        });
    }, 150);
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [scan.workspace, page, query, status, severity, scan.busy, scan.run?.status, refresh]);
  const liveRuns = scan.localRuns.filter(
    (r) =>
      !scan.workspace ||
      r.status === "running" ||
      r.status === "paused" ||
      !!scan.saveErrors?.[r.id] ||
      (r.id === scan.run?.id && (scan.busy || !!scan.error)),
  );
  const live = liveRuns
    .flatMap((run) =>
      run.findings.map((finding) => ({
        runId: run.id,
        startedAt: run.startedAt,
        url: run.plan.request.url,
        method: run.plan.request.method,
        finding,
      })),
    )
    .filter(
      (row) =>
        (!query ||
          `${row.finding.title} ${row.url} ${row.finding.excerpts.join(" ")}`
            .toLowerCase()
            .includes(query.toLowerCase())) &&
        (!status || row.finding.status === status) &&
        (!severity || row.finding.severity === severity),
    );
  const findings = Array.from(
    new Map([...rows, ...live].map((row) => [`${row.runId}:${row.finding.id}`, row])).values(),
  );
  const active = scan.localRuns.filter((r) => r.status === "running" || r.status === "paused");
  const summary = (task: ScanSummary | ScanRun) =>
    "plan" in task
      ? {
          ...task,
          url: task.plan.request.url,
          method: task.plan.request.method,
          maxRequests: task.plan.maxRequests,
          mode: task.plan.mode,
          findings: task.findings.length,
        }
      : task;
  const taskRows = tasks
    .map(summary)
    .sort(
      (a, b) =>
        Number(["running", "paused"].includes(b.status)) -
          Number(["running", "paused"].includes(a.status)) ||
        b.startedAt.localeCompare(a.startedAt),
    );
  useEffect(() => {
    setTaskPage((p) => Math.min(p, Math.max(0, Math.ceil(taskRows.length / 10) - 1)));
  }, [offset, scan.workspace, taskRows.length]);
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Active tasks", value: active.length },
          {
            label: scan.workspace ? "Saved findings (filtered)" : "Session findings",
            value:
              total +
              live.filter(
                (row) =>
                  !rows.some(
                    (saved) => saved.runId === row.runId && saved.finding.id === row.finding.id,
                  ),
              ).length,
          },
          { label: "Live findings", value: active.reduce((n, r) => n + r.findings.length, 0) },
          {
            label: "Verified on this page",
            value: findings.filter((r) => r.finding.status === "verified").length,
          },
        ].map((card) => (
          <div key={card.label} className="rounded-lg border bg-card p-4">
            <p className="text-xs text-muted-foreground">{card.label}</p>
            <p className="mt-2 text-2xl font-semibold tabular-nums">{card.value}</p>
          </div>
        ))}
      </div>
      <section className="rounded-lg border bg-card">
        <div className="flex flex-wrap items-center gap-2 border-b p-4">
          <h2 className="mr-auto font-medium">Scan tasks</h2>
          <span className="text-xs text-muted-foreground" aria-live="polite">
            Page {Math.floor(offset / 50) * 5 + taskPage + 1} · 10 tasks per page
          </span>
          {
            <>
              <Button
                variant="outline"
                size="sm"
                disabled={!offset && !taskPage}
                onClick={() => {
                  if (taskPage) setTaskPage((p) => p - 1);
                  else {
                    pendingTaskPage.current = 4;
                    onPage(Math.max(0, offset - 50));
                  }
                }}
              >
                Previous tasks
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={!more && (taskPage + 1) * 10 >= taskRows.length}
                onClick={() =>
                  (taskPage + 1) * 10 < taskRows.length
                    ? setTaskPage((p) => p + 1)
                    : onPage(offset + 50)
                }
              >
                Next tasks
              </Button>
            </>
          }
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              onRefresh();
              setRefresh((v) => v + 1);
            }}
          >
            Refresh
          </Button>
        </div>
        <div className="overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-muted/30 text-muted-foreground">
              <tr>
                {["Endpoint", "Status", "Requests", "Findings", "Started", "Actions"].map((v) => (
                  <th key={v} className="px-4 py-3 font-medium">
                    {v}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {taskRows.slice(taskPage * 10, taskPage * 10 + 10).map((task) => (
                <tr key={task.id} className="border-t">
                  <td className="px-4 py-3">
                    <span className="mr-2 font-semibold text-primary">{task.method ?? "—"}</span>
                    <span
                      className="inline-block max-w-[32rem] truncate align-bottom font-mono"
                      title={task.url}
                    >
                      {task.url ?? "Saved endpoint"}
                    </span>
                    <p className="mt-1 text-[10px] text-muted-foreground">
                      {task.mode}
                      {task.profileName ? ` · ${task.profileName}` : ""}
                    </p>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={
                        "rounded px-2 py-1 " +
                        (task.status === "running"
                          ? "bg-primary/10 text-primary"
                          : task.status === "paused"
                            ? "bg-amber-500/10 text-amber-500"
                            : "bg-muted text-muted-foreground")
                      }
                    >
                      {task.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 tabular-nums">{task.sent}</td>
                  <td className="px-4 py-3 tabular-nums">{task.findings}</td>
                  <td className="px-4 py-3 whitespace-nowrap text-muted-foreground">
                    {new Date(task.startedAt).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onSelect(task.id)}
                        aria-label={`View scan task ${task.id}`}
                      >
                        View
                      </Button>
                      {scan.localRuns.some((r) => r.id === task.id) &&
                        ["running", "paused"].includes(task.status) && (
                          <>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() =>
                                task.status === "paused"
                                  ? scan.resume(task.id)
                                  : scan.pause(task.id)
                              }
                            >
                              {task.status === "paused" ? "Resume" : "Pause"}
                            </Button>
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => scan.stop(task.id)}
                            >
                              Stop
                            </Button>
                          </>
                        )}
                      {scan.saveErrors?.[task.id] && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => void scan.retrySave(task.id).catch(() => undefined)}
                        >
                          Retry saving
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!taskRows.length && (
            <p className="p-8 text-center text-sm text-muted-foreground">
              No scan tasks yet. Right-click a request and choose Scan to create one.
            </p>
          )}
        </div>
      </section>
      <section className="rounded-lg border bg-card">
        <div className="space-y-3 border-b p-4">
          <h2 className="font-medium">Findings</h2>
          <div className="flex flex-wrap gap-2">
            <input
              aria-label="Search findings"
              className={input + " min-w-48 flex-1"}
              placeholder="Search finding or endpoint…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select
              aria-label="Dashboard finding status"
              className={input}
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">All statuses</option>
              {["verified", "suspected", "needs_review", "false_positive"].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
            <select
              aria-label="Finding severity"
              className={input}
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All severities</option>
              {["critical", "high", "medium", "low", "info"].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </div>
        </div>
        {error && (
          <p role="alert" className="p-4 text-sm text-destructive">
            {error}
          </p>
        )}
        <div className="overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-muted/30 text-muted-foreground">
              <tr>
                {["Severity", "Finding", "Endpoint", "Status", "Confidence", ""].map((v, i) => (
                  <th key={i} className="px-4 py-3 font-medium">
                    {v}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {findings.map((row) => (
                <tr key={`${row.runId}:${row.finding.id}`} className="border-t">
                  <td className="px-4 py-3 uppercase">
                    <span
                      className={
                        row.finding.severity === "high" || row.finding.severity === "critical"
                          ? "text-destructive"
                          : row.finding.severity === "medium"
                            ? "text-amber-500"
                            : "text-muted-foreground"
                      }
                    >
                      {row.finding.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-medium">
                    {row.finding.title}
                    <span className="mt-1 block text-[10px] text-muted-foreground">
                      {row.finding.checkId}
                    </span>
                    {row.finding.checkId.startsWith("js-") && (
                      <span className="mt-1 block max-w-md break-all font-mono text-[11px] text-muted-foreground">
                        {row.finding.excerpts.find(
                          (value) =>
                            value.startsWith("Endpoint candidate:") || value.includes(" = "),
                        )}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-block max-w-80 truncate font-mono" title={row.url}>
                      {row.method} {row.url}
                    </span>
                  </td>
                  <td className="px-4 py-3">{row.finding.status}</td>
                  <td className="px-4 py-3">{row.finding.confidence}</td>
                  <td className="px-4 py-3">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => onSelect(row.runId, row.finding.id)}
                      aria-label={`View finding ${row.finding.id}`}
                    >
                      View evidence
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!findings.length && (
            <p className="p-8 text-center text-sm text-muted-foreground">
              {loading ? "Loading findings…" : "No findings match the current filters."}
            </p>
          )}
        </div>
        {
          <div className="flex items-center gap-3 border-t p-3 text-xs">
            <Button
              variant="outline"
              size="sm"
              disabled={!page || loading}
              onClick={() => setPage(Math.max(0, page - 100))}
            >
              Previous findings
            </Button>
            <span>
              {total
                ? `${page + 1}–${Math.min(page + 100, total)} of ${total} saved findings`
                : "0 saved findings"}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={!moreFindings || loading}
              onClick={() => setPage(page + 100)}
            >
              Next findings
            </Button>
          </div>
        }
      </section>
    </div>
  );
}
