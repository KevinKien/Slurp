import { useEffect, useState } from "react";
import { Button } from "./ui/button";
import { useInspector } from "./inspector";
import { useAuthProfiles } from "./auth-profiles-provider";
import { useMatrix } from "./matrix-provider";
import { CodePane } from "./code-pane";
import { ResponseDiffButton } from "./response-diff";
import {
  assessCell,
  cellKey,
  type MatrixExpectation,
  type MatrixRun,
  type MatrixSummary,
} from "@/lib/authorization-matrix";
import { defaultDiffOptions } from "@/lib/response-diff";
import { fetchMatrixRun, fetchMatrixRuns } from "@/lib/security-api";
import { requestText } from "@/lib/traffic";
export function MatrixView() {
  const auth = useAuthProfiles()!;
  return <MatrixWorkspace key={auth.workspace ?? "@temporary"} />;
}
function MatrixWorkspace() {
  const auth = useAuthProfiles()!,
    matrix = useMatrix(),
    { sessions } = useInspector();
  const [requestIds, setRequestIds] = useState<number[]>([]),
    [profileIds, setProfileIds] = useState<string[]>([]),
    [baselineId, setBaseline] = useState(""),
    [expectations, setExpectations] = useState<Record<string, MatrixExpectation>>({}),
    [error, setError] = useState(""),
    [selected, setSelected] = useState(""),
    [saved, setSaved] = useState<MatrixRun | null>(null),
    [summaries, setSummaries] = useState<MatrixSummary[]>([]),
    [more, setMore] = useState(false),
    [loading, setLoading] = useState(false),
    [retry, setRetry] = useState(0),
    [cellId, setCellId] = useState(""),
    [ignoredPaths, setIgnoredPaths] = useState("");
  const profiles = [
    { id: "@anonymous", name: "Anonymous (no profile credentials)" },
    ...auth.document.profiles,
  ];
  const identities = profiles.filter((p) => profileIds.includes(p.id));
  const requests = sessions.filter((s) => requestIds.includes(s.id));
  const load = async () => {
    if (!auth.workspace) return;
    setLoading(true);
    try {
      const page = await fetchMatrixRuns(auth.workspace);
      setSummaries(page.data);
      setMore(page.has_more);
    } catch (error) {
      setError(String(error));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    void load();
  }, [auth.workspace, retry]);
  useEffect(() => {
    if (matrix.run) {
      setSelected(matrix.run.id);
      setSaved(null);
    }
  }, [matrix.run?.id]);
  const local = matrix.localRuns.find((r) => r.id === selected);
  useEffect(() => {
    setSaved(null);
    setCellId("");
    if (!selected || local || !auth.workspace) return;
    let active = true;
    setLoading(true);
    fetchMatrixRun(auth.workspace, selected)
      .then(
        (run) => {
          if (active) setSaved(run);
        },
        (error) => {
          if (active) setError(String(error));
        },
      )
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [selected, !!local, auth.workspace]);
  const run = local ?? saved;
  const list = new Map(summaries.map((r) => [r.id, r]));
  for (const r of matrix.localRuns)
    list.set(r.id, { id: r.id, startedAt: r.startedAt, status: r.status, cells: r.results.length });
  const detail = run?.results.find((c) => cellKey(c.requestId, c.profileId) === cellId);
  const baseline = run?.results.find(
    (c) => c.requestId === detail?.requestId && c.profileId === run.baselineId,
  );
  const start = () => {
    try {
      matrix.start({
        requests: requests.map((s) => ({ id: String(s.id), name: s.name, request: s.request })),
        identities: identities.map((p) => ({ id: p.id, name: p.name })),
        baselineId,
        expectations,
        options: {
          ...defaultDiffOptions,
          ignoredPaths: ignoredPaths
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
        },
        stripHeaders: auth.document.profiles.flatMap((p) => Object.keys(p.headers)),
      });
      setError("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Could not start matrix");
    }
  };
  return (
    <div className="h-full overflow-auto p-6 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Authorization Matrix</h1>
          <p className="mt-2 text-muted-foreground">
            Send the same requests with different account profiles and compare access behavior.
          </p>
        </div>
        <a
          href="/docs/security-testing.html#matrix"
          target="_blank"
          rel="noreferrer"
          className="text-primary hover:underline"
        >
          Documentation
        </a>
      </div>
      <div className="mt-5 grid gap-4 md:grid-cols-2">
        <fieldset
          disabled={matrix.busy}
          className="max-h-56 space-y-2 overflow-auto rounded border border-border p-3"
        >
          <legend>Replay requests</legend>
          {sessions.map((s) => (
            <label key={s.id} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={requestIds.includes(s.id)}
                onChange={(e) =>
                  setRequestIds((prev) =>
                    e.target.checked ? [...prev, s.id] : prev.filter((id) => id !== s.id),
                  )
                }
              />
              <span className="truncate">
                {s.name} · {s.request.method} {s.request.url}
              </span>
            </label>
          ))}
        </fieldset>
        <fieldset
          disabled={matrix.busy}
          className="max-h-56 space-y-2 overflow-auto rounded border border-border p-3"
        >
          <legend>Profiles</legend>
          {profiles.map((p) => (
            <label key={p.id} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={profileIds.includes(p.id)}
                onChange={(e) => {
                  setProfileIds((prev) =>
                    e.target.checked ? [...prev, p.id] : prev.filter((id) => id !== p.id),
                  );
                  if (e.target.checked && !baselineId) setBaseline(p.id);
                }}
              />
              {p.name}
            </label>
          ))}
        </fieldset>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <label>
          Baseline{" "}
          <select
            aria-label="Matrix baseline"
            className="inspector-input ml-2"
            value={baselineId}
            disabled={matrix.busy}
            onChange={(e) => setBaseline(e.target.value)}
          >
            <option value="">Select baseline</option>
            {identities.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex min-w-0 flex-1 items-center gap-2">
          Ignore JSON paths
          <input
            aria-label="Matrix ignored JSON paths"
            className="inspector-input min-w-0 flex-1"
            placeholder="timestamp, meta.requestId"
            value={ignoredPaths}
            disabled={matrix.busy}
            onChange={(e) => setIgnoredPaths(e.target.value)}
          />
        </label>
      </div>
      {!!requests.length && !!identities.length && (
        <div className="mt-3 overflow-auto">
          <table className="w-full text-left">
            <caption className="py-2 text-left text-muted-foreground">
              Expected access per request and profile. Observe flags identical successful bodies for
              review.
            </caption>
            <thead>
              <tr>
                <th>Request</th>
                {identities.map((p) => (
                  <th key={p.id} className="p-2">
                    {p.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {requests.map((r) => (
                <tr key={r.id} className="border-t border-border">
                  <td>{r.name}</td>
                  {identities.map((p) => (
                    <td key={p.id} className="p-2">
                      <select
                        aria-label={`Expected access ${r.name} ${p.name}`}
                        className="inspector-input"
                        disabled={matrix.busy}
                        value={expectations[cellKey(String(r.id), p.id)] ?? "observe"}
                        onChange={(e) =>
                          setExpectations((prev) => ({
                            ...prev,
                            [cellKey(String(r.id), p.id)]: e.target.value as MatrixExpectation,
                          }))
                        }
                      >
                        <option value="observe">Observe</option>
                        <option value="allow">Allow</option>
                        <option value="deny">Deny</option>
                      </select>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Button
          size="sm"
          disabled={matrix.busy || !auth.ready || !requests.length || !identities.length}
          onClick={start}
        >
          Run matrix ({requests.length * identities.length} requests)
        </Button>
        {matrix.busy && (
          <Button size="sm" variant="destructive" onClick={matrix.stop}>
            Stop after current request
          </Button>
        )}
        <span className="text-muted-foreground">
          Sends real requests, sequentially. Scripts are not executed. Review mutations before
          running.
        </span>
      </div>
      <p className="mt-2 text-muted-foreground">
        Matrix replaces Authorization, Cookie and profile-managed headers. Credentials embedded in
        URLs, bodies or shared variables remain; inspect requests before testing anonymous access.
      </p>
      {error && (
        <p role="alert" className="mt-3 text-destructive">
          {error}
        </p>
      )}
      {auth.error && (
        <p role="alert" className="mt-3 text-destructive">
          Profiles: {auth.error}
        </p>
      )}
      {matrix.error && (
        <p role="alert" className="mt-3 text-destructive">
          Evidence could not be saved: {matrix.error}
          <Button size="sm" variant="ghost" onClick={matrix.retrySave}>
            Retry saving
          </Button>
        </p>
      )}
      <div className="mt-6 flex flex-wrap gap-2 border-t border-border pt-4">
        <select
          aria-label="Matrix run"
          className="inspector-input min-w-0 flex-1"
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
        >
          <option value="">Select a run</option>
          {[...list.values()]
            .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
            .map((r) => (
              <option key={r.id} value={r.id}>
                {new Date(r.startedAt).toLocaleString()} · {r.status} · {r.cells} cells
              </option>
            ))}
        </select>
        <Button size="sm" variant="outline" onClick={() => setRetry((v) => v + 1)}>
          Refresh history
        </Button>
        {more && (
          <Button
            size="sm"
            variant="outline"
            disabled={loading}
            onClick={async () => {
              if (!auth.workspace) return;
              try {
                const page = await fetchMatrixRuns(auth.workspace, summaries.length);
                setSummaries((prev) => [...prev, ...page.data]);
                setMore(page.has_more);
              } catch (error) {
                setError(String(error));
              }
            }}
          >
            Load older
          </Button>
        )}
      </div>
      {!auth.workspace && (
        <p className="mt-2 text-muted-foreground">
          Temporary evidence is lost on reload. Saved workspaces retain the latest 50 matrix runs.
        </p>
      )}
      {loading && (
        <p role="status" className="mt-3">
          Loading evidence…
        </p>
      )}
      {run && (
        <>
          <p role="status" className="mt-4">
            {run.status === "running" && !matrix.busy ? "Interrupted browser session" : run.status}{" "}
            · {run.results.length}/{run.requests.length * run.identities.length} cells ·{" "}
            {run.message}
          </p>
          <div className="mt-3 overflow-auto">
            <table className="w-full text-left">
              <thead>
                <tr>
                  <th>Request</th>
                  {run.identities.map((p) => (
                    <th key={p.id} className="p-2">
                      {p.name}
                      {p.id === run.baselineId ? " (baseline)" : ""}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {run.requests.map((row) => (
                  <tr key={row.id} className="border-t border-border">
                    <td className="py-3">{row.name}</td>
                    {run.identities.map((identity) => {
                      const cell = run.results.find(
                          (c) => c.requestId === row.id && c.profileId === identity.id,
                        ),
                        base = run.results.find(
                          (c) => c.requestId === row.id && c.profileId === run.baselineId,
                        ),
                        assessment = cell ? assessCell(cell, base, run.options) : null;
                      return (
                        <td key={identity.id} className="p-2">
                          <button
                            disabled={!cell}
                            className={`cursor-pointer text-left ${assessment?.kind === "review" ? "text-warning" : assessment?.kind === "pass" ? "text-primary" : "text-muted-foreground"}`}
                            title={assessment?.message}
                            onClick={() => setCellId(cellKey(row.id, identity.id))}
                          >
                            {cell
                              ? `HTTP ${cell.response?.status ?? "error"} · ${cell.duration} ms · ${assessment?.kind}`
                              : "Pending"}
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {detail && (
        <section className="mt-4 space-y-3 rounded border border-border p-4">
          <h2 className="text-sm font-medium">Selected evidence</h2>
          <p>{assessCell(detail, baseline, run!.options).message}</p>
          {detail.error && (
            <p role="alert" className="text-destructive">
              {detail.error}
            </p>
          )}
          {baseline?.response &&
            detail.response &&
            !baseline.evidenceTruncated &&
            !detail.evidenceTruncated && (
              <ResponseDiffButton
                left={baseline.response}
                right={detail.response}
                label="Compare with baseline"
              />
            )}
          <div className="grid gap-3 lg:grid-cols-2">
            <div className="flex h-80 min-w-0 flex-col overflow-hidden border border-border">
              {detail.request && (
                <CodePane
                  title="Sent request"
                  body={requestText(detail.request)}
                  raw={requestText(detail.request)}
                  headers={detail.request.headers}
                />
              )}
            </div>
            <div className="flex h-80 min-w-0 flex-col overflow-hidden border border-border">
              {detail.response && (
                <CodePane
                  title="Response"
                  body={detail.response.responseBody}
                  raw={detail.response.responseBody}
                  headers={detail.response.responseHeaders}
                />
              )}
            </div>
          </div>
        </section>
      )}
      <p className="mt-4 text-muted-foreground">
        Review flags are leads, not confirmed authorization vulnerabilities. A 200 response may
        contain an application error or intentionally public data.
      </p>
    </div>
  );
}
