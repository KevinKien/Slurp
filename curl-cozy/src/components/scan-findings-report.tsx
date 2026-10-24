import { useEffect, useState } from "react";
import type { Finding, ScanEvidence, ScanRun } from "@/lib/scan";
import { parameterKey } from "@/lib/scan";
import { statusTexts } from "@/lib/traffic";
import { parameterValue } from "@/lib/scan/parameters";
import { CodePane } from "./code-pane";
import { RequestMenu } from "./request-menu";
import { ResponseDiffButton } from "./response-diff";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";

export function scanRequestRaw(e: ScanEvidence) {
  if (e.rawRequest) return e.rawRequest;
  const url = new URL(e.request.url);
  const headers = { ...e.request.headers };
  if (!Object.keys(headers).some((k) => k.toLowerCase() === "host")) headers["Host"] = url.host;
  return `${e.request.method} ${url.pathname}${url.search} HTTP/1.1\r\n${Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\r\n")}\r\n\r\n${e.request.body}`;
}
export function scanResponseRaw(e: ScanEvidence) {
  if (e.rawResponse) return e.rawResponse;
  if (!e.response) return e.error ?? "No response captured.";
  const headers = Object.entries(e.response.responseHeaders).map(([k, v]) => `${k}: ${v}`);
  if (
    e.setCookies.length &&
    !Object.keys(e.response.responseHeaders).some((k) => k.toLowerCase() === "set-cookie")
  )
    headers.push(...e.setCookies.map((v) => `Set-Cookie: ${v}`));
  return `HTTP/1.1 ${e.response.status}${statusTexts[e.response.status] ? " " + statusTexts[e.response.status] : ""}\r\n${headers.join("\r\n")}\r\n\r\n${e.response.responseBody}`;
}
function value(f: Finding, request: ScanEvidence["request"]) {
  if (!f.parameter) return null;
  try {
    return parameterValue(request, f.parameter);
  } catch {
    return "Parameter absent in this evidence.";
  }
}
export function ScanFindingsReport({
  run,
  filter,
  focusFinding,
}: {
  run: ScanRun;
  filter: string;
  focusFinding: string;
}) {
  const [selected, setSelected] = useState(focusFinding);
  useEffect(() => {
    if (focusFinding) setSelected(focusFinding);
  }, [focusFinding]);
  const findings = run.findings.filter((f) => filter === "all" || f.status === filter);
  const finding = findings.find((f) => f.id === selected) ?? findings[0];
  return (
    <div className="min-w-0 overflow-hidden rounded border border-border">
      <div className="max-h-60 overflow-auto">
        <table className="w-full text-left text-xs" aria-label="Scan findings">
          <thead className="sticky top-0 z-10 bg-muted">
            <tr>
              {[
                "Issue type",
                "Host",
                "Path / endpoint",
                "Insertion point",
                "Severity",
                "Status",
              ].map((label) => (
                <th key={label} className="p-3 font-medium whitespace-nowrap">
                  {label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr
                key={f.id}
                onClick={() => setSelected(f.id)}
                className={finding?.id === f.id ? "bg-primary/15" : "hover:bg-muted/60"}
              >
                <td className="p-3">
                  <button
                    type="button"
                    aria-pressed={finding?.id === f.id}
                    onClick={() => setSelected(f.id)}
                    className="text-left font-medium hover:underline"
                  >
                    {f.title}
                  </button>
                </td>
                <td className="p-3 whitespace-nowrap">
                  {new URL(f.endpoint ?? run.plan.request.url).origin}
                </td>
                <td className="p-3 font-mono break-all min-w-48">
                  {f.checkId === "js-endpoints"
                    ? (f.excerpts
                        .find((x) => x.startsWith("Endpoint candidate:"))
                        ?.slice(19)
                        .trim() ?? new URL(f.endpoint ?? run.plan.request.url).pathname)
                    : new URL(f.endpoint ?? run.plan.request.url).pathname}
                </td>
                <td className="p-3 font-mono whitespace-nowrap">
                  {f.parameter ? parameterKey(f.parameter) : "Request / response"}
                </td>
                <td className="p-3 uppercase">{f.severity}</td>
                <td className="p-3 whitespace-nowrap">{f.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!findings.length && (
          <p className="p-4 text-sm text-muted-foreground">
            {run.findings.length
              ? "No findings match this filter."
              : "No findings recorded. Review skipped and inconclusive check results."}
          </p>
        )}
      </div>
      {finding && <FindingDetail key={finding.id} run={run} finding={finding} />}
    </div>
  );
}
function FindingDetail({ run, finding: f }: { run: ScanRun; finding: Finding }) {
  const evidence = f.evidenceIds
    .map((id) => run.evidence.find((e) => e.id === id))
    .filter((e): e is ScanEvidence => !!e);
  const [tab, setTab] = useState("advisory");
  const index = Number(tab.split(":")[1]);
  const selected =
    evidence[index] ??
    evidence.find(
      (e) =>
        e.id !== f.baselineId &&
        !run.baselineIds.includes(e.id) &&
        !/control|baseline/i.test(e.label),
    ) ??
    evidence[0];
  const baseline = run.evidence.find(
    (e) => (f.baselineId ? e.id === f.baselineId : run.baselineIds.includes(e.id)) && e.response,
  );
  const originalRequest = baseline?.request ?? run.plan.request;
  const original = value(f, originalRequest);
  const payload = selected ? value(f, selected.request) : null;
  return (
    <Tabs value={tab} onValueChange={setTab} className="min-w-0 border-t border-border">
      <div className="min-w-0 border-b border-border">
        <TabsList
          aria-label="Finding evidence"
          className="h-auto min-h-11 w-full flex-wrap justify-start gap-1 rounded-none bg-transparent p-1"
        >
          <TabsTrigger value="advisory">Advisory</TabsTrigger>
          {evidence.map((e, i) => (
            <span key={e.id} className="contents">
              <TabsTrigger value={`request:${i}`} title={e.label}>
                Request {i + 1}
              </TabsTrigger>
              <TabsTrigger value={`response:${i}`} title={e.label}>
                Response {i + 1}
              </TabsTrigger>
              {!!e.oast?.length && <TabsTrigger value={`oast:${i}`}>OAST {i + 1}</TabsTrigger>}
              {!!e.browser?.length && (
                <TabsTrigger value={`browser:${i}`}>Browser {i + 1}</TabsTrigger>
              )}
            </span>
          ))}
        </TabsList>
      </div>
      <div className="grid min-w-0 md:grid-cols-[minmax(0,1fr)_18rem]">
        <div className="min-w-0">
          <TabsContent
            value="advisory"
            className="m-0 h-[26rem] overflow-auto p-4 space-y-3 text-sm"
          >
            <p>{f.summary}</p>
            <p>
              <strong>Verification: </strong>
              {f.verification.method} — {f.verification.outcome}
            </p>
            <p>{f.verification.reason}</p>
            <pre className="whitespace-pre-wrap break-words text-xs">{f.excerpts.join("\n")}</pre>
            <p>
              <strong>Remediation: </strong>
              {f.remediation}
            </p>
            <p className="text-xs text-muted-foreground">
              Evidence previews describe the saved application request and response. The sender may
              manage transport headers; raw views are reconstructed, not original wire bytes.
            </p>
          </TabsContent>
          {evidence.map((e, i) => (
            <div key={e.id}>
              <TabsContent value={`request:${i}`} className="m-0 h-[26rem] overflow-hidden">
                <RequestMenu request={e.request}>
                  <div className="h-full">
                    <CodePane
                      compareTo={{
                        body: scanRequestRaw({ ...e, request: originalRequest }),
                        raw: scanRequestRaw({ ...e, request: originalRequest }),
                        headers: originalRequest.headers,
                      }}
                      highlightTerms={(() => {
                        const payload = value(f, e.request);
                        return payload && payload !== original
                          ? [
                              payload,
                              encodeURIComponent(payload),
                              encodeURIComponent(payload).replace(
                                /[!'()*]/g,
                                (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase(),
                              ),
                              new URLSearchParams({ v: payload }).toString().slice(2),
                              JSON.stringify(payload).slice(1, -1),
                            ]
                          : [];
                      })()}
                      title="Request"
                      body={scanRequestRaw(e)}
                      raw={scanRequestRaw(e)}
                      headers={e.request.headers}
                    />
                  </div>
                </RequestMenu>
              </TabsContent>
              <TabsContent value={`response:${i}`} className="m-0 h-[26rem] overflow-hidden">
                <CodePane
                  compareTo={
                    baseline?.response && baseline.id !== e.id
                      ? {
                          body: baseline.response.responseBody,
                          raw: scanResponseRaw(baseline),
                          headers: baseline.response.responseHeaders,
                        }
                      : undefined
                  }
                  initialTab="Raw"
                  highlightTerms={f.excerpts
                    .flatMap((excerpt) => {
                      const header = /^[A-Za-z][A-Za-z-]*:\s*(.+)$/.exec(excerpt);
                      return [excerpt, ...(header?.[1] ? [header[1]] : [])];
                    })
                    .filter((term) => term.length > 2 && !term.includes("<absent>"))}
                  title="Response"
                  body={e.response?.responseBody ?? e.error ?? "No response captured."}
                  raw={scanResponseRaw(e)}
                  headers={e.response?.responseHeaders ?? {}}
                />
              </TabsContent>
              {!!e.oast?.length && (
                <TabsContent
                  value={`oast:${i}`}
                  className="m-0 h-[26rem] overflow-auto p-4 space-y-4 text-xs"
                >
                  {e.oast.map((probe) => (
                    <div key={probe.id} className="space-y-2 rounded border p-3 break-all">
                      <p className="font-mono">{probe.url}</p>
                      {probe.dnsName && <p>DNS: {probe.dnsName}</p>}
                      <p>Expires: {new Date(probe.expiresAt).toLocaleString()}</p>
                      {!probe.events.length && (
                        <p>No callback observed during the polling window.</p>
                      )}
                      {probe.events.map((event, index) => (
                        <p key={index}>
                          {new Date(event.timestamp).toLocaleString()} ·{" "}
                          {event.protocol.toUpperCase()} · {event.peer}
                          <br />
                          {event.detail}
                        </p>
                      ))}
                    </div>
                  ))}
                </TabsContent>
              )}
              {!!e.browser?.length && (
                <TabsContent
                  value={`browser:${i}`}
                  className="m-0 h-[26rem] overflow-auto p-4 space-y-4 text-xs"
                >
                  {e.browser.map((observation, n) => (
                    <div key={n} className="space-y-2 rounded border border-border p-3 break-all">
                      <p className="font-medium">
                        {observation.executed
                          ? "Payload callback executed"
                          : "No payload callback observed"}{" "}
                        · {observation.browser}
                      </p>
                      <p>
                        <strong>Browser URL:</strong> {observation.url}
                      </p>
                      <p>
                        <strong>Marker:</strong> {observation.marker}
                      </p>
                      <p>
                        <strong>DOM sinks:</strong>{" "}
                        {observation.sinks.join(", ") || "None recorded"}
                      </p>
                      {!!observation.interactions?.length && (
                        <div>
                          <strong>Browser interactions:</strong>
                          {observation.interactions.map((action, i) => (
                            <p key={i}>{action}</p>
                          ))}
                        </div>
                      )}
                      {observation.sinkTraces?.map((trace, i) => (
                        <div key={i} className="space-y-1">
                          <strong>{trace.sink}</strong>
                          <pre className="whitespace-pre-wrap break-all">{trace.value}</pre>
                          <pre className="whitespace-pre-wrap break-all text-muted-foreground">
                            {trace.stack}
                          </pre>
                        </div>
                      ))}
                      <p>
                        <strong>Blocked secondary requests:</strong> {observation.blockedRequests}
                      </p>
                      {!!observation.requestedScripts?.length && (
                        <div className="space-y-1">
                          <strong>Blocked script dependencies:</strong>
                          {observation.requestedScripts.map((url) => (
                            <p key={url} className="font-mono">
                              {url}
                            </p>
                          ))}
                        </div>
                      )}
                      {observation.cspViolations.map((violation, i) => (
                        <p key={i} className="whitespace-pre-wrap">
                          {violation}
                        </p>
                      ))}
                    </div>
                  ))}
                </TabsContent>
              )}
            </div>
          ))}
        </div>
        <aside
          className="min-w-0 border-t md:border-t-0 md:border-l border-border p-4 text-xs space-y-3 md:max-h-[26rem] overflow-auto"
          aria-label="Finding inspector"
        >
          <h3 className="text-sm font-medium">Inspector</h3>
          <p className="text-muted-foreground">
            Yellow: injected value / changed request lines. Green: response lines changed from
            baseline. Large responses highlight the changed region. Use Compare baseline to inspect
            deletions.
          </p>
          <p>
            <strong>Check:</strong> {f.checkId}
          </p>
          <p>
            <strong>Insertion point:</strong>{" "}
            {f.parameter ? parameterKey(f.parameter) : "Request / response"}
          </p>
          <p>
            {f.status} · {f.confidence} confidence
          </p>
          {original !== null && (
            <div>
              <strong>Original value</strong>
              <pre className="mt-1 whitespace-pre-wrap break-all rounded bg-muted p-2">
                {JSON.stringify(original)}
              </pre>
            </div>
          )}
          {selected ? (
            <>
              <p className="break-words font-medium">
                {selected.label}
                {selected.id === f.baselineId || run.baselineIds.includes(selected.id)
                  ? " · Baseline"
                  : ""}
              </p>
              <p>
                {selected.response?.status ?? "Error"} · {selected.duration} ms · {selected.size}{" "}
                bytes
              </p>
              <p>{new Date(selected.timestamp).toLocaleString()}</p>
              {payload !== null && (
                <div>
                  <strong>Payload / parameter value</strong>
                  <pre className="mt-1 whitespace-pre-wrap break-all rounded bg-muted p-2">
                    {JSON.stringify(payload)}
                  </pre>
                </div>
              )}
              {selected.error && <p className="text-destructive">{selected.error}</p>}
              {selected.truncated && (
                <p className="text-amber-500">
                  Evidence preview truncated; saved content may be incomplete.
                </p>
              )}
              {baseline?.response &&
                selected.response &&
                baseline.id !== selected.id &&
                !baseline.truncated &&
                !selected.truncated && (
                  <ResponseDiffButton
                    left={baseline.response}
                    right={selected.response}
                    label="Compare baseline"
                  />
                )}
            </>
          ) : (
            <p className="text-muted-foreground">
              Choose a Request or Response tab to inspect its payload and evidence.
            </p>
          )}
        </aside>
      </div>
    </Tabs>
  );
}
