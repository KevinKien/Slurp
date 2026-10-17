import type { HttpRequest } from "./traffic";
import type { ComparableResponse, DiffOptions } from "./response-diff";
import { compareResponses } from "./response-diff";
import { flowId } from "./flows";
import type { ReplayVariables } from "./replay-features";
export type MatrixExpectation = "observe" | "allow" | "deny";
export interface MatrixRequest {
  id: string;
  name: string;
  request: HttpRequest;
}
export interface MatrixIdentity {
  id: string;
  name: string;
}
export interface MatrixCell {
  requestId: string;
  profileId: string;
  expectation: MatrixExpectation;
  request?: HttpRequest;
  response?: ComparableResponse;
  error?: string;
  duration: number;
  evidenceTruncated?: boolean;
}
export interface MatrixRun {
  id: string;
  startedAt: string;
  finishedAt?: string;
  status: "running" | "completed" | "stopped" | "failed";
  message: string;
  requests: MatrixRequest[];
  identities: MatrixIdentity[];
  baselineId: string;
  options: DiffOptions;
  results: MatrixCell[];
}
export interface MatrixSummary {
  id: string;
  startedAt: string;
  status: MatrixRun["status"];
  cells: number;
}
export interface MatrixPlan {
  requests: MatrixRequest[];
  identities: MatrixIdentity[];
  baselineId: string;
  options: DiffOptions;
  expectations: Record<string, MatrixExpectation>;
  stripHeaders: string[];
}
export const cellKey = (requestId: string, profileId: string) => `${requestId}:${profileId}`;
export function assessCell(
  cell: MatrixCell,
  baseline: MatrixCell | undefined,
  options: DiffOptions,
): { kind: "pass" | "review" | "inconclusive" | "observed"; message: string } {
  if (cell.error || !cell.response)
    return { kind: "inconclusive", message: cell.error || "No response" };
  const status = cell.response.status;
  const allowed = status >= 200 && status < 300,
    denied = [401, 403, 404].includes(status);
  if (status >= 500 || (status >= 300 && status < 400) || status === 429)
    return { kind: "inconclusive", message: `HTTP ${status}; inspect manually` };
  if (cell.expectation === "deny")
    return allowed
      ? { kind: "review", message: "Expected denial; received a successful response" }
      : denied
        ? { kind: "pass", message: "Expected denial; inspect body to confirm" }
        : { kind: "inconclusive", message: `Unexpected HTTP ${status}` };
  if (cell.expectation === "allow")
    return allowed
      ? { kind: "pass", message: "Expected access; received success" }
      : { kind: "review", message: `Expected access; received HTTP ${status}` };
  if (
    baseline &&
    baseline !== cell &&
    baseline.response &&
    !baseline.error &&
    allowed &&
    baseline.response.status >= 200 &&
    baseline.response.status < 300
  ) {
    const diff = compareResponses(baseline.response, cell.response, options);
    if (!diff.statusChanged && !diff.bodyChanged)
      return { kind: "review", message: "Same successful status and normalized body as baseline" };
  }
  return { kind: "observed", message: `HTTP ${status}; no access expectation specified` };
}
export interface MatrixSession {
  variables: ReplayVariables;
  resolve: (
    template: HttpRequest,
    variables: ReplayVariables,
    stripCredentials?: string[],
  ) => HttpRequest;
  receive: (url: string, cookies: string[]) => void;
}
interface Dependencies {
  identities: Record<string, MatrixSession>;
  send: (
    request: HttpRequest,
  ) => Promise<
    | {
        ok: true;
        status: number;
        responseHeaders: Record<string, string>;
        responseBody: string;
        duration: number;
        setCookies?: string[];
      }
    | { ok: false; error: string }
  >;
  isCurrent: () => boolean;
  onChange: (run: MatrixRun) => void;
}
export class MatrixRunner {
  private cancelled = false;
  private started = false;
  private state: MatrixRun;
  constructor(
    private plan: MatrixPlan,
    private deps: Dependencies,
  ) {
    if (
      !plan.requests.length ||
      !plan.identities.length ||
      plan.requests.length > 20 ||
      plan.identities.length > 30 ||
      plan.requests.length * plan.identities.length > 200
    )
      throw Error("Select 1–20 requests and profiles, up to 200 cells.");
    if (!plan.identities.some((p) => p.id === plan.baselineId))
      throw Error("Select a baseline profile.");
    if (new TextEncoder().encode(JSON.stringify(plan)).length > 2_000_000)
      throw Error("Matrix configuration exceeds 2 MB.");
    this.plan = structuredClone(plan);
    this.state = {
      id: flowId(),
      startedAt: new Date().toISOString(),
      status: "running",
      message: "",
      requests: this.plan.requests,
      identities: this.plan.identities,
      baselineId: plan.baselineId,
      options: this.plan.options,
      results: [],
    };
  }
  get run() {
    return this.state;
  }
  get active() {
    return this.state.status === "running";
  }
  stop() {
    this.cancelled = true;
  }
  private emit(patch: Partial<MatrixRun> = {}) {
    this.state = { ...this.state, ...patch };
    this.deps.onChange(this.state);
  }
  async start() {
    if (this.started) return;
    this.started = true;
    this.emit();
    try {
      for (const row of this.plan.requests)
        for (const identity of this.plan.identities) {
          if (this.cancelled || !this.deps.isCurrent()) {
            this.emit({
              status: "stopped",
              message: "Stopped. In-flight requests may still complete on the server.",
              finishedAt: new Date().toISOString(),
            });
            return;
          }
          if (new TextEncoder().encode(JSON.stringify(this.state)).length > 8_000_000) {
            this.emit({
              status: "stopped",
              message: "Evidence reached the 8 MB budget. Run a smaller selection to continue.",
              finishedAt: new Date().toISOString(),
            });
            return;
          }
          let cell: MatrixCell = {
            requestId: row.id,
            profileId: identity.id,
            expectation: this.plan.expectations[cellKey(row.id, identity.id)] ?? "observe",
            duration: 0,
          };
          const started = Date.now();
          try {
            const session = this.deps.identities[identity.id];
            if (!session) throw Error("Profile session unavailable.");
            const stripped = {
              ...row.request,
              headers: Object.fromEntries(
                Object.entries(row.request.headers).filter(
                  ([key]) =>
                    !/^(authorization|cookie)$/i.test(key) &&
                    !this.plan.stripHeaders.some(
                      (name) => name.toLowerCase() === key.toLowerCase(),
                    ),
                ),
              ),
            };
            const request = session.resolve(stripped, session.variables, this.plan.stripHeaders);
            cell = { ...cell, request };
            const result = await this.deps.send(request);
            if (!result.ok) throw Error(result.error);
            cell = {
              ...cell,
              response: {
                status: result.status,
                responseHeaders: result.responseHeaders,
                responseBody: result.responseBody,
              },
              duration: result.duration,
            };
            if (!this.cancelled && this.deps.isCurrent())
              session.receive(request.url, result.setCookies ?? []);
          } catch (error) {
            cell = { ...cell, error: error instanceof Error ? error.message : "Request failed" };
          }
          // Bound JSON-escaped evidence as well as raw response bytes. Binary/control
          // text can expand sixfold when serialized; mark previews inconclusive.
          if (cell.response) {
            const fullResponse=cell.response;
            let headerBytes = 0;
            const headers: Record<string, string> = {};
            for (const [name, value] of Object.entries(cell.response.responseHeaders)) {
              const bytes = new TextEncoder().encode(JSON.stringify([name, value])).length;
              if (headerBytes + bytes > 128000) {
                cell = { ...cell, evidenceTruncated: true };
                continue;
              }
              headers[name] = value;
              headerBytes += bytes;
            }
            cell = { ...cell, response: { ...fullResponse, responseHeaders: headers } };
            if (new TextEncoder().encode(JSON.stringify(cell)).length > 3_000_000)
              cell = {
                ...cell,
                evidenceTruncated: true,
                response: {
                  ...cell.response!,
                  responseBody: cell.response!.responseBody.slice(0, 200000),
                },
              };
            if (cell.evidenceTruncated)
              cell = {
                ...cell,
                error:
                  "Evidence exceeded the snapshot budget. Response preview was truncated; inspect a single Replay send for the full result.",
              };
          }
          cell = { ...cell, duration: Math.max(cell.duration, Date.now() - started) };
          this.emit({ results: [...this.state.results, cell] });
        }
      this.emit({
        status: this.cancelled || !this.deps.isCurrent() ? "stopped" : "completed",
        finishedAt: new Date().toISOString(),
      });
    } catch (error) {
      this.emit({
        status: "failed",
        message: error instanceof Error ? error.message : "Matrix failed",
        finishedAt: new Date().toISOString(),
      });
    }
  }
}
