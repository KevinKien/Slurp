import { flowId } from "../flows";
import { compareResponses, defaultDiffOptions } from "../response-diff";
import { validateFinalRequest } from "../intruder";
import { getScanCheck } from "./checks";
import { mutateParameter, parameterKey } from "./parameters";
import type { HttpRequest } from "../traffic";
import type {
  CheckResult,
  Exchange,
  Finding,
  ScanEvidence,
  ScanPlan,
  ScanResponse,
  ScanRun,
} from "./types";
export function newScanPlan(request: HttpRequest): ScanPlan {
  return {
    request: structuredClone(request),
    mode: "passive",
    checks: ["cookie-flags", "error-disclosure", "security-headers"],
    parameters: [],
    allowSending: false,
    baselineSamples: 2,
    maxRequests: 30,
    rate: 2,
    delay: 0,
    diffOptions: structuredClone(defaultDiffOptions),
  };
}
export function validateScanPlan(plan: ScanPlan) {
  validateFinalRequest(plan.request);
  if (!["passive", "active"].includes(plan.mode) || typeof plan.allowSending !== "boolean")
    throw Error("Invalid scan mode.");
  if (
    !Array.isArray(plan.checks) ||
    !plan.checks.length ||
    plan.checks.length > 6 ||
    new Set(plan.checks).size !== plan.checks.length
  )
    throw Error("Select 1–6 unique checks.");
  for (const id of plan.checks) {
    const check = getScanCheck(id);
    if (plan.mode === "passive" && check.active)
      throw Error("Active checks require active scan mode.");
  }
  if (
    !Array.isArray(plan.parameters) ||
    plan.parameters.length > 10 ||
    new Set(plan.parameters.map(parameterKey)).size !== plan.parameters.length
  )
    throw Error("Select at most 10 unique parameters.");
  for (const parameter of plan.parameters) {
    if (!["query", "json"].includes(parameter.kind)) throw Error("Unsupported scan parameter.");
    mutateParameter(plan.request, parameter, "scan_validation");
  }
  for (const [n, min, max] of [
    [plan.baselineSamples, 2, 3],
    [plan.maxRequests, 1, 100],
    [plan.rate, 1, 20],
    [plan.delay, 0, 60000],
  ] as const)
    if (!Number.isInteger(n) || n < min || n > max)
      throw Error("Invalid baseline, request budget or rate controls.");
  if (
    !plan.diffOptions ||
    !Array.isArray(plan.diffOptions.ignoredHeaders) ||
    !Array.isArray(plan.diffOptions.ignoredPaths) ||
    [...plan.diffOptions.ignoredHeaders, ...plan.diffOptions.ignoredPaths].some(
      (v) => typeof v !== "string" || v.length > 200,
    ) ||
    plan.diffOptions.ignoredHeaders.length > 50 ||
    plan.diffOptions.ignoredPaths.length > 50
  )
    throw Error("Invalid response comparison options.");
  if (plan.mode === "active" && (!plan.allowSending || plan.maxRequests < plan.baselineSamples))
    throw Error(
      "Active scanning requires explicit sending permission and enough baseline requests.",
    );
  if (plan.mode === "passive" && !plan.observed)
    throw Error("Passive scanning requires an existing response and never sends requests.");
  if (plan.observed)
    validateResponse({
      ...plan.observed.response,
      duration: plan.observed.duration ?? 0,
      size:
        plan.observed.size ?? new TextEncoder().encode(plan.observed.response.responseBody).length,
      ...(plan.observed.setCookies && { setCookies: plan.observed.setCookies }),
    });
  const { observed: _, ...config } = plan;
  if (new TextEncoder().encode(JSON.stringify(config)).length > 500000)
    throw Error("Scan configuration exceeds 500 KB.");
}
function validateResponse(response: ScanResponse) {
  if (
    !Number.isInteger(response.status) ||
    response.status < 100 ||
    response.status > 599 ||
    typeof response.responseBody !== "string" ||
    new TextEncoder().encode(response.responseBody).length > 2_000_000 ||
    !response.responseHeaders ||
    typeof response.responseHeaders !== "object" ||
    Object.keys(response.responseHeaders).length > 200 ||
    new TextEncoder().encode(JSON.stringify(response.responseHeaders)).length > 256000 ||
    (response.setCookies !== undefined &&
      (!Array.isArray(response.setCookies) ||
        response.setCookies.length > 1000 ||
        new TextEncoder().encode(JSON.stringify(response.setCookies)).length > 256000)) ||
    Array.isArray(response.responseHeaders) ||
    Object.values(response.responseHeaders).some((v) => typeof v !== "string") ||
    !Number.isFinite(response.duration) ||
    response.duration < 0 ||
    response.duration > 3600000 ||
    !Number.isInteger(response.size) ||
    response.size < 0 ||
    response.size > 2_000_000 ||
    response.setCookies?.some((v) => typeof v !== "string")
  )
    throw Error("Invalid or oversized scan response.");
}
export interface ScanDependencies {
  send: (
    request: HttpRequest,
  ) => Promise<({ ok: true } & ScanResponse) | { ok: false; error: string }>;
  isCurrent: () => boolean;
  onChange?: (run: ScanRun) => void;
  /** Called once, after execution. Retrying persistence must not repeat HTTP. */
  save?: (run: ScanRun) => Promise<void>;
  receive?: (url: string, cookies: string[]) => void;
}
class Halt extends Error {}
export class ScanEngine {
  private state: ScanRun;
  private original: ScanPlan;
  private started = false;
  private cancelled = false;
  private paused = false;
  private nextTime = 0;
  private wakeups = new Set<() => void>();
  private saveError = "";
  constructor(
    plan: ScanPlan,
    private deps: ScanDependencies,
    profile?: { id: string; name: string },
  ) {
    validateScanPlan(plan);
    this.original = structuredClone(plan);
    const { observed: _, ...snapshot } = this.original;
    this.state = {
      version: 1,
      id: flowId(),
      startedAt: new Date().toISOString(),
      status: "running",
      message: "",
      plan: snapshot,
      sent: 0,
      bytes: 0,
      baselineStable: null,
      baselineIds: [],
      evidence: [],
      findings: [],
      checks: [],
      ...(profile && { profileId: profile.id, profileName: profile.name }),
    };
  }
  /** Snapshot protects evidence from accidental mutation by consumers. */
  get run() {
    return structuredClone(this.state);
  }
  get active() {
    return this.started && ["running", "paused"].includes(this.state.status);
  }
  get persistenceError() {
    return this.saveError;
  }
  private emit(patch: Partial<ScanRun> = {}) {
    this.state = { ...this.state, ...patch };
    this.deps.onChange?.(this.run);
  }
  private wake() {
    for (const wake of [...this.wakeups]) wake();
  }
  private wait(ms: number) {
    return new Promise<void>((resolve) => {
      const wake = () => {
        clearTimeout(timer);
        this.wakeups.delete(wake);
        resolve();
      };
      const timer = setTimeout(wake, Math.max(1, Math.min(1000, ms)));
      this.wakeups.add(wake);
    });
  }
  stop() {
    if (this.started && this.active) {
      this.cancelled = true;
      this.paused = false;
      this.wake();
    }
  }
  pause() {
    if (this.active && !this.cancelled) {
      this.paused = true;
      this.emit({ status: "paused" });
      this.wake();
    }
  }
  resume() {
    if (this.active && this.paused && !this.cancelled) {
      this.paused = false;
      this.emit({ status: "running" });
      this.wake();
    }
  }
  private guard() {
    if (this.cancelled || !this.deps.isCurrent())
      throw new Halt("Stopped. In-flight requests may still complete on the server.");
  }
  private async ready() {
    while (true) {
      this.guard();
      if (!this.paused) return;
      await this.wait(1000);
    }
  }
  private async capture(
    request: HttpRequest,
    label: string,
    response?: ScanResponse,
    error?: string,
  ): Promise<Exchange> {
    const headers: Record<string, string> = {};
    let headerBytes = 0,
      truncated = false;
    for (const [key, value] of Object.entries(response?.responseHeaders ?? {})) {
      const bytes = new TextEncoder().encode(JSON.stringify([key, value])).length;
      if (headerBytes + bytes > 32000) {
        truncated = true;
        continue;
      }
      headers[key] = value;
      headerBytes += bytes;
    }
    const cookies: string[] = [];
    let cookieBytes = 0;
    for (const cookie of response?.setCookies ?? []) {
      const bytes = new TextEncoder().encode(JSON.stringify(cookie)).length;
      if (cookieBytes + bytes > 16000) {
        truncated = true;
        continue;
      }
      cookies.push(cookie);
      cookieBytes += bytes;
    }
    if ((response?.responseBody.length ?? 0) > 32000) truncated = true;
    const digest =
      response && globalThis.crypto?.subtle
        ? await crypto.subtle
            .digest("SHA-256", new TextEncoder().encode(response.responseBody))
            .catch(() => null)
        : null;
    const evidence: ScanEvidence = {
      id: flowId(),
      label,
      timestamp: new Date().toISOString(),
      request: structuredClone(request),
      duration: response?.duration ?? 0,
      size: response?.size ?? 0,
      setCookies: cookies,
      truncated,
      ...(response && {
        response: {
          status: response.status,
          responseHeaders: headers,
          responseBody: response.responseBody.slice(0, 32000),
        },
      }),
      ...(error && { error }),
      ...(digest && {
        bodyHash: Array.from(new Uint8Array(digest), (v) => v.toString(16).padStart(2, "0")).join(
          "",
        ),
      }),
    };
    const bytes = new TextEncoder().encode(JSON.stringify(evidence)).length;
    if (this.state.bytes + bytes > 8_000_000) throw new Halt("Scan evidence budget reached.");
    this.emit({ evidence: [...this.state.evidence, evidence], bytes: this.state.bytes + bytes });
    return { evidence, ...(response && { response }) };
  }
  private probe = async (request: HttpRequest, label: string): Promise<Exchange> => {
    if (this.original.mode !== "active" || !this.original.allowSending)
      throw Error("This scan cannot send requests.");
    validateFinalRequest(request);
    // Checks can vary only input/header values on the selected endpoint.
    const origin = new URL(this.original.request.url),
      target = new URL(request.url);
    if (
      origin.origin !== target.origin ||
      origin.pathname !== target.pathname ||
      request.method !== this.original.request.method
    )
      throw Error("Scan probes must stay on the selected endpoint and method.");
    await this.ready();
    if (this.state.sent >= this.original.maxRequests)
      throw new Halt("Request budget reached; remaining checks were not completed.");
    const reserve = new TextEncoder().encode(JSON.stringify(request)).length + 512000;
    if (this.state.bytes + reserve > 8_000_000)
      throw new Halt("Scan evidence budget reached; no further requests were sent.");
    while (this.nextTime > Date.now()) {
      await this.wait(this.nextTime - Date.now());
      await this.ready();
    }
    await this.ready();
    this.nextTime = Date.now() + Math.max(1000 / this.original.rate, this.original.delay);
    this.emit({ sent: this.state.sent + 1 });
    let response: ScanResponse;
    try {
      const sent = await this.deps.send(structuredClone(request));
      if (!sent.ok) return await this.capture(request, label, undefined, sent.error);
      validateResponse(sent);
      response = sent;
    } catch (error) {
      return this.capture(
        request,
        label,
        undefined,
        error instanceof Error ? error.message : "Request failed",
      );
    }
    const exchange = await this.capture(request, label, response);
    if (!this.cancelled && this.deps.isCurrent())
      this.deps.receive?.(request.url, response.setCookies ?? []);
    return exchange;
  };
  private addResult(result: CheckResult, findings: Finding[] = []) {
    this.emit({
      checks: [...this.state.checks, result],
      findings: [
        ...this.state.findings,
        ...findings.filter(
          (f) => !this.state.findings.some((old) => old.fingerprint === f.fingerprint),
        ),
      ],
    });
  }
  async start(): Promise<ScanRun> {
    if (this.started) throw Error("This scan engine has already started.");
    this.started = true;
    this.emit();
    const baselines: Exchange[] = [];
    try {
      if (this.original.mode === "passive") {
        this.guard();
        const observed = this.original.observed!;
        baselines.push(
          await this.capture(this.original.request, "Observed response", {
            ...observed.response,
            setCookies: observed.setCookies ?? [],
            duration: observed.duration ?? 0,
            size: observed.size ?? new TextEncoder().encode(observed.response.responseBody).length,
          }),
        );
      } else
        for (let i = 0; i < this.original.baselineSamples; i++)
          baselines.push(await this.probe(this.original.request, `Baseline ${i + 1}`));
      const stable =
        baselines.length >= 2 &&
        baselines.every((e) => !!e.response) &&
        baselines.slice(1).every((e) => {
          const diff = compareResponses(
            baselines[0]!.response!,
            e.response!,
            this.original.diffOptions,
          );
          return !diff.statusChanged && !diff.bodyChanged;
        });
      this.emit({
        baselineStable: baselines.length >= 2 ? stable : null,
        baselineIds: baselines.map((e) => e.evidence.id),
      });
      if (baselines.some((e) => !e.response))
        throw Error("A baseline request failed. No active checks were performed.");
      for (const id of this.original.checks) {
        const check = getScanCheck(id),
          parameters = check.perParameter ? this.original.parameters : [undefined];
        if (!parameters.length) {
          this.addResult({
            checkId: id,
            status: "skipped",
            message: "No explicit parameters selected.",
            findingIds: [],
          });
          continue;
        }
        for (const parameter of parameters) {
          await this.ready();
          const common = { checkId: id, ...(parameter && { parameter }) };
          try {
            const output = await check.run({
              request: structuredClone(this.original.request),
              baselines,
              stable,
              ...(parameter && { parameter }),
              probe: this.probe,
              nonce: () => `scan${flowId().replace(/[^a-zA-Z0-9]/g, "")}`,
            });
            const endpoint = new URL(this.original.request.url);
            const findings = output.findings
              .filter((f, i, all) => all.findIndex((other) => other.title === f.title) === i)
              .map((f) => ({
                ...f,
                id: flowId(),
                checkId: id,
                ...(parameter && { parameter }),
                fingerprint: JSON.stringify([
                  this.original.request.method,
                  endpoint.origin,
                  endpoint.pathname,
                  id,
                  parameter ? parameterKey(parameter) : "",
                  f.title,
                ]),
              }));
            this.addResult(
              {
                ...common,
                status: output.inconclusive
                  ? "inconclusive"
                  : findings.length
                    ? "findings"
                    : "passed",
                message: output.message,
                findingIds: findings.map((f) => f.id),
              },
              findings,
            );
          } catch (error) {
            this.addResult({
              ...common,
              status: "inconclusive",
              message: error instanceof Error ? error.message : "Check failed",
              findingIds: [],
            });
            if (error instanceof Halt) throw error;
          }
        }
      }
      this.guard();
      this.emit({ status: "completed", finishedAt: new Date().toISOString() });
    } catch (error) {
      this.emit({
        status: error instanceof Halt ? "stopped" : "failed",
        message: error instanceof Error ? error.message : "Scan failed",
        finishedAt: new Date().toISOString(),
      });
    }
    for (const id of this.original.checks) {
      const check = getScanCheck(id);
      for (const parameter of check.perParameter ? this.original.parameters : [undefined]) {
        if (
          !this.state.checks.some(
            (r) =>
              r.checkId === id &&
              (r.parameter ? parameterKey(r.parameter) : "") ===
                (parameter ? parameterKey(parameter) : ""),
          )
        )
          this.addResult({
            checkId: id,
            ...(parameter && { parameter }),
            status: "skipped",
            message: "Scan ended before this check completed.",
            findingIds: [],
          });
      }
    }
    await this.retrySave();
    return this.run;
  }
  async retrySave() {
    if (["running", "paused"].includes(this.state.status))
      throw Error("Cannot save an unfinished scan.");
    if (!this.deps.save) return;
    try {
      await this.deps.save(this.run);
      this.saveError = "";
    } catch (error) {
      this.saveError = error instanceof Error ? error.message : "Could not save scan evidence";
    }
  }
}
