import { resolveReplayRequest, type ReplayVariables } from "./replay-features";
import {
  flowId,
  flowValuesEqual,
  flowRunBytes,
  readFlowPath,
  statusMatches,
  validateFlow,
  validateFlowVariables,
  type Flow,
  type FlowRun,
  type FlowStepResult,
} from "./flows";
import type { HttpRequest, Traffic } from "./traffic";
import type { ScriptInput, ScriptResult } from "./replay-script-engine";
export type FlowSendResult =
  | {
      ok: true;
      status: number;
      statusText: string;
      duration: number;
      size: number;
      responseHeaders: Record<string, string>;
      responseBody: string;
    }
  | { ok: false; error: string };
export interface FlowRunOptions {
  startIndex?: number;
  endIndex?: number;
  variables?: ReplayVariables;
  parentRunId?: string;
  profileId?: string;
  profileName?: string;
}
interface Dependencies {
  resolve?: (template: HttpRequest, variables: ReplayVariables) => HttpRequest;
  send: (request: HttpRequest) => Promise<FlowSendResult>;
  script: (input: ScriptInput) => Promise<ScriptResult>;
  onChange: (run: FlowRun) => void;
  isCurrent: () => boolean;
}
export class FlowRunner {
  private state: FlowRun;
  private busy = false;
  private cancelled = false;
  constructor(
    flow: Flow,
    private deps: Dependencies,
    options: FlowRunOptions = {},
  ) {
    validateFlow(flow);
    const variables = structuredClone(options.variables ?? flow.variables);
    validateFlowVariables(variables);
    const start = options.startIndex ?? 0,
      end = options.endIndex ?? flow.steps.length;
    if (
      !Number.isInteger(start) ||
      !Number.isInteger(end) ||
      start < 0 ||
      end > flow.steps.length ||
      start >= end
    )
      throw Error("Select at least one step to run.");
    this.state = {
      ...(options.profileId && {profileId:options.profileId,profileName:options.profileName??''}),
      id: flowId(),
      flow: structuredClone(flow),
      startedAt: new Date().toISOString(),
      duration: 0,
      status: "running",
      initialVariables: variables,
      variables: { ...variables },
      results: [],
      startIndex: start,
      nextIndex: start,
      endIndex: end,
      sendingIndex: null,
      message: "",
      ...(options.parentRunId && { parentRunId: options.parentRunId }),
    };
  }
  get run() {
    return this.state;
  }
  get active() {
    return this.busy || ["running", "paused"].includes(this.state.status);
  }
  private emit(patch: Partial<FlowRun> = {}) {
    this.state = {
      ...this.state,
      ...patch,
      duration: Math.max(0, Date.now() - Date.parse(this.state.startedAt)),
    };
    this.deps.onChange(this.state);
  }
  private finish(status: "passed" | "failed" | "stopped", message = "") {
    this.emit({ status, message, sendingIndex: null, finishedAt: new Date().toISOString() });
  }
  stop(message = "Stopped by user. An in-flight request may still complete on the server.") {
    if (this.state.finishedAt || !this.active) return;
    this.cancelled = true;
    if (this.busy) this.emit({ status: "stopped", message });
    else this.finish("stopped", message);
  }
  async start() {
    this.emit();
    await this.drive(false);
  }
  async continue(patch: ReplayVariables) {
    if (this.state.status !== "paused" || this.busy) throw Error("Run is not paused.");
    const variables = { ...patch };
    validateFlowVariables(variables);
    this.emit({ variables, status: "running", message: "" });
    await this.drive(true);
  }
  async skip() {
    if (this.state.status !== "paused" || this.busy) throw Error("Run is not paused.");
    const index = this.state.nextIndex,
      step = this.state.flow.steps[index]!;
    this.emit({
      results: [
        ...this.state.results,
        {
          stepId: step.id,
          index,
          name: step.name,
          status: "skipped",
          checks: [],
          variablesBefore: { ...this.state.variables },
          variablesAfter: { ...this.state.variables },
          duration: 0,
        },
      ],
      nextIndex: index + 1,
      status: "running",
      message: "",
    });
    await this.drive(false);
  }
  private async drive(ignorePause: boolean) {
    if (this.busy || this.cancelled) return;
    this.busy = true;
    try {
      while (this.state.nextIndex < this.state.endIndex) {
        if (this.cancelled || !this.deps.isCurrent()) {
          this.cancelled = true;
          this.finish(
            "stopped",
            this.state.message || "Workspace changed. No further steps were sent.",
          );
          return;
        }
        if (flowRunBytes(this.state) > 8_000_000) {
          this.finish(
            "stopped",
            "Run history reached the size budget. Start a new run from this checkpoint to continue.",
          );
          return;
        }
        const index = this.state.nextIndex,
          step = this.state.flow.steps[index]!;
        if (!step.enabled) {
          this.emit({
            results: [
              ...this.state.results,
              {
                stepId: step.id,
                index,
                name: step.name,
                status: "skipped",
                checks: [],
                variablesBefore: { ...this.state.variables },
                variablesAfter: { ...this.state.variables },
                duration: 0,
              },
            ],
            nextIndex: index + 1,
          });
          continue;
        }
        if (step.pauseBefore && !ignorePause) {
          this.emit({
            status: "paused",
            message: step.pauseMessage || "Edit run variables, then continue.",
          });
          return;
        }
        ignorePause = false;
        const before = { ...this.state.variables },
          started = Date.now();
        let result: FlowStepResult = {
          stepId: step.id,
          index,
          name: step.name,
          status: "failed",
          checks: [],
          variablesBefore: before,
          variablesAfter: before,
          duration: 0,
        };
        this.emit({ sendingIndex: index });
        try {
          const request = this.deps.resolve ? this.deps.resolve(step.request, before) : resolveReplayRequest(step.request, before);
          result = { ...result, request };
          const sent = await this.deps.send(request);
          if (!sent.ok) throw Error(sent.error);
          const response: Traffic = {
            ...request,
            ...sent,
            id: Date.now(),
            timestamp: new Date().toISOString(),
          };
          result = { ...result, response };
          if (this.cancelled || !this.deps.isCurrent())
            throw Error(
              "Run stopped after sending. Response received; further processing was skipped.",
            );
          const checks = [
            {
              passed: statusMatches(response.status, step.expectedStatus),
              message: `HTTP ${response.status}; expected ${step.expectedStatus || "any status"}`,
            },
          ];
          let parsed: unknown;
          let parsedReady = false;
          const json = () => {
            if (!parsedReady) {
              parsed = JSON.parse(response.responseBody);
              parsedReady = true;
            }
            return parsed;
          };
          for (const assertion of step.assertions) {
            const actual = readFlowPath(json(), assertion.path);
            let expected: unknown = assertion.expected;
            try {
              expected = JSON.parse(assertion.expected);
            } catch {}
            const passed =
              assertion.operator === "exists"
                ? actual !== undefined
                : assertion.operator === "equals"
                  ? actual !== undefined && flowValuesEqual(actual, expected)
                  : typeof actual === "string" && actual.includes(assertion.expected);
            checks.push({
              passed,
              message: `JSON ${assertion.path || "$"} ${assertion.operator}${assertion.operator === "exists" ? "" : ` ${assertion.expected}`}`,
            });
          }
          result = { ...result, checks };
          let candidate = { ...before };
          for (const extractor of step.extractors) {
            let value: unknown;
            if (extractor.source === "text") value = response.responseBody;
            else if (extractor.source === "header")
              value = Object.entries(response.responseHeaders).find(
                ([key]) => key.toLowerCase() === extractor.path.toLowerCase(),
              )?.[1];
            else value = readFlowPath(json(), extractor.path);
            if (value === undefined || value === null)
              throw Error(
                `Extractor did not find ${extractor.path || "$"} for ${extractor.variable}`,
              );
            candidate = {
              ...candidate,
              [extractor.variable]: typeof value === "string" ? value : JSON.stringify(value),
            };
          }
          validateFlowVariables(candidate);
          if (step.afterResponse.trim()) {
            const scriptResult = await this.deps.script({
              source: step.afterResponse,
              response: {
                status: response.status,
                body: response.responseBody,
                headers: response.responseHeaders,
              },
              variables: candidate,
            });
            result = { ...result, scriptResult };
            if (scriptResult.error) throw Error(`After response: ${scriptResult.error}`);
            candidate = { ...candidate, ...scriptResult.updates };
            validateFlowVariables(candidate);
          }
          if (this.cancelled || !this.deps.isCurrent())
            throw Error("Run stopped; variable changes were discarded.");
          if (checks.some((check) => !check.passed))
            throw Error("Step checks failed. Variable changes were discarded.");
          result = { ...result, status: "passed", variablesAfter: candidate };
        } catch (error) {
          result = {
            ...result,
            error: error instanceof Error ? error.message : "Step failed",
            ...(result.scriptResult && { scriptResult: { ...result.scriptResult, updates: {} } }),
          };
        }
        result = { ...result, duration: Math.max(0, Date.now() - started) };
        this.emit({
          results: [...this.state.results, result],
          variables: result.variablesAfter,
          nextIndex: index + 1,
          sendingIndex: null,
        });
        if (this.cancelled || !this.deps.isCurrent()) {
          this.cancelled = true;
          this.finish(
            "stopped",
            this.state.message || "Workspace changed. No further steps were sent.",
          );
          return;
        }
        if (result.status === "failed" && step.onFailure === "stop") {
          this.finish("failed", `Stopped at ${step.name}.`);
          return;
        }
        if (flowRunBytes(this.state) > 8_000_000 && this.state.nextIndex < this.state.endIndex) {
          this.finish(
            "stopped",
            "Run history reached the size budget. Start a new run from this checkpoint to continue.",
          );
          return;
        }
      }
      this.finish(
        this.state.results.some((r) => r.status === "failed") ? "failed" : "passed",
        this.state.endIndex < this.state.flow.steps.length
          ? "Requested step range completed."
          : "Flow completed.",
      );
    } catch (error) {
      this.finish("failed", error instanceof Error ? error.message : "Flow failed");
    } finally {
      this.busy = false;
    }
  }
}
