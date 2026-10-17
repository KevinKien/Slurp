import { methods, type HttpRequest, type Traffic } from "./traffic";
import { variableName, type ReplayVariables } from "./replay-features";
import type { ScriptResult } from "./replay-script-engine";
export interface FlowExtractor {
  variable: string;
  source: "json" | "header" | "text";
  path: string;
}
export interface FlowAssertion {
  path: string;
  operator: "exists" | "equals" | "contains";
  expected: string;
}
export interface FlowStep {
  id: string;
  name: string;
  enabled: boolean;
  request: HttpRequest;
  pauseBefore: boolean;
  pauseMessage: string;
  expectedStatus: string;
  onFailure: "stop" | "continue";
  extractors: FlowExtractor[];
  assertions: FlowAssertion[];
  afterResponse: string;
}
export interface Flow {
  id: string;
  name: string;
  variables: ReplayVariables;
  steps: FlowStep[];
}
export interface FlowDocument {
  flows: Flow[];
  active: string | null;
}
export interface FlowStepResult {
  stepId: string;
  index: number;
  name: string;
  status: "passed" | "failed" | "skipped";
  request?: HttpRequest;
  response?: Traffic;
  error?: string;
  checks: { passed: boolean; message: string }[];
  scriptResult?: ScriptResult;
  variablesBefore: ReplayVariables;
  variablesAfter: ReplayVariables;
  duration: number;
}
export interface FlowRun {
  profileId?: string;
  profileName?: string;
  id: string;
  flow: Flow;
  startedAt: string;
  finishedAt?: string;
  duration: number;
  status: "running" | "paused" | "passed" | "failed" | "stopped";
  initialVariables: ReplayVariables;
  variables: ReplayVariables;
  results: FlowStepResult[];
  startIndex: number;
  nextIndex: number;
  endIndex: number;
  sendingIndex: number | null;
  message: string;
  parentRunId?: string;
}
export interface FlowRunSummary {
  id: string;
  flowId: string;
  name: string;
  startedAt: string;
  status: FlowRun["status"];
  duration: number;
  steps: number;
}
export const flowId = () =>
  globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
export const emptyFlowDocument = (): FlowDocument => ({ flows: [], active: null });
export const newFlowStep = (
  request: HttpRequest = { method: "GET", url: "", headers: {}, body: "" },
  name = "New step",
): FlowStep => ({
  id: flowId(),
  name,
  enabled: true,
  request: structuredClone(request),
  pauseBefore: false,
  pauseMessage: "Enter any required variables (for example otp), then continue.",
  expectedStatus: "2xx",
  onFailure: "stop",
  extractors: [],
  assertions: [],
  afterResponse: "",
});
export const newFlow = (): Flow => ({
  id: flowId(),
  name: "Untitled flow",
  variables: {},
  steps: [],
});
const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;
export function validateFlowVariables(variables: ReplayVariables): void {
  if (
    !variables ||
    typeof variables !== "object" ||
    Array.isArray(variables) ||
    Object.keys(variables).length > 100
  )
    throw Error("A run supports up to 100 variables.");
  for (const [name, value] of Object.entries(variables))
    if (
      !variableName.test(name) ||
      typeof value !== "string" ||
      new TextEncoder().encode(value).length > 64000
    )
      throw Error("Invalid variable name or value exceeds 64 KB.");
  if (bytes(variables) > 256000) throw Error("Flow variables exceed the 256 KB total limit.");
}
export function validStatusExpectation(value: string): boolean {
  return value === "" || /^[1-5](?:\d\d|xx)(?:\s*,\s*[1-5](?:\d\d|xx))*$/.test(value);
}
export function statusMatches(status: number, expected: string): boolean {
  return (
    !expected ||
    expected.split(",").some((v) => {
      const token = v.trim();
      return token.endsWith("xx")
        ? Math.floor(status / 100) === Number(token[0])
        : status === Number(token);
    })
  );
}
export function flowValuesEqual(left: unknown, right: unknown, depth = 0): boolean {
  if (left === right) return true;
  if (depth > 64) throw Error("JSON comparison exceeds the nesting limit.");
  if (!left || !right || typeof left !== "object" || typeof right !== "object") return false;
  if (Array.isArray(left) !== Array.isArray(right)) return false;
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every(
      (key) =>
        Object.hasOwn(right, key) &&
        flowValuesEqual(
          (left as Record<string, unknown>)[key],
          (right as Record<string, unknown>)[key],
          depth + 1,
        ),
    )
  );
}
export function validateFlow(flow: Flow): void {
  if (
    typeof flow.id !== "string" ||
    !flow.id ||
    flow.id.length > 100 ||
    typeof flow.name !== "string" ||
    !flow.name.trim() ||
    flow.name.length > 200 ||
    !Array.isArray(flow.steps) ||
    flow.steps.length > 50
  )
    throw Error("Flow name is required (up to 200 characters); at most 50 steps are supported.");
  validateFlowVariables(flow.variables);
  if (bytes(flow) > 5_000_000) throw Error("Flow exceeds the 5 MB size limit.");
  const ids = new Set<string>();
  for (const step of flow.steps) {
    if (
      typeof step.id !== "string" ||
      !step.id ||
      step.id.length > 100 ||
      ids.has(step.id) ||
      typeof step.name !== "string" ||
      !step.name.trim() ||
      step.name.length > 200
    )
      throw Error("Step names and unique IDs are required.");
    ids.add(step.id);
    if (
      typeof step.enabled !== "boolean" ||
      typeof step.pauseBefore !== "boolean" ||
      typeof step.pauseMessage !== "string" ||
      step.pauseMessage.length > 2000 ||
      !["stop", "continue"].includes(step.onFailure)
    )
      throw Error("Invalid step settings.");
    if (typeof step.expectedStatus !== "string" || !validStatusExpectation(step.expectedStatus))
      throw Error(
        "Expected status must be empty, an HTTP code, a class such as 2xx, or a comma-separated list.",
      );
    if (typeof step.afterResponse !== "string" || step.afterResponse.length > 32000)
      throw Error("Script exceeds 32,000 characters.");
    const req = step.request;
    if (
      !req ||
      !methods.includes(req.method) ||
      typeof req.url !== "string" ||
      req.url.length > 4096 ||
      typeof req.body !== "string" ||
      new TextEncoder().encode(req.body).length > 1_000_000 ||
      !req.headers ||
      Array.isArray(req.headers) ||
      typeof req.headers !== "object" ||
      Object.keys(req.headers).length > 200
    )
      throw Error("Invalid request or request exceeds Replay size limits.");
    if (
      Object.entries(req.headers).some(
        ([k, v]) =>
          !k ||
          typeof v !== "string" ||
          k.length > 8192 ||
          v.length > 8192 ||
          /[\r\n\0]/.test(k + v),
      )
    )
      throw Error("Invalid request header.");
    if (
      !Array.isArray(step.extractors) ||
      step.extractors.length > 20 ||
      !Array.isArray(step.assertions) ||
      step.assertions.length > 20
    )
      throw Error("At most 20 extractors and assertions are supported per step.");
    for (const extractor of step.extractors)
      if (
        typeof extractor.variable !== "string" ||
        !variableName.test(extractor.variable) ||
        !["json", "header", "text"].includes(extractor.source) ||
        typeof extractor.path !== "string" ||
        extractor.path.length > 500
      )
        throw Error("Invalid extractor: enter a valid variable name and path.");
    for (const assertion of step.assertions)
      if (
        typeof assertion.path !== "string" ||
        assertion.path.length > 500 ||
        !["exists", "equals", "contains"].includes(assertion.operator) ||
        typeof assertion.expected !== "string" ||
        assertion.expected.length > 64000
      )
        throw Error("Invalid JSON assertion.");
  }
}
export function validateFlowDocument(doc: FlowDocument): void {
  if (!doc || !Array.isArray(doc.flows) || doc.flows.length > 50)
    throw Error("A workspace supports up to 50 flows.");
  const seen = new Set<string>();
  for (const flow of doc.flows) {
    validateFlow(flow);
    if (seen.has(flow.id)) throw Error("Duplicate flow ID.");
    seen.add(flow.id);
  }
  if (bytes(doc) > 5_000_000) throw Error("Flow definitions exceed the 5 MB workspace limit.");
}
export function normalizeFlowDocument(raw: unknown): FlowDocument {
  const doc = raw as FlowDocument;
  validateFlowDocument(doc);
  return {
    flows: doc.flows,
    active: doc.flows.some((flow) => flow.id === doc.active)
      ? doc.active
      : (doc.flows[0]?.id ?? null),
  };
}
/** Dot paths, numeric array indices and JSON pointers; no evaluation or inherited properties. */
export function readFlowPath(value: unknown, path: string): unknown {
  if (!path || path === "$") return value;
  let parts: string[];
  if (path.startsWith("/"))
    parts = path
      .slice(1)
      .split("/")
      .map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
  else {
    const normalized = path.replace(/^\$\.?/, "").replace(/\[(\d+)\]/g, ".$1");
    if (/[\[\]]/.test(normalized))
      throw Error("Use dot paths, numeric array indices or JSON pointers.");
    parts = normalized.split(".");
  }
  let current = value;
  for (const part of parts) {
    if (!current || typeof current !== "object" || !Object.hasOwn(current, part)) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}
export const flowRunSummary = (run: FlowRun): FlowRunSummary => ({
  id: run.id,
  flowId: run.flow.id,
  name: run.flow.name,
  startedAt: run.startedAt,
  status: run.status,
  duration: run.duration,
  steps: run.results.length,
});
export const flowRunBytes = bytes;
