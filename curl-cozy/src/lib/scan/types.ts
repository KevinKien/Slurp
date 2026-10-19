import type { HttpRequest } from "../traffic";
import type { ComparableResponse, DiffOptions } from "../response-diff";
export type FindingStatus = "suspected" | "verified" | "needs_review" | "false_positive";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ProtocolVariant = "control" | "chunked" | "cl-te" | "te-cl" | "duplicate-cl";
export interface ProtocolResponse {
  ok: true;
  rawRequest: string;
  rawResponse: string;
  status: number;
  duration: number;
  size: number;
}
export type CheckId =
  | "403-bypass"
  | "dependency-audit"
  | "jwt-signature"
  | "graphql-introspection"
  | "graphql-batching"
  | "http-framing"
  | "browser-xss"
  | "dom-xss"
  | "dom-interaction"
  | "oast-ssrf"
  | "oast-xxe"
  | "cookie-flags"
  | "error-disclosure"
  | "security-headers"
  | "reflection"
  | "input-errors"
  | "cors"
  | "noauthen"
  | "js-endpoints"
  | "js-secrets"
  | "passive-audit"
  | "sql-injection"
  | "ssti"
  | "path-traversal"
  | "open-redirect"
  | "cookie-audit"
  | "disclosure-audit"
  | "policy-audit"
  | "sql-boolean"
  | "sql-time"
  | "header-injection"
  | "auth-access"
  | "referer-access"
  | "client-ip"
  | "url-override"
  | "http-methods"
  | "command-injection"
  | "code-injection"
  | "el-injection"
  | "ldap-injection"
  | "xpath-injection"
  | "xml-injection"
  | "xml-entity"
  | "xxe"
  | "xml-injection-body"
  | "xml-entity-body"
  | "xxe-body";
export type ScanParameter =
  { kind: "query"; name: string; occurrence: number } | { kind: "json"; pointer: string };
export interface ScanPlan {
  request: HttpRequest;
  mode: "passive" | "active" | "both";
  checks: CheckId[];
  policy?: import("./registry").ScanPolicy;
  parameters: ScanParameter[];
  /** Required before sending any request, including baseline requests. */
  allowSending: boolean;
  observed?: {
    response: ComparableResponse;
    setCookies?: string[];
    duration?: number;
    size?: number;
  };
  baselineSamples: number;
  /** Legacy saved plans only; ignored during execution. */
  maxRequests?: number;
  rate: number;
  delay: number;
  diffOptions: DiffOptions;
}
export interface ScanEvidence {
  rawRequest?: string;
  rawResponse?: string;
  browser?: BrowserObservation[];
  oast?: OastProbe[];
  id: string;
  label: string;
  timestamp: string;
  request: HttpRequest;
  response?: ComparableResponse;
  setCookies: string[];
  duration: number;
  size: number;
  error?: string;
  truncated: boolean;
  bodyHash?: string;
}
export interface Finding {
  id: string;
  fingerprint: string;
  checkId: CheckId;
  title: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  status: FindingStatus;
  parameter?: ScanParameter;
  evidenceIds: string[];
  summary: string;
  verification: {
    method: string;
    outcome: "confirmed" | "inconclusive" | "not_performed";
    reason: string;
  };
  excerpts: string[];
  remediation: string;
}
export interface CheckResult {
  checkId: CheckId;
  parameter?: ScanParameter;
  status: "passed" | "findings" | "inconclusive" | "skipped";
  message: string;
  findingIds: string[];
}
export interface ScanRun {
  domAudits?: import("./dom-audit").DomAudit[];
  version: 1;
  id: string;
  startedAt: string;
  finishedAt?: string;
  status: "running" | "paused" | "completed" | "stopped" | "failed";
  message: string;
  plan: ScanPlan;
  profileId?: string;
  profileName?: string;
  sent: number;
  bytes: number;
  baselineStable: boolean | null;
  baselineIds: string[];
  evidence: ScanEvidence[];
  findings: Finding[];
  checks: CheckResult[];
}
export interface ScanResponse extends ComparableResponse {
  setCookies?: string[];
  duration: number;
  size: number;
}
export interface Exchange {
  evidence: ScanEvidence;
  response?: ScanResponse;
}
export interface ScanCheckContext {
  dependencies?: (
    name: string,
    version: string,
  ) => Promise<import("./dependency-checks").DependencyResult | { ok: false; error: string }>;
  protocol?: (variant: ProtocolVariant, label: string) => Promise<Exchange>;
  oast?: OastClient;
  loadScript?: (url: string) => Promise<Exchange>;
  recordDomAudit?: (audit: import("./dom-audit").DomAudit) => void;
  browser?: import("./browser-checks").BrowserValidator;
  request: HttpRequest;
  baselines: Exchange[];
  stable: boolean;
  diffOptions?: DiffOptions;
  parameter?: ScanParameter;
  probe: (request: HttpRequest, label: string) => Promise<Exchange>;
  nonce: () => string;
}
export interface BrowserInteraction {
  selector?: string;
  value?: string;
}
export interface BrowserObservation {
  interactions?: string[];
  /** Blocked main-frame GET script dependencies, never fetched by Chromium. */
  requestedScripts?: string[];
  sinkTraces?: BrowserSinkTrace[];
  executed: boolean;
  marker: string;
  url: string;
  sinks: string[];
  cspViolations: string[];
  blockedRequests: number;
  browser: string;
}
export interface BrowserSinkTrace {
  sink: string;
  value: string;
  stack: string;
}
export interface BrowserResource {
  url: string;
  body: string;
  headers: Record<string, string>;
}
export interface CheckOutput {
  findings: Omit<Finding, "id" | "fingerprint" | "checkId" | "parameter">[];
  message: string;
  inconclusive?: boolean;
}
export interface ScanCheck {
  id: CheckId;
  name: string;
  active: boolean;
  perParameter: boolean;
  run: (ctx: ScanCheckContext) => Promise<CheckOutput>;
}

export interface OastEvent {
  protocol: "http" | "dns";
  timestamp: string;
  peer: string;
  detail: string;
}
export interface OastProbe {
  id: string;
  url: string;
  dnsName?: string;
  expiresAt: string;
  events: OastEvent[];
}
export interface OastClient {
  issue: () => Promise<OastProbe>;
  poll: (probe: OastProbe, exchange?: Exchange) => Promise<OastProbe>;
  wait: (ms: number) => Promise<void>;
}
