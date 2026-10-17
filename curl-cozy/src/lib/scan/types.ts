import type { HttpRequest } from "../traffic";
import type { ComparableResponse, DiffOptions } from "../response-diff";
export type FindingStatus = "suspected" | "verified" | "needs_review" | "false_positive";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type CheckId =
  "cookie-flags" | "error-disclosure" | "security-headers" | "reflection" | "input-errors" | "cors";
export type ScanParameter =
  { kind: "query"; name: string; occurrence: number } | { kind: "json"; pointer: string };
export interface ScanPlan {
  request: HttpRequest;
  mode: "passive" | "active";
  checks: CheckId[];
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
  maxRequests: number;
  rate: number;
  delay: number;
  diffOptions: DiffOptions;
}
export interface ScanEvidence {
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
  request: HttpRequest;
  baselines: Exchange[];
  stable: boolean;
  parameter?: ScanParameter;
  probe: (request: HttpRequest, label: string) => Promise<Exchange>;
  nonce: () => string;
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
