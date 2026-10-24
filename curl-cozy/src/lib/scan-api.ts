import { apiFetch } from "./api";
import type { ScanRun } from "./scan";
export async function validateBrowserSnapshot(input: {
  url: string;
  body: string;
  headers: Record<string, string>;
  marker: string;
  resources?: import("./scan/types").BrowserResource[];
  interaction?: import("./scan/types").BrowserInteraction;
}): Promise<Omit<import("./scan/types").BrowserObservation, "marker" | "url">> {
  const response = await apiFetch<
    | { ok: true; observation: Omit<import("./scan/types").BrowserObservation, "marker" | "url"> }
    | { ok: false; error: string }
  >("/api/scan/browser", { method: "POST", body: JSON.stringify(input) });
  if (!response.ok) throw Error(response.error);
  return response.observation;
}
export interface AutomaticAuditStatus {
  enabled: boolean;
  queued: number;
  active: number;
  completed: number;
  skipped: number;
  errors: number;
}
export const fetchAutomaticAudit = () => apiFetch<AutomaticAuditStatus>("/api/scan/automatic");
export const setAutomaticAudit = (enabled: boolean) =>
  apiFetch<AutomaticAuditStatus>("/api/scan/automatic", {
    method: "PUT",
    body: JSON.stringify({ enabled }),
  });
export interface ScanSummary {
  id: string;
  startedAt: string;
  status: ScanRun["status"];
  sent: number;
  findings: number;
  url?: string;
  method?: string;
  mode?: string;
  maxRequests?: number;
  profileName?: string;
}
const base = (workspace: string) => `/api/workspaces/${encodeURIComponent(workspace)}/scan-runs`;
export const saveScanRun = (workspace: string, run: ScanRun) =>
  apiFetch<void>(`${base(workspace)}/${encodeURIComponent(run.id)}`, {
    method: "PUT",
    body: JSON.stringify(run),
  });
export const fetchScanRun = (workspace: string, id: string) =>
  apiFetch<ScanRun>(`${base(workspace)}/${encodeURIComponent(id)}`);
export const fetchScanRuns = (workspace: string, offset = 0) =>
  apiFetch<{ data: ScanSummary[]; has_more: boolean }>(`${base(workspace)}?offset=${offset}`);
export const deleteScanRun = (workspace: string, id: string) =>
  apiFetch<void>(`${base(workspace)}/${encodeURIComponent(id)}`, { method: "DELETE" });

export interface DashboardFinding {
  runId: string;
  startedAt: string;
  url: string;
  method: string;
  finding: import("./scan").Finding;
}
export const fetchScanFindings = (
  workspace: string,
  offset = 0,
  q = "",
  status = "",
  severity = "",
) =>
  apiFetch<{ data: DashboardFinding[]; total: number; has_more: boolean }>(
    `/api/workspaces/${encodeURIComponent(workspace)}/scan-findings?${new URLSearchParams({ offset: String(offset), q, status, severity })}`,
  );

export const issueOastProbe = () =>
  apiFetch<import("./scan/types").OastProbe>("/api/scan/oast/probes", { method: "POST" });
export const pollOastProbe = (id: string) =>
  apiFetch<import("./scan/types").OastProbe>(`/api/scan/oast/probes/${encodeURIComponent(id)}`);
export const fetchOastStatus = () =>
  apiFetch<{ enabled: boolean; error?: string; http: boolean; dns: boolean }>("/api/scan/oast");

export const probeHttpProtocol = (input: {
  url: string;
  variant: import("./scan/types").ProtocolVariant;
  timeoutMs: number;
}) =>
  apiFetch<import("./scan/types").ProtocolResponse | { ok: false; error: string }>(
    "/api/scan/protocol",
    { method: "POST", body: JSON.stringify(input) },
  );

export const lookupDependency = (name: string, version: string) =>
  apiFetch<import("./scan/dependency-checks").DependencyResult | { ok: false; error: string }>(
    "/api/scan/dependencies",
    { method: "POST", body: JSON.stringify({ package: name, version }) },
  );

export const publishJwtKey = (material: { kind: "jwks" | "certificate"; body: string }) =>
  apiFetch<import("./scan/types").OastProbe>("/api/scan/oast/keys", {
    method: "POST",
    body: JSON.stringify(material),
    headers: { "Content-Type": "application/json" },
  });

export const probeHostHeader = (input:{request:import("./traffic").HttpRequest;header:"host"|"x-forwarded-host";host:string;timeoutMs:number}) => apiFetch<({ok:true}&import("./scan/types").ScanResponse)|{ok:false;error:string}>("/api/scan/host-header",{method:"POST",body:JSON.stringify({request:{...input.request,timeout:Math.min(30000,input.timeoutMs)},header:input.header,host:input.host})});
