import { apiFetch } from "./api";
import type { ScanRun } from "./scan";
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
