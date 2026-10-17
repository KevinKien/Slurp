import { apiFetch } from "./api";
import type { FlowDocument, FlowRun, FlowRunSummary } from "./flows";
const base = (workspace: string) => `/api/workspaces/${encodeURIComponent(workspace)}`;
export const fetchFlows = (workspace: string) => apiFetch<FlowDocument>(`${base(workspace)}/flows`);
export const saveFlows = (workspace: string, document: FlowDocument) =>
  apiFetch<void>(`${base(workspace)}/flows`, { method: "PUT", body: JSON.stringify(document) });
export const saveFlowRun = (workspace: string, run: FlowRun) =>
  apiFetch<void>(`${base(workspace)}/flow-runs/${encodeURIComponent(run.id)}`, {
    method: "PUT",
    body: JSON.stringify(run),
  });
export const fetchFlowRuns = (workspace: string, offset = 0) =>
  apiFetch<{ data: FlowRunSummary[]; has_more: boolean }>(
    `${base(workspace)}/flow-runs?offset=${offset}`,
  );
export const fetchFlowRun = (workspace: string, id: string) =>
  apiFetch<FlowRun>(`${base(workspace)}/flow-runs/${encodeURIComponent(id)}`);
