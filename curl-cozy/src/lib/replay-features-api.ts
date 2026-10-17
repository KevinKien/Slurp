import { apiFetch } from "./api";
import type { ReplayRun, ReplayRunSummary } from "./replay-features";
const path = (workspace: string, tab: number) =>
  `/api/workspaces/${encodeURIComponent(workspace)}/replay/tabs/${tab}/runs`;
export const saveReplayRun = (workspace: string, tab: number, run: ReplayRun) =>
  apiFetch<ReplayRun>(path(workspace, tab), { method: "POST", body: JSON.stringify(run) });
export const fetchReplayRuns = (workspace: string, tab: number, offset = 0) =>
  apiFetch<{ data: ReplayRunSummary[]; has_more: boolean }>(
    `${path(workspace, tab)}?offset=${offset}`,
  );
export const fetchReplayRun = (workspace: string, tab: number, id: string) =>
  apiFetch<ReplayRun>(`${path(workspace, tab)}/${encodeURIComponent(id)}`);
export const updateTrafficAnnotation = (
  id: string,
  patch: { bookmarked?: boolean; notes?: string },
) =>
  apiFetch<{ bookmarked: boolean; notes: string }>(
    `/api/traffic/${encodeURIComponent(id)}/annotation`,
    { method: "PATCH", body: JSON.stringify(patch) },
  );
