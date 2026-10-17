import { apiFetch } from "./api";
import type { ProfilesDocument } from "./auth-profiles";
import type { MatrixRun, MatrixSummary } from "./authorization-matrix";
const base = (workspace: string) => `/api/workspaces/${encodeURIComponent(workspace)}`;
export const fetchProfiles = (workspace: string) =>
  apiFetch<{ revision: number; document: ProfilesDocument }>(`${base(workspace)}/profiles`);
export const saveProfiles = (workspace: string, revision: number, document: ProfilesDocument) =>
  apiFetch<{ revision: number }>(`${base(workspace)}/profiles`, {
    method: "PUT",
    body: JSON.stringify({ revision, document }),
  });
export const saveMatrixRun = (workspace: string, run: MatrixRun) =>
  apiFetch<void>(`${base(workspace)}/matrix-runs/${encodeURIComponent(run.id)}`, {
    method: "PUT",
    body: JSON.stringify(run),
  });
export const fetchMatrixRuns = (workspace: string, offset = 0) =>
  apiFetch<{ data: MatrixSummary[]; has_more: boolean }>(
    `${base(workspace)}/matrix-runs?offset=${offset}`,
  );
export const fetchMatrixRun = (workspace: string, id: string) =>
  apiFetch<MatrixRun>(`${base(workspace)}/matrix-runs/${encodeURIComponent(id)}`);
