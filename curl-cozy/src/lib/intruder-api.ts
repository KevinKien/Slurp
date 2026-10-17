import { apiFetch } from "./api";
import type {
  IntruderConfig,
  IntruderRun,
  IntruderRunSummary,
  IntruderResult,
  IntruderResultSummary,
  PayloadFile,
} from "./intruder";
const base = (workspace: string) => `/api/workspaces/${encodeURIComponent(workspace)}`;
export const fetchIntruder = (workspace: string) =>
  apiFetch<{ revision: number; document: IntruderConfig | null }>(`${base(workspace)}/intruder`);
export const saveIntruder = (workspace: string, revision: number, document: IntruderConfig) =>
  apiFetch<{ revision: number }>(`${base(workspace)}/intruder`, {
    method: "PUT",
    body: JSON.stringify({ revision, document }),
  });
export const fetchPayloadFiles = (workspace: string) =>
  apiFetch<{ data: PayloadFile[] }>(`${base(workspace)}/intruder-sources`);
export const createPayloadFile = (workspace: string, name: string) =>
  apiFetch<{ id: string }>(`${base(workspace)}/intruder-sources`, {
    method: "POST",
    body: JSON.stringify({ name }),
  });
export const appendPayloads = (workspace: string, id: string, offset: number, values: string[]) =>
  apiFetch<{ count: number }>(
    `${base(workspace)}/intruder-sources/${encodeURIComponent(id)}/append`,
    { method: "POST", body: JSON.stringify({ offset, values }) },
  );
export const finalizePayloadFile = (workspace: string, id: string) =>
  apiFetch<void>(`${base(workspace)}/intruder-sources/${encodeURIComponent(id)}/finalize`, {
    method: "POST",
  });
export const deletePayloadFile = (workspace: string, id: string) =>
  apiFetch<void>(`${base(workspace)}/intruder-sources/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
export const fetchPayloadPage = (workspace: string, id: string, offset: number) =>
  apiFetch<{ values: string[] }>(
    `${base(workspace)}/intruder-sources/${encodeURIComponent(id)}?offset=${offset}`,
  );
export const saveIntruderRun = (workspace: string, run: IntruderRun) =>
  apiFetch<void>(`${base(workspace)}/intruder-runs/${encodeURIComponent(run.id)}`, {
    method: "PUT",
    body: JSON.stringify(run),
  });
export const fetchIntruderRun = (workspace: string, id: string) =>
  apiFetch<IntruderRun>(`${base(workspace)}/intruder-runs/${encodeURIComponent(id)}`);
export const fetchIntruderRuns = (workspace: string, offset = 0) =>
  apiFetch<{ data: IntruderRunSummary[]; has_more: boolean }>(
    `${base(workspace)}/intruder-runs?offset=${offset}`,
  );
export const deleteIntruderRun = (workspace: string, id: string) =>
  apiFetch<void>(`${base(workspace)}/intruder-runs/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
export const saveIntruderResult = (workspace: string, run: string, result: IntruderResult) =>
  apiFetch<void>(
    `${base(workspace)}/intruder-runs/${encodeURIComponent(run)}/results/${result.index}`,
    { method: "PUT", body: JSON.stringify(result) },
  );
export const fetchIntruderResult = (workspace: string, run: string, index: number) =>
  apiFetch<IntruderResult>(
    `${base(workspace)}/intruder-runs/${encodeURIComponent(run)}/results/${index}`,
  );
export interface IntruderResultQuery {
  offset: number;
  q: string;
  status: number;
  matched: boolean;
  errors: boolean;
  sort: string;
  descending: boolean;
}
export const fetchIntruderResults = (workspace: string, run: string, query: IntruderResultQuery) =>
  apiFetch<{ data: IntruderResultSummary[]; total: number; has_more: boolean }>(
    `${base(workspace)}/intruder-runs/${encodeURIComponent(run)}/results?${new URLSearchParams(Object.entries(query).map(([key, value]) => [key, String(value)]))}`,
  );
