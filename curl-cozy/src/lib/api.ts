/// API client for the Rust proxy backend.

const sameOrigin = import.meta.env["VITE_SLURP_SAME_ORIGIN"] === "true";
export const API_BASE = typeof window !== "undefined"
  ? (sameOrigin ? window.location.origin : (import.meta.env["VITE_PROXY_API_URL"] ?? "http://127.0.0.1:5174"))
  : "http://127.0.0.1:5174";
export const WS_URL = typeof window !== "undefined"
  ? (sameOrigin ? `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/api/ws` : (import.meta.env["VITE_PROXY_WS_URL"] ?? "ws://127.0.0.1:5174/api/ws"))
  : "ws://127.0.0.1:5174/api/ws";

/** Shape returned by the Rust backend for each captured request. */
export interface ApiTrafficEntry {
  bookmarked?: boolean;
  notes?: string;
  id: string;
  timestamp: string;
  method: string;
  url: string;
  host: string;
  path: string;
  scheme: string;
  request_headers: string; // JSON string of Record<string, string[]>
  request_body: number[]; // byte array
  request_content_type: string | null;
  status_code: number;
  response_headers: string; // JSON string
  response_body: number[]; // byte array
  response_content_type: string | null;
  duration_ms: number;
  request_size: number;
  response_size: number;
  error: string | null;
  workspace_id: string;
  /** "proxy" for captured traffic, "replay" for requests sent from the Replay tool. */
  source: string;
}

export interface ListResponse {
  summary?: boolean;
  data: ApiTrafficEntry[];
  total: number;
  limit?: number;
  offset?: number;
  next_cursor?: string | null;
}

export interface TrafficStats {
  total_requests: number;
  total_request_bytes: number;
  total_response_bytes: number;
  error_count: number;
  top_hosts: [string, number][];
}

export interface TrafficFilters {
  bookmarked?: boolean;
  history?: boolean;
  cursor?: string;
  ascending?: boolean;
  status_class?: number;
  domains?: string[];
  limit?: number;
  offset?: number;
  host?: string;
  method?: string;
  status?: number;
  search?: string;
  /** Workspace id; omit for all workspaces. */
  workspace?: string;
}

export interface Workspace {
  id: string;
  name: string;
  created_at: string;
  request_count: number;
  /** True for the workspace receiving newly captured traffic. */
  active: boolean;
}

/** Where newly captured traffic goes, as reported by the proxy. */
export interface SessionInfo {
  /** "unchosen" until the user picks; "temporary" keeps requests in memory only. */
  target: "unchosen" | "temporary" | "workspace";
  workspace_id: string | null;
  /** Requests currently held in memory only. */
  temporary_count: number;
}

/** A request/response pair from the Replay tool, to be stored like captured traffic. */
export interface SaveReplayPayload {
  method: string;
  url: string;
  request_headers: [string, string][];
  request_body: string;
  status_code: number;
  response_headers: [string, string][];
  response_body: string;
  duration_ms: number;
  error: string | null;
}

export type HeaderPair = [name: string, value: string];

/** Interception switches: which kinds of message the proxy holds for review. */
export interface InterceptSettings {
  requests: boolean;
  responses: boolean;
}

/** A request or response currently held by the proxy, waiting for a decision. */
export interface HeldItem {
  websocket?: {opcode:number;direction:string;fin:boolean;compressed:boolean;masked:boolean;size:number;text:string|null;hex:string;truncated:boolean;dropped?:boolean} | null;
  request?: { method: string; url: string; headers: HeaderPair[]; body: string | null } | null;
  id: string;
  phase: "request" | "response";
  created_at: string;
  scheme: string;
  host: string;
  url: string;
  /** Request method (for responses: of the originating request). */
  method: string;
  /** Request path and query (for responses: of the originating request). */
  path: string;
  status: number | null;
  headers: HeaderPair[];
  /** Body text; null when the body is binary or too large to edit. */
  body: string | null;
  body_size: number;
  body_editable: boolean;
}

/** Edits to apply when forwarding a held item. Omitted fields keep their original value. */
export interface InterceptEdit {
  method?: string;
  path?: string;
  status?: number;
  headers?: HeaderPair[];
  body?: string;
}

export interface ScopeSettings { enabled: boolean; domains: string[]; }

export interface InterceptState {
  scope?: ScopeSettings;
  settings: InterceptSettings;
  held: HeldItem[];
}

export interface ProxyInfo {
  version: string;
  executable: string | null;
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    // Workspace endpoints return {error: "..."}; show that instead of a bare status.
    const detail = await res.json().then((b: { error?: string }) => b.error, () => undefined);
    throw new Error(detail ?? `API ${res.status}: ${res.statusText}`);
  }
  // DELETE returns 204 No Content
  if (res.status === 204) return undefined as unknown as T;
  return res.json();
}

/** Fetch traffic entries with optional filters. */
export async function fetchTraffic(
  filters: TrafficFilters = {},
): Promise<ListResponse> {
  const params = new URLSearchParams();
  if (filters.bookmarked) params.set("bookmarked", "true");
  if (filters.cursor) params.set("cursor", filters.cursor);
  if (filters.ascending) params.set("ascending", "true");
  if (filters.status_class) params.set("status_class", String(filters.status_class));
  if (filters.domains?.length) params.set("domains", JSON.stringify(filters.domains));
  if (filters.limit != null) params.set("limit", String(filters.limit));
  if (filters.offset != null) params.set("offset", String(filters.offset));
  if (filters.host) params.set("host", filters.host);
  if (filters.method) params.set("method", filters.method);
  if (filters.status != null) params.set("status", String(filters.status));
  if (filters.search) params.set("search", filters.search);
  if (filters.workspace) params.set("workspace", filters.workspace);
  const qs = params.toString();
  return apiFetch<ListResponse>(`/api/${filters.history ? "history" : "traffic"}${qs ? `?${qs}` : ""}`);
}

/** Fetch a single traffic entry. */
export async function fetchTrafficDetail(
  id: string,
): Promise<ApiTrafficEntry> {
  return apiFetch<ApiTrafficEntry>(`/api/traffic/${id}`);
}

/** Get traffic statistics. */
export async function fetchStats(workspace?: string): Promise<TrafficStats> {
  return apiFetch<TrafficStats>(`/api/stats${workspace ? `?workspace=${encodeURIComponent(workspace)}` : ""}`);
}

/** Clear captured traffic: one workspace if given, otherwise everything. */
export async function clearTraffic(workspace?: string): Promise<void> {
  await apiFetch<void>(`/api/traffic${workspace ? `?workspace=${encodeURIComponent(workspace)}` : ""}`, {
    method: "DELETE",
  });
}

export async function fetchWorkspaces(): Promise<Workspace[]> {
  return apiFetch<Workspace[]>("/api/workspaces");
}

export async function createWorkspace(name: string): Promise<Workspace> {
  return apiFetch<Workspace>("/api/workspaces", { method: "POST", body: JSON.stringify({ name }) });
}

export async function renameWorkspace(id: string, name: string): Promise<void> {
  await apiFetch<void>(`/api/workspaces/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ name }),
  });
}

/** Deletes the workspace and all traffic stored in it. */
export async function deleteWorkspace(id: string): Promise<void> {
  await apiFetch<void>(`/api/workspaces/${encodeURIComponent(id)}`, { method: "DELETE" });
}

/** Route newly captured traffic into this workspace. */
export async function activateWorkspace(id: string): Promise<void> {
  await apiFetch<void>(`/api/workspaces/${encodeURIComponent(id)}/activate`, { method: "POST" });
}

export async function fetchInfo(): Promise<ProxyInfo> {
  return apiFetch<ProxyInfo>("/api/info");
}

/** Export all traffic as JSON. */
export async function exportTraffic(): Promise<ApiTrafficEntry[]> {
  return apiFetch<ApiTrafficEntry[]>("/api/traffic/export");
}

/** Check if the proxy backend is reachable. */
export async function checkConnection(): Promise<boolean> {
  try {
    await fetchStats();
    return true;
  } catch {
    return false;
  }
}

export async function fetchIntercept(): Promise<InterceptState> {
  return apiFetch<InterceptState>("/api/intercept");
}

export async function updateInterceptSettings(update: Partial<InterceptSettings>): Promise<InterceptSettings> {
  return apiFetch<InterceptSettings>("/api/intercept/settings", { method: "PUT", body: JSON.stringify(update) });
}

/** Forward a held item, optionally with edits. Rejects (and keeps the item held) if the edit is invalid. */
export async function forwardHeld(id: string, edit?: InterceptEdit): Promise<void> {
  await apiFetch<void>(`/api/intercept/${encodeURIComponent(id)}/forward`, {
    method: "POST",
    ...(edit && { body: JSON.stringify(edit) }),
  });
}

/** Drop a held item; the client receives a 502. */
export async function dropHeld(id: string): Promise<void> {
  await apiFetch<void>(`/api/intercept/${encodeURIComponent(id)}/drop`, { method: "POST" });
}

/** Forward everything that is held, unchanged. */
export async function forwardAllHeld(): Promise<void> {
  await apiFetch<void>("/api/intercept/forward-all", { method: "POST" });
}

export async function fetchSession(): Promise<SessionInfo> {
  return apiFetch<SessionInfo>("/api/session");
}

/** Continue without a workspace: requests stay in memory and are lost when the tool exits. */
export async function useTemporarySession(): Promise<void> {
  await apiFetch<void>("/api/session/temporary", { method: "POST" });
}

/** Store a replayed request in the current workspace (or in memory if none is chosen). */
export async function saveReplay(payload: SaveReplayPayload): Promise<ApiTrafficEntry> {
  return apiFetch<ApiTrafficEntry>("/api/traffic", { method: "POST", body: JSON.stringify(payload) });
}

/** Saved Replay tabs of a workspace (empty if none were saved yet). */
export async function fetchReplayTabs(workspaceId: string): Promise<unknown> {
  return apiFetch<unknown>(`/api/workspaces/${encodeURIComponent(workspaceId)}/replay`);
}

/** Replace a workspace's saved Replay tabs. `keepalive` lets the request finish while the page unloads. */
export async function saveReplayTabs(workspaceId: string, doc: unknown, options: { keepalive?: boolean } = {}): Promise<void> {
  await apiFetch<void>(`/api/workspaces/${encodeURIComponent(workspaceId)}/replay`, {
    method: "PUT",
    body: JSON.stringify(doc),
    ...(options.keepalive && { keepalive: true }),
  });
}

export async function updateScope(scope: ScopeSettings): Promise<ScopeSettings> {
  return apiFetch<ScopeSettings>("/api/intercept/scope", { method: "PUT", body: JSON.stringify(scope) });
}

export interface ProxyListenerSettings { host: string; port: number }
export async function proxyListenerSettings(settings?: ProxyListenerSettings): Promise<ProxyListenerSettings> {
  const response = await fetch(`${API_BASE}/api/settings/proxy`, settings === undefined ? {} : {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.error ?? `Proxy settings request failed (${response.status})`);
  }
  return response.json();
}

export interface ProxyLocalInterface { name: string; address: string }
export async function fetchProxyInterfaces(): Promise<ProxyLocalInterface[]> {
  return apiFetch<ProxyLocalInterface[]>('/api/settings/proxy/interfaces');
}
