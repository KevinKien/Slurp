import type { HttpRequest, Traffic } from "./traffic";

export type ReplayVariables = Record<string, string>;
export interface ReplayRun {
  profileId?: string;
  profileName?: string;
  id: string;
  timestamp: string;
  afterResponse?: string;
  scriptResult?: import("./replay-script-engine").ScriptResult;
  template: HttpRequest;
  request: HttpRequest;
  response?: Traffic | null;
  error?: string | null;
  duration: number;
}
export interface ReplayRunSummary {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  status?: number | null;
  error?: string | null;
  duration: number;
}
export const variableName = /^[A-Za-z_][A-Za-z0-9_.-]{0,99}$/;
export function normalizeVariables(doc: unknown): ReplayVariables {
  const raw = (doc as { variables?: unknown } | null)?.variables;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  return Object.fromEntries(
    Object.entries(raw)
      .filter(
        ([key, value]) =>
          variableName.test(key) &&
          typeof value === "string" &&
          new TextEncoder().encode(value).length <= 64_000,
      )
      .slice(0, 100),
  );
}
export function resolveReplayRequest(
  request: HttpRequest,
  variables: ReplayVariables,
  protocol: "http" | "websocket" = "http",
): HttpRequest {
  const replace = (value: string) => {
    let remaining = value,
      result = "";
    while (remaining.includes("{{")) {
      const start = remaining.indexOf("{{"),
        end = remaining.indexOf("}}", start + 2);
      if (end < 0) throw new Error("Unclosed variable placeholder");
      const key = remaining.slice(start + 2, end).trim();
      if (!Object.hasOwn(variables, key)) throw new Error(`Missing variable: ${key}`);
      result += remaining.slice(0, start) + variables[key];
      if (result.length > 2_000_000) throw new Error("Resolved value too large");
      remaining = remaining.slice(end + 2);
    }
    return result + remaining;
  };
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(request.headers)) {
    const name = replace(key),
      text = replace(value);
    if (Object.keys(headers).some((existing) => existing.toLowerCase() === name.toLowerCase()))
      throw new Error("Duplicate resolved header");
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n\0]/.test(text))
      throw new Error("Invalid resolved header");
    Object.defineProperty(headers, name, {
      value: text,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  const result = { ...request, url: replace(request.url), headers, body: replace(request.body) };
  if (result.url.length > 4096 || new TextEncoder().encode(result.body).length > 1_000_000)
    throw new Error("Resolved request exceeds size limit");
  const url = new URL(result.url);
  if (!(protocol === "websocket" ? ["ws:", "wss:"] : ["http:", "https:"]).includes(url.protocol) || url.username || url.password)
    throw new Error(protocol === "websocket" ? "Expected WS(S) URL without credentials" : "Expected HTTP(S) URL without credentials");
  return result;
}
export const runSummary = (run: ReplayRun): ReplayRunSummary => ({
  id: run.id,
  timestamp: run.timestamp,
  method: run.request.method,
  url: run.request.url,
  status: run.response?.status ?? null,
  error: run.error ?? null,
  duration: run.duration,
});

/** Query editing keeps the URL template intact, including a variable base URL. */
export function replayQuery(url: string): [string, string][] {
  const base = url.split("#", 1)[0] ?? "",
    start = base.indexOf("?");
  return start < 0 ? [] : Array.from(new URLSearchParams(base.slice(start + 1)).entries());
}
export function setReplayQuery(url: string, entries: [string, string][]): string {
  const hash = url.indexOf("#"),
    fragment = hash < 0 ? "" : url.slice(hash),
    beforeHash = hash < 0 ? url : url.slice(0, hash);
  const start = beforeHash.indexOf("?"),
    base = start < 0 ? beforeHash : beforeHash.slice(0, start);
  const params = new URLSearchParams(entries.filter(([key]) => key));
  const query = params
    .toString()
    .replace(/%7B%7B(.*?)%7D%7D/gi, (match) => decodeURIComponent(match));
  return `${base}${query ? "?" + query : ""}${fragment}`;
}
