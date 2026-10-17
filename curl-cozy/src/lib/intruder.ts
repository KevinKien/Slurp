import { methods, type HttpRequest } from "./traffic";
import type { ComparableResponse } from "./response-diff";
export type PayloadEncoding = "none" | "url" | "base64" | "hex" | "html";
export type PayloadSource =
  | { kind: "list"; values: string[] }
  | { kind: "numbers"; from: string; to: string; step: string; pad: number }
  | { kind: "file"; id: string; name: string; count: number };
export interface IntruderConfig {
  request: HttpRequest;
  source: PayloadSource;
  encoding: PayloadEncoding;
  start: number;
  limit: number;
  concurrency: number;
  rate: number;
  delay: number;
  matchText: string;
}
export interface PayloadFile {
  id: string;
  name: string;
  count: number;
  bytes: number;
  ready: boolean;
}
export interface IntruderRun {
  id: string;
  startedAt: string;
  finishedAt?: string;
  config: IntruderConfig;
  profileId?: string;
  profileName?: string;
  count: number;
  completed: number;
  launched: number;
  inFlight: number;
  bytes: number;
  saved?: number;
  status: "running" | "paused" | "completed" | "stopped" | "failed";
  message: string;
}
export interface IntruderRunSummary {
  id: string;
  startedAt: string;
  status: IntruderRun["status"];
  count: number;
  completed: number;
  bytes: number;
}
export interface IntruderResultSummary {
  index: number;
  payloadIndex: number;
  payload: string;
  status: number | null;
  size: number;
  duration: number;
  matched: boolean | number;
  error?: string;
  truncated: boolean | number;
}
export interface IntruderResult extends IntruderResultSummary {
  timestamp: string;
  encodedPayload: string;
  request?: HttpRequest;
  response?: ComparableResponse;
  bodyHash?: string;
}
export const newIntruderConfig = (): IntruderConfig => ({
  request: { method: "GET", url: "", headers: {}, body: "" },
  source: { kind: "list", values: [] },
  encoding: "none",
  start: 0,
  limit: 1000,
  concurrency: 1,
  rate: 5,
  delay: 0,
  matchText: "",
});
export function sourceCount(source: PayloadSource): number {
  if (source.kind === "list") return source.values.length;
  if (source.kind === "file") return source.count;
  if (
    !/^-?\d{1,20}$/.test(source.from) ||
    !/^[-+]?\d{1,20}$/.test(source.to) ||
    !/^[-+]?\d{1,20}$/.test(source.step)
  )
    throw Error("Use integer values for the number range.");
  const from = BigInt(source.from),
    to = BigInt(source.to),
    step = BigInt(source.step),
    min = -(2n ** 63n),
    max = 2n ** 63n - 1n;
  if ([from, to, step].some((v) => v < min || v > max))
    throw Error("Numbers must fit a signed 64-bit integer.");
  if (step === 0n || (to > from && step < 0n) || (to < from && step > 0n))
    throw Error("Step must move from the start toward the end and cannot be zero.");
  const total = (to - from) / step + 1n;
  if (total > 1000000n) throw Error("A number range supports up to 1 million payloads.");
  return Number(total);
}
export function payloadAt(source: Exclude<PayloadSource, { kind: "file" }>, index: number): string {
  if (!Number.isInteger(index) || index < 0 || index >= sourceCount(source))
    throw Error("Payload index is outside the source.");
  if (source.kind === "list") return source.values[index]!;
  const value = BigInt(source.from) + BigInt(source.step) * BigInt(index);
  return (
    (value < 0n ? "-" : "") + (value < 0n ? -value : value).toString().padStart(source.pad, "0")
  );
}
export function encodePayload(value: string, encoding: PayloadEncoding): string {
  if (encoding === "url")
    return encodeURIComponent(value).replace(
      /[!'()*]/g,
      (char) => "%" + char.charCodeAt(0).toString(16).toUpperCase(),
    );
  if (encoding === "base64")
    return btoa(
      Array.from(new TextEncoder().encode(value), (byte) => String.fromCharCode(byte)).join(""),
    );
  if (encoding === "hex")
    return Array.from(new TextEncoder().encode(value), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
  if (encoding === "html")
    return value.replace(
      /[&<>"']/g,
      (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!,
    );
  return value;
}
export function positionCount(request: HttpRequest): number {
  if (Object.keys(request.headers).some((name) => name.includes("§")))
    throw Error("Mark header values, not header names.");
  let count = 0;
  for (const text of [request.url, request.body, ...Object.values(request.headers)]) {
    const markers = text.split("§").length - 1;
    if (markers % 2) throw Error("Payload markers must be paired within the same field.");
    count += markers / 2;
  }
  return count;
}
export function validateFinalRequest(request: HttpRequest) {
  if (!methods.includes(request.method)) throw Error("Unsupported method.");
  if (request.url.length > 4096 || new TextEncoder().encode(request.body).length > 1000000)
    throw Error("Request exceeds URL/body size limits.");
  const url = new URL(request.url);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password)
    throw Error("Expected an HTTP(S) URL without credentials.");
  if (Object.keys(request.headers).length > 200) throw Error("Too many request headers.");
  for (const [name, value] of Object.entries(request.headers))
    if (
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) ||
      name.length > 8192 ||
      value.length > 8192 ||
      /[\r\n\0]/.test(value)
    )
      throw Error("Payload produced an invalid request header.");
}
export function applyPayload(
  request: HttpRequest,
  payload: string,
  encoding: PayloadEncoding,
): HttpRequest {
  if (positionCount(request) !== 1)
    throw Error(
      "Mark exactly one payload position with §value§. A selected profile may replace marked authentication headers.",
    );
  const encoded = encodePayload(payload, encoding);
  const replace = (text: string) => {
    const start = text.indexOf("§");
    if (start < 0) return text;
    const end = text.indexOf("§", start + 1);
    return text.slice(0, start) + encoded + text.slice(end + 1);
  };
  const result = {
    ...request,
    url: replace(request.url),
    body: replace(request.body),
    headers: Object.fromEntries(
      Object.entries(request.headers).map(([key, value]) => [key, replace(value)]),
    ),
  };
  validateFinalRequest(result);
  return result;
}
export function validateIntruderConfig(config: IntruderConfig, requirePosition = true) {
  if (
    !config ||
    !config.request ||
    typeof config.request.url !== "string" ||
    typeof config.request.body !== "string" ||
    !config.request.headers ||
    typeof config.request.headers !== "object" ||
    Array.isArray(config.request.headers) ||
    Object.values(config.request.headers).some((v) => typeof v !== "string")
  )
    throw Error("Invalid request.");
  if (
    !methods.includes(config.request.method) ||
    config.request.url.length > 4096 ||
    new TextEncoder().encode(config.request.body).length > 1000000
  )
    throw Error("Invalid request or request too large.");
  if (!["none", "url", "base64", "hex", "html"].includes(config.encoding))
    throw Error("Invalid payload encoding.");
  for (const [value, min, max] of [
    [config.start, 0, 999999],
    [config.limit, 1, 100000],
    [config.concurrency, 1, 10],
    [config.rate, 1, 100],
    [config.delay, 0, 60000],
  ] as const)
    if (!Number.isInteger(value) || value < min || value > max)
      throw Error("Invalid request range, concurrency or rate controls.");
  if (typeof config.matchText !== "string" || config.matchText.length > 2000)
    throw Error("Match text exceeds 2,000 characters.");
  if (
    config.source.kind === "list" &&
    (config.source.values.length > 10000 ||
      config.source.values.some(
        (v) => typeof v !== "string" || new TextEncoder().encode(v).length > 16384,
      ))
  )
    throw Error(
      "Use up to 10,000 manual payloads, each at most 16 KB. Import a file for larger lists.",
    );
  if (
    config.source.kind === "numbers" &&
    (!Number.isInteger(config.source.pad) || config.source.pad < 0 || config.source.pad > 32)
  )
    throw Error("Number padding must be between 0 and 32.");
  const count = sourceCount(config.source);
  if (!Number.isInteger(count) || count < 0 || count > 1000000)
    throw Error("Invalid payload count.");
  if (new TextEncoder().encode(JSON.stringify(config)).length > 2000000)
    throw Error("Configuration exceeds 2 MB.");
  if (requirePosition) {
    if (positionCount(config.request) !== 1)
      throw Error("Mark exactly one payload position with §value§.");
    if (count <= config.start) throw Error("The source has no payloads at this starting offset.");
  }
  return Math.min(config.limit, Math.max(0, count - config.start));
}
