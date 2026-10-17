import type { HttpRequest } from "./traffic";
import type { HeldItem } from "./api";
import { parseHeld } from "./intercept";

/** POSIX shell quoting: substitutions and single quotes stay literal. */
export function shellQuote(value: string): string {
  if (value.includes("\0")) throw new Error("NUL bytes cannot be represented in a shell command.");
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

export function toCurl(request: HttpRequest): string {
  const url = new URL(request.url);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Use an HTTP or HTTPS URL.");
  const args = ["curl", "--globoff", "--path-as-is", "--url", shellQuote(request.url)];
  for (const [name, value] of Object.entries(request.headers)) {
    if (
      /^(content-length|connection|transfer-encoding|proxy-connection|proxy-authorization|accept-encoding)$/i.test(
        name,
      )
    )
      continue;
    args.push("--header", shellQuote(`${name}: ${value}`));
  }
  if (request.body) args.push("--data-raw", shellQuote(request.body));
  if (request.method.toUpperCase() === "HEAD") args.push("--head");
  else args.push("--request", shellQuote(request.method));
  return args.join(" ");
}

/** Use request drafts, and the originating request when inspecting a held response. */
export function requestFromHeld(item: HeldItem, draft?: string): HttpRequest {
  if (item.phase === "response" || item.websocket) {
    if (!item.request || item.request.body === null)
      throw new Error("The original request body is unavailable or binary.");
    return {
      ...item.request,
      headers: Object.fromEntries(item.request.headers),
      body: item.websocket ? (item.websocket.text ?? item.websocket.hex) : item.request.body,
    };
  }
  if (item.body === null)
    throw new Error("Binary or oversized bodies cannot be copied as a text request.");
  const edit = draft === undefined ? undefined : parseHeld(item, draft);
  const url = new URL(item.url);
  const path = edit?.path ?? item.path;
  // Concatenate with the original origin: a path beginning // must not change the target host.
  return {
    method: edit?.method ?? item.method,
    url: `${url.origin}${path}`,
    headers: Object.fromEntries(edit?.headers ?? item.headers),
    body: edit?.body ?? item.body,
  };
}
