import type { HttpRequest } from "../traffic";
import type { ScanParameter } from "./types";
export function parameterKey(p: ScanParameter) {
  return p.kind === "query" ? `query:${p.name}:${p.occurrence}` : `json:${p.pointer}`;
}
function parts(pointer: string) {
  if (!pointer.startsWith("/") || pointer.length > 1000 || /~(?![01])/u.test(pointer))
    throw Error("Use an RFC 6901 JSON pointer.");
  return pointer
    .slice(1)
    .split("/")
    .map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
}
export function mutateParameter(
  request: HttpRequest,
  parameter: ScanParameter,
  value: string,
): HttpRequest {
  const result = structuredClone(request);
  if (parameter.kind === "query") {
    if (!parameter.name || !Number.isInteger(parameter.occurrence) || parameter.occurrence < 0)
      throw Error("Invalid query parameter.");
    // Preserve every unselected query segment byte-for-byte, including signatures and duplicate keys.
    const hash = result.url.indexOf("#"),
      end = hash < 0 ? result.url.length : hash,
      question = result.url.indexOf("?");
    if (question < 0 || question > end) throw Error("Query parameter not found.");
    const segments = result.url.slice(question + 1, end).split("&");
    let occurrence = 0,
      found = false;
    const next = segments.map((segment) => {
      const equal = segment.indexOf("="),
        raw = equal < 0 ? segment : segment.slice(0, equal);
      let name: string;
      try {
        name = decodeURIComponent(raw.replace(/\+/g, " "));
      } catch {
        throw Error("Malformed query encoding.");
      }
      if (name !== parameter.name || occurrence++ !== parameter.occurrence) return segment;
      found = true;
      return raw + "=" + encodeURIComponent(value);
    });
    if (!found) throw Error("Query parameter not found.");
    result.url = result.url.slice(0, question + 1) + next.join("&") + result.url.slice(end);
    return result;
  }
  const keys = parts(parameter.pointer);
  let root: unknown;
  try {
    root = JSON.parse(request.body);
  } catch {
    throw Error("JSON body required.");
  }
  let node: unknown = root;
  for (const key of keys.slice(0, -1)) {
    if (!node || typeof node !== "object" || !Object.hasOwn(node, key))
      throw Error("JSON parameter not found.");
    node = (node as Record<string, unknown>)[key];
  }
  const last = keys.at(-1)!;
  if (!node || typeof node !== "object" || !Object.hasOwn(node, last))
    throw Error("JSON parameter not found.");
  if (Array.isArray(node) && (!/^(0|[1-9]\d*)$/.test(last) || Number(last) >= node.length))
    throw Error("Invalid JSON array index.");
  if (
    typeof (node as Record<string, unknown>)[last] === "object" &&
    (node as Record<string, unknown>)[last] !== null
  )
    throw Error("Select a scalar JSON value.");
  Object.defineProperty(node, last, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
  result.body = JSON.stringify(root);
  return result;
}
export function withHeader(request: HttpRequest, name: string, value: string): HttpRequest {
  return {
    ...request,
    headers: {
      ...Object.fromEntries(
        Object.entries(request.headers).filter(([key]) => key.toLowerCase() !== name.toLowerCase()),
      ),
      [name]: value,
    },
  };
}
