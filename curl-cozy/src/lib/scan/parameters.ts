import type { HttpRequest } from "../traffic";
import type { ScanParameter } from "./types";
export function parameterKey(p: ScanParameter) {
  return p.kind !== "json" ? `${p.kind}:${p.name}:${p.occurrence}` : `json:${p.pointer}`;
}
function parts(pointer: string) {
  if (!pointer.startsWith("/") || pointer.length > 1000 || /~(?![01])/u.test(pointer))
    throw Error("Use an RFC 6901 JSON pointer.");
  return pointer
    .slice(1)
    .split("/")
    .map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
}
function mutateValue(
  request: HttpRequest,
  parameter: ScanParameter,
  value: string | number | Record<string, string>,
): HttpRequest {
  if (typeof value === "object" && parameter.kind !== "json")
    throw Error("Objects require a JSON parameter.");
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
      return raw + "=" + encodeURIComponent(value as string);
    });
    if (!found) throw Error("Query parameter not found.");
    result.url = result.url.slice(0, question + 1) + next.join("&") + result.url.slice(end);
    return result;
  }
  if (parameter.kind === "form") {
    if (!isFormRequest(request)) throw Error("Form-urlencoded body required.");
    if (!parameter.name || !Number.isInteger(parameter.occurrence) || parameter.occurrence < 0)
      throw Error("Invalid form parameter.");
    let occurrence = 0,
      found = false;
    result.body = request.body
      .split("&")
      .map((segment) => {
        const equal = segment.indexOf("="),
          raw = equal < 0 ? segment : segment.slice(0, equal);
        const name = decodeURIComponent(raw.replace(/\+/g, " "));
        if (name !== parameter.name || occurrence++ !== parameter.occurrence) return segment;
        found = true;
        return raw + "=" + encodeURIComponent(value as string);
      })
      .join("&");
    if (!found) throw Error("Form parameter not found.");
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

/** Read the explicitly selected scalar without changing the captured request. */
export function parameterValue(request: HttpRequest, parameter: ScanParameter): string {
  if (parameter.kind === "query")
    return new URL(request.url).searchParams.getAll(parameter.name)[parameter.occurrence] ?? "";
  if (parameter.kind === "form") {
    if (!isFormRequest(request)) throw Error("Form-urlencoded body required.");
    return new URLSearchParams(request.body).getAll(parameter.name)[parameter.occurrence] ?? "";
  }
  let node: unknown = JSON.parse(request.body);
  for (const key of parts(parameter.pointer)) {
    if (!node || typeof node !== "object" || !Object.hasOwn(node, key))
      throw Error("JSON parameter not found.");
    node = (node as Record<string, unknown>)[key];
  }
  return node !== null && typeof node === "object" ? JSON.stringify(node) : String(node ?? "");
}

export function isFormRequest(request: HttpRequest): boolean {
  return Object.entries(request.headers).some(
    ([name, value]) =>
      name.toLowerCase() === "content-type" &&
      value.split(";")[0]!.trim().toLowerCase() === "application/x-www-form-urlencoded",
  );
}

export function mutateParameter(
  request: HttpRequest,
  parameter: ScanParameter,
  value: string,
): HttpRequest {
  return mutateValue(request, parameter, value);
}
/** Object injection is restricted to explicitly selected JSON scalars. */
export function mutateJsonOperator(
  request: HttpRequest,
  parameter: ScanParameter,
  value: Record<string, string>,
): HttpRequest {
  if (parameter.kind !== "json") throw Error("JSON scalar parameter required.");
  return mutateValue(request, parameter, value);
}

export function mutateNumber(
  request: HttpRequest,
  parameter: ScanParameter,
  value: number,
): HttpRequest {
  if (!Number.isFinite(value)) throw Error("Finite numeric value required.");
  if (parameter.kind !== "json") return mutateValue(request, parameter, String(value));
  let scalar: unknown = JSON.parse(request.body);
  for (const part of parts(parameter.pointer)) {
    if (!scalar || typeof scalar !== "object" || !Object.hasOwn(scalar, part))
      throw Error("JSON parameter not found.");
    scalar = (scalar as Record<string, unknown>)[part];
  }
  if (typeof scalar !== "string" && typeof scalar !== "number")
    throw Error("Numeric scalar required.");
  return mutateValue(request, parameter, typeof scalar === "string" ? String(value) : value);
}
