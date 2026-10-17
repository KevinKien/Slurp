import { methods, type HttpRequest } from "./traffic";
import { variableName, type ReplayVariables } from "./replay-features";
export const MAX_POSTMAN_BYTES = 10_000_000;
export interface PostmanRequest {
  id: number;
  name: string;
  request: HttpRequest | null;
  warnings: string[];
  scripts: string[];
}
export interface PostmanImport {
  name: string;
  requests: PostmanRequest[];
  variables: ReplayVariables;
  warnings: string[];
}
const record = (v: unknown): Record<string, unknown> =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
const text = (v: unknown) => (typeof v === "string" ? v : "");
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
function scriptPreview(scripts: string[]): string[] {
  if (!scripts.length) return [];
  let preview = "";
  for (const script of scripts) {
    const next = (preview ? "\n\n" : "") + script;
    const remaining = 32000 - preview.length;
    preview += next.slice(0, remaining);
    if (next.length > remaining) return [preview + "\n[Preview truncated]"];
  }
  return [preview];
}
function readVariables(raw: unknown, warnings: string[]): ReplayVariables {
  const entries: [string, string][] = [];
  for (const value of list(raw)) {
    const row = record(value);
    if (row["disabled"] === true || row["enabled"] === false) continue;
    const key = text(row["key"]),
      valueText =
        typeof row["value"] === "string"
          ? row["value"]
          : typeof row["value"] === "number" || typeof row["value"] === "boolean"
            ? String(row["value"])
            : null;
    if (
      !variableName.test(key) ||
      valueText === null ||
      new TextEncoder().encode(valueText).length > 64000
    ) {
      warnings.push(`Skipped invalid or oversized variable: ${key || "(unnamed)"}`);
      continue;
    }
    entries.push([key, valueText]);
  }
  const result = Object.fromEntries(entries);
  if (Object.keys(result).length > 100) throw Error("A maximum of 100 variables can be imported.");
  return result;
}
export function parsePostmanEnvironment(source: string): {
  variables: ReplayVariables;
  warnings: string[];
} {
  const doc = parseJSON(source),
    warnings: string[] = [];
  if (!Array.isArray(doc["values"]))
    throw Error("Expected a Postman Environment JSON file with a values array.");
  return { variables: readVariables(doc["values"], warnings), warnings };
}
function parseJSON(source: string) {
  if (new TextEncoder().encode(source).length > MAX_POSTMAN_BYTES)
    throw Error("File exceeds the 10 MB limit.");
  let raw: unknown;
  try {
    raw = JSON.parse(source);
  } catch {
    throw Error("File is not valid JSON.");
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw Error("Expected a JSON object.");
  return record(raw);
}
export function parsePostmanCollection(source: string): PostmanImport {
  const doc = parseJSON(source),
    info = record(doc["info"]),
    schema = text(info["schema"]);
  if (
    !/^https?:\/\/schema\.getpostman\.com\/json\/collection\/v2\.(0|1)\.0\/collection\.json$/.test(
      schema,
    ) ||
    !Array.isArray(doc["item"])
  )
    throw Error("Expected a Postman Collection v2.0 or v2.1 JSON file.");
  const warnings: string[] = [],
    requests: PostmanRequest[] = [];
  const variables = readVariables(doc["variable"], warnings);
  let nodes = 0;
  const events = (raw: unknown) =>
    list(raw).flatMap((e) => {
      const event = record(e),
        script = record(event["script"]),
        exec = script["exec"];
      const code = Array.isArray(exec) ? exec.map(text).join("\n") : text(exec);
      return code.trim()
        ? [
            `${text(event["listen"]) || "script"}:\n${code.slice(0, 32000)}${code.length > 32000 ? "\n[Preview truncated]" : ""}`,
          ]
        : [];
    });
  const visit = (
    items: unknown[],
    path: string[],
    auth: unknown,
    inheritedScripts: string[],
    depth: number,
  ) => {
    if (depth > 20) throw Error("Collection nesting exceeds 20 folders.");
    for (const raw of items) {
      if (++nodes > 5000) throw Error("Collection exceeds 5,000 items.");
      const item = record(raw),
        name = (text(item["name"]) || "Untitled request").slice(0, 200),
        parts = [...path, name];
      const scripts = [...inheritedScripts, ...events(item["event"])];
      const nextAuth = item["auth"] ?? auth;
      if (Array.isArray(item["item"])) {
        if (list(item["variable"]).length)
          warnings.push(`Folder variables are not imported: ${parts.join(" / ")}`);
        visit(item["item"], parts, nextAuth, scripts, depth + 1);
        continue;
      }
      if (!Object.hasOwn(item, "request")) continue;
      if (requests.length >= 500)
        throw Error("Collection exceeds 500 requests. Split the collection into smaller files.");
      const issues: string[] = [],
        errors: string[] = [];
      const source = item["request"],
        req = typeof source === "string" ? { url: source, method: "GET" } : record(source);
      const method = (text(req["method"]) || "GET").toUpperCase();
      if (!methods.includes(method)) errors.push(`Unsupported method: ${method}`);
      const urlData = req["url"],
        urlObject = record(urlData);
      let url = typeof urlData === "string" ? urlData : text(urlObject["raw"]);
      if (!url) {
        const host = Array.isArray(urlObject["host"])
          ? urlObject["host"].map(text).join(".")
          : text(urlObject["host"]);
        const pathValue = Array.isArray(urlObject["path"])
          ? urlObject["path"].map((v) => text(record(v)["value"]) || text(v)).join("/")
          : text(urlObject["path"]);
        url = `${text(urlObject["protocol"]) || "https"}://${host}${urlObject["port"] ? ":" + text(urlObject["port"]) : ""}/${pathValue}`;
      }
      if (Array.isArray(urlObject["query"])) {
        const hash = url.indexOf("#"),
          fragment = hash < 0 ? "" : url.slice(hash),
          base = (hash < 0 ? url : url.slice(0, hash)).split("?")[0];
        const query = list(urlObject["query"])
          .map(record)
          .filter((q) => q["disabled"] !== true)
          .map(
            (q) => `${encodeURIComponent(text(q["key"]))}=${encodeURIComponent(text(q["value"]))}`,
          )
          .join("&")
          .replace(/%7B%7B(.*?)%7D%7D/gi, (m) => decodeURIComponent(m));
        url = `${base}${query ? "?" + query : ""}${fragment}`;
      }
      for (const rawVariable of list(urlObject["variable"])) {
        const variable = record(rawVariable),
          key = text(variable["key"]),
          value = text(variable["value"]);
        if (key && variable["disabled"] !== true && value)
          url = url.replace(
            new RegExp(":" + key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?=/|[?#]|$)", "g"),
            () => value,
          );
      }
      if (/\/:\w/.test(url)) errors.push("Unresolved Postman path parameters.");
      const testUrl = url
        .replace(/^\{\{[^{}]+\}\}/, "https://example.test")
        .replace(/\{\{[^{}]+\}\}/g, "example");
      try {
        const parsed = new URL(testUrl);
        if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password)
          throw Error();
      } catch {
        errors.push("Invalid HTTP(S) URL or URL contains credentials.");
      }
      if (url.length > 4096) errors.push("URL exceeds 4,096 characters.");
      const headerEntries: [string, string][] = [];
      let rawHeaders = list(req["header"]);
      if (typeof req["header"] === "string")
        rawHeaders = req["header"]
          .split(/\r?\n/)
          .filter((line) => line.trim())
          .map((line) => {
            const colon = line.indexOf(":");
            if (colon < 1) {
              errors.push("Invalid raw header line.");
              return {};
            }
            return { key: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() };
          });
      for (const rawHeader of rawHeaders) {
        const h = record(rawHeader);
        if (h["disabled"] === true) continue;
        const key = text(h["key"]),
          value = text(h["value"]);
        if (
          !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(key.replace(/\{\{[^{}]+\}\}/g, "placeholder")) ||
          /[\r\n\0]/.test(key + value)
        )
          errors.push("Invalid header.");
        if (headerEntries.some(([k]) => k.toLowerCase() === key.toLowerCase()))
          errors.push(`Duplicate header cannot be represented: ${key}`);
        headerEntries.push([key, value]);
      }
      const hasHeader = (key: string) =>
        headerEntries.some(([k]) => k.toLowerCase() === key.toLowerCase());
      const authData = record(req["auth"] ?? nextAuth),
        authType = text(authData["type"]);
      const authValues = Object.fromEntries(
        list(authData[authType])
          .map(record)
          .map((v) => [text(v["key"]), text(v["value"])]),
      );
      if (authType && authType !== "noauth" && !hasHeader("authorization")) {
        if (authType === "bearer")
          headerEntries.push(["Authorization", `Bearer ${authValues["token"] ?? ""}`]);
        else if (authType === "basic") {
          const credentials = `${authValues["username"] ?? ""}:${authValues["password"] ?? ""}`;
          if (credentials.includes("{{"))
            errors.push("Basic auth with variables requires manual conversion.");
          else {
            const bytes = new TextEncoder().encode(credentials);
            headerEntries.push([
              "Authorization",
              `Basic ${btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(""))}`,
            ]);
          }
        } else errors.push(`Unsupported authentication: ${authType}`);
      }
      const bodyData = record(req["body"]);
      let body = "";
      if (bodyData["disabled"] !== true && bodyData["mode"]) {
        if (bodyData["mode"] === "raw") {
          body = text(bodyData["raw"]);
          const language = text(record(record(bodyData["options"])["raw"])["language"]);
          const contentTypes: Record<string, string> = {
            json: "application/json",
            xml: "application/xml",
            html: "text/html",
            javascript: "application/javascript",
            text: "text/plain",
          };
          if (Object.hasOwn(contentTypes, language) && !hasHeader("content-type"))
            headerEntries.push(["Content-Type", contentTypes[language]!]);
        } else errors.push(`Unsupported body mode: ${text(bodyData["mode"])} (raw bodies only).`);
      }
      if (new TextEncoder().encode(body).length > 1_000_000) errors.push("Body exceeds 1 MB.");
      if (headerEntries.length > 200) errors.push("Request exceeds 200 headers.");
      if (["GET", "HEAD"].includes(method) && body)
        errors.push(`${method} bodies are not sent by Replay.`);
      if (scripts.length)
        issues.push(
          "Postman scripts are not converted or executed. Review the original scripts below.",
        );
      if (item["protocolProfileBehavior"] || req["protocolProfileBehavior"])
        issues.push("Postman protocol options are not imported.");
      requests.push({
        id: requests.length,
        name: parts.join(" / ").slice(0, 200),
        request: errors.length
          ? null
          : { method, url, headers: Object.fromEntries(headerEntries), body },
        warnings: [...errors, ...issues],
        scripts: scriptPreview(scripts),
      });
    }
  };
  visit(doc["item"] as unknown[], [], doc["auth"], events(doc["event"]), 0);
  if (!requests.length) throw Error("Collection contains no requests.");
  return { name: text(info["name"]) || "Postman collection", requests, variables, warnings };
}
export function missingPostmanVariables(
  requests: PostmanRequest[],
  variables: ReplayVariables,
): string[] {
  const missing = new Set<string>();
  for (const item of requests) {
    if (!item.request) continue;
    const req = item.request;
    for (const source of [req.url, req.body, ...Object.entries(req.headers).flat()])
      for (const match of source.matchAll(/\{\{\s*([^{}]+?)\s*\}\}/g))
        if (!Object.hasOwn(variables, match[1]!)) missing.add(match[1]!);
  }
  return [...missing].sort();
}
export function mergePostmanVariables(
  existing: ReplayVariables,
  incoming: ReplayVariables,
  overwrite: boolean,
): ReplayVariables {
  const merged = overwrite ? { ...existing, ...incoming } : { ...incoming, ...existing };
  if (Object.keys(merged).length > 100)
    throw Error("Import would exceed the limit of 100 workspace variables.");
  return merged;
}
