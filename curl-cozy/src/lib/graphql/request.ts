import type { HttpRequest } from "@/lib/traffic";

export type GraphqlDraft = {
  endpoint: string;
  headers: Record<string, string>;
  query: string;
  variables: string;
  operationName: string;
};

const HOP = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "accept-encoding",
  "expect",
  "keep-alive",
]);

/** `Name: value` lines to a header map (invalid lines are reported). */
export function parseHeaderLines(text: string): {
  headers: Record<string, string>;
  invalid: string[];
} {
  const headers: Record<string, string> = {};
  const invalid: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const colon = line.indexOf(":");
    const name = colon > 0 ? line.slice(0, colon).trim() : "";
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) invalid.push(line);
    else headers[name] = line.slice(colon + 1).trim();
  }
  return { headers, invalid };
}

export const formatHeaderLines = (headers: Record<string, string>) =>
  Object.entries(headers)
    .map(([name, value]) => `${name}: ${value}`)
    .join("\n");

/** The first operation name declared in the document (used for `operationName`). */
export function operationNames(query: string): string[] {
  const names: string[] = [];
  for (const match of query
    .replace(/#[^\n]*/g, "")
    .matchAll(/(?:^|[\s}])(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)/g))
    names.push(match[2]!);
  return names;
}

/** JSON variables text to an object; empty means none. */
export function parseVariables(text: string): Record<string, unknown> | undefined {
  if (!text.trim()) return undefined;
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Variables must be a JSON object.");
  return value as Record<string, unknown>;
}

/** The HTTP request that sends the draft: a JSON POST, the form every GraphQL server accepts. */
export function buildGraphqlRequest(draft: GraphqlDraft): HttpRequest {
  const url = new URL(draft.endpoint);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Use an HTTP(S) endpoint URL.");
  if (!draft.query.trim()) throw new Error("Write a query first.");
  const variables = parseVariables(draft.variables);
  const names = operationNames(draft.query);
  const operationName = draft.operationName.trim() || (names.length > 1 ? undefined : names[0]);
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(draft.headers))
    if (!HOP.has(name.toLowerCase()) && name.toLowerCase() !== "content-type")
      headers[name] = value;
  headers["Content-Type"] = "application/json";
  if (!Object.keys(headers).some((n) => n.toLowerCase() === "accept"))
    headers["Accept"] = "application/json";
  const body = {
    query: draft.query,
    ...(variables ? { variables } : {}),
    ...(operationName ? { operationName } : {}),
  };
  return { method: "POST", url: url.href, headers, body: JSON.stringify(body) };
}

export type CapturedGraphql = {
  draft: Partial<GraphqlDraft> & { endpoint: string; headers: Record<string, string> };
  isGraphql: boolean;
};

/** Prefill the editor from a captured request: GraphQL JSON POST (single or batched), GET `?query=`, or application/graphql. */
export function fromCapturedRequest(request: HttpRequest): CapturedGraphql {
  const url = new URL(request.url);
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(request.headers))
    if (!HOP.has(name.toLowerCase()) && name.toLowerCase() !== "content-type")
      headers[name] = value;
  const contentType =
    Object.entries(request.headers)
      .find(([n]) => n.toLowerCase() === "content-type")?.[1]
      ?.toLowerCase() ?? "";
  const take = (value: unknown): Partial<GraphqlDraft> | undefined => {
    const item = (Array.isArray(value) ? value[0] : value) as Record<string, unknown> | undefined;
    if (!item || typeof item !== "object" || typeof item["query"] !== "string") return undefined;
    const variables = item["variables"];
    return {
      query: item["query"],
      variables:
        variables && typeof variables === "object" ? JSON.stringify(variables, null, 2) : "",
      operationName: typeof item["operationName"] === "string" ? item["operationName"] : "",
    };
  };
  if (request.method.toUpperCase() === "GET" && url.searchParams.has("query")) {
    let variables = "";
    try {
      const raw = url.searchParams.get("variables");
      if (raw) variables = JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      /* keep empty */
    }
    const query = url.searchParams.get("query") ?? "";
    for (const key of ["query", "variables", "operationName", "extensions"])
      url.searchParams.delete(key);
    return {
      draft: {
        endpoint: url.href,
        headers,
        query,
        variables,
        operationName: url.searchParams.get("operationName") ?? "",
      },
      isGraphql: true,
    };
  }
  let parsed: Partial<GraphqlDraft> | undefined;
  try {
    parsed = take(JSON.parse(request.body));
  } catch {
    parsed = undefined;
  }
  if (!parsed && contentType.includes("application/graphql") && request.body.trim())
    parsed = { query: request.body, variables: "", operationName: "" };
  const likelyEndpoint = /graphql|gql/i.test(url.pathname) || contentType.includes("graphql");
  return {
    draft: { endpoint: url.href, headers, ...(parsed ?? {}) },
    isGraphql: Boolean(parsed) || likelyEndpoint,
  };
}

/** Hands a request from History to the GraphQL page, which reads it once on load. */
const SEED_KEY = "slurp-graphql-seed";
export const SEED_EVENT = "slurp-graphql-seed";
export function setGraphqlSeed(request: HttpRequest) {
  try {
    sessionStorage.setItem(SEED_KEY, JSON.stringify(request));
  } catch {
    /* the page opens empty */
  }
  // The page may already be open (the request was still loading when it opened).
  if (typeof window !== "undefined") window.dispatchEvent(new Event(SEED_EVENT));
}
export function takeGraphqlSeed(): HttpRequest | undefined {
  try {
    const raw = sessionStorage.getItem(SEED_KEY);
    sessionStorage.removeItem(SEED_KEY);
    return raw ? (JSON.parse(raw) as HttpRequest) : undefined;
  } catch {
    return undefined;
  }
}
