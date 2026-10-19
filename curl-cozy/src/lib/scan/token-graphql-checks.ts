import type { ScanCheck, ScanCheckContext, Exchange } from "./types";
import { compareResponses } from "../response-diff";
import { withHeader } from "./parameters";
import { withoutCredentials } from "./http-checks";
import { ok, text, h, result, observation } from "./extended-checks";
const success = (x: Exchange) => ok(x) && x.response!.status >= 200 && x.response!.status < 300;
const same = (a: Exchange, b: Exchange, ctx: ScanCheckContext) => {
  if (!ok(a) || !ok(b)) return false;
  const d = compareResponses(a.response!, b.response!, ctx.diffOptions);
  return !d.statusChanged && !d.bodyChanged;
};
function decode(part: string): Record<string, unknown> {
  if (part.length > 12000 || !/^[\w-]+$/.test(part)) throw Error("Invalid JWT segment");
  const bytes = Uint8Array.from(atob(part.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0),
  );
  const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw Error("Invalid JWT JSON");
  return value as Record<string, unknown>;
}
const encode = (value: unknown) =>
  btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(value))))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
export const jwtSignature: ScanCheck = {
  id: "jwt-signature",
  name: "JWT signature verification",
  active: true,
  perParameter: false,
  async run(ctx) {
    const auth = Object.entries(ctx.request.headers).find(
      ([k]) => k.toLowerCase() === "authorization",
    )?.[1];
    const token = auth?.match(/^Bearer ([\w-]+\.[\w-]+\.[\w-]+)$/i)?.[1];
    if (!token) return result("A signed compact JWT in Authorization: Bearer is required.", true);
    const [head, payload, signature] = token.split(".") as [string, string, string];
    let header: Record<string, unknown>;
    try {
      header = decode(head);
      decode(payload);
    } catch {
      return result("JWT JSON is malformed or exceeds limits.", true);
    }
    if (typeof header["alg"] !== "string" || header["alg"].toLowerCase() === "none")
      return result("A signed JWT baseline is required.", true);
    if (!ctx.stable || !ctx.baselines.every(success))
      return result("Stable successful JWT baselines required.", true);
    const clean = withoutCredentials(ctx.request).request;
    const original = withHeader(clean, "Authorization", `Bearer ${token}`);
    const restored = await ctx.probe(original, "JWT isolated original token control");
    const anonymous = await ctx.probe(clean, "JWT anonymous control");
    const invalid = await ctx.probe(
      withHeader(clean, "Authorization", `Bearer ${ctx.nonce()}`),
      "JWT malformed token control",
    );
    if (
      !same(restored, ctx.baselines[0]!, ctx) ||
      ![anonymous, invalid].every((x) => ok(x) && [401, 403].includes(x.response!.status))
    )
      return result(
        "JWT isolation or denied anonymous/invalid-token controls failed; public responses are not signature bypass evidence.",
        true,
      );
    const findings = [];
    for (const mode of ["invalid-signature", "alg-none", "missing-signature"] as const) {
      const rows: Exchange[] = [];
      for (let i = 0; i < 2; i++) {
        // Change a significant signature byte, never only unused base64 padding bits.
        const bad =
          (i === 0 ? (signature[0] === "A" ? "B" : "A") : signature[0] === "C" ? "D" : "C") +
          signature.slice(1);
        const modified =
          mode === "invalid-signature"
            ? `${head}.${payload}.${bad}`
            : mode === "alg-none"
              ? `${encode({ ...header, alg: "none" })}.${payload}.`
              : `${head}.${payload}.`;
        rows.push(
          await ctx.probe(
            withHeader(clean, "Authorization", `Bearer ${modified}`),
            `JWT ${mode} ${i + 1}`,
          ),
        );
      }
      const restore = await ctx.probe(original, "JWT original signature restore");
      if (rows.every((x) => success(x) && same(x, restored, ctx)) && same(restore, restored, ctx))
        findings.push(
          ...observation(
            `JWT accepted with ${mode}`,
            "Modified JWTs returned the authenticated response twice while anonymous and malformed-token controls were denied. Claims were preserved; inspect protected data and token validation. This does not establish role escalation.",
            [...ctx.baselines, restored, anonymous, invalid, ...rows, restore],
            [`Algorithm: ${header["alg"]}; variant: ${mode}; JWT claims unchanged`],
            "high",
          ).findings,
        );
    }
    return { findings, message: "JWT signature mutation and denial controls completed." };
  },
};
function graphRequest(ctx: ScanCheckContext, query: string, batch = false) {
  const request = structuredClone(ctx.request);
  const url = new URL(request.url);
  if (request.method === "GET" && url.searchParams.has("query") && !batch) {
    url.searchParams.set("query", query);
    for (const key of ["variables", "operationName", "extensions"]) url.searchParams.delete(key);
    request.url = url.href;
    return request;
  }
  if (request.method !== "POST") return undefined;
  let detected = h(ctx.baselines[0]!, "content-type").includes("graphql");
  const contentType =
    Object.entries(request.headers).find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "";
  try {
    const value = JSON.parse(request.body);
    detected ||=
      typeof value?.query === "string" ||
      (Array.isArray(value) && value.some((x) => typeof x?.query === "string"));
  } catch {
    /* application/graphql below */
  }
  if (!detected && !contentType.toLowerCase().includes("application/graphql")) return undefined;
  // All active operations are small read-only queries, including when the captured operation was a mutation.
  const operation = { query };
  request.body = JSON.stringify(batch ? [operation, operation] : operation);
  return withHeader(request, "Content-Type", "application/json");
}
function json(x: Exchange): any {
  if (!success(x)) return undefined;
  try {
    return JSON.parse(text(x));
  } catch {
    return undefined;
  }
}
export const graphqlIntrospection: ScanCheck = {
  id: "graphql-introspection",
  name: "GraphQL schema introspection",
  active: true,
  perParameter: false,
  async run(ctx) {
    const query =
      "query SlurpIntrospection { __schema { queryType { name } mutationType { name } } }";
    const request = graphRequest(ctx, query);
    if (!request)
      return result(
        "A captured GraphQL GET query, JSON POST or application/graphql POST is required.",
        true,
      );
    const control = graphRequest(ctx, `query SlurpControl { ${ctx.nonce()} }`)!;
    const a = await ctx.probe(request, "GraphQL bounded schema introspection");
    const negative = await ctx.probe(control, "GraphQL unknown field control");
    const b = await ctx.probe(request, "GraphQL introspection repeat");
    const name = json(a)?.data?.__schema?.queryType?.name;
    if (
      typeof name !== "string" ||
      !name ||
      name !== json(b)?.data?.__schema?.queryType?.name ||
      !Array.isArray(json(negative)?.errors) ||
      json(negative).errors.length === 0 ||
      json(negative)?.data?.__schema
    )
      return result(
        "Repeated schema data with GraphQL error control not observed.",
        ![a, negative, b].every(ok),
      );
    return observation(
      "GraphQL schema introspection enabled",
      "Two bounded read-only introspection operations exposed the root type names; an unknown-field control produced GraphQL errors. Introspection can be intentional and is not an authentication bypass.",
      [a, negative, b],
      [`Root query type: ${name}`],
      "info",
    );
  },
};
export const graphqlBatch: ScanCheck = {
  id: "graphql-batching",
  name: "GraphQL batch operation policy",
  active: true,
  perParameter: false,
  async run(ctx) {
    const marker = ctx.nonce();
    const query = `query SlurpBatch { ${marker}: __typename }`;
    const batch = graphRequest(ctx, query, true),
      single = graphRequest(ctx, query);
    if (!batch || !single) return result("GraphQL JSON POST is required for batch checks.", true);
    const a = await ctx.probe(single, "GraphQL single operation control");
    const b = await ctx.probe(batch, "GraphQL two-operation batch");
    const c = await ctx.probe(batch, "GraphQL batch repeat");
    const typename = json(a)?.data?.[marker];
    if (
      typeof typename !== "string" ||
      ![b, c].every((x) => {
        const v = json(x);
        return (
          Array.isArray(v) &&
          v.length === 2 &&
          v.every((y) => y?.data?.[marker] === typename && !y.errors)
        );
      })
    )
      return result("Two-operation batch execution not reproduced.", ![a, b, c].every(ok));
    return observation(
      "GraphQL accepts multiple operations in one HTTP request",
      "A two-operation read-only batch executed twice and matched the single-operation control. This reports batching capability; rate-limit bypass and denial of service were not tested.",
      [a, b, c],
      ["Two __typename operations per batch; no depth or load testing"],
      "info",
    );
  },
};
export const tokenGraphqlChecks = [jwtSignature, graphqlIntrospection, graphqlBatch];
