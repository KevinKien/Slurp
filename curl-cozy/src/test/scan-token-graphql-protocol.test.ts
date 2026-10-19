import { expect, it, vi } from "vitest";
import { jwtSignature, graphqlIntrospection, graphqlBatch } from "../lib/scan/token-graphql-checks";
import { httpFraming } from "../lib/scan/protocol-checks";
import { ScanEngine, newScanPlan } from "../lib/scan";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";
const encode = (x: unknown) =>
  btoa(JSON.stringify(x)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const token = `${encode({ alg: "HS256", typ: "JWT" })}.${encode({ sub: "alice", role: "user" })}.YWJjZGVmZw`;
let count = 0;
const request = {
  url: "http://localhost:8088/api/me",
  method: "GET",
  headers: { Authorization: `Bearer ${token}`, Cookie: "sid=private" },
  body: "",
};
function response(body = '{"user":"alice"}', status = 200): Exchange {
  return {
    response: { status, responseHeaders: {}, responseBody: body, duration: 1, size: body.length },
    evidence: {
      id: `e${++count}`,
      label: "fixture",
      timestamp: new Date().toISOString(),
      request,
      setCookies: [],
      duration: 1,
      size: body.length,
      truncated: false,
    },
  };
}
function context(probe: ScanCheckContext["probe"]): ScanCheckContext {
  return {
    request,
    baselines: [response(), response()],
    stable: true,
    nonce: () => `slurp${++count}`,
    probe,
  };
}
it("JWT detects modified signature acceptance only with denied controls and isolated original", async () => {
  const ctx = context(async (r) => {
    expect(r.headers).not.toHaveProperty("Cookie");
    const auth = r.headers["Authorization"] ?? "";
    return auth.startsWith("Bearer ey") ? response() : response("denied", 401);
  });
  const output = await jwtSignature.run(ctx);
  expect(output.findings.map((x) => x.title)).toContain("JWT accepted with invalid-signature");
  expect(output.findings.every((x) => x.evidenceIds.length >= 8)).toBe(true);
  ctx.probe = async (r) =>
    r.headers["Authorization"] === `Bearer ${token}` ? response() : response("denied", 401);
  expect((await jwtSignature.run(ctx)).findings).toHaveLength(0);
});
it("JWT ignores public endpoints, cookie-auth fallback and broken restoration", async () => {
  const ctx = context(async () => response());
  expect((await jwtSignature.run(ctx)).inconclusive).toBe(true);
  ctx.probe = async () => response("denied", 401);
  expect((await jwtSignature.run(ctx)).inconclusive).toBe(true);
  ctx.request = { ...request, headers: { Authorization: "Bearer not.jwt.json", Cookie: "" } };
  expect((await jwtSignature.run(ctx)).inconclusive).toBe(true);
});
function graphContext(): ScanCheckContext {
  return {
    ...context(async () => response()),
    request: {
      ...request,
      method: "POST",
      body: JSON.stringify({
        query: "mutation { deleteAccount }",
        variables: { id: "secret" },
        extensions: { persistedQuery: { hash: "private" } },
      }),
    },
  };
}
it("GraphQL introspection uses read-only operations and requires error controls", async () => {
  const ctx = graphContext();
  ctx.probe = async (r) => {
    const value = JSON.parse(r.body);
    expect(value).not.toHaveProperty("variables");
    expect(value.query).not.toContain("deleteAccount");
    return response(
      JSON.stringify(
        value.query.includes("__schema")
          ? { data: { __schema: { queryType: { name: "Query" } } } }
          : { errors: [{ message: "unknown field" }] },
      ),
    );
  };
  expect((await graphqlIntrospection.run(ctx)).findings).toHaveLength(1);
  ctx.probe = async () => response('{"data":{"__schema":{"queryType":{"name":"Query"}}}}');
  expect((await graphqlIntrospection.run(ctx)).findings).toHaveLength(0);
});
it("GraphQL batching reports capability, ignores echoed arrays and errors", async () => {
  const ctx = graphContext();
  ctx.probe = async (r) => {
    const parsed = JSON.parse(r.body);
    const op = Array.isArray(parsed) ? parsed[0] : parsed;
    const alias = op.query.match(/\{ (\w+):/)[1];
    const data = { data: { [alias]: "Query" } };
    return response(JSON.stringify(Array.isArray(parsed) ? [data, data] : data));
  };
  expect((await graphqlBatch.run(ctx)).findings[0]?.severity).toBe("info");
  ctx.probe = async (r) => response(r.body);
  expect((await graphqlBatch.run(ctx)).findings).toHaveLength(0);
});
it("GraphQL GET preserves endpoint and removes stale operation metadata", async () => {
  const ctx = graphContext();
  ctx.request = {
    ...request,
    url: "http://localhost:8088/graphql?query=old&variables=old&operationName=old&extensions=old",
    headers: {},
    body: "",
  };
  ctx.probe = async (r) => {
    const u = new URL(r.url);
    expect(u.pathname).toBe("/graphql");
    expect(u.searchParams.has("variables")).toBe(false);
    return response('{"errors":[]}');
  };
  await graphqlIntrospection.run(ctx);
  expect((await graphqlBatch.run(ctx)).inconclusive).toBe(true);
});
it("framing reports acceptance only; rejection/timeouts never prove smuggling", async () => {
  const ctx = context(async () => response());
  ctx.protocol = async () => response();
  const output = await httpFraming.run(ctx);
  expect(output.findings).toHaveLength(3);
  expect(output.findings.every((x) => x.status === "needs_review" && x.severity === "low")).toBe(
    true,
  );
  ctx.protocol = async (variant) =>
    variant === "control" || variant === "chunked" ? response() : response("bad", 400);
  expect((await httpFraming.run(ctx)).findings).toHaveLength(0);
  ctx.protocol = async () => ({ evidence: { ...response().evidence, error: "timeout" } });
  expect((await httpFraming.run(ctx)).inconclusive).toBe(true);
});
it("engine enforces framing policy, routes raw probes, strips credentials and stores wire evidence", async () => {
  const plan = {
    ...newScanPlan({ ...request, url: request.url + "?token=secret&x=1" }),
    mode: "active" as const,
    checks: ["http-framing" as const],
    allowSending: true,
    rate: 20,
    policy: {
      maxImpact: "intrusive" as const,
      allowIntrusive: true,
      includeExperimental: true,
      maxDurationMs: 30000,
      requestTimeoutMs: 1000,
    },
  };
  const protocol = vi.fn(async (input) => {
    expect(input.url).not.toContain("secret");
    return {
      ok: true as const,
      rawRequest: "GET /api/me?x=1 HTTP/1.1\r\n\r\n",
      rawResponse: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
      status: 200,
      duration: 1,
      size: 38,
    };
  });
  const deps = {
    send: vi.fn(async () => ({ ok: true as const, ...response().response! })),
    protocol,
    isCurrent: () => true,
  };
  const engine = new ScanEngine(plan, deps);
  const run = await engine.start();
  expect(protocol).toHaveBeenCalledTimes(11);
  expect(run.evidence.filter((x) => x.rawRequest)).toHaveLength(11);
  const blocked = new ScanEngine(
    { ...plan, policy: { ...plan.policy, allowIntrusive: false } },
    deps,
  );
  await blocked.start();
  expect(protocol).toHaveBeenCalledTimes(11);
});
