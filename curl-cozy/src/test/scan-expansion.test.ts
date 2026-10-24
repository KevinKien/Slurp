import { corsTrust } from "../lib/scan/cors-trust-check";
import { expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { scanParameters } from "../lib/scan-selection";
import { mutateParameter, mutateJsonOperator, parameterValue } from "../lib/scan/parameters";
import { jwtWeakSecret } from "../lib/scan/jwt-secret-check";
import { nosqlOperators } from "../lib/scan/nosql-checks";
import { nosqlInjection } from "../lib/scan/injection-checks";
import { newScanPlan, ScanEngine } from "../lib/scan";
import type { HttpRequest } from "../lib/traffic";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";
const request: HttpRequest = {
  method: "POST",
  url: "http://localhost:8088/search?x=1",
  headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
  body: "q=first&q=a+b&sig=%2f%2F&empty=",
};
let n = 0;
function exchange(body = '{"items":[1]}', status = 200): Exchange {
  return {
    response: {
      status,
      responseBody: body,
      responseHeaders: { "content-type": "application/json" },
      duration: 1,
      size: body.length,
    },
    evidence: {
      id: `e${++n}`,
      label: "test",
      timestamp: new Date().toISOString(),
      request,
      duration: 1,
      size: body.length,
      truncated: false,
      setCookies: [],
    },
  };
}
function context(): ScanCheckContext {
  return {
    request: {
      ...request,
      headers: { "Content-Type": "application/json" },
      body: '{"email":"a+b@test.com","password":"private"}',
    },
    baselines: [exchange(), exchange()],
    stable: true,
    parameter: { kind: "json", pointer: "/email" },
    nonce: () => `nonce${++n}`,
    probe: vi.fn(async () => exchange()),
  };
}
it("discovers duplicate form fields and preserves unrelated bytes", () => {
  const p = { kind: "form" as const, name: "q", occurrence: 1 };
  expect(scanParameters(request)).toContainEqual(p);
  expect(parameterValue(request, p)).toBe("a b");
  expect(mutateParameter(request, p, "' OR 1=1").body).toBe(
    "q=first&q='%20OR%201%3D1&sig=%2f%2F&empty=",
  );
  expect(request.body).toContain("q=a+b");
  expect(() => mutateParameter(request, { ...p, occurrence: 3 }, "x")).toThrow();
  expect(() => mutateParameter({ ...request, body: "%ZZ=x" }, p, "x")).toThrow();
  expect(() => mutateParameter({ ...request, headers: {} }, p, "x")).toThrow();
});
it("runs form scanning through engine with parameter evidence", async () => {
  const plan = {
    ...newScanPlan(request),
    mode: "active" as const,
    checks: ["reflection" as const],
    allowSending: true,
    rate: 20,
    parameters: [{ kind: "form" as const, name: "q", occurrence: 1 }],
  };
  const run = await new ScanEngine(plan, {
    isCurrent: () => true,
    send: async (r) => ({
      ok: true,
      ...exchange(new URLSearchParams(r.body).getAll("q")[1]!).response!,
    }),
  }).start();
  expect(run.status).toBe("completed");
  expect(run.findings[0]?.parameter).toEqual(plan.parameters[0]);
  expect(run.evidence.every((e) => e.request.body.includes("sig=%2f%2F"))).toBe(true);
});
it("NoSQL operator detection requires repeatable exact/nonmatch pairs and scalar restore", async () => {
  const ctx = context();
  ctx.probe = vi.fn(async (r) => {
    const email = JSON.parse(r.body).email;
    const match =
      typeof email === "string"
        ? email === "a+b@test.com"
        : new RegExp(email.$regex).test("a+b@test.com");
    return match ? exchange() : exchange('{"items":[]}');
  });
  const out = await nosqlOperators.run(ctx);
  expect(out.findings[0]?.status).toBe("needs_review");
  expect(out.findings[0]?.evidenceIds).toHaveLength(7);
  ctx.probe = vi.fn(async () => exchange());
  expect((await nosqlOperators.run(ctx)).findings).toHaveLength(0);
  ctx.probe = vi.fn(async (r) => exchange(r.body));
  expect((await nosqlOperators.run(ctx)).findings).toHaveLength(0);
  ctx.probe = vi.fn(async () => exchange("error", 500));
  expect((await nosqlOperators.run(ctx)).findings).toHaveLength(0);
});
it("NoSQL rejects numeric inputs and preserves nested and prototype-named JSON keys", async () => {
  const ctx = context();
  ctx.request.body = '{"email":123}';
  expect((await nosqlOperators.run(ctx)).inconclusive).toBe(true);
  expect(ctx.probe).not.toHaveBeenCalled();
  const r = { ...ctx.request, body: '{"a/b":{"~x":"v"},"__proto__":"scalar","keep":1}' };
  const changed = mutateJsonOperator(r, { kind: "json", pointer: "/a~1b/~0x" }, { $regex: "^v$" });
  expect(JSON.parse(changed.body)["a/b"]["~x"]).toEqual({ $regex: "^v$" });
  expect(JSON.parse(changed.body).keep).toBe(1);
  const proto = mutateJsonOperator(r, { kind: "json", pointer: "/__proto__" }, { $regex: "x" });
  expect(Object.hasOwn(JSON.parse(proto.body), "__proto__")).toBe(true);
  expect(({} as Record<string, unknown>)["$regex"]).toBeUndefined();
});
it("NoSQL parser requires repeated errors and clean controls", async () => {
  const ctx = context();
  ctx.probe = vi.fn(async (r) =>
    JSON.parse(r.body).email.includes("$slurp")
      ? exchange("MongoServerError: malformed query", 500)
      : exchange(),
  );
  expect((await nosqlInjection.run(ctx)).findings).toHaveLength(1);
  ctx.probe = vi.fn(async () => exchange("MongoServerError", 500));
  expect((await nosqlInjection.run(ctx)).findings).toHaveLength(0);
});
async function jwt(secret: string, algorithm: string) {
  const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
  const enc = (value: unknown) => b64(new TextEncoder().encode(JSON.stringify(value)));
  const input = `${enc({ alg: algorithm })}.${enc({ sub: "alice" })}`;
  const hash = ({ HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" } as Record<string, string>)[
    algorithm
  ]!;
  const key = await webcrypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash },
    false,
    ["sign"],
  );
  return `${input}.${b64(new Uint8Array(await webcrypto.subtle.sign("HMAC", key, new TextEncoder().encode(input))))}`;
}
it("verifies weak JWT HMAC keys locally without disclosing keys or sending requests", async () => {
  vi.stubGlobal("crypto", webcrypto);
  try {
    for (const alg of ["HS256", "HS384", "HS512"]) {
      const ctx = context();
      ctx.request.headers = { Authorization: `Bearer ${await jwt("supersecretkey", alg)}` };
      const out = await jwtWeakSecret.run(ctx);
      expect(out.findings[0]).toMatchObject({
        status: "verified",
        confidence: "high",
        severity: "high",
      });
      expect(JSON.stringify(out)).not.toContain("supersecretkey");
      expect(ctx.probe).not.toHaveBeenCalled();
    }
    const ctx = context();
    ctx.request.headers = {
      Authorization: `Bearer ${await jwt("random-unlisted-signing-key-42918", "HS256")}`,
    };
    expect((await jwtWeakSecret.run(ctx)).findings).toHaveLength(0);
    ctx.request.headers = { Authorization: "Bearer not.valid.signature" };
    expect((await jwtWeakSecret.run(ctx)).inconclusive).toBe(true);
  } finally {
    vi.unstubAllGlobals();
  }
});

it("CORS detects null and hostname trust bypasses with preserved content and negative controls", async () => {
  const ctx = context();
  ctx.request.url = "https://api.example.test/me";
  ctx.probe = vi.fn(async (request) => {
    const x = exchange();
    const origin = request.headers["Origin"];
    if (origin === "null" || origin?.includes("api.example.test.")) {
      x.response!.responseHeaders["access-control-allow-origin"] = origin;
      x.response!.responseHeaders["access-control-allow-credentials"] = "true";
    }
    return x;
  });
  const out = await corsTrust.run(ctx);
  expect(out.findings.map((f) => f.title)).toEqual([
    "Credentialed CORS accepts null origin",
    "Credentialed CORS accepts trusted hostname prefix",
  ]);
  expect(out.findings.every((f) => f.status === "needs_review" && f.evidenceIds.length === 6)).toBe(
    true,
  );
  ctx.probe = vi.fn(async (request) => {
    const x = exchange();
    const origin = request.headers["Origin"];
    if (origin) {
      x.response!.responseHeaders["access-control-allow-origin"] = origin;
      x.response!.responseHeaders["access-control-allow-credentials"] = "true";
    }
    return x;
  });
  expect((await corsTrust.run(ctx)).findings).toHaveLength(0);
  ctx.probe = vi.fn(async () => exchange());
  expect((await corsTrust.run(ctx)).findings).toHaveLength(0);
});
it("CORS ignores reflected headers when baseline data changes and avoids IP hostname probes", async () => {
  const ctx = context();
  ctx.request.url = "http://127.0.0.1/me";
  const origins: string[] = [];
  ctx.probe = vi.fn(async (request) => {
    const origin = request.headers["Origin"] ?? "";
    origins.push(origin);
    const x = exchange(origin === "null" ? '{"login":"required"}' : '{"items":[1]}');
    if (origin === "null") {
      x.response!.responseHeaders["access-control-allow-origin"] = "null";
      x.response!.responseHeaders["access-control-allow-credentials"] = "true";
    }
    return x;
  });
  expect((await corsTrust.run(ctx)).findings).toHaveLength(0);
  expect(origins).toHaveLength(2);
  expect(origins.some((x) => x.includes("127.0.0.1"))).toBe(false);
});
