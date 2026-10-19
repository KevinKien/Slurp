import { expect, it } from "vitest";
import { httpChecks, withoutCredentials } from "../lib/scan/http-checks";
import { traversal, openRedirect } from "../lib/scan/extended-checks";
import type { ScanCheckContext, Exchange } from "../lib/scan/types";
const request = {
  method: "GET",
  url: "https://example.test/api?q=2",
  headers: { Authorization: "Bearer private", Cookie: "sid=private" },
  body: "",
};
let next = 0;
function response(
  body = "allowed",
  status = 200,
  headers: Record<string, string> = {},
  duration = 20,
): Exchange {
  return {
    response: { status, responseHeaders: headers, responseBody: body, duration, size: body.length },
    evidence: {
      id: `e${++next}`,
      label: "fixture",
      timestamp: new Date().toISOString(),
      request,
      setCookies: [],
      duration,
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
    parameter: { kind: "query", name: "q", occurrence: 0 },
    probe,
    nonce: () => `marker${++next}`,
  };
}
const check = (id: string) => httpChecks.find((x) => x.id === id)!;
it("SQL boolean requires repeated true/false differences and a restored original", async () => {
  const ctx = context(async (r) =>
    response(new URL(r.url).searchParams.get("q")!.includes("137=149") ? "empty" : "allowed"),
  );
  expect((await check("sql-boolean").run(ctx)).findings).toHaveLength(1);
  ctx.probe = async () => response("allowed");
  expect((await check("sql-boolean").run(ctx)).findings).toHaveLength(0);
  ctx.probe = async (r) => response(new URL(r.url).searchParams.get("q") ?? "");
  expect((await check("sql-boolean").run(ctx)).findings).toHaveLength(0);
});
it("SQL timing needs two delays and stable zero-delay/original controls", async () => {
  const ctx = context(async (r) =>
    response(
      "allowed",
      200,
      {},
      new URL(r.url).searchParams.get("q")!.includes("SLEEP(2)") ? 2020 : 20,
    ),
  );
  const output = await check("sql-time").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.status).toBe("needs_review");
  ctx.probe = async () => response("allowed", 200, {}, 2020);
  expect((await check("sql-time").run(ctx)).findings).toHaveLength(0);
});
it("SQL timeouts and timing jitter remain inconclusive", async () => {
  const ctx = context(async () => ({ evidence: response().evidence }));
  expect((await check("sql-time").run(ctx)).inconclusive).toBe(true);
  ctx.baselines = [response("allowed", 200, {}, 20), response("allowed", 200, {}, 400)];
  expect((await check("sql-time").run(ctx)).inconclusive).toBe(true);
});
it("CRLF requires actual independently controlled response headers, not reflected text", async () => {
  const ctx = context(async (r) => {
    const q = new URL(r.url).searchParams.get("q")!;
    return response(q, 200, q.includes("\r\n") ? { "x-slurp-probe": q.split(": ")[1]! } : {});
  });
  expect((await check("header-injection").run(ctx)).findings).toHaveLength(1);
  ctx.probe = async (r) => response(new URL(r.url).searchParams.get("q")!);
  expect((await check("header-injection").run(ctx)).findings).toHaveLength(0);
});
it("credential stripping preserves signed query bytes, duplicates and request bodies", () => {
  const original = {
    ...request,
    url: "https://example.test/api?sig=%2f%20&token=secret&q=a+b&q=2#f",
    headers: {
      AUTHORIZATION: "Bearer private",
      Cookie: "sid=private",
      "X-API-Key": "private",
      Accept: "application/json",
    },
    body: '{"token":"body-value"}',
  };
  const clean = withoutCredentials(original);
  expect(clean.removed).toBe(4);
  expect(clean.request.headers).toEqual({ Accept: "application/json" });
  expect(clean.request.url).toBe("https://example.test/api?sig=%2f%20&q=a+b&q=2#f");
  expect(clean.request.body).toBe(original.body);
  expect(original.headers.Cookie).toContain("private");
});
it("anonymous audit compares response content and does not treat every 200 as a match", async () => {
  const ctx = context(async () => response());
  expect((await check("auth-access").run(ctx)).findings).toHaveLength(1);
  ctx.probe = async (r) =>
    r.headers["Authorization"] === "Bearer private" ? response() : response("login page");
  expect((await check("auth-access").run(ctx)).findings).toHaveLength(0);
  ctx.request = { ...request, headers: {} };
  expect((await check("auth-access").run(ctx)).inconclusive).toBe(true);
});
it("Referer access needs successful repeats plus denied negative/original controls", async () => {
  const ctx = context(async (r) =>
    r.headers["Referer"] === "https://example.test/"
      ? response("protected")
      : response("denied", 403),
  );
  ctx.baselines = [response("denied", 403), response("denied", 403)];
  expect((await check("referer-access").run(ctx)).findings).toHaveLength(1);
  ctx.probe = async () => response("public");
  expect((await check("referer-access").run(ctx)).findings).toHaveLength(0);
});
it("client IP checks use sender-supported headers and compare against a non-loopback control", async () => {
  const seen: string[] = [];
  const ctx = context(async (r) => {
    seen.push(...Object.keys(r.headers));
    return Object.entries(r.headers).some(([k, v]) => k === "X-Real-IP" && v === "127.0.0.1")
      ? response("protected")
      : response("denied", 403);
  });
  ctx.baselines = [response("denied", 403), response("denied", 403)];
  expect((await check("client-ip").run(ctx)).findings).toHaveLength(1);
  expect(seen.some((x) => x.toLowerCase().startsWith("x-forwarded-"))).toBe(false);
});
it("routing checks report header influence with repeated missing-path controls", async () => {
  const ctx = context(async (r) =>
    Object.entries(r.headers).some(
      ([k, v]) => /X-(Original|Rewrite)-URL/.test(k) && v.startsWith("/slurp-missing-"),
    )
      ? response("missing", 404)
      : response(),
  );
  const output = await check("url-override").run(ctx);
  expect(output.findings.length).toBeGreaterThan(0);
  expect(output.findings[0]?.summary).toContain("not proof of authorization bypass");
});
it("method audit strips credentials, never writes PUT and requires a TRACE request line", async () => {
  const seen: string[] = [];
  const ctx = context(async (r) => {
    seen.push(r.method);
    expect(r.headers["Authorization"]).toBeUndefined();
    expect(r.headers["Cookie"]).toBeUndefined();
    return r.method === "OPTIONS"
      ? response("", 200, { allow: "GET, PUT, OPTIONS, TRACE" })
      : response(`TRACE /api HTTP/1.1\r\nX-Slurp-Probe: ${r.headers["X-Slurp-Probe"]}\r\n`);
  });
  const output = await check("http-methods").run(ctx);
  expect(output.findings).toHaveLength(2);
  expect(seen).toEqual(["OPTIONS", "TRACE", "TRACE"]);
  ctx.probe = async (r) =>
    response(`ordinary reflection X-Slurp-Probe: ${r.headers["X-Slurp-Probe"]}`);
  expect((await check("http-methods").run(ctx)).findings).toHaveLength(0);
});
it("protocol-relative redirect is tested after an absolute URL is rejected", async () => {
  const ctx = context(async (r) => {
    const value = new URL(r.url).searchParams.get("q")!;
    return value.startsWith("//") ? response("", 302, { location: value }) : response();
  });
  expect((await openRedirect.run(ctx)).findings).toHaveLength(1);
});
it("encoded traversal still needs a file signature absent from the missing-file control", async () => {
  const ctx = context(async (r) =>
    new URL(r.url).searchParams.get("q")!.startsWith("%2e")
      ? response("root:x:0:0:root:/root:/bin/bash")
      : response("missing", 404),
  );
  expect((await traversal.run(ctx)).findings).toHaveLength(1);
});
it("wildcard CORS is a reviewable configuration observation, never a credentialed bypass claim", async () => {
  const { getScanCheck } = await import("../lib/scan/checks");
  const ctx = context(async () =>
    response("public", 200, {
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "true",
    }),
  );
  const output = await getScanCheck("cors").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.severity).toBe("low");
  expect(output.findings[0]?.status).toBe("needs_review");
  expect(output.findings[0]?.summary).toContain("reject wildcard");
});
it("recognizes the usual Windows INI section order only for traversal probes", async () => {
  const ctx = context(async (r) =>
    new URL(r.url).searchParams.get("q")!.includes("Windows")
      ? response("[fonts]\r\n[extensions]\r\n[mci extensions]\r\n")
      : response("missing", 404),
  );
  expect((await traversal.run(ctx)).findings).toHaveLength(1);
});

it("SQL boolean also tests OR predicates for empty numeric parameters and reflected fields", async () => {
  const html = (v: string, content: string) =>
    `<input name="min_price" value="${v}"><p>${content}</p>`;
  const ctx = context(async (r) => {
    const v = new URL(r.url).searchParams.get("min_price")!;
    return response(html(v, /0 OR (7=7|9=9)$/.test(v) ? "all products" : "products"));
  });
  ctx.request = { ...request, url: "https://example.test/products?min_price=" };
  ctx.parameter = { kind: "query", name: "min_price", occurrence: 0 };
  ctx.baselines = [response(html("", "products")), response(html("", "products"))];
  expect((await check("sql-boolean").run(ctx)).findings[0]?.title).toContain(
    "repeated boolean differential",
  );
});
