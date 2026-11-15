/** Defects the scan benchmark (curl-cozy/benchmark) found in the checks and the engine; see benchmark/RESULTS.md. */
import { expect, it, vi } from "vitest";
import { injectionChecks } from "../lib/scan/injection-checks";
import { sqlTime } from "../lib/scan/http-checks";
import { graphqlFieldSuggestion } from "../lib/scan/token-graphql-checks";
import { defaultScanPolicy } from "../lib/scan/registry";
import { ScanEngine, newScanPlan } from "../lib/scan";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";
import type { HttpRequest } from "../lib/traffic";

let next = 0;
function response(body = "baseline", status = 200, duration = 10): Exchange {
  return {
    response: { status, responseHeaders: {}, responseBody: body, duration, size: body.length },
    evidence: {
      id: `e${++next}`,
      label: "fixture",
      timestamp: new Date().toISOString(),
      request: { method: "GET", url: "https://example.test/", headers: {}, body: "" },
      setCookies: [],
      duration: 10,
      size: body.length,
      truncated: false,
    },
  };
}
const request: HttpRequest = {
  method: "GET",
  url: "https://example.test/api?q=original",
  headers: {},
  body: "",
};
const value = (r: HttpRequest) => r.body || new URL(r.url).searchParams.get("q")!;
function context(
  probe: (r: HttpRequest) => Exchange,
  base: HttpRequest = request,
): ScanCheckContext {
  return {
    request: base,
    stable: true,
    baselines: [response(), response()],
    parameter: { kind: "query", name: "q", occurrence: 0 },
    nonce: () => `random${++next}`,
    probe: vi.fn(async (r) => probe(r)),
  };
}
const check = (id: string) => injectionChecks.find((c) => c.id === id)!;
const UID = "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n";

it("command-bypass keeps trying evasions after a filter rejects the first payloads", async () => {
  // A blacklist that answers 400 to ';' and '|' but not to '&', a newline or a substitution.
  const ctx = context((r) => {
    const v = value(r);
    if (/[;|]/.test(v)) return response("Invalid characters", 400);
    return /^&id$/.test(v) ? response(UID) : response();
  });
  const found = await check("command-bypass").run(ctx);
  expect(found.findings).toHaveLength(1);
  expect(found.findings[0]?.title).toContain("background");
  // Everything blocked is still inconclusive, not a clean pass.
  const blocked = await check("command-bypass").run(
    context((r) =>
      value(r) === "original" || value(r).startsWith("slurp_")
        ? response()
        : response("blocked", 403),
    ),
  );
  expect(blocked.inconclusive).toBe(true);
});

it("command-injection tries the substitution style when the separator style is rejected", async () => {
  const ctx = context((r) => {
    const v = value(r);
    if (v.startsWith(";")) return response("Invalid characters", 400);
    const m = v.match(/^\$\(printf '%s%s' '([^']+)' '([^']+)'\)$/);
    return m ? response(m[1]! + m[2]!) : response();
  });
  expect((await check("command-injection").run(ctx)).findings).toHaveLength(1);
});

it("arithmetic checks try the next syntax family when the first one is a server error", async () => {
  // eval() of JavaScript: Python- and PHP-style payloads are syntax errors (500).
  const ctx = context((r) => {
    const v = value(r);
    const m = v.match(/^String\((\d+)\*(\d+)\)$/);
    if (m) return response(String(Number(m[1]) * Number(m[2])));
    return /^(print\(|echo )/.test(v) ? response("SyntaxError", 500) : response();
  });
  const found = await check("code-injection").run(ctx);
  expect(found.findings).toHaveLength(1);
  expect(found.findings[0]?.excerpts.join(" ")).toContain("JavaScript-like String");
  const allRejected = await check("code-injection").run(
    context((r) => (value(r) === "original" ? response() : response("error", 500))),
  );
  expect(allRejected.inconclusive).toBe(true);
});

it("XXE recognises file content that starts right after a tag", async () => {
  const ctx = context((r) =>
    /SYSTEM "file:\/\/\/etc\/passwd"/.test(value(r)) && !value(r).includes("&amp;")
      ? response("<echo>root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin</echo>")
      : response(),
  );
  const found = await check("xxe").run(ctx);
  expect(found.findings).toHaveLength(1);
  expect(found.findings[0]?.excerpts.join(" ")).not.toContain("root:x");
});

it("GraphQL field suggestions need an actual suggestion, not the standard validation error", async () => {
  const graphql: HttpRequest = {
    method: "POST",
    url: "https://example.test/graphql",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "{ user { id } }" }),
  };
  const answer = (message: string) => (r: HttpRequest) =>
    JSON.parse(r.body).query.includes("__typename")
      ? response(JSON.stringify({ data: { __typename: "Query" } }))
      : response(JSON.stringify({ errors: [{ message }] }));
  const standard = context(answer('Cannot query field "slurp_x" on type "Query".'), graphql);
  expect((await graphqlFieldSuggestion.run(standard)).findings).toHaveLength(0);
  const suggesting = context(
    answer('Cannot query field "slurp_x" on type "Query". Did you mean "user"?'),
    graphql,
  );
  expect((await graphqlFieldSuggestion.run(suggesting)).findings).toHaveLength(1);
});

it("url-override can reach a denied path through the origin root, and nothing else off the endpoint", async () => {
  const seen: string[] = [];
  // ACL on the received URL; the application routes on X-Original-URL.
  const send = vi.fn(async (r: HttpRequest) => {
    const url = new URL(r.url);
    seen.push(`${r.method} ${url.pathname}`);
    const header = Object.entries(r.headers).find(([n]) =>
      /^x-(original|rewrite)-url$/i.test(n),
    )?.[1];
    const body = (text: string, status = 200) => ({
      ok: true as const,
      status,
      responseHeaders: {},
      responseBody: text,
      duration: 5,
      size: text.length,
    });
    if (url.pathname.startsWith("/admin")) return body("Forbidden", 403);
    const effective = header ?? url.pathname;
    return effective.startsWith("/admin")
      ? body("admin panel")
      : effective === "/"
        ? body("home")
        : body("Not found", 404);
  });
  const plan = {
    ...newScanPlan({
      method: "GET",
      url: "https://example.test/admin/panel",
      headers: {},
      body: "",
    }),
    mode: "active" as const,
    checks: ["url-override" as const],
    allowSending: true,
    rate: 20,
    policy: { ...defaultScanPolicy },
  };
  const engine = new ScanEngine(plan, { send, isCurrent: () => true });
  await engine.start();
  const run = engine.run;
  expect(run.findings.map((f) => f.checkId)).toContain("url-override");
  expect(seen).toContain("GET /");
  expect(seen.filter((s) => !/ \/(admin\/panel|)$|slurp-missing/.test(s))).toEqual([]);
});

it("other checks still may not leave the selected endpoint", async () => {
  const send = vi.fn(async () => ({
    ok: true as const,
    status: 200,
    responseHeaders: {},
    responseBody: "x",
    duration: 1,
    size: 1,
  }));
  const plan = {
    ...newScanPlan({
      method: "GET",
      url: "https://example.test/admin/panel?q=1",
      headers: {},
      body: "",
    }),
    mode: "active" as const,
    checks: ["reflection" as const],
    parameters: [{ kind: "query" as const, name: "q", occurrence: 0 }],
    allowSending: true,
    rate: 20,
  };
  const engine = new ScanEngine(plan, { send, isCurrent: () => true });
  // Reflection never asks for another path; a probe to "/" from any check but url-override is refused by the engine.
  await engine.start();
  for (const [r] of send.mock.calls as unknown as [HttpRequest][])
    expect(new URL(r.url).pathname).toBe("/admin/panel");
});

it("sql-time tries the numeric form when the quoted one breaks the query", async () => {
  const sleeps = (r: HttpRequest) => Number(/SLEEP\((\d)\)/.exec(value(r))?.[1]);
  // A numeric context: a stray quote is a syntax error, a bare AND ... SLEEP() delays.
  const numeric = context((r) => {
    if (value(r).includes("'")) return response("database error", 500);
    return Number.isNaN(sleeps(r)) ? response() : response("baseline", 200, 10 + sleeps(r) * 1000);
  });
  const found = await sqlTime.run(numeric);
  expect(found.findings).toHaveLength(1);
  expect(found.findings[0]?.summary).toContain("numeric context");
  // A string context still works through the first form.
  const quoted = context((r) =>
    Number.isNaN(sleeps(r)) ? response() : response("baseline", 200, 10 + sleeps(r) * 1000),
  );
  expect((await sqlTime.run(quoted)).findings[0]?.summary).toContain("quoted context");
  // No delay in either form is a pass; a rejected form on its own is not.
  const clean = await sqlTime.run(context(() => response()));
  expect(clean.findings).toEqual([]);
  expect(clean.inconclusive).toBeFalsy();
  const rejected = await sqlTime.run(
    context((r) => (Number.isNaN(sleeps(r)) ? response() : response("blocked", 403))),
  );
  expect(rejected.inconclusive).toBe(true);
});
