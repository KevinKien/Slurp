import { expect, it, vi } from "vitest";
import { businessChecks, businessKind } from "../lib/scan/business-checks";
import { hiddenParameters, parameterHints } from "../lib/scan/discovery-checks";
import { mutateNumber } from "../lib/scan/parameters";
import { ScanEngine, newScanPlan } from "../lib/scan";
import { defaultScanPolicy } from "../lib/scan/registry";
import type { HttpRequest } from "../lib/traffic";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";
const request: HttpRequest = {
  method: "POST",
  url: "http://localhost:8088/api/test",
  headers: { "Content-Type": "application/json" },
  body: '{"xyz":5,"nested":{"anything":"12.5"},"delivery_date":"2099-01-01"}',
};
let n = 0;
function response(body = request.body, status = 200): Exchange {
  return {
    response: { status, responseBody: body, responseHeaders: {}, duration: 1, size: body.length },
    evidence: {
      id: `e${++n}`,
      request,
      label: "fixture",
      timestamp: new Date().toISOString(),
      setCookies: [],
      duration: 1,
      size: body.length,
      truncated: false,
    },
  };
}
function ctx(): ScanCheckContext {
  return {
    request,
    parameter: { kind: "json", pointer: "/xyz" },
    baselines: [response(), response()],
    stable: true,
    nonce: () => `nonce${++n}`,
    probe: vi.fn(async (r) =>
      Number.isNaN(Number(JSON.parse(r.body).xyz))
        ? response('{"error":"invalid number"}', 422)
        : response(r.body),
    ),
  };
}
const numeric = businessChecks[0]!,
  dates = businessChecks[1]!;
it("numeric detection uses values, not names, and preserves JSON scalar types", () => {
  const c = ctx();
  expect(businessKind(c, { kind: "json", pointer: "/xyz" })).toBe("number");
  expect(businessKind(c, { kind: "json", pointer: "/nested/anything" })).toBe("number");
  expect(JSON.parse(mutateNumber(request, { kind: "json", pointer: "/xyz" }, -1).body).xyz).toBe(
    -1,
  );
  expect(
    JSON.parse(mutateNumber(request, { kind: "json", pointer: "/nested/anything" }, -1).body).nested
      .anything,
  ).toBe("-1");
  const query = { ...request, url: request.url + "?abc=1e2" };
  expect(businessKind({ request: query }, { kind: "query", name: "abc", occurrence: 0 })).toBe(
    "number",
  );
});
it("reports negative responses with echoed data; rejects semantic errors and ignores blanket status 200", async () => {
  const c = ctx();
  expect((await numeric.run(c)).findings[0]?.title).toContain(
    "Negative numeric value returned for xyz",
  );
  c.probe = vi.fn(async (r) =>
    Number(JSON.parse(r.body).xyz) < 0
      ? response('{"error":"negative forbidden"}', 200)
      : response(r.body),
  );
  expect(
    (await numeric.run(c)).findings.filter((f) => f.title.startsWith("Negative")),
  ).toHaveLength(0);
  c.probe = vi.fn(async () => response('{"ok":true}'));
  expect((await numeric.run(c)).findings).toHaveLength(0); // malformed-number control must be rejected
});
it("records low-confidence acceptance acknowledgements without claiming values were applied", async () => {
  const c = ctx();
  c.probe = vi.fn(async (r) =>
    Number.isNaN(Number(JSON.parse(r.body).xyz))
      ? response("invalid", 400)
      : response('{"success":true}'),
  );
  const f = (await numeric.run(c)).findings[0];
  expect(f?.severity).toBe("info");
  expect(f?.summary).toContain("may be ignored, clamped or normalized");
});
it("tests malformed and past dates, but never labels historical baselines as future-only", async () => {
  const c = ctx();
  c.parameter = { kind: "json", pointer: "/delivery_date" };
  c.probe = vi.fn(async (r) => response(r.body));
  expect((await dates.run(c)).findings).toHaveLength(2);
  c.request = { ...request, body: '{"delivery_date":"1990-01-01"}' };
  c.baselines = [response(c.request.body), response(c.request.body)];
  expect((await dates.run(c)).findings.map((f) => f.title)).toEqual([
    "Invalid date format returned for delivery_date",
  ]);
});
it("business engine automatically scans every numeric field even with no selected parameters", async () => {
  const body = JSON.stringify(
    Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`arbitrary${i}`, i + 1])),
  );
  const r = { ...request, body };
  const plan = {
    ...newScanPlan(r),
    mode: "active" as const,
    checks: ["business-negative" as const],
    parameters: [],
    allowSending: true,
    rate: 20,
    policy: { ...defaultScanPolicy, maxImpact: "intrusive" as const, allowIntrusive: true },
  };
  const engine = new ScanEngine(plan, {
    isCurrent: () => true,
    send: async (r) => {
      const v = JSON.parse(r.body);
      return {
        ok: true as const,
        ...(Object.values(v).some((x) => typeof x === "string")
          ? response("invalid number", 422)
          : response(r.body)
        ).response!,
      };
    },
  });
  const run = await engine.start();
  expect(run.status).toBe("completed");
  expect(run.findings).toHaveLength(55);
  expect(run.checks).toHaveLength(11);
}, 30000);
it("discovers names from captured HTML/JS, then requires named-input differential and unknown-name controls", async () => {
  expect(
    parameterHints(
      '<input name="search"><script>u.searchParams.get("filter")</script><a href="/p?page=2">',
    ),
  ).toEqual(["search", "filter", "page"]);
  const c = ctx();
  c.request = { ...request, method: "GET", headers: {}, body: "" };
  c.baselines = [response("baseline"), response("baseline")];
  c.probe = vi.fn(async (r) =>
    new URL(r.url).searchParams.has("search") ? response("search results") : response("baseline"),
  );
  expect((await hiddenParameters.run(c)).findings.map((f) => f.title)).toEqual([
    "Potential hidden query input: search",
  ]);
  c.probe = vi.fn(async (r) => response(r.url));
  expect((await hiddenParameters.run(c)).findings).toHaveLength(0);
});

it("verifies numeric state with independent before/after GET reads and original restoration", async () => {
  const c = ctx();
  let stored = 5;
  c.businessReadback = {
    url: request.url + "/saved",
    parameter: "json:/xyz",
    pointer: "/data/value",
  };
  // Use the shared key format, not a name heuristic.
  c.businessReadback.parameter = (await import("../lib/scan/parameters")).parameterKey(
    c.parameter!,
  );
  c.readBusiness = vi.fn(async () => response(JSON.stringify({ data: { value: stored } })));
  c.probe = vi.fn(async (r) => {
    const v = JSON.parse(r.body).xyz;
    if (typeof v !== "number") return response("invalid", 422);
    stored = v;
    return response('{"success":true}');
  });
  const out = await numeric.run(c);
  expect(out.findings).toHaveLength(5);
  expect(out.findings.every((f) => f.title.includes("persisted in read-back"))).toBe(true);
  expect(out.findings.every((f) => f.severity === "medium")).toBe(true);
  expect(stored).toBe(5);
  expect(c.readBusiness).toHaveBeenCalled();
});
it("does not claim persistence when GET ignores writes, clamps values or restoration fails", async () => {
  for (const mode of ["ignored", "clamped", "restore-failed"] as const) {
    const c = ctx();
    let stored = 5;
    c.businessReadback = {
      url: request.url + "/saved",
      parameter: (await import("../lib/scan/parameters")).parameterKey(c.parameter!),
      pointer: "/data/value",
    };
    c.readBusiness = vi.fn(async () => response(JSON.stringify({ data: { value: stored } })));
    c.probe = vi.fn(async (r) => {
      const v = JSON.parse(r.body).xyz;
      if (typeof v !== "number") return response("invalid", 422);
      if (mode === "clamped") stored = 5;
      if (mode === "restore-failed" && v !== 5) stored = v;
      return response('{"success":true}');
    });
    expect((await numeric.run(c)).findings.some((f) => f.title.includes("persisted"))).toBe(false);
  }
});
it("engine restricts configured read-back to same-origin GET and records its evidence", async () => {
  const { parameterKey } = await import("../lib/scan/parameters");
  const plan = {
    ...newScanPlan(request),
    mode: "active" as const,
    checks: ["business-negative" as const],
    allowSending: true,
    rate: 20,
    parameters: [],
    businessReadback: {
      url: "http://localhost:8088/api/saved",
      parameter: parameterKey({ kind: "json", pointer: "/xyz" }),
      pointer: "/xyz",
    },
    policy: { ...defaultScanPolicy, maxImpact: "intrusive" as const, allowIntrusive: true },
  };
  let saved = 5;
  const engine = new ScanEngine(plan, {
    isCurrent: () => true,
    send: async (r) => {
      if (r.url === plan.businessReadback.url) {
        expect(r.method).toBe("GET");
        expect(r.body).toBe("");
        return { ok: true as const, ...response(JSON.stringify({ xyz: saved })).response! };
      }
      const v = JSON.parse(r.body).xyz;
      if (typeof v !== "number")
        return { ok: true as const, ...response("invalid", 422).response! };
      saved = v;
      return { ok: true as const, ...response(r.body).response! };
    },
  });
  const run = await engine.start();
  expect(run.status).toBe("completed");
  expect(run.findings.some((f) => f.title.includes("persisted in read-back"))).toBe(true);
  expect(run.evidence.some((e) => e.request.url === plan.businessReadback.url)).toBe(true);
  expect(
    () =>
      new ScanEngine(
        { ...plan, businessReadback: { ...plan.businessReadback, url: "http://evil.test/" } },
        { isCurrent: () => true, send: vi.fn() },
      ),
  ).toThrow(/same-origin/);
}, 30000);
