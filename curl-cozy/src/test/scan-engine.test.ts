import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ScanEngine,
  newScanPlan,
  mutateParameter,
  validateScanPlan,
  type ScanDependencies,
  type ScanPlan,
  type ScanResponse,
} from "../lib/scan";
import type { HttpRequest } from "../lib/traffic";
const request: HttpRequest = {
  method: "GET",
  url: "https://example.com/items?q=original",
  headers: { Authorization: "Bearer a" },
  body: "",
};
const response = (patch: Partial<ScanResponse> = {}): ScanResponse => ({
  status: 200,
  responseHeaders: { "content-type": "application/json" },
  responseBody: '{"ok":true}',
  duration: 5,
  size: 11,
  ...patch,
});
function active(checks: ScanPlan["checks"] = ["reflection"]): ScanPlan {
  return {
    ...newScanPlan(request),
    mode: "active",
    allowSending: true,
    checks,
    parameters: [{ kind: "query", name: "q", occurrence: 0 }],
    rate: 20,
  };
}
async function execute(
  plan: ScanPlan,
  send: ScanDependencies["send"] = vi.fn(async () => ({ ok: true as const, ...response() })),
) {
  const save = vi.fn(async () => {}),
    engine = new ScanEngine(plan, { send, isCurrent: () => true, save });
  const done = engine.start();
  await vi.runAllTimersAsync();
  await vi.waitFor(() => expect(engine.active).toBe(false));
  await done;
  return { engine, run: engine.run, send, save };
}
afterEach(() => vi.useRealTimers());
describe("Scan parameters and planning", () => {
  it("changes only one duplicate query occurrence and preserves other bytes", () => {
    const original = {
      ...request,
      url: "https://example.com/items?sig=%2f%20&q=one&q=two&x=a+b#fragment",
    };
    expect(mutateParameter(original, { kind: "query", name: "q", occurrence: 1 }, "a b&").url).toBe(
      "https://example.com/items?sig=%2f%20&q=one&q=a%20b%26&x=a+b#fragment",
    );
    expect(original.url).toContain("q=two");
    expect(() =>
      mutateParameter(original, { kind: "query", name: "q", occurrence: 2 }, "x"),
    ).toThrow("not found");
  });
  it("mutates escaped JSON pointers, arrays and own __proto__ safely", () => {
    const original = {
      ...request,
      method: "POST",
      body: '{"a/b":{"~name":[1,2]},"__proto__":"safe"}',
    };
    expect(
      JSON.parse(mutateParameter(original, { kind: "json", pointer: "/a~1b/~0name/1" }, "x").body)[
        "a/b"
      ]["~name"],
    ).toEqual([1, "x"]);
    expect(
      JSON.parse(mutateParameter(original, { kind: "json", pointer: "/__proto__" }, "x").body)
        .__proto__,
    ).toBe("x");
    expect(({} as any).polluted).toBeUndefined();
    expect(() => mutateParameter(original, { kind: "json", pointer: "/a~1b" }, "x")).toThrow(
      "scalar",
    );
  });
  it("rejects sending without opt-in, unsupported checks and unselected fields", () => {
    expect(() => validateScanPlan({ ...active(), allowSending: false })).toThrow("permission");
    expect(() => validateScanPlan({ ...newScanPlan(request), checks: ["reflection"] })).toThrow(
      "Active checks",
    );
    expect(() =>
      validateScanPlan({
        ...active(),
        parameters: [{ kind: "query", name: "missing", occurrence: 0 }],
      }),
    ).toThrow("not found");
    expect(() => validateScanPlan({ ...active(), maxRequests: 1 })).not.toThrow();
  });
});
describe("Scan checks and verification", () => {
  it("inspects passive observations without sending and verifies facts only", async () => {
    vi.useFakeTimers();
    const plan = newScanPlan(request);
    plan.observed = {
      response: response({
        responseHeaders: { "content-type": "text/html" },
        responseBody: "Traceback (most recent call last):",
      }),
      setCookies: ["sid=secret; Path=/", "public=value; Path=/"],
    };
    const { run, send, save } = await execute(plan);
    expect(send).not.toHaveBeenCalled();
    expect(save).toHaveBeenCalledTimes(1);
    expect(run.status).toBe("completed");
    expect(run.findings.find((f) => f.checkId === "cookie-flags")?.status).toBe("verified");
    expect(run.findings.find((f) => f.checkId === "error-disclosure")?.status).toBe("suspected");
    expect(run.findings.every((f) => f.evidenceIds.length)).toBe(true);
    expect(run.findings.flatMap((f) => f.excerpts).join(" ")).not.toContain("sid=secret");
  });
  it("does not split collapsed Set-Cookie on Expires commas", async () => {
    vi.useFakeTimers();
    const plan = newScanPlan(request);
    plan.checks = ["cookie-flags"];
    plan.observed = {
      response: response({
        responseHeaders: { "set-cookie": "a=x; Expires=Wed, 21 Oct 2030 07:28:00 GMT, b=x" },
      }),
    };
    const { run } = await execute(plan);
    expect(run.findings).toHaveLength(0);
    expect(run.checks[0]?.status).toBe("inconclusive");
  });
  it("deduplicates repeated Set-Cookie fields", async () => {
    vi.useFakeTimers();
    const plan = newScanPlan(request);
    plan.checks = ["cookie-flags"];
    plan.observed = { response: response(), setCookies: ["a=one", "a=two"] };
    const { run } = await execute(plan);
    expect(run.findings).toHaveLength(2);
    expect(new Set(run.findings.map((f) => f.fingerprint)).size).toBe(2);
  });
  it("confirms reflection with independent markers without claiming XSS", async () => {
    vi.useFakeTimers();
    const send = vi.fn(async (req: typeof request) => ({
      ok: true as const,
      ...response({ responseBody: new URL(req.url).searchParams.get("q")! }),
    }));
    const { run } = await execute(active(), send);
    expect(run.sent).toBe(4);
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]?.status).toBe("verified");
    expect(run.findings[0]?.severity).toBe("info");
    expect(run.findings[0]?.title).toBe("Input reflected in response");
    expect(run.findings[0]?.summary).toContain("does not establish XSS");
    expect(new Set(run.findings[0]?.evidenceIds).size).toBe(4);
  });
  it("does not verify a marker reflected only once", async () => {
    vi.useFakeTimers();
    let count = 0;
    const send = vi.fn(async (req: typeof request) => ({
      ok: true as const,
      ...response({ responseBody: ++count === 3 ? new URL(req.url).searchParams.get("q")! : "ok" }),
    }));
    const { run } = await execute(active(), send);
    expect(run.findings).toHaveLength(0);
  });
  it("downgrades verification when evidence is truncated", async () => {
    vi.useFakeTimers();
    const send = vi.fn(async (req: typeof request) => ({
      ok: true as const,
      ...response({ responseBody: "x".repeat(40000) + new URL(req.url).searchParams.get("q")! }),
    }));
    const { run } = await execute(active(), send);
    expect(run.findings[0]?.status).toBe("needs_review");
    expect(run.evidence.some((e) => e.truncated)).toBe(true);
    expect(run.evidence[0]?.response?.responseBody).toHaveLength(32000);
  });
  it("requires stable baselines before input-error probing", async () => {
    vi.useFakeTimers();
    let count = 0;
    const send = vi.fn(async () => ({
      ok: true as const,
      ...response({ responseBody: String(++count) }),
    }));
    const { run } = await execute(active(["input-errors"]), send);
    expect(run.baselineStable).toBe(false);
    expect(run.sent).toBe(2);
    expect(run.checks[0]?.status).toBe("inconclusive");
    expect(run.findings).toHaveLength(0);
  });
  it("normalizes configured dynamic JSON fields before comparing baselines", async () => {
    vi.useFakeTimers();
    let count = 0;
    const plan = active(["input-errors"]);
    plan.diffOptions.ignoredPaths = ["requestId"];
    const send = vi.fn(async () => ({
      ok: true as const,
      ...response({ responseBody: JSON.stringify({ ok: true, requestId: ++count }) }),
    }));
    const { run } = await execute(plan, send);
    expect(run.baselineStable).toBe(true);
    expect(run.sent).toBe(3);
  });
  it("repeats input errors and checks an original-value control without claiming injection", async () => {
    vi.useFakeTimers();
    const send = vi.fn(async (req: typeof request) => ({
      ok: true as const,
      ...response({ status: new URL(req.url).searchParams.get("q") === "original" ? 200 : 500 }),
    }));
    const { run } = await execute(active(["input-errors"]), send);
    expect(run.sent).toBe(5);
    expect(run.findings[0]?.status).toBe("needs_review");
    expect(run.findings[0]?.summary).toContain("does not establish SQL injection");
    expect(run.findings[0]?.evidenceIds).toHaveLength(5);
  });
  it("does not report a non-reproducing server error", async () => {
    vi.useFakeTimers();
    let count = 0;
    const send = vi.fn(async () => ({
      ok: true as const,
      ...response({ status: ++count === 3 ? 500 : 200 }),
    }));
    const { run } = await execute(active(["input-errors"]), send);
    expect(run.findings).toHaveLength(0);
    expect(run.checks[0]?.status).toBe("inconclusive");
  });
  it("marks credentialed CORS reflection for browser review", async () => {
    vi.useFakeTimers();
    const send = vi.fn(async (req: typeof request) => ({
      ok: true as const,
      ...response({
        responseHeaders: req.headers["Origin"]
          ? {
              "access-control-allow-origin": req.headers["Origin"],
              "access-control-allow-credentials": "true",
            }
          : {},
      }),
    }));
    const { run } = await execute(active(["cors"]), send);
    expect(run.findings[0]?.status).toBe("needs_review");
    expect(run.findings[0]?.verification.reason).toContain("real browser");
    expect(run.findings[0]?.evidenceIds).toHaveLength(2);
  });
});
describe("Scan lifecycle and evidence", () => {
  it("ignores legacy request budgets and completes all selected checks", async () => {
    vi.useFakeTimers();
    const plan = active(["reflection", "input-errors", "cors"]);
    plan.maxRequests = 3;
    const { run } = await execute(plan);
    expect(run.sent).toBeGreaterThan(3);
    expect(run.status).toBe("completed");
    expect(run.checks.find((c) => c.checkId === "cors")?.status).not.toBe("skipped");
  });
  it("finishes every selected check beyond 100 requests", async () => {
    vi.useFakeTimers();
    const plan = active(["ldap-injection", "xpath-injection", "xml-injection"]);
    plan.request.url =
      "https://example.com/items?" +
      Array.from({ length: 10 }, (_, i) => `q${i}=original`).join("&");
    plan.parameters = Array.from({ length: 10 }, (_, i) => ({
      kind: "query" as const,
      name: `q${i}`,
      occurrence: 0,
    }));
    const digest = globalThis.crypto?.subtle
      ? vi.spyOn(crypto.subtle, "digest").mockResolvedValue(new ArrayBuffer(32))
      : null;
    let run;
    try {
      ({ run } = await execute(plan));
    } finally {
      digest?.mockRestore();
    }
    expect(run.sent).toBe(122);
    expect(run.status).toBe("completed");
    expect(run.checks).toHaveLength(30);
    expect(run.checks.every((check) => check.status === "passed")).toBe(true);
  });
  it("spaces sends and supports pause/resume", async () => {
    vi.useFakeTimers();
    const times: number[] = [];
    const engine = new ScanEngine(active(), {
      isCurrent: () => true,
      send: async () => {
        times.push(Date.now());
        return { ok: true, ...response() };
      },
    });
    const done = engine.start();
    await vi.advanceTimersByTimeAsync(1);
    engine.pause();
    await vi.advanceTimersByTimeAsync(500);
    expect(times).toHaveLength(1);
    engine.resume();
    await vi.runAllTimersAsync();
    await vi.waitFor(() => expect(engine.active).toBe(false));
    await done;
    expect(times).toHaveLength(4);
    for (let i = 1; i < times.length; i++)
      expect(times[i]! - times[i - 1]!).toBeGreaterThanOrEqual(50);
  });
  it("stops on workspace change and keeps the in-flight response", async () => {
    let current = true,
      resolve!: (v: { ok: true } & ScanResponse) => void;
    const send = vi.fn(
      () =>
        new Promise<{ ok: true } & ScanResponse>((r) => {
          resolve = r;
        }),
    );
    const receive = vi.fn();
    const engine = new ScanEngine(active(), { isCurrent: () => current, send, receive });
    const done = engine.start();
    await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(1));
    current = false;
    resolve({ ok: true, ...response() });
    await done;
    expect(engine.run.status).toBe("stopped");
    expect(engine.run.evidence).toHaveLength(1);
    expect(receive).not.toHaveBeenCalled();
  });
  it("captures transport errors and fails before active probes", async () => {
    vi.useFakeTimers();
    const send = vi.fn(async () => ({ ok: false as const, error: "timeout" }));
    const { run } = await execute(active(), send as any);
    expect(run.status).toBe("failed");
    expect(run.findings).toHaveLength(0);
    expect(run.evidence[0]?.error).toBe("timeout");
    expect(run.sent).toBe(2);
  });
  it("retries saving immutable evidence without repeating network requests", async () => {
    vi.useFakeTimers();
    const send: ScanDependencies["send"] = vi.fn(async () => ({
        ok: true as const,
        ...response(),
      })),
      save = vi.fn().mockRejectedValueOnce(Error("disk full")).mockResolvedValue(undefined);
    const engine = new ScanEngine(active(), { isCurrent: () => true, send, save });
    const done = engine.start();
    await vi.runAllTimersAsync();
    await vi.waitFor(() => expect(engine.active).toBe(false));
    await done;
    expect(engine.persistenceError).toBe("disk full");
    const snapshot = engine.run;
    snapshot.evidence.length = 0;
    expect(engine.run.evidence.length).toBeGreaterThan(0);
    await engine.retrySave();
    expect(engine.persistenceError).toBe("");
    expect(send).toHaveBeenCalledTimes(4);
    expect(save).toHaveBeenCalledTimes(2);
    await expect(engine.start()).rejects.toThrow("already started");
  });
});

describe("Scan negative controls and bounded evidence", () => {
  it("ignores explicit cookie deletion and secure cookies", async () => {
    vi.useFakeTimers();
    const plan = newScanPlan(request);
    plan.checks = ["cookie-flags"];
    plan.observed = {
      response: response(),
      setCookies: ["deleted=; Max-Age=0", "sid=value; Secure; HttpOnly"],
    };
    const { run } = await execute(plan);
    expect(run.findings).toHaveLength(0);
  });
  it("does not accept non-browser credential flags or wildcard origins as credentialed reflection", async () => {
    vi.useFakeTimers();
    for (const flag of ["TRUE", "false"]) {
      const send = vi.fn(async (req: HttpRequest) => ({
        ok: true as const,
        ...response({
          responseHeaders: req.headers["Origin"]
            ? {
                "access-control-allow-origin": req.headers["Origin"],
                "access-control-allow-credentials": flag,
              }
            : {},
        }),
      }));
      const { run } = await execute(active(["cors"]), send);
      expect(run.findings).toHaveLength(0);
    }
  });
  it("stops before exceeding its evidence budget", async () => {
    vi.useFakeTimers();
    const plan = active();
    plan.maxRequests = 100;
    plan.request = {
      ...request,
      method: "POST",
      body: "x".repeat(400000),
      url:
        "https://example.com/items?" +
        Array.from({ length: 10 }, (_, i) => `q${i}=original`).join("&"),
    };
    plan.parameters = Array.from({ length: 10 }, (_, i) => ({
      kind: "query" as const,
      name: `q${i}`,
      occurrence: 0,
    }));
    const { run } = await execute(plan);
    expect(run.status).toBe("stopped");
    expect(run.message).toContain("evidence budget");
    expect(run.sent).toBeLessThan(22);
    expect(run.bytes).toBeLessThanOrEqual(8_000_000);
  });
});
it("Both audits the captured response while active probes use fresh baselines", async () => {
  vi.useFakeTimers();
  const plan = active(["passive-audit", "reflection"]);
  plan.mode = "both";
  plan.observed = {
    response: {
      status: 200,
      responseHeaders: { "content-type": "text/html" },
      responseBody: "<h1>captured</h1>",
    },
  };
  const { run } = await execute(
    plan,
    vi.fn(async (r) => ({
      ok: true as const,
      ...response({ responseBody: new URL(r.url).searchParams.get("q") ?? "" }),
    })),
  );
  expect(run.status).toBe("completed");
  expect(run.findings.some((f) => f.title.includes("Content-Security-Policy"))).toBe(true);
  expect(run.findings.some((f) => f.checkId === "reflection")).toBe(true);
  expect(run.evidence.some((e) => e.label === "Observed response")).toBe(true);
});
it("blocks intrusive checks before sending even when selected programmatically", async () => {
  vi.useFakeTimers();
  const plan = active(["path-traversal"]);
  const { run, send } = await execute(plan);
  expect(send).not.toHaveBeenCalled();
  expect(run.checks[0]?.status).toBe("skipped");
  expect(run.checks[0]?.message).toContain("policy");
});
it("enforces elapsed duration and forwards a bounded request timeout", async () => {
  vi.useFakeTimers();
  const plan = active();
  plan.policy = {
    maxImpact: "medium",
    allowIntrusive: false,
    includeExperimental: true,
    maxDurationMs: 1000,
    requestTimeoutMs: 5000,
  };
  const send = vi.fn(async (_request: HttpRequest, _options?: { timeoutMs: number }) => {
    await new Promise((resolve) => setTimeout(resolve, 1100));
    return { ok: true as const, ...response() };
  });
  const { run } = await execute(plan, send);
  expect(run.status).toBe("stopped");
  expect(run.message).toContain("duration");
  expect(send.mock.calls[0]?.[1]).toEqual({ timeoutMs: 1000 });
});
it("allows only method-policy probes to use OPTIONS/TRACE and captures their actual methods", async () => {
  vi.useFakeTimers();
  const plan = active(["http-methods"]);
  const send = vi.fn(async (r: HttpRequest) => ({
    ok: true as const,
    ...response({
      responseHeaders: { allow: "GET, OPTIONS, TRACE" },
      responseBody:
        r.method === "TRACE"
          ? `TRACE /items HTTP/1.1\r\nX-Slurp-Probe: ${r.headers["X-Slurp-Probe"]}\r\n`
          : '{"ok":true}',
    }),
  }));
  const { run } = await execute(plan, send);
  expect(run.status).toBe("completed");
  expect(run.evidence.filter((e) => e.request.method === "TRACE")).toHaveLength(2);
  expect(run.findings.some((f) => f.title.includes("TRACE"))).toBe(true);
  expect(send.mock.calls.map(([r]) => r.method)).toEqual([
    "GET",
    "GET",
    "OPTIONS",
    "TRACE",
    "TRACE",
  ]);
});
it("requires intrusive policy opt-in before scheduling time-based SQL probes", async () => {
  vi.useFakeTimers();
  const { run, send } = await execute(active(["sql-time"]));
  expect(send).not.toHaveBeenCalled();
  expect(run.checks[0]?.status).toBe("skipped");
});
it("anonymous diagnostic responses do not overwrite the selected profile cookie jar", async () => {
  vi.useFakeTimers();
  const receive = vi.fn();
  const engine = new ScanEngine(active(["auth-access"]), {
    isCurrent: () => true,
    receive,
    send: async (r) => ({
      ok: true as const,
      ...response({
        setCookies: [
          r.headers["Authorization"] === "Bearer a" ? "sid=authenticated" : "sid=anonymous",
        ],
      }),
    }),
  });
  const done = engine.start();
  await vi.runAllTimersAsync();
  await vi.waitFor(() => expect(engine.active).toBe(false));
  await done;
  expect(engine.run.findings.some((f) => f.checkId === "auth-access")).toBe(true);
  expect(receive).toHaveBeenCalledTimes(2);
  expect(receive.mock.calls.every(([, cookies]) => cookies[0] === "sid=authenticated")).toBe(true);
});
it("ordinary checks cannot change the selected method or endpoint", async () => {
  vi.useFakeTimers();
  const { getScanCheck } = await import("../lib/scan/checks");
  for (const patch of [{ method: "TRACE" }, { url: "https://example.com/other" }]) {
    const spy = vi.spyOn(getScanCheck("reflection"), "run").mockImplementation(async (ctx) => {
      await ctx.probe({ ...ctx.request, ...patch }, "Disallowed target");
      return { findings: [], message: "unexpected" };
    });
    try {
      const { run, send } = await execute(active());
      expect(run.checks[0]?.status).toBe("inconclusive");
      expect(send).toHaveBeenCalledTimes(2);
    } finally {
      spy.mockRestore();
    }
  }
});

it("fetches one unmodified response for passive scanning and never sends attack probes", async () => {
  vi.useFakeTimers();
  const plan = { ...newScanPlan(request), allowSending: true };
  const { run, send } = await execute(plan);
  expect(send).toHaveBeenCalledTimes(1);
  expect(send).toHaveBeenCalledWith(request, expect.any(Object));
  expect(run.sent).toBe(1);
  expect(run.status).toBe("completed");
  expect(run.evidence[0]?.label).toBe("Passive response fetch");
});
it("does not retry or create findings if the passive response fetch fails", async () => {
  vi.useFakeTimers();
  const send = vi.fn(async () => ({ ok: false as const, error: "connection refused" }));
  const { run } = await execute({ ...newScanPlan(request), allowSending: true }, send);
  expect(send).toHaveBeenCalledTimes(1);
  expect(run.status).toBe("failed");
  expect(run.findings).toHaveLength(0);
  expect(run.message).toContain("Could not fetch");
});
