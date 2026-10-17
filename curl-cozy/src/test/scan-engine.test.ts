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
    expect(() => validateScanPlan({ ...active(), maxRequests: 1 })).toThrow("baseline");
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
  it("enforces request budget and explicitly marks remaining checks skipped", async () => {
    vi.useFakeTimers();
    const plan = active(["reflection", "input-errors", "cors"]);
    plan.maxRequests = 3;
    const { run } = await execute(plan);
    expect(run.sent).toBe(3);
    expect(run.status).toBe("stopped");
    expect(run.checks.find((c) => c.checkId === "cors")?.status).toBe("skipped");
    expect(run.message).toContain("budget");
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
