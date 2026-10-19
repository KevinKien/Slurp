import { expect, it, vi } from "vitest";
import { browserChecks } from "../lib/scan/browser-checks";
import { ScanEngine, newScanPlan } from "../lib/scan";
import { metadata } from "../lib/scan/registry";
import type { BrowserObservation, Exchange, ScanCheckContext } from "../lib/scan/types";
import type { HttpRequest } from "../lib/traffic";
const request: HttpRequest = {
  method: "GET",
  url: "https://example.test/products?q=original",
  headers: {},
  body: "",
};
let serial = 0;
function exchange(req = request, body = "<p>original</p>", contentType = "text/html"): Exchange {
  const response = {
    status: 200,
    responseHeaders: { "Content-Type": contentType },
    responseBody: body,
    duration: 1,
    size: body.length,
  };
  return {
    response,
    evidence: {
      id: `e${++serial}`,
      label: "fixture",
      timestamp: new Date().toISOString(),
      request: req,
      response,
      setCookies: [],
      duration: 1,
      size: body.length,
      truncated: false,
    },
  };
}
const observation = (
  executed = false,
  sinks: string[] = [],
): Omit<BrowserObservation, "marker" | "url"> => ({
  executed,
  sinks,
  cspViolations: [],
  blockedRequests: 0,
  browser: "Chromium fixture",
});
function context(): ScanCheckContext {
  return {
    request,
    baselines: [exchange(), exchange()],
    stable: true,
    parameter: { kind: "query", name: "q", occurrence: 0 },
    nonce: () => `slurpBrowserMarker${++serial}`,
    probe: vi.fn(async (req) => exchange(req, `<p>${new URL(req.url).searchParams.get("q")}</p>`)),
    browser: vi.fn(async (x, marker, url) => ({
      ...observation(x.response!.responseBody.includes(`__slurpXss('${marker}')`)),
      marker,
      url: url ?? x.evidence.request.url,
    })),
  };
}
const reflected = browserChecks[0]!,
  dom = browserChecks[1]!;
it("requires a browser adapter and HTML before sending payloads", async () => {
  const ctx = context();
  delete ctx.browser;
  expect((await reflected.run(ctx)).inconclusive).toBe(true);
  expect(ctx.probe).not.toHaveBeenCalled();
  ctx.browser = context().browser!;
  ctx.baselines = [exchange(request, "{}", "application/json")];
  expect((await reflected.run(ctx)).inconclusive).toBe(true);
  expect(ctx.probe).not.toHaveBeenCalled();
});
it("confirms repeated execution with independent markers and both controls", async () => {
  const ctx = context(),
    found = await reflected.run(ctx);
  expect(found.findings).toHaveLength(1);
  expect(found.findings[0]).toMatchObject({
    title: "Reflected cross-site scripting (browser-validated)",
    status: "verified",
    confidence: "high",
    verification: { outcome: "confirmed" },
  });
  expect(ctx.browser).toHaveBeenCalledTimes(4);
  const calls = vi.mocked(ctx.browser!).mock.calls;
  expect(calls[0]![1]).not.toBe(calls[1]![1]);
  expect(ctx.probe).toHaveBeenCalledTimes(4);
});
it("does not treat reflected strings as XSS without browser execution", async () => {
  const ctx = context();
  ctx.browser = vi.fn(async (_x, marker, url) => ({
    ...observation(),
    marker,
    url: url ?? request.url,
  }));
  const found = await reflected.run(ctx);
  expect(found.findings).toHaveLength(0);
  expect(found.inconclusive).toBe(true);
});
it("rejects one-off callbacks and callbacks that occur in controls", async () => {
  for (const mode of ["one-off", "all"] as const) {
    const ctx = context();
    let n = 0;
    ctx.browser = vi.fn(async (_x, marker) => ({
      ...observation(mode === "all" || ++n === 1),
      marker,
      url: request.url,
    }));
    expect((await reflected.run(ctx)).findings).toHaveLength(0);
  }
});
it("records CSP blocking as inconclusive rather than a clean scan", async () => {
  const ctx = context();
  ctx.browser = vi.fn(async (_x, marker) => ({
    ...observation(),
    cspViolations: ["Refused inline handler"],
    marker,
    url: request.url,
  }));
  const found = await reflected.run(ctx);
  expect(found.message).toContain("policy violations");
  expect(found.inconclusive).toBe(true);
});
it("tests URL fragments without sending them to the HTTP server", async () => {
  const ctx = context();
  ctx.baselines = [
    exchange(
      request,
      "<script>document.write(decodeURIComponent(location.hash.slice(1)))</script>",
    ),
  ];
  ctx.browser = vi.fn(async (_x, marker, url) => ({
    ...observation(!!url && decodeURIComponent(new URL(url).hash).includes("__slurpXss"), [
      "innerHTML",
    ]),
    marker,
    url: url ?? request.url,
  }));
  const found = await dom.run(ctx);
  expect(found.findings[0]?.title).toContain("DOM-based");
  expect(ctx.probe).not.toHaveBeenCalled();
  expect(found.findings[0]?.excerpts.some((e) => e.startsWith("Browser URL:"))).toBe(true);
});
it("attributes parameter execution to DOM only with repeated sink evidence", async () => {
  const ctx = context(),
    validate = ctx.browser!;
  ctx.browser = async (...args) => ({ ...(await validate(...args)), sinks: ["innerHTML"] });
  expect((await reflected.run(ctx)).findings[0]?.title).toContain("DOM-based");
});
it("persists browser observations on HTTP evidence without increasing sent count", async () => {
  const plan = {
    ...newScanPlan(request),
    mode: "active" as const,
    checks: ["browser-xss" as const],
    parameters: [{ kind: "query" as const, name: "q", occurrence: 0 }],
    allowSending: true,
    rate: 20,
  };
  const engine = new ScanEngine(plan, {
    isCurrent: () => true,
    send: async (req) => ({
      ok: true,
      ...exchange(req, `<p>${new URL(req.url).searchParams.get("q")}</p>`).response!,
    }),
    browser: async (input) => observation(input.body.includes(`__slurpXss('${input.marker}')`)),
  });
  const run = await engine.start();
  expect(run.status).toBe("completed");
  expect(run.sent).toBe(6);
  expect(run.evidence.flatMap((e) => e.browser ?? [])).toHaveLength(4);
  expect(run.findings[0]?.status).toBe("verified");
  expect(metadata("browser-xss").status).toBe("experimental");
});
it("browser errors never become findings", async () => {
  const ctx = context();
  ctx.browser = async () => {
    throw Error("Chrome/Chromium not found");
  };
  await expect(reflected.run(ctx)).rejects.toThrow("not found");
});
