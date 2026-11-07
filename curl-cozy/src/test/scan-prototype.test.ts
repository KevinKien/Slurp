import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import type { BrowserObservation, Exchange, ScanCheckContext } from "../lib/scan/types";

const request = { method: "GET", url: "https://app.test/", headers: {}, body: "" };
const exchange = (body: string): Exchange => ({
  response: { status: 200, responseHeaders: { "content-type": "text/html" }, responseBody: body, duration: 1, size: body.length },
  evidence: {
    id: Math.random().toString(),
    label: "fixture",
    timestamp: new Date().toISOString(),
    request,
    setCookies: [],
    duration: 1,
    size: body.length,
    truncated: false,
  },
});
function observation(url: string | undefined, polluted: boolean): BrowserObservation {
  return {
    executed: false,
    marker: "marker",
    url: url ?? "https://app.test/",
    sinks: [],
    cspViolations: [],
    blockedRequests: 0,
    browser: "fake",
    sinkTraces: [],
    requestedScripts: [],
    interactions: [],
    prototypePolluted: polluted,
  };
}
function context(probe: ScanCheckContext["probe"], browser?: ScanCheckContext["browser"]): ScanCheckContext {
  let nonce = 0;
  return {
    request,
    baselines: [exchange("<html><body>app</body></html>")],
    stable: true,
    probe,
    nonce: () => `marker${++nonce}`,
    ...(browser && { browser }),
  };
}

it("prototype pollution is reported only when the browser confirms the property twice", async () => {
  const vulnerable = context(
    async () => exchange("ok"),
    async (_exchange, _marker, url) => observation(url, !!url?.includes("__proto__")),
  );
  const output = await getScanCheck("prototype-pollution").run(vulnerable);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.severity).toBe("medium");
  expect(output.findings[0]?.summary).toContain("not proof of XSS");

  const clean = context(
    async () => exchange("ok"),
    async (_exchange, _marker, url) => observation(url, false),
  );
  expect((await getScanCheck("prototype-pollution").run(clean)).findings).toHaveLength(0);
});

it("prototype pollution is inconclusive without a browser validator", async () => {
  const ctx = context(async () => exchange("ok"));
  expect((await getScanCheck("prototype-pollution").run(ctx)).inconclusive).toBe(true);
});
