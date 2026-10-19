import { expect, it, vi } from "vitest";
import { auditDomScripts } from "../lib/scan/dom-audit";
import { runDomXss } from "../lib/scan/dom-xss";
import { ScanEngine, newScanPlan } from "../lib/scan";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";
import type { HttpRequest } from "../lib/traffic";
const request: HttpRequest = { method: "GET", url: "https://app.test/page", headers: {}, body: "" };
const html = `<input id="search"><div id="target"></div><button onclick="target.innerHTML=document.getElementById('search').value">Apply</button>`;
const response = {
  status: 200,
  responseBody: html,
  responseHeaders: { "Content-Type": "text/html" },
  duration: 1,
  size: html.length,
};
const baseline: Exchange = {
  response,
  evidence: {
    id: "base",
    label: "base",
    timestamp: new Date().toISOString(),
    request,
    response,
    duration: 1,
    size: html.length,
    setCookies: [],
    truncated: false,
  },
};
function context(): ScanCheckContext {
  let serial = 0;
  return {
    request,
    baselines: [baseline],
    stable: true,
    nonce: () => `slurpInteractionMarker${++serial}`,
    probe: vi.fn(async () => {
      throw Error("Unexpected HTTP probe");
    }),
    recordDomAudit: vi.fn(),
    browser: vi.fn(async (_x, marker, url, _resources, interaction) => ({
      executed: interaction?.value?.includes(`__slurpXss(/${marker}/.source)`) ?? false,
      marker,
      url: url!,
      browser: "Chrome fixture",
      sinks: ["innerHTML"],
      cspViolations: [],
      blockedRequests: 0,
      interactions: interaction
        ? ["fill/input/change INPUT#search", "mouseover/focus/events BUTTON#go"]
        : [],
    })),
  };
}
it("audits input-value sources and confirms event-driven execution with matching controls", async () => {
  const ctx = context();
  const audit = await auditDomScripts(ctx);
  expect(
    audit.report.candidates.some(
      (c) => c.source.kind === "input" && c.source.name === '[id="search"]',
    ),
  ).toBe(true);
  const output = await runDomXss(ctx, true);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.excerpts.join(" ")).toContain("Interaction:");
  expect(ctx.probe).not.toHaveBeenCalled();
  const calls = vi.mocked(ctx.browser!).mock.calls;
  expect(calls.every((call) => call[2] === request.url)).toBe(true);
  expect(calls.at(-1)![4]).toEqual({});
});
it("does not enable input/event probing for the ordinary DOM check", async () => {
  const ctx = context();
  expect((await runDomXss(ctx)).findings).toHaveLength(0);
  expect(vi.mocked(ctx.browser!).mock.calls.every((call) => call[4] === undefined)).toBe(true);
});
it("rejects callbacks that also occur during interaction controls", async () => {
  const ctx = context();
  ctx.browser = vi.fn(async (_x, marker, url) => ({
    executed: true,
    marker,
    url: url!,
    browser: "Chrome fixture",
    sinks: [],
    cspViolations: [],
    blockedRequests: 0,
  }));
  expect((await runDomXss(ctx, true)).findings).toHaveLength(0);
});
it("forwards interactions to the isolated renderer and saves their trace", async () => {
  const browser = vi.fn(async (input: { marker: string; interaction?: { value?: string } }) => ({
    executed: input.interaction?.value?.includes(`__slurpXss(/${input.marker}/.source)`) ?? false,
    browser: "Chrome fixture",
    sinks: ["innerHTML"],
    cspViolations: [],
    blockedRequests: 0,
    interactions: ["input/change INPUT#search", "click BUTTON#go"],
  }));
  const run = await new ScanEngine(
    {
      ...newScanPlan(request),
      mode: "active",
      checks: ["dom-interaction"],
      allowSending: true,
      rate: 20,
    },
    { isCurrent: () => true, browser, send: async () => ({ ok: true, ...response }) },
  ).start();
  expect(run.status).toBe("completed");
  expect(run.findings).toHaveLength(1);
  expect(run.sent).toBe(2);
  expect(run.evidence[0]!.browser?.some((b) => b.interactions?.length)).toBe(true);
});
