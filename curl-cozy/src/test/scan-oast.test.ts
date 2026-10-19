import { expect, it, vi } from "vitest";
import { oastChecks } from "../lib/scan/oast-checks";
import { ScanEngine, newScanPlan } from "../lib/scan";
import type { Exchange, OastProbe, ScanCheckContext } from "../lib/scan/types";
import type { HttpRequest } from "../lib/traffic";
const request: HttpRequest = {
  method: "POST",
  url: "http://app.test/api?url=original",
  headers: { "Content-Type": "application/json" },
  body: "{}",
};
let serial = 0;
function exchange(req = request): Exchange {
  const response = {
    status: 200,
    responseBody: "ok",
    responseHeaders: { "Content-Type": "text/plain" },
    duration: 1,
    size: 2,
  };
  return {
    response,
    evidence: {
      id: `e${++serial}`,
      label: "fixture",
      timestamp: new Date().toISOString(),
      request: req,
      response,
      duration: 1,
      size: 2,
      setCookies: [],
      truncated: false,
    },
  };
}
function context(mode: "http" | "dns" | "none" | "one" | "control" = "http"): ScanCheckContext {
  let issued = 0;
  const context: ScanCheckContext = {
    request,
    baselines: [exchange()],
    stable: true,
    parameter: { kind: "query", name: "url", occurrence: 0 },
    nonce: () => `marker${++serial}`,
    probe: vi.fn(async (req) => exchange(req)),
    oast: {
      issue: vi.fn(async () => ({
        id: `probe${++issued}`,
        url: `http://oast.test/slurp-oast/probe${issued}`,
        expiresAt: new Date(Date.now() + 600000).toISOString(),
        events: [],
      })),
      poll: vi.fn(async (p) => ({
        ...p,
        events:
          mode === "control" ||
          (p.id !== "probe3" && mode !== "none" && (mode !== "one" || p.id === "probe1"))
            ? [
                {
                  protocol: mode === "dns" ? "dns" : "http",
                  timestamp: new Date().toISOString(),
                  peer: "192.0.2.10",
                  detail: "callback",
                },
              ]
            : [],
      })),
      wait: vi.fn(async () => {}),
    },
  };
  return context;
}
const ssrf = oastChecks[0]!,
  xxe = oastChecks[1]!;
it("reports only repeated independent callbacks and keeps an unsubmitted control", async () => {
  const ctx = context();
  const output = await ssrf.run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.status).toBe("needs_review");
  expect(output.findings[0]!.verification.outcome).toBe("confirmed");
  const calls = vi.mocked(ctx.probe).mock.calls;
  expect(calls).toHaveLength(2);
  expect(calls[0]![0].url).not.toBe(calls[1]![0].url);
  expect(calls.every(([r]) => !r.url.includes("probe3"))).toBe(true);
});
it("does not equate missing, single or control callbacks with a vulnerability", async () => {
  for (const mode of ["none", "one", "control"] as const) {
    const ctx = context(mode);
    const output = await ssrf.run(ctx);
    expect(output.findings).toHaveLength(0);
    expect(output.inconclusive).toBe(true);
  }
});
it("labels DNS-only interactions without claiming an HTTP fetch", async () => {
  const result = await ssrf.run(context("dns"));
  expect(result.findings[0]!.severity).toBe("medium");
  expect(result.findings[0]!.verification.reason).toContain("DNS alone");
});
it("injects bounded external parameter-entity probes into an XML body", async () => {
  const ctx = context();
  ctx.request = {
    ...request,
    headers: { "Content-Type": "application/xml" },
    body: '<?xml version="1.0"?><root><name>original</name></root>',
  };
  const result = await xxe.run(ctx);
  expect(result.findings).toHaveLength(1);
  const body = vi.mocked(ctx.probe).mock.calls[0]![0].body;
  expect(body).toContain('<?xml version="1.0"?><!DOCTYPE root');
  expect(body).toContain('SYSTEM "http://oast.test/slurp-oast/probe1"');
  expect(body).toContain("<name>original</name>");
  ctx.request.body = "<!DOCTYPE root><root/>";
  vi.mocked(ctx.probe).mockClear();
  expect((await xxe.run(ctx)).inconclusive).toBe(true);
  expect(ctx.probe).not.toHaveBeenCalled();
});
it("requires a collector and XML prerequisites before sending probes", async () => {
  const ctx = context();
  delete ctx.oast;
  expect((await ssrf.run(ctx)).inconclusive).toBe(true);
  expect(ctx.probe).not.toHaveBeenCalled();
  const json = context();
  expect((await xxe.run(json)).inconclusive).toBe(true);
  expect(json.probe).not.toHaveBeenCalled();
});
it("persists callback and control evidence on their corresponding probe requests", async () => {
  const ctx = context();
  const plan = {
    ...newScanPlan(request),
    mode: "active" as const,
    checks: ["oast-ssrf" as const],
    allowSending: true,
    rate: 20,
    parameters: [{ kind: "query" as const, name: "url", occurrence: 0 }],
  };
  const run = await new ScanEngine(plan, {
    isCurrent: () => true,
    oast: ctx.oast!,
    send: async (req) => ({ ok: true, ...exchange(req).response! }),
  }).start();
  expect(run.status).toBe("completed");
  expect(run.findings).toHaveLength(1);
  const probes = run.evidence.filter((e) => e.oast?.length);
  expect(probes).toHaveLength(2);
  expect(probes[0]!.oast).toHaveLength(2);
  expect(probes[0]!.oast!.find((p) => p.id === "probe3")!.events).toHaveLength(0);
  expect(run.sent).toBe(4);
});
it("rejects mismatched callback correlation and late results after workspace changes", async () => {
  for (const mode of ["mismatch", "workspace"] as const) {
    const ctx = context();
    let current = true;
    const plan = {
      ...newScanPlan(request),
      mode: "active" as const,
      checks: ["oast-ssrf" as const],
      allowSending: true,
      rate: 20,
      parameters: [{ kind: "query" as const, name: "url", occurrence: 0 }],
    };
    const run = await new ScanEngine(plan, {
      isCurrent: () => current,
      oast: {
        issue: ctx.oast!.issue,
        poll: async (p) => {
          if (mode === "workspace") current = false;
          return { ...p, id: mode === "mismatch" ? "wrong-id" : p.id };
        },
      },
      send: async (req) => ({ ok: true, ...exchange(req).response! }),
    }).start();
    expect(run.findings).toHaveLength(0);
    expect(run.evidence.every((e) => !e.oast?.length)).toBe(true);
    if (mode === "workspace") expect(run.status).toBe("stopped");
  }
});
