import { expect, it, vi } from "vitest";
import { injectionChecks } from "../lib/scan/injection-checks";
import { metadata, policyReason, defaultScanPolicy } from "../lib/scan/registry";
import { ScanEngine, newScanPlan } from "../lib/scan";
import type { ScanCheckContext, Exchange } from "../lib/scan/types";
import type { HttpRequest } from "../lib/traffic";
const request = {
  method: "GET",
  url: "https://example.test/api?q=original",
  headers: {},
  body: "",
};
let next = 0;
function response(body = "baseline", status = 200): Exchange {
  return {
    response: { status, responseHeaders: {}, responseBody: body, duration: 10, size: body.length },
    evidence: {
      id: `e${++next}`,
      label: "fixture",
      timestamp: new Date().toISOString(),
      request,
      setCookies: [],
      duration: 10,
      size: body.length,
      truncated: false,
    },
  };
}
const payload = (r: HttpRequest) => r.body || new URL(r.url).searchParams.get("q")!;
function context(handler: (value: string) => string = () => "baseline"): ScanCheckContext {
  return {
    request,
    stable: true,
    baselines: [response(), response()],
    parameter: { kind: "query", name: "q", occurrence: 0 },
    nonce: () => `random${++next}`,
    probe: vi.fn(async (r) => response(handler(payload(r)))),
  };
}
const check = (id: string) => injectionChecks.find((c) => c.id === id)!;
it("requires stable successful baselines and a selected input before specialized injection probes", async () => {
  for (const c of injectionChecks) {
    const ctx = context();
    ctx.stable = false;
    expect((await c.run(ctx)).inconclusive).toBe(true);
    expect(ctx.probe).not.toHaveBeenCalled();
  }
});
it("does not mistake raw payload reflection for execution, parser errors or file disclosure", async () => {
  for (const c of injectionChecks.filter((c) => c.perParameter)) {
    const ctx = context((v) => (v === "original" ? "baseline" : v));
    expect((await c.run(ctx)).findings, c.id).toHaveLength(0);
  }
});
it("command probes require two independently constructed outputs and a restored original", async () => {
  const ctx = context((v) => {
    const m = v.match(/printf '%s%s' '([^']+)' '([^']+)'/);
    return m ? m[1]! + m[2]! : "baseline";
  });
  const found = await check("command-injection").run(ctx);
  expect(found.findings).toHaveLength(1);
  expect(found.findings[0]).toMatchObject({
    status: "needs_review",
    severity: "high",
    verification: { outcome: "inconclusive" },
  });
  ctx.probe = vi.fn(async (r) => response(payload(r) === "original" ? "changed" : payload(r)));
  expect((await check("command-injection").run(ctx)).findings).toHaveLength(0);
});
it("one command marker is insufficient", async () => {
  let outputs = 0;
  const ctx = context((v) => {
    const m = v.match(/printf '%s%s' '([^']+)' '([^']+)'/);
    return m && outputs++ === 0 ? m[1]! + m[2]! : "baseline";
  });
  expect((await check("command-injection").run(ctx)).findings).toHaveLength(0);
});
for (const id of ["code-injection", "el-injection"]) {
  it(`${id} uses two computed products and non-evaluating controls`, async () => {
    const ctx = context((v) => {
      if (v.includes("'")) return v;
      const m = v.match(/(\d+)\*(\d+)/);
      return m ? String(Number(m[1]) * Number(m[2])) : "baseline";
    });
    const found = await check(id).run(ctx);
    expect(found.findings).toHaveLength(1);
    expect(found.findings[0]?.summary).toContain("not proven");
    ctx.probe = vi.fn(async (r) => {
      const m = payload(r).match(/(\d+)\*(\d+)/);
      return response(m ? String(Number(m[1]) * Number(m[2])) : "baseline");
    });
    expect((await check(id).run(ctx)).findings).toHaveLength(0);
  });
}
for (const [id, signature] of [
  ["ldap-injection", "javax.naming.directory.InvalidSearchFilterException"],
  ["xpath-injection", "XPathExpressionException"],
  ["xml-injection", "org.xml.sax.SAXParseException"],
]) {
  it(`${id} requires repeated contextual errors absent from controls`, async () => {
    const ctx = context();
    ctx.probe = vi.fn(async (r) =>
      response(
        payload(r).startsWith("slurp-control-") || payload(r) === "original"
          ? "baseline"
          : signature!,
        payload(r) === "original" || payload(r).startsWith("slurp-control-") ? 200 : 500,
      ),
    );
    expect((await check(id!).run(ctx)).findings).toHaveLength(1);
    ctx.baselines = [response(signature!), response(signature!)];
    expect((await check(id!).run(ctx)).inconclusive).toBe(true);
  });
}
it("does not report WAF failures or generic server errors as parser injection", async () => {
  for (const id of ["ldap-injection", "xpath-injection", "xml-injection"]) {
    const ctx = context();
    ctx.probe = vi.fn(async () => response("Internal server error", 500));
    expect((await check(id).run(ctx)).findings).toHaveLength(0);
    ctx.probe = vi.fn(async () =>
      response("XPathExpressionException SAXParseException LDAPException", 403),
    );
    expect((await check(id).run(ctx)).inconclusive).toBe(true);
  }
});
function xmlHandler(v: string) {
  if (v === "original") return "baseline";
  if (v.includes("&amp;")) return v;
  const a = v.match(/<!ENTITY a "([^"]+)"/),
    b = v.match(/<!ENTITY b "([^"]+)"/);
  return a && b ? a[1]! + b[1]! : "baseline";
}
it("internal entities report processing only, never external file access", async () => {
  const found = await check("xml-entity").run(context(xmlHandler));
  expect(found.findings).toHaveLength(1);
  expect(found.findings[0]?.title).toBe("XML internal entity expansion observed");
  expect(found.findings[0]?.summary).toContain("does not establish XXE");
});
it("XXE requires repeated file signatures and escaped/missing-file controls", async () => {
  const ctx = context((v) =>
    v.includes('SYSTEM "file:///etc/passwd"') && !v.includes("&amp;")
      ? "root:x:0:0:root:/root:/bin/sh\n"
      : "baseline",
  );
  const found = await check("xxe").run(ctx);
  expect(found.findings).toHaveLength(1);
  expect(found.findings[0]?.excerpts.join(" ")).not.toContain("root:x");
  ctx.probe = vi.fn(async () => response("root:x:0:0:root:/root:/bin/sh\n"));
  expect((await check("xxe").run(ctx)).findings).toHaveLength(0);
});
it("XML body variants require XML media type and replace only the body", async () => {
  const ctx = context(xmlHandler);
  delete ctx.parameter;
  ctx.request = {
    ...request,
    method: "POST",
    headers: { "Content-Type": "application/soap+xml; charset=utf-8" },
    body: "<original/>",
  };
  ctx.probe = vi.fn(async (r) => {
    expect(r.url).toBe(request.url);
    expect(r.headers).toEqual(ctx.request.headers);
    return response(r.body === "<original/>" ? "baseline" : xmlHandler(r.body));
  });
  expect((await check("xml-entity-body").run(ctx)).findings).toHaveLength(1);
  ctx.request = {
    ...ctx.request,
    headers: { "Content-Type": "application/json" },
    body: '{"ok":true}',
  };
  vi.mocked(ctx.probe).mockClear();
  expect((await check("xml-entity-body").run(ctx)).inconclusive).toBe(true);
  expect(ctx.probe).not.toHaveBeenCalled();
});
it("truncated evidence cannot establish injection", async () => {
  const ctx = context();
  ctx.probe = vi.fn(async () => ({
    ...response("LDAPException"),
    evidence: { ...response().evidence, truncated: true },
  }));
  expect((await check("ldap-injection").run(ctx)).inconclusive).toBe(true);
});
it("execution and file probes are intrusive and remain blocked by default policy", () => {
  for (const id of ["command-injection", "code-injection", "xxe", "xxe-body"]) {
    expect(metadata(id).impact).toBe("intrusive");
    expect(policyReason(id, defaultScanPolicy)).toBeTruthy();
  }
});
it("engine enforces policy but ignores legacy request counts for new checks", async () => {
  const plan = newScanPlan(request);
  plan.mode = "active";
  plan.checks = ["command-injection"];
  plan.allowSending = true;
  plan.parameters = [{ kind: "query", name: "q", occurrence: 0 }];
  const send = vi.fn(async () => ({ ok: true as const, ...response().response! }));
  const denied = new ScanEngine(plan, { send, isCurrent: () => true });
  await denied.start();
  expect(send).not.toHaveBeenCalled();
  plan.policy = { ...defaultScanPolicy, maxImpact: "intrusive", allowIntrusive: true };
  plan.maxRequests = 3;
  plan.rate = 20;
  plan.delay = 0;
  const bounded = new ScanEngine(plan, { send, isCurrent: () => true });
  await bounded.start();
  expect(send.mock.calls.length).toBeGreaterThan(3);
});

it("oversized baseline analysis is inconclusive without probing", async () => {
  const ctx = context();
  ctx.baselines = [response("x".repeat(256001)), response("x".repeat(256001))];
  expect((await check("el-injection").run(ctx)).inconclusive).toBe(true);
  expect(ctx.probe).not.toHaveBeenCalled();
});
it("records XML body findings through the engine without parameter selection", async () => {
  const xmlRequest = {
    ...request,
    method: "POST",
    headers: { "Content-Type": "application/xml" },
    body: "<original/>",
  };
  const plan = newScanPlan(xmlRequest);
  plan.mode = "active";
  plan.allowSending = true;
  plan.checks = ["xml-entity-body"];
  plan.rate = 20;
  const send = vi.fn(async (r: HttpRequest) => ({
    ok: true as const,
    ...response(r.body === "<original/>" ? "baseline" : xmlHandler(r.body)).response!,
  }));
  const run = await new ScanEngine(plan, { send, isCurrent: () => true }).start();
  expect(run.status).toBe("completed");
  expect(run.findings).toHaveLength(1);
  expect(run.findings[0]).toMatchObject({ checkId: "xml-entity-body", status: "needs_review" });
  expect(send).toHaveBeenCalledTimes(7);
  for (const [r] of send.mock.calls) {
    expect(r.url).toBe(xmlRequest.url);
    expect(r.method).toBe("POST");
  }
});
