import { expect, it, vi } from "vitest";
import { auditDomScripts } from "../lib/scan/dom-audit";
import { prepareDomAudit } from "../lib/scan/dom-discovery";
import { domPayloadFamilies, domSourceUrl, runDomXss } from "../lib/scan/dom-xss";
import { ScanEngine, newScanPlan } from "../lib/scan";
import type { BrowserObservation, Exchange, ScanCheckContext } from "../lib/scan/types";
import type { HttpRequest } from "../lib/traffic";
const request: HttpRequest = {
  method: "POST",
  url: "https://app.test/page?q=original",
  headers: {
    Authorization: "Bearer private",
    Cookie: "sid=private",
    "Content-Type": "application/json",
  },
  body: '{"test":1}',
};
let serial = 0;
function response(body: string, req = request, type = "text/html"): Exchange {
  const data = {
    status: 200,
    responseBody: body,
    responseHeaders: { "Content-Type": type },
    duration: 1,
    size: body.length,
  };
  return {
    response: data,
    evidence: {
      id: `e${++serial}`,
      label: "test",
      request: req,
      response: data,
      timestamp: new Date().toISOString(),
      truncated: false,
      setCookies: [],
      duration: 1,
      size: body.length,
    },
  };
}
function context(html: string): ScanCheckContext {
  return {
    request,
    baselines: [response(html)],
    stable: true,
    nonce: () => `slurpDomMarker${++serial}`,
    probe: vi.fn(async () => {
      throw Error("No parameter HTTP probes expected");
    }),
    recordDomAudit: vi.fn(),
    browser: vi.fn(async (_x, marker, url) => ({
      executed: false,
      sinks: [],
      cspViolations: [],
      blockedRequests: 0,
      browser: "Chrome fixture",
      marker,
      url: url ?? request.url,
    })),
  };
}
const inline = (code: string) => `<div id="target"></div><script>${code}</script>`;
it("audits aliases, named query sources, decoded hash sources and sink contexts", async () => {
  const ctx = context(
    inline(
      `const params=new URLSearchParams(location.search); const input=params.get('q'); document.querySelector('#target').innerHTML=input; const hash=decodeURIComponent(location.hash.slice(1)); eval(hash); location.href=params.get('next');`,
    ),
  );
  const { report } = await auditDomScripts(ctx);
  expect(report.candidates).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        context: "html",
        sink: "innerHTML",
        source: expect.objectContaining({ kind: "query", name: "q" }),
      }),
      expect.objectContaining({
        context: "script",
        sink: "eval",
        source: expect.objectContaining({ kind: "fragment", decoded: true }),
      }),
      expect.objectContaining({
        context: "url",
        source: expect.objectContaining({ name: "next" }),
      }),
    ]),
  );
  expect(report.candidates[0]!.line).toBeGreaterThan(0);
  expect(ctx.probe).not.toHaveBeenCalled();
});
it("does not invent a flow from comments, string literals or textContent", async () => {
  const ctx = context(
    inline(
      `// eval(location.hash)\nconst example="element.innerHTML=location.search"; document.getElementById('target').textContent=location.hash;`,
    ),
  );
  expect((await auditDomScripts(ctx)).report.candidates).toHaveLength(0);
});
it("captures executable external scripts once and follows literal module imports", async () => {
  const ctx = context(
    `<base href="/assets/"><script type="application/json">{"x":"eval(location.hash)"}</script><script type="module" src="main.js?x=1&amp;y=2"></script><script src="main.js?x=1&amp;y=2"></script>`,
  );
  ctx.loadScript = vi.fn(async (url) =>
    response(
      url.includes("main.js")
        ? `import {render} from './render.js';render(new URL(location.href).searchParams.get('q'));`
        : `export function render(value){document.getElementById('target').innerHTML=value}`,
      { ...request, method: "GET", url, body: "" },
      "application/javascript",
    ),
  );
  const { report, resources, evidence } = await auditDomScripts(ctx);
  expect(ctx.loadScript).toHaveBeenCalledTimes(2);
  expect(resources.map((r) => r.url)).toEqual([
    "https://app.test/assets/main.js?x=1&y=2",
    "https://app.test/assets/render.js",
  ]);
  expect(evidence).toHaveLength(3);
  expect(
    report.candidates.some((c) => c.source.name === "q" && c.script.endsWith("render.js")),
  ).toBe(true);
});
it("records parse and scope failures as audit notes", async () => {
  const ctx = context(
    `<script src="https://cdn.test/app.js"></script><script>const = invalid syntax</script>`,
  );
  ctx.loadScript = async () => {
    throw Error("outside Target Scope");
  };
  const { report, resources } = await auditDomScripts(ctx);
  expect(report.notes.join(" ")).toContain("outside Target Scope");
  expect(report.notes.join(" ")).toContain("Could not parse");
  expect(resources).toHaveLength(0);
});
it("chooses HTML quote context, code expressions and JavaScript URL payload families", () => {
  const observation: BrowserObservation = {
    executed: false,
    marker: "marker",
    url: request.url,
    sinks: ["innerHTML"],
    sinkTraces: [{ sink: "innerHTML", value: '<input value="marker">', stack: "app.js:2" }],
    cspViolations: [],
    blockedRequests: 0,
    browser: "Chrome",
  };
  expect(domPayloadFamilies("html", observation, "marker")[0]!.name).toBe(
    "double-quoted-attribute",
  );
  expect(domPayloadFamilies("script")[0]!.value("testmarker")).toBe(
    "__slurpXss(/testmarker/.source)",
  );
  expect(domPayloadFamilies("url")[0]!.value("testmarker")).toMatch(/^javascript:/);
  const url = domSourceUrl(
    request.url,
    { kind: "query", name: "newParam", label: "get", decoded: true, base64: false },
    "<svg>",
  );
  expect(new URL(url).searchParams.get("newParam")).toBe("<svg>");
  expect(new URL(url).origin).toBe("https://app.test");
});
it("audits first, observes a benign marker, and confirms DOM execution using captured scripts", async () => {
  const ctx = context(`<script src="/app.js"></script>`);
  let audited = false;
  ctx.loadScript = vi.fn(async (url) =>
    response(
      "const q=new URLSearchParams(location.search).get('q');document.getElementById('target').innerHTML='<input value=\"'+q+'\">';",
      { ...request, url, method: "GET", body: "" },
      "application/javascript",
    ),
  );
  ctx.recordDomAudit = vi.fn(() => {
    audited = true;
  });
  ctx.browser = vi.fn(async (_x, marker, url, resources) => {
    expect(audited).toBe(true);
    expect(resources).toHaveLength(1);
    const q = new URL(url!).searchParams.get("q")!;
    return {
      executed: q.includes(`__slurpXss(/${marker}/.source)`),
      marker,
      url: url!,
      sinks: ["innerHTML"],
      sinkTraces: [
        { sink: "innerHTML", value: `<input value="${q}">`, stack: "https://app.test/app.js:1" },
      ],
      cspViolations: [],
      blockedRequests: 0,
      browser: "Chrome",
      requestedScripts: url === request.url ? [] : ["https://app.test/payload-only.js"],
    };
  });
  const output = await runDomXss(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.status).toBe("verified");
  expect(output.findings[0]!.excerpts).toContain("Payload family: double-quoted-attribute");
  expect(ctx.browser).toHaveBeenCalledTimes(6);
  expect(ctx.loadScript).toHaveBeenCalledTimes(1);
  expect(ctx.probe).not.toHaveBeenCalled();
});
it("static source/sink candidates and marker reflection alone are never vulnerabilities", async () => {
  const ctx = context(inline(`document.write(decodeURIComponent(location.hash.slice(1)))`));
  const result = await runDomXss(ctx);
  expect(result.findings).toHaveLength(0);
  expect(result.inconclusive).toBe(true);
  expect(ctx.recordDomAudit).toHaveBeenCalled();
});
it("loads GET scripts through shared sender without leaking credentials to scoped cross-origin scripts", async () => {
  const html = `<script src="/app.js"></script><script src="https://cdn.test/vendor.js"></script><script src="https://outside.test/blocked.js"></script>`;
  const seen: HttpRequest[] = [],
    receive = vi.fn();
  const plan = {
    ...newScanPlan(request),
    request: {
      ...request,
      headers: {
        ...request.headers,
        "X-HTTP-Method-Override": "DELETE",
        "X-Original-URL": "/api/private",
      },
    },
    mode: "active" as const,
    allowSending: true,
    checks: ["dom-xss" as const],
    rate: 20,
  };
  const run = await new ScanEngine(plan, {
    isCurrent: () => true,
    receive,
    allowScriptOrigin: (url) => new URL(url).origin === "https://cdn.test",
    browser: async () => ({
      executed: false,
      sinks: [],
      cspViolations: [],
      blockedRequests: 0,
      browser: "Chrome fixture",
      requestedScripts: [],
    }),
    send: async (r) => {
      seen.push(r);
      return {
        ok: true,
        ...response(
          r.url === request.url ? html : "const safe=true;",
          r,
          r.url === request.url ? "text/html" : "application/javascript",
        ).response!,
      };
    },
  }).start();
  expect(run.sent).toBe(4);
  expect(seen.filter((r) => r.url.startsWith("https://outside"))).toHaveLength(0);
  const local = seen.find((r) => r.url.endsWith("/app.js"))!,
    foreign = seen.find((r) => r.url.endsWith("vendor.js"))!;
  expect(local).toMatchObject({
    method: "GET",
    body: "",
    headers: { Authorization: "Bearer private", Cookie: "sid=private" },
  });
  expect(foreign.headers).toEqual({});
  expect(local.headers).not.toHaveProperty("X-HTTP-Method-Override");
  expect(local.headers).not.toHaveProperty("X-Original-URL");
  expect(foreign.method).toBe("GET");
  expect(foreign.body).toBe("");
  expect(receive).toHaveBeenCalledTimes(2);
  expect(run.domAudits).toHaveLength(1);
  expect(run.domAudits![0]!.notes.join(" ")).toContain("Target Scope");
});

it("discovers computed runtime dependencies before selecting payloads and retains one audit", async () => {
  const ctx = context(
    inline(
      `const s=document.createElement('script');s.src='/'+window.bundle;document.head.append(s)`,
    ),
  );
  ctx.loadScript = vi.fn(async (url) =>
    response(
      url.endsWith("lazy.js")
        ? `const chunk='render'; import('/'+chunk+'.js')`
        : `document.getElementById('target').innerHTML=new URLSearchParams(location.search).get('q')`,
      { ...request, method: "GET", body: "", url },
      "application/javascript",
    ),
  );
  ctx.browser = vi.fn(async (_x, marker, url, resources) => ({
    executed: false,
    marker,
    url: url!,
    browser: "Chrome",
    sinks: [],
    cspViolations: [],
    blockedRequests: 1,
    requestedScripts: !resources?.length
      ? ["https://app.test/lazy.js"]
      : resources.length === 1
        ? ["https://app.test/render.js"]
        : [],
  }));
  const prepared = await prepareDomAudit(ctx);
  expect(prepared.resources).toHaveLength(2);
  expect(ctx.loadScript).toHaveBeenCalledTimes(2);
  expect(prepared.report.runtimeScripts).toEqual([
    "https://app.test/lazy.js",
    "https://app.test/render.js",
  ]);
  expect(prepared.report.candidates).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ script: "https://app.test/render.js", context: "html" }),
    ]),
  );
  expect(new Set(vi.mocked(ctx.recordDomAudit!).mock.calls.map(([a]) => a.id)).size).toBe(1);
  expect(vi.mocked(ctx.browser).mock.calls.every((call) => call[2] === request.url)).toBe(true);
});

it("does not retry excluded runtime dependencies, or follow non-HTTP and credential URLs", async () => {
  const ctx = context(inline(`const loader=true`));
  ctx.loadScript = vi.fn(async () => {
    throw Error("outside Target Scope");
  });
  ctx.browser = vi.fn(async (_x, marker, url) => ({
    executed: false,
    marker,
    url: url!,
    browser: "Chrome",
    sinks: [],
    cspViolations: [],
    blockedRequests: 1,
    requestedScripts: [
      "https://outside.test/a.js",
      "file:///etc/passwd",
      "http://user:password@app.test/private.js",
      "not a URL",
    ],
  }));
  const prepared = await prepareDomAudit(ctx);
  expect(ctx.loadScript).toHaveBeenCalledTimes(1);
  expect(ctx.browser).toHaveBeenCalledTimes(2);
  expect(prepared.report.notes.join(" ")).toContain("outside Target Scope");
  expect(prepared.report.runtimeScripts).toEqual(["https://outside.test/a.js"]);
});

it("bounds dependency discovery rounds and shares a 16-URL fetch quota", async () => {
  const ctx = context(inline(`const loader=true`));
  let round = 0;
  ctx.browser = vi.fn(async (_x, marker, url) => ({
    executed: false,
    marker,
    url: url!,
    browser: "Chrome",
    sinks: [],
    cspViolations: [],
    blockedRequests: 8,
    requestedScripts: Array.from(
      { length: 8 },
      (_, i) => `https://app.test/chunk-${round}-${i}.js`,
    ).map((url, i) => {
      if (i === 7) round++;
      return url;
    }),
  }));
  ctx.loadScript = vi.fn(async (url) =>
    response(
      "const ok=true",
      { ...request, url, method: "GET", body: "" },
      "application/javascript",
    ),
  );
  const prepared = await prepareDomAudit(ctx);
  expect(ctx.browser).toHaveBeenCalledTimes(3);
  expect(ctx.loadScript).toHaveBeenCalledTimes(16);
  expect(prepared.resources).toHaveLength(16);
  expect(prepared.report.notes.join(" ")).toContain("discovery limit");
});

it("integrates runtime capture, scope exclusions, payload proof and evidence into one task", async () => {
  const seen: HttpRequest[] = [];
  const plan = {
    ...newScanPlan(request),
    mode: "active" as const,
    allowSending: true,
    checks: ["dom-xss" as const],
    rate: 20,
  };
  const run = await new ScanEngine(plan, {
    isCurrent: () => true,
    send: async (req) => {
      seen.push(req);
      return {
        ok: true,
        ...response(
          req.url === request.url
            ? inline(
                `const name='lazy';const s=document.createElement('script');s.src='/'+name+'.js';document.head.append(s)`,
              )
            : `document.getElementById('target').innerHTML=new URLSearchParams(location.search).get('q')`,
          req,
          req.url === request.url ? "text/html" : "application/javascript",
        ).response!,
      };
    },
    browser: async (input) => {
      const value = new URL(input.url).searchParams.get("q") ?? "";
      const ready = !!input.resources?.some((r) => r.url === "https://app.test/lazy.js");
      return {
        executed: ready && value.includes(`__slurpXss(/${input.marker}/.source)`),
        browser: "Chrome fixture",
        sinks: ready ? ["innerHTML"] : [],
        cspViolations: [],
        blockedRequests: 1,
        requestedScripts:
          input.url === request.url
            ? ready
              ? ["https://outside.test/cross.js"]
              : ["https://app.test/lazy.js", "https://outside.test/cross.js"]
            : ["https://app.test/payload-only.js"],
      };
    },
  }).start();
  expect(run.status).toBe("completed");
  expect(run.sent).toBe(3);
  expect(run.findings).toHaveLength(1);
  expect(run.findings[0]!.status).toBe("verified");
  expect(run.domAudits).toHaveLength(1);
  expect(run.domAudits![0]!.runtimeScripts).toContain("https://app.test/lazy.js");
  expect(run.domAudits![0]!.notes.join(" ")).toContain("Target Scope");
  expect(
    run.evidence.some((e) =>
      e.browser?.some((b) => b.requestedScripts?.includes("https://app.test/payload-only.js")),
    ),
  ).toBe(true);
  expect(seen.every((r) => [request.url, "https://app.test/lazy.js"].includes(r.url))).toBe(true);
});
