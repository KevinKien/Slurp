import { expect, it, vi } from "vitest";
import { crawl, crawlLinks, crawlUrl } from "../lib/scan/crawler";
import { newScanPlan, ScanEngine } from "../lib/scan";
import type { Exchange } from "../lib/scan/types";
import type { HttpRequest } from "../lib/traffic";
const seed: HttpRequest = {
  method: "GET",
  url: "http://localhost:8088/start?q=hello",
  headers: { Authorization: "Bearer fixture", Host: "localhost:8088", "Content-Length": "5" },
  body: "",
};
function response(body: string, status = 200, headers: Record<string, string> = {}) {
  return {
    status,
    responseHeaders: { "Content-Type": "text/html", ...headers },
    responseBody: body,
    duration: 1,
    size: body.length,
  };
}
let id = 0;
function exchange(
  request: HttpRequest,
  body: string,
  status = 200,
  headers: Record<string, string> = {},
): Exchange {
  return {
    response: response(body, status, headers),
    evidence: {
      id: `crawl-${++id}`,
      request,
      label: "crawl",
      timestamp: new Date().toISOString(),
      setCookies: [],
      duration: 1,
      size: body.length,
      truncated: false,
    },
  };
}
it("extracts inert HTML links, GET forms and JS literals without executing code", () => {
  const html =
    '<base href="/dir/"><a href="next?a=1&amp;b=2">next</a><script src="app.js"></script><form action="/search"><input name="q" value="hello"><input name="secret" type="password" value="hidden"></form><form action="/write" method="post"><input name="x" value="1"></form>';
  const links = crawlLinks(html, "text/html", seed.url);
  expect(links).toContain("http://localhost:8088/dir/next?a=1&b=2");
  expect(links).toContain("http://localhost:8088/dir/app.js");
  expect(links).toContain("http://localhost:8088/search?q=hello");
  expect(links.some((x) => x.includes("/write") || x.includes("hidden"))).toBe(false);
  expect(
    crawlLinks('fetch("/api/items"); window.mustNotRun=true;', "application/javascript", seed.url),
  ).toEqual(["http://localhost:8088/api/items"]);
});
it("enforces same origin, GET-only, depth and URL limits and deduplicates query shapes", async () => {
  const send = vi.fn(async (r: HttpRequest) =>
    exchange(
      r,
      '<a href="/next?q=1">a</a><a href="/next?q=2">b</a><a href="http://foreign.test/">x</a><a href="/deep">d</a><a href="/logout">out</a>',
    ),
  );
  const pages = await crawl(
    seed,
    { maxUrls: 3, maxDepth: 1 },
    send,
    () => true,
    () => {},
  );
  expect(pages).toHaveLength(3);
  expect(pages.map((p) => p.request.url)).toEqual([
    seed.url,
    "http://localhost:8088/next?q=1",
    "http://localhost:8088/deep",
  ]);
  expect(
    send.mock.calls.every(
      ([r]) =>
        r.method === "GET" &&
        r.body === "" &&
        r.headers["Authorization"] === "Bearer fixture" &&
        !r.headers["Host"] &&
        !r.headers["Content-Length"],
    ),
  ).toBe(true);
  expect(crawlUrl("http://evil.test/", seed.url, seed.url)).toBeUndefined();
  expect(crawlUrl("http://u:p@localhost:8088/", seed.url, seed.url)).toBeUndefined();
  expect(crawlUrl("javascript:alert(1)", seed.url, seed.url)).toBeUndefined();
});
it("applies scope before fetching and never follows foreign redirects", async () => {
  const send = vi.fn(async (r: HttpRequest) =>
    exchange(r, "", 302, { Location: "http://foreign.test/private" }),
  );
  expect(
    await crawl(
      seed,
      { maxUrls: 10, maxDepth: 2 },
      send,
      () => true,
      () => {},
    ),
  ).toHaveLength(1);
  await expect(
    crawl(
      seed,
      { maxUrls: 10, maxDepth: 2 },
      send,
      () => false,
      () => {},
    ),
  ).rejects.toThrow(/Scope/);
  expect(send).toHaveBeenCalledTimes(1);
});
it("is off by default and requires explicit sending permission when enabled", () => {
  const plan = newScanPlan(seed);
  expect(plan.crawlBeforeScan ?? false).toBe(false);
  expect(
    () =>
      new ScanEngine({ ...plan, crawlBeforeScan: true }, { send: vi.fn(), isCurrent: () => true }),
  ).toThrow(/permission/);
});
it("passive crawl completes discovery before audits and retains evidence for every endpoint", async () => {
  const send = vi.fn(async (r: HttpRequest) => ({
    ok: true as const,
    ...response(
      r.url === seed.url ? '<a href="/next">next</a><input name="first">' : '<input name="second">',
    ),
  }));
  const engine = new ScanEngine(
    {
      ...newScanPlan(seed),
      crawlBeforeScan: true,
      allowSending: true,
      rate: 20,
      checks: ["parameter-hints"],
      crawlOptions: { maxUrls: 5, maxDepth: 2 },
    },
    { send, isCurrent: () => true },
  );
  const run = await engine.start();
  expect(run.status).toBe("completed");
  expect(send).toHaveBeenCalledTimes(2);
  expect(run.crawl?.phase).toBe("completed");
  expect(run.crawl?.urls).toHaveLength(2);
  expect(new Set(run.checks.map((c) => c.endpoint))).toEqual(
    new Set([seed.url, "http://localhost:8088/next"]),
  );
  expect(run.findings).toHaveLength(2);
  expect(
    run.findings.every((f) => f.evidenceIds.every((id) => run.evidence.some((e) => e.id === id))),
  ).toBe(true);
});
it("active crawl scans new query inputs with the selected checks", async () => {
  const calls: string[] = [];
  const send = vi.fn(async (r: HttpRequest) => {
    calls.push(r.url);
    const u = new URL(r.url);
    return {
      ok: true as const,
      ...response(`<a href="/next?q=hello">next</a> ${u.searchParams.get("q") ?? ""}`),
    };
  });
  const plan = {
    ...newScanPlan(seed),
    mode: "active" as const,
    checks: ["reflection" as const],
    allowSending: true,
    crawlBeforeScan: true,
    crawlOptions: { maxUrls: 2, maxDepth: 1 },
    parameters: [{ kind: "query" as const, name: "q", occurrence: 0 }],
    rate: 20,
  };
  const run = await new ScanEngine(plan, { send, isCurrent: () => true }).start();
  expect(run.status).toBe("completed");
  expect(calls.slice(0, 2)).toEqual([seed.url, "http://localhost:8088/next?q=hello"]);
  expect(
    run.checks.filter((c) => c.checkId === "reflection" && c.status === "findings"),
  ).toHaveLength(2);
  expect(new Set(run.findings.map((f) => JSON.parse(f.fingerprint)[2]))).toEqual(
    new Set(["/start", "/next"]),
  );
}, 10000);
it("stop during crawling prevents further discovery and scan probes", async () => {
  let engine: ScanEngine;
  const send = vi.fn(async () => {
    engine.stop();
    return { ok: true as const, ...response('<a href="/next">next</a>') };
  });
  engine = new ScanEngine(
    {
      ...newScanPlan(seed),
      crawlBeforeScan: true,
      allowSending: true,
      rate: 20,
      checks: ["parameter-hints"],
    },
    { send, isCurrent: () => true },
  );
  const run = await engine.start();
  expect(run.status).toBe("stopped");
  expect(send).toHaveBeenCalledTimes(1);
});

it("stop while scanning a discovered endpoint cancels its remaining checks and the seed scan", async () => {
  let engine: ScanEngine;
  let calls = 0;
  const send = vi.fn(async (r: HttpRequest) => {
    if (++calls === 3) engine.stop();
    return { ok: true as const, ...response('<a href="/next?q=hello">next</a> hello') };
  });
  engine = new ScanEngine(
    {
      ...newScanPlan(seed),
      mode: "active",
      checks: ["reflection"],
      parameters: [{ kind: "query", name: "q", occurrence: 0 }],
      crawlBeforeScan: true,
      allowSending: true,
      rate: 20,
    },
    { send, isCurrent: () => true },
  );
  const run = await engine.start();
  expect(run.status).toBe("stopped");
  expect(calls).toBe(3);
});

it("pause and resume gate the scan of discovered endpoints", async () => {
  let engine: ScanEngine;
  let calls = 0;
  let notify!: () => void;
  const paused = new Promise<void>((resolve) => {
    notify = resolve;
  });
  const send = vi.fn(async (r: HttpRequest) => {
    if (++calls === 3) {
      engine.pause();
      notify();
    }
    return {
      ok: true as const,
      ...response(`<a href="/next?q=hello">next</a> ${new URL(r.url).searchParams.get("q")}`),
    };
  });
  engine = new ScanEngine(
    {
      ...newScanPlan(seed),
      mode: "active",
      checks: ["reflection"],
      parameters: [{ kind: "query", name: "q", occurrence: 0 }],
      crawlBeforeScan: true,
      allowSending: true,
      rate: 20,
    },
    { send, isCurrent: () => true },
  );
  const done = engine.start();
  await paused;
  await new Promise((resolve) => setTimeout(resolve, 120));
  expect(calls).toBe(3);
  expect(engine.run.status).toBe("paused");
  engine.resume();
  expect((await done).status).toBe("completed");
  expect(calls).toBeGreaterThan(3);
}, 10000);
