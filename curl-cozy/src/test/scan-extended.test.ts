import { expect, it, vi } from "vitest";
import { extendedChecks } from "../lib/scan/extended-checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";
const request = {
  method: "GET",
  url: "https://example.test/api?q=original",
  headers: {},
  body: "",
};
const exchange = (
  body: string,
  headers: Record<string, string> = { "content-type": "text/plain" },
  status = 200,
): Exchange => ({
  response: {
    status,
    responseHeaders: headers,
    responseBody: body,
    duration: 1,
    size: body.length,
  },
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
function context(probe: ScanCheckContext["probe"]): ScanCheckContext {
  let nonce = 0;
  return {
    request,
    baselines: [exchange("normal"), exchange("normal")],
    stable: true,
    parameter: { kind: "query", name: "q", occurrence: 0 },
    probe,
    nonce: () => `marker${++nonce}`,
  };
}
const check = (id: string) => extendedChecks.find((x) => x.id === id)!;
it("passive audit records missing document headers without sending", async () => {
  const probe = vi.fn();
  const ctx = context(probe);
  ctx.baselines = [exchange("<h1>hello</h1>", { "content-type": "text/html" })];
  const output = await check("passive-audit").run(ctx);
  expect(output.findings.map((x) => x.title).join(" ")).toContain("Content-Security-Policy");
  expect(output.findings.map((x) => x.title).join(" ")).toContain("Strict-Transport-Security");
  expect(probe).not.toHaveBeenCalled();
});
it("SQL detection needs repeated errors absent from controls", async () => {
  for (const vulnerable of [true, false]) {
    const ctx = context(async (r) =>
      exchange(
        vulnerable && new URL(r.url).searchParams.get("q") === "'\"" ? "SQLSTATE[42000]" : "normal",
      ),
    );
    expect((await check("sql-injection").run(ctx)).findings).toHaveLength(vulnerable ? 1 : 0);
  }
});
it("SSTI requires evaluated arithmetic, not reflected expressions", async () => {
  for (const evaluate of [true, false]) {
    const ctx = context(async (r) => {
      let value = new URL(r.url).searchParams.get("q")!;
      if (evaluate)
        value = value.replace(/\{\{(\d+)\*(\d+)\}\}/g, (_, a, b) => String(Number(a) * Number(b)));
      return exchange(value);
    });
    expect((await check("ssti").run(ctx)).findings).toHaveLength(evaluate ? 1 : 0);
  }
});
it("traversal requires content signatures absent from controls", async () => {
  const ctx = context(async (r) =>
    exchange(
      new URL(r.url).searchParams.get("q")!.includes("etc/passwd")
        ? "root:x:0:0:root:/root:/bin/bash"
        : "not found",
    ),
  );
  expect((await check("path-traversal").run(ctx)).findings).toHaveLength(1);
  ctx.baselines = [exchange("root:x:0:0:root:/root:/bin/bash")];
  expect((await check("path-traversal").run(ctx)).inconclusive).toBe(true);
});
it("redirect requires both independently controlled Location destinations", async () => {
  const ctx = context(async (r) =>
    exchange(
      "",
      { "content-type": "text/plain", location: new URL(r.url).searchParams.get("q")! } as any,
      302,
    ),
  );
  expect((await check("open-redirect").run(ctx)).findings).toHaveLength(1);
  ctx.probe = async () =>
    exchange("https://example.invalid", { "content-type": "text/plain" }, 200);
  expect((await check("open-redirect").run(ctx)).findings).toHaveLength(0);
});

it("detects hidden SQL errors using repeated single/doubled-quote repair", async () => {
  const ctx = context(async (r) => {
    const value = new URL(r.url).searchParams.get("q")!;
    return value === "'" ? exchange("internal server error", undefined, 500) : exchange("normal");
  });
  ctx.request = { ...request, url: "https://example.test/api?q=" };
  const output = await check("sql-injection").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]).toMatchObject({
    status: "needs_review",
    title: "Possible SQL injection: repeated quote-repair differential",
  });
});
it("quote-repair rejects ordinary reflection, generic failures and changed controls", async () => {
  for (const mode of ["reflection", "all-errors", "drift"]) {
    const ctx = context(async (r) => {
      const value = new URL(r.url).searchParams.get("q")!;
      if (mode === "reflection") return exchange(value);
      if (mode === "all-errors") return exchange("internal server error", undefined, 500);
      if (value.endsWith("''")) return exchange("normal");
      if (value.endsWith("'")) return exchange("internal server error", undefined, 500);
      return exchange("changed");
    });
    expect((await check("sql-injection").run(ctx)).findings).toHaveLength(0);
  }
});
it("quote-repair works for a selected JSON scalar", async () => {
  const ctx = context(async (r) => {
    const value = JSON.parse(r.body).email;
    return exchange(
      value === "admin'" ? "internal server error" : "normal",
      undefined,
      value === "admin'" ? 500 : 200,
    );
  });
  ctx.request = { ...request, method: "POST", body: '{"email":"admin","password":"unchanged"}' };
  ctx.parameter = { kind: "json", pointer: "/email" };
  expect((await check("sql-injection").run(ctx)).findings).toHaveLength(1);
});

for (const name of ["min_price", "max_price"]) {
  it(`detects quote repair with a reflected ${name} form input`, async () => {
    const html = (v: string) =>
      `<input type="number" name="${name}" value="${v.replaceAll("'", "&#39;")}"><p>products</p>`;
    const ctx = context(async (r) => {
      const v = new URL(r.url).searchParams.get(name)!;
      return v === "'" ? exchange("internal server error", undefined, 500) : exchange(html(v));
    });
    ctx.request = { ...request, url: `https://example.test/products?${name}=` };
    ctx.parameter = { kind: "query", name, occurrence: 0 };
    ctx.baselines = [exchange(html("")), exchange(html(""))];
    expect((await check("sql-injection").run(ctx)).findings[0]?.title).toContain("quote-repair");
  });
}
it("detects repeated numeric boolean groups while rejecting reflection and drifting controls", async () => {
  for (const mode of ["vulnerable", "reflection", "drift", "single-pair"]) {
    const html = (v: string, content: string) =>
      `<input name="min_price" value="${v}"><p>${content}</p>`;
    const ctx = context(async (r) => {
      const v = new URL(r.url).searchParams.get("min_price")!;
      const content =
        mode === "reflection"
          ? "products"
          : /0 OR (7=7|9=9)$/.test(v)
            ? mode === "single-pair" && v.includes("9=9")
              ? "products"
              : "all products"
            : mode === "drift" && !v
              ? "changed"
              : "products";
      return exchange(html(v, content));
    });
    ctx.request = { ...request, url: "https://example.test/products?min_price=" };
    ctx.parameter = { kind: "query", name: "min_price", occurrence: 0 };
    ctx.baselines = [exchange(html("", "products")), exchange(html("", "products"))];
    const output = await check("sql-injection").run(ctx);
    expect(output.findings).toHaveLength(mode === "vulnerable" ? 1 : 0);
    if (mode === "vulnerable") expect(output.findings[0]?.title).toContain("boolean differential");
  }
});

it("audits CSP framing and inline style policy without sending", async () => {
  const probe = vi.fn();
  const cases = [
    {
      csp: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'self'; connect-src 'self'",
      frame: true,
      style: true,
    },
    { csp: "default-src 'none'", frame: true, style: false },
    { csp: "frame-ancestors 'none'; style-src 'self'", frame: false, style: false },
    {
      csp: "frame-ancestors 'self'; style-src 'unsafe-inline' 'nonce-AbCd123'",
      frame: false,
      style: false,
    },
    { csp: "frame-ancestors *; style-src 'unsafe-inline'", xfo: "DENY", frame: true, style: true },
    { csp: "style-src 'unsafe-inline'", xfo: "SAMEORIGIN", frame: false, style: true },
    {
      csp: "style-src 'unsafe-inline'; style-src-elem 'none'; style-src-attr 'none'",
      frame: true,
      style: false,
    },
    {
      csp: "style-src 'unsafe-inline', style-src 'self'; frame-ancestors 'self'",
      frame: false,
      style: false,
    },
    {
      csp: "frame-ancestors 'none'; frame-ancestors *; style-src 'self'; style-src 'unsafe-inline'",
      frame: false,
      style: false,
    },
  ];
  for (const row of cases) {
    const ctx = context(probe);
    ctx.baselines = [
      exchange("<h1>login</h1>", {
        "content-type": "text/html",
        "content-security-policy": row.csp,
        "x-frame-options": row.xfo ?? "",
      }),
    ];
    const titles = (await check("passive-audit").run(ctx)).findings.map((f) => f.title);
    expect(titles.includes("Content security policy: allows clickjacking"), row.csp).toBe(
      row.frame,
    );
    expect(
      titles.includes("Content security policy: allows untrusted style execution"),
      row.csp,
    ).toBe(row.style);
  }
  expect(probe).not.toHaveBeenCalled();
});
it("report-only CSP does not enforce framing or style restrictions", async () => {
  const ctx = context(vi.fn());
  ctx.baselines = [
    exchange("<h1>login</h1>", {
      "content-type": "text/html",
      "content-security-policy-report-only": "frame-ancestors 'none'; style-src 'none'",
    }),
  ];
  const titles = (await check("passive-audit").run(ctx)).findings.map((f) => f.title);
  expect(titles).toContain("HTML response has no observed framing restriction");
  expect(titles).toContain("HTML response lacks Content-Security-Policy");
});
