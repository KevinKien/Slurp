import { expect, it, vi } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";

const request = {
  method: "GET",
  url: "https://example.test/api?q=original",
  headers: {},
  body: "",
};
const exchange = (body: string, headers: Record<string, string> = { "content-type": "text/html" }): Exchange => ({
  response: { status: 200, responseHeaders: headers, responseBody: body, duration: 1, size: body.length },
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
function context(probe: ScanCheckContext["probe"], baselines: Exchange[]): ScanCheckContext {
  let nonce = 0;
  return {
    request,
    baselines,
    stable: true,
    parameter: { kind: "query", name: "q", occurrence: 0 },
    probe,
    nonce: () => `marker${++nonce}`,
  };
}

it("registers the bypass checks", () => {
  expect(getScanCheck("sql-bypass").name).toContain("WAF");
  expect(getScanCheck("xss-bypass").name).toContain("XSS");
  expect(getScanCheck("nosql-bypass").name).toContain("NoSQL");
});

it("SQL bypass requires repeated evasion errors absent from the control", async () => {
  const error = "You have an error in your SQL syntax; check the manual";
  const vulnerable = context(
    async (req) => {
      const value = new URL(req.url).searchParams.get("q") ?? "";
      return exchange(value.includes("OR") || value.includes("UNION") ? error : "ok", {
        "content-type": "text/plain",
      });
    },
    [exchange("ok", { "content-type": "text/plain" })],
  );
  const output = await getScanCheck("sql-bypass").run(vulnerable);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.severity).toBe("medium");

  const clean = context(
    async () => exchange("ok", { "content-type": "text/plain" }),
    [exchange("ok", { "content-type": "text/plain" })],
  );
  expect((await getScanCheck("sql-bypass").run(clean)).findings).toHaveLength(0);
});

it("XSS bypass needs an HTML response and raw repeated reflection", async () => {
  const reflected = context(
    async (req) => {
      const value = new URL(req.url).searchParams.get("q") ?? "";
      return exchange(`<html><body>${value}</body></html>`);
    },
    [exchange("<html><body>ok</body></html>")],
  );
  const output = await getScanCheck("xss-bypass").run(reflected);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.summary).toContain("does not confirm execution");

  const escaped = context(
    async (req) => {
      const value = new URL(req.url).searchParams.get("q") ?? "";
      const safe = value.replace(/</g, "&lt;").replace(/>/g, "&gt;");
      return exchange(`<html><body>${safe}</body></html>`);
    },
    [exchange("<html><body>ok</body></html>")],
  );
  expect((await getScanCheck("xss-bypass").run(escaped)).findings).toHaveLength(0);

  const json = context(async () => exchange('{"ok":true}', { "content-type": "application/json" }), [
    exchange('{"ok":true}', { "content-type": "application/json" }),
  ]);
  expect((await getScanCheck("xss-bypass").run(json)).inconclusive).toBe(true);
});

it("NoSQL bracket operators require a match/missing differential", async () => {
  const baseline = exchange('{"data":[{"user":"admin"}]}', { "content-type": "application/json" });
  const vulnerable = context(
    async (req) => {
      const url = new URL(req.url);
      const key = [...url.searchParams.keys()].find((name) => name.includes("$regex"));
      const pattern = key ? url.searchParams.get(key)! : "";
      return exchange(
        pattern.includes("missing") ? '{"data":[]}' : '{"data":[{"user":"admin"}]}',
        { "content-type": "application/json" },
      );
    },
    [baseline, baseline],
  );
  const output = await getScanCheck("nosql-bypass").run(vulnerable);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.summary).toContain("$regex");

  const ignored = context(
    async () => exchange('{"data":[{"user":"admin"}]}', { "content-type": "application/json" }),
    [baseline, baseline],
  );
  expect((await getScanCheck("nosql-bypass").run(ignored)).findings).toHaveLength(0);
});
