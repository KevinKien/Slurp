import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";

const request = {
  method: "GET",
  url: "https://app.test/account/settings",
  headers: { cookie: "session=abc", accept: "text/html" },
  body: "",
};
const exchange = (body: string, headers: Record<string, string> = {}): Exchange => ({
  response: { status: 200, responseHeaders: { "content-type": "application/json", ...headers }, responseBody: body, duration: 1, size: body.length },
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
function context(probe: ScanCheckContext["probe"], baselines = [exchange('{"account":"secret","email":"victim@test","padding":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}')]): ScanCheckContext {
  let nonce = 0;
  return { request, baselines, stable: true, probe, nonce: () => `marker${++nonce}` };
}

it("cache poisoning reports a reflected unkeyed header only with a cache indicator", async () => {
  const ctx = context(async (req) => {
    const value = Object.values(req.headers).find((header) => header.startsWith("slurp-")) ?? "";
    return value
      ? exchange(JSON.stringify({ echo: value }), { "x-cache": "miss" })
      : exchange('{"account":"secret"}');
  });
  const output = await getScanCheck("cache-poisoning").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("Unkeyed x-forwarded-host");
  expect(output.findings[0]?.summary).toContain("did not send a clean follow-up");

  const clean = context(async () => exchange('{"account":"secret"}'));
  expect((await getScanCheck("cache-poisoning").run(clean)).findings).toHaveLength(0);
});

it("cache deception reports a static suffix returning the baseline body with cache headers", async () => {
  const baseline = '{"account":"secret","email":"victim@test","padding":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}';
  const ctx = context(
    async (req) => {
      const path = new URL(req.url).pathname;
      return path.includes(".css")
        ? exchange(baseline, { "x-cache": "HIT" })
        : exchange(baseline);
    },
    [exchange(baseline)],
  );
  const output = await getScanCheck("cache-deception").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("Static-looking path");
  expect(output.findings[0]?.summary).toContain("did not force caching");

  const strict = context(
    async (req) => {
      const path = new URL(req.url).pathname;
      return path.includes(".css") ? exchange("not found") : exchange(baseline);
    },
    [exchange(baseline)],
  );
  expect((await getScanCheck("cache-deception").run(strict)).findings).toHaveLength(0);
});
