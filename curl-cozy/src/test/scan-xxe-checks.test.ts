import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";

const request = {
  method: "POST",
  url: "https://example.test/api/xml",
  headers: { "content-type": "application/xml" },
  body: "<foo>bar</foo>",
};
const exchange = (body: string): Exchange => ({
  response: { status: 200, responseHeaders: { "content-type": "text/plain" }, responseBody: body, duration: 1, size: body.length },
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
    baselines: [exchange("ok"), exchange("ok")],
    stable: true,
    probe,
    nonce: () => `marker${++nonce}`,
  };
}

it("XXE reports a remote HTTP entity signature", async () => {
  const ctx = context(async (req) => {
    const referenced = req.body.includes("&slurpfile;") && !req.body.includes("&amp;slurpfile;");
    return referenced && req.body.includes('SYSTEM "http://example.com/"')
      ? exchange("Example Domain")
      : exchange("ok");
  });
  const output = await getScanCheck("xxe").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("remote");
});

it("XXE never requests cloud metadata automatically", async () => {
  const bodies: string[] = [];
  const ctx = context(async (req) => {
    bodies.push(req.body);
    return exchange("ok");
  });
  await getScanCheck("xxe").run(ctx);
  expect(bodies.some((body) => body.includes("169.254.169.254"))).toBe(false);
});
