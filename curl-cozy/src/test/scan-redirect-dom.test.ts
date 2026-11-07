import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";

const request = { method: "GET", url: "https://app.test/login?next=home", headers: {}, body: "" };
const exchange = (body = "", status = 200, headers: Record<string, string> = {}): Exchange => ({
  response: { status, responseHeaders: headers, responseBody: body, duration: 1, size: body.length },
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
    baselines: [exchange("<html>ok</html>")],
    stable: true,
    parameter: { kind: "query", name: "next", occurrence: 0 },
    probe,
    nonce: () => `marker${++nonce}`,
  };
}

it("open redirect detects host-prefix and encoded bypass forms", async () => {
  const ctx = context(async (req) => {
    const value = new URL(req.url).searchParams.get("next") ?? "";
    return value.includes("@") ? exchange("", 302, { location: value }) : exchange("home");
  });
  const output = await getScanCheck("open-redirect").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("bypass");
});

it("open redirect reports a javascript: Location without executing it", async () => {
  const ctx = context(async (req) => {
    const value = new URL(req.url).searchParams.get("next") ?? "";
    return value.startsWith("javascript:")
      ? exchange("", 302, { location: value })
      : exchange("home");
  });
  const output = await getScanCheck("open-redirect").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("javascript:");
  expect(output.findings[0]?.severity).toBe("high");
});

it("postMessage audit flags a listener without origin checks and wildcard targets", async () => {
  const vulnerable = context(async () => exchange("ok"));
  vulnerable.baselines = [
    exchange(
      `<html><script>window.addEventListener('message', e => { document.getElementById('x').innerHTML = e.data; }); parent.postMessage('hi', '*');</script></html>`,
      200,
      { "content-type": "text/html" },
    ),
  ];
  (vulnerable as unknown as { parameter?: unknown }).parameter = undefined;
  const output = await getScanCheck("postmessage-audit").run(vulnerable);
  expect(output.findings.length).toBeGreaterThanOrEqual(2);
  expect(output.findings.some((finding) => finding.title.includes("wildcard"))).toBe(true);

  const safe = context(async () => exchange("ok"));
  safe.baselines = [
    exchange(
      `<html><script>window.addEventListener('message', e => { if (e.origin !== 'https://trusted.test') return; document.body.textContent = e.data; });</script></html>`,
      200,
      { "content-type": "text/html" },
    ),
  ];
  (safe as unknown as { parameter?: unknown }).parameter = undefined;
  expect((await getScanCheck("postmessage-audit").run(safe)).findings).toHaveLength(0);
});
