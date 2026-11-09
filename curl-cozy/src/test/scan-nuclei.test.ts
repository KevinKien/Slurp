import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import { parseNuclei } from "../lib/scan/nuclei-check";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";

const request = { method: "GET", url: "https://app.test/", headers: { cookie: "a=b" }, body: "" };
const exchange = (body: string, status = 200): Exchange => ({
  response: { status, responseHeaders: { "content-type": "text/html" }, responseBody: body, duration: 1, size: body.length },
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
const template = `
id: exposed-panel
info:
  name: Exposed Panel
  severity: medium
  description: Dashboard was exposed.
http:
  - method: GET
    path: ["{{BaseURL}}/admin"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Dashboard"]
        part: body
`;
function context(probe: ScanCheckContext["probe"], yaml = template): ScanCheckContext {
  let nonce = 0;
  return {
    request,
    baselines: [exchange("ok")],
    stable: true,
    probe,
    nonce: () => `marker${++nonce}`,
    nucleiTemplates: [yaml],
  };
}

it("parses the supported Nuclei http subset and rejects raw templates", () => {
  const parsed = parseNuclei([template]);
  expect(parsed.errors).toHaveLength(0);
  expect(parsed.templates[0]?.id).toBe("exposed-panel");
  const raw = parseNuclei([
    "id: raw\ninfo: {name: Raw, severity: low}\nhttp:\n  - raw:\n      - |\n        GET / HTTP/1.1\n",
  ]);
  expect(raw.templates).toHaveLength(0);
  expect(raw.errors.join(" ")).toContain("raw");
});

it("runs a bounded template and reports a matcher hit", async () => {
  const seen: string[] = [];
  const ctx = context(async (req) => {
    seen.push(`${req.method} ${req.url}`);
    return req.url.endsWith("/admin") ? exchange("Dashboard") : exchange("missing", 404);
  });
  const output = await getScanCheck("nuclei-template").run(ctx);
  expect(seen).toEqual(["GET https://app.test/admin"]);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("Exposed Panel");
  expect(output.findings[0]?.severity).toBe("medium");
  expect(output.findings[0]?.summary).toContain("not proof of exploitability");
});

it("does not report when matchers fail and rejects cross-origin paths", async () => {
  const failed = await getScanCheck("nuclei-template").run(
    context(async () => exchange("login")),
  );
  expect(failed.findings).toHaveLength(0);

  const cross = template.replace('{{BaseURL}}/admin', 'https://evil.test/admin');
  let sent = 0;
  const output = await getScanCheck("nuclei-template").run(
    context(async () => {
      sent++;
      return exchange("Dashboard");
    }, cross),
  );
  expect(sent).toBe(0);
  expect(output.findings).toHaveLength(0);
  expect(output.message).toContain("cross-origin");
});
