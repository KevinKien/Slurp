import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";

const request = { method: "GET", url: "https://example.test/api?q=original", headers: {}, body: "" };
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
    parameter: { kind: "query", name: "q", occurrence: 0 },
    probe,
    nonce: () => `marker${++nonce}`,
  };
}
const uid = "uid=33(www-data) gid=33(www-data) groups=33(www-data)";

it("command bypass reproduces benign id output and requires a clean control", async () => {
  const vulnerable = context(async (req) => {
    const value = new URL(req.url).searchParams.get("q") ?? "";
    return exchange(value.includes("id") && !value.startsWith("slurp_") ? uid : "ok");
  });
  const output = await getScanCheck("command-bypass").run(vulnerable);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.severity).toBe("high");

  const clean = context(async () => exchange("ok"));
  expect((await getScanCheck("command-bypass").run(clean)).findings).toHaveLength(0);
});

it("command bypass reports IFS and base64 filter evasions", async () => {
  const ctx = context(async (req) => {
    const value = new URL(req.url).searchParams.get("q") ?? "";
    return exchange(value.includes("IFS") || value.includes("base64") ? uid : "ok");
  });
  const output = await getScanCheck("command-bypass").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("IFS");
});

it("argument injection needs repeated execution-flag output", async () => {
  const vulnerable = context(async (req) => {
    const value = new URL(req.url).searchParams.get("q") ?? "";
    return exchange(value.includes("--checkpoint-action=exec=id") ? uid : "ok");
  });
  const output = await getScanCheck("argument-injection").run(vulnerable);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("tar checkpoint");

  const clean = context(async () => exchange("ok"));
  expect((await getScanCheck("argument-injection").run(clean)).findings).toHaveLength(0);
});
