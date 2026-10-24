import { expect, it, vi } from "vitest";
import { hostHeaderCheck, hostSinks } from "../lib/scan/host-header-check";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";
const request = { method: "GET", url: "http://localhost/products", headers: {}, body: "" };
let n = 0;
function response(body = "original", location = ""): Exchange {
  return {
    response: {
      status: 200,
      responseBody: body,
      responseHeaders: { "content-type": "text/html", location },
      duration: 1,
      size: body.length,
    },
    evidence: {
      id: `e${++n}`,
      label: "test",
      timestamp: new Date().toISOString(),
      request,
      duration: 1,
      size: body.length,
      truncated: false,
      setCookies: [],
    },
  };
}
function context(): ScanCheckContext {
  return {
    request,
    baselines: [response(), response()],
    stable: true,
    nonce: () => `n${++n}`,
    probe: vi.fn(async () => response()),
    probeHost: vi.fn(async (_, __, host) => response("redirect", `https://${host}/login`)),
  };
}
it("counts real redirect and HTML sinks, excluding plain echoes", () => {
  const host = "slurp-probe.invalid";
  expect(hostSinks(response(`<p>https://${host}/</p>`), host)).toEqual([]);
  expect(hostSinks(response(`<script src="//${host}/a.js"></script>`), host)).toEqual([
    "script.src:/a.js",
  ]);
  expect(hostSinks(response("", `https://${host}/login`), host)).toEqual(["Location:/login"]);
  expect(hostSinks(response("", `https://${host}.evil.com/`), host)).toEqual([]);
  expect(hostSinks(response("", `https://user@${host}/`), host)).toEqual([]);
});
it("requires independent host probes and restored controls", async () => {
  const ctx = context();
  const out = await hostHeaderCheck.run(ctx);
  expect(out.findings).toHaveLength(2);
  expect(ctx.probeHost).toHaveBeenCalledTimes(4);
  expect(out.findings[0]!.evidenceIds).toHaveLength(6);
});
it("does not report plain body reflection", async () => {
  const ctx = context();
  ctx.probeHost = vi.fn(async (_, __, host) => response(`echo ${host}`));
  expect((await hostHeaderCheck.run(ctx)).findings).toHaveLength(0);
});
it("rejects unstable restored responses", async () => {
  const ctx = context();
  ctx.probe = vi.fn(async (_, label) =>
    response(label.includes("restored") ? "changed" : "original"),
  );
  const out = await hostHeaderCheck.run(ctx);
  expect(out.findings).toHaveLength(0);
  expect(out.inconclusive).toBe(true);
});
