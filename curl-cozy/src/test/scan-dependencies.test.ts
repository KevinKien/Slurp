import { expect, it, vi } from "vitest";
import { identifyDependencies, dependencyAudit } from "../lib/scan/dependency-checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";
const request = { url: "http://localhost:8088/vendor.js", method: "GET", headers: {}, body: "" };
const source = "/*! jQuery v3.4.1 | jquery.org/license */\n/*! lodash 4.17.20 */\nconst x=1;";
function ctx(body = source): ScanCheckContext {
  const exchange: Exchange = {
    response: {
      status: 200,
      responseHeaders: { "content-type": "application/javascript" },
      responseBody: body,
      duration: 1,
      size: body.length,
    },
    evidence: {
      id: "e1",
      label: "captured",
      timestamp: new Date().toISOString(),
      request,
      setCookies: [],
      duration: 1,
      size: body.length,
      truncated: false,
    },
  };
  return {
    request,
    baselines: [exchange],
    stable: true,
    nonce: () => "marker",
    probe: async () => {
      throw Error("Must not fetch asset or run JS");
    },
  };
}
it("identifies exact stable explicit banners and deduplicates packages", () => {
  expect(identifyDependencies(source + source).map((x) => `${x.package}@${x.version}`)).toEqual([
    "jquery@3.4.1",
    "lodash@4.17.20",
  ]);
  expect(
    identifyDependencies(
      'const VERSION="3.4.1"; const sample="/* jQuery v3.4.1 */"; // jQuery v3.4.1-beta',
    ),
  ).toEqual([]);
  expect(identifyDependencies("/*! DOMPurify 3.0.0 */ /*! AngularJS v1.6.0 */")).toHaveLength(2);
});
it("reports exact OSV matches with captured source evidence and advisory reference", async () => {
  const context = ctx();
  context.dependencies = vi.fn(async (name, version) => ({
    ok: true as const,
    package: name,
    version,
    advisories: [
      { id: "GHSA-fixture", summary: "Example vulnerable release", aliases: ["CVE-2026-1234"] },
    ],
  }));
  const output = await dependencyAudit.run(context);
  expect(context.dependencies).toHaveBeenCalledWith("jquery", "3.4.1");
  expect(output.findings).toHaveLength(2);
  expect(output.findings[0]?.evidenceIds).toEqual(["e1"]);
  expect(output.findings[0]?.status).toBe("needs_review");
  expect(output.findings[0]?.excerpts.join("\n")).toContain(
    "https://osv.dev/vulnerability/GHSA-fixture",
  );
});
it("no match is not a security guarantee; unavailable service and mismatched correlation are handled", async () => {
  const context = ctx();
  context.dependencies = async (name, version) => ({
    ok: true as const,
    package: name,
    version,
    advisories: [],
  });
  expect((await dependencyAudit.run(context)).findings).toHaveLength(0);
  context.dependencies = async () => ({ ok: false, error: "offline" });
  expect((await dependencyAudit.run(context)).inconclusive).toBe(true);
  context.dependencies = async () => ({
    ok: true,
    package: "wrong",
    version: "1.2.3",
    advisories: [],
  });
  await expect(dependencyAudit.run(context)).rejects.toThrow("correlation");
});
it("HTML examples, absent versions and truncated evidence do not create findings", async () => {
  const context = ctx();
  context.baselines[0]!.response!.responseHeaders = { "content-type": "text/html" };
  expect((await dependencyAudit.run(context)).findings).toHaveLength(0);
  expect((await dependencyAudit.run(ctx("const unknown = 1;"))).inconclusive).toBe(true);
  const truncated = ctx();
  truncated.baselines[0]!.evidence.truncated = true;
  expect((await dependencyAudit.run(truncated)).inconclusive).toBe(true);
});
