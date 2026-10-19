import { expect, it, vi } from "vitest";
import { cookieAudit, disclosureAudit, policyAudit } from "../lib/scan/passive-checks";
import { scanChecks } from "../lib/scan/checks";
import {
  checkRegistry,
  defaultScanPolicy,
  metadata,
  policyReason,
  presetChecks,
  presetPolicy,
  validatePolicy,
} from "../lib/scan/registry";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";
const request = { method: "GET", url: "https://app.example.test/", headers: {}, body: "" };
function context(
  body = "",
  headers: Record<string, string> = {},
  cookies: string[] = [],
): ScanCheckContext {
  const response = {
    status: 200,
    responseBody: body,
    responseHeaders: headers,
    setCookies: cookies,
    duration: 1,
    size: body.length,
  };
  const exchange: Exchange = {
    response,
    evidence: {
      id: "captured",
      label: "Observed",
      timestamp: new Date().toISOString(),
      request,
      response,
      setCookies: cookies,
      duration: 1,
      size: body.length,
      truncated: false,
    },
  };
  return {
    request,
    baselines: [exchange],
    stable: false,
    probe: vi.fn(async () => {
      throw Error("Unexpected send");
    }),
    nonce: () => "marker",
  };
}
it("registers every executable check exactly once with honest execution metadata", () => {
  expect(new Set(checkRegistry.map((x) => x.id)).size).toBe(checkRegistry.length);
  for (const check of scanChecks) {
    const entry = metadata(check.id);
    expect(entry.status).not.toBe("planned");
    expect(entry.execution).not.toBe("automatic");
    expect(entry.impact === "passive").toBe(!check.active);
  }
  for (const entry of checkRegistry.filter((x) => x.status === "planned"))
    expect(scanChecks.some((x) => x.id === entry.id)).toBe(false);
});
it("presets never silently enable intrusive or planned checks", () => {
  for (const preset of ["passive", "balanced", "comprehensive"] as const) {
    const policy = presetPolicy(preset);
    validatePolicy(policy);
    for (const id of presetChecks("both", policy)) {
      expect(policyReason(id, policy)).toBeUndefined();
      expect(metadata(id).impact).not.toBe("intrusive");
    }
  }
  expect(
    policyReason("path-traversal", { ...defaultScanPolicy, maxImpact: "intrusive" }),
  ).toContain("opt-in");
  expect(
    policyReason("path-traversal", {
      ...defaultScanPolicy,
      maxImpact: "intrusive",
      allowIntrusive: true,
    }),
  ).toBeUndefined();
  expect(() => validatePolicy({ ...defaultScanPolicy, maxDurationMs: NaN })).toThrow();
  expect(() => validatePolicy({ ...defaultScanPolicy, requestTimeoutMs: 0 })).toThrow();
});
it("audits cookie identities, parent domains and browser prefix rules with masked values", async () => {
  const ctx = context("", {}, [
    "sid=secret-value; Domain=example.test; Path=/",
    "sid=other-secret; Domain=example.test; Path=/",
    "__Host-auth=hidden-value; SameSite=None",
  ]);
  const output = await cookieAudit.run(ctx);
  const titles = output.findings.map((x) => x.title).join(" ");
  expect(titles).toContain("Duplicate cookie");
  expect(titles).toContain("parent domain");
  expect(titles).toContain("__Host-");
  expect(titles).toContain("SameSite=None");
  expect(JSON.stringify(output)).not.toContain("secret-value");
  expect(ctx.probe).not.toHaveBeenCalled();
});
it("does not split collapsed cookies or flag deleted cookies", async () => {
  expect(
    (
      await cookieAudit.run(
        context("", { "set-cookie": "sid=value; Expires=Wed, 01 Jan 2030 00:00:00 GMT" }),
      )
    ).inconclusive,
  ).toBe(true);
  expect(
    (
      await cookieAudit.run(
        context("", {}, [
          "password=old-value; Max-Age=0",
          "__Host-old=old-value; Expires=Wed, 01 Jan 2020 00:00:00 GMT",
        ]),
      )
    ).findings,
  ).toHaveLength(0);
});
it("masks submitted passwords, connection strings and private JWK material", async () => {
  const value = "unique-test-password";
  const ctx = context(
    JSON.stringify({
      password: value,
      connection: "postgres://admin:private-pass@db/app",
      key: { kty: "RSA", d: "private-key-test-material" },
    }),
  );
  ctx.request = { ...request, method: "POST", body: JSON.stringify({ password: value }) };
  const output = await disclosureAudit.run(ctx);
  const titles = output.findings.map((x) => x.title).join(" ");
  expect(titles).toContain("Submitted password");
  expect(titles).toContain("connection string");
  expect(titles).toContain("Private JWK");
  expect(JSON.stringify(output)).not.toContain(value);
  expect(JSON.stringify(output)).not.toContain("private-pass");
  expect(JSON.stringify(output)).not.toContain("private-key-test-material");
});
it("distinguishes contextual PII and Luhn-valid candidates from arbitrary digit strings", async () => {
  const output = await disclosureAudit.run(context("SSN: 123-45-6789 card 4111 1111 1111 1111"));
  expect(output.findings.map((x) => x.title).join(" ")).toContain("payment card");
  expect(output.findings.map((x) => x.title).join(" ")).toContain("social security");
  expect(JSON.stringify(output)).not.toContain("123-45-6789");
  expect((await disclosureAudit.run(context("4111 1111 1111 1112"))).findings).toHaveLength(0);
});
it("audits effective CSP fallback and flags zero HSTS age without calling findings confirmed", async () => {
  const output = await policyAudit.run(
    context("<h1>test</h1>", {
      "content-type": "text/html",
      "content-security-policy":
        "default-src 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'",
      "strict-transport-security": "max-age=0",
    }),
  );
  expect(output.findings.some((x) => x.title.includes("unsafe-inline"))).toBe(false);
  expect(output.findings.some((x) => x.title.includes("HSTS"))).toBe(true);
  expect(output.findings.every((x) => x.status !== "verified")).toBe(true);
});
it("marks bounded disclosure analysis incomplete and leaves valid negative responses clean", async () => {
  expect((await disclosureAudit.run(context("a".repeat(256001)))).inconclusive).toBe(true);
  expect(
    (await policyAudit.run(context('{"ok":true}', { "content-type": "application/json" })))
      .findings,
  ).toHaveLength(0);
});
it("honors the first CSP directive and marks combined policies inconclusive", async () => {
  const output = await policyAudit.run(
    context("", {
      "content-type": "text/html",
      "content-security-policy":
        "script-src 'self'; script-src 'unsafe-eval'; object-src 'none'; base-uri 'self'",
    }),
  );
  expect(output.findings.some((x) => x.title.includes("unsafe-eval"))).toBe(false);
  expect(
    (
      await policyAudit.run(
        context("", {
          "content-type": "text/html",
          "content-security-policy": "script-src *, script-src 'self'",
        }),
      )
    ).inconclusive,
  ).toBe(true);
});
