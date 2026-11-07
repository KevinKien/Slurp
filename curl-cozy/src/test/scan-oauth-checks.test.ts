import { expect, it } from "vitest";
import { oauthChecks } from "../lib/scan/oauth-checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";

const base = "https://idp.test/oauth/authorize?client_id=app&response_type=code&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&state=xyz&nonce=n1";
const check = oauthChecks[0]!;
let next = 0;
function exchange(body = "", status = 200, headers: Record<string, string> = {}): Exchange {
  return {
    response: { status, responseHeaders: headers, responseBody: body, duration: 10, size: body.length },
    evidence: {
      id: `o${++next}`,
      label: "fixture",
      timestamp: new Date().toISOString(),
      request: { method: "GET", url: base, headers: {}, body: "" },
      setCookies: [],
      duration: 10,
      size: body.length,
      truncated: false,
    },
  };
}
function context(
  probe: ScanCheckContext["probe"],
  url = base,
  baselines: Exchange[] = [exchange("", 302, { location: "https://app.test/cb?code=x" })],
): ScanCheckContext {
  return {
    request: { method: "GET", url, headers: {}, body: "" },
    baselines,
    stable: true,
    probe,
    nonce: () => `marker${++next}`,
  };
}
function redirectTo(host: string) {
  return exchange("", 302, { location: `https://${host}/cb?code=abc` });
}

it("accepts only destinations whose parsed host is the attacker", async () => {
  const strict = context(async (request) => {
    const value = new URL(request.url).searchParams.get("redirect_uri") ?? "";
    try {
      const host = new URL(value, "https://idp.test").hostname;
      if (host.endsWith(".invalid")) return exchange("invalid redirect_uri", 400);
    } catch {
      return exchange("invalid", 400);
    }
    return request.url.startsWith("https://app.test/") ? exchange("app") : redirectTo("app.test");
  });
  expect((await check.run(strict)).findings).toHaveLength(0);

  const vulnerable = context(async (request) => {
    const value = new URL(request.url).searchParams.get("redirect_uri") ?? "";
    const host = new URL(value, "https://idp.test").hostname;
    return host.endsWith(".invalid") ? redirectTo(host) : redirectTo("app.test");
  });
  const direct = await check.run(vulnerable);
  expect(direct.findings).toHaveLength(1);
  expect(direct.findings[0]?.severity).toBe("high");
  expect(direct.findings[0]?.summary).toContain("no code or token was used");
});

it("finds prefix and suffix validation bypasses after a plain attacker origin is rejected", async () => {
  const ctx = context(async (request) => {
    const value = new URL(request.url).searchParams.get("redirect_uri") ?? "";
    const host = new URL(value, "https://idp.test").hostname;
    if (host.endsWith(".invalid") && !value.includes("@") && !value.includes("://app.test."))
      return exchange("invalid", 400);
    return host.endsWith(".invalid") ? redirectTo(host) : redirectTo("app.test");
  });
  const output = await check.run(ctx);
  expect(output.findings.some((finding) => finding.title.includes("bypass accepted"))).toBe(true);
});

it("reports missing state and unescaped form_post state", async () => {
  const withoutState = "https://idp.test/oauth/authorize?client_id=app&response_type=code&redirect_uri=https%3A%2F%2Fapp.test%2Fcb";
  const ctx = context(async (request) => {
    const url = new URL(request.url);
    if (url.searchParams.get("response_mode") === "form_post") {
      const state = url.searchParams.get("state") ?? "";
      const tag = /<([a-z][\w-]*)>/i.exec(state)?.[1];
      return exchange(
        tag
          ? `<html><body><form method="post"><input name="state" value="${state}"></form></body></html>`
          : "<html><body>form</body></html>",
      );
    }
    return redirectTo("app.test");
  }, withoutState);
  const output = await check.run(ctx);
  expect(output.findings.some((finding) => finding.title.includes("omits state"))).toBe(true);
  expect(output.findings.some((finding) => finding.title.includes("form_post"))).toBe(true);
});

it("reports a dangling callback host and an unverified ID-token email", async () => {
  const payload = btoa(JSON.stringify({ email: "victim@example.test", email_verified: false }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const idToken = `eyJhbGciOiJub25lIn0.${payload}.sig`;
  const body = JSON.stringify({ id_token: idToken });
  const ctx = context(async (request) => {
    if (new URL(request.url).hostname === "app.test") return exchange("NoSuchBucket");
    return redirectTo("app.test");
  }, base, [exchange(body, 302, { location: "https://app.test/cb?code=x" })]);
  const output = await check.run(ctx);
  expect(output.findings.some((finding) => finding.title.includes("callback host appears unclaimed"))).toBe(true);
  expect(output.findings.some((finding) => finding.title.includes("unverified email"))).toBe(true);
});
