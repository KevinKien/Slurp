import { beforeAll, afterAll, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { jwtConfusion } from "../lib/scan/jwt-confusion-check";
import { jwtSignature, encodeJwtPart, decodeJwtPart } from "../lib/scan/token-graphql-checks";
import { newScanPlan, ScanEngine, validateScanPlan } from "../lib/scan";
import type { ScanCheckContext, Exchange } from "../lib/scan/types";
import type { HttpRequest } from "../lib/traffic";
let token: string, publicPem: string, jwk: JsonWebKey & { kid: string };
let n = 0;
beforeAll(async () => {
  vi.stubGlobal("crypto", webcrypto);
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "fixture-key" };
  const der = await crypto.subtle.exportKey("spki", pair.publicKey);
  publicPem = `-----BEGIN PUBLIC KEY-----\n${Buffer.from(der)
    .toString("base64")
    .match(/.{1,64}/g)!
    .join("\n")}\n-----END PUBLIC KEY-----`;
  const input = `${encodeJwtPart({ alg: "RS256", kid: "fixture-key" })}.${encodeJwtPart({ sub: "alice", role: "user" })}`;
  token = `${input}.${Buffer.from(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(input))).toString("base64url")}`;
});
afterAll(() => vi.unstubAllGlobals());
const request = (): HttpRequest => ({
  method: "GET",
  url: "https://example.test/api/me",
  headers: { Authorization: `Bearer ${token}`, Cookie: "sid=private" },
  body: "",
});
function exchange(body = '{"user":"alice"}', status = 200): Exchange {
  return {
    response: { status, responseHeaders: {}, responseBody: body, duration: 1, size: body.length },
    evidence: {
      id: `jwt${++n}`,
      label: "fixture",
      timestamp: new Date().toISOString(),
      request: request(),
      setCookies: [],
      duration: 1,
      size: body.length,
      truncated: false,
    },
  };
}
async function server(r: HttpRequest, vulnerable = true): Promise<Exchange> {
  expect(r.headers).not.toHaveProperty("Cookie");
  const received = r.headers["Authorization"]?.replace(/^Bearer /, "") ?? "";
  if (received === token) return exchange();
  try {
    const [head, payload, signature] = received.split(".") as [string, string, string];
    const header = decodeJwtPart(head);
    expect(payload).toBe(token.split(".")[1]);
    if (vulnerable && header["alg"] === "HS256") {
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(publicPem),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"],
      );
      if (
        await crypto.subtle.verify(
          "HMAC",
          key,
          Uint8Array.from(Buffer.from(signature, "base64url")),
          new TextEncoder().encode(`${head}.${payload}`),
        )
      )
        return exchange();
    }
  } catch {
    /* deny */
  }
  return exchange("denied", 401);
}
function context(): ScanCheckContext {
  return {
    request: request(),
    baselines: [exchange(), exchange()],
    stable: true,
    nonce: () => `nonce${++n}`,
    probe: vi.fn((r: HttpRequest) => server(r)),
    jwtPublicKey: publicPem,
  };
}
it("verifies original RSA key then detects cryptographic HMAC confusion with unchanged claims", async () => {
  const out = await jwtConfusion.run(context());
  expect(out.findings[0]?.title).toContain("RS256 to HS256");
  expect(out.findings[0]?.evidenceIds.length).toBeGreaterThanOrEqual(11);
  expect(out.findings[0]?.status).toBe("needs_review");
});
it("rejects pinned algorithms, public endpoints, ignored signatures and invalid keys", async () => {
  const ctx = context();
  ctx.probe = vi.fn((r) => server(r, false));
  expect((await jwtConfusion.run(ctx)).findings).toHaveLength(0);
  ctx.probe = vi.fn(async () => exchange());
  expect((await jwtConfusion.run(ctx)).inconclusive).toBe(true);
  ctx.jwtPublicKey = "invalid";
  ctx.probe = vi.fn((r: HttpRequest) => server(r));
  expect((await jwtConfusion.run(ctx)).inconclusive).toBe(true);
  expect(ctx.probe).not.toHaveBeenCalled();
});
it("discovers same-origin public JWKS with matching kid and records resource evidence", async () => {
  const ctx = context();
  delete ctx.jwtPublicKey;
  ctx.loadJwtResource = vi.fn(async (url) =>
    url.endsWith("/jwks.json")
      ? exchange(JSON.stringify({ keys: [jwk] }))
      : exchange("missing", 404),
  );
  const out = await jwtConfusion.run(ctx);
  expect(out.findings).toHaveLength(1);
  expect(out.findings[0]?.excerpts.join(" ")).toContain("/.well-known/jwks.json");
  expect(ctx.loadJwtResource).toHaveBeenCalledTimes(3);
  expect(out.findings[0]?.evidenceIds.length).toBeGreaterThanOrEqual(14);
});
it("follows same-origin OpenID jwks_uri and refuses foreign origins or mismatched kid", async () => {
  const ctx = context();
  delete ctx.jwtPublicKey;
  ctx.loadJwtResource = vi.fn(async (url) =>
    url.endsWith("openid-configuration")
      ? exchange('{"jwks_uri":"https://example.test/keys/rsa"}')
      : url.endsWith("/keys/rsa")
        ? exchange(JSON.stringify({ keys: [jwk] }))
        : exchange("missing", 404),
  );
  expect((await jwtConfusion.run(ctx)).findings).toHaveLength(1);
  expect(ctx.loadJwtResource).toHaveBeenCalledWith("https://example.test/keys/rsa");
  ctx.loadJwtResource = vi.fn(async (url) =>
    url.endsWith("openid-configuration")
      ? exchange('{"jwks_uri":"https://foreign.test/keys"}')
      : exchange("missing", 404),
  );
  ctx.probe = vi.fn((r: HttpRequest) => server(r));
  expect((await jwtConfusion.run(ctx)).inconclusive).toBe(true);
  expect(ctx.loadJwtResource).toHaveBeenCalledTimes(3);
  expect(ctx.probe).not.toHaveBeenCalled();
  ctx.loadJwtResource = vi.fn(async () =>
    exchange(JSON.stringify({ keys: [{ ...jwk, kid: "wrong-key" }] })),
  );
  expect((await jwtConfusion.run(ctx)).inconclusive).toBe(true);
});
it("tests none, None, NONE and nOnE independently and respects strict validators", async () => {
  for (const casing of ["none", "None", "NONE", "nOnE"]) {
    const ctx = context();
    ctx.probe = vi.fn(async (r) => {
      const received = r.headers["Authorization"]?.replace(/^Bearer /, "");
      if (received === token) return exchange();
      try {
        if (decodeJwtPart(received!.split(".")[0]!)["alg"] === casing && received!.endsWith("."))
          return exchange();
      } catch {
        /* deny */
      }
      return exchange("denied", 401);
    });
    expect((await jwtSignature.run(ctx)).findings.map((f) => f.title)).toEqual([
      `JWT accepted with alg-${casing}`,
    ]);
  }
  const ctx = context();
  ctx.probe = vi.fn((r) => server(r, false));
  expect((await jwtSignature.run(ctx)).findings).toHaveLength(0);
});
it("engine discovers keys with anonymous GETs and suppresses cookie updates for JWT probes", async () => {
  const plan = {
    ...newScanPlan({ ...request(), method: "POST", body: '{"view":"me"}' }),
    mode: "active" as const,
    checks: ["jwt-confusion" as const],
    allowSending: true,
    rate: 20,
  };
  const receive = vi.fn();
  const send = vi.fn(async (r: HttpRequest) => {
    if (r.url !== plan.request.url) {
      expect(r.method).toBe("GET");
      expect(r.body).toBe("");
      expect(r.headers).toEqual({ Accept: "application/json" });
      expect(new URL(r.url).origin).toBe("https://example.test");
      return {
        ok: true as const,
        ...(r.url.endsWith("/jwks.json")
          ? exchange(JSON.stringify({ keys: [jwk] }))
          : exchange("missing", 404)
        ).response!,
      };
    }
    return { ok: true as const, ...(r.headers["Cookie"] ? exchange() : await server(r)).response! };
  });
  const run = await new ScanEngine(plan, { send, receive, isCurrent: () => true }).start();
  expect(run.status).toBe("completed");
  expect(run.findings[0]?.checkId).toBe("jwt-confusion");
  expect(run.evidence.filter((e) => e.label === "JWT public-key discovery")).toHaveLength(3);
  expect(receive).toHaveBeenCalledTimes(2);
  expect(() => validateScanPlan({ ...plan, jwtPublicKey: "-----BEGIN PRIVATE KEY-----" })).toThrow(
    "public PEM",
  );
});
it("does not classify arbitrary HMAC signature acceptance as RSA/HMAC confusion", async () => {
  const ctx = context();
  ctx.probe = vi.fn(async (r) => {
    const received = r.headers["Authorization"]?.replace(/^Bearer /, "");
    if (received === token) return exchange();
    try {
      if (decodeJwtPart(received!.split(".")[0]!)["alg"] === "HS256") return exchange();
    } catch {
      /* deny */
    }
    return exchange("denied", 401);
  });
  expect((await jwtConfusion.run(ctx)).findings).toHaveLength(0);
});
it("does not probe when the discovered RSA key cannot verify the captured signature", async () => {
  const ctx = context();
  delete ctx.jwtPublicKey;
  const [head, payload, signature] = token.split(".");
  ctx.request.headers["Authorization"] =
    `Bearer ${head}.${payload}.${signature![0] === "A" ? "B" : "A"}${signature!.slice(1)}`;
  ctx.loadJwtResource = vi.fn(async () => exchange(JSON.stringify({ keys: [jwk] })));
  expect((await jwtConfusion.run(ctx)).inconclusive).toBe(true);
  expect(ctx.probe).not.toHaveBeenCalled();
});
