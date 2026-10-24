import { beforeAll, afterAll, expect, it, vi } from "vitest";
import { webcrypto, X509Certificate, createPublicKey } from "node:crypto";
import { jwtKeyChecks } from "../lib/scan/jwt-key-checks";
import { jwtConfusion } from "../lib/scan/jwt-confusion-check";
import { encodeJwtPart, decodeJwtPart } from "../lib/scan/token-graphql-checks";
import {
  selfSignedCertificate,
  parsePublicPem,
  pkcs1FromSpki,
  toPem,
  base64url,
  unbase64,
} from "../lib/scan/rsa-material";
import type { Exchange, OastProbe, ScanCheckContext } from "../lib/scan/types";
import type { HttpRequest } from "../lib/traffic";
let rsa: CryptoKeyPair, original: string, cert: string;
let count = 0;
const claims = encodeJwtPart({ sub: "alice", role: "user" });
beforeAll(async () => {
  vi.stubGlobal("crypto", webcrypto);
  rsa = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const input = `${encodeJwtPart({ alg: "RS256", kid: "original" })}.${claims}`;
  original = `${input}.${base64url(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", rsa.privateKey, new TextEncoder().encode(input)))}`;
  cert = await selfSignedCertificate(rsa);
});
afterAll(() => vi.unstubAllGlobals());
const request = (): HttpRequest => ({
  method: "GET",
  url: "http://localhost:8088/api/me",
  headers: { Authorization: `Bearer ${original}`, Cookie: "sid=private" },
  body: "",
});
function exchange(body = '{"user":"alice"}', status = 200): Exchange {
  return {
    response: { status, responseBody: body, responseHeaders: {}, duration: 1, size: body.length },
    evidence: {
      id: `key${++count}`,
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
function context() {
  const materials = new Map<string, { body: string; probe: OastProbe }>();
  const makeProbe = (): OastProbe => ({
    id: `p${++count}`,
    url: `http://collector.test/key${count}`,
    expiresAt: new Date(Date.now() + 600000).toISOString(),
    events: [],
  });
  const ctx: ScanCheckContext = {
    request: request(),
    baselines: [exchange(), exchange()],
    stable: true,
    nonce: () => `nonce${++count}`,
    probe: vi.fn(async (r) => {
      expect(r.headers).not.toHaveProperty("Cookie");
      const token = r.headers["Authorization"]?.replace(/^Bearer /, "");
      if (token === original) return exchange();
      try {
        const [head, payload, signature] = token!.split(".") as [string, string, string];
        const h = decodeJwtPart(head);
        if (payload !== claims) return exchange("claims changed", 401);
        let key: CryptoKey | undefined;
        if (h["jwk"])
          key = await crypto.subtle.importKey(
            "jwk",
            h["jwk"] as JsonWebKey,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            false,
            ["verify"],
          );
        for (const source of [h["jku"], h["x5u"]])
          if (typeof source === "string") {
            const material = materials.get(source);
            if (!material) continue;
            material.probe.events.push({
              protocol: "http",
              timestamp: new Date().toISOString(),
              peer: "127.0.0.1",
              detail: "GET key",
            });
            if (source === h["jku"])
              key = await crypto.subtle.importKey(
                "jwk",
                JSON.parse(material.body).keys[0],
                { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                false,
                ["verify"],
              );
            else
              key = await crypto.subtle.importKey(
                "spki",
                parsePublicPem(material.body).spki,
                { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                false,
                ["verify"],
              );
          }
        if (
          key &&
          (await crypto.subtle.verify(
            "RSASSA-PKCS1-v1_5",
            key,
            unbase64(signature),
            new TextEncoder().encode(`${head}.${payload}`),
          ))
        )
          return exchange();
      } catch {
        /* denied */
      }
      return exchange("denied", 401);
    }),
    oast: {
      issue: vi.fn(async () => makeProbe()),
      publishKey: vi.fn(async (material) => {
        const probe = makeProbe();
        materials.set(probe.url, { body: material.body, probe });
        return probe;
      }),
      poll: vi.fn(async (p) => materials.get(p.url)?.probe ?? p),
      wait: async () => {},
    },
  };
  return ctx;
}
for (const id of ["jwt-jwk", "jwt-jku", "jwt-x5u"])
  it(`${id} requires cryptographic acceptance and rejects wrong signatures`, async () => {
    const ctx = context();
    const check = jwtKeyChecks.find((c) => c.id === id)!;
    const out = await check.run(ctx);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]?.severity).toBe("high");
    expect(out.findings[0]?.status).toBe("needs_review");
    ctx.probe = vi.fn(async (r) =>
      r.headers["Authorization"] === `Bearer ${original}` ? exchange() : exchange("denied", 401),
    );
    expect((await check.run(ctx)).findings).toHaveLength(0);
  });
it("never reports key-source authentication bypass for callbacks alone or ignored signatures", async () => {
  const ctx = context();
  ctx.probe = vi.fn(async () => exchange());
  expect((await jwtKeyChecks[1]!.run(ctx)).findings).toHaveLength(0);
  const missing = context();
  delete missing.oast;
  expect((await jwtKeyChecks[2]!.run(missing)).inconclusive).toBe(true);
});
it("PKCS#1 and certificate SPKI extraction match the original RSA key and certificate signature", async () => {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey));
  const pkcs1 = pkcs1FromSpki(spki);
  expect(parsePublicPem(toPem("RSA PUBLIC KEY", pkcs1)).spki).toEqual(spki);
  expect(parsePublicPem(cert).spki).toEqual(spki);
  const x509 = new X509Certificate(cert);
  expect(x509.verify(x509.publicKey)).toBe(true);
  expect(x509.publicKey.export({ type: "spki", format: "der" })).toEqual(Buffer.from(spki));
  expect(createPublicKey(toPem("RSA PUBLIC KEY", pkcs1)).asymmetricKeyType).toBe("rsa");
  expect(() =>
    parsePublicPem("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"),
  ).toThrow();
  expect(() => parsePublicPem(toPem("CERTIFICATE", Uint8Array.of(0x30, 0x82, 0xff)))).toThrow();
});
it("confusion accepts PKCS#1 and certificate inputs while still verifying original RSA signature", async () => {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey));
  for (const value of [toPem("RSA PUBLIC KEY", pkcs1FromSpki(spki)), cert]) {
    const ctx = context();
    ctx.jwtPublicKey = value;
    ctx.probe = vi.fn(async (r) =>
      r.headers["Authorization"] === `Bearer ${original}` ? exchange() : exchange("denied", 401),
    );
    const out = await jwtConfusion.run(ctx);
    expect(out.inconclusive).not.toBe(true);
    expect(out.findings).toHaveLength(0);
  }
});
it("kid null-file bypass must pass HMAC verification and reject unknown key identifiers", async () => {
  const ctx = context();
  const secret = new TextEncoder().encode("fixture-original-secret");
  const key = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const input = `${encodeJwtPart({ alg: "HS256", kid: "original" })}.${claims}`;
  const token = `${input}.${base64url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input)))}`;
  ctx.request.headers = { Authorization: `Bearer ${token}` };
  ctx.probe = vi.fn(async (r) => {
    const t = r.headers["Authorization"]?.replace(/^Bearer /, "");
    if (t === token) return exchange();
    try {
      const [head, payload, signature] = t!.split(".") as [string, string, string];
      const h = decodeJwtPart(head);
      if (typeof h["kid"] === "string" && h["kid"].endsWith("/dev/null")) {
        const k = await crypto.subtle.importKey(
          "raw",
          Uint8Array.of(0),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["verify"],
        );
        if (
          await crypto.subtle.verify(
            "HMAC",
            k,
            unbase64(signature),
            new TextEncoder().encode(`${head}.${payload}`),
          )
        )
          return exchange();
      }
    } catch {
      /* denied */
    }
    return exchange("denied", 401);
  });
  const out = await jwtKeyChecks.find((c) => c.id === "jwt-kid")!.run(ctx);
  expect(out.findings[0]?.title).toContain("null-file");
});
it("detects algorithm confusion when the HMAC secret is PKCS#1 PEM or certificate PEM", async () => {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey));
  for (const publicMaterial of [toPem("RSA PUBLIC KEY", pkcs1FromSpki(spki)), cert]) {
    const ctx = context(); ctx.jwtPublicKey = publicMaterial;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(publicMaterial), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    ctx.probe = vi.fn(async r => {
      const token = r.headers["Authorization"]?.replace(/^Bearer /, ""); if (token === original) return exchange();
      try {
        const [head,payload,signature] = token!.split(".") as [string,string,string];
        if (decodeJwtPart(head)["alg"] === "HS256" && await crypto.subtle.verify("HMAC", key, unbase64(signature), new TextEncoder().encode(`${head}.${payload}`))) return exchange();
      } catch { /* denied */ }
      return exchange("denied", 401);
    });
    expect((await jwtConfusion.run(ctx)).findings[0]?.title).toContain("RS256 to HS256");
  }
});
