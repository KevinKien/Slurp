import type { ScanCheck } from "./types";
import { observation, result } from "./extended-checks";

// Deliberately small local dictionary. Tokens and candidate keys never leave this process.
const candidates = [
  "secret",
  "secretkey",
  "secret-key",
  "your-256-bit-secret",
  "your-secret-key",
  "your_jwt_secret",
  "jwt_secret",
  "jwt-secret",
  "jwtsecret",
  "changeme",
  "change-me",
  "supersecret",
  "supersecretkey",
  "password",
  "123456",
  "test",
  "development",
  "slurp",
];
function bytes(segment: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw Error("Invalid JWT encoding");
  return Uint8Array.from(atob(segment.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0),
  );
}
export const jwtWeakSecret: ScanCheck = {
  id: "jwt-weak-secret",
  name: "JWT weak HMAC signing secret (local verification)",
  active: false,
  perParameter: false,
  async run(ctx) {
    if (!ctx.baselines[0]?.response) return result("Captured response evidence required.", true);
    const auth = Object.entries(ctx.request.headers).find(
      ([key]) => key.toLowerCase() === "authorization",
    )?.[1];
    const token = auth?.match(/^Bearer ([\w-]+\.[\w-]+\.[\w-]+)$/i)?.[1];
    if (!token) return result("Signed Bearer JWT required for local HMAC analysis.", true);
    if (token.length > 24000) return result("JWT exceeds local analysis limit.", true);
    if (!globalThis.crypto?.subtle)
      return result("Web Crypto unavailable; use localhost or HTTPS.", true);
    const [head, payload, signature] = token.split(".") as [string, string, string];
    let alg: string, sig: Uint8Array<ArrayBuffer>;
    try {
      const header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes(head)));
      const claims = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes(payload)));
      if (
        !header ||
        typeof header !== "object" ||
        !claims ||
        typeof claims !== "object" ||
        Array.isArray(claims)
      )
        throw Error("Invalid JWT JSON");
      alg = header.alg;
      sig = bytes(signature);
    } catch {
      return result("Malformed JWT; local signature analysis skipped.", true);
    }
    const hashes: Record<string, { hash: string; length: number }> = {
      HS256: { hash: "SHA-256", length: 32 },
      HS384: { hash: "SHA-384", length: 48 },
      HS512: { hash: "SHA-512", length: 64 },
    };
    const config = Object.hasOwn(hashes, alg) ? hashes[alg] : undefined;
    if (!config) return result("Local weak-secret analysis supports HS256, HS384 and HS512 only.");
    if (sig.length !== config.length) return result("Invalid HMAC signature length.", true);
    const input = new TextEncoder().encode(`${head}.${payload}`);
    for (const candidate of candidates) {
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(candidate),
        { name: "HMAC", hash: config.hash },
        false,
        ["verify"],
      );
      if (!(await crypto.subtle.verify("HMAC", key, sig, input))) continue;
      const output = observation(
        "JWT signed with a common weak HMAC secret",
        "A bounded local dictionary candidate cryptographically verifies the captured JWT signature. No token was sent, changed or forged. This establishes a guessable signing key for this token; current server acceptance and account impact were not tested.",
        ctx.baselines.slice(0, 1),
        [`Algorithm: ${alg}`, "Common dictionary secret matched; key omitted from report"],
        "high",
      );
      const finding = output.findings[0]!;
      finding.confidence = "high";
      finding.status = "verified";
      finding.verification = {
        method: "local HMAC signature verification",
        outcome: "confirmed",
        reason:
          "A common dictionary key verifies the original signed bytes; server acceptance was not tested.",
      };
      finding.remediation =
        "Rotate the signing key to a cryptographically random secret, invalidate affected tokens and store signing keys outside source code.";
      return output;
    }
    return result(
      `No match in ${candidates.length} local HMAC candidates; key strength is not established.`,
    );
  },
};
