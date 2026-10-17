/**
 * JWT (JWS) tools built on the browser's Web Crypto API. Secrets and private keys are used
 * locally and never leave the page.
 */
import { base64DecodeToBytes, base64EncodeBytes } from './codec';

export const JWT_ALGS = [
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'none',
] as const;
export type JwtAlg = (typeof JWT_ALGS)[number];

const isJwtAlg = (v: unknown): v is JwtAlg => typeof v === 'string' && (JWT_ALGS as readonly string[]).includes(v);

const textEncoder = new TextEncoder();
const b64u = (bytes: Uint8Array) => base64EncodeBytes(bytes, true);
const b64uText = (text: string) => b64u(textEncoder.encode(text));

// ── Algorithm details ──

type Family = 'HS' | 'RS' | 'PS' | 'ES';
const HASH: Record<string, string> = { '256': 'SHA-256', '384': 'SHA-384', '512': 'SHA-512' };
// DER encodings of the curve OIDs: prime256v1, secp384r1, secp521r1.
const CURVES: Record<string, { name: string; oid: number[] }> = {
  '256': { name: 'P-256', oid: [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] },
  '384': { name: 'P-384', oid: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] },
  '512': { name: 'P-521', oid: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23] },
};

function algInfo(alg: Exclude<JwtAlg, 'none'>) {
  const family = alg.slice(0, 2) as Family;
  const bits = alg.slice(2);
  return { family, bits, hash: HASH[bits]!, curve: CURVES[bits]! };
}

/** Parameters for importing a key of this algorithm. */
function importParams(alg: Exclude<JwtAlg, 'none'>): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams {
  const { family, hash, curve } = algInfo(alg);
  switch (family) {
    case 'HS':
      return { name: 'HMAC', hash };
    case 'RS':
      return { name: 'RSASSA-PKCS1-v1_5', hash };
    case 'PS':
      return { name: 'RSA-PSS', hash };
    case 'ES':
      return { name: 'ECDSA', namedCurve: curve.name };
  }
}

/** Parameters for signing/verifying. RSA-PSS uses a salt as long as the hash (RFC 7518). */
function signParams(alg: Exclude<JwtAlg, 'none'>): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  const { family, hash, bits } = algInfo(alg);
  switch (family) {
    case 'HS':
      return { name: 'HMAC' };
    case 'RS':
      return { name: 'RSASSA-PKCS1-v1_5' };
    case 'PS':
      return { name: 'RSA-PSS', saltLength: Number(bits) / 8 };
    case 'ES':
      return { name: 'ECDSA', hash };
  }
}

// ── Minimal DER/PEM helpers (enough to wrap legacy key formats for Web Crypto) ──

const concat = (...parts: (Uint8Array | number[])[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};

function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return [0x80 | bytes.length, ...bytes];
}

const der = (tag: number, content: Uint8Array | number[]) => concat([tag], derLength(content.length), content);

const OID_RSA = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/** RSA PKCS#1 private key -> PKCS#8. */
const rsaPkcs1ToPkcs8 = (pkcs1: Uint8Array) =>
  der(0x30, concat([0x02, 0x01, 0x00], der(0x30, concat(OID_RSA, [0x05, 0x00])), der(0x04, pkcs1)));

/** RSA PKCS#1 public key -> SubjectPublicKeyInfo. */
const rsaPkcs1ToSpki = (pkcs1: Uint8Array) =>
  der(0x30, concat(der(0x30, concat(OID_RSA, [0x05, 0x00])), der(0x03, concat([0x00], pkcs1))));

/** SEC1 EC private key -> PKCS#8, for the curve the algorithm requires. */
const sec1ToPkcs8 = (sec1: Uint8Array, curveOid: number[]) =>
  der(0x30, concat([0x02, 0x01, 0x00], der(0x30, concat(OID_EC, curveOid)), der(0x04, sec1)));

interface Pem {
  label: string;
  bytes: Uint8Array;
}

function parsePem(text: string): Pem {
  if (/ENCRYPTED/.test(text)) {
    throw new Error('Encrypted private keys are not supported. Decrypt it first, e.g. openssl pkcs8 -in key.pem -out plain.pem');
  }
  const m = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(text.trim());
  if (!m) throw new Error('Expected a PEM key ("-----BEGIN ... KEY-----").');
  try {
    return { label: m[1]!, bytes: base64DecodeToBytes(m[2]!) };
  } catch {
    throw new Error('The PEM body is not valid Base64.');
  }
}

const toBuffer = (bytes: Uint8Array): ArrayBuffer => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

const MISMATCH = (alg: string) => new Error(`The key does not match ${alg} (wrong key type or curve).`);

/** Import a PEM private key (PKCS#8, RSA PKCS#1 or EC SEC1) for the given algorithm. */
async function importPrivateKey(alg: Exclude<JwtAlg, 'none'>, pem: Pem, extractable: boolean, usage: KeyUsage): Promise<CryptoKey> {
  const { family, curve } = algInfo(alg);
  let pkcs8: Uint8Array;
  switch (pem.label) {
    case 'PRIVATE KEY':
      pkcs8 = pem.bytes;
      break;
    case 'RSA PRIVATE KEY':
      pkcs8 = rsaPkcs1ToPkcs8(pem.bytes);
      break;
    case 'EC PRIVATE KEY':
      pkcs8 = sec1ToPkcs8(pem.bytes, curve.oid);
      break;
    default:
      throw new Error(`Unsupported key type "${pem.label}". Use a PRIVATE KEY (PKCS#8), RSA PRIVATE KEY or EC PRIVATE KEY.`);
  }
  if (family === 'HS') throw new Error('HS algorithms use a shared secret, not a PEM key.');
  try {
    return await crypto.subtle.importKey('pkcs8', toBuffer(pkcs8), importParams(alg) as RsaHashedImportParams, extractable, [usage]);
  } catch {
    throw MISMATCH(alg);
  }
}

/** The key used to verify: a public key as given, or the public half of a private key. */
async function importVerifyKey(alg: Exclude<JwtAlg, 'none'>, keyText: string): Promise<CryptoKey> {
  const pem = parsePem(keyText);
  if (/PRIVATE KEY$/.test(pem.label)) {
    // Web Crypto cannot derive a public key directly; go through JWK and keep only the public fields.
    const priv = await importPrivateKey(alg, pem, true, 'sign');
    const jwk = await crypto.subtle.exportKey('jwk', priv);
    const pub: JsonWebKey = jwk.kty === 'RSA' ? { kty: 'RSA', n: jwk.n!, e: jwk.e!, ext: true } : { kty: 'EC', crv: jwk.crv!, x: jwk.x!, y: jwk.y!, ext: true };
    try {
      return await crypto.subtle.importKey('jwk', pub, importParams(alg) as RsaHashedImportParams, false, ['verify']);
    } catch {
      throw MISMATCH(alg);
    }
  }
  let spki: Uint8Array;
  if (pem.label === 'PUBLIC KEY') spki = pem.bytes;
  else if (pem.label === 'RSA PUBLIC KEY') spki = rsaPkcs1ToSpki(pem.bytes);
  else throw new Error(`Unsupported key type "${pem.label}". Use a PUBLIC KEY (SPKI), RSA PUBLIC KEY, or a private key.`);
  try {
    return await crypto.subtle.importKey('spki', toBuffer(spki), importParams(alg) as RsaHashedImportParams, false, ['verify']);
  } catch {
    throw MISMATCH(alg);
  }
}

export type SecretEncoding = 'text' | 'base64';

async function importSecret(alg: Exclude<JwtAlg, 'none'>, secret: string, encoding: SecretEncoding, usage: KeyUsage): Promise<CryptoKey> {
  let bytes: Uint8Array;
  try {
    bytes = encoding === 'base64' ? base64DecodeToBytes(secret) : textEncoder.encode(secret);
  } catch {
    throw new Error('The secret is not valid Base64 (or switch the secret to plain text).');
  }
  if (bytes.length === 0) throw new Error('The secret must not be empty.');
  return crypto.subtle.importKey('raw', toBuffer(bytes), importParams(alg) as HmacImportParams, false, [usage]);
}

// ── Decode ──

export interface DecodedJwt {
  header: Record<string, unknown>;
  /** The parsed payload, or the raw text when it is not JSON. */
  payload: unknown;
  signature: string;
  alg: string | undefined;
}

function decodePart(part: string, what: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(base64DecodeToBytes(part));
  } catch {
    throw new Error(`The ${what} is not valid Base64URL text.`);
  }
}

/** Split and decode a token (a leading "Bearer " is accepted). Throws with a user-facing reason. */
export function decodeJwt(token: string): DecodedJwt {
  const parts = token.trim().replace(/^bearer\s+/i, '').split('.');
  if (parts.length !== 3) {
    throw new Error(parts.length === 5 ? 'This looks like an encrypted JWT (JWE, 5 parts). Only signed tokens (3 parts) can be decoded here.' : `A signed JWT has 3 dot-separated parts, this has ${parts.length}.`);
  }
  const headerText = decodePart(parts[0]!, 'header');
  let header: unknown;
  try {
    header = JSON.parse(headerText);
  } catch {
    throw new Error('The header is not valid JSON.');
  }
  if (typeof header !== 'object' || header === null || Array.isArray(header)) throw new Error('The header must be a JSON object.');

  const payloadText = decodePart(parts[1]!, 'payload');
  let payload: unknown = payloadText;
  try {
    payload = JSON.parse(payloadText);
  } catch {
    // Not JSON (allowed by JWS): show the raw text.
  }
  const alg = (header as Record<string, unknown>)['alg'];
  return { header: header as Record<string, unknown>, payload, signature: parts[2]!, alg: typeof alg === 'string' ? alg : undefined };
}

// ── Verify ──

export type VerifyResult =
  | { status: 'valid' | 'invalid' | 'unsigned' | 'no-key'; message: string }
  | { status: 'error'; message: string };

export interface VerifyOptions {
  /** Secret (HS*) or PEM public/private key (RS*, PS*, ES*). */
  key: string;
  secretEncoding?: SecretEncoding;
}

/** Check a token's signature with the algorithm named in its own header. */
export async function verifyJwt(token: string, options: VerifyOptions): Promise<VerifyResult> {
  let decoded: DecodedJwt;
  try {
    decoded = decodeJwt(token);
  } catch (e) {
    return { status: 'error', message: e instanceof Error ? e.message : 'Invalid token' };
  }
  const { alg, signature } = decoded;
  if (!isJwtAlg(alg)) return { status: 'error', message: `Unsupported algorithm: ${alg === undefined ? 'no "alg" in the header' : `"${alg}"`}.` };
  if (alg === 'none') {
    return { status: 'unsigned', message: 'alg is "none": the token is unsigned, so there is nothing to verify (and it should not be trusted).' };
  }
  if (!options.key.trim()) return { status: 'no-key', message: alg.startsWith('HS') ? 'Enter the secret to verify the signature.' : 'Enter the public or private key to verify the signature.' };

  try {
    const key = alg.startsWith('HS')
      ? await importSecret(alg, options.key, options.secretEncoding ?? 'text', 'verify')
      : await importVerifyKey(alg, options.key);
    const signingInput = textEncoder.encode(token.trim().replace(/^bearer\s+/i, '').split('.').slice(0, 2).join('.'));
    let sig: Uint8Array;
    try {
      sig = base64DecodeToBytes(signature);
    } catch {
      return { status: 'invalid', message: 'The signature is not valid Base64URL.' };
    }
    const ok = await crypto.subtle.verify(signParams(alg), key, toBuffer(sig), toBuffer(signingInput));
    return ok ? { status: 'valid', message: 'Signature verified.' } : { status: 'invalid', message: 'Signature does not match: wrong key, or the token was modified.' };
  } catch (e) {
    return { status: 'error', message: e instanceof Error ? e.message : 'Could not verify' };
  }
}

// ── Sign ──

export interface SignOptions {
  alg: JwtAlg;
  /** Header as JSON text. Unless `exact`, `alg` is set to match `alg`. */
  headerText: string;
  payloadText: string;
  /** Secret (HS*) or PEM private key (RS*, PS*, ES*); unused for "none". */
  key?: string;
  secretEncoding?: SecretEncoding;
  /** Use the typed JSON byte for byte instead of re-serializing it (and keep its own "alg"). */
  exact?: boolean;
}

function parseJson(text: string, what: string): unknown {
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`The ${what} is not valid JSON${e instanceof Error ? `: ${e.message}` : '.'}`);
  }
}

/** Build and sign a token. Throws with a user-facing reason when an input is invalid. */
export async function signJwt(options: SignOptions): Promise<string> {
  const { alg, exact } = options;
  const header = parseJson(options.headerText, 'header');
  if (typeof header !== 'object' || header === null || Array.isArray(header)) throw new Error('The header must be a JSON object.');
  parseJson(options.payloadText, 'payload'); // validate

  const headerJson = exact ? options.headerText.trim() : JSON.stringify({ ...(header as object), alg });
  const payloadJson = exact ? options.payloadText.trim() : JSON.stringify(JSON.parse(options.payloadText));
  const signingInput = `${b64uText(headerJson)}.${b64uText(payloadJson)}`;

  if (alg === 'none') return `${signingInput}.`;
  const keyText = options.key ?? '';
  if (!keyText.trim()) throw new Error(alg.startsWith('HS') ? 'Enter a secret to sign with.' : 'Enter a private key (PEM) to sign with.');

  const key = alg.startsWith('HS')
    ? await importSecret(alg, keyText, options.secretEncoding ?? 'text', 'sign')
    : await importPrivateKey(alg, parsePem(keyText), false, 'sign');
  const signature = await crypto.subtle.sign(signParams(alg), key, toBuffer(textEncoder.encode(signingInput)));
  return `${signingInput}.${b64u(new Uint8Array(signature))}`;
}

// ── Claims ──

export interface ClaimTime {
  claim: 'iat' | 'nbf' | 'exp';
  iso: string;
  /** "expired", "not yet valid" or "ok" for exp/nbf; always "ok" for iat. */
  state: 'ok' | 'expired' | 'not-yet-valid';
  relative: string;
}

function relative(deltaSeconds: number): string {
  const abs = Math.abs(deltaSeconds);
  const units: [number, string][] = [[86400, 'day'], [3600, 'hour'], [60, 'minute'], [1, 'second']];
  const [size, name] = units.find(([s]) => abs >= s) ?? [1, 'second'];
  const n = Math.floor(abs / size);
  const text = `${n} ${name}${n === 1 ? '' : 's'}`;
  return deltaSeconds >= 0 ? `in ${text}` : `${text} ago`;
}

/** Human-readable times for the registered time claims, relative to `now`. */
export function describeClaimTimes(payload: unknown, now: number = Date.now()): ClaimTime[] {
  if (typeof payload !== 'object' || payload === null) return [];
  const out: ClaimTime[] = [];
  for (const claim of ['iat', 'nbf', 'exp'] as const) {
    const value = (payload as Record<string, unknown>)[claim];
    if (typeof value !== 'number' || !Number.isFinite(value) || Math.abs(value) > 8.64e12 / 1000) continue;
    const delta = value - now / 1000;
    out.push({
      claim,
      iso: new Date(value * 1000).toISOString(),
      state: claim === 'exp' && delta < 0 ? 'expired' : claim === 'nbf' && delta > 0 ? 'not-yet-valid' : 'ok',
      relative: relative(delta),
    });
  }
  return out;
}
