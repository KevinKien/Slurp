// @vitest-environment node
import { constants, createSign, createVerify, generateKeyPairSync, sign as nodeSign, verify as nodeVerify, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeJwt, describeClaimTimes, signJwt, verifyJwt, type JwtAlg } from '@/lib/jwt';

const HEADER = '{"alg":"HS256","typ":"JWT"}';
const PAYLOAD = '{"sub":"1234567890","name":"John Doe","iat":1516239022}';
// The well-known example token from jwt.io, signed with "your-256-bit-secret".
const JWT_IO = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

const b64uToBuf = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const parts = (token: string) => token.split('.') as [string, string, string];

describe('HMAC (HS*)', () => {
  it('reproduces the jwt.io reference token exactly', async () => {
    const token = await signJwt({ alg: 'HS256', headerText: HEADER, payloadText: PAYLOAD, key: 'your-256-bit-secret' });
    expect(token).toBe(JWT_IO);
  });

  it('verifies with the right secret and rejects a wrong one or a tampered token', async () => {
    expect(await verifyJwt(JWT_IO, { key: 'your-256-bit-secret' })).toMatchObject({ status: 'valid' });
    expect(await verifyJwt(JWT_IO, { key: 'wrong-secret' })).toMatchObject({ status: 'invalid' });
    const [h, , s] = parts(JWT_IO);
    const forgedPayload = Buffer.from('{"sub":"1","admin":true}').toString('base64url');
    expect(await verifyJwt(`${h}.${forgedPayload}.${s}`, { key: 'your-256-bit-secret' })).toMatchObject({ status: 'invalid' });
  });

  it('works for HS384 and HS512 and matches node:crypto', async () => {
    for (const [alg, hash] of [['HS384', 'sha384'], ['HS512', 'sha512']] as const) {
      const token = await signJwt({ alg, headerText: HEADER, payloadText: PAYLOAD, key: 'k3y' });
      const [h, p, s] = parts(token);
      const { createHmac } = await import('node:crypto');
      expect(b64uToBuf(s).equals(createHmac(hash, 'k3y').update(`${h}.${p}`).digest())).toBe(true);
      expect(await verifyJwt(token, { key: 'k3y' })).toMatchObject({ status: 'valid' });
      expect(decodeJwt(token).alg).toBe(alg);
    }
  });

  it('accepts a base64-encoded secret', async () => {
    const secret = Buffer.from('binary-secret-ÿ\u0000').toString('base64');
    const token = await signJwt({ alg: 'HS256', headerText: HEADER, payloadText: PAYLOAD, key: secret, secretEncoding: 'base64' });
    expect(await verifyJwt(token, { key: secret, secretEncoding: 'base64' })).toMatchObject({ status: 'valid' });
    expect(await verifyJwt(token, { key: secret })).toMatchObject({ status: 'invalid' });
  });

  it('refuses an empty secret and a bad base64 secret', async () => {
    await expect(signJwt({ alg: 'HS256', headerText: HEADER, payloadText: PAYLOAD, key: '' })).rejects.toThrow(/secret/i);
    await expect(signJwt({ alg: 'HS256', headerText: HEADER, payloadText: PAYLOAD, key: '!!!', secretEncoding: 'base64' })).rejects.toThrow(/base64/i);
  });
});

describe('formatting of the signed token', () => {
  it('forces the selected alg into the header unless exact mode is on', async () => {
    const token = await signJwt({ alg: 'HS384', headerText: '{"typ":"JWT","alg":"HS256","kid":"k1"}', payloadText: '{"a":1}', key: 'k' });
    expect(decodeJwt(token).header).toEqual({ typ: 'JWT', alg: 'HS384', kid: 'k1' });
  });

  it('exact mode keeps the typed JSON byte for byte, even a misleading alg', async () => {
    const header = '{ "alg" : "HS256",  "typ":"JWT" }';
    const payload = '{\n  "a": 1,\n  "a": 2\n}';
    const token = await signJwt({ alg: 'HS512', headerText: header, payloadText: payload, key: 'k', exact: true });
    const [h, p] = parts(token);
    expect(Buffer.from(h, 'base64url').toString()).toBe(header);
    expect(Buffer.from(p, 'base64url').toString()).toBe(payload);
    expect(await verifyJwt(token, { key: 'k' })).toMatchObject({ status: 'invalid' }); // Signed with HS512, but verification follows the HS256 header.
  });

  it('rejects invalid JSON and non-object headers with a reason', async () => {
    await expect(signJwt({ alg: 'HS256', headerText: '{nope', payloadText: '{}', key: 'k' })).rejects.toThrow(/header is not valid JSON/);
    await expect(signJwt({ alg: 'HS256', headerText: '[]', payloadText: '{}', key: 'k' })).rejects.toThrow(/header must be a JSON object/);
    await expect(signJwt({ alg: 'HS256', headerText: '{}', payloadText: '{nope', key: 'k' })).rejects.toThrow(/payload is not valid JSON/);
  });
});

describe('alg none', () => {
  it('produces an unsigned token with an empty signature and reports it as unsigned', async () => {
    const token = await signJwt({ alg: 'none', headerText: '{"typ":"JWT"}', payloadText: '{"admin":true}' });
    expect(token.endsWith('.')).toBe(true);
    expect(decodeJwt(token).header).toEqual({ typ: 'JWT', alg: 'none' });
    expect(await verifyJwt(token, { key: 'anything' })).toMatchObject({ status: 'unsigned' });
  });
});

type Spec = { alg: JwtAlg; hash: string; type: 'rsa' | 'ec'; curve?: string; bits: number };
const SPECS: Spec[] = [
  { alg: 'RS256', hash: 'sha256', type: 'rsa', bits: 256 },
  { alg: 'RS384', hash: 'sha384', type: 'rsa', bits: 384 },
  { alg: 'RS512', hash: 'sha512', type: 'rsa', bits: 512 },
  { alg: 'PS256', hash: 'sha256', type: 'rsa', bits: 256 },
  { alg: 'PS384', hash: 'sha384', type: 'rsa', bits: 384 },
  { alg: 'PS512', hash: 'sha512', type: 'rsa', bits: 512 },
  { alg: 'ES256', hash: 'sha256', type: 'ec', curve: 'prime256v1', bits: 256 },
  { alg: 'ES384', hash: 'sha384', type: 'ec', curve: 'secp384r1', bits: 384 },
  { alg: 'ES512', hash: 'sha512', type: 'ec', curve: 'secp521r1', bits: 512 },
];

const rsaKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ecKeys: Record<string, { privateKey: KeyObject; publicKey: KeyObject }> = {
  prime256v1: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
  secp384r1: generateKeyPairSync('ec', { namedCurve: 'secp384r1' }),
  secp521r1: generateKeyPairSync('ec', { namedCurve: 'secp521r1' }),
};
const pair = (spec: Spec) => (spec.type === 'rsa' ? rsaKeys : ecKeys[spec.curve!]!);
const pem = (k: KeyObject, type: 'pkcs8' | 'pkcs1' | 'spki' | 'sec1') => k.export({ type, format: 'pem' } as never).toString();

/** Check a token's signature with node:crypto, independent of our own verify code. */
function nodeChecks(spec: Spec, token: string): boolean {
  const [h, p, s] = parts(token);
  const input = Buffer.from(`${h}.${p}`);
  const sig = b64uToBuf(s);
  const pub = pair(spec).publicKey;
  if (spec.alg.startsWith('RS')) return createVerify(`RSA-${spec.hash.toUpperCase()}`).update(input).verify(pub, sig);
  if (spec.alg.startsWith('PS')) {
    return nodeVerify(spec.hash, input, { key: pub, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: spec.bits / 8 }, sig);
  }
  return nodeVerify(spec.hash, input, { key: pub, dsaEncoding: 'ieee-p1363' }, sig);
}

describe.each(SPECS)('$alg with private/public keys', (spec) => {
  it('signs with a PKCS#8 private key; node:crypto accepts the signature', async () => {
    const token = await signJwt({ alg: spec.alg, headerText: HEADER, payloadText: PAYLOAD, key: pem(pair(spec).privateKey, 'pkcs8') });
    expect(nodeChecks(spec, token)).toBe(true);
    if (spec.type === 'ec') expect(b64uToBuf(parts(token)[2]).length).toBe(Math.ceil((spec.bits === 512 ? 521 : spec.bits) / 8) * 2); // raw r||s, not DER
  });

  it('verifies with the public key, and with the private key (derives the public half)', async () => {
    const token = await signJwt({ alg: spec.alg, headerText: HEADER, payloadText: PAYLOAD, key: pem(pair(spec).privateKey, 'pkcs8') });
    expect(await verifyJwt(token, { key: pem(pair(spec).publicKey, 'spki') })).toMatchObject({ status: 'valid' });
    expect(await verifyJwt(token, { key: pem(pair(spec).privateKey, 'pkcs8') })).toMatchObject({ status: 'valid' });
  });

  it('verifies a token signed by node:crypto', async () => {
    const [h, p] = [Buffer.from(JSON.stringify({ alg: spec.alg, typ: 'JWT' })).toString('base64url'), Buffer.from(PAYLOAD).toString('base64url')];
    const input = Buffer.from(`${h}.${p}`);
    const priv = pair(spec).privateKey;
    const signature = spec.alg.startsWith('RS')
      ? createSign(`RSA-${spec.hash.toUpperCase()}`).update(input).sign(priv)
      : spec.alg.startsWith('PS')
        ? nodeSign(spec.hash, input, { key: priv, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: spec.bits / 8 })
        : nodeSign(spec.hash, input, { key: priv, dsaEncoding: 'ieee-p1363' });
    const token = `${h}.${p}.${signature.toString('base64url')}`;
    expect(await verifyJwt(token, { key: pem(pair(spec).publicKey, 'spki') })).toMatchObject({ status: 'valid' });
  });

  it('rejects a different key and a modified token', async () => {
    const token = await signJwt({ alg: spec.alg, headerText: HEADER, payloadText: PAYLOAD, key: pem(pair(spec).privateKey, 'pkcs8') });
    const other = spec.type === 'rsa' ? generateKeyPairSync('rsa', { modulusLength: 2048 }) : generateKeyPairSync('ec', { namedCurve: spec.curve! });
    expect(await verifyJwt(token, { key: pem(other.publicKey, 'spki') })).toMatchObject({ status: 'invalid' });
    const [h, , s] = parts(token);
    const forged = `${h}.${Buffer.from('{"admin":true}').toString('base64url')}.${s}`;
    expect(await verifyJwt(forged, { key: pem(pair(spec).publicKey, 'spki') })).toMatchObject({ status: 'invalid' });
  });
});

describe('legacy key formats', () => {
  it('signs with an RSA PKCS#1 private key and verifies with an RSA PKCS#1 public key', async () => {
    const priv = pem(rsaKeys.privateKey, 'pkcs1');
    expect(priv).toContain('BEGIN RSA PRIVATE KEY');
    const token = await signJwt({ alg: 'RS256', headerText: HEADER, payloadText: PAYLOAD, key: priv });
    expect(nodeChecks(SPECS[0]!, token)).toBe(true);
    const pub = pem(rsaKeys.publicKey, 'pkcs1');
    expect(pub).toContain('BEGIN RSA PUBLIC KEY');
    expect(await verifyJwt(token, { key: pub })).toMatchObject({ status: 'valid' });
    expect(await verifyJwt(token, { key: priv })).toMatchObject({ status: 'valid' });
  });

  it('signs with an EC SEC1 private key for each curve', async () => {
    for (const spec of SPECS.filter((s) => s.type === 'ec')) {
      const priv = pem(pair(spec).privateKey, 'sec1');
      expect(priv).toContain('BEGIN EC PRIVATE KEY');
      const token = await signJwt({ alg: spec.alg, headerText: HEADER, payloadText: PAYLOAD, key: priv });
      expect(nodeChecks(spec, token)).toBe(true);
      expect(await verifyJwt(token, { key: priv })).toMatchObject({ status: 'valid' });
    }
  });
});

describe('key errors are explained', () => {
  it('rejects a key of the wrong type or curve for the algorithm', async () => {
    const ec = pem(ecKeys['prime256v1']!.privateKey, 'pkcs8');
    await expect(signJwt({ alg: 'RS256', headerText: HEADER, payloadText: PAYLOAD, key: ec })).rejects.toThrow(/does not match RS256/);
    await expect(signJwt({ alg: 'ES384', headerText: HEADER, payloadText: PAYLOAD, key: ec })).rejects.toThrow(/does not match ES384/);
    await expect(signJwt({ alg: 'ES256', headerText: HEADER, payloadText: PAYLOAD, key: pem(rsaKeys.privateKey, 'pkcs8') })).rejects.toThrow(/does not match ES256/);
  });

  it('rejects text that is not a key, encrypted keys, and unsupported PEM types', async () => {
    const base = { alg: 'RS256' as const, headerText: HEADER, payloadText: PAYLOAD };
    await expect(signJwt({ ...base, key: 'just some text' })).rejects.toThrow(/PEM/);
    await expect(signJwt({ ...base, key: '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----' })).rejects.toThrow(/Encrypted private keys are not supported/);
    await expect(signJwt({ ...base, key: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----' })).rejects.toThrow(/Unsupported key type/);
    await expect(signJwt({ ...base, key: '' })).rejects.toThrow(/private key/i);
    const token = await signJwt({ ...base, key: pem(rsaKeys.privateKey, 'pkcs8') });
    expect(await verifyJwt(token, { key: 'nope' })).toMatchObject({ status: 'error' });
    expect(await verifyJwt(token, { key: '' })).toMatchObject({ status: 'no-key' });
  });
});

describe('decodeJwt', () => {
  it('decodes header and payload, with an optional Bearer prefix', () => {
    const d = decodeJwt(`Bearer ${JWT_IO}`);
    expect(d.header).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(d.payload).toEqual({ sub: '1234567890', name: 'John Doe', iat: 1516239022 });
    expect(d.alg).toBe('HS256');
    expect(d.signature).toBe('SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
  });

  it('keeps a non-JSON payload as text', () => {
    const token = `${Buffer.from('{"alg":"HS256"}').toString('base64url')}.${Buffer.from('plain text').toString('base64url')}.x`;
    expect(decodeJwt(token).payload).toBe('plain text');
  });

  it('explains malformed tokens', () => {
    expect(() => decodeJwt('abc')).toThrow(/3 dot-separated parts, this has 1/);
    expect(() => decodeJwt('a.b.c.d.e')).toThrow(/JWE/);
    expect(() => decodeJwt('###.e30.x')).toThrow(/header is not valid Base64URL/);
    expect(() => decodeJwt(`${Buffer.from('nope').toString('base64url')}.e30.x`)).toThrow(/header is not valid JSON/);
    expect(() => decodeJwt(`${Buffer.from('[]').toString('base64url')}.e30.x`)).toThrow(/header must be a JSON object/);
    expect(() => decodeJwt(`${Buffer.from('{}').toString('base64url')}.###.x`)).toThrow(/payload is not valid Base64URL/);
  });

  it('verify reports unknown algorithms and bad tokens instead of throwing', async () => {
    const none = `${Buffer.from('{"typ":"JWT"}').toString('base64url')}.e30.x`;
    expect(await verifyJwt(none, { key: 'k' })).toMatchObject({ status: 'error', message: expect.stringMatching(/no "alg"/) });
    const weird = `${Buffer.from('{"alg":"HS999"}').toString('base64url')}.e30.x`;
    expect(await verifyJwt(weird, { key: 'k' })).toMatchObject({ status: 'error', message: expect.stringMatching(/HS999/) });
    expect(await verifyJwt('garbage', { key: 'k' })).toMatchObject({ status: 'error' });
  });
});

describe('describeClaimTimes', () => {
  const now = Date.UTC(2026, 9, 15, 12, 0, 0);
  const at = (secondsFromNow: number) => Math.floor(now / 1000) + secondsFromNow;

  it('flags expired and not-yet-valid tokens and describes times relative to now', () => {
    const claims = describeClaimTimes({ iat: at(-90), nbf: at(7200), exp: at(-86400 * 3) }, now);
    expect(claims.map((c) => [c.claim, c.state, c.relative])).toEqual([
      ['iat', 'ok', '1 minute ago'],
      ['nbf', 'not-yet-valid', 'in 2 hours'],
      ['exp', 'expired', '3 days ago'],
    ]);
    expect(claims[0]!.iso).toBe(new Date((at(-90)) * 1000).toISOString());
  });

  it('treats a future exp as ok and ignores missing, non-numeric and absurd values', () => {
    expect(describeClaimTimes({ exp: at(3600) }, now)).toMatchObject([{ claim: 'exp', state: 'ok', relative: 'in 1 hour' }]);
    expect(describeClaimTimes({ exp: '123', nbf: null, iat: 1e30 }, now)).toEqual([]);
    expect(describeClaimTimes('text', now)).toEqual([]);
    expect(describeClaimTimes(null, now)).toEqual([]);
  });
});
