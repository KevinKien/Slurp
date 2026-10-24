/** Minimal bounded DER handling for RSA public material. No private PEM import. */
export const unbase64 = (s: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
export const base64 = (b: Uint8Array | ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(b)));
export const base64url = (b: ArrayBuffer | Uint8Array) =>
  base64(b).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
export function der(tag: number, ...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const size = parts.reduce((n, b) => n + b.length, 0);
  if (size > 20000) throw Error("DER exceeds limit");
  const len = size < 128 ? [size] : size < 256 ? [0x81, size] : [0x82, size >> 8, size & 255];
  return Uint8Array.from([tag, ...len, ...parts.flatMap((b) => [...b])]);
}
export function tlv(
  b: Uint8Array,
  at = 0,
): { tag: number; start: number; end: number; next: number; raw: Uint8Array<ArrayBuffer> } {
  const prefix = at;
  const tag = b[at++];
  let size = b[at++];
  if (tag === undefined || size === undefined) throw Error("Truncated DER");
  if (size & 128) {
    const count = size & 127;
    if (!count || count > 2 || at + count > b.length) throw Error("Invalid DER length");
    size = 0;
    for (let i = 0; i < count; i++) size = size * 256 + b[at++]!;
  }
  if (at + size > b.length) throw Error("Truncated DER value");
  return {
    tag,
    start: at,
    end: at + size,
    next: at + size,
    raw: Uint8Array.from(b.slice(prefix, at + size)),
  };
}
export function children(b: Uint8Array): Uint8Array<ArrayBuffer>[] {
  const outer = tlv(b);
  if (outer.tag !== 0x30 || outer.next !== b.length) throw Error("DER sequence required");
  const rows: Uint8Array<ArrayBuffer>[] = [];
  for (let at = outer.start; at < outer.end;) {
    const item = tlv(b, at);
    if (item.next > outer.end) throw Error("Invalid child");
    rows.push(item.raw);
    at = item.next;
    if (rows.length > 64) throw Error("Too many DER children");
  }
  return rows;
}
const rsaOid = Uint8Array.from([
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1, 5, 0,
]);
export function wrapPkcs1(pkcs1: Uint8Array) {
  return der(0x30, rsaOid, der(3, Uint8Array.of(0), pkcs1));
}
export function pkcs1FromSpki(spki: Uint8Array) {
  const rows = children(spki);
  const bits = tlv(rows[1]!);
  if (bits.tag !== 3 || rows[1]![bits.start] !== 0) throw Error("RSA bit string required");
  const result = rows[1]!.slice(bits.start + 1, bits.end);
  const ints = children(result);
  if (ints.length !== 2 || ints.some((i) => i[0] !== 2)) throw Error("RSA key required");
  return result;
}
export const toPem = (label: string, b: Uint8Array | ArrayBuffer) =>
  `-----BEGIN ${label}-----\n${base64(b)
    .match(/.{1,64}/g)!
    .join("\n")}\n-----END ${label}-----`;
export function parsePublicPem(value: string): {
  spki: Uint8Array<ArrayBuffer>;
  certificate?: Uint8Array<ArrayBuffer>;
} {
  if (value.length > 16000 || /PRIVATE KEY/.test(value)) throw Error("Public material only");
  const match = value
    .trim()
    .match(
      /^-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE)-----\s+([A-Za-z0-9+/=\s]+)\s+-----END \1-----$/,
    );
  if (!match) throw Error("Public PEM required");
  const b = unbase64(match[2]!.replace(/\s/g, ""));
  if (match[1] === "PUBLIC KEY") {
    children(b);
    return { spki: b };
  }
  if (match[1] === "RSA PUBLIC KEY") {
    const spki = wrapPkcs1(b);
    pkcs1FromSpki(spki);
    return { spki };
  }
  const cert = children(b);
  const fields = children(cert[0]!);
  const index = fields[0]?.[0] === 0xa0 ? 6 : 5;
  const spki = fields[index];
  if (!spki) throw Error("Missing certificate SPKI");
  pkcs1FromSpki(spki);
  return { spki, certificate: b };
}
export async function selfSignedCertificate(pair: CryptoKeyPair): Promise<string> {
  const algo = Uint8Array.from([
    0x30, 0x0d, 6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 11, 5, 0,
  ]);
  const utf8 = new TextEncoder();
  const name = der(
    0x30,
    der(
      0x31,
      der(
        0x30,
        Uint8Array.from([6, 3, 0x55, 4, 3]),
        der(12, utf8.encode("Slurp scan ephemeral key")),
      ),
    ),
  );
  const stamp = (ms: number) =>
    new Date(ms)
      .toISOString()
      .replace(/[-:T]/g, "")
      .replace(/\.\d{3}Z/, "Z");
  const now = Date.now();
  const validity = der(
    0x30,
    der(24, utf8.encode(stamp(now - 86400000))),
    der(24, utf8.encode(stamp(now + 86400000))),
  );
  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] = 1;
  const tbs = der(
    0x30,
    der(0xa0, der(2, Uint8Array.of(2))),
    der(2, serial),
    algo,
    name,
    validity,
    name,
    new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, tbs),
  );
  return toPem("CERTIFICATE", der(0x30, tbs, algo, der(3, Uint8Array.of(0), signature)));
}
