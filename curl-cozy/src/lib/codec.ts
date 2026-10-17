/** Text encoders/decoders for the Tools page. All work happens locally in the browser. */

export type CodecId = 'base64' | 'base64url' | 'url' | 'html' | 'hex';

export const CODECS: { id: CodecId; label: string }[] = [
  { id: 'base64', label: 'Base64' },
  { id: 'base64url', label: 'Base64URL' },
  { id: 'url', label: 'URL' },
  { id: 'html', label: 'HTML entities' },
  { id: 'hex', label: 'Hex' },
];

export type CodecResult = { ok: true; value: string; note?: string } | { ok: false; error: string };

export interface CodecOptions {
  /** URL decode: treat "+" as a space (form encoding). */
  plusAsSpace?: boolean;
  /** HTML encode: also escape every non-ASCII character as a numeric entity. */
  escapeNonAscii?: boolean;
  /** Hex encode: text placed between bytes ("" , " " or ":"). */
  hexSeparator?: string;
  /** Hex encode: upper-case digits. */
  hexUpper?: boolean;
}

const utf8 = new TextEncoder();
const NOT_UTF8 = 'The bytes are not valid UTF-8; invalid sequences are shown as �.';

export function bytesToBinary(bytes: Uint8Array): string {
  // Chunked so large inputs don't overflow the argument limit of fromCharCode.
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return out;
}

export function binaryToBytes(binary: string): Uint8Array {
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Bytes to text, reporting whether they were valid UTF-8. */
function bytesToText(bytes: Uint8Array): { value: string; note?: string } {
  try {
    return { value: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
  } catch {
    return { value: new TextDecoder('utf-8').decode(bytes), note: NOT_UTF8 };
  }
}

// ── Base64 / Base64URL ──

export function base64EncodeBytes(bytes: Uint8Array, urlSafe = false): string {
  const b64 = btoa(bytesToBinary(bytes));
  return urlSafe ? b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : b64;
}

/** Decode standard or URL-safe Base64, with or without padding. Throws on invalid input. */
export function base64DecodeToBytes(input: string): Uint8Array {
  const clean = input.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(clean)) throw new Error('Not valid Base64: it contains characters outside A-Z a-z 0-9 + / - _ =');
  const stripped = clean.replace(/=+$/, '');
  if (stripped.length % 4 === 1) throw new Error('Not valid Base64: the length is impossible (a stray character is left over).');
  const standard = stripped.replace(/-/g, '+').replace(/_/g, '/');
  return binaryToBytes(atob(standard + '='.repeat((4 - (standard.length % 4)) % 4)));
}

// ── HTML entities ──

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '©', reg: '®', trade: '™',
  hellip: '…', mdash: '—', ndash: '–', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”',
  euro: '€', pound: '£', yen: '¥', cent: '¢', sect: '§', deg: '°', plusmn: '±',
  times: '×', divide: '÷', laquo: '«', raquo: '»', bull: '•', middot: '·',
};

/** Decode HTML entities using a built-in table (named entities beyond the common ones are left as written). */
export function decodeHtmlWithTable(input: string): string {
  return input.replace(/&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([A-Za-z][A-Za-z0-9]{1,31}));/g, (whole, dec, hex, name) => {
    if (name) return NAMED_ENTITIES[name] ?? whole;
    const code = dec ? Number(dec) : parseInt(hex, 16);
    // Out-of-range and surrogate code points are not characters; keep them as written.
    return code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff) ? String.fromCodePoint(code) : whole;
  });
}

function decodeHtml(input: string): string {
  if (typeof document === 'undefined') return decodeHtmlWithTable(input);
  // A textarea's content is plain text for the HTML parser, so nothing in the input is ever
  // interpreted as markup or executed; the browser just resolves the entities (all ~2,000 of them).
  const el = document.createElement('textarea');
  el.innerHTML = input;
  return el.value;
}

function encodeHtml(input: string, escapeNonAscii: boolean): string {
  const escaped = input.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
  return escapeNonAscii ? escaped.replace(/[^\x00-\x7f]/gu, (c) => `&#x${c.codePointAt(0)!.toString(16).toUpperCase()};`) : escaped;
}

// ── Hex ──

function hexEncode(bytes: Uint8Array, separator: string, upper: boolean): string {
  const digits = Array.from(bytes, (b) => b.toString(16).padStart(2, '0'));
  const joined = digits.join(separator);
  return upper ? joined.toUpperCase() : joined;
}

function hexDecodeToBytes(input: string): Uint8Array {
  // Tolerate the usual ways of writing hex bytes: spaces, 0x, \x, colons, dashes, commas.
  const clean = input.replace(/0x|\\x/gi, '').replace(/[\s:,-]+/g, '');
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('Not valid hex: use only 0-9 and a-f.');
  if (clean.length % 2 !== 0) throw new Error('Not valid hex: an odd number of digits (each byte needs two).');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

// ── Public API ──

export function encode(codec: CodecId, text: string, options: CodecOptions = {}): string {
  switch (codec) {
    case 'base64':
      return base64EncodeBytes(utf8.encode(text));
    case 'base64url':
      return base64EncodeBytes(utf8.encode(text), true);
    case 'url':
      return encodeURIComponent(text);
    case 'html':
      return encodeHtml(text, !!options.escapeNonAscii);
    case 'hex':
      return hexEncode(utf8.encode(text), options.hexSeparator ?? '', !!options.hexUpper);
  }
}

export function decode(codec: CodecId, text: string, options: CodecOptions = {}): CodecResult {
  try {
    switch (codec) {
      case 'base64':
      case 'base64url':
        return { ok: true, ...bytesToText(base64DecodeToBytes(text)) };
      case 'url':
        return { ok: true, value: decodeURIComponent(options.plusAsSpace ? text.replace(/\+/g, ' ') : text) };
      case 'html':
        return { ok: true, value: decodeHtml(text) };
      case 'hex':
        return { ok: true, ...bytesToText(hexDecodeToBytes(text)) };
    }
  } catch (e) {
    if (e instanceof URIError) return { ok: false, error: 'Not valid URL encoding: a "%" is not followed by two hex digits (or the bytes are not UTF-8).' };
    return { ok: false, error: e instanceof Error ? e.message : 'Could not decode' };
  }
}
