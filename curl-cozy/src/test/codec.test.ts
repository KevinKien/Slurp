import { describe, expect, it } from 'vitest';
import { base64DecodeToBytes, decode, decodeHtmlWithTable, encode, type CodecId } from '@/lib/codec';
import { generateUuids } from '@/lib/uuid';

const ok = (codec: CodecId, text: string, options = {}) => {
  const r = decode(codec, text, options);
  if (!r.ok) throw new Error(r.error);
  return r;
};

describe('base64', () => {
  it('matches known vectors, including UTF-8 text', () => {
    expect(encode('base64', 'Hello, World!')).toBe('SGVsbG8sIFdvcmxkIQ==');
    expect(encode('base64', 'héllo ✓')).toBe('aMOpbGxvIOKckw==');
    expect(ok('base64', 'aMOpbGxvIOKckw==').value).toBe('héllo ✓');
    expect(encode('base64', '')).toBe('');
  });

  it('decodes with or without padding, ignoring whitespace and line breaks', () => {
    expect(ok('base64', 'SGVsbG8').value).toBe('Hello');
    expect(ok('base64', 'SGVs\nbG8g\r\nV29ybGQ=').value).toBe('Hello World');
  });

  it('base64url uses - and _ and drops padding, and either alphabet decodes', () => {
    const bytes = 'ûÿþ'; // encodes to +//+ in standard base64
    const std = encode('base64', bytes);
    const url = encode('base64url', bytes);
    expect(url).toBe(std.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    expect(url).not.toMatch(/[+/=]/);
    expect(ok('base64url', url).value).toBe(bytes);
    expect(ok('base64', url).value).toBe(bytes);
  });

  it('round-trips arbitrary text', () => {
    for (const text of ['a', 'ab', 'abc', 'abcd', '\n\t', '日本語', '😀 emoji', 'x'.repeat(100_000)]) {
      expect(ok('base64', encode('base64', text)).value).toBe(text);
      expect(ok('base64url', encode('base64url', text)).value).toBe(text);
    }
  });

  it('rejects invalid input with a reason', () => {
    expect(decode('base64', 'not base64!').ok).toBe(false);
    expect(() => base64DecodeToBytes('A')).toThrow(/length/i);
    expect(decode('base64', 'A')).toMatchObject({ ok: false });
  });

  it('flags bytes that are not valid UTF-8 instead of failing', () => {
    const r = ok('base64', '/w=='); // 0xFF
    expect(r.value).toContain('�');
    expect(r.note).toMatch(/not valid utf-8/i);
  });
});

describe('url', () => {
  it('encodes reserved characters and UTF-8', () => {
    expect(encode('url', 'a b&c=d/é?')).toBe('a%20b%26c%3Dd%2F%C3%A9%3F');
    expect(ok('url', 'a%20b%26c%3Dd%2F%C3%A9%3F').value).toBe('a b&c=d/é?');
  });

  it('only treats + as a space when asked', () => {
    expect(ok('url', 'a+b%20c').value).toBe('a+b c');
    expect(ok('url', 'a+b%20c', { plusAsSpace: true }).value).toBe('a b c');
  });

  it('reports malformed percent-encoding', () => {
    expect(decode('url', '100%')).toMatchObject({ ok: false });
    expect(decode('url', '%E0%A4%A')).toMatchObject({ ok: false });
  });
});

describe('html', () => {
  it('escapes the five markup characters', () => {
    expect(encode('html', `<a href="x" onclick='y'>&</a>`)).toBe('&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
  });

  it('can also escape non-ASCII characters, including astral ones', () => {
    expect(encode('html', 'é😀', { escapeNonAscii: true })).toBe('&#xE9;&#x1F600;');
  });

  it('decodes named, decimal and hex entities', () => {
    expect(ok('html', '&lt;b&gt; &amp; &quot;q&quot; &#39;s&#39; &#x41;&#66; &copy; &hellip; &nbsp;|').value).toBe('<b> & "q" \'s\' AB © …  |');
  });

  it('leaves unknown or malformed entities alone', () => {
    expect(ok('html', '&zzzunknown; & &#; &#xZZ;').value).toBe('&zzzunknown; & &#; &#xZZ;');
  });

  it('follows browser rules for legacy entities written without a semicolon', () => {
    expect(ok('html', 'a &amp b &lt c').value).toBe('a & b < c');
  });

  it('never turns input into markup: decoded tags stay plain text', () => {
    const r = ok('html', '&lt;script&gt;alert(1)&lt;/script&gt;</textarea><img src=x onerror=alert(1)>');
    expect(r.value).toBe('<script>alert(1)</script></textarea><img src=x onerror=alert(1)>');
    expect(document.querySelector('img')).toBeNull();
  });

  it('table fallback agrees with the browser decoder on common entities and rejects bad code points', () => {
    const sample = '&lt;&gt;&amp;&quot;&#39;&#x41;&copy;&euro;';
    expect(decodeHtmlWithTable(sample)).toBe(ok('html', sample).value);
    expect(decodeHtmlWithTable('&#0; &#55296; &#1114112;')).toBe('&#0; &#55296; &#1114112;');
  });
});

describe('hex', () => {
  it('encodes UTF-8 bytes with an optional separator and case', () => {
    expect(encode('hex', 'Hi é')).toBe('486920c3a9');
    expect(encode('hex', 'Hi', { hexSeparator: ' ' })).toBe('48 69');
    expect(encode('hex', 'Hi', { hexSeparator: ':', hexUpper: true })).toBe('48:69');
  });

  it('decodes the usual notations', () => {
    for (const form of ['486920c3a9', '48 69 20 c3 a9', '0x48 0x69 0x20 0xc3 0xa9', '\\x48\\x69\\x20\\xc3\\xa9', '48:69:20:C3:A9', '48-69-20-c3-a9']) {
      expect(ok('hex', form).value).toBe('Hi é');
    }
  });

  it('rejects bad hex with a reason', () => {
    expect(decode('hex', 'abc')).toMatchObject({ ok: false, error: expect.stringMatching(/odd/i) });
    expect(decode('hex', 'zz')).toMatchObject({ ok: false, error: expect.stringMatching(/0-9/) });
  });
});

describe('UUID generation', () => {
  const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

  it('makes valid, unique v4 UUIDs', () => {
    const ids = generateUuids(500, { version: 'v4' });
    expect(ids.every((id) => V4.test(id))).toBe(true);
    expect(new Set(ids).size).toBe(500);
  });

  it('makes valid v7 UUIDs that sort in creation order and carry the current time', () => {
    const before = Date.now();
    const ids = generateUuids(1000, { version: 'v7' });
    const after = Date.now();
    expect(ids.every((id) => V7.test(id))).toBe(true);
    expect(new Set(ids).size).toBe(1000);
    expect([...ids].sort()).toEqual(ids);
    const ts = parseInt(ids[0]!.replace(/-/g, '').slice(0, 12), 16);
    expect(ts).toBeGreaterThanOrEqual(before);
    expect(ts).toBeLessThanOrEqual(after + 5);
  });

  it('formats: upper case, no hyphens, and bounds the count', () => {
    expect(generateUuids(1, { version: 'v4', uppercase: true })[0]).toMatch(/^[0-9A-F-]{36}$/);
    expect(generateUuids(1, { version: 'v4', hyphens: false })[0]).toMatch(/^[0-9a-f]{32}$/);
    expect(generateUuids(0, { version: 'v4' })).toHaveLength(1);
    expect(generateUuids(99999, { version: 'v4' })).toHaveLength(1000);
    expect(generateUuids(Number.NaN, { version: 'v4' })).toHaveLength(1);
  });
});
