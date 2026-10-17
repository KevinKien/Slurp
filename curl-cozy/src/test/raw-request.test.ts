import { describe, expect, it } from 'vitest';
import { parseRawRequest, requestText, type HttpRequest } from '@/lib/traffic';

const base = 'https://api.acme.io/get';

describe('parseRawRequest', () => {
  it('round-trips what requestText produces', () => {
    const req: HttpRequest = {
      method: 'POST',
      url: 'https://api.acme.io/v1/items?limit=2',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: '{"a":1}\n',
    };
    expect(parseRawRequest(requestText(req), req.url)).toEqual(req);
  });

  it('applies edits to method, path, headers and body', () => {
    const r = parseRawRequest(
      'DELETE /v2/things/9?force=1 HTTP/1.1\nHost: api.acme.io\nX-Debug: on\nAuthorization: Bearer abc\n\nbye',
      base,
    );
    expect(r).toEqual({
      method: 'DELETE',
      url: 'https://api.acme.io/v2/things/9?force=1',
      headers: { 'X-Debug': 'on', Authorization: 'Bearer abc' },
      body: 'bye',
    });
  });

  it('follows an edited Host header and keeps the base scheme', () => {
    expect(parseRawRequest('GET /x HTTP/1.1\nHost: other.example.com', base).url).toBe('https://other.example.com/x');
    expect(parseRawRequest('GET /x HTTP/1.1\nhost: other.example.com:8443', base).url).toBe('https://other.example.com:8443/x');
  });

  it('falls back to the base host when Host is missing, and accepts absolute URLs', () => {
    expect(parseRawRequest('GET /x', base).url).toBe('https://api.acme.io/x');
    expect(parseRawRequest('GET https://elsewhere.dev/a?b=1 HTTP/1.1', base).url).toBe('https://elsewhere.dev/a?b=1');
  });

  it('handles CRLF, lowercase methods, repeated headers and a body containing blank lines', () => {
    const r = parseRawRequest('post /p HTTP/1.1\r\nHost: api.acme.io\r\nX-A: 1\r\nX-A: 2\r\n\r\nline1\n\nline3', base);
    expect(r.method).toBe('POST');
    expect(r.headers).toEqual({ 'X-A': '1, 2' });
    expect(r.body).toBe('line1\n\nline3');
  });

  it('reports what is wrong', () => {
    expect(() => parseRawRequest('', base)).toThrow(/request line/i);
    expect(() => parseRawRequest('GET', base)).toThrow(/invalid request line/i);
    expect(() => parseRawRequest('FETCH /x HTTP/1.1', base)).toThrow(/unsupported http method/i);
    expect(() => parseRawRequest('GET /x HTTP/1.1\nNot a header', base)).toThrow(/line 2/);
    expect(() => parseRawRequest('GET x HTTP/1.1', base)).toThrow(/start with \//);
    expect(() => parseRawRequest('GET /x HTTP/1.1', 'not a url')).toThrow(/host header/i);
    expect(() => parseRawRequest('GET ftp://x.dev/a HTTP/1.1', base)).toThrow();
  });
});
