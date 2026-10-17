import { describe, expect, it } from 'vitest';
import type { HeldItem } from '@/lib/api';
import { formatHeld, isUnedited, parseHeld } from '@/lib/intercept';

const request = (over: Partial<HeldItem> = {}): HeldItem => ({
  id: 'r1',
  phase: 'request',
  created_at: '2026-10-15T00:00:00Z',
  scheme: 'https',
  host: 'api.acme.io',
  url: 'https://api.acme.io/v1/items?limit=2',
  method: 'POST',
  path: '/v1/items?limit=2',
  status: null,
  headers: [
    ['host', 'api.acme.io'],
    ['cookie', 'a=1'],
    ['cookie', 'b=2'],
  ],
  body: '{"a":1}',
  body_size: 7,
  body_editable: true,
  ...over,
});

const response = (over: Partial<HeldItem> = {}): HeldItem =>
  request({
    id: 's1',
    phase: 'response',
    status: 200,
    method: 'GET',
    headers: [['content-type', 'application/json']],
    body: '{"ok":true}',
    ...over,
  });

describe('formatHeld', () => {
  it('renders a request as HTTP text', () => {
    expect(formatHeld(request())).toBe(
      'POST /v1/items?limit=2 HTTP/1.1\nhost: api.acme.io\ncookie: a=1\ncookie: b=2\n\n{"a":1}',
    );
  });

  it('renders a response with its reason phrase', () => {
    expect(formatHeld(response())).toBe('HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"ok":true}');
    expect(formatHeld(response({ status: 599 }))).toMatch(/^HTTP\/1\.1 599\n/);
  });

  it('leaves binary bodies out of the text', () => {
    expect(formatHeld(request({ body: null, body_editable: false, body_size: 9 }))).toMatch(/\n\n$/);
  });
});

describe('parseHeld', () => {
  it('round-trips unedited text without a body edit', () => {
    const item = request();
    const edit = parseHeld(item, formatHeld(item));
    expect(edit).toEqual({ method: 'POST', path: '/v1/items?limit=2', headers: item.headers });
    expect(isUnedited(item, formatHeld(item))).toBe(true);
  });

  it('picks up edits to method, path, headers and body, keeping repeated headers in order', () => {
    const edit = parseHeld(
      request(),
      'delete /v2/x?y=1 HTTP/1.1\nhost: other.example\ncookie: a=1\ncookie: z=9\nx-new: 1\n\nbye',
    );
    expect(edit).toEqual({
      method: 'DELETE',
      path: '/v2/x?y=1',
      headers: [
        ['host', 'other.example'],
        ['cookie', 'a=1'],
        ['cookie', 'z=9'],
        ['x-new', '1'],
      ],
      body: 'bye',
    });
  });

  it('does not rewrite a body when only the headers changed (CRLF bodies survive)', () => {
    const multipart = request({ body: '--b\r\nContent-Disposition: form-data\r\n\r\nx\r\n--b--\r\n' });
    const text = formatHeld(multipart).replace('cookie: a=1', 'cookie: a=2').replace(/\r\n/g, '\n');
    const edit = parseHeld(multipart, text);
    expect(edit.body).toBeUndefined();
    expect(edit.headers).toContainEqual(['cookie', 'a=2']);
  });

  it('never sends a body for binary items', () => {
    const bin = request({ body: null, body_editable: false, body_size: 3 });
    expect(parseHeld(bin, `${formatHeld(bin)}typed anyway`).body).toBeUndefined();
  });

  it('parses response edits', () => {
    const edit = parseHeld(response(), 'HTTP/1.1 418 I am a teapot\ncontent-type: text/plain\nx-a: b\n\nshort and stout');
    expect(edit).toEqual({
      status: 418,
      headers: [
        ['content-type', 'text/plain'],
        ['x-a', 'b'],
      ],
      body: 'short and stout',
    });
  });

  it('explains what is wrong', () => {
    expect(() => parseHeld(request(), '')).toThrow(/invalid request line/i);
    expect(() => parseHeld(request(), 'GET /x HTTP/1.1\nNot a header')).toThrow(/line 2/);
    expect(() => parseHeld(request(), 'GET x HTTP/1.1')).toThrow(/start with \//);
    expect(() => parseHeld(response(), 'oops')).toThrow(/invalid status line/i);
    expect(() => parseHeld(response(), 'HTTP/1.1 99')).toThrow(/invalid status line/i);
    expect(() => parseHeld(response(), 'HTTP/1.1 100')).toThrow(/between 200 and 599/);
    expect(() => parseHeld(response(), 'HTTP/1.1 600')).toThrow(/between 200 and 599/);
  });
});
