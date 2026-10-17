import { afterEach, expect, it, vi } from 'vitest';
import { sendHttpRequest } from '../lib/replay.functions';
const data = { method: 'GET' as const, url: 'https://example.com', headers: {}, body: '', timeout: 1000 };
afterEach(() => vi.unstubAllGlobals());
it('uses the Rust endpoint and preserves separate Set-Cookie values for profile jars', async () => {
  const result = { ok: true, status: 200, statusText: 'OK', duration: 2, size: 2, responseHeaders: {}, setCookies: ['a=1; Path=/', 'b=2; Path=/'], responseBody: '{}' };
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(result)));
  vi.stubGlobal('fetch', fetcher);
  expect(await sendHttpRequest({ data })).toEqual(result);
  expect(fetcher.mock.calls[0]![0]).toMatch(/\/api\/replay\/send$/);
  expect(JSON.parse(fetcher.mock.calls[0]![1].body)).toEqual(data);
});
it('returns a failed outcome for API and transport failures instead of reporting success', async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ error: 'origin not allowed' }), { status: 403 }))
    .mockRejectedValueOnce(new Error('Disconnected'));
  vi.stubGlobal('fetch', fetcher);
  expect(await sendHttpRequest({ data })).toEqual({ ok: false, error: 'origin not allowed' });
  expect(await sendHttpRequest({ data })).toEqual({ ok: false, error: 'Disconnected' });
});
