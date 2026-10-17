import { expect, it } from 'vitest';
import { exportHar } from '@/lib/har-export';
import { importTraffic, type Traffic } from '@/lib/traffic';

it('exports HAR 1.2 text snapshots with repeated query values and UTF-8 body sizes', () => {
  const request: Traffic = { id: 1, method: 'POST', url: 'http://localhost:8088/login?q=a&q=b', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer fixture' }, body: '{"name":"Alex ✓"}', status: 200, statusText: 'OK', duration: 12, size: 2, timestamp: '2026-10-17T00:00:00Z', responseHeaders: { 'content-type': 'application/json' }, responseBody: '{}', notes: 'Login' };
  const har = exportHar([request]);
  expect(har.log.version).toBe('1.2');
  const entry = har.log.entries[0]!;
  expect(entry.request.queryString).toEqual([{ name: 'q', value: 'a' }, { name: 'q', value: 'b' }]);
  expect(entry.request.bodySize).toBe(new TextEncoder().encode(request.body).length);
  expect(entry.response.content.text).toBe('{}');
  expect(entry.comment).toBe('Login');
  const [restored] = importTraffic(JSON.stringify(har));
  expect(restored).toMatchObject({ url: request.url, body: request.body, responseBody: '{}', status: 200 });
  expect(exportHar([]).log.entries).toEqual([]);
});
