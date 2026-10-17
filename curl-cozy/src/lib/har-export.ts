import { APP_VERSION } from "./version";
import type { Traffic } from './traffic';

const bytes = (text: string) => new TextEncoder().encode(text).length;
const headers = (values: Record<string, string>) => Object.entries(values).map(([name, value]) => ({ name, value }));
const header = (values: Record<string, string>, name: string) => Object.entries(values).find(([key]) => key.toLowerCase() === name)?.[1] ?? '';

/** Export the text request/response snapshots available in History as HAR 1.2. */
export function exportHar(rows: Traffic[]) {
  return { log: {
    version: '1.2', creator: { name: 'Slurp', version: APP_VERSION }, entries: rows.map(row => {
      const url = new URL(row.url);
      url.hash = '';
      const duration = Number.isFinite(row.duration) ? Math.max(0, row.duration) : 0;
      return {
        startedDateTime: new Date(row.timestamp).toISOString(), time: duration,
        request: {
          method: row.method, url: url.href, httpVersion: 'HTTP/1.1', headers: headers(row.headers),
          queryString: Array.from(url.searchParams, ([name, value]) => ({ name, value })), cookies: [],
          headersSize: -1, bodySize: bytes(row.body),
          ...(row.body ? { postData: { mimeType: header(row.headers, 'content-type') || 'text/plain', text: row.body } } : {}),
        },
        response: {
          status: row.status, statusText: row.statusText, httpVersion: 'HTTP/1.1', headers: headers(row.responseHeaders), cookies: [],
          content: { size: bytes(row.responseBody), mimeType: header(row.responseHeaders, 'content-type') || 'application/octet-stream', text: row.responseBody },
          redirectURL: header(row.responseHeaders, 'location'), headersSize: -1, bodySize: row.size,
        },
        cache: {}, timings: { send: 0, wait: duration, receive: 0 },
        ...(row.notes ? { comment: row.notes } : {}),
      };
    }),
  } };
}
