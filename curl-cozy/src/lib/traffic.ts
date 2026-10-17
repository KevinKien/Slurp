import { parse } from 'shell-quote';
import type { ApiTrafficEntry } from './api';

export type HttpRequest = { method: string; url: string; headers: Record<string, string>; body: string };
export type Traffic = HttpRequest & { id: number; bookmarked?: boolean; notes?: string; apiId?: string; bodyLoaded?: boolean; workspaceId?: string; source?: string; status: number; statusText: string; duration: number; size: number; timestamp: string; responseHeaders: Record<string, string>; responseBody: string };

// ── Map Rust API response to frontend Traffic type ──────────────

/** Counter for assigning numeric IDs from API entries. */
let _nextId = 100_000;

/** Parse the JSON-encoded headers string from Rust into a flat Record. */
function parseHeaders(raw: string): Record<string, string> {
  if (!raw || raw === '{}') return {};
  try {
    const parsed: Record<string, string | string[]> = JSON.parse(raw);
    const flat: Record<string, string> = {};
    for (const [key, val] of Object.entries(parsed)) {
      flat[key] = Array.isArray(val) ? val.join(', ') : String(val);
    }
    return flat;
  } catch {
    return {};
  }
}

/** Decode a byte array (number[]) to a UTF-8 string. */
function decodeBody(bytes: number[] | Uint8Array | undefined): string {
  if (!bytes || bytes.length === 0) return '';
  try {
    return new TextDecoder().decode(new Uint8Array(bytes));
  } catch {
    return '';
  }
}

/** Standard status text lookup. */
export const statusTexts: Record<number, string> = {
  200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content',
  301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
  405: 'Method Not Allowed', 408: 'Request Timeout', 429: 'Too Many Requests',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable',
};

/** Convert a Rust TrafficEntry to the frontend Traffic shape. */
export function mapApiEntry(entry: ApiTrafficEntry): Traffic {
  const reqHeaders = parseHeaders(entry.request_headers);
  const resHeaders = parseHeaders(entry.response_headers);
  const body = decodeBody(entry.request_body);
  const responseBody = decodeBody(entry.response_body);

  return {
    id: _nextId++,
    apiId: entry.id,
    bookmarked: entry.bookmarked??false,
    notes: entry.notes??'',
    workspaceId: entry.workspace_id,
    source: entry.source,
    method: entry.method,
    url: entry.url,
    headers: reqHeaders,
    body,
    status: entry.status_code,
    statusText: statusTexts[entry.status_code] ?? (entry.error || ''),
    duration: entry.duration_ms,
    size: entry.response_size,
    timestamp: entry.timestamp,
    responseHeaders: resHeaders,
    responseBody,
  };
}

/** Convert a batch of API entries. */
export function mapApiEntries(entries: ApiTrafficEntry[]): Traffic[] {
  return entries.map(mapApiEntry);
}
export const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
export const pretty = (body: string) => { try { return JSON.stringify(JSON.parse(body), null, 2); } catch { return body.replace(/></g, '>\n<'); } };
export const sizeLabel = (size: number) => size >= 1024 ? `${(size / 1024).toFixed(1)} KB` : `${size} B`;
export const requestText = (r: HttpRequest) => { if(r.url.includes('{{'))return `${r.method} ${r.url} HTTP/1.1\n${Object.entries(r.headers).map(([k,v])=>`${k}: ${v}`).join('\n')}\n\n${r.body}`; const u = new URL(r.url); return `${r.method} ${u.pathname}${u.search} HTTP/1.1\nHost: ${u.host}\n${Object.entries(r.headers).map(([k,v]) => `${k}: ${v}`).join('\n')}\n\n${r.body}`; };
/**
 * Parse an editable raw HTTP request ("GET /path HTTP/1.1", headers, blank line, body) back into a request.
 * The Host header (or an absolute-URL request line) decides the target host; the scheme and, when no
 * Host is given, the host come from `baseUrl`. Host is not kept as a header because it is derived from the URL.
 * Throws an Error with a user-facing message when the text is not a valid request.
 */
export function parseRawRequest(text: string, baseUrl: string): HttpRequest {
  const normalized = text.replace(/\r\n?/g, '\n');
  const split = normalized.indexOf('\n\n');
  const head = split === -1 ? normalized : normalized.slice(0, split);
  const body = split === -1 ? '' : normalized.slice(split + 2);
  const lines = head.split('\n');
  const requestLine = lines.shift()?.trim() ?? '';
  if (!requestLine) throw new Error('The first line must be the request line, e.g. GET /path HTTP/1.1');

  const match = /^([A-Za-z]+)\s+(\S+)(?:\s+HTTP\/\d(?:\.\d)?)?$/.exec(requestLine);
  if (!match) throw new Error('Invalid request line. Expected: METHOD /path HTTP/1.1');
  const method = match[1]!.toUpperCase();
  if (!methods.includes(method)) throw new Error(`Unsupported HTTP method: ${method}`);
  const target = match[2]!;

  const headers: Record<string, string> = {};
  let host = '';
  for (const [i, line] of lines.entries()) {
    if (!line.trim()) continue;
    const at = line.indexOf(':');
    const name = at > 0 ? line.slice(0, at).trim() : '';
    if (!name || /[\s]/.test(name)) throw new Error(`Invalid header on line ${i + 2}: "${line.trim().slice(0, 40)}"`);
    const value = line.slice(at + 1).trim();
    if (name.toLowerCase() === 'host') {
      host = value;
      continue;
    }
    // Repeated headers are combined, which is equivalent for HTTP and fits a name->value map.
    headers[name] = name in headers ? `${headers[name]}, ${value}` : value;
  }

  if(target.includes('{{') && !target.startsWith('/')) return {method,url:target,headers,body};
  let base: URL | undefined;
  try {
    base = new URL(baseUrl);
  } catch {
    // No usable base URL; the request must then be self-contained.
  }
  let url: URL;
  try {
    if (/^https?:\/\//i.test(target)) url = new URL(target);
    else if (target.startsWith('/')) {
      const authority = host || base?.host;
      if (!authority) throw new Error('missing host');
      url = new URL(`${base?.protocol ?? 'https:'}//${authority}${target}`);
    } else throw new Error('bad target');
  } catch {
    throw new Error(
      target.startsWith('/') ? 'Add a valid Host header (e.g. Host: api.example.com).' : 'The request target must start with / or be a full http(s) URL.',
    );
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Use an HTTP or HTTPS URL.');
  return { method, url: url.href, headers, body };
}

export const responseText = (r: Traffic) => `HTTP/1.1 ${r.status} ${r.statusText}\n${Object.entries(r.responseHeaders).map(([k,v]) => `${k}: ${v}`).join('\n')}\n\n${r.responseBody}`;

export function parseCurl(source: string): HttpRequest {
 const tokens = parse(source.replace(/\\\r?\n/g, ' '), () => '').filter((x): x is string => typeof x === 'string');
 if (tokens.shift() !== 'curl') throw new Error('The command must start with curl.');
 let method = 'GET', url = '', body = ''; const headers: Record<string,string> = {};
 for (let i=0;i<tokens.length;i++) {
  const token = tokens[i]; if(token === undefined) continue;
  if (['-X','--request','-H','--header','-d','--data','--data-raw','--data-binary','--json','--url','-u','--user'].includes(token)) {
   const value = tokens[++i]; if (value === undefined) throw new Error(`Missing value for ${token}`);
   if (token === '-X' || token === '--request') method = value.toUpperCase();
   else if (token === '-H' || token === '--header') { const at=value.indexOf(':'); if (at<1) throw new Error('Invalid header'); headers[value.slice(0,at).trim()] = value.slice(at+1).trim(); }
   else if (token === '--url') url=value;
   else if (token === '-u' || token === '--user') headers['Authorization'] = `Basic ${btoa(value)}`;
   else { if(value.startsWith('@')) throw new Error('Local file references are not supported.'); body=value; if(method==='GET') method='POST'; if(token==='--json') {headers['Content-Type']='application/json'; headers['Accept']='application/json';} }
  } else if (token === '-I' || token === '--head') method='HEAD';
  else if (/^https?:\/\//.test(token)) url=token;
  else if (!['-s','--silent','-L','--location','--compressed','-k','--insecure','--globoff','--path-as-is'].includes(token)) throw new Error(`Unsupported cURL option: ${token}`);
 }
 const target = new URL(url); if(!['http:','https:'].includes(target.protocol)) throw new Error('Use an HTTP or HTTPS URL.');
 if(!methods.includes(method)) throw new Error('Unsupported HTTP method.');
 return { method, url:target.href, headers, body };
}

export function importTraffic(source: string): Traffic[] {
 const now = new Date().toISOString();
 const asTraffic = (request: HttpRequest, extra: Partial<Traffic> = {}): Traffic => ({ ...request, id:0, status:0, statusText:'Not sent', duration:0, size:0, timestamp:now, responseHeaders:{}, responseBody:'', ...extra });
 if (source.trim().startsWith('curl ')) return [asTraffic(parseCurl(source))];
 const data = JSON.parse(source);
 if (data?.log?.entries && Array.isArray(data.log.entries)) return data.log.entries.map((e: any) => {
  const headers = (list: any[]) => Object.fromEntries((list ?? []).map(h=>[String(h.name),String(h.value)]));
  const url=new URL(e.request.url); if(!['http:','https:'].includes(url.protocol)) throw new Error('Invalid HAR URL.');
  return asTraffic({method:String(e.request.method),url:url.href,headers:headers(e.request.headers),body:e.request.postData?.text ?? ''}, {status:Number(e.response.status),statusText:e.response.statusText ?? '',duration:Math.max(0,Number(e.time)||0),size:Math.max(0,e.response.content?.size ?? 0),timestamp:e.startedDateTime ?? now,responseHeaders:headers(e.response.headers),responseBody:e.response.content?.encoding === 'base64' ? atob(e.response.content.text ?? '') : e.response.content?.text ?? ''});
 });
 const rows=Array.isArray(data) ? data : data.traffic;
 if(!Array.isArray(rows)) throw new Error('Expected a HAR file or an array of traffic logs.');
 return rows.map((r: any)=>{ const url=new URL(r.url); if(!['http:','https:'].includes(url.protocol) || !methods.includes(r.method)) throw new Error('Invalid traffic request.'); const row=asTraffic({ method:r.method,url:url.href,headers:r.headers && typeof r.headers==='object' ? r.headers : {},body:String(r.body ?? '') }, {status:Number(r.status)||0,statusText:String(r.statusText ?? ''),duration:Number(r.duration)||0,size:Number(r.size)||0,timestamp:r.timestamp ?? now,responseHeaders:r.responseHeaders ?? {},responseBody:String(r.responseBody ?? '')});return {...row,bookmarked:r.bookmarked===true,notes:typeof r.notes==='string'?r.notes.slice(0,16000):''}; });
}