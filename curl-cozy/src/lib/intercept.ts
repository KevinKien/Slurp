import type { HeaderPair, HeldItem, InterceptEdit } from './api';
import { statusTexts } from './traffic';

/** Placeholder shown when an item's body cannot be edited as text. */
export const BINARY_BODY_NOTE = 'Body is binary or too large to edit; it is forwarded unchanged.';

const normalizeNewlines = (s: string) => s.replace(/\r\n?/g, '\n');

/** Render a held request or response as editable HTTP text. */
export function formatHeld(item: HeldItem): string {
  const start =
    item.phase === 'request'
      ? `${item.method} ${item.path} HTTP/1.1`
      : `HTTP/1.1 ${item.status ?? 0}${item.status && statusTexts[item.status] ? ` ${statusTexts[item.status]}` : ''}`;
  const headers = item.headers.map(([name, value]) => `${name}: ${value}`);
  return `${[start, ...headers].join('\n')}\n\n${item.body ?? ''}`;
}

/** Split HTTP text into its start line, header lines and body. */
function splitMessage(text: string) {
  const normalized = normalizeNewlines(text);
  const split = normalized.indexOf('\n\n');
  const head = split === -1 ? normalized : normalized.slice(0, split);
  const body = split === -1 ? '' : normalized.slice(split + 2);
  const [startLine = '', ...headerLines] = head.split('\n');
  return { startLine: startLine.trim(), headerLines, body };
}

function parseHeaderLines(lines: string[]): HeaderPair[] {
  const headers: HeaderPair[] = [];
  for (const [i, line] of lines.entries()) {
    if (!line.trim()) continue;
    const at = line.indexOf(':');
    const name = at > 0 ? line.slice(0, at).trim() : '';
    if (!name || /\s/.test(name)) throw new Error(`Invalid header on line ${i + 2}: "${line.trim().slice(0, 40)}"`);
    headers.push([name, line.slice(at + 1).trim()]);
  }
  return headers;
}

/**
 * Parse edited text back into the edit to send with "Forward". Throws an Error with a
 * user-facing message when the text is not a valid message. Repeated headers and their
 * order are kept. The body is only included when it really changed (or the text is the
 * only copy), so editing a header never rewrites a body, e.g. CRLF in a multipart upload.
 */
export function parseHeld(item: HeldItem, text: string): InterceptEdit {
  const { startLine, headerLines, body } = splitMessage(text);
  const headers = parseHeaderLines(headerLines);
  const edit: InterceptEdit = { headers };

  if (item.phase === 'request') {
    const m = /^([A-Za-z]+)\s+(\S+)(?:\s+HTTP\/\d(?:\.\d)?)?$/.exec(startLine);
    if (!m) throw new Error('Invalid request line. Expected: METHOD /path HTTP/1.1');
    if (!m[2]!.startsWith('/')) throw new Error('The request path must start with /');
    edit.method = m[1]!.toUpperCase();
    edit.path = m[2]!;
  } else {
    const m = /^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s.*)?$/.exec(startLine);
    if (!m) throw new Error('Invalid status line. Expected: HTTP/1.1 200 OK');
    const status = Number(m[1]);
    if (status < 200 || status > 599) throw new Error('The status code must be between 200 and 599');
    edit.status = status;
  }

  if (item.body_editable && normalizeNewlines(body) !== normalizeNewlines(item.body ?? '')) edit.body = body;
  return edit;
}

/** True when the text is exactly what `formatHeld` produced, i.e. nothing was edited. */
export const isUnedited = (item: HeldItem, text: string) => text === formatHeld(item);
