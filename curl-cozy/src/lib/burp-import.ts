/**
 * Burp Suite import. Two interoperable sources are supported, both parsed locally:
 *
 * 1. Burp XML item exports — in Burp select the items, right-click, "Save items", and keep
 *    "Base64-encode requests and responses" enabled.
 * 2. JSON produced by the community `prub` tool (`prub export project.burp export.json`), which
 *    reads `.burp` project files without opening Burp.
 *
 * A `.burp` project file itself uses a proprietary binary format that PortSwigger does not
 * publish, so it is detected and rejected with instructions instead of guessed at.
 * Only the request side becomes a Replay tab; responses are ignored.
 */
import { methods, type HttpRequest } from "./traffic";
import type { PostmanImport, PostmanRequest } from "./postman-import";

export const MAX_BURP_BYTES = 10_000_000;
export const MAX_BURP_ITEMS = 5_000;
export const MAX_BURP_REQUESTS = 500;

const MAX_BODY = 1_000_000;
const MAX_HEADERS = 200;
const MAX_HEADER_BYTES = 8_192;
const MAX_URL = 4_096;
const MAX_NAME = 200;
const MAX_XML_DEPTH = 64;

/** Headers that describe the captured connection rather than the request's intent. */
const FRAMING_HEADERS = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "proxy-connection",
  "keep-alive",
  "upgrade",
  "te",
  "trailer",
  "expect",
]);

const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const HTTP_TARGET = /^https?:\/\//i;
const SCHEME_PREFIX = /^[A-Za-z][A-Za-z0-9+.-]*:/;
const REQUEST_LINE =
  /^([!#$%&'*+\-.^_`|~0-9A-Za-z]+)[ \t]+(\S+)(?:[ \t]+HTTP\/[0-9.]+)?[ \t]*$/;

export const BURP_PROJECT_HELP =
  "Burp project files (.burp) use a proprietary binary format that PortSwigger does not publish, so they cannot be read directly. " +
  'In Burp, select the items you need, right-click and choose "Save items", then import the saved XML. ' +
  "To convert a whole project without opening Burp, export it with the community prub tool (prub export project.burp export.json) and import that JSON.";

export interface BurpSource {
  name: string;
  source: string;
}

/** A decoded XML element: only the parts this importer needs. */
interface Field {
  name: string;
  text: string;
  attributes: Record<string, string>;
}

interface Item {
  fields: Map<string, Field>;
}

interface RawRequest {
  method: string;
  target: string;
  headers: [string, string][];
  body: Uint8Array;
}

interface BuildContext {
  methodField?: string;
  schemeField?: string;
  hostField?: string;
  portField?: string;
  comment?: string;
  nameHint?: string;
}

interface BuiltRequest {
  request: HttpRequest;
  name: string;
  warnings: string[];
}

function utf8Size(value: string): number {
  return new TextEncoder().encode(value).length;
}

function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function utf8Text(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

/** Byte-faithful decode for the request head, which is not required to be UTF-8. */
function latin1(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 4096) {
    out += String.fromCharCode(...bytes.subarray(i, i + 4096));
  }
  return out;
}

function isUtf8(bytes: Uint8Array): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

function decodeBase64(raw: string): Uint8Array {
  const compact = raw.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!compact || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact))
    throw Error("Item contains invalid base64 data.");
  const padded = compact.padEnd(Math.ceil(compact.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw Error("Item contains invalid base64 data.");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeEntities(value: string): string {
  if (!value.includes("&")) return value;
  return value.replace(
    /&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);/g,
    (match: string, body: string) => {
      if (body.startsWith("#x") || body.startsWith("#X")) {
        const code = Number.parseInt(body.slice(2), 16);
        return Number.isInteger(code) && code > 0 && code <= 0x10ffff
          ? String.fromCodePoint(code)
          : match;
      }
      if (body.startsWith("#")) {
        const code = Number.parseInt(body.slice(1), 10);
        return Number.isInteger(code) && code > 0 && code <= 0x10ffff
          ? String.fromCodePoint(code)
          : match;
      }
      const named: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
      return named[body] ?? match;
    },
  );
}

type XmlEvent =
  | { type: "start"; name: string; attributes: Record<string, string>; selfClosing: boolean }
  | { type: "end"; name: string }
  | { type: "text"; value: string };

/** Minimal XML scanner for the element subset Burp writes: tags, attributes, CDATA, entities. */
function* xmlEvents(source: string): Generator<XmlEvent> {
  const length = source.length;
  let index = 0;
  while (index < length) {
    const open = source.indexOf("<", index);
    if (open < 0) {
      if (index < length) yield { type: "text", value: decodeEntities(source.slice(index)) };
      return;
    }
    if (open > index) yield { type: "text", value: decodeEntities(source.slice(index, open)) };
    index = open;
    if (source.startsWith("<!--", index)) {
      const end = source.indexOf("-->", index + 4);
      if (end < 0) return;
      index = end + 3;
      continue;
    }
    if (source.startsWith("<![CDATA[", index)) {
      const end = source.indexOf("]]>", index + 9);
      if (end < 0) return;
      yield { type: "text", value: source.slice(index + 9, end) };
      index = end + 3;
      continue;
    }
    if (source.startsWith("<?", index)) {
      const end = source.indexOf("?>", index + 2);
      if (end < 0) return;
      index = end + 2;
      continue;
    }
    if (source.startsWith("<!", index)) {
      // DOCTYPE and similar declarations, including a bracketed internal subset.
      let cursor = index + 2;
      let depth = 0;
      while (cursor < length) {
        const character = source.charAt(cursor);
        if (character === '"' || character === "'") {
          const quote = character;
          cursor++;
          while (cursor < length && source.charAt(cursor) !== quote) cursor++;
        } else if (character === "[") depth++;
        else if (character === "]") depth = Math.max(0, depth - 1);
        else if (character === ">" && depth === 0) break;
        cursor++;
      }
      index = cursor + 1;
      continue;
    }
    if (source.startsWith("</", index)) {
      const end = source.indexOf(">", index + 2);
      if (end < 0) return;
      yield { type: "end", name: source.slice(index + 2, end).trim() };
      index = end + 1;
      continue;
    }
    const nameMatch = /^[A-Za-z_:][-A-Za-z0-9_:.]*/.exec(source.slice(index + 1, index + 129));
    if (!nameMatch) {
      index++;
      continue;
    }
    const name = nameMatch[0];
    let cursor = index + 1 + name.length;
    const attributes: Record<string, string> = {};
    let selfClosing = false;
    while (cursor < length) {
      while (cursor < length && /\s/.test(source.charAt(cursor))) cursor++;
      const character = source.charAt(cursor);
      if (character === ">") {
        cursor++;
        break;
      }
      if (character === "/" && source.charAt(cursor + 1) === ">") {
        selfClosing = true;
        cursor += 2;
        break;
      }
      const attributeMatch = /^[^\s=/>]+/.exec(source.slice(cursor, cursor + 257));
      if (!attributeMatch) {
        cursor++;
        continue;
      }
      const attributeName = attributeMatch[0];
      cursor += attributeName.length;
      while (cursor < length && /\s/.test(source.charAt(cursor))) cursor++;
      if (source.charAt(cursor) !== "=") continue;
      cursor++;
      while (cursor < length && /\s/.test(source.charAt(cursor))) cursor++;
      const quote = source.charAt(cursor);
      let value = "";
      if (quote === '"' || quote === "'") {
        const end = source.indexOf(quote, cursor + 1);
        if (end < 0) return;
        value = source.slice(cursor + 1, end);
        cursor = end + 1;
      } else {
        const bare = /^[^\s/>]+/.exec(source.slice(cursor, cursor + 257));
        value = bare ? bare[0] : "";
        cursor += value.length;
      }
      attributes[attributeName.toLowerCase()] = decodeEntities(value);
    }
    yield { type: "start", name, attributes, selfClosing };
    index = cursor;
  }
}

/** Collect `<items><item>…</item></items>` entries without building a full DOM. */
function collectItems(source: string): { items: Item[]; version: string } {
  interface Frame {
    name: string;
    attributes: Record<string, string>;
    text: string;
    children: Field[];
  }
  const frames: Frame[] = [];
  const items: Item[] = [];
  let version = "";
  for (const event of xmlEvents(source)) {
    if (event.type === "text") {
      const top = frames[frames.length - 1];
      if (top) top.text += event.value;
      continue;
    }
    if (event.type === "start") {
      if (event.name === "items" && !version) version = event.attributes["burpversion"] ?? "";
      if (event.selfClosing) {
        const parent = frames[frames.length - 1];
        if (parent && parent.name === "item")
          parent.children.push({ name: event.name, text: "", attributes: event.attributes });
        continue;
      }
      if (frames.length >= MAX_XML_DEPTH) throw Error("XML nesting is too deep to be a Burp export.");
      frames.push({ name: event.name, attributes: event.attributes, text: "", children: [] });
      continue;
    }
    const frame = frames.pop();
    if (!frame) continue;
    const parent = frames[frames.length - 1];
    if (parent && parent.name === "item") {
      parent.children.push({ name: frame.name, text: frame.text, attributes: frame.attributes });
    }
    if (frame.name === "item") {
      if (items.length >= MAX_BURP_ITEMS)
        throw Error(
          `Burp export exceeds ${MAX_BURP_ITEMS.toLocaleString("en-US")} items. Select fewer items in Burp.`,
        );
      const fields = new Map<string, Field>();
      for (const child of frame.children) if (!fields.has(child.name)) fields.set(child.name, child);
      items.push({ fields });
    }
  }
  return { items, version };
}

function fieldText(item: Item, name: string): string {
  return item.fields.get(name)?.text ?? "";
}

/** Decode an item payload according to its `base64` attribute, with a content sniff when absent. */
function payloadBytes(field: Field): Uint8Array {
  const flag = (field.attributes["base64"] ?? "").toLowerCase();
  if (flag === "false") return utf8Bytes(field.text);
  if (flag === "true") return decodeBase64(field.text);
  if (/^[A-Za-z]+[ \t]+\S/.test(field.text.trim())) return utf8Bytes(field.text);
  try {
    return decodeBase64(field.text);
  } catch {
    return utf8Bytes(field.text);
  }
}

function parseRawRequest(bytes: Uint8Array): RawRequest {
  if (!bytes.length) throw Error("Item has an empty request.");
  if (bytes.length > 1 && bytes[0] === 0x1f && bytes[1] === 0x8b)
    throw Error(
      "Compressed request data is not supported. In Burp, save items as XML with base64 encoding.",
    );
  let headEnd = -1;
  let separator = 0;
  for (let i = 0; i + 1 < bytes.length; i++) {
    if (
      bytes[i] === 13 &&
      bytes[i + 1] === 10 &&
      i + 3 < bytes.length &&
      bytes[i + 2] === 13 &&
      bytes[i + 3] === 10
    ) {
      headEnd = i;
      separator = 4;
      break;
    }
    if (bytes[i] === 10 && bytes[i + 1] === 10) {
      headEnd = i;
      separator = 2;
      break;
    }
  }
  if (headEnd < 0) headEnd = bytes.length;
  const head = latin1(bytes.subarray(0, headEnd));
  const body = bytes.subarray(Math.min(bytes.length, headEnd + separator));
  const lines = head.split(/\r?\n/);
  const startLine = lines.shift() ?? "";
  const match = REQUEST_LINE.exec(startLine);
  if (!match || !match[1] || !match[2])
    throw Error("Item request line is not valid HTTP/1.x.");
  const headers: [string, string][] = [];
  for (const line of lines) {
    if (!line) continue;
    if ((line.startsWith(" ") || line.startsWith("\t")) && headers.length) {
      const last = headers[headers.length - 1];
      if (last) last[1] = `${last[1]} ${line.trim()}`;
      continue;
    }
    const colon = line.indexOf(":");
    if (colon < 1) continue;
    const name = line.slice(0, colon).trim();
    const value = line
      .slice(colon + 1)
      .replace(/^[ \t]+/, "")
      .replace(/[ \t]+$/, "");
    headers.push([name, value]);
  }
  return { method: match[1].toUpperCase(), target: match[2], headers, body };
}

function firstHeader(headers: [string, string][], name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of headers) if (key.toLowerCase() === lower) return value;
  return undefined;
}

function parsePort(value: string): number {
  const port = Number(value);
  if (!/^\d{1,5}$/.test(value) || !Number.isInteger(port) || port < 1 || port > 65535)
    throw Error("Request has an invalid port.");
  return port;
}

function splitAuthority(value: string): { host: string; port?: number } {
  const trimmed = value.trim();
  if (!trimmed) throw Error("Request has an empty Host header.");
  if (trimmed.startsWith("[")) {
    const close = trimmed.indexOf("]");
    if (close < 0) throw Error("Request has an invalid IPv6 host.");
    const host = trimmed.slice(1, close);
    if (!host) throw Error("Request has an invalid IPv6 host.");
    const rest = trimmed.slice(close + 1);
    if (!rest) return { host };
    if (!rest.startsWith(":")) throw Error("Request Host header is not valid.");
    return { host, port: parsePort(rest.slice(1)) };
  }
  const first = trimmed.indexOf(":");
  if (first < 0) return { host: trimmed };
  if (first !== trimmed.lastIndexOf(":")) return { host: trimmed };
  const host = trimmed.slice(0, first);
  if (!host) throw Error("Request Host header is not valid.");
  return { host, port: parsePort(trimmed.slice(first + 1)) };
}

function buildRequest(bytes: Uint8Array, context: BuildContext): BuiltRequest {
  const raw = parseRawRequest(bytes);
  const method = raw.method;
  if (method === "CONNECT") throw Error("CONNECT tunnels cannot be imported as Replay requests.");
  if (!methods.includes(method)) throw Error(`Unsupported method: ${method.slice(0, 20)}`);
  const target = raw.target;
  if (target === "*") throw Error("Asterisk-form request targets cannot be imported.");
  if (!target.startsWith("/") && !HTTP_TARGET.test(target)) {
    if (SCHEME_PREFIX.test(target))
      throw Error("Only HTTP and HTTPS request targets can be imported.");
    throw Error("Request target is not an HTTP origin-form or absolute-form path.");
  }

  const hostHeader = firstHeader(raw.headers, "host");
  const hostField = (context.hostField ?? "").trim();
  const authoritySource = (hostHeader ?? hostField).trim();
  if (!authoritySource) throw Error("Request has no Host header to build a URL from.");
  const authority = splitAuthority(authoritySource);

  const fieldPort = (context.portField ?? "").trim();
  const schemeField = (context.schemeField ?? "").trim().toLowerCase();
  let scheme: "http" | "https";
  if (schemeField === "https") scheme = "https";
  else if (schemeField === "http") scheme = "http";
  else if (authority.port === 443 || fieldPort === "443") scheme = "https";
  else scheme = "http";

  const defaultPort = scheme === "https" ? 443 : 80;
  // The Host header is what the client actually addressed; the item port is the fallback.
  const port = authority.port ?? (fieldPort ? parsePort(fieldPort) : defaultPort);
  const host = authority.host;
  const hostname = host.includes(":") ? `[${host}]` : host;
  const urlText = HTTP_TARGET.test(target)
    ? target
    : `${scheme}://${hostname}${port === defaultPort ? "" : `:${port}`}${target}`;

  let parsed: URL;
  try {
    parsed = new URL(urlText);
  } catch {
    throw Error("Item does not produce a valid HTTP(S) URL.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:")
    throw Error("Only HTTP and HTTPS requests can be imported.");
  if (parsed.username || parsed.password)
    throw Error("URLs containing credentials cannot be imported.");
  const url = parsed.href;
  if (url.length > MAX_URL) throw Error(`URL exceeds ${MAX_URL.toLocaleString("en-US")} characters.`);

  const warnings: string[] = [];
  const dropped = new Set<string>();
  const duplicates = new Set<string>();
  const entries: [string, string][] = [];
  const seen = new Set<string>();
  for (const [name, value] of raw.headers) {
    const lower = name.toLowerCase();
    if (FRAMING_HEADERS.has(lower)) {
      dropped.add(lower);
      continue;
    }
    if (!HEADER_NAME.test(name)) throw Error(`Invalid header name: ${name.slice(0, 40)}`);
    if (name.length > MAX_HEADER_BYTES || value.length > MAX_HEADER_BYTES)
      throw Error(`Header "${name.slice(0, 40)}" exceeds 8 KB.`);
    if (/[\r\n\0]/.test(value)) throw Error(`Invalid value for header "${name.slice(0, 40)}".`);
    if (seen.has(lower)) {
      duplicates.add(name);
      continue;
    }
    seen.add(lower);
    entries.push([name, value]);
  }
  if (entries.length > MAX_HEADERS) throw Error(`Request exceeds ${MAX_HEADERS} headers.`);

  let body = "";
  if (raw.body.length) {
    if (raw.body.length > MAX_BODY) throw Error("Request body exceeds 1 MB.");
    if (raw.body.length > 1 && raw.body[0] === 0x1f && raw.body[1] === 0x8b)
      throw Error("Compressed (gzip) request bodies cannot be imported as text.");
    body = utf8Text(raw.body);
    if (raw.body.includes(0) || !isUtf8(raw.body))
      warnings.push(
        "Request body contains non-text bytes; it was decoded as UTF-8 and may differ when sent.",
      );
  }
  if (body && (method === "GET" || method === "HEAD"))
    warnings.push(`${method} bodies are not sent by Replay.`);
  if (dropped.size)
    warnings.push(
      `Removed connection framing headers: ${[...dropped].sort().join(", ")}. The URL and body define what is sent.`,
    );
  if (duplicates.size)
    warnings.push(`Duplicate headers kept only once: ${[...duplicates].sort().join(", ")}.`);

  const path = `${parsed.pathname}${parsed.search}`;
  const comment = (context.comment ?? "").trim().replace(/\s+/g, " ");
  const name = (comment || (context.nameHint ?? "").trim() || `${method} ${path}`).slice(0, MAX_NAME);
  return {
    request: { method, url, headers: Object.fromEntries(entries), body },
    name,
    warnings,
  };
}

function fallbackName(item: Item, index: number): string {
  const comment = fieldText(item, "comment").trim().replace(/\s+/g, " ");
  if (comment) return comment.slice(0, MAX_NAME);
  const method = fieldText(item, "method").trim().toUpperCase() || "Request";
  const path = fieldText(item, "path").trim() || fieldText(item, "url").trim();
  if (path) return `${method} ${path}`.slice(0, MAX_NAME);
  return `Burp item ${index + 1}`;
}

function assignName(name: string, used: Set<string>): string {
  let candidate = (name || "Burp request").slice(0, MAX_NAME);
  if (!used.has(candidate)) {
    used.add(candidate);
    return candidate;
  }
  let suffix = 2;
  while (used.has(`${candidate.slice(0, MAX_NAME - 5)} (${suffix})`)) suffix++;
  candidate = `${candidate.slice(0, MAX_NAME - 5)} (${suffix})`;
  used.add(candidate);
  return candidate;
}

function looksBinary(source: string): boolean {
  const sample = source.slice(0, 4096);
  if (!sample) return false;
  if (sample.includes("\uFFFD")) return true;
  let control = 0;
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i);
    if (code === 0) return true;
    if (code < 9 || (code > 13 && code < 32)) control++;
  }
  return control > sample.length / 20;
}

function parseBurpXml(source: string): PostmanImport {
  const { items, version } = collectItems(source);
  if (!items.length) throw Error("Burp export contains no <item> elements.");
  const requests: PostmanRequest[] = [];
  const warnings: string[] = [];
  const used = new Set<string>();
  let missing = 0;
  let responses = 0;
  for (const [index, item] of items.entries()) {
    if (requests.length >= MAX_BURP_REQUESTS)
      throw Error(
        `Burp export exceeds ${MAX_BURP_REQUESTS} requests. Select fewer items in Burp and save them separately.`,
      );
    const requestField = item.fields.get("request");
    if (!requestField || !requestField.text.trim()) {
      missing++;
      continue;
    }
    const response = item.fields.get("response");
    if (response && response.text.trim()) responses++;
    const itemWarnings: string[] = [];
    let request: HttpRequest | null = null;
    let name = "";
    try {
      const built = buildRequest(payloadBytes(requestField), {
        methodField: fieldText(item, "method"),
        schemeField: fieldText(item, "protocol"),
        hostField: fieldText(item, "host"),
        portField: fieldText(item, "port"),
        comment: fieldText(item, "comment"),
      });
      request = built.request;
      name = built.name;
      itemWarnings.push(...built.warnings);
    } catch (error) {
      itemWarnings.push(
        error instanceof Error ? error.message.slice(0, 500) : "Invalid Burp item.",
      );
      name = fallbackName(item, index);
    }
    requests.push({
      id: requests.length,
      name: assignName(name, used),
      request,
      warnings: itemWarnings,
      scripts: [],
    });
  }
  if (!requests.length)
    throw Error(
      missing
        ? "Burp export contains no requests. The selected items have responses only."
        : "Burp export contains no requests that can become Replay tabs.",
    );
  if (missing)
    warnings.push(
      `Skipped ${missing} item${missing === 1 ? "" : "s"} without a request (responses only).`,
    );
  if (responses)
    warnings.push("Captured responses are not imported; only the request side becomes a Replay tab.");
  return {
    name: version ? `Burp export · ${version}` : "Burp export",
    requests,
    variables: {},
    warnings,
  };
}

interface ProjectEntry {
  id: string;
  payload: string;
  caption?: string;
}

/** Read the documented JSON export shape produced by the community `prub` tool. */
function parseProjectExport(source: string): PostmanImport {
  let document: unknown;
  try {
    document = JSON.parse(source);
  } catch {
    throw Error("File is not valid JSON.");
  }
  if (!document || typeof document !== "object" || Array.isArray(document))
    throw Error("Expected a Burp JSON export object.");
  const record = document as Record<string, unknown>;
  const entries: ProjectEntry[] = [];
  let skipped = 0;
  for (const section of ["proxy", "repeater", "target"] as const) {
    const rows = record[section];
    if (!Array.isArray(rows)) continue;
    for (const row of rows) {
      if (entries.length >= MAX_BURP_REQUESTS)
        throw Error(
          `Burp export exceeds ${MAX_BURP_REQUESTS} requests. Export fewer entries and import them separately.`,
        );
      if (!row || typeof row !== "object") continue;
      const item = row as Record<string, unknown>;
      const payload = item["request_base64"];
      if (typeof payload !== "string" || !payload) {
        skipped++;
        continue;
      }
      const id = typeof item["id"] === "string" ? item["id"] : section;
      const tab = item["tab"];
      const caption =
        tab && typeof tab === "object" ? (tab as Record<string, unknown>)["caption"] : undefined;
      entries.push(
        typeof caption === "string" && caption.trim()
          ? { id, payload, caption: caption.trim().slice(0, MAX_NAME) }
          : { id, payload },
      );
    }
  }
  if (!entries.length)
    throw Error(
      "Expected a Burp XML export, or a prub JSON export with proxy, repeater or target requests.",
    );
  const requests: PostmanRequest[] = [];
  const warnings: string[] = [];
  const used = new Set<string>();
  for (const entry of entries) {
    const itemWarnings: string[] = [];
    let request: HttpRequest | null = null;
    let name = entry.caption ?? entry.id;
    try {
      const built = buildRequest(decodeBase64(entry.payload), {
        nameHint: entry.caption ?? entry.id,
      });
      request = built.request;
      name = built.name;
      itemWarnings.push(...built.warnings);
    } catch (error) {
      itemWarnings.push(
        error instanceof Error ? error.message.slice(0, 500) : "Invalid Burp item.",
      );
    }
    requests.push({
      id: requests.length,
      name: assignName(name, used),
      request,
      warnings: itemWarnings,
      scripts: [],
    });
  }
  if (skipped)
    warnings.push(
      `Skipped ${skipped} entr${skipped === 1 ? "y" : "ies"} without a stored request.`,
    );
  warnings.push(
    "Project request bytes do not record the URL scheme, so imported URLs default to http; change them to https in Replay when the capture used TLS.",
    "Project exports contain requests only; responses and Repeater tab groups are not imported.",
  );
  const schema = record["burp_schema"];
  return {
    name:
      typeof schema === "number" && Number.isInteger(schema)
        ? `Burp project export · schema ${schema}`
        : "Burp project export",
    requests,
    variables: {},
    warnings,
  };
}

/**
 * Parse a Burp XML item export or a `prub` JSON project export into Replay-ready requests.
 * Throws with an actionable message for binary `.burp` project files.
 */
export function parseBurpExport(source: string, _fileName = ""): PostmanImport {
  const normalized = source.charCodeAt(0) === 0xfeff ? source.slice(1) : source;
  if (!normalized.trim()) throw Error("The selected file is empty.");
  if (utf8Size(normalized) > MAX_BURP_BYTES) throw Error("File exceeds the 10 MB limit.");
  if (looksBinary(normalized)) throw Error(BURP_PROJECT_HELP);
  const start = normalized.trimStart();
  if (start.startsWith("{")) return parseProjectExport(normalized);
  if (start.startsWith("<")) return parseBurpXml(normalized);
  throw Error(
    "Expected a Burp XML export from Save items, or a prub JSON project export.",
  );
}
