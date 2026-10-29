import { describe, expect, it } from "vitest";
import {
  BURP_PROJECT_HELP,
  MAX_BURP_BYTES,
  parseBurpExport,
} from "../lib/burp-import";

const bytes = (text: string) => new TextEncoder().encode(text);
const base64 = (text: string) => {
  let binary = "";
  for (const byte of bytes(text)) binary += String.fromCharCode(byte);
  return btoa(binary);
};

interface ItemOptions {
  url?: string;
  host?: string;
  hostIp?: string;
  port?: string;
  protocol?: string;
  method?: string;
  path?: string;
  request?: string;
  /** Verbatim `<request>` payload, bypassing the base64 encoder. */
  payload?: string;
  response?: string;
  comment?: string;
  /** Emit the comment without CDATA so XML entities are exercised. */
  entityComment?: string;
  base64?: string;
}

function item(options: ItemOptions = {}) {
  const url = options.url ?? "https://example.com/items?limit=2";
  const request =
    options.request ??
    `GET /items?limit=2 HTTP/1.1\r\nHost: ${options.host ?? "example.com"}\r\nAccept: application/json\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n`;
  const base64Attribute = options.base64 === undefined ? ' base64="true"' : ` base64="${options.base64}"`;
  const payload =
    options.payload ?? (options.base64 === "false" ? request : base64(request));
  const comment =
    options.entityComment !== undefined
      ? `<comment>${options.entityComment}</comment>`
      : `<comment><![CDATA[${options.comment ?? ""}]]></comment>`;
  return `<item>
  <time>Mon Jan 01 00:00:00 GMT 2024</time>
  <url><![CDATA[${url}]]></url>
  <host ip="${options.hostIp ?? "93.184.216.34"}">${options.host ?? "example.com"}</host>
  <port>${options.port ?? "443"}</port>
  <protocol>${options.protocol ?? "https"}</protocol>
  <method><![CDATA[${options.method ?? "GET"}]]></method>
  <path><![CDATA[${options.path ?? "/items"}]]></path>
  <extension>null</extension>
  <request${base64Attribute}><![CDATA[${payload}]]></request>
  <status>200</status>
  <responselength>19</responselength>
  <mimetype>JSON</mimetype>
  <response base64="true"><![CDATA[${base64(options.response ?? "HTTP/1.1 200 OK\r\n\r\n{\"items\":[]}")}]]></response>
  ${comment}
</item>`;
}

const exportXml = (items: string, version = "2026.7.1") => `<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ELEMENT item (time,url,host,port,protocol,method,path,extension,request,status,responselength,mimetype,response,comment)>
]>
<items burpVersion="${version}" exportTime="Mon Jan 01 00:00:00 GMT 2024">${items}
</items>`;

describe("Burp XML export import", () => {
  it("imports a saved item as a Replay request and drops framing headers", () => {
    const result = parseBurpExport(exportXml(item({ comment: "List items" })));
    expect(result.name).toBe("Burp export · 2026.7.1");
    expect(result.variables).toEqual({});
    expect(result.requests).toHaveLength(1);
    const [request] = result.requests;
    expect(request?.name).toBe("List items");
    expect(request?.request).toEqual({
      method: "GET",
      url: "https://example.com/items?limit=2",
      headers: { Accept: "application/json" },
      body: "",
    });
    expect(request?.warnings.join(" ")).toContain("Removed connection framing headers");
    expect(request?.warnings.join(" ")).toContain("content-length");
    expect(result.warnings.join(" ")).toContain("Captured responses are not imported");
  });

  it("decodes base64 request bodies and unsupported framing", () => {
    const request = `POST /api/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{"name":"alice"}`;
    const result = parseBurpExport(
      exportXml(item({ request, host: "api.example.com", path: "/api/users", method: "POST" })),
    );
    const built = result.requests[0]?.request;
    expect(built?.method).toBe("POST");
    expect(built?.url).toBe("https://api.example.com/api/users");
    expect(built?.headers).toEqual({ "Content-Type": "application/json" });
    expect(built?.body).toBe('{"name":"alice"}');
  });

  it("accepts plain-text items when base64 is disabled", () => {
    const request = `PUT /plain HTTP/1.1\r\nHost: example.com\r\n\r\nraw body`;
    const result = parseBurpExport(
      exportXml(item({ request, base64: "false", method: "PUT", path: "/plain" })),
    );
    expect(result.requests[0]?.request?.body).toBe("raw body");
    expect(result.requests[0]?.request?.method).toBe("PUT");
  });

  it("builds the URL from host, port and protocol when the Host header is absent", () => {
    const request = `GET /health HTTP/1.1\r\nAccept: */*\r\n\r\n`;
    const result = parseBurpExport(
      exportXml(
        item({ request, host: "internal.example.com", port: "8443", protocol: "https", path: "/health" }),
      ),
    );
    expect(result.requests[0]?.request?.url).toBe("https://internal.example.com:8443/health");
  });

  it("uses an absolute-form request target and IPv6 hosts", () => {
    const absolute = parseBurpExport(
      exportXml(
        item({ request: `GET http://other.example/path HTTP/1.1\r\nHost: other.example\r\n\r\n` }),
      ),
    );
    expect(absolute.requests[0]?.request?.url).toBe("http://other.example/path");
    const ipv6 = parseBurpExport(
      exportXml(
        item({
          request: `GET /v6 HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n`,
          host: "2001:db8::1",
          path: "/v6",
        }),
      ),
    );
    expect(ipv6.requests[0]?.request?.url).toBe("https://[2001:db8::1]:8080/v6");
  });

  it("keeps the first duplicate header and reports it", () => {
    const request = `GET /dup HTTP/1.1\r\nHost: example.com\r\nX-Trace: one\r\nX-Trace: two\r\n\r\n`;
    const result = parseBurpExport(exportXml(item({ request, path: "/dup" })));
    expect(result.requests[0]?.request?.headers).toEqual({ "X-Trace": "one" });
    expect(result.requests[0]?.warnings.join(" ")).toContain("Duplicate headers kept only once: X-Trace");
  });

  it("decodes XML entities and rejects CONNECT, unknown methods and missing requests", () => {
    const entity = parseBurpExport(
      exportXml(item({ entityComment: "Tom &amp; Jerry" })),
    );
    expect(entity.requests[0]?.name).toBe("Tom & Jerry");

    const connect = parseBurpExport(
      exportXml(
        item({ request: `CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n` }),
      ),
    );
    expect(connect.requests[0]?.request).toBeNull();
    expect(connect.requests[0]?.warnings.join(" ")).toContain("CONNECT tunnels");

    const method = parseBurpExport(
      exportXml(item({ request: `PROPFIND /dav HTTP/1.1\r\nHost: example.com\r\n\r\n` })),
    );
    expect(method.requests[0]?.request).toBeNull();
    expect(method.requests[0]?.warnings.join(" ")).toContain("Unsupported method: PROPFIND");

    const missing = parseBurpExport(exportXml(`${item({ comment: "Kept" })}<item><url>/x</url></item>`));
    expect(missing.requests).toHaveLength(1);
    expect(missing.warnings.join(" ")).toContain("Skipped 1 item without a request");
  });

  it("rejects responses-only exports and warns about GET bodies", () => {
    expect(() => parseBurpExport(exportXml(`<item><request></request></item>`))).toThrow(
      /no requests/i,
    );
    const getWithBody = parseBurpExport(
      exportXml(
        item({ request: `GET /g HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc`, path: "/g" }),
      ),
    );
    expect(getWithBody.requests[0]?.warnings.join(" ")).toContain("GET bodies are not sent by Replay.");
  });

  it("disables items with invalid base64 or oversized bodies while keeping the rest", () => {
    const invalid = parseBurpExport(
      exportXml(
        item({ payload: "not base64 !!!", path: "/bad" }) +
          item({
            request: `GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n`,
            path: "/ok",
          }),
      ),
    );
    expect(invalid.requests).toHaveLength(2);
    expect(invalid.requests[0]?.request).toBeNull();
    expect(invalid.requests[0]?.warnings.join(" ")).toContain("invalid base64");
    expect(invalid.requests[1]?.request?.url).toBe("https://example.com/ok");

    const bigBody = "x".repeat(1_000_001);
    const oversized = parseBurpExport(
      exportXml(
        item({
          request: `POST /big HTTP/1.1\r\nHost: example.com\r\nContent-Length: ${bigBody.length}\r\n\r\n${bigBody}`,
          path: "/big",
          method: "POST",
        }),
      ),
    );
    expect(oversized.requests[0]?.request).toBeNull();
    expect(oversized.requests[0]?.warnings.join(" ")).toContain("Request body exceeds 1 MB");
  });

  it("deduplicates identical tab names", () => {
    const result = parseBurpExport(exportXml(item({ comment: "Same" }) + item({ comment: "Same" })));
    expect(result.requests.map((request) => request.name)).toEqual(["Same", "Same (2)"]);
  });

  it("enforces the 10 MB file limit", () => {
    const oversized = `${exportXml(item())}${" ".repeat(MAX_BURP_BYTES)}`;
    expect(() => parseBurpExport(oversized)).toThrow("File exceeds the 10 MB limit.");
  });
});

describe("Burp project handling", () => {
  it("explains how to export a binary .burp project instead of guessing", () => {
    const binary = `\u0000\u0001burp\u0007${"\u0000".repeat(64)}`;
    expect(() => parseBurpExport(binary)).toThrow(BURP_PROJECT_HELP);
    expect(BURP_PROJECT_HELP).toContain("Save items");
  });

  it("imports a prub JSON project export with Repeater captions", () => {
    const request = (method: string, target: string, host: string) =>
      base64(`${method} ${target} HTTP/1.1\r\nHost: ${host}\r\n\r\n`);
    const source = JSON.stringify({
      burp_schema: 226,
      project_name: "example",
      proxy: [{ id: "proxy-000001", request_base64: request("GET", "/from-proxy", "example.com"), response_base64: null }],
      repeater: [
        {
          id: "repeater-000001",
          request_base64: request("POST", "/from-repeater", "api.example.com"),
          response_base64: null,
          tab: { caption: "login attempt", uuid: "a1b297a2-203f-433a-88ae-6e6d964c3a5e" },
          group: null,
          pair_index: 1,
        },
      ],
      target: [{ id: "target-000001", request_base64: null, response_base64: null }],
    });
    const result = parseBurpExport(source, "export.json");
    expect(result.name).toBe("Burp project export · schema 226");
    expect(result.requests.map((request) => request.name)).toEqual([
      "proxy-000001",
      "login attempt",
    ]);
    expect(result.requests[0]?.request?.url).toBe("http://example.com/from-proxy");
    expect(result.requests[1]?.request?.method).toBe("POST");
    expect(result.warnings.join(" ")).toContain("Skipped 1 entry without a stored request");
    expect(result.warnings.join(" ")).toContain("default to http");
    expect(result.warnings.join(" ")).toContain("Repeater tab groups are not imported");
  });

  it("rejects unrelated JSON and non-Burp text", () => {
    expect(() => parseBurpExport('{"items":[]}')).toThrow(/prub JSON export/);
    expect(() => parseBurpExport("hello")).toThrow(/Burp XML export/);
    expect(() => parseBurpExport("   ")).toThrow(/empty/i);
  });
});
