import { describe, expect, it } from "vitest";
import { parse } from "shell-quote";
import { toCurl, requestFromHeld } from "@/lib/request-actions";
import type { HeldItem } from "@/lib/api";
import { formatHeld } from "@/lib/intercept";
const request = {
  method: "POST",
  url: "https://example.com/api?q=a&b=2",
  headers: {
    "Content-Type": "application/json",
    Authorization: "Bearer token",
    "Content-Length": "999",
  },
  body: '{"name":"O\'Brien","value":"$(touch /tmp/no) `echo no`"}',
};
const held: HeldItem = {
  id: "h1",
  phase: "request",
  created_at: "2026-01-01T00:00:00Z",
  scheme: "https",
  host: "example.com",
  url: "https://example.com/api",
  method: "POST",
  path: "/api",
  status: null,
  headers: [["Content-Type", "application/json"]],
  body: "original",
  body_size: 8,
  body_editable: true,
};
describe("Request context actions", () => {
  it("exports shell-safe cURL preserving URL, headers and literal body", () => {
    const command = toCurl(request);
    const tokens = parse(command);
    expect(tokens).toEqual([
      "curl",
      "--globoff",
      "--path-as-is",
      "--url",
      request.url,
      "--header",
      "Content-Type: application/json",
      "--header",
      "Authorization: Bearer token",
      "--data-raw",
      request.body,
      "--request",
      "POST",
    ]);
    expect(command).not.toContain("Content-Length");
  });
  it("supports HEAD and rejects unrepresentable shell values", () => {
    expect(parse(toCurl({ ...request, method: "HEAD", headers: {}, body: "" }))).toContain(
      "--head",
    );
    expect(() => toCurl({ ...request, body: "a\0b" })).toThrow(/NUL/);
    expect(() => toCurl({ ...request, url: "file:///etc/passwd" })).toThrow(/HTTP/);
  });
  it("uses edited Intercept request content without changing the destination host", () => {
    const draft = formatHeld(held)
      .replace("POST /api", "PUT //other.example/edited")
      .replace("original", "changed");
    const result = requestFromHeld(held, draft);
    expect(result.method).toBe("PUT");
    expect(result.url).toBe("https://example.com//other.example/edited");
    expect(result.body).toBe("changed");
  });
  it("uses the originating request for held responses, never response headers or body", () => {
    const response: HeldItem = {
      ...held,
      phase: "response",
      status: 200,
      body: "response body",
      headers: [["Set-Cookie", "response-cookie"]],
      request: {
        method: "POST",
        url: held.url,
        headers: [["Authorization", "Bearer original"]],
        body: "request body",
      },
    };
    expect(requestFromHeld(response)).toEqual({
      method: "POST",
      url: held.url,
      headers: { Authorization: "Bearer original" },
      body: "request body",
    });
    expect(() => requestFromHeld({ ...response, request: null })).toThrow(/original request/);
  });
});
