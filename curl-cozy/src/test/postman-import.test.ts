import { describe, it, expect } from "vitest";
import {
  parsePostmanCollection,
  parsePostmanEnvironment,
  mergePostmanVariables,
  missingPostmanVariables,
} from "../lib/postman-import";
const collection = (item: unknown[], extra: object = {}) =>
  JSON.stringify({
    info: {
      name: "Test collection",
      schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    item,
    ...extra,
  });
const item = (request: unknown, name = "Login") => ({ name, request });
describe("Postman Collection import", () => {
  it("imports nested requests, collection variables and raw JSON body", () => {
    const result = parsePostmanCollection(
      collection(
        [
          {
            name: "Auth",
            item: [
              item({
                method: "POST",
                url: "{{base_url}}/login",
                body: {
                  mode: "raw",
                  raw: '{"email":"{{email}}"}',
                  options: { raw: { language: "json" } },
                },
              }),
            ],
          },
        ],
        {
          variable: [
            { key: "base_url", value: "https://example.com" },
            { key: "email", value: "a@example.com" },
            { key: "disabled", value: "x", disabled: true },
          ],
        },
      ),
    );
    expect(result.requests[0]).toMatchObject({
      name: "Auth / Login",
      request: {
        method: "POST",
        url: "{{base_url}}/login",
        headers: { "Content-Type": "application/json" },
        body: '{"email":"{{email}}"}',
      },
    });
    expect(result.variables).toEqual({ base_url: "https://example.com", email: "a@example.com" });
    expect(missingPostmanVariables(result.requests, result.variables)).toEqual([]);
  });
  it("supports v2.0 and string request URLs", () => {
    expect(
      parsePostmanCollection(collection([item("https://example.com")]).replace("v2.1.0", "v2.0.0"))
        .requests[0]?.request?.method,
    ).toBe("GET");
  });
  it("reconstructs structured URLs, excludes disabled query and header entries and resolves path parameters", () => {
    const result = parsePostmanCollection(
      collection([
        item({
          method: "GET",
          url: {
            protocol: "https",
            host: ["api", "example", "com"],
            path: ["users", ":id"],
            variable: [{ key: "id", value: "42" }],
            query: [
              { key: "q", value: "{{search}}" },
              { key: "disabled", value: "no", disabled: true },
            ],
          },
          header: [
            { key: "X-Test", value: "yes" },
            { key: "Disabled", value: "no", disabled: true },
          ],
        }),
      ]),
    );
    expect(result.requests[0]?.request).toMatchObject({
      url: "https://api.example.com/users/42?q={{search}}",
      headers: { "X-Test": "yes" },
    });
    expect(missingPostmanVariables(result.requests, {})).toEqual(["search"]);
  });
  it("uses raw URL and removes disabled structured query parameters", () => {
    expect(
      parsePostmanCollection(
        collection([
          item({
            url: {
              raw: "https://example.com/?a=1&b=2#part",
              query: [
                { key: "a", value: "1" },
                { key: "b", value: "2", disabled: true },
              ],
            },
          }),
        ]),
      ).requests[0]?.request?.url,
    ).toBe("https://example.com/?a=1#part");
  });
  it("inherits auth and scripts but request noauth overrides inherited auth", () => {
    const result = parsePostmanCollection(
      collection([
        {
          name: "Folder",
          auth: { type: "bearer", bearer: [{ key: "token", value: "{{token}}" }] },
          event: [{ listen: "test", script: { exec: ['pm.test("x",()=>{});'] } }],
          item: [
            item({ url: "https://example.com" }),
            item({ url: "https://example.com", auth: { type: "noauth" } }, "Public"),
          ],
        },
      ]),
    );
    expect(result.requests[0]?.request?.headers).toEqual({ Authorization: "Bearer {{token}}" });
    expect(result.requests[1]?.request?.headers).toEqual({});
    expect(result.requests[0]?.scripts[0]).toContain("pm.test");
    expect(result.requests[0]?.warnings[0]).toContain("not converted");
  });
  it("converts literal Basic auth and preserves explicit authorization headers", () => {
    const result = parsePostmanCollection(
      collection([
        item({
          url: "https://example.com",
          auth: {
            type: "basic",
            basic: [
              { key: "username", value: "user" },
              { key: "password", value: "pass" },
            ],
          },
        }),
        item({ url: "https://example.com", header: "Authorization: custom\r\nX-Test: yes" }),
      ]),
    );
    expect(result.requests[0]?.request?.headers["Authorization"]).toBe("Basic dXNlcjpwYXNz");
    expect(result.requests[1]?.request?.headers).toEqual({
      Authorization: "custom",
      "X-Test": "yes",
    });
  });
  it.each(["formdata", "file", "graphql", "urlencoded"])(
    "disables unsupported %s bodies without importing partial requests",
    (mode) => {
      const result = parsePostmanCollection(
        collection([item({ url: "https://example.com", method: "POST", body: { mode } })]),
      );
      expect(result.requests[0]?.request).toBeNull();
      expect(result.requests[0]?.warnings[0]).toContain("Unsupported body");
    },
  );
  it("disables unsupported auth and Basic auth placeholders", () => {
    const result = parsePostmanCollection(
      collection([
        item({ url: "https://example.com", auth: { type: "oauth2" } }),
        item({
          url: "https://example.com",
          auth: { type: "basic", basic: [{ key: "password", value: "{{password}}" }] },
        }),
      ]),
    );
    expect(result.requests.every((r) => r.request === null)).toBe(true);
  });
  it("rejects duplicate headers, invalid methods, credentials and oversized bodies per request", () => {
    const requests = [
      {
        url: "https://example.com",
        header: [
          { key: "x", value: "1" },
          { key: "X", value: "2" },
        ],
      },
      { url: "https://example.com", method: "OTHER" },
      { url: "https://user:pass@example.com" },
      {
        url: "https://example.com",
        method: "POST",
        body: { mode: "raw", raw: "x".repeat(1_000_001) },
      },
    ];
    expect(
      parsePostmanCollection(collection(requests.map((r) => item(r)))).requests.every(
        (r) => r.request === null,
      ),
    ).toBe(true);
  });
  it("rejects invalid JSON, unsupported documents and collections exceeding item limits", () => {
    expect(() => parsePostmanCollection("{")).toThrow("valid JSON");
    expect(() => parsePostmanCollection('{"items":[]}')).toThrow("v2.0 or v2.1");
    expect(() =>
      parsePostmanCollection(
        collection(Array.from({ length: 501 }, () => item("https://example.com"))),
      ),
    ).toThrow("500 requests");
  });
  it("imports environment values and keeps existing workspace values unless overwrite is enabled", () => {
    const env = parsePostmanEnvironment(
      JSON.stringify({
        values: [
          { key: "token", value: "new" },
          { key: "disabled", value: "x", enabled: false },
          { key: "count", value: 42 },
          { key: "invalid name", value: "skip" },
        ],
      }),
    );
    expect(env.variables).toEqual({ token: "new", count: "42" });
    expect(env.warnings).toHaveLength(1);
    expect(mergePostmanVariables({ token: "old" }, env.variables, false)).toEqual({
      token: "old",
      count: "42",
    });
    expect(mergePostmanVariables({ token: "old" }, env.variables, true)["token"]).toBe("new");
    expect(() => parsePostmanEnvironment("{}")).toThrow("Environment");
  });
  it("handles special object keys without prototype mutation and enforces merged variable count", () => {
    const result = parsePostmanCollection(
      collection([item("https://example.com")], {
        variable: [{ key: "__proto__", value: "safe" }],
      }),
    );
    expect(Object.hasOwn(result.variables, "__proto__")).toBe(true);
    expect(Object.getPrototypeOf(result.variables)).toBe(Object.prototype);
    expect(() =>
      mergePostmanVariables(
        Object.fromEntries(Array.from({ length: 100 }, (_, i) => ["v" + i, "x"])),
        { extra: "x" },
        false,
      ),
    ).toThrow("100");
  });
});
