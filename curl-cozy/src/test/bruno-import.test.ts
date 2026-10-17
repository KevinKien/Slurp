import { describe, it, expect } from "vitest";
import { parseBrunoFiles, parseBrunoEnvironment } from "../lib/bruno-import";
const source = (extra = "", request = "post", bodyMode = "json") => `meta {
  name: Login
  type: http
  seq: 1
}

${request} {
  url: {{base_url}}/login
  body: ${bodyMode}
  auth: none
}
${extra}`;
const parse = (content: string, name = "login.bru") => parseBrunoFiles([{ name, source: content }]);
describe("native Bruno .bru imports", () => {
  it("parses JSON bodies without evaluating templates or scripts", () => {
    const result = parse(
      source(`body:json {
  {
    "email": "{{email}}",
    "nested": {"key": "value"}
  }
}
headers {
  X-Enabled: yes
  ~X-Disabled: no
}`),
    );
    expect(result.requests[0]).toMatchObject({
      name: "Login",
      request: {
        method: "POST",
        url: "{{base_url}}/login",
        headers: { "Content-Type": "application/json", "X-Enabled": "yes" },
        body: expect.stringContaining('"nested": {"key": "value"}'),
      },
    });
  });
  it("imports multiple requests with unique IDs and preserves user-selected order", () => {
    const result = parseBrunoFiles([
      { name: "a.bru", source: source() },
      { name: "b.bru", source: source().replace("name: Login", "name: Profile") },
    ]);
    expect(result.requests.map((r) => [r.id, r.name])).toEqual([
      [0, "Login"],
      [1, "Profile"],
    ]);
  });
  it("maps enabled query and path parameters", () => {
    const result = parse(
      source(
        `params:query {
  search: {{term}}
  ~disabled: no
}
params:path {
  id: 42
}`,
        "get",
        "none",
      ).replace("/login", "/users/:id"),
    );
    expect(result.requests[0]?.request?.url).toBe("{{base_url}}/users/42?search={{term}}");
  });
  it("converts Bearer and literal Basic auth", () => {
    const bearer = parse(
      source(`auth:bearer {
  token: {{token}}
}`).replace("auth: none", "auth: bearer"),
    );
    expect(bearer.requests[0]?.request?.headers["Authorization"]).toBe("Bearer {{token}}");
    const basic = parse(
      source(`auth:basic {
  username: user
  password: pass
}`).replace("auth: none", "auth: basic"),
    );
    expect(basic.requests[0]?.request?.headers["Authorization"]).toBe("Basic dXNlcjpwYXNz");
  });
  it("does not execute scripts and reports extractors and assertions", () => {
    const result = parse(
      source(`script:pre-request {
  globalThis.BRUNO_IMPORT_EXECUTED = true;
}
script:post-response {
  bru.setVar("token", res.body.token);
}
vars:pre-request {
  email: user@example.com
}
vars:post-response {
  token: res.body.token
}
assert {
  res.status: eq 200
}
tests {
  test("ok", function() {});
}`),
    );
    expect(Object.hasOwn(globalThis, "BRUNO_IMPORT_EXECUTED")).toBe(false);
    expect(result.requests[0]?.scripts[0]).toContain("bru.setVar");
    expect(result.requests[0]?.warnings.join(" ")).toContain("Request-scoped variables");
    expect(result.requests[0]?.warnings.join(" ")).toContain("assertions");
    expect(result.variables).toEqual({});
  });
  it.each(["form-urlencoded", "multipart-form", "file", "graphql"])(
    "disables unsupported %s bodies",
    (mode) => {
      const result = parse(source("", "post", mode));
      expect(result.requests[0]?.request).toBeNull();
      expect(result.requests[0]?.warnings[0]).toContain("Unsupported Bruno body");
    },
  );
  it("disables unresolved inherited auth instead of silently stripping it", () => {
    const result = parse(source().replace("auth: none", "auth: inherit"));
    expect(result.requests[0]?.request).toBeNull();
    expect(result.requests[0]?.warnings[0]).toContain("Inherited");
  });
  it("isolates malformed files so other selected requests can still be imported", () => {
    const result = parseBrunoFiles([
      { name: "bad.bru", source: "meta { broken" },
      { name: "good.bru", source: source() },
    ]);
    expect(result.requests[0]?.request).toBeNull();
    expect(result.requests[1]?.request?.method).toBe("POST");
  });
  it("supports text, XML and SPARQL bodies", () => {
    for (const mode of ["text", "xml", "sparql"]) {
      const result = parse(
        source(
          `body:${mode} {
  payload
}`,
          "post",
          mode,
        ),
      );
      expect(result.requests[0]?.request?.body).toBe("payload");
    }
  });
  it("imports environment values, skips disabled entries and warns about secret placeholders", () => {
    const result = parseBrunoEnvironment({
      name: "dev.bru",
      source: `vars {
  base_url: https://example.com
  ~disabled: no
}
vars:secret [
  token
]`,
    });
    expect(result.variables).toEqual({ base_url: "https://example.com" });
    expect(result.warnings[0]).toContain("Secret value");
  });
  it("rejects request files used as environments and rejects excessive input", () => {
    expect(() => parseBrunoEnvironment({ name: "request.bru", source: source() })).toThrow();
    expect(() => parseBrunoFiles([])).toThrow("at least one");
    expect(() =>
      parseBrunoFiles(Array.from({ length: 501 }, () => ({ name: "a.bru", source: "" }))),
    ).toThrow("500");
    expect(parse("x".repeat(2_000_001)).requests[0]?.warnings[0]).toContain("2 MB");
  });
});
