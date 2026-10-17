import { describe, expect, it } from "vitest";
import {
  normalizeVariables,
  replayQuery,
  setReplayQuery,
  resolveReplayRequest,
} from "@/lib/replay-features";
import { nextReplayTabId, serializeTabs } from "@/lib/replay-tabs";
import { parseRawRequest, requestText } from "@/lib/traffic";
const template = {
  method: "POST",
  url: "{{base_url}}/users/{{id}}",
  headers: { Authorization: "Bearer {{ token }}", "Content-Type": "application/json" },
  body: '{"name":"{{name}}"}',
};
const variables = { base_url: "https://example.com", id: "42", token: "secret", name: "Alex" };
describe("Replay variables and snapshots", () => {
  it("resolves URL, headers and body without mutating the template", () => {
    const request = resolveReplayRequest(template, variables);
    expect(request).toEqual({
      method: "POST",
      url: "https://example.com/users/42",
      headers: { Authorization: "Bearer secret", "Content-Type": "application/json" },
      body: '{"name":"Alex"}',
    });
    expect(template.url).toBe("{{base_url}}/users/{{id}}");
    variables.token = "new-token";
    expect(request.headers["Authorization"]).toBe("Bearer secret");
    variables.token = "secret";
  });
  it("rejects missing, inherited and unclosed variables, and header injection", () => {
    expect(() => resolveReplayRequest(template, {})).toThrow("Missing variable");
    expect(() =>
      resolveReplayRequest({ ...template, url: "https://example.com/{{toString}}" }, {}),
    ).toThrow("Missing variable");
    expect(() =>
      resolveReplayRequest({ ...template, url: "https://example.com/{{broken" }, variables),
    ).toThrow("Unclosed");
    expect(() =>
      resolveReplayRequest(template, { ...variables, token: "a\r\nInjected: yes" }),
    ).toThrow("header");
  });
  it("inserts variable values once and preserves literal dollar signs", () => {
    const result = resolveReplayRequest(
      { ...template, body: "{{name}}" },
      { ...variables, name: "$& {{token}}" },
    );
    expect(result.body).toBe("$& {{token}}");
  });
  it("normalizes older documents and saves variables alongside drafts without runtime state", () => {
    expect(normalizeVariables({ tabs: [] })).toEqual({});
    expect(normalizeVariables({ variables: { ok: "value", "bad name": "x", invalid: 4 } })).toEqual(
      { ok: "value" },
    );
    const doc = serializeTabs([{ id: 1, name: "Login", request: template }], 1, variables);
    expect(doc.variables).toEqual(variables);
    expect(doc.tabs[0]?.request).toEqual(template);
  });
  it("round-trips variable templates through the raw editor", () => {
    expect(parseRawRequest(requestText(template), template.url)).toEqual(template);
  });
  it("does not recycle a closed tab ID", () => {
    const id = nextReplayTabId([{ id: 1 }]);
    expect(nextReplayTabId([{ id: 1 }])).toBeGreaterThan(id);
  });
});

it("preserves placeholders when editing query parameters with a variable base URL", () => {
  const url = "{{base_url}}/users?q={{token}}#details";
  expect(replayQuery(url)).toEqual([["q", "{{token}}"]]);
  expect(
    setReplayQuery(url, [
      ["q", "{{token}}"],
      ["name", "a b"],
    ]),
  ).toBe("{{base_url}}/users?q={{token}}&name=a+b#details");
});
