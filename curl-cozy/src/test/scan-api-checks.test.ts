import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";

const graphqlRequest = {
  method: "POST",
  url: "https://app.test/graphql",
  headers: { "content-type": "application/json", cookie: "session=abc" },
  body: JSON.stringify({ query: "{ __typename }" }),
};
const exchange = (body: string, status = 200): Exchange => ({
  response: { status, responseHeaders: { "content-type": "application/json" }, responseBody: body, duration: 1, size: body.length },
  evidence: {
    id: Math.random().toString(),
    label: "fixture",
    timestamp: new Date().toISOString(),
    request: graphqlRequest,
    setCookies: [],
    duration: 1,
    size: body.length,
    truncated: false,
  },
});
function context(probe: ScanCheckContext["probe"], request: ScanCheckContext["request"] = graphqlRequest): ScanCheckContext {
  let nonce = 0;
  return { request, baselines: [exchange("ok")], stable: true, probe, nonce: () => `marker${++nonce}` };
}

it("GraphQL endpoint discovery reports a __typename response", async () => {
  const ctx = context(async (req) => {
    const path = new URL(req.url).pathname;
    return path === "/api/graphql" && req.method === "POST"
      ? exchange('{"data":{"__typename":"Query"}}')
      : exchange("not found", 404);
  });
  const output = await getScanCheck("graphql-endpoint").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("GraphQL endpoint discovered");

  const clean = context(async () => exchange("not found", 404));
  expect((await getScanCheck("graphql-endpoint").run(clean)).findings).toHaveLength(0);
});

it("OpenAPI exposure reports a document with paths", async () => {
  const ctx = context(async (req) =>
    new URL(req.url).pathname === "/swagger.json"
      ? exchange('{"openapi":"3.0.0","paths":{"/users":{}}}')
      : exchange("not found", 404),
  );
  const output = await getScanCheck("openapi-exposure").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("API specification exposed");
});

it("JWT query detection is passive and reports a token parameter", async () => {
  const request = {
    method: "GET",
    url: "https://app.test/account?access_token=abcdefghijklmnop",
    headers: {},
    body: "",
  };
  const ctx = context(async () => exchange("ok"), request);
  const output = await getScanCheck("jwt-query").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.severity).toBe("low");
});

it("GraphQL field suggestions need a repeated suggestion error", async () => {
  const ctx = context(async (req) => {
    const body = typeof req.body === "string" ? req.body : "";
    return body.includes("slurp_")
      ? exchange('{"errors":[{"message":"Cannot query field. Did you mean id?"}]}')
      : exchange('{"data":{"__typename":"Query"}}');
  });
  const output = await getScanCheck("graphql-field-suggestion").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("field suggestions");
  expect(output.findings[0]?.severity).toBe("info");
});
