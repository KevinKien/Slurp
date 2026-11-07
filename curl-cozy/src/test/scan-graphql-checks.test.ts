import { expect, it } from "vitest";
import { tokenGraphqlChecks } from "../lib/scan/token-graphql-checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";

const request = {
  method: "POST",
  url: "https://example.test/graphql",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ query: "{ __typename }" }),
};
let next = 0;
function exchange(body: unknown, status = 200): Exchange {
  const text = JSON.stringify(body);
  return {
    response: {
      status,
      responseHeaders: { "content-type": "application/json" },
      responseBody: text,
      duration: 10,
      size: text.length,
    },
    evidence: {
      id: `g${++next}`,
      label: "fixture",
      timestamp: new Date().toISOString(),
      request,
      setCookies: [],
      duration: 10,
      size: text.length,
      truncated: false,
    },
  };
}
function aliases(query: string): string[] {
  return [...query.matchAll(/([A-Za-z_][\w]*)\s*:\s*__typename/g)].map((match) => match[1]!);
}
function context(): ScanCheckContext {
  return {
    request,
    baselines: [exchange({ data: { __typename: "Query" } })],
    stable: true,
    probe: async (input) => {
      const body = JSON.parse(input.body);
      const operations: { query: string }[] = Array.isArray(body) ? body : [body];
      const results = operations.map((operation) => ({
        data: Object.fromEntries(aliases(operation.query).map((name) => [name, "Query"])),
      }));
      return exchange(Array.isArray(body) ? results : results[0]);
    },
    nonce: () => `marker${++next}`,
  };
}
const check = tokenGraphqlChecks.find((item) => item.id === "graphql-batching")!;

it("reports array batching and 20-alias execution with read-only controls", async () => {
  const output = await check.run(context());
  expect(output.findings).toHaveLength(2);
  const text = output.findings.map((finding) => `${finding.title} ${finding.summary}`).join(" ");
  expect(text).toContain("two-operation read-only batch");
  expect(text).toContain("20 __typename aliases");
  expect(output.message).toContain("rate-limit bypass was not exercised");
});
it("does not report batching when aliases are dropped or the batch is not an array", async () => {
  const ctx = context();
  ctx.probe = async (input) => {
    const body = JSON.parse(input.body);
    if (Array.isArray(body)) return exchange({ data: { __typename: "Query" } });
    const names = aliases(body.query);
    return exchange({ data: Object.fromEntries(names.slice(0, 3).map((name) => [name, "Query"])) });
  };
  const output = await check.run(ctx);
  expect(output.findings).toHaveLength(0);
  expect(output.inconclusive).toBeFalsy();
});
