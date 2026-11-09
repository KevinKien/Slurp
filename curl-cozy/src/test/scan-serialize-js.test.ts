import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import { serializeFunctionSignature } from "../lib/scan/serialize-js-check";

const payload = "function f(x){ return x</script=+/ + '</script><img src=x onerror=alert(1)>' }";

it("signatures the serialize-javascript 7.1.1 function-body shape", () => {
  expect(serializeFunctionSignature(payload)).toBe(true);
  expect(serializeFunctionSignature('<img src=x onerror=alert(1)>')).toBe(false);
  expect(serializeFunctionSignature("<div>plain</div>")).toBe(false);
});

it("reports the signature without sending a request", async () => {
  const check = getScanCheck("serialize-js-xss");
  const context = {
    request: { method: "GET", url: "https://app.test/", headers: {}, body: "" },
    baselines: [
      {
        response: { status: 200, responseHeaders: { "content-type": "text/html" }, responseBody: payload },
        evidence: { id: "baseline" },
      },
    ],
    stable: true,
    probe: async () => {
      throw Error("signature inspection must not send requests");
    },
    nonce: () => "marker",
  } as never;
  const output = await check.run(context);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.severity).toBe("medium");
  expect(output.findings[0]?.verification.outcome).toBe("inconclusive");
});
