import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import { svgEntitySignature } from "../lib/scan/svg-entity-check";

const payload = '<svg xmlns="http://www.w3.org/2000/svg"><a href="&Tab;javascript:alert(1)">x</a></svg>';

it("signatures the SVG entity/named-reference collision", () => {
  expect(svgEntitySignature(payload)).toBe(true);
  expect(svgEntitySignature('<svg><a href="#safe">x</a></svg>')).toBe(false);
  expect(svgEntitySignature('<div>no svg</div>')).toBe(false);
});

it("reports the payload without clicking or executing it", async () => {
  const check = getScanCheck("svg-entity-xss");
  const context = {
    request: { method: "GET", url: "https://app.test/", headers: {}, body: "" },
    baselines: [
      {
        response: { status: 200, responseHeaders: { "content-type": "image/svg+xml" }, responseBody: payload },
        evidence: { id: "baseline" },
      },
    ],
    stable: true,
    probe: async () => {
      throw Error("SVG signature inspection must not send requests");
    },
    nonce: () => "marker",
  } as never;
  const output = await check.run(context);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.severity).toBe("medium");
  expect(output.findings[0]?.verification.outcome).toBe("inconclusive");
});
