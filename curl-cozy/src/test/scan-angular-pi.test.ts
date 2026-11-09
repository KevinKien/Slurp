import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import { angularPiSignature } from "../lib/scan/angular-pi-check";

const payload = '<noscript><?x </noscript ?><img src=x onerror=alert(1)></noscript>';

it("signatures a processing instruction breaking a fallback container", () => {
  expect(angularPiSignature(payload)).toBe(true);
  expect(angularPiSignature('<noscript><p>plain</p></noscript>')).toBe(false);
  expect(angularPiSignature('<iframe><?x </iframe ?><img src=x onerror=alert(1)></iframe>')).toBe(true);
});

it("reports the serialized signature without executing it", async () => {
  const check = getScanCheck("angular-pi-xss");
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
