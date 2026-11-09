import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import { twigConcatSignature } from "../lib/scan/twig-concat-check";

const payload = '<img src=1 {{"on"~"error"}}=alert(1)>';

it("signatures Twig concatenation that builds an event handler", () => {
  expect(twigConcatSignature(payload)).toBe(true);
  expect(twigConcatSignature('<a href="{{"java"~"script"}}:alert(1)">x</a>')).toBe(true);
  expect(twigConcatSignature("<div>{{ 1 ~ 2 }}</div>")).toBe(false);
  expect(twigConcatSignature("<img src=1 onerror=alert(1)>")).toBe(false);
});

it("reports the Twig signature without rendering it", async () => {
  const check = getScanCheck("twig-concat-xss");
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
      throw Error("Twig signature inspection must not send requests");
    },
    nonce: () => "marker",
  } as never;
  const output = await check.run(context);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.severity).toBe("medium");
  expect(output.findings[0]?.verification.outcome).toBe("inconclusive");
});
