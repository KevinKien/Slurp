import { expect, it } from "vitest";
import { scanChecks } from "../lib/scan/checks";
import { mxssPayloads } from "../lib/scan/browser-checks";
import { metadata } from "../lib/scan/registry";

it("ships annotation-xml payloads for the ammonia mXSS case", () => {
  const values = mxssPayloads.map((payload) => payload("marker"));
  expect(values).toHaveLength(4);
  expect(values.every((value) => value.includes("annotation-xml"))).toBe(true);
  expect(values.some((value) => value.includes("<style>"))).toBe(true);
  expect(values.some((value) => value.includes("srcdoc"))).toBe(true);
  expect(scanChecks.some((check) => check.id === "mxss")).toBe(true);
  expect(metadata("mxss").category).toBe("Browser");
  expect(metadata("mxss").impact).toBe("medium");
});
