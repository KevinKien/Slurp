import { expect, it } from "vitest";
import { scanChecks } from "../lib/scan/checks";
import { quasarPayloads } from "../lib/scan/browser-checks";
import { metadata } from "../lib/scan/registry";

it("ships Quasar getHead title/meta breakout payloads", () => {
  const values = quasarPayloads.map((payload) => payload("marker"));
  expect(values).toHaveLength(4);
  expect(values.every((value) => value.includes("__slurpXss('marker')"))).toBe(true);
  expect(values.some((value) => value.startsWith("</title><script>"))).toBe(true);
  expect(values.some((value) => value.includes("onerror"))).toBe(true);
  expect(scanChecks.some((check) => check.id === "quasar-meta-xss")).toBe(true);
  expect(metadata("quasar-meta-xss").category).toBe("Browser");
  expect(metadata("quasar-meta-xss").impact).toBe("medium");
});
