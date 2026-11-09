import { expect, it } from "vitest";
import { scanChecks } from "../lib/scan/checks";
import { metadata } from "../lib/scan/registry";
import { prototypeXssUrls } from "../lib/scan/prototype-xss";

it("builds Apostrophe/Vue innerHTML pollution URLs and registers the check", () => {
  const urls = prototypeXssUrls("https://app.test/admin?x=1", "marker");
  expect(urls).toHaveLength(2);
  expect(urls[0]).toContain("&__proto__[innerHTML]=");
  expect(decodeURIComponent(urls[0]!)).toContain("__slurpXss('marker')");
  expect(urls[1]).toContain("constructor[prototype][innerHTML]");
  expect(scanChecks.some((check) => check.id === "prototype-xss")).toBe(true);
  expect(metadata("prototype-xss").category).toBe("Browser");
  expect(metadata("prototype-xss").impact).toBe("medium");
});
