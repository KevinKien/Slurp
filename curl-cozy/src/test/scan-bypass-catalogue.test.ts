import { expect, it } from "vitest";
import { bypassCatalogue } from "../lib/scan/bypass-catalogue";

it("catalogues every bypass layer with concrete vectors", () => {
  expect(Object.keys(bypassCatalogue)).toEqual([
    "encoding",
    "caseSpace",
    "keyword",
    "path",
    "hostUrl",
    "header",
    "contentType",
    "auth",
    "rateLimit",
    "waf",
    "sanitizer",
    "cache",
  ]);
  expect(bypassCatalogue.path).toContain("..;/");
  expect(bypassCatalogue.path).toContain("%c0%af");
  expect(bypassCatalogue.encoding.unicode).toContain("%uff0e");
  expect(bypassCatalogue.keyword.some((value) => value.includes("CONCAT"))).toBe(true);
  expect(bypassCatalogue.header).toContain("X-Rewrite-URL");
  expect(bypassCatalogue.sanitizer).toContain("mXSS");
});
