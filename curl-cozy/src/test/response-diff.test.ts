import { it, expect } from "vitest";
import { compareResponses, lineDiff } from "../lib/response-diff";
const response = (body: string, status = 200, headers: Record<string, string> = {}) => ({
  status,
  responseHeaders: headers,
  responseBody: body,
});
it("compares JSON structurally while ignoring selected fields and header casing", () => {
  const a = response('{"a":1,"timestamp":"old","data":{"id":2}}', 200, {
    "Content-Type": "application/json",
    Date: "old",
  });
  const b = response('{"data":{"id":2},"timestamp":"new","a":1}', 200, {
    "content-type": "application/json",
    date: "new",
  });
  expect(compareResponses(a, b).equal).toBe(false);
  expect(
    compareResponses(a, b, { ignoredHeaders: ["date"], ignoredPaths: ["timestamp"] }).equal,
  ).toBe(true);
});
it("keeps status and meaningful header differences visible", () => {
  const diff = compareResponses(response("{}"), response("{}", 403, { "x-role": "admin" }));
  expect(diff.statusChanged).toBe(true);
  expect(diff.headersChanged).toBe(true);
  expect(diff.bodyChanged).toBe(false);
});
it("supports JSON pointers and preserves text whitespace", () => {
  expect(
    compareResponses(response('{"data":{"a/b":"x"}}'), response('{"data":{"a/b":"y"}}'), {
      ignoredHeaders: [],
      ignoredPaths: ["/data/a~1b"],
    }).equal,
  ).toBe(true);
  expect(compareResponses(response(" a\r\nb"), response(" a\nb")).equal).toBe(true);
  expect(compareResponses(response(" a"), response("a")).equal).toBe(false);
});
it("highlights insertions and deletions and reports truncation without hiding full-body differences", () => {
  expect(lineDiff("a\nb", "a\nc\nb").lines).toContainEqual({ kind: "added", text: "c" });
  expect(lineDiff("a\nb", "b").lines).toContainEqual({ kind: "removed", text: "a" });
  const a = Array(800).fill("same").join("\n");
  const b = a + "\nchanged";
  expect(lineDiff(a, b).truncated).toBe(true);
  expect(compareResponses(response(a), response(b)).bodyChanged).toBe(true);
});
