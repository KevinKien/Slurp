import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import type { Exchange, ScanCheckContext } from "../lib/scan/types";

const boundary = "slurp-boundary";
function multipart(filename = "a.jpg") {
  return `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: image/jpeg\r\n\r\nDATA\r\n--${boundary}--\r\n`;
}
const request = {
  method: "POST",
  url: "https://example.test/api/upload",
  headers: { "content-type": `multipart/form-data; boundary=${boundary}` },
  body: multipart(),
};
const exchange = (body: string, status = 200): Exchange => ({
  response: { status, responseHeaders: { "content-type": "application/json" }, responseBody: body, duration: 1, size: body.length },
  evidence: {
    id: Math.random().toString(),
    label: "fixture",
    timestamp: new Date().toISOString(),
    request,
    setCookies: [],
    duration: 1,
    size: body.length,
    truncated: false,
  },
});
function context(probe: ScanCheckContext["probe"], baselines = [exchange('{"ok":true}')]): ScanCheckContext {
  let nonce = 0;
  return { request, baselines, stable: true, probe, nonce: () => `marker${++nonce}` };
}

it("upload reports an accepted .php filename only when the baseline upload succeeds", async () => {
  const vulnerable = context(async () => exchange('{"ok":true}'));
  const output = await getScanCheck("file-upload").run(vulnerable);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.severity).toBe("high");
  expect(output.findings[0]?.summary).toContain("not executable code");

  const strict = context(async (req) =>
    exchange(req.body.includes('filename="a.jpg"') ? '{"ok":true}' : "rejected", req.body.includes('filename="a.jpg"') ? 200 : 403),
  );
  expect((await getScanCheck("file-upload").run(strict)).findings).toHaveLength(0);
});

it("upload reports a double-extension bypass when plain .php is rejected", async () => {
  const bypass = context(async (req) => {
    if (req.body.includes('filename="a.jpg"')) return exchange('{"ok":true}');
    const plain = /filename="[^"]*\.php"/.test(req.body);
    return exchange(plain ? "rejected" : '{"ok":true}', plain ? 403 : 200);
  });
  const output = await getScanCheck("file-upload").run(bypass);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("double extension");
});

it("path traversal accepts encoded and null-byte variants without a plain match", async () => {
  const ctx = context(
    async (req) => {
      const value = new URL(req.url).searchParams.get("q") ?? "";
      return exchange(
        value.includes("....//") || value.includes("\u0000")
          ? "root:x:0:0:root:/root:/bin/bash"
          : "not found",
      );
    },
    [exchange("not found")],
  );
  ctx.request = { method: "GET", url: "https://example.test/api?q=original", headers: {}, body: "" };
  (ctx.parameter as { kind: "query"; name: string; occurrence: number }) = { kind: "query", name: "q", occurrence: 0 };
  // restore baseline request context
  ctx.baselines = [exchange("not found")];
  const output = await getScanCheck("path-traversal").run(ctx);
  expect(output.findings).toHaveLength(1);
});

it("file inclusion reports expect://id command output", async () => {
  const ctx = context(
    async (req) => {
      const value = new URL(req.url).searchParams.get("q") ?? "";
      return exchange(
        value === "expect://id" ? "uid=0(root) gid=0(root)" : "ok",
      );
    },
    [exchange("ok")],
  );
  ctx.request = { method: "GET", url: "https://example.test/api?q=original", headers: {}, body: "" };
  (ctx.parameter as { kind: "query"; name: string; occurrence: number }) = { kind: "query", name: "q", occurrence: 0 };
  const output = await getScanCheck("file-inclusion").run(ctx);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.title).toContain("wrapper");
});
