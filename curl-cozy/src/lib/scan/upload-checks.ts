import type { Exchange, ScanCheck, ScanCheckContext } from "./types";
import type { HttpRequest } from "../traffic";
import { ok, result, observation } from "./extended-checks";

type Part = { head: string; body: string };

function successful(x: Exchange) {
  return ok(x) && x.response!.status >= 200 && x.response!.status < 300;
}

function parseMultipart(request: HttpRequest, contentType: string) {
  const match = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
  const boundary = match?.[1] ?? match?.[2];
  if (!boundary || !request.body.includes(`--${boundary}`)) return undefined;
  const parts: Part[] = [];
  for (const chunk of request.body.split(`--${boundary}`).slice(1)) {
    if (chunk.startsWith("--")) break;
    const normalized = chunk.replace(/^\r?\n/, "").replace(/\r?\n$/, "");
    const separator = normalized.indexOf("\r\n\r\n");
    if (separator < 0) continue;
    parts.push({ head: normalized.slice(0, separator), body: normalized.slice(separator + 4) });
  }
  const index = parts.findIndex((part) => /filename\s*=\s*"[^"]*"/i.test(part.head));
  return index < 0 ? undefined : { boundary, parts, index };
}

function serialize(boundary: string, parts: Part[]) {
  return (
    parts.map((part) => `--${boundary}\r\n${part.head}\r\n\r\n${part.body}\r\n`).join("") +
    `--${boundary}--\r\n`
  );
}

function withPart(
  request: HttpRequest,
  header: string,
  boundary: string,
  parts: Part[],
  index: number,
  changes: { filename?: string; contentType?: string; body?: string },
): HttpRequest {
  const next = parts.map((part, i) => {
    if (i !== index) return part;
    let head = part.head;
    if (changes.filename)
      head = head.replace(/filename\s*=\s*"[^"]*"/i, `filename="${changes.filename}"`);
    if (changes.contentType) {
      head = /^content-type:/im.test(head)
        ? head.replace(/^content-type:.*$/im, `Content-Type: ${changes.contentType}`)
        : `${head}\r\nContent-Type: ${changes.contentType}`;
    }
    return { head, body: changes.body ?? part.body };
  });
  return {
    ...request,
    headers: { ...request.headers, [header]: request.headers[header]! },
    body: serialize(boundary, next),
  };
}

export const fileUpload: ScanCheck = {
  id: "file-upload",
  name: "File upload — extension, Content-Type and magic-byte bypass",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.stable) return result("Stable baselines required for upload checks.", true);
    const header = Object.keys(ctx.request.headers).find(
      (name) => name.toLowerCase() === "content-type",
    );
    if (!header) return result("A multipart/form-data upload request is required.", true);
    const parsed = parseMultipart(ctx.request, ctx.request.headers[header]!);
    if (!parsed)
      return result("A multipart upload with a filename part is required.", true);
    const control = await ctx.probe(ctx.request, "Upload original control");
    if (!successful(control))
      return result("Original upload did not succeed; baseline upload required.", true);
    const nonce = ctx.nonce().replace(/[^a-zA-Z0-9]/g, "");
    const base = `slurp_${nonce}`;
    const text = `SLURP-${nonce}`;
    const attempts = [
      {
        id: "php",
        filename: `${base}.php`,
        contentType: "text/plain",
        body: text,
        severity: "high" as const,
        title: "Upload accepts a .php filename",
        note: "The uploaded body is plain marker text, not executable code.",
      },
      {
        id: "php-jpg",
        filename: `${base}.php.jpg`,
        contentType: "image/jpeg",
        body: text,
        severity: "medium" as const,
        title: "Upload accepts a double extension (.php.jpg)",
        note: "A later handler that strips the last extension may execute the file as PHP.",
      },
      {
        id: "phtml",
        filename: `${base}.phtml`,
        contentType: "text/plain",
        body: text,
        severity: "medium" as const,
        title: "Upload accepts a .phtml filename",
        note: "Alternate PHP handlers can execute .phtml files.",
      },
      {
        id: "content-type",
        filename: `${base}.php`,
        contentType: "image/png",
        body: text,
        severity: "medium" as const,
        title: "Upload accepts .php with a spoofed image Content-Type",
        note: "Validation appears to trust the client-supplied MIME type.",
      },
      {
        id: "magic",
        filename: `${base}.php`,
        contentType: "image/gif",
        body: `GIF89a${text}`,
        severity: "medium" as const,
        title: "Upload accepts .php with a GIF magic byte",
        note: "A magic-byte check was bypassed with a PHP-capable filename.",
      },
    ];
    for (const attempt of attempts) {
      const request = withPart(
        ctx.request,
        header,
        parsed.boundary,
        parsed.parts,
        parsed.index,
        attempt,
      );
      const probe = await ctx.probe(request, `Upload ${attempt.id} probe`);
      const repeat = await ctx.probe(request, `Upload ${attempt.id} repeat`);
      if (!successful(probe) || !successful(repeat)) continue;
      return observation(
        attempt.title,
        `The upload endpoint accepted ${attempt.id === "php" ? "a .php filename" : "a bypass variant"} twice while the original upload also succeeded. ${attempt.note} Acceptance is not execution: the file location, web accessibility and server handler configuration still require review. No executable code, .htaccess or web.config was uploaded.`,
        [control, probe, repeat],
        [
          `Filename: ${attempt.filename}`,
          `Content-Type: ${attempt.contentType}`,
          "Accepted twice; body contained a plain marker only",
        ],
        attempt.severity,
      );
    }
    return result("No dangerous extension, Content-Type or magic-byte upload was accepted.");
  },
};

export const uploadChecks = [fileUpload];
