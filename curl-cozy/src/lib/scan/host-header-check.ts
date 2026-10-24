import { parse, type DefaultTreeAdapterMap } from "parse5";
import type { Exchange, ScanCheck } from "./types";
import { observation, ok, result, text } from "./extended-checks";
import { withHeader } from "./parameters";
/** Only absolute navigation/resource URLs count; plain host/body echoes are excluded. */
export function hostSinks(exchange: Exchange, host: string): string[] {
  if (!ok(exchange)) return [];
  const found: string[] = [];
  const add = (raw: string, source: string) => {
    try {
      const url = new URL(raw.startsWith("//") ? `https:${raw}` : raw);
      if (
        ["http:", "https:"].includes(url.protocol) &&
        url.hostname === host &&
        !url.username &&
        !url.password
      )
        found.push(`${source}:${url.pathname}${url.search}`);
    } catch {
      /* Relative URLs and text are not host-control evidence. */
    }
  };
  const header = (name: string) =>
    Object.entries(exchange.response!.responseHeaders).find(
      ([k]) => k.toLowerCase() === name,
    )?.[1] ?? "";
  add(header("location"), "Location");
  if (/html/i.test(header("content-type"))) {
    let visited = 0;
    const walk = (node: DefaultTreeAdapterMap["node"], depth: number) => {
      if (++visited > 10000 || depth > 100 || found.length >= 30) return;
      if ("tagName" in node) {
        const attr =
          node.tagName === "form"
            ? "action"
            : ["a", "base", "link"].includes(node.tagName)
              ? "href"
              : ["script", "iframe"].includes(node.tagName)
                ? "src"
                : undefined;
        const value = attr && node.attrs.find((a) => a.name === attr)?.value;
        if (value) add(value, `${node.tagName}.${attr}`);
      }
      if ("childNodes" in node) for (const child of node.childNodes) walk(child, depth + 1);
    };
    walk(parse(text(exchange).slice(0, 256000)), 0);
  }
  return [...new Set(found)].sort();
}
export const hostHeaderCheck: ScanCheck = {
  id: "host-header",
  name: "Host header injection",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.probeHost) return result("Host-header scan sender unavailable.", true);
    if (!ctx.stable)
      return result("Stable original responses required for host-header comparison.", true);
    const request = withHeader(
      withHeader(ctx.request, "Cache-Control", "no-store"),
      "Pragma",
      "no-cache",
    );
    const original = await ctx.probe(request, "Host header original control");
    if (!ok(original)) return result("Host-header baseline unavailable.", true);
    const findings = [];
    let incomplete = false;
    for (const header of ["host", "x-forwarded-host"] as const) {
      const rows = [original];
      let shape: string[] | undefined;
      let matched = true;
      for (let i = 0; i < 2; i++) {
        const host = `slurp-${ctx
          .nonce()
          .replace(/[^a-z0-9]/gi, "")
          .toLowerCase()
          .slice(0, 40)}.invalid`;
        const probe = await ctx.probeHost(
          request,
          header,
          host,
          `Host injection: ${header} = ${host}`,
        );
        const control = await ctx.probe(
          withHeader(request, "X-Slurp-Host-Control", host),
          "Host header unused-marker control",
        );
        rows.push(probe, control);
        if (!ok(probe) || !ok(control)) {
          incomplete = true;
          matched = false;
          break;
        }
        const sinks = hostSinks(probe, host);
        if (
          !sinks.length ||
          hostSinks(control, host).length ||
          (shape && JSON.stringify(shape) !== JSON.stringify(sinks))
        ) {
          matched = false;
          break;
        }
        shape = sinks;
      }
      if (!matched) continue;
      const restore = await ctx.probe(request, "Host header restored original control");
      rows.push(restore);
      const location = (x: Exchange) =>
        Object.entries(x.response?.responseHeaders ?? {}).find(
          ([k]) => k.toLowerCase() === "location",
        )?.[1] ?? "";
      if (
        !ok(restore) ||
        restore.response!.status !== original.response!.status ||
        text(restore) !== text(original) ||
        location(restore) !== location(original)
      ) {
        incomplete = true;
        continue;
      }
      const out = observation(
        `Host header injection via ${header}`,
        "Two independent untrusted host values controlled absolute response URLs in the same navigation/resource contexts. Unused-marker controls did not reproduce it and the original response was restored. The network destination and TLS hostname remained those of the original URL. This is host-dependent URL generation requiring review; password-reset poisoning, cache poisoning and SSRF are not established.",
        rows,
        shape ?? [],
        "medium",
      );
      out.findings[0]!.remediation =
        "Validate Host against a server-side allowlist, trust forwarding headers only from configured proxies, and generate security-sensitive absolute URLs from a configured canonical origin.";
      findings.push(...out.findings);
    }
    return {
      findings,
      message: incomplete
        ? "Some host-header controls were incomplete."
        : "Host and X-Forwarded-Host URL-generation controls completed.",
      inconclusive: incomplete && !findings.length,
    };
  },
};
