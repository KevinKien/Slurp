import type { ScanCheck, ScanCheckContext, Exchange } from "./types";
import { withHeader } from "./parameters";
import { compareResponses } from "../response-diff";
import { ok, text, h, result, observation } from "./extended-checks";
const success = (x: Exchange) => ok(x) && x.response!.status >= 200 && x.response!.status < 300;
function same(a: Exchange, b: Exchange, ctx: ScanCheckContext) {
  if (!success(a) || !success(b)) return false;
  const diff = compareResponses(a.response!, b.response!, ctx.diffOptions);
  return !diff.statusChanged && !diff.bodyChanged;
}
export const corsTrust: ScanCheck = {
  id: "cors-trust",
  name: "CORS null and hostname validation bypass",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (
      !ctx.stable ||
      ctx.baselines.length < 2 ||
      !ctx.baselines.every(success) ||
      !text(ctx.baselines[0]!).trim()
    )
      return result("Stable successful nonempty baselines required.", true);
    const url = new URL(ctx.request.url);
    const nonce = () =>
      ctx
        .nonce()
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "")
        .slice(0, 48);
    const reflected = (x: Exchange, origin: string) =>
      same(x, ctx.baselines[0]!, ctx) &&
      h(x, "access-control-allow-origin").trim() === origin &&
      h(x, "access-control-allow-credentials").trim() === "true";
    const controlOrigin = `https://${nonce()}.invalid`;
    const control = await ctx.probe(
      withHeader(ctx.request, "Origin", controlOrigin),
      "CORS unrelated origin control",
    );
    if (!success(control)) return result("CORS control request unavailable.", true);
    // Generic arbitrary-origin reflection is already covered by the existing CORS check.
    if (
      reflected(control, controlOrigin) ||
      h(control, "access-control-allow-origin").trim() === "*"
    )
      return result(
        "Generic untrusted-origin policy observed; use the CORS origin handling check.",
      );
    const families = [{ name: "null origin", origins: ["null", "null"] }];
    if (!url.hostname.includes(":") && !/^[0-9.]+$/.test(url.hostname)) {
      families.push(
        {
          name: "trusted hostname prefix",
          origins: [1, 2].map(() => `${url.protocol}//${url.hostname}.${nonce()}.invalid`),
        },
        {
          name: "trusted hostname suffix",
          origins: [1, 2].map(() => `${url.protocol}//${nonce()}${url.hostname}`),
        },
      );
    }
    const findings = [];
    let incomplete = false;
    for (const family of families) {
      const a = await ctx.probe(
        withHeader(ctx.request, "Origin", family.origins[0]!),
        `CORS ${family.name}`,
      );
      if (!success(a)) {
        incomplete = true;
        continue;
      }
      if (!reflected(a, family.origins[0]!)) continue;
      const b = await ctx.probe(
        withHeader(ctx.request, "Origin", family.origins[1]!),
        `CORS ${family.name} independent repeat`,
      );
      const restore = await ctx.probe(ctx.request, "CORS original origin restore");
      if (!success(b) || !success(restore)) {
        incomplete = true;
        continue;
      }
      if (!reflected(b, family.origins[1]!) || !same(restore, ctx.baselines[0]!, ctx)) continue;
      const output = observation(
        `Credentialed CORS accepts ${family.name}`,
        "The tested origin was allowed with credentials twice and preserved the baseline response, while an unrelated-origin control was not allowed. The original request restored the response. Browser cookie, preflight and sensitive-data access must be verified; null origins and hostname comparison errors are not independently proof of exploitation.",
        [...ctx.baselines, control, a, b, restore],
        family.origins.map((origin) => `Origin: ${origin}; ACAO matched; ACAC: true`),
        "medium",
      );
      output.findings[0]!.remediation =
        "Parse and compare complete origins against an exact trusted allowlist; reject null origins unless explicitly required. Avoid hostname substring checks.";
      findings.push(...output.findings);
    }
    return {
      findings,
      message: incomplete
        ? "Some CORS trust probes were unavailable; coverage is incomplete."
        : "CORS null, hostname-prefix and hostname-suffix controls completed.",
      inconclusive: incomplete && !findings.length,
    };
  },
};
