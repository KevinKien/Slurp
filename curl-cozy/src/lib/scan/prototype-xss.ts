import type { Exchange, ScanCheck, ScanCheckContext } from "./types";
import { h, result, observation } from "./extended-checks";

const html = (x: Exchange) =>
  !!x.response &&
  x.response.status >= 200 &&
  x.response.status < 300 &&
  h(x, "content-type").split(";")[0]?.trim().toLowerCase() === "text/html" &&
  x.response.responseBody.length <= 256000;

export function prototypeXssUrls(original: string, marker: string): string[] {
  const payload = `<img src=x onerror="__slurpXss('${marker}')">`;
  const encoded = encodeURIComponent(payload);
  const [base = ""] = original.split("#");
  const join = base.includes("?") ? "&" : "?";
  return [
    `${base}${join}__proto__[innerHTML]=${encoded}`,
    `${base}${join}constructor[prototype][innerHTML]=${encoded}`,
  ];
}

export const prototypeXss: ScanCheck = {
  id: "prototype-xss",
  name: "Prototype pollution to DOM XSS (Vue innerHTML)",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.browser)
      return result("Browser validator is unavailable in this execution environment.", true);
    if (!ctx.stable || !ctx.baselines.every(html))
      return result("Successful HTML baselines are required.", true);
    const marker = ctx.nonce().replace(/[^a-zA-Z0-9]/g, "");
    const urls = prototypeXssUrls(ctx.request.url, marker);
    for (const url of urls) {
      const first = await ctx.browser(ctx.baselines[0]!, marker, url);
      if (!first.executed) continue;
      const secondMarker = ctx.nonce().replace(/[^a-zA-Z0-9]/g, "");
      const secondUrl = prototypeXssUrls(ctx.request.url, secondMarker)[0]!;
      const repeat = await ctx.browser(ctx.baselines[0]!, secondMarker, secondUrl);
      if (!repeat.executed) continue;
      const control = await ctx.browser(ctx.baselines[0]!, marker, ctx.baselines[0]!.evidence.request.url);
      if (control.executed) continue;
      return observation(
        "Prototype pollution to DOM XSS (Vue innerHTML)",
        "Two independent __proto__[innerHTML] payloads executed the browser callback while a clean original-value control did not. The query parser writes an enumerable innerHTML property onto Object.prototype, and Vue's element mount enumerates inherited props and assigns it to el.innerHTML. This is consistent with CVE-2026-113659 / GHSA-m2m5-rw3w-cwmj in ApostropheCMS < 4.33.0, but the parser stack and authenticated session must be confirmed. No server request was sent by this check.",
        [ctx.baselines[0]!],
        [urls[0]!, `Callback: __slurpXss('${marker}')`, "Control: original URL did not execute"],
        "high",
      );
    }
    return result(
      "No prototype-pollution-to-innerHTML execution was observed for the supported Vue payloads; CSP, non-Vue rendering or a non-vulnerable parser remain possible.",
    );
  },
};

export const prototypeXssChecks = [prototypeXss];
