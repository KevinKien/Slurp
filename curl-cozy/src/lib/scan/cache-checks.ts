import type { Exchange, ScanCheck, ScanCheckContext } from "./types";
import type { HttpRequest } from "../traffic";
import { withHeader } from "./parameters";
import { compareResponses } from "../response-diff";
import { ok, text, result, observation } from "./extended-checks";

function header(x: Exchange, name: string) {
  return (
    Object.entries(x.response?.responseHeaders ?? {}).find(
      ([key]) => key.toLowerCase() === name.toLowerCase(),
    )?.[1] ?? ""
  );
}

function cacheSignal(x: Exchange): string | undefined {
  for (const name of ["x-cache", "cf-cache-status", "x-cache-status", "cdn-cache", "age"]) {
    const value = header(x, name);
    if (value) return `${name}: ${value}`;
  }
  const control = header(x, "cache-control").toLowerCase();
  if (/public|s-maxage|max-age/.test(control)) return `cache-control: ${control}`;
  return undefined;
}

function withCacheBuster(request: HttpRequest, nonce: string): HttpRequest {
  const url = new URL(request.url);
  url.searchParams.set("slurp_cb", nonce);
  return { ...request, url: url.href };
}

export const cachePoisoning: ScanCheck = {
  id: "cache-poisoning",
  name: "Web cache poisoning — unkeyed header reflection",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.stable || ctx.request.method !== "GET")
      return result("Stable baselines and a captured GET request are required.", true);
    const baseline = ctx.baselines[0]!;
    if (!ok(baseline)) return result("A successful baseline is required.", true);
    const headers = [
      ["x-forwarded-host", (nonce: string) => `slurp-${nonce}.invalid`],
      ["x-host", (nonce: string) => `slurp-${nonce}.invalid`],
      ["x-forwarded-server", (nonce: string) => `slurp-${nonce}.invalid`],
      ["x-original-url", (nonce: string) => `/slurp-${nonce}`],
      ["x-rewrite-url", (nonce: string) => `/slurp-${nonce}`],
      ["x-forwarded-prefix", (nonce: string) => `/slurp-${nonce}`],
      ["user-agent", (nonce: string) => `slurp-${nonce}`],
    ] as const;
    for (const [name, make] of headers) {
      const nonce = ctx.nonce().replace(/[^a-zA-Z0-9]/g, "");
      const value = make(nonce);
      const request = withHeader(withCacheBuster(ctx.request, nonce), name, value);
      const probe = await ctx.probe(request, `Cache poisoning ${name} probe`);
      const repeat = await ctx.probe(request, `Cache poisoning ${name} repeat`);
      if (!ok(probe) || !ok(repeat)) return result("Cache poisoning probes incomplete.", true);
      const reflected = (x: Exchange) =>
        text(x).includes(value) ||
        Object.values(x.response?.responseHeaders ?? {}).some((headerValue) =>
          headerValue.includes(value),
        );
      const signal = cacheSignal(probe);
      if (
        reflected(probe) &&
        reflected(repeat) &&
        signal &&
        !reflected(baseline) &&
        JSON.stringify(probe.response?.responseHeaders ?? {}) ===
          JSON.stringify(repeat.response?.responseHeaders ?? {})
      ) {
        return observation(
          `Unkeyed ${name} reflected in a cacheable response`,
          `The ${name} header value appeared twice in a response that also carried a cache indicator (${signal}). An unkeyed input that is reflected into a cacheable response can enable cache poisoning, but this check did not send a clean follow-up request, confirm a shared cache or poison other users. Confirm with an isolated cache key on staging.`,
          [baseline, probe, repeat],
          [
            `Header: ${name}: ${value}`,
            `Cache indicator: ${signal}`,
            "No cache-poisoning confirmation request was sent",
          ],
          "medium",
        );
      }
    }
    return result("No reflected unkeyed header was found in a cacheable response.");
  },
};

function sameBody(a: Exchange, b: Exchange, ctx: ScanCheckContext) {
  if (!ok(a) || !ok(b)) return false;
  const diff = compareResponses(a.response!, b.response!, ctx.diffOptions);
  return !diff.statusChanged && !diff.bodyChanged;
}

export const cacheDeception: ScanCheck = {
  id: "cache-deception",
  name: "Web cache deception — static path returns dynamic data",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.stable || ctx.request.method !== "GET")
      return result("Stable baselines and a captured GET request are required.", true);
    const baseline = ctx.baselines[0]!;
    if (!ok(baseline) || baseline.response!.status < 200 || baseline.response!.status >= 300)
      return result("A successful baseline is required.", true);
    if (text(baseline).length < 100)
      return result("A baseline body of at least 100 characters is required.", true);
    const base = new URL(ctx.request.url);
    const suffixes = [";.css", "%2f.css", "/.css"];
    for (const suffix of suffixes) {
      const nonce = ctx.nonce().replace(/[^a-zA-Z0-9]/g, "");
      const query = new URLSearchParams(base.search);
      query.set("slurp_cb", nonce);
      const url = `${base.origin}${base.pathname}${suffix}?${query.toString()}`;
      const request = { ...ctx.request, url };
      const probe = await ctx.probe(request, "Cache deception probe");
      const repeat = await ctx.probe(request, "Cache deception repeat");
      if (!ok(probe) || !ok(repeat)) continue;
      const signal = cacheSignal(probe);
      if (sameBody(probe, baseline, ctx) && sameBody(repeat, baseline, ctx) && signal) {
        return observation(
          "Static-looking path returns the dynamic response and looks cacheable",
          `Appending ${suffix} returned the same body as the captured authenticated request twice, and the response carried a cache indicator (${signal}). If a shared cache treats that path as static, it may store and serve this data to other users. This check used a unique cache buster and did not force caching, confirm a shared cache or retrieve another user's data.`,
          [baseline, probe, repeat],
          [
            `Path suffix: ${suffix}`,
            `Cache indicator: ${signal}`,
            "No cache poisoning or cross-user retrieval was attempted",
          ],
          "medium",
        );
      }
    }
    return result("No static-looking path returned the baseline body with a cache indicator.");
  },
};

export const cacheChecks = [cachePoisoning, cacheDeception];
