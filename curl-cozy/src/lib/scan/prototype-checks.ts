import type { Exchange, ScanCheck, ScanCheckContext } from "./types";
import { h, result, observation } from "./extended-checks";

const html = (x: Exchange) =>
  !!x.response &&
  x.response.status >= 200 &&
  x.response.status < 300 &&
  h(x, "content-type").split(";")[0]?.trim().toLowerCase() === "text/html" &&
  x.response.responseBody.length <= 256000;

function withQuery(url: string, key: string, value: string) {
  const next = new URL(url);
  next.searchParams.set(key, value);
  return next.toString();
}

export const prototypePollution: ScanCheck = {
  id: "prototype-pollution",
  name: "Client-side prototype pollution",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.browser)
      return result("Browser validator is unavailable in this execution environment.", true);
    if (!ctx.stable || !ctx.baselines.every(html))
      return result("Successful HTML baselines are required.", true);
    const property = `slurp_${ctx.nonce().replace(/[^a-zA-Z0-9]/g, "")}`;
    const marker = `${ctx.nonce().replace(/[^a-zA-Z0-9]/g, "")}xxxxxxxxxxxxxxxx`.slice(0, 32);
    const urls = [
      withQuery(ctx.request.url, `__proto__[${property}]`, "1"),
      withQuery(ctx.request.url, `constructor[prototype][${property}]`, "1"),
      withQuery(ctx.request.url, `__pro__proto__to__[${property}]`, "1"),
      `${ctx.request.url.split("#")[0]}#__proto__[${property}]=1`,
    ];
    for (const url of urls) {
      const first = await ctx.browser(ctx.baselines[0]!, marker, url, undefined, undefined, property);
      if (!first.prototypePolluted) continue;
      const repeat = await ctx.browser(ctx.baselines[0]!, marker, url, undefined, undefined, property);
      if (!repeat.prototypePolluted) continue;
      return observation(
        "Client-side prototype pollution",
        "The browser confirmed that a fresh object exposes the injected property after loading the page with a prototype-pollution payload, twice. This is a client-side primitive, not proof of XSS or server-side pollution; a gadget that writes the property into a sink such as innerHTML, srcdoc, href or src still needs review.",
        [ctx.baselines[0]!],
        [`Property: ${property}=1`, `URL: ${url}`],
        "medium",
      );
    }
    return result("No client-side prototype pollution was confirmed for the supported query and hash payloads.");
  },
};

export const prototypeChecks = [prototypePollution];
