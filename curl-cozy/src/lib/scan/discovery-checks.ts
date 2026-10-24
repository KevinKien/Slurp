import type { ScanCheck, ScanCheckContext, Exchange } from "./types";
import type { HttpRequest } from "../traffic";
import { isFormRequest, withHeader } from "./parameters";
import { scanParameters } from "../scan-selection";
import { compareResponses } from "../response-diff";
import { ok, text, result, observation } from "./extended-checks";
export function parameterHints(body: string): string[] {
  const names = new Set<string>();
  const patterns = [
    /\bname\s*=\s*["']([A-Za-z][\w-]{0,63})["']/gi,
    /(?:searchParams|URLSearchParams|params)\s*\.\s*(?:get|has)\s*\(\s*["']([A-Za-z][\w-]{0,63})["']/g,
    /[?&]([A-Za-z][\w-]{0,63})=/g,
  ];
  for (const re of patterns)
    for (const m of body.slice(0, 256000).matchAll(re)) {
      names.add(m[1]!);
      if (names.size >= 32) return [...names];
    }
  return [...names];
}
const same = (a: Exchange, b: Exchange, ctx: ScanCheckContext) => {
  if (!ok(a) || !ok(b)) return false;
  const d = compareResponses(a.response!, b.response!, ctx.diffOptions);
  return !d.statusChanged && !d.bodyChanged;
};
function add(
  request: HttpRequest,
  channel: "query" | "body" | "header",
  name: string,
  value: string,
): HttpRequest {
  const r = structuredClone(request);
  if (channel === "header") return withHeader(r, name, value);
  if (channel === "query") {
    const hash = r.url.indexOf("#"),
      end = hash < 0 ? r.url.length : hash;
    r.url =
      r.url.slice(0, end) +
      (r.url.slice(0, end).includes("?") ? "&" : "?") +
      encodeURIComponent(name) +
      "=" +
      encodeURIComponent(value) +
      r.url.slice(end);
  } else if (isFormRequest(r))
    r.body += (r.body ? "&" : "") + encodeURIComponent(name) + "=" + encodeURIComponent(value);
  else {
    const root: unknown = JSON.parse(r.body);
    if (!root || typeof root !== "object" || Array.isArray(root))
      throw Error("JSON object required");
    Object.defineProperty(root, name, {
      value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
    r.body = JSON.stringify(root);
  }
  return r;
}
export const parameterHintsCheck: ScanCheck = {
  id: "parameter-hints",
  name: "Parameter names in captured HTML and scripts",
  active: false,
  perParameter: false,
  async run(ctx) {
    const x = ctx.baselines[0];
    if (!x?.response) return result("Captured response required.", true);
    const names = parameterHints(text(x));
    if (!names.length) return result("No supported literal parameter names observed.");
    return observation(
      "Parameter name candidates in captured content",
      "Literal form field names, searchParams.get/has calls and URL query names were extracted without executing code or fetching endpoints. Names may belong to other endpoints and require review.",
      [x],
      names,
      "info",
    );
  },
};
export const hiddenParameters: ScanCheck = {
  id: "hidden-parameters",
  name: "Hidden parameter and header discovery",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (
      !ctx.stable ||
      ctx.baselines.length < 2 ||
      !ctx.baselines.every((x) => ok(x) && x.response!.status >= 200 && x.response!.status < 300)
    )
      return result("Stable successful baselines required for discovery.", true);
    const existing = new Set(
      scanParameters(ctx.request)
        .filter((p) => p.kind !== "json")
        .map((p) => p.name),
    );
    let bodyObject: Record<string, unknown> | undefined;
    try {
      const v = JSON.parse(ctx.request.body);
      if (v && typeof v === "object" && !Array.isArray(v)) bodyObject = v;
    } catch {
      /* non-JSON */
    }
    const names = [
      ...new Set([
        ...parameterHints(text(ctx.baselines[0]!)),
        "q",
        "query",
        "search",
        "filter",
        "sort",
        "order",
        "limit",
        "offset",
        "page",
        "fields",
        "include",
        "format",
      ]),
    ]
      .filter(
        (name) =>
          !/^(?:password|token|secret|authorization|cookie|csrf|role|admin|__proto__|constructor|prototype)$/i.test(
            name,
          ),
      )
      .slice(0, 12);
    const slots: { channel: "query" | "body" | "header"; name: string }[] = [];
    for (const name of names) {
      if (!existing.has(name)) slots.push({ channel: "query", name });
      if (
        (isFormRequest(ctx.request) && !existing.has(name)) ||
        (bodyObject && !Object.hasOwn(bodyObject, name))
      )
        slots.push({ channel: "body", name });
    }
    for (const name of ["X-Debug", "X-Preview", "X-Format"])
      if (!Object.keys(ctx.request.headers).some((k) => k.toLowerCase() === name.toLowerCase()))
        slots.push({ channel: "header", name });
    const findings = [];
    let incomplete = false;
    for (const { channel, name } of slots.slice(0, 27)) {
      const marker = ctx.nonce();
      const controlName = channel === "header" ? `X-Slurp-${ctx.nonce()}` : `slurp_${ctx.nonce()}`;
      const control = await ctx.probe(
        add(ctx.request, channel, controlName, marker),
        "Discovery unknown-name control",
      );
      if (!same(control, ctx.baselines[0]!, ctx)) {
        if (!ok(control)) incomplete = true;
        continue;
      }
      const candidate = await ctx.probe(
        add(ctx.request, channel, name, marker),
        `Discovery ${channel}: ${name}`,
      );
      if (!ok(candidate)) {
        incomplete = true;
        continue;
      }
      if (
        same(candidate, control, ctx) ||
        candidate.response!.status >= 500 ||
        [401, 403, 429].includes(candidate.response!.status)
      )
        continue;
      const repeat = await ctx.probe(
        add(ctx.request, channel, name, marker),
        `Discovery ${name} repeat`,
      );
      const restore = await ctx.probe(ctx.request, "Discovery original restore");
      if (!ok(repeat) || !ok(restore)) {
        incomplete = true;
        continue;
      }
      if (!same(candidate, repeat, ctx) || !same(restore, ctx.baselines[0]!, ctx)) continue;
      findings.push(
        ...observation(
          `Potential hidden ${channel} input: ${name}`,
          "A named input repeatedly changed the response while a random input name with the same value preserved the baseline. The original request restored the response. This is input discovery, not proof of a vulnerability. Use the saved probe request to investigate the candidate; generic request echo and unstable controls are excluded.",
          [...ctx.baselines, control, candidate, repeat, restore],
          [`Channel: ${channel}`, `Name: ${name}`, `Probe value: ${marker}`],
          "info",
        ).findings,
      );
    }
    return {
      findings,
      message:
        "Bounded hidden-input discovery completed; untested names and dynamic inputs remain outside coverage.",
      inconclusive: incomplete && !findings.length,
    };
  },
};
