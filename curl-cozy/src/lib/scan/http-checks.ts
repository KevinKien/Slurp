import type { Exchange, ScanCheck, ScanCheckContext } from "./types";
import type { HttpRequest } from "../traffic";
import { compareResponses } from "../response-diff";
import { mutateParameter, withHeader } from "./parameters";
import { h, text, ok, result, observation, sqlBooleanDifferential } from "./extended-checks";
const success = (x: Exchange) => ok(x) && x.response!.status >= 200 && x.response!.status < 300;
function same(a: Exchange, b: Exchange, ctx: ScanCheckContext) {
  if (!ok(a) || !ok(b)) return false;
  const diff = compareResponses(a.response!, b.response!, ctx.diffOptions);
  return !diff.statusChanged && !diff.bodyChanged;
}
function value(ctx: ScanCheckContext): string {
  const parameter = ctx.parameter!;
  if (parameter.kind === "query")
    return new URL(ctx.request.url).searchParams.getAll(parameter.name)[parameter.occurrence] ?? "";
  let root: unknown = JSON.parse(ctx.request.body);
  for (const part of parameter.pointer
    .slice(1)
    .split("/")
    .map((x) => x.replace(/~1/g, "/").replace(/~0/g, "~"))) {
    if (!root || typeof root !== "object" || !Object.hasOwn(root, part))
      throw Error("Parameter no longer exists.");
    root = (root as Record<string, unknown>)[part];
  }
  return String(root ?? "");
}
export const sqlBoolean: ScanCheck = {
  id: "sql-boolean",
  name: "SQL injection — boolean differential",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.parameter || !ctx.stable || !ctx.baselines.every(success))
      return result("Stable successful baselines and selected parameter required.", true);
    const original = value(ctx);
    const baseline = ctx.baselines[0]!;
    for (const quote of ["", "'"]) {
      const first = 137,
        second = 149;
      const truth = `${original}${quote} AND ${first}=${first}${quote ? "-- " : ""}`;
      const falsehood = `${original}${quote} AND ${first}=${second}${quote ? "-- " : ""}`;
      const responses: Exchange[] = [];
      for (const [payload, label] of [
        [truth, "Boolean true"],
        [falsehood, "Boolean false"],
        [falsehood, "Boolean false repeat"],
        [truth, "Boolean true repeat"],
      ])
        responses.push(
          await ctx.probe(mutateParameter(ctx.request, ctx.parameter, payload!), label!),
        );
      const restore = await ctx.probe(ctx.request, "Boolean original control");
      if (![...responses, restore].every(success)) continue;
      const [a, b, c, d] = responses;
      if (
        same(a!, baseline, ctx) &&
        same(d!, baseline, ctx) &&
        same(restore, baseline, ctx) &&
        same(b!, c!, ctx) &&
        !same(a!, b!, ctx)
      )
        return observation(
          "Possible SQL injection: controlled boolean response differential",
          "Repeated true expressions match successful baselines and the original control; repeated false expressions consistently differ. Application validation can mimic this behavior; SQL execution is not proven.",
          [...ctx.baselines, ...responses, restore],
          ["True/false/false/true ordering; original control restored baseline"],
          "medium",
        );
    }
    return sqlBooleanDifferential(ctx);
  },
};
export const sqlTime: ScanCheck = {
  id: "sql-time",
  name: "SQL injection — bounded time differential (MySQL)",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.parameter || !ctx.stable || !ctx.baselines.every(success))
      return result("Stable successful baselines and selected parameter required.", true);
    const durations = ctx.baselines.map((x) => x.response!.duration);
    if (Math.max(...durations) - Math.min(...durations) > 250 || Math.max(...durations) > 1000)
      return result("Baseline timing is noisy or slow; timing check skipped.", true);
    const original = value(ctx);
    const rows: Exchange[] = [];
    for (const seconds of [0, 2, 2, 0])
      rows.push(
        await ctx.probe(
          mutateParameter(
            ctx.request,
            ctx.parameter,
            `${original}' AND (SELECT 1 FROM (SELECT SLEEP(${seconds}))slurp)=1-- `,
          ),
          `SQL timing ${seconds}s`,
        ),
      );
    const restore = await ctx.probe(ctx.request, "Timing original control");
    if (![...rows, restore].every(success))
      return result(
        "Timing requests failed, timed out or were blocked; timeouts are not findings.",
        true,
      );
    const [a, b, c, d] = rows;
    const fast = [a!, d!].map((x) => x.response!.duration);
    const slow = [b!, c!].map((x) => x.response!.duration);
    if (
      !rows.every((x) => same(x, ctx.baselines[0]!, ctx)) ||
      !same(restore, ctx.baselines[0]!, ctx)
    )
      return result("Response content/status changed during timing probes.", true);
    if (
      Math.max(...fast) - Math.min(...fast) > 250 ||
      Math.max(...slow) - Math.min(...slow) > 400 ||
      restore.response!.duration > Math.max(...durations) + 500
    )
      return result("Timing controls are unstable.", true);
    if (Math.min(...slow) - Math.max(...fast) < 1500)
      return result("No repeatable delay above the timing threshold.");
    return observation(
      "Possible SQL injection: repeated controlled delay",
      "Two SLEEP(2) probes were slower than interleaved SLEEP(0) controls, with stable response content and restored baseline. Queueing and application behavior can still mimic timing; this is not confirmed SQL execution.",
      [...ctx.baselines, ...rows, restore],
      [
        `Fast controls (ms): ${fast.join(", ")}`,
        `Delayed probes (ms): ${slow.join(", ")}`,
        `Original control (ms): ${restore.response!.duration}`,
      ],
      "medium",
    );
  },
};
export const headerInjection: ScanCheck = {
  id: "header-injection",
  name: "Response header injection — CRLF controls",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.parameter) return result("Select a query/JSON parameter.", true);
    const rows: Exchange[] = [];
    for (let i = 0; i < 2; i++) {
      const marker = ctx.nonce();
      const injected = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, `slurp\r\nX-Slurp-Probe: ${marker}`),
        "CRLF header probe",
      );
      const control = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, `slurp X-Slurp-Probe: ${marker}`),
        "CRLF plain-text control",
      );
      if (!ok(injected) || !ok(control))
        return result("Header injection evidence incomplete.", true);
      if (
        h(injected, "x-slurp-probe").trim() !== marker ||
        h(control, "x-slurp-probe").includes(marker)
      )
        return result("No independently controlled response header; body reflection is ignored.");
      rows.push(injected, control);
    }
    return observation(
      "Response header injection through input",
      "Two independent markers appeared in an actual response header only for CRLF probes, not plain-text controls. Review downstream header handling and impact.",
      rows,
      ["X-Slurp-Probe header controlled by two CRLF parameter values"],
      "medium",
    );
  },
};
const credential =
  /^(authorization|proxy-authorization|cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token|access-token|token|x-csrf-token|x-xsrf-token)$/i;
export function withoutCredentials(request: HttpRequest): {
  request: HttpRequest;
  removed: number;
} {
  const clean = structuredClone(request);
  let removed = 0;
  clean.headers = Object.fromEntries(
    Object.entries(clean.headers).filter(([name]) => {
      if (credential.test(name)) {
        removed++;
        return false;
      }
      return true;
    }),
  );
  const hash = clean.url.indexOf("#"),
    end = hash < 0 ? clean.url.length : hash,
    question = clean.url.indexOf("?");
  if (question >= 0 && question < end) {
    const segments = clean.url.slice(question + 1, end).split("&");
    const kept = segments.filter((segment) => {
      let key: string;
      try {
        key = decodeURIComponent(segment.split("=")[0]!.replace(/\+/g, " "));
      } catch {
        return true;
      }
      if (/^(access_token|auth_token|api_key|apikey|token|jwt|id_token|sessionid)$/i.test(key)) {
        removed++;
        return false;
      }
      return true;
    });
    if (kept.length !== segments.length)
      clean.url =
        clean.url.slice(0, question) +
        (kept.length ? "?" + kept.join("&") : "") +
        clean.url.slice(end);
  }
  return { request: clean, removed };
}
export const authAccess: ScanCheck = {
  id: "auth-access",
  name: "Anonymous and invalid-credential access",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.stable || !ctx.baselines.every(success))
      return result("Stable successful authenticated baselines required.", true);
    const clean = withoutCredentials(ctx.request);
    if (!clean.removed)
      return result(
        "No recognized header/query credentials to remove; body authentication is not mutated.",
        true,
      );
    const anonymous = await ctx.probe(clean.request, "Anonymous access");
    const invalid = await ctx.probe(
      withHeader(clean.request, "Authorization", "Bearer " + ctx.nonce()),
      "Invalid credential control",
    );
    const repeat = await ctx.probe(clean.request, "Anonymous repeat");
    const restore = await ctx.probe(ctx.request, "Authenticated original control");
    if (![anonymous, invalid, repeat, restore].every(ok))
      return result("Access-control evidence incomplete.", true);
    const baseline = ctx.baselines[0]!;
    if (
      !success(anonymous) ||
      !success(repeat) ||
      !same(anonymous, baseline, ctx) ||
      !same(repeat, baseline, ctx) ||
      !same(restore, baseline, ctx)
    )
      return result("Anonymous responses did not consistently match the successful baseline.");
    return observation(
      "Authenticated response also available without recognized credentials",
      "Repeated anonymous responses match the authenticated baseline. The endpoint may be public, and body/custom credentials may remain; intended access policy must be verified.",
      [...ctx.baselines, anonymous, invalid, repeat, restore],
      [
        `${clean.removed} recognized credential fields removed; values redacted`,
        `Anonymous status: ${anonymous.response!.status}; invalid-token status: ${invalid.response!.status}`,
      ],
      "medium",
    );
  },
};
async function deniedAccess(ctx: ScanCheckContext, kind: "referer" | "ip") {
  if (!ctx.stable || !ctx.baselines.every((x) => ok(x) && [401, 403].includes(x.response!.status)))
    return result("Stable 401/403 baselines required.", true);
  const clean = withoutCredentials(ctx.request).request;
  const names = kind === "referer" ? ["Referer"] : ["X-Real-IP", "X-Client-IP"];
  for (const name of names) {
    const allowed = kind === "referer" ? new URL("/", ctx.request.url).toString() : "127.0.0.1";
    const rejected = kind === "referer" ? `https://${ctx.nonce()}.invalid/` : "192.0.2.123";
    const a = await ctx.probe(withHeader(clean, name, allowed), `${name} candidate`);
    const b = await ctx.probe(withHeader(clean, name, rejected), `${name} negative control`);
    const c = await ctx.probe(withHeader(clean, name, allowed), `${name} repeat`);
    const restore = await ctx.probe(clean, "Denied original control");
    if (![a, b, c, restore].every(ok)) return result("Header access evidence incomplete.", true);
    if (
      success(a) &&
      success(c) &&
      same(a, c, ctx) &&
      [401, 403].includes(b.response!.status) &&
      [401, 403].includes(restore.response!.status) &&
      text(a).length > 0
    )
      return observation(
        `${kind === "referer" ? "Referer" : "Client IP header"}-dependent access response`,
        "A supplied header repeatedly changed a denied response to a successful nonempty response, while negative and original controls stayed denied. Confirm protected functionality and upstream trust configuration.",
        [...ctx.baselines, a, b, c, restore],
        [`Header tested: ${name}; candidate: ${allowed}; negative control: ${rejected}`],
        "medium",
      );
  }
  return result("No controlled denied-to-success response change for supported headers.");
}
export const refererAccess: ScanCheck = {
  id: "referer-access",
  name: "Referer-dependent access",
  active: true,
  perParameter: false,
  run: (ctx) => deniedAccess(ctx, "referer"),
};
export const clientIp: ScanCheck = {
  id: "client-ip",
  name: "Client IP header trust",
  active: true,
  perParameter: false,
  run: (ctx) => deniedAccess(ctx, "ip"),
};
export const urlOverride: ScanCheck = {
  id: "url-override",
  name: "URL override header routing",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.stable) return result("Stable baselines required.", true);
    const findings: ReturnType<typeof observation>["findings"] = [];
    for (const name of ["X-Original-URL", "X-Rewrite-URL"]) {
      const original = new URL(ctx.request.url);
      const current = original.pathname + original.search;
      const missing = "/slurp-missing-" + ctx.nonce();
      const a = await ctx.probe(withHeader(ctx.request, name, current), `${name} original path`);
      const b = await ctx.probe(withHeader(ctx.request, name, missing), `${name} missing path`);
      const c = await ctx.probe(withHeader(ctx.request, name, missing), `${name} missing repeat`);
      const restore = await ctx.probe(ctx.request, "Routing original control");
      if (![a, b, c, restore].every(ok)) return result("Routing-header evidence incomplete.", true);
      if (
        same(a, ctx.baselines[0]!, ctx) &&
        same(restore, ctx.baselines[0]!, ctx) &&
        b.response!.status === 404 &&
        same(b, c, ctx) &&
        !same(b, a, ctx)
      )
        findings.push(
          ...observation(
            "Request routing influenced by " + name,
            "A routing header carrying a nonexistent path repeatedly produced a distinct 404; the current-path and original controls match baseline. This is routing behavior, not proof of authorization bypass.",
            [...ctx.baselines, a, b, c, restore],
            [`${name}: <current path> versus unique missing path`],
            "info",
          ).findings,
        );
    }
    return { findings, message: "Supported routing-header controls completed." };
  },
};
export const httpMethods: ScanCheck = {
  id: "http-methods",
  name: "HTTP method policy — OPTIONS / TRACE",
  active: true,
  perParameter: false,
  async run(ctx) {
    const request = withoutCredentials(ctx.request).request;
    request.body = "";
    // Method diagnostics need no application headers, including unknown credentials.
    request.headers = {};
    const options = await ctx.probe({ ...request, method: "OPTIONS" }, "Method advertisement");
    const findings: ReturnType<typeof observation>["findings"] = [];
    if (ok(options) && /(?:^|[,\s])PUT(?:[,\s]|$)/i.test(h(options, "allow")))
      findings.push(
        ...observation(
          "PUT method advertised by endpoint",
          "The OPTIONS Allow header advertises PUT. No write was attempted; this does not establish unauthorized file creation.",
          [options],
          ["Allow: " + h(options, "allow")],
          "info",
        ).findings,
      );
    const rows: Exchange[] = [];
    for (let i = 0; i < 2; i++) {
      const marker = ctx.nonce();
      const trace = await ctx.probe(
        withHeader({ ...request, method: "TRACE" }, "X-Slurp-Probe", marker),
        "TRACE marker reflection",
      );
      if (!ok(trace))
        return { findings, message: "TRACE evidence incomplete.", inconclusive: true };
      if (
        !success(trace) ||
        !/^TRACE\s+\S+\s+HTTP\/[12](?:\.\d)?/i.test(text(trace).trimStart()) ||
        (!text(trace).includes(`X-Slurp-Probe: ${marker}`) &&
          !text(trace).includes(`x-slurp-probe: ${marker}`))
      )
        return {
          findings,
          message: "OPTIONS inspected; repeated TRACE header reflection not observed.",
          inconclusive: !ok(options),
        };
      rows.push(trace);
    }
    findings.push(
      ...observation(
        "TRACE reflects request headers",
        "Two TRACE requests reflected unique diagnostic headers. Recognized credentials were removed; browser restrictions and deployment context determine impact.",
        rows,
        ["Two unique X-Slurp-Probe headers reflected by TRACE"],
        "low",
      ).findings,
    );
    return {
      findings,
      message: "OPTIONS and TRACE inspection completed.",
      inconclusive: !ok(options),
    };
  },
};
export const httpChecks = [
  sqlBoolean,
  sqlTime,
  headerInjection,
  authAccess,
  refererAccess,
  clientIp,
  urlOverride,
  httpMethods,
];
