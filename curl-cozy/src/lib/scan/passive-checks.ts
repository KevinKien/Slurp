import type { CheckOutput, Exchange, ScanCheck } from "./types";
type Candidate = CheckOutput["findings"][number];
const header = (x: Exchange, name: string) =>
  Object.entries(x.response?.responseHeaders ?? {}).find(
    ([key]) => key.toLowerCase() === name,
  )?.[1] ?? "";
function finding(
  x: Exchange,
  title: string,
  summary: string,
  excerpts: string[],
  severity: Candidate["severity"] = "info",
): Candidate {
  return {
    title: title.slice(0, 900),
    summary: summary.slice(0, 9000),
    severity,
    confidence: "medium",
    status: "needs_review",
    evidenceIds: [x.evidence.id],
    excerpts: excerpts.map((v) => v.slice(0, 1000)),
    verification: {
      method: "passive captured-data observation",
      outcome: "inconclusive",
      reason:
        "The pattern is present in captured data; intended use and security impact require review.",
    },
    remediation:
      "Review the captured evidence and apply the relevant data minimization or security policy.",
  };
}
function output(
  x: Exchange,
  findings: Candidate[],
  message: string,
  incomplete = false,
): CheckOutput {
  return {
    findings: findings.slice(0, 100),
    message,
    inconclusive: incomplete || x.evidence.truncated || findings.length > 100,
  };
}
export const cookieAudit: ScanCheck = {
  id: "cookie-audit",
  name: "Cookie scope, prefixes and duplicate fields",
  active: false,
  perParameter: false,
  async run(ctx) {
    const x = ctx.baselines[0]!;
    if (!x.response) return { findings: [], message: "No captured response.", inconclusive: true };
    const cookies = x.response.setCookies ?? [];
    if (!cookies.length && header(x, "set-cookie"))
      return {
        findings: [],
        message: "Separate Set-Cookie fields unavailable; collapsed fields are not split.",
        inconclusive: true,
      };
    const found: Candidate[] = [];
    const identities = new Set<string>();
    const host = new URL(ctx.request.url).hostname.toLowerCase();
    for (const line of cookies.slice(0, 100)) {
      const parts = line.split(";").map((s) => s.trim());
      const pair = parts.shift() ?? "";
      const equal = pair.indexOf("=");
      if (equal < 1) continue;
      const name = pair.slice(0, equal);
      const attrs = new Map(
        parts.map((p) => {
          const i = p.indexOf("=");
          return [p.slice(0, i < 0 ? p.length : i).toLowerCase(), i < 0 ? "" : p.slice(i + 1)];
        }),
      );
      if (attrs.has("max-age") && Number(attrs.get("max-age")) <= 0) continue;
      if (!attrs.has("max-age") && attrs.has("expires")) {
        const expiration = Date.parse(attrs.get("expires")!);
        if (Number.isFinite(expiration) && expiration <= Date.now()) continue;
      }
      const domain = (attrs.get("domain") ?? host).replace(/^\./, "").toLowerCase();
      const path = attrs.get("path") ?? "<default>";
      const identity = JSON.stringify([name, domain, path]);
      const excerpt = `Set-Cookie: ${name}=[REDACTED]`;
      const add = (title: string, summary: string, severity: Candidate["severity"] = "low") =>
        found.push(finding(x, `${title}: ${name}`, summary, [excerpt], severity));
      if (identities.has(identity))
        add(
          "Duplicate cookie identity",
          "Multiple Set-Cookie fields set the same name, domain and path. Browser ordering may matter.",
          "info",
        );
      identities.add(identity);
      if (domain !== host && host.endsWith("." + domain))
        add(
          "Cookie scoped to parent domain",
          `Cookie Domain=${domain} includes sibling subdomains; assess whether this scope is intended.`,
        );
      if (!attrs.has("samesite"))
        add(
          "Cookie has no explicit SameSite policy",
          "No SameSite attribute was observed. Browser defaults may be Lax; assess cross-site requirements rather than assuming CSRF.",
          "info",
        );
      if (attrs.get("samesite")?.toLowerCase() === "none" && !attrs.has("secure"))
        add(
          "SameSite=None cookie lacks Secure",
          "Modern browsers generally reject SameSite=None without Secure.",
        );
      if (name.startsWith("__Secure-") && !attrs.has("secure"))
        add("Invalid __Secure- cookie prefix", "__Secure- cookies require the Secure attribute.");
      if (
        name.startsWith("__Host-") &&
        (!attrs.has("secure") || attrs.has("domain") || attrs.get("path") !== "/")
      )
        add(
          "Invalid __Host- cookie prefix",
          "__Host- cookies require Secure, Path=/ and no Domain attribute.",
        );
      if (/^(password|passwd|pwd)$/i.test(name))
        add(
          "Password-like cookie name",
          "A password-like cookie name was observed. The value was not tested and may be unrelated.",
          "medium",
        );
    }
    return output(x, found, "Cookie scope and prefix inspection completed.", cookies.length > 100);
  },
};
export const disclosureAudit: ScanCheck = {
  id: "disclosure-audit",
  name: "Sensitive data, definitions and technology disclosure",
  active: false,
  perParameter: false,
  async run(ctx) {
    const x = ctx.baselines[0]!;
    if (!x.response) return { findings: [], message: "No captured response.", inconclusive: true };
    const original = x.response.responseBody;
    const source = original.slice(0, 256000);
    const found: Candidate[] = [];
    const add = (
      title: string,
      summary: string,
      excerpts: string[],
      severity: Candidate["severity"] = "info",
    ) => found.push(finding(x, title, summary, excerpts, severity));
    const signatures: [string, RegExp, string, Candidate["severity"]][] = [
      [
        "Database connection string in response",
        /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^\s"'<>]{1,500}/i,
        "A database URI-like string was observed; public examples can match.",
        "medium",
      ],
      [
        "Password-like field in response",
        /["'](?:password|passwd|pwd)["']\s*:\s*["'][^"'\r\n]{3,200}["']/i,
        "A password-like JSON field contains a literal value; verify whether it is sensitive.",
        "medium",
      ],
      [
        "Email address disclosed",
        /\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,150}\.[A-Z]{2,24}\b/i,
        "An email-like string is present; public contact information is often intentional.",
        "info",
      ],
      [
        "Private IPv4 address disclosed",
        /\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b/,
        "A private IPv4-like address appears in response text; assess context.",
        "info",
      ],
      [
        "Possible server source code disclosure",
        /<\?php\s|<%@\s*(?:Page|Import)\b/i,
        "A server source-code opening marker is present; escaped examples may match.",
        "low",
      ],
      [
        "Possible serialized Java object",
        /\brO0AB[A-Za-z0-9+/]{12,}/,
        "A Java serialization base64 prefix was observed; this does not establish unsafe deserialization.",
        "info",
      ],
      [
        "GraphQL schema or response observed",
        /"__schema"\s*:\s*\{|"__typename"\s*:\s*"|\btype\s+Query\s*\{/,
        "GraphQL-specific response/schema syntax is present. No introspection query was sent.",
        "info",
      ],
    ];
    for (const [title, pattern, summary, severity] of signatures)
      if (pattern.test(source))
        add(
          title,
          summary,
          ["Matching content detected; sensitive values redacted. Review local response evidence."],
          severity,
        );
    if (
      /\b(?:ssn|social security)\b[\s\S]{0,60}\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/i.test(
        source,
      )
    )
      add(
        "Possible social security number disclosed",
        "A structured SSN-like value appears near an SSN label; examples may match.",
        ["Contextual SSN pattern detected; value redacted."],
        "low",
      );
    for (const match of source.matchAll(/\b(?:\d[ -]?){12,18}\d\b/g)) {
      const digits = match[0].replace(/\D/g, "");
      if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) continue;
      let sum = 0;
      let double = false;
      for (const char of digits.split("").reverse()) {
        let digit = Number(char);
        if (double) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
        double = !double;
      }
      if (sum % 10 === 0) {
        add(
          "Possible payment card number disclosed",
          "A 13–19 digit value passes the Luhn checksum. Identifiers and test cards may match.",
          ["Luhn-valid numeric candidate detected; value redacted."],
          "low",
        );
        break;
      }
    }
    try {
      const root: unknown = JSON.parse(source);
      const queue: unknown[] = [root];
      let visited = 0;
      while (queue.length && visited++ < 2000) {
        const node = queue.pop();
        if (!node || typeof node !== "object") continue;
        const record = node as Record<string, unknown>;
        if (
          ["RSA", "EC", "OKP"].includes(String(record["kty"])) &&
          typeof record["d"] === "string" &&
          record["d"].length > 8
        ) {
          add(
            "Private JWK material disclosed",
            "A JWK object includes an asymmetric private-key parameter. Review whether it is real key material.",
            ["JWK private parameter d detected; key values redacted."],
            "medium",
          );
          break;
        }
        for (const value of Object.values(record).slice(0, 2000))
          if (value && typeof value === "object") queue.push(value);
      }
    } catch {
      /* Non-JSON and bounded partial JSON are not JWK inputs. */
    }
    for (const name of ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"])
      if (header(x, name))
        add(
          `Technology header disclosed: ${name}`,
          "A technology-identifying header is present; this is not evidence of a vulnerable version.",
          [`${name}: ${header(x, name).slice(0, 200)}`],
        );
    const requestQuery = new URL(ctx.request.url).searchParams;
    const passwordFields = new Map<string, string>();
    for (const [key, value] of requestQuery)
      if (/^(password|passwd|pwd)$/i.test(key) && value.length >= 6) passwordFields.set(key, value);
    try {
      const data = JSON.parse(ctx.request.body);
      if (data && typeof data === "object" && !Array.isArray(data))
        for (const [key, value] of Object.entries(data))
          if (
            /^(password|passwd|pwd)$/i.test(key) &&
            typeof value === "string" &&
            value.length >= 6
          )
            passwordFields.set(key, value);
    } catch {
      if (
        Object.entries(ctx.request.headers).some(
          ([k, v]) =>
            k.toLowerCase() === "content-type" && v.includes("application/x-www-form-urlencoded"),
        )
      )
        for (const [key, value] of new URLSearchParams(ctx.request.body))
          if (/^(password|passwd|pwd)$/i.test(key) && value.length >= 6)
            passwordFields.set(key, value);
    }
    for (const [key, value] of passwordFields)
      if (source.includes(value))
        add(
          "Submitted password-like value returned in response",
          "A nontrivial submitted password-field value appears literally in the response. Review whether this exposes a real credential.",
          [`${key}=[REDACTED]; matching response value redacted`],
          "medium",
        );
    return output(
      x,
      found,
      "Bounded sensitive-data and technology inspection completed.",
      original.length > source.length,
    );
  },
};
export const policyAudit: ScanCheck = {
  id: "policy-audit",
  name: "CSP directives, MIME and transport policy",
  active: false,
  perParameter: false,
  async run(ctx) {
    const x = ctx.baselines[0]!;
    if (!x.response) return { findings: [], message: "No captured response.", inconclusive: true };
    const found: Candidate[] = [];
    const add = (title: string, summary: string, excerpts: string[]) =>
      found.push(finding(x, title, summary, excerpts, "low"));
    const type = header(x, "content-type").toLowerCase();
    const html = type.split(";")[0]?.trim() === "text/html";
    const source = x.response.responseBody.slice(0, 256000);
    const csp = header(x, "content-security-policy");
    const directives = new Map<string, string[]>();
    for (const directive of csp.split(";")) {
      const [name, ...values] = directive.trim().split(/\s+/);
      const key = name?.toLowerCase() ?? "";
      if (key && !directives.has(key))
        directives.set(
          key,
          values.map((v) => v.toLowerCase()),
        );
    }
    const combinedPolicies = csp.includes(",");
    if (html && csp && !combinedPolicies) {
      const script = directives.get("script-src") ?? directives.get("default-src") ?? [];
      for (const token of ["'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:", "data:"])
        if (script.includes(token))
          add(
            `CSP script policy contains ${token}`,
            "The effective script directive advertises a broad or potentially unsafe source. Nonces, hashes, strict-dynamic and browser semantics can change enforcement; review the complete policy.",
            [`Script source token: ${token}`],
          );
      if (!directives.has("object-src") && !directives.has("default-src"))
        add(
          "CSP lacks object source restriction",
          "Neither object-src nor its default-src fallback is present.",
          ["object-src: <absent>; default-src: <absent>"],
        );
      if (!directives.has("base-uri"))
        add(
          "CSP lacks base-uri restriction",
          "The policy does not restrict base element URLs; exploitability depends on HTML injection.",
          ["base-uri: <absent>"],
        );
    }
    if (
      html &&
      !/charset\s*=/i.test(type) &&
      !/<meta\b[^>]*(?:charset\s*=|http-equiv\s*=\s*["']?content-type)/i.test(source)
    )
      add(
        "HTML has no observed charset declaration",
        "Neither the Content-Type nor the inspected HTML declares a charset; browser defaults may apply.",
        ["No header/meta charset found in inspected source"],
      );
    if (html && /<\?xml\b|^\s*%PDF-/i.test(source))
      add(
        "Possible response MIME mismatch",
        "The declared HTML type disagrees with a recognizable content prefix; verify the actual representation.",
        ["Content-Type: text/html; conflicting prefix observed"],
      );
    if (new URL(ctx.request.url).protocol === "https:") {
      const hsts = header(x, "strict-transport-security");
      if (hsts) {
        const age = /(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i.exec(hsts);
        if (!age || Number(age[1]) === 0)
          add(
            "HSTS policy missing or disabling max-age",
            "An HSTS header exists but has no recognized positive max-age.",
            ["HSTS max-age: invalid or zero"],
          );
      }
    }
    return output(
      x,
      found,
      combinedPolicies
        ? "Combined CSP policies require manual review; other supported policy observations were inspected."
        : "CSP, MIME and transport policy inspection completed.",
      x.response.responseBody.length > source.length || combinedPolicies,
    );
  },
};
export const passiveChecks = [cookieAudit, disclosureAudit, policyAudit];
