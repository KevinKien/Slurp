import { hostHeaderCheck } from "./host-header-check";
import { businessChecks } from "./business-checks";
import { parameterHintsCheck, hiddenParameters } from "./discovery-checks";
import { jwtKeyChecks } from "./jwt-key-checks";
import { jwtConfusion } from "./jwt-confusion-check";
import { corsTrust } from "./cors-trust-check";
import { nosqlOperators } from "./nosql-checks";
import { jwtWeakSecret } from "./jwt-secret-check";
import { dependencyAudit } from "./dependency-checks";
import { tokenGraphqlChecks } from "./token-graphql-checks";
import { protocolChecks } from "./protocol-checks";
import { injectionChecks } from "./injection-checks";
import { browserChecks } from "./browser-checks";
import { oastChecks } from "./oast-checks";
import { httpChecks } from "./http-checks";
import { passiveChecks } from "./passive-checks";
import { extendedChecks } from "./extended-checks";
import type { CheckOutput, Exchange, ScanCheck, ScanCheckContext } from "./types";
import { mutateParameter, withHeader } from "./parameters";
const header = (x: Exchange, name: string) =>
  Object.entries(x.response?.responseHeaders ?? {}).find(
    ([k]) => k.toLowerCase() === name.toLowerCase(),
  )?.[1] ?? "";
const good = (x: Exchange) =>
  !!x.response && !x.evidence.error && x.response.status < 300 && x.response.status >= 200;
const body = (x: Exchange) => x.response?.responseBody ?? "";
const empty = (message: string, inconclusive = false): CheckOutput => ({
  findings: [],
  message,
  inconclusive,
});
type Candidate = CheckOutput["findings"][number];
function candidate(
  p: Partial<Candidate> & Pick<Candidate, "title" | "summary" | "evidenceIds">,
): Candidate {
  return {
    severity: "info",
    confidence: "medium",
    status: "suspected",
    verification: {
      method: "response inspection",
      outcome: "not_performed",
      reason: "Manual confirmation required.",
    },
    excerpts: [],
    remediation: "Review the response and intended endpoint behavior.",
    ...p,
  };
}
function verifiedFact(
  title: string,
  summary: string,
  exchanges: Exchange[],
  excerpts: string[],
  remediation: string,
): Candidate {
  const complete = exchanges.every((e) => !e.evidence.truncated);
  return candidate({
    title: title.slice(0, 900),
    summary,
    evidenceIds: exchanges.map((e) => e.evidence.id),
    excerpts: excerpts.map((s) => s.slice(0, 4000)),
    remediation,
    confidence: complete ? "high" : "medium",
    status: complete ? "verified" : "needs_review",
    verification: {
      method: "direct configuration observation",
      outcome: complete ? "confirmed" : "inconclusive",
      reason: complete
        ? "The stated configuration is present in the captured response; exploitability is not asserted."
        : "Evidence was truncated. Review the full response.",
    },
  });
}
const disclosure =
  /Traceback \(most recent call last\):|Fatal error:[^\n]{0,300}?\bon line \d{1,10}|(?:java\.[\w.]{1,200}(?:Exception|Error))(?::|\s)|\bat [\w.$]{1,200}\([^\n]{0,300}\.java:\d{1,10}\)|SQLSTATE\[[A-Z0-9]{5}\]|You have an error in your SQL syntax|Microsoft OLE DB Provider for SQL Server/gi;
function signatures(x: Exchange) {
  const result: string[] = [];
  for (const match of body(x).matchAll(disclosure)) {
    result.push(match[0].slice(0, 250));
    if (result.length === 10) break;
  }
  return result;
}
function snippet(text: string, marker: string) {
  const i = text.indexOf(marker);
  return text.slice(Math.max(0, i - 100), i + marker.length + 100);
}
const cookieFlags: ScanCheck = {
  id: "cookie-flags",
  name: "Cookie flags",
  active: false,
  perParameter: false,
  async run(ctx) {
    const findings: Candidate[] = [];
    const first = ctx.baselines[0]!;
    if (!first.response) return empty("No baseline response.", true);
    // getSetCookie retains separate fields; never split on commas (Expires contains commas).
    const cookies = first.response.setCookies ?? [];
    if (!cookies.length && header(first, "set-cookie"))
      return empty("Separate Set-Cookie fields unavailable; cookie inspection skipped.", true);
    for (const line of cookies.slice(0, 100)) {
      const segments = line.split(";").map((s) => s.trim()),
        pair = segments[0]!,
        eq = pair.indexOf("=");
      if (eq <= 0) continue;
      if (
        segments
          .slice(1)
          .some((s) => /^max-age\s*=\s*-?\d+$/i.test(s) && Number(s.slice(s.indexOf("=") + 1)) <= 0)
      )
        continue;
      const name = pair.slice(0, eq),
        flags = new Set(segments.slice(1).map((s) => s.split("=")[0]!.toLowerCase()));
      for (const flag of ["secure", "httponly"])
        if (!flags.has(flag)) {
          const matches = ctx.baselines.filter((e) =>
            (e.response?.setCookies ?? []).some((c) => {
              const parts = c.split(";").map((s) => s.trim());
              return (
                parts[0]?.startsWith(name + "=") &&
                !parts.slice(1).some((v) => v.split("=")[0]!.toLowerCase() === flag)
              );
            }),
          );
          const f = verifiedFact(
            `Cookie ${name} has no ${flag === "secure" ? "Secure" : "HttpOnly"} flag`,
            `The ${flag} attribute is absent from this Set-Cookie field. Some cookies intentionally require JavaScript access; review the cookie's purpose.`,
            matches,
            [`Set-Cookie: ${name}=<redacted>; missing ${flag}`],
            `Set ${flag === "secure" ? "Secure on HTTPS cookies" : "HttpOnly on cookies that JavaScript does not need"}.`,
          );
          f.severity = "low";
          findings.push(f);
        }
    }
    return {
      findings,
      message: findings.length
        ? "Cookie configuration observations recorded."
        : "No missing Secure/HttpOnly attributes observed.",
    };
  },
};
const errors: ScanCheck = {
  id: "error-disclosure",
  name: "Error disclosure",
  active: false,
  perParameter: false,
  async run(ctx) {
    const first = ctx.baselines[0]!;
    const hits = signatures(first);
    if (!first.response) return empty("No baseline response.", true);
    if (!hits.length) return empty("No supported error signatures observed.");
    return {
      message: "Error signatures require contextual review.",
      findings: [
        candidate({
          title: "Possible internal error disclosure",
          severity: "low",
          summary:
            "The response contains a stack-trace or database-error signature. Quoted documentation and example content can produce false positives.",
          status: "suspected",
          evidenceIds: [first.evidence.id],
          excerpts: hits,
        }),
      ],
    };
  },
};
const headers: ScanCheck = {
  id: "security-headers",
  name: "Response headers",
  active: false,
  perParameter: false,
  async run(ctx) {
    const first = ctx.baselines[0]!;
    if (!good(first)) return empty("Header checks require a successful response.", true);
    if (header(first, "content-type").split(";")[0]!.trim().toLowerCase() !== "text/html")
      return empty("Browser document header checks do not apply to this content type.");
    const findings: Candidate[] = [];
    if (header(first, "x-content-type-options").toLowerCase() !== "nosniff")
      findings.push(
        verifiedFact(
          "HTML response lacks X-Content-Type-Options: nosniff",
          "A browser document response does not advertise nosniff. This is a configuration observation, not proof of script execution.",
          [first],
          [
            "Content-Type: " + header(first, "content-type"),
            "X-Content-Type-Options: " + (header(first, "x-content-type-options") || "<absent>"),
          ],
          "Return X-Content-Type-Options: nosniff with the correct Content-Type.",
        ),
      );
    return {
      findings,
      message: findings.length
        ? "Document header observations recorded."
        : "No supported header issues observed.",
    };
  },
};
const reflection: ScanCheck = {
  id: "reflection",
  name: "Input reflection",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.parameter) throw Error("Parameter required.");
    const marks = [ctx.nonce(), ctx.nonce()];
    const responses: Exchange[] = [];
    for (const mark of marks)
      responses.push(
        await ctx.probe(mutateParameter(ctx.request, ctx.parameter, mark), "Reflection marker"),
      );
    if (responses.some((e) => !e.response)) return empty("A reflection probe failed.", true);
    if (!responses.every((e, i) => body(e).includes(marks[i]!)))
      return empty("Two independent markers were not both reflected.");
    const cross =
      ctx.baselines.some((e) => marks.some((m) => body(e).includes(m))) ||
      responses.some((e, i) => body(e).includes(marks[1 - i]!));
    if (cross)
      return empty("Markers appeared in control responses; verification is inconclusive.", true);
    const finding = verifiedFact(
      "Input reflected in response",
      "Two distinct alphanumeric markers were returned by the endpoint. This confirms reflection only; it does not establish XSS or code execution.",
      [...ctx.baselines, ...responses],
      responses.map((e, i) => snippet(body(e), marks[i]!)),
      "Review the output context and apply context-appropriate encoding.",
    );
    finding.verification.method =
      "two independent reflection markers with baseline and cross-marker controls";
    return { findings: [finding], message: "Reflection reproduced; XSS remains untested." };
  },
};
const inputErrors: ScanCheck = {
  id: "input-errors",
  name: "Input error handling",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (!ctx.parameter) throw Error("Parameter required.");
    if (!ctx.stable || !ctx.baselines.every(good))
      return empty("A stable successful baseline is required.", true);
    const mutated = mutateParameter(ctx.request, ctx.parameter, "'\""),
      first = await ctx.probe(mutated, "Malformed input");
    if (!first.response) return empty("Input probe failed.", true);
    const baselineSignatures = new Set(ctx.baselines.flatMap(signatures));
    const newErrors = signatures(first).filter((s) => !baselineSignatures.has(s));
    if (first.response.status < 500 && !newErrors.length)
      return empty("No new server error or supported error signature.");
    const repeat = await ctx.probe(mutated, "Repeat malformed input"),
      control = await ctx.probe(ctx.request, "Original-value control");
    if (!repeat.response || !good(control))
      return empty("Repeat or control request failed; no finding confirmed.", true);
    const reproduced =
      (first.response.status >= 500 && repeat.response.status >= 500) ||
      newErrors.some((s) => signatures(repeat).includes(s));
    if (!reproduced) return empty("The input error did not reproduce.", true);
    return {
      message: "Reproducible error handling behavior requires review.",
      findings: [
        candidate({
          title: "Malformed input triggers a reproducible server error",
          severity: "low",
          confidence: "high",
          status: "needs_review",
          summary:
            "The changed input produced an error twice while the original-value control succeeded. This does not establish SQL injection or another injection vulnerability.",
          evidenceIds: [
            ...ctx.baselines.map((e) => e.evidence.id),
            first.evidence.id,
            repeat.evidence.id,
            control.evidence.id,
          ],
          excerpts: [
            `Baseline: ${ctx.baselines.map((e) => e.response?.status).join(", ")}; probes: ${first.response.status}, ${repeat.response.status}; control: ${control.response!.status}`,
            ...newErrors,
          ],
          verification: {
            method: "repeat mutation and original-value control",
            outcome: "inconclusive",
            reason:
              "The server-error behavior is reproducible; security impact and root cause require manual review.",
          },
          remediation:
            "Validate input and handle parser/database exceptions without exposing internal details.",
        }),
      ],
    };
  },
};
const cors: ScanCheck = {
  id: "cors",
  name: "CORS origin handling",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.baselines.every(good))
      return empty("CORS probes require successful baseline responses.", true);
    const origins = [
        `https://${ctx.nonce().toLowerCase()}.invalid`,
        `https://${ctx.nonce().toLowerCase()}.invalid`,
      ],
      responses: Exchange[] = [];
    for (const origin of origins)
      responses.push(
        await ctx.probe(withHeader(ctx.request, "Origin", origin), "Untrusted Origin"),
      );
    if (!responses.every(good))
      return empty("CORS probe did not return successful responses.", true);
    if (responses.every((e) => header(e, "access-control-allow-origin").trim() === "*")) {
      return {
        message: "Wildcard CORS observed; review whether data is public.",
        findings: [
          candidate({
            title: "Wildcard CORS policy accepts untrusted origins",
            severity: "low",
            status: "needs_review",
            summary:
              "Both untrusted-Origin probes returned Access-Control-Allow-Origin: *. Public resources may intentionally allow this. Browsers reject wildcard ACAO with credentialed access; data sensitivity and browser behavior require review.",
            evidenceIds: responses.map((e) => e.evidence.id),
            excerpts: ["Access-Control-Allow-Origin: *"],
          }),
        ],
      };
    }
    if (
      !responses.every(
        (e, i) =>
          header(e, "access-control-allow-origin") === origins[i] &&
          header(e, "access-control-allow-credentials") === "true",
      )
    )
      return empty("No credentialed reflection of both untrusted origins observed.");
    return {
      message: "CORS configuration needs browser verification.",
      findings: [
        candidate({
          title: "Untrusted origins accepted with credentialed CORS",
          severity: "medium",
          confidence: "medium",
          status: "needs_review",
          summary:
            "Two unrelated origins were echoed with Access-Control-Allow-Credentials: true. Browser cookie policy, preflight requirements and response sensitivity are not established.",
          evidenceIds: responses.map((e) => e.evidence.id),
          excerpts: responses.map(
            (e, i) =>
              `Origin: ${origins[i]}; Access-Control-Allow-Origin: ${header(e, "access-control-allow-origin")}; Access-Control-Allow-Credentials: ${header(e, "access-control-allow-credentials")}`,
          ),
          verification: {
            method: "two untrusted Origin probes",
            outcome: "inconclusive",
            reason:
              "A real browser must verify cross-origin access to sensitive data with the relevant credentials.",
          },
          remediation:
            "Use an explicit trusted-origin allowlist and enable credentialed CORS only where required.",
        }),
      ],
    };
  },
};
export const scanChecks: ReadonlyArray<ScanCheck> = [
  hostHeaderCheck,
  dependencyAudit,
  jwtWeakSecret,
  jwtConfusion,
  ...jwtKeyChecks,
  ...businessChecks,
  parameterHintsCheck,
  hiddenParameters,
  nosqlOperators,
  ...tokenGraphqlChecks,
  ...protocolChecks,
  ...oastChecks,
  ...browserChecks,
  ...extendedChecks.filter((check) => !check.active),
  ...passiveChecks,
  cookieFlags,
  errors,
  headers,
  reflection,
  inputErrors,
  cors,
  corsTrust,
  ...httpChecks,
  ...injectionChecks,
  ...extendedChecks.filter((check) => check.active),
];
export function getScanCheck(id: string) {
  const check = scanChecks.find((c) => c.id === id);
  if (!check) throw Error(`Unknown scan check: ${id}`);
  return check;
}
