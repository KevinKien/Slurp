import { result } from "./extended-checks";
import type { ScanCheck } from "./types";

const fixed = [3, 2, 11];
function versionOf(html: string): string | undefined {
  const match = html.match(/(?:mercury|mr\.?markdown)[^0-9]{0,40}(\d+\.\d+\.\d+)/i);
  return match?.[1];
}
function olderThanFixed(version: string): boolean {
  const parts = version.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    const value = parts[index] ?? 0;
    if (value !== fixed[index]) return value < fixed[index]!;
  }
  return false;
}

export function mercuryExposure(html: string): {
  mercury: boolean;
  markdownSink: boolean;
  version?: string;
  vulnerable: boolean;
} {
  const lower = html.toLowerCase();
  const mercury = lower.includes("mercury") || lower.includes("ipywidgets");
  const markdownSink =
    lower.includes("widget-html-content") ||
    lower.includes("mr.markdown") ||
    lower.includes("mr-markdown");
  const version = versionOf(html);
  return {
    mercury,
    markdownSink,
    ...(version ? { version } : {}),
    vulnerable: Boolean(version && olderThanFixed(version)),
  };
}

export const mercuryMarkdown: ScanCheck = {
  id: "mercury-markdown-xss",
  name: "Mercury mr.Markdown unsafe HTML sink",
  active: false,
  perParameter: false,
  async run(ctx) {
    const baseline = ctx.baselines[0];
    if (!baseline?.response || baseline.response.status >= 300)
      return result("A successful HTML baseline is required.", true);
    const html = baseline.response.responseBody;
    if (new TextEncoder().encode(html).length > 256000)
      return result("Mercury inspection requires an HTML response up to 256 KB.", true);
    const exposure = mercuryExposure(html);
    if (!exposure.mercury)
      return result("No Mercury or ipywidgets marker was found in the captured HTML.", true);
    if (!exposure.markdownSink)
      return result(
        "Mercury markers were found but no Markdown/HTML widget sink was visible in the captured HTML; the widget may render after JavaScript.",
        true,
      );
    const version = exposure.version;
    const title = version
      ? `Mercury ${version} uses an unsanitized mr.Markdown HTML sink (CVE-2026-111059)`
      : "Mercury mr.Markdown uses an unsanitized HTML sink (CVE-2026-111059)";
    return {
      findings: [
        {
          title,
          severity: "medium",
          confidence: version ? "high" : "medium",
          status: "needs_review",
          summary: version
            ? `The captured page identifies Mercury ${version} and an ipywidgets HTML/Markdown sink. Mercury before 3.2.11 converts mr.Markdown input with python-markdown without sanitization and the HTML widget renders it through innerHTML, so untrusted data rendered by the app can execute script in a viewer's browser. This is a sink/version observation, not proof that untrusted data reaches it; no payload was submitted.`
            : "The captured page identifies Mercury/ipywidgets and an HTML or Markdown widget sink. Mercury before 3.2.11 renders mr.Markdown output through innerHTML without sanitization, so untrusted data rendered by the app can execute script in a viewer's browser. The product version was not visible; confirm it and whether untrusted data reaches the widget. No payload was submitted.",
          evidenceIds: [baseline.evidence.id],
          excerpts: [
            "Mercury/ipywidgets marker present",
            "Markdown/HTML widget sink present",
            version ? `Version observed: ${version}` : "Version not visible in captured HTML",
          ],
          remediation:
            "Upgrade mercury to 3.2.11 or later and sanitize Markdown output by default with an allowlist (nh3/bleach), keeping raw HTML behind an explicit unsafe opt-in. Add a restrictive CSP as defense in depth.",
          verification: {
            method: "captured HTML fingerprint and sink inspection; no payload submitted",
            outcome: "inconclusive",
            reason:
              "The version/sink is observed, but a stored or DOM XSS requires attacker-controlled data reaching mr.Markdown and a viewer session.",
          },
        },
      ],
      message: `Mercury${version ? ` ${version}` : ""} and an HTML/Markdown widget sink were observed.`,
    };
  },
};

export const mercuryChecks = [mercuryMarkdown];
