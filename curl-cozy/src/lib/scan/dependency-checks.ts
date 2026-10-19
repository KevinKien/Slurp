import { tokenizer } from "acorn";
import type { ScanCheck } from "./types";
import { h, result, observation, text } from "./extended-checks";
export interface Dependency {
  package: string;
  version: string;
  banner: string;
}
export interface DependencyResult {
  ok: true;
  package: string;
  version: string;
  advisories: { id: string; summary: string; aliases: string[] }[];
}
// Exact stable releases in explicit library banners only. A generic VERSION or URL is not attribution.
const signatures: readonly [string, RegExp][] = [
  ["jquery", /\bjQuery(?: JavaScript Library)?\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/gi],
  ["lodash", /\b(?:lodash|Lo-Dash)\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/gi],
  ["angular", /\bAngularJS\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/gi],
  ["bootstrap", /\bBootstrap\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/gi],
  ["moment", /\bmoment(?:\.js)?\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/gi],
  ["vue", /\bVue(?:\.js)?\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/gi],
  ["react", /\bReact\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/g],
  ["react-dom", /\bReactDOM\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/g],
  ["handlebars", /\bHandlebars(?:\.js)?\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/gi],
  ["underscore", /\bUnderscore(?:\.js)?\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/gi],
  ["axios", /\bAxios\s+v?(\d+\.\d+\.\d+)(?![\w.+-])/gi],
  ["dompurify", /\bDOMPurify\s+(?:\([^\n)]{0,30}\)\s*)?v?(\d+\.\d+\.\d+)(?![\w.+-])/gi],
];
export function identifyDependencies(source: string): Dependency[] {
  const found = new Map<string, Dependency>();
  // Only comments explicitly naming the library are version evidence; strings/examples are ignored.
  const comments: string[] = [];
  try {
    const tokens = tokenizer(source.slice(0, 256000), {
      ecmaVersion: "latest",
      sourceType: "module",
      allowHashBang: true,
      onComment: (_block, value) => {
        comments.push(value);
      },
    });
    while (tokens.getToken().type.label !== "eof") {
      /* Tokenize without parsing/evaluating the asset. */
    }
  } catch {
    /* Retain explicit comments preceding unsupported/truncated syntax. */
  }
  for (const comment of comments)
    for (const [name, pattern] of signatures) {
      pattern.lastIndex = 0;
      for (const match of comment.matchAll(pattern)) {
        const version = match[1]!;
        found.set(`${name}@${version}`, { package: name, version, banner: match[0].slice(0, 300) });
        if (found.size >= 10) return [...found.values()];
      }
    }
  return [...found.values()];
}
export const dependencyAudit: ScanCheck = {
  id: "dependency-audit",
  name: "Vulnerable JavaScript dependencies (OSV)",
  active: false,
  perParameter: false,
  async run(ctx) {
    const baseline = ctx.baselines[0];
    if (!baseline?.response || baseline.evidence.error)
      return result("Complete captured JavaScript response required.", true);
    const mime = h(baseline, "content-type").toLowerCase();
    if (
      mime.includes("html") ||
      (!/(?:java|ecma)script/.test(mime) && !/\.m?js$/i.test(new URL(ctx.request.url).pathname))
    )
      return result("This response is not identified as JavaScript.");
    const dependencies = identifyDependencies(text(baseline));
    if (!dependencies.length)
      return result(
        "No supported exact-version library banner found; this does not establish safe dependencies.",
        true,
      );
    if (!ctx.dependencies) return result("OSV advisory lookup is unavailable.", true);
    const findings = [];
    let failures = 0;
    for (const dependency of dependencies) {
      const lookup = await ctx.dependencies(dependency.package, dependency.version);
      if (!lookup.ok) {
        failures++;
        continue;
      }
      if (lookup.package !== dependency.package || lookup.version !== dependency.version)
        throw Error("Dependency advisory correlation mismatch");
      for (const advisory of lookup.advisories.slice(0, 50)) {
        findings.push(
          ...observation(
            `Vulnerable JavaScript dependency: ${dependency.package}@${dependency.version} (${advisory.id})`,
            `A captured library banner identifies this npm release and OSV reports an advisory for that exact version. ${advisory.summary} Banner attribution, bundled patches, actual execution and vulnerable feature usage require review; exploitability is not established.`,
            [baseline],
            [
              dependency.banner,
              `OSV: https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}`,
              ...advisory.aliases.slice(0, 10),
            ],
            "medium",
          ).findings,
        );
        const finding = findings.at(-1)!;
        finding.verification = {
          method: "explicit library/version banner and exact npm version OSV query",
          outcome: "confirmed",
          reason:
            "Confirms an advisory match for the banner-declared release, not runtime execution or exploitability.",
        };
        finding.remediation =
          "Verify the bundled package and patch status, then upgrade to an unaffected release listed in the linked advisory. Rebuild and verify the deployed asset.";
      }
    }
    return {
      findings,
      message: `Identified ${dependencies.length} exact-version dependencies; ${failures} lookup failures. No match is not proof of security.`,
      inconclusive: failures > 0 || baseline.evidence.truncated || text(baseline).length > 256000,
    };
  },
};
