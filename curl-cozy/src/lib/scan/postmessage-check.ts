import type { CheckOutput, Exchange, ScanCheck } from "./types";
import { h, text, result, observation } from "./extended-checks";

const listener = /addEventListener\s*\(\s*['"]message['"]|onmessage\s*=/gi;
const sink = /eval\s*\(|innerHTML|insertAdjacentHTML|outerHTML|srcdoc|location\s*=|document\.write/;
const wildcard = /postMessage\s*\([^)]*,\s*["']\*["']\s*\)/g;

export const postmessageAudit: ScanCheck = {
  id: "postmessage-audit",
  name: "postMessage listener hardening (static)",
  active: false,
  perParameter: false,
  async run(ctx): Promise<CheckOutput> {
    const baseline = ctx.baselines[0] as Exchange | undefined;
    if (!baseline) return result("A captured HTML response is required.", true);
    if (!h(baseline, "content-type").toLowerCase().includes("html"))
      return result("A captured HTML response is required.", true);
    const body = text(baseline).slice(0, 256000);
    const findings: ReturnType<typeof observation>["findings"] = [];
    let seen = 0;
    for (const match of body.matchAll(listener)) {
      if (seen >= 3) break;
      const start = match.index ?? 0;
      const block = body.slice(start, start + 400);
      if (/\borigin\b/i.test(block)) continue;
      const reachesSink = sink.test(block);
      const output = observation(
        reachesSink
          ? "postMessage handler without origin check reaches a DOM sink"
          : "postMessage handler without a visible origin check",
        `A message listener was found without an origin check in the surrounding code${reachesSink ? " and it references a DOM or script sink" : ""}. This is a static observation from the captured HTML; the handler may validate origin elsewhere or be unreachable. No message was posted and no sink was executed.`,
        [baseline],
        [`Snippet: ${block.replace(/\s+/g, " ").slice(0, 240)}`],
        reachesSink ? "medium" : "low",
      );
      findings.push(output.findings[0]!);
      seen++;
    }
    for (const match of body.matchAll(wildcard)) {
      const output = observation(
        "postMessage uses a wildcard target origin",
        "A postMessage call uses '*' as the target origin. Any window that obtains a reference to the page can receive the message; confirm whether the payload is sensitive and whether the receiving origin is validated.",
        [baseline],
        [`Snippet: ${(match[0] ?? "").slice(0, 240)}`],
        "low",
      );
      findings.push(output.findings[0]!);
      break;
    }
    return {
      findings,
      message: findings.length
        ? "Static postMessage review produced observations; no message delivery or execution was tested."
        : "No obvious postMessage origin or wildcard issue found in the captured HTML.",
      inconclusive: !body.trim(),
    };
  },
};

export const postmessageChecks = [postmessageAudit];
