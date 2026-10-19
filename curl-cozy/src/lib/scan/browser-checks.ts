import { mutateParameter } from "./parameters";
import { h, result } from "./extended-checks";
import { runDomXss } from "./dom-xss";
import type {
  BrowserObservation,
  CheckOutput,
  Exchange,
  ScanCheck,
  ScanCheckContext,
} from "./types";

export type BrowserValidator = (
  exchange: Exchange,
  marker: string,
  url?: string,
  resources?: import("./types").BrowserResource[],
  interaction?: import("./types").BrowserInteraction,
) => Promise<BrowserObservation>;
const html = (x: Exchange) =>
  !!x.response &&
  x.response.status >= 200 &&
  x.response.status < 300 &&
  h(x, "content-type").split(";")[0]?.trim().toLowerCase() === "text/html" &&
  x.response.responseBody.length <= 256000;
const payloads = [
  (m: string) => `"><svg onload="__slurpXss('${m}')">`,
  (m: string) => `'><svg onload="__slurpXss('${m}')">`,
  (m: string) => `</script><svg onload="__slurpXss('${m}')">`,
  (m: string) => `';__slurpXss('${m}');//`,
  (m: string) => `";__slurpXss('${m}');//`,
  (m: string) => `<img src=x onerror="__slurpXss('${m}')">`,
];
async function run(ctx: ScanCheckContext, fragment: boolean): Promise<CheckOutput> {
  if (!ctx.browser)
    return result("Browser validator is unavailable in this execution environment.", true);
  if (!fragment && !ctx.parameter) return result("Select a query or JSON parameter.", true);
  if (!ctx.baselines.every(html))
    return result("Browser XSS requires successful HTML baselines of at most 256 KB.", true);
  const browser = ctx.browser;
  const fragments = (value: string) => {
    const url = new URL(ctx.request.url);
    url.hash = encodeURIComponent(value);
    return url.toString();
  };
  const probe = async (value: string, label: string) => {
    // Fragments never reach the server: render the original response with the changed browser URL.
    if (fragment) return ctx.baselines[0]!;
    return ctx.probe(mutateParameter(ctx.request, ctx.parameter!, value), label);
  };
  const validate = (x: Exchange, marker: string, value?: string) =>
    browser(x, marker, fragment && value !== undefined ? fragments(value) : undefined);
  const evidence = [...ctx.baselines];
  let cspBlocked = false;
  for (const payload of payloads) {
    const marker = ctx.nonce(),
      value = payload(marker);
    const first = await probe(value, fragment ? "DOM fragment candidate" : "Browser XSS candidate");
    evidence.push(first);
    if (!html(first)) return result("An XSS probe did not return a supported HTML response.", true);
    const execution = await validate(first, marker, value);
    cspBlocked ||= execution.cspViolations.length > 0;
    if (!execution.executed) continue;
    const secondMarker = ctx.nonce(),
      secondValue = payload(secondMarker);
    const repeat = await probe(secondValue, "Repeat browser XSS with independent marker");
    evidence.push(repeat);
    if (!html(repeat)) return result("The repeated XSS response is unavailable.", true);
    const repeated = await validate(repeat, secondMarker, secondValue);
    if (!repeated.executed)
      return result("Browser execution did not reproduce with an independent marker.", true);
    const controlMarker = ctx.nonce();
    const negative = await probe(controlMarker, "Non-executable XSS marker control");
    evidence.push(negative);
    if (!html(negative)) return result("The non-executable XSS control failed.", true);
    const plain = await validate(negative, controlMarker, controlMarker);
    const original = fragment
      ? ctx.baselines[0]!
      : await ctx.probe(ctx.request, "Original-value XSS control");
    evidence.push(original);
    if (!html(original)) return result("The original-value XSS control failed.", true);
    const restored = await browser(original, marker);
    if (plain.executed || restored.executed)
      return result("A control also invoked the callback; XSS attribution is inconclusive.", true);
    const dom = fragment || (execution.sinks.length > 0 && repeated.sinks.length > 0);
    // Non-reflected execution without a recorded sink remains browser-observed XSS,
    // rather than being incorrectly labeled a proven server-side reflection.
    const reflected =
      first.response!.responseBody.includes(marker) &&
      repeat.response!.responseBody.includes(secondMarker);
    const kind = dom ? "DOM-based" : reflected ? "Reflected" : "Browser-observed";
    return {
      message: `${kind} XSS executed twice in isolated Chromium; plain and original controls did not execute.`,
      findings: [
        {
          title: `${kind} cross-site scripting (browser-validated)`,
          severity: "high",
          confidence: "high",
          status: "verified",
          evidenceIds: [...new Set(evidence.map((x) => x.evidence.id))],
          summary: `Two independent payloads invoked the browser callback while non-executable and original-value controls did not. The response was rendered at its original URL with its CSP headers. Secondary network requests and external scripts were blocked; this verifies execution in the isolated response snapshot.`,
          excerpts: [
            value,
            secondValue,
            `Browser: ${execution.browser}`,
            `Callback: __slurpXss('${marker}')`,
            ...(fragment ? [`Browser URL: ${fragments(value)}`] : []),
            ...[...new Set([...execution.sinks, ...repeated.sinks])]
              .slice(0, 12)
              .map((s) => `DOM sink: ${s}`),
          ].map((s) => s.slice(0, 4000)),
          verification: {
            method:
              "Isolated Chromium execution, independent repeated payload and negative/original controls",
            outcome: "confirmed",
            reason:
              "Both payload callbacks executed in the rendered response; neither control executed. Verification applies to the network-isolated snapshot, without external scripts or prior browser state.",
          },
          remediation:
            "Use context-aware output encoding and safe DOM APIs such as textContent. Sanitize intentional HTML with a maintained sanitizer and enforce a restrictive CSP.",
        },
      ],
    };
  }
  return result(
    cspBlocked
      ? "No payload execution observed; browser policy violations were recorded. External-script and state-dependent paths remain untested."
      : "No supported payload executed in the isolated snapshot. External-script and state-dependent paths remain untested.",
    true,
  );
}
export const browserChecks: ScanCheck[] = [
  {
    id: "browser-xss",
    name: "Reflected and DOM XSS (browser validation)",
    active: true,
    perParameter: true,
    run: (ctx) => run(ctx, false),
  },
  {
    id: "dom-xss",
    name: "DOM XSS (script audit and browser validation)",
    active: true,
    perParameter: false,
    run: runDomXss,
  },
  {
    id: "dom-interaction",
    name: "DOM XSS (input and event interaction)",
    active: true,
    perParameter: false,
    run: (ctx) => runDomXss(ctx, true),
  },
];
