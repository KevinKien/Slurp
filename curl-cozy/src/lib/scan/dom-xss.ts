import { type DomCandidate, type DomContext, type DomSource } from "./dom-audit";
import { prepareDomAudit } from "./dom-discovery";
import { h, result } from "./extended-checks";
import type { BrowserObservation, CheckOutput, ScanCheckContext } from "./types";
const callback = (marker: string) => `__slurpXss(/${marker}/.source)`;
const families: Record<DomContext, Array<{ name: string; value: (marker: string) => string }>> = {
  html: [
    { name: "html-element", value: (m) => `<svg onload="${callback(m)}"></svg>` },
    { name: "double-quoted-attribute", value: (m) => `"><svg onload="${callback(m)}"></svg>` },
    { name: "single-quoted-attribute", value: (m) => `'><svg onload="${callback(m)}"></svg>` },
    { name: "html-error-handler", value: (m) => `<img src=x onerror="${callback(m)}">` },
    { name: "html-spaced-handler", value: (m) => `<img src=x onerror = "${callback(m)}">` },
  ],
  script: [
    { name: "javascript-expression", value: callback },
    { name: "single-quoted-javascript", value: (m) => `'-${callback(m)}-'` },
    { name: "double-quoted-javascript", value: (m) => `"-${callback(m)}-"` },
    { name: "single-quoted-statement", value: (m) => `');${callback(m)};//` },
    { name: "double-quoted-statement", value: (m) => `");${callback(m)};//` },
    { name: "template-literal", value: (m) => `\${${callback(m)}}` },
  ],
  url: [{ name: "javascript-url", value: (m) => `javascript:${callback(m)}` }],
};
export function domPayloadFamilies(
  context: DomContext,
  observation?: BrowserObservation,
  marker?: string,
) {
  const values = [...families[context]];
  if (context !== "html" || !marker) return values;
  const trace = observation?.sinkTraces?.find((t) => t.value.includes(marker));
  if (!trace) return values;
  const prefix = trace.value.slice(0, trace.value.indexOf(marker));
  // The marker first reaches the real sink. Prefer the quote context in that value.
  const tag = prefix.slice(prefix.lastIndexOf("<"));
  const preferred = /(?:href|src|action)\s*=\s*["']?$/i.test(tag)
    ? families.url[0]
    : /="[^"<>]*$/.test(tag)
      ? families.html[1]
      : /='[^'<>]*$/.test(tag)
        ? families.html[2]
        : families.html[0];
  return [preferred!, ...values.filter((p) => p.name !== preferred!.name)];
}
export function domSourceUrl(original: string, source: DomSource, value: string) {
  const url = new URL(original),
    payload = source.base64 ? btoa(value) : value;
  if (source.kind === "query") {
    if (!source.name) throw Error("A query source needs a parameter name.");
    url.searchParams.set(source.name, payload);
  } else if (source.kind === "fragment" || source.kind === "url") {
    url.hash = source.decoded ? encodeURIComponent(payload) : payload;
  } else if (source.kind === "input") return url.href;
  else
    throw Error("This source needs browser state or interaction and is not currently injectable.");
  if (url.href.length > 12000) throw Error("DOM browser URL exceeds 12 KB.");
  return url.href;
}
function targets(candidate: DomCandidate, original: string): DomCandidate[] {
  if (candidate.source.kind === "unsupported") return [];
  if (candidate.source.kind !== "query" || candidate.source.name !== undefined) return [candidate];
  return [...new Set(new URL(original).searchParams.keys())]
    .slice(0, 10)
    .map((name) => ({ ...candidate, source: { ...candidate.source, name } }));
}
export async function runDomXss(ctx: ScanCheckContext, interact = false): Promise<CheckOutput> {
  if (!ctx.browser)
    return result("Browser validator is unavailable in this execution environment.", true);
  const baseline = ctx.baselines[0];
  if (
    !baseline?.response ||
    baseline.response.status < 200 ||
    baseline.response.status >= 300 ||
    h(baseline, "content-type").split(";")[0]?.trim().toLowerCase() !== "text/html" ||
    new TextEncoder().encode(baseline.response.responseBody).length > 256000
  )
    return result("DOM script audit requires a successful HTML response up to 256 KB.", true);
  const { report, resources, evidence } = await prepareDomAudit(ctx, interact);
  ctx.recordDomAudit?.(report);
  if (!report.candidates.length)
    return result(
      `Audited ${report.scripts.length} scripts; no supported ${interact ? "input/URL" : "URL"} source-to-sink candidate was identified. Static analysis is incomplete for dynamic/obfuscated flows.`,
      true,
    );
  const render = (marker: string, url: string, source?: DomSource, value?: string) =>
    ctx.browser!(
      baseline,
      marker,
      url,
      resources,
      interact
        ? {
            ...(source?.kind === "input" && source.name && value !== undefined
              ? { selector: source.name, value: source.base64 ? btoa(value) : value }
              : {}),
          }
        : undefined,
    );
  const findings: CheckOutput["findings"] = [],
    tested = new Set<string>();
  let attempts = 0;
  for (const original of report.candidates)
    for (const candidate of targets(original, ctx.request.url)) {
      if (candidate.source.kind === "input" && !interact) continue;
      const sourceKey = JSON.stringify([candidate.source, candidate.context]);
      if (tested.has(sourceKey)) continue;
      tested.add(sourceKey);
      const marker = ctx.nonce(),
        markerUrl = domSourceUrl(ctx.request.url, candidate.source, marker);
      const reached = await render(marker, markerUrl, candidate.source, marker);
      const options = domPayloadFamilies(candidate.context, reached, marker);
      candidate.families = options.map((p) => p.name);
      for (const family of options) {
        attempts++;
        const firstMarker = ctx.nonce(),
          payload = family.value(firstMarker),
          firstUrl = domSourceUrl(ctx.request.url, candidate.source, payload);
        const first = await render(firstMarker, firstUrl, candidate.source, payload);
        if (!first.executed) continue;
        const secondMarker = ctx.nonce(),
          secondPayload = family.value(secondMarker);
        const repeated = await render(
          secondMarker,
          domSourceUrl(ctx.request.url, candidate.source, secondPayload),
          candidate.source,
          secondPayload,
        );
        if (!repeated.executed) {
          report.notes.push(
            `Execution did not reproduce: ${candidate.source.label} -> ${candidate.sink}`,
          );
          break;
        }
        const controlMarker = ctx.nonce();
        const plain = await render(
          controlMarker,
          domSourceUrl(ctx.request.url, candidate.source, controlMarker),
          candidate.source,
          controlMarker,
        );
        const restored = await render(firstMarker, ctx.request.url);
        if (reached.executed || plain.executed || restored.executed) {
          report.notes.push(
            `A control invoked the callback; attribution is inconclusive: ${candidate.source.label}`,
          );
          break;
        }
        const sourceLabel =
          candidate.source.kind === "query"
            ? `query parameter ${JSON.stringify(candidate.source.name)}`
            : candidate.source.label;
        const traces = [...(first.sinkTraces ?? []), ...(repeated.sinkTraces ?? [])].slice(0, 2);
        findings.push({
          title:
            `DOM-based cross-site scripting: ${sourceLabel} (${candidate.context} context)`.slice(
              0,
              240,
            ),
          severity: "high",
          confidence: "high",
          status: "verified",
          evidenceIds: [...new Set(evidence.map((x) => x.evidence.id))],
          summary: `A script audit identified a ${candidate.source.kind === "input" ? "DOM input" : "URL"} source and a dangerous sink. Context-selected payloads executed twice with independent callbacks in the original HTML and captured-script snapshots. ${candidate.source.kind === "input" ? "Only the identified DOM input value changed, followed by bounded event exploration" : "Only the browser URL changed"}; the server response was not modified. Benign marker and original-state controls did not execute.`,
          verification: {
            method: `Script source/sink audit, benign marker observation, context-selected browser payloads${interact ? ", bounded input/event exploration" : ""} and negative/original controls`,
            outcome: "confirmed",
            reason:
              "Both independent payloads executed in the main document's original origin. Control callbacks did not execute. Scripts were served from captured snapshots with their CSP/MIME policy; uncaptured network requests remained blocked. Static flow hints do not constitute full taint tracking.",
          },
          excerpts: [
            `Source: ${sourceLabel}`,
            `Static sink candidate: ${candidate.sink}`,
            `Script: ${candidate.script}:${candidate.line}:${candidate.column}`,
            candidate.excerpt,
            `Payload family: ${family.name}`,
            payload,
            secondPayload,
            `Browser URL: ${firstUrl}`,
            `DOM audit: ${report.id}`,
            `Browser: ${first.browser}`,
            ...(first.interactions ?? []).map((a) => `Interaction: ${a}`),
            ...traces.flatMap((t) => [
              `Observed sink: ${t.sink}`,
              `Sink value: ${t.value}`,
              `Sink stack: ${t.stack}`,
            ]),
          ].map((s) => s.slice(0, 4000)),
          remediation:
            "Use textContent and safe DOM construction instead of HTML/code evaluation. Apply context-aware sanitization for intentional HTML, restrict executable URL schemes and enforce CSP/Trusted Types.",
        });
        break;
      }
    }
  if (report.candidates.some((c) => c.source.kind === "unsupported"))
    report.notes.push(
      "Referrer, storage and other state-dependent sources require a separate stateful browser workflow.",
    );
  report.notes = report.notes.slice(0, 40);
  ctx.recordDomAudit?.(report);
  return {
    findings,
    message: `Audited ${report.scripts.length} scripts; ${report.candidates.length} static candidates, ${attempts} context-selected payload attempts, ${findings.length} browser-validated findings. Review the DOM script audit for untested paths.`,
    inconclusive: !findings.length,
  };
}
