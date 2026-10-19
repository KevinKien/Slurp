import type { CheckOutput, Exchange, OastProbe, ScanCheck, ScanCheckContext } from "./types";
import { mutateParameter } from "./parameters";
import { result } from "./extended-checks";

async function run(ctx: ScanCheckContext, xml: boolean): Promise<CheckOutput> {
  if (!ctx.oast)
    return result("OAST collector is unavailable in this execution environment.", true);
  if (!xml && !ctx.parameter) return result("Select a URL-bearing query or JSON parameter.", true);
  if (
    xml &&
    (!/(?:application|text)\/(?:[\w.+-]*\+)?xml\b/i.test(
      Object.entries(ctx.request.headers).find(([k]) => k.toLowerCase() === "content-type")?.[1] ??
        "",
    ) ||
      !ctx.request.body.trimStart().startsWith("<"))
  )
    return result("OAST XXE requires an XML request body and XML Content-Type.", true);
  // Never destroy existing document types or signed documents silently.
  if (xml && /<!DOCTYPE|<!ENTITY|<(?:[\w.-]+:)?Signature\b/i.test(ctx.request.body))
    return result("Existing DTD/entity or signed XML requires a dedicated manual workflow.", true);
  const client = ctx.oast;
  const first = await client.issue(),
    second = await client.issue(),
    control = await client.issue();
  const probes = [first, second];
  const exchanges: Exchange[] = [];
  for (const [i, probe] of probes.entries()) {
    let request = ctx.request;
    if (xml) {
      const root = /^(?:\s*<\?xml[^?]*\?>)?\s*<([A-Za-z_][\w.:-]*)\b/.exec(ctx.request.body)?.[1];
      if (!root) return result("Unable to identify the XML root element.", true);
      const declaration = /^(\s*<\?xml[^?]*\?>)/.exec(ctx.request.body)?.[1] ?? "";
      const rest = ctx.request.body.slice(declaration.length);
      const url = probe.url.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
      // External parameter-entity retrieval does not depend on an application
      // field accepting an arbitrary entity-reference value.
      const dtd = `<!DOCTYPE ${root} [<!ENTITY % slurpOast SYSTEM "${url}">%slurpOast;]>`;
      request = { ...ctx.request, body: declaration + dtd + rest };
    } else request = mutateParameter(ctx.request, ctx.parameter!, probe.url);
    exchanges.push(
      await ctx.probe(request, `${xml ? "XXE external entity" : "SSRF URL"} OAST probe ${i + 1}`),
    );
  }
  let observed: OastProbe[] = [];
  let negative = control;
  // A bounded callback window; no callback is never a clean security result.
  for (let round = 0; round < 16; round++) {
    observed = await Promise.all(probes.map((p, i) => client.poll(p, exchanges[i])));
    negative = await client.poll(control, exchanges[0]);
    if (negative.events.length)
      return result(
        "An unsubmitted OAST control received an interaction; attribution is inconclusive.",
        true,
      );
    if (observed.every((p) => p.events.length)) break;
    if (round < 15) await client.wait(1000);
  }
  if (!observed.every((p) => p.events.length))
    return result(
      "Two independent OAST probes were sent, but correlated callbacks did not both arrive within 15 seconds. Review callback evidence and collector reachability; delayed callbacks remain unassessed.",
      true,
    );
  const http = observed.every((p) => p.events.some((e) => e.protocol === "http"));
  const kind = xml
    ? "External XML entity interaction"
    : "Server-side external interaction (SSRF candidate)";
  return {
    message: `Two independent ${http ? "HTTP" : "HTTP/DNS"} callbacks correlated; unsubmitted control remained silent.`,
    findings: [
      {
        title: `${kind} via ${http ? "HTTP" : "DNS/HTTP"} callback`,
        severity: xml || http ? "high" : "medium",
        confidence: "high",
        status: "needs_review",
        evidenceIds: [...ctx.baselines, ...exchanges].map((x) => x.evidence.id),
        summary:
          "The collector observed interactions for two independently generated callback addresses supplied only in the probe requests. An unsubmitted random-address control received no interactions. This confirms external interaction, not sensitive resource access; intermediaries and link scanners must be considered.",
        verification: {
          method: "Independent OAST callback correlation with an unsubmitted control",
          outcome: "confirmed",
          reason: http
            ? "Both unique probes caused HTTP callbacks. Review source peers and application behavior before confirming SSRF/XXE exploitability."
            : "Both probes caused HTTP/DNS interactions. DNS alone establishes name resolution, not an HTTP fetch or internal-data access.",
        },
        excerpts: [
          ...observed.flatMap((p) => [
            `Callback URL: ${p.url}`,
            ...(p.dnsName ? [`DNS name: ${p.dnsName}`] : []),
            ...p.events.map(
              (e) => `${e.timestamp} ${e.protocol.toUpperCase()} ${e.peer} ${e.detail}`,
            ),
          ]),
          `Unsubmitted control: ${negative.id}; ${negative.events.length} events`,
        ].map((s) => s.slice(0, 4000)),
        remediation: xml
          ? "Disable external general/parameter entities and DTD processing. Use a parser with external resource resolution disabled."
          : "Allowlist outbound destinations and schemes, validate resolved addresses at connection time and enforce network egress restrictions.",
      },
    ],
  };
}
export const oastChecks: ScanCheck[] = [
  {
    id: "oast-ssrf",
    name: "Blind SSRF (OAST HTTP/DNS)",
    active: true,
    perParameter: true,
    run: (ctx) => run(ctx, false),
  },
  {
    id: "oast-xxe",
    name: "Blind XXE (OAST HTTP/DNS)",
    active: true,
    perParameter: false,
    run: (ctx) => run(ctx, true),
  },
];
