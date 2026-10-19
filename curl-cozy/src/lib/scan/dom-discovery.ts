import { auditDomScripts } from "./dom-audit";
import type { Exchange, ScanCheckContext } from "./types";

/** Discover dependencies using the original URL only. Payload renders cannot
 * cause additional HTTP requests, even when a payload changes a script URL. */
export async function prepareDomAudit(ctx: ScanCheckContext, interact = false) {
  const cache = new Map<string, Promise<Exchange>>();
  let bytes = 0;
  const bounded: ScanCheckContext = { ...ctx };
  if (ctx.loadScript) {
    bounded.loadScript = (url) => {
      const existing = cache.get(url);
      if (existing) return existing;
      if (cache.size >= 16 || bytes >= 1_000_000)
        return Promise.reject(Error("Runtime script count/byte limit reached."));
      const pending = ctx.loadScript!(url).then((exchange) => {
        const size = new TextEncoder().encode(exchange.response?.responseBody ?? "").length;
        bytes += size;
        if (size > 256000 || bytes > 1_000_000) throw Error("Runtime script byte limit reached.");
        return exchange;
      });
      cache.set(url, pending);
      return pending;
    };
  }
  let prepared = await auditDomScripts(bounded);
  const id = prepared.report.id;
  const discovered = new Set<string>();
  const notes: string[] = [];
  const record = () => {
    prepared.report.id = id;
    prepared.report.runtimeScripts = [...discovered];
    prepared.report.notes = [...new Set([...notes, ...prepared.report.notes])].slice(0, 40);
    ctx.recordDomAudit?.(prepared.report);
  };
  record();
  // A page may load its first executable code dynamically, even if the static
  // audit found no source/sink candidate. Do not gate discovery on candidates.
  if (!ctx.browser || !prepared.report.scripts.some((s) => s.parsed)) return prepared;
  for (let round = 0; round < 3; round++) {
    const observation = await ctx.browser(
      ctx.baselines[0]!,
      ctx.nonce(),
      ctx.request.url,
      prepared.resources,
      interact ? {} : undefined,
    );
    let added = 0;
    for (const value of observation.requestedScripts ?? []) {
      try {
        const url = new URL(value);
        if (
          !["http:", "https:"].includes(url.protocol) ||
          url.username ||
          url.password ||
          url.hash ||
          url.href.length > 4096 ||
          discovered.has(url.href)
        )
          continue;
        if (discovered.size >= 16) {
          notes.push(
            "Runtime dependency discovery limit reached; additional scripts remain untested.",
          );
          break;
        }
        discovered.add(url.href);
        added++;
      } catch {
        /* Ignore malformed dependency hints. */
      }
    }
    if (!added) {
      record();
      return prepared;
    }
    // Rebuild the static audit with new sources; cached promises prevent repeat
    // HTTP requests (including failures), and preserve one task-wide quota.
    prepared = await auditDomScripts(bounded, [...discovered]);
    record();
    if (round === 2) {
      notes.push(
        "Runtime discovery stopped after three rounds; further dependency levels remain untested.",
      );
      record();
    }
  }
  return prepared;
}
