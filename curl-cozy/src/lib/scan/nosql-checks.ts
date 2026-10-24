import type { ScanCheck, Exchange, ScanCheckContext } from "./types";
import { mutateJsonOperator, parameterValue } from "./parameters";
import { compareResponses } from "../response-diff";
import { ok, text, h, result, observation } from "./extended-checks";
const success = (x: Exchange) => ok(x) && x.response!.status >= 200 && x.response!.status < 300;
function same(a: Exchange, b: Exchange, ctx: ScanCheckContext) {
  if (!ok(a) || !ok(b)) return false;
  const diff = compareResponses(a.response!, b.response!, ctx.diffOptions);
  return !diff.statusChanged && !diff.bodyChanged;
}
function data(x: Exchange) {
  if (!success(x) || !h(x, "content-type").toLowerCase().includes("json") || !text(x).trim())
    return false;
  try {
    const parsed = JSON.parse(text(x));
    return (
      parsed !== null &&
      typeof parsed === "object" &&
      !Object.hasOwn(parsed, "error") &&
      !Object.hasOwn(parsed, "errors")
    );
  } catch {
    return false;
  }
}
export const nosqlOperators: ScanCheck = {
  id: "nosql-operators",
  name: "NoSQL JSON operator interpretation",
  active: true,
  perParameter: true,
  async run(ctx) {
    if (
      ctx.parameter?.kind !== "json" ||
      !ctx.stable ||
      ctx.baselines.length < 2 ||
      !ctx.baselines.every(data)
    )
      return result(
        "Selected JSON string and stable successful JSON data baselines required.",
        true,
      );
    const original = parameterValue(ctx.request, ctx.parameter);
    // Avoid coercing numbers, nulls or booleans into a regex query.
    let node: unknown = JSON.parse(ctx.request.body);
    for (const part of ctx.parameter.pointer
      .slice(1)
      .split("/")
      .map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"))) {
      if (!node || typeof node !== "object" || !Object.hasOwn(node, part))
        return result("JSON scalar no longer exists.", true);
      node = (node as Record<string, unknown>)[part];
    }
    if (typeof node !== "string" || original.length > 1000)
      return result("Bounded JSON string scalar required.", true);
    const escaped = original.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const rows: Exchange[] = [];
    for (let i = 0; i < 2; i++) {
      // Anchored literal pattern preserves the original match set, rather than broadening the query.
      const positive = i === 0 ? `^${escaped}$` : `^(?:${escaped})$`;
      const negative = `^slurp_missing_${ctx.nonce().replace(/[^a-zA-Z0-9]/g, "")}$`;
      rows.push(
        await ctx.probe(
          mutateJsonOperator(ctx.request, ctx.parameter, { $regex: positive }),
          `NoSQL exact regex ${i + 1}`,
        ),
      );
      rows.push(
        await ctx.probe(
          mutateJsonOperator(ctx.request, ctx.parameter, { $regex: negative }),
          `NoSQL nonmatching regex ${i + 1}`,
        ),
      );
    }
    const restore = await ctx.probe(ctx.request, "NoSQL original scalar restore");
    if (!same(restore, ctx.baselines[0]!, ctx) || !rows.every(ok))
      return result("NoSQL controls unavailable or original data changed.", true);
    const [a, b, c, d] = rows as [Exchange, Exchange, Exchange, Exchange];
    const denied = (x: Exchange) => ok(x) && [401, 403].includes(x.response!.status);
    const negativeValid = [b, d].every(denied) || ([b, d].every(data) && same(b, d, ctx));
    if (
      ![a, c].every((x) => data(x) && same(x, ctx.baselines[0]!, ctx)) ||
      !negativeValid ||
      same(a, b, ctx) ||
      same(c, d, ctx)
    )
      return result("No repeated exact-match/nonmatch JSON operator differential.");
    const output = observation(
      "Possible NoSQL injection: JSON regex operators interpreted",
      "Two anchored exact-match regex objects reproduced the scalar response while independent nonmatching patterns produced consistent different data or access denial. The original scalar restored the baseline. This supports operator interpretation; intended query-DSL support and authorization impact require review. No broad match, JavaScript evaluation or data writes were introduced by the payloads.",
      [...ctx.baselines, ...rows, restore],
      [
        "JSON scalar replaced by $regex objects",
        "Two exact-match and nonmatch pairs; original scalar restored",
      ],
      "medium",
    );
    output.findings[0]!.remediation =
      "Enforce scalar input types, reject client-supplied query operators and construct database queries from validated values.";
    return output;
  },
};
