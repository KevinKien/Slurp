import type { ScanCheck, ScanCheckContext, Exchange, ScanParameter } from "./types";
import { mutateParameter, mutateNumber, parameterValue, parameterKey } from "./parameters";
import { ok, text, result, observation } from "./extended-checks";
export const fieldName = (p: ScanParameter) =>
  p.kind === "json" ? p.pointer.split("/").at(-1)!.replace(/~1/g, "/").replace(/~0/g, "~") : p.name;

export function businessKind(
  ctx: Pick<ScanCheckContext, "request">,
  p: ScanParameter,
): "number" | "date" | undefined {
  const value = parameterValue(ctx.request, p);
  if (
    /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(value.trim()) &&
    Number.isFinite(Number(value))
  )
    return "number";
  if (/^\d{4}-\d{2}-\d{2}(?:T.*)?$/.test(value) && Number.isFinite(Date.parse(value)))
    return "date";
  return undefined;
}
function accepted(x: Exchange) {
  if (!ok(x) || x.response!.status < 200 || x.response!.status >= 300 || !text(x).trim())
    return false;
  try {
    const v = JSON.parse(text(x));
    if (
      !v ||
      typeof v !== "object" ||
      v.error ||
      (Array.isArray(v.errors) ? v.errors.length : v.errors) ||
      v.success === false ||
      v.ok === false ||
      /^(?:error|failed|invalid|denied)$/i.test(v.status ?? "")
    )
      return false;
    return true;
  } catch {
    return false;
  }
}
function reflected(x: Exchange, name: string, value: string) {
  if (!accepted(x)) return false;
  let count = 0;
  const walk = (v: unknown, depth: number): boolean => {
    if (++count > 1000 || depth > 10 || !v || typeof v !== "object") return false;
    return Object.entries(v).some(
      ([key, child]) => (key === name && String(child) === value) || walk(child, depth + 1),
    );
  };
  return walk(JSON.parse(text(x)), 0);
}
function scalarAt(x: Exchange, pointer: string): unknown {
  if (!accepted(x)) return undefined;
  let v: unknown = JSON.parse(text(x));
  if (pointer !== "")
    for (const part of pointer.slice(1).split("/")) {
      const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
      if (!v || typeof v !== "object" || !Object.hasOwn(v, key)) return undefined;
      v = (v as Record<string, unknown>)[key];
    }
  return typeof v === "number" || typeof v === "string" ? v : undefined;
}
async function run(ctx: ScanCheckContext, kind: "number" | "date") {
  if (
    !ctx.parameter ||
    ctx.baselines.length < 2 ||
    !ctx.baselines.every(accepted) ||
    businessKind(ctx, ctx.parameter) !== kind
  )
    return result(`A matching ${kind} field and successful JSON baselines required.`, true);
  const p = ctx.parameter,
    original = parameterValue(ctx.request, p),
    name = fieldName(p);
  const groups: { name: string; values: string[]; note: string }[] = [];
  if (kind === "number") {
    groups.push({
      name: "Negative numeric value",
      values: ["-1", String(-Math.max(2, Math.abs(Number(original))))],
      note: "Negative values may be intentional for credits, ranges or corrections; business impact requires review.",
    });
    groups.push(
      {
        name: "Zero numeric value",
        values: ["0", "0"],
        note: "Zero can be valid; verify the intended lower bound.",
      },
      {
        name: "Large numeric value",
        values: ["2147483648", "9007199254740991"],
        note: "Large values can be valid; check range and overflow handling.",
      },
      {
        name: "Fractional numeric value",
        values: ["0.5", "1.5"],
        note: "Fractional values can be valid; confirm whether this field must be integral.",
      },
      {
        name: "Numeric boundary value",
        values: ["2147483647", "2147483646"],
        note: "Tests the signed 32-bit integer boundary; no application-specific limit is inferred.",
      },
    );
  } else {
    groups.push({
      name: "Invalid date format",
      values: [`not-a-date-${ctx.nonce()}`, "2025-02-30"],
      note: "The date strings are malformed or contain an impossible calendar date; reflection does not prove persistence.",
    });
    if (Date.parse(original) > Date.now()) {
      const date = (days: number) => {
        const d = new Date(Date.now() - days * 86400000);
        return original.includes("T") ? d.toISOString() : d.toISOString().slice(0, 10);
      };
      groups.push({
        name: "Past date",
        values: [date(365), date(730)],
        note: "Past dates can be intentional. A future-only business rule and downstream effects must be verified.",
      });
    }
  }
  const findings = [];
  let incomplete = false;
  for (const group of groups) {
    const rows: Exchange[] = [];
    let matches = true;
    const config = ctx.businessReadback;
    const readback = config && config.parameter === parameterKey(p) && ctx.readBusiness;
    let persisted = !!readback;
    let beforeValue: unknown;
    if (readback) {
      const first = await readback("Business read-back: before mutation");
      const repeat = await readback("Business read-back: before repeat");
      rows.push(first, repeat);
      beforeValue = scalarAt(first, config!.pointer);
      persisted =
        beforeValue !== undefined &&
        beforeValue === scalarAt(repeat, config!.pointer) &&
        String(beforeValue) === original;
      if (!persisted) incomplete = true;
    }
    const writes: Exchange[] = [];
    for (const value of group.values) {
      const request =
        kind === "number"
          ? mutateNumber(ctx.request, p, Number(value))
          : mutateParameter(ctx.request, p, value);
      const a = await ctx.probe(request, `${group.name}: ${value}`);
      rows.push(a);
      writes.push(a);
      if (!ok(a)) {
        incomplete = true;
        matches = false;
        break;
      }
      // A 2xx response alone does not establish that the field was processed.
      if (!accepted(a)) {
        matches = false;
        break;
      }
      if (readback) {
        const after = await readback(`Business read-back: after ${value}`);
        const repeat = await readback(`Business read-back: after ${value} repeat`);
        rows.push(after, repeat);
        const actual = scalarAt(after, config!.pointer);
        if (
          actual === undefined ||
          String(actual) !== value ||
          actual !== scalarAt(repeat, config!.pointer) ||
          (Number.isFinite(Number(beforeValue)) && Number(beforeValue) === Number(value))
        )
          persisted = false;
      }
    }
    if (!matches && !readback) continue;
    const restore = await ctx.probe(ctx.request, "Business original-value control");
    if (!accepted(restore)) {
      incomplete = true;
      continue;
    }
    if (readback) {
      const restored = await readback("Business read-back: original-value restoration");
      rows.push(restored);
      if (scalarAt(restored, config!.pointer) !== beforeValue) {
        persisted = false;
        incomplete = true;
      }
    }
    if (!matches) continue;
    if (kind === "number") {
      const invalid = await ctx.probe(
        mutateParameter(ctx.request, p, `slurp-invalid-${ctx.nonce()}`),
        "Business malformed numeric control",
      );
      rows.push(invalid);
      if (!ok(invalid)) {
        incomplete = true;
        continue;
      }
      if (![400, 422].includes(invalid.response!.status)) continue;
    }
    const echoed = group.values.every((value, i) => reflected(writes[i]!, name, value));
    const out = observation(
      `${group.name} ${persisted ? "persisted in read-back" : echoed ? "returned" : "received successful responses"} for ${name}`,
      `Two test requests received successful JSON responses without recognized error envelopes, and the original-value control succeeded. ${echoed ? "Both test values were returned under the tested field." : "The response did not establish that the values were applied; they may be ignored, clamped or normalized."} ${group.note} ${persisted ? "Independent GET read-backs showed a stable original value, both submitted values twice, and restoration of the original value. This establishes observed state changes at the configured read-back field, not business impact or database-level durability." : readback ? "Configured read-back did not establish repeatable persistence and restoration; review its evidence." : "No separate read-back or account/balance verification was performed; the API may only echo input."} Replaying the captured request may change server state.`,
      [...ctx.baselines, ...rows, restore],
      [
        ...group.values.map((v) => `${name} = ${v}`),
        ...(readback
          ? [
              `Read-back GET ${config!.url}; JSON pointer ${config!.pointer || "(root)"}; original value ${String(beforeValue)}`,
            ]
          : []),
      ],
      persisted ? "medium" : echoed ? "low" : "info",
    );
    out.findings[0]!.remediation =
      "Validate numeric bounds and strict calendar formats server-side, and enforce the intended business rules independently of client input.";
    findings.push(...out.findings);
  }
  return {
    findings,
    message: incomplete
      ? "Some business-rule evidence was unavailable or controls failed."
      : "Business-rule probes completed; accepted values require business-context review.",
    inconclusive: incomplete && !findings.length,
  };
}
export const businessChecks: ScanCheck[] = [
  {
    id: "business-negative",
    name: "Business logic: numeric bounds and persistence",
    active: true,
    perParameter: true,
    run: (ctx) => run(ctx, "number"),
  },
  {
    id: "business-dates",
    name: "Business logic: past and invalid dates",
    active: true,
    perParameter: true,
    run: (ctx) => run(ctx, "date"),
  },
];
