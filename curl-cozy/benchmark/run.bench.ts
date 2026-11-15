import http from "node:http";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { expect, it } from "vitest";
import { ScanEngine, newScanPlan } from "../src/lib/scan";
import { checkRegistry } from "../src/lib/scan/registry";
import { getScanCheck } from "../src/lib/scan/checks";
import type { CheckId, ScanRun } from "../src/lib/scan/types";
import type { HttpRequest } from "../src/lib/traffic";
import { cases, type Case } from "./cases";
import { startLab } from "./lab";

type SendResult =
  | {
      ok: true;
      status: number;
      responseHeaders: Record<string, string>;
      responseBody: string;
      setCookies: string[];
      duration: number;
      size: number;
    }
  | { ok: false; error: string };

/** Sends the exact request bytes: a URL parser would normalize paths such as `/a/./b` or `//x`. */
function sendRaw(request: HttpRequest, timeoutMs = 15000): Promise<SendResult> {
  return new Promise((resolve) => {
    const started = Date.now();
    const match = /^https?:\/\/([^/:]+):(\d+)(\/.*)?$/.exec(request.url);
    if (!match) return resolve({ ok: false, error: "unsupported URL" });
    const headers: Record<string, string> = {
      ...request.headers,
      host: `${match[1]}:${match[2]}`,
      connection: "close",
    };
    if (request.body) headers["content-length"] = String(Buffer.byteLength(request.body, "latin1"));
    const req = http.request(
      {
        host: match[1]!,
        port: Number(match[2]),
        path: match[3] ?? "/",
        method: request.method,
        headers,
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("latin1");
          const responseHeaders: Record<string, string> = {};
          for (const [name, value] of Object.entries(res.headers))
            if (name !== "set-cookie")
              responseHeaders[name] = Array.isArray(value) ? value.join(", ") : String(value ?? "");
          resolve({
            ok: true,
            status: res.statusCode ?? 0,
            responseHeaders,
            responseBody: body,
            setCookies: res.headers["set-cookie"] ?? [],
            duration: Date.now() - started,
            size: body.length,
          });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => resolve({ ok: false, error: String(e.message) }));
    if (request.body) req.write(request.body, "latin1");
    req.end();
  });
}

/**
 * Configuration observations that fire on any page lacking headers, echoing input or showing an email
 * address. They are true statements about the response, not about the tested input, so they are only
 * scored on cases that are meant to be clean for them (see `strict` in the cases).
 */
const AMBIENT = new Set([
  "passive-audit",
  "security-headers",
  "policy-audit",
  "cookie-flags",
  "cookie-audit",
  "disclosure-audit",
  "parameter-hints",
  "reflection",
  "xss-bypass",
]);

const ALL_CHECKS = checkRegistry
  .filter((c) => c.status !== "planned" && c.execution !== "automatic")
  .map((c) => c.id)
  .filter((id) => {
    try {
      getScanCheck(id as CheckId);
      return true;
    } catch {
      return false;
    }
  }) as CheckId[];

async function runBatch(c: Case, origin: string, checks: CheckId[]): Promise<ScanRun> {
  const request = c.request(origin);
  // Passive checks need a captured response; the lab plays the role of the proxy history.
  const captured = await sendRaw(request);
  if (!captured.ok) throw new Error(`${c.id}: lab unreachable: ${captured.error}`);
  const plan = {
    ...newScanPlan(request),
    mode: "both" as const,
    observed: {
      response: {
        status: captured.status,
        responseHeaders: captured.responseHeaders,
        responseBody: captured.responseBody,
      },
      setCookies: captured.setCookies,
      duration: captured.duration,
      size: captured.size,
    },
    allowSending: true,
    checks,
    parameters: c.parameter ? [c.parameter] : [],
    baselineSamples: 3,
    policy: {
      maxImpact: "intrusive" as const,
      allowIntrusive: true,
      includeExperimental: true,
      maxDurationMs: 900_000,
      requestTimeoutMs: 15000,
    },
  };
  const engine = new ScanEngine(plan, {
    send: (r, o) => sendRaw(r, o?.timeoutMs),
    isCurrent: () => true,
  });
  // The lab is local: lift the 20 requests/second ceiling that protects real targets.
  const original = (engine as unknown as { original: { rate: number; delay: number } }).original;
  original.rate = 1_000_000;
  original.delay = 0;
  await engine.start();
  return engine.run;
}

type CaseResult = {
  id: string;
  found: string[];
  checks: Record<string, { status: string; message: string }>;
  sent: number;
  seconds: number;
  errors: string[];
};

async function runCase(c: Case, origin: string): Promise<CaseResult> {
  const started = Date.now();
  const found = new Set<string>();
  const checks: CaseResult["checks"] = {};
  const errors: string[] = [];
  let sent = 0;
  for (let i = 0; i < ALL_CHECKS.length; i += 60) {
    const run = await runBatch(c, origin, ALL_CHECKS.slice(i, i + 60));
    sent += run.sent;
    if (run.status !== "completed") errors.push(`${run.status}: ${run.message}`);
    for (const f of run.findings) found.add(f.checkId);
    for (const r of run.checks) checks[r.checkId] = { status: r.status, message: r.message ?? "" };
  }
  return {
    id: c.id,
    found: [...found].sort(),
    checks,
    sent,
    seconds: (Date.now() - started) / 1000,
    errors,
  };
}

async function pool<T, R>(items: T[], size: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: size }, async () => {
      while (next < items.length) {
        const index = next++;
        out[index] = await fn(items[index]!);
      }
    }),
  );
  return out;
}

it("scores the scan checks against the lab", async () => {
  const lab = await startLab();
  const only = process.env["BENCH_ONLY"]?.split(",");
  const selected = only
    ? cases.filter((c) => only.includes(c.id) || only.includes(c.group))
    : cases;
  const started = Date.now();
  const results = await pool(selected, 6, async (c) => {
    const r = await runCase(c, lab.origin);
    process.stdout.write(
      `${c.kind.padEnd(5)} ${c.id.padEnd(22)} ${r.seconds.toFixed(1).padStart(5)}s sent=${String(r.sent).padStart(4)} found=[${r.found.join(", ")}]${r.errors.length ? " ERR " + r.errors.join("|") : ""}\n`,
    );
    return r;
  });
  await lab.close();

  // Score every check.
  const score = new Map<
    string,
    {
      expected: string[];
      hit: string[];
      missed: string[];
      falsePositives: string[];
      tolerated: string[];
      negatives: number;
    }
  >();
  for (const id of ALL_CHECKS)
    score.set(id, {
      expected: [],
      hit: [],
      missed: [],
      falsePositives: [],
      tolerated: [],
      negatives: 0,
    });
  for (const c of selected) {
    const r = results.find((x) => x.id === c.id)!;
    for (const id of ALL_CHECKS) {
      const s = score.get(id)!;
      const found = r.found.includes(id);
      if (c.expect.includes(id)) {
        s.expected.push(c.id);
        (found ? s.hit : s.missed).push(c.id);
      } else if (
        found &&
        (c.tolerate?.includes(id) || (AMBIENT.has(id) && !c.strict?.includes(id)))
      )
        s.tolerated.push(c.id);
      else if (found) s.falsePositives.push(c.id);
      if (c.kind !== "vuln") s.negatives++;
    }
  }
  const outDir = path.resolve(__dirname, "results");
  mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().slice(0, 10);
  const payload = {
    date: stamp,
    registry: Object.fromEntries(checkRegistry.map((c) => [c.id, c.status])),
    seconds: (Date.now() - started) / 1000,
    cases: selected.map((c) => ({
      id: c.id,
      group: c.group,
      kind: c.kind,
      title: c.title,
      expect: c.expect,
      tolerate: c.tolerate ?? [],
    })),
    results,
    score: Object.fromEntries(score),
  };
  writeFileSync(
    path.join(
      outDir,
      `scan-benchmark-${stamp}${process.env["BENCH_TAG"] ? "-" + process.env["BENCH_TAG"] : ""}${only ? "-partial" : ""}.json`,
    ),
    JSON.stringify(payload, null, 2),
  );
  expect(results.length).toBe(selected.length);
}, 3_600_000);
