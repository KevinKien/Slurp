import { loadAll } from "js-yaml";
import type { Exchange, ScanCheck, ScanCheckContext } from "./types";
import { ok, text, result, observation } from "./extended-checks";

type Matcher = {
  type: "status" | "word" | "regex" | "size";
  part: "body" | "header" | "all";
  condition: "and" | "or";
  negative: boolean;
  words: string[];
  regex: string[];
  status: number[];
  size: number[];
};
type TemplateRequest = {
  method: "GET" | "POST";
  paths: string[];
  headers: Record<string, string>;
  body: string;
  condition: "and" | "or";
  matchers: Matcher[];
};
type Template = {
  id: string;
  name: string;
  severity: string;
  description: string;
  requests: TemplateRequest[];
};

const MAX_TEMPLATES = 5;
const MAX_REQUESTS = 10;
const severities = new Set(["info", "low", "medium", "high", "critical", "unknown"]);

function stringList(value: unknown): string[] {
  if (typeof value === "string") return [value];
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}
function numberList(value: unknown): number[] {
  const list = Array.isArray(value) ? value : [value];
  return list.filter((item): item is number => typeof item === "number" && Number.isFinite(item));
}

function parseMatcher(value: unknown): Matcher | string {
  if (!value || typeof value !== "object") return "matcher is not an object";
  const raw = value as Record<string, unknown>;
  const type = String(raw["type"] ?? "");
  if (!["status", "word", "regex", "size"].includes(type)) return `unsupported matcher type: ${type}`;
  const part = String(raw["part"] ?? "body").toLowerCase();
  if (!["body", "header", "all"].includes(part)) return `unsupported matcher part: ${part}`;
  const condition = String(raw["condition"] ?? "or").toLowerCase();
  if (!["and", "or"].includes(condition)) return `unsupported matcher condition: ${condition}`;
  const matcher: Matcher = {
    type: type as Matcher["type"],
    part: part as Matcher["part"],
    condition: condition as Matcher["condition"],
    negative: raw["negative"] === true,
    words: stringList(raw["words"]),
    regex: stringList(raw["regex"]),
    status: numberList(raw["status"]),
    size: numberList(raw["size"]),
  };
  if (matcher.type === "word" && matcher.words.length === 0) return "word matcher has no words";
  if (matcher.type === "regex") {
    if (matcher.regex.length === 0) return "regex matcher has no patterns";
    for (const pattern of matcher.regex) {
      try {
        new RegExp(pattern);
      } catch {
        return `invalid regex: ${pattern}`;
      }
    }
  }
  if (matcher.type === "status" && matcher.status.length === 0) return "status matcher has no codes";
  if (matcher.type === "size" && matcher.size.length === 0) return "size matcher has no sizes";
  return matcher;
}

function parseRequest(value: unknown): TemplateRequest | string {
  if (!value || typeof value !== "object") return "request is not an object";
  const raw = value as Record<string, unknown>;
  if (raw["raw"]) return "raw requests are not supported";
  if (raw["payloads"] || raw["attack"]) return "payload/attack templates are not supported";
  if (raw["req-condition"]) return "req-condition templates are not supported";
  const method = String(raw["method"] ?? "GET").toUpperCase();
  if (!["GET", "POST"].includes(method)) return `unsupported method: ${method}`;
  const paths = stringList(raw["path"]);
  if (!paths.length) return "request has no path";
  const headers: Record<string, string> = {};
  if (raw["headers"] && typeof raw["headers"] === "object") {
    for (const [name, header] of Object.entries(raw["headers"] as Record<string, unknown>)) {
      if (typeof header === "string") headers[name] = header;
    }
  }
  const body = typeof raw["body"] === "string" ? raw["body"] : "";
  const condition = String(raw["matchers-condition"] ?? "or").toLowerCase();
  if (!["and", "or"].includes(condition)) return `unsupported matchers-condition: ${condition}`;
  const matchers: Matcher[] = [];
  for (const value of Array.isArray(raw["matchers"]) ? raw["matchers"] : []) {
    const parsed = parseMatcher(value);
    if (typeof parsed === "string") return parsed;
    matchers.push(parsed);
  }
  if (!matchers.length) return "request has no matchers";
  return {
    method: method as "GET" | "POST",
    paths,
    headers,
    body,
    condition: condition as "and" | "or",
    matchers,
  };
}

export function parseNuclei(texts: string[]): { templates: Template[]; errors: string[] } {
  const templates: Template[] = [];
  const errors: string[] = [];
  for (const text of texts) {
    let docs: unknown[];
    try {
      docs = loadAll(text);
    } catch (error) {
      errors.push(`YAML parse failed: ${error instanceof Error ? error.message : "invalid YAML"}`);
      continue;
    }
    for (const doc of docs) {
      if (!doc || typeof doc !== "object") continue;
      const raw = doc as Record<string, unknown>;
      if (templates.length >= MAX_TEMPLATES) {
        errors.push(`template limit ${MAX_TEMPLATES} reached`);
        break;
      }
      for (const protocol of ["code", "javascript", "headless", "network", "dns", "file"]) {
        if (raw[protocol]) {
          errors.push(`${String(raw["id"] ?? "template")}: ${protocol} protocol is not supported`);
          break;
        }
      }
      if (raw["code"] || raw["javascript"] || raw["headless"] || raw["network"] || raw["dns"] || raw["file"]) continue;
      if (raw["payloads"] || raw["attack"]) {
        errors.push(`${String(raw["id"] ?? "template")}: payload/attack templates are not supported`);
        continue;
      }
      const id = typeof raw["id"] === "string" ? raw["id"].trim() : "";
      const info = raw["info"] && typeof raw["info"] === "object" ? (raw["info"] as Record<string, unknown>) : {};
      if (!id) {
        errors.push("template has no id");
        continue;
      }
      const requestsRaw = Array.isArray(raw["http"])
        ? raw["http"]
        : Array.isArray(raw["requests"])
          ? raw["requests"]
          : [];
      if (!requestsRaw.length) {
        errors.push(`${id}: no http/requests section`);
        continue;
      }
      const requests: TemplateRequest[] = [];
      for (const item of requestsRaw.slice(0, MAX_REQUESTS)) {
        const parsed = parseRequest(item);
        if (typeof parsed === "string") errors.push(`${id}: ${parsed}`);
        else requests.push(parsed);
      }
      if (!requests.length) continue;
      const severity = String(info["severity"] ?? "unknown").toLowerCase();
      templates.push({
        id,
        name: typeof info["name"] === "string" && info["name"] ? info["name"] : id,
        severity: severities.has(severity) ? severity : "unknown",
        description: typeof info["description"] === "string" ? info["description"] : "",
        requests,
      });
    }
  }
  return { templates, errors };
}

function resolvePath(path: string, base: URL, nonce: string): string | undefined {
  let value = path;
  const replacements: Record<string, string> = {
    BaseURL: base.origin,
    RootURL: base.origin,
    Hostname: base.host,
    Host: base.hostname,
    Port: base.port || (base.protocol === "https:" ? "443" : "80"),
    Scheme: base.protocol.replace(":", ""),
    randstr: nonce,
    rand_int: String(Math.floor(Math.random() * 1000000)),
  };
  for (const [name, replacement] of Object.entries(replacements))
    value = value.replaceAll(`{{${name}}}`, replacement);
  if (/\{\{[^}]+\}\}/.test(value)) return undefined;
  if (/^https?:\/\//i.test(value)) {
    try {
      const absolute = new URL(value);
      return absolute.origin === base.origin ? absolute.href : undefined;
    } catch {
      return undefined;
    }
  }
  return base.origin + (value.startsWith("/") ? value : `/${value}`);
}

function matches(exchange: Exchange, matcher: Matcher): boolean {
  const body = text(exchange).slice(0, 256000);
  const headers = Object.entries(exchange.response?.responseHeaders ?? {})
    .map(([name, value]) => `${name}: ${value}`)
    .join("\n")
    .slice(0, 256000);
  const source = matcher.part === "body" ? body : matcher.part === "header" ? headers : `${body}\n${headers}`;
  let resultValue = false;
  if (matcher.type === "status") resultValue = matcher.status.includes(exchange.response!.status);
  if (matcher.type === "size") resultValue = matcher.size.includes(body.length);
  if (matcher.type === "word")
    resultValue =
      matcher.condition === "and"
        ? matcher.words.every((word) => source.includes(word))
        : matcher.words.some((word) => source.includes(word));
  if (matcher.type === "regex")
    resultValue =
      matcher.condition === "and"
        ? matcher.regex.every((pattern) => new RegExp(pattern).test(source))
        : matcher.regex.some((pattern) => new RegExp(pattern).test(source));
  return matcher.negative ? !resultValue : resultValue;
}

export const nucleiTemplate: ScanCheck = {
  id: "nuclei-template",
  name: "Nuclei templates (bounded native subset)",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.nucleiTemplates?.length)
      return result("Paste or import at least one Nuclei template YAML document.", true);
    const { templates, errors } = parseNuclei(ctx.nucleiTemplates);
    const findings: ReturnType<typeof observation>["findings"] = [];
    const skipped = [...errors];
    let executed = 0;
    for (const template of templates) {
      const evidence: Exchange[] = [];
      let matched = false;
      for (const request of template.requests) {
        if (matched) break;
        for (const path of request.paths) {
          const base = new URL(ctx.request.url);
          const url = resolvePath(path, base, ctx.nonce().replace(/[^a-zA-Z0-9]/g, ""));
          if (!url) {
            skipped.push(`${template.id}: unsupported variable or cross-origin path`);
            continue;
          }
          const headers = {
            ...ctx.request.headers,
            ...request.headers,
          };
          for (const name of ["host", "content-length", "transfer-encoding"])
            delete headers[name];
          const probe = await ctx.probe(
            {
              method: request.method,
              url,
              headers,
              body: request.method === "GET" ? "" : request.body,
            },
            `Nuclei ${template.id}`,
          );
          executed++;
          evidence.push(probe);
          if (!ok(probe)) {
            skipped.push(`${template.id}: request failed`);
            break;
          }
          const all = request.matchers.map((matcher) => matches(probe, matcher));
          const hit =
            request.condition === "and" ? all.every(Boolean) : all.some(Boolean);
          if (hit) {
            matched = true;
            const output = observation(
              `[Nuclei] ${template.name}`,
              `Template ${template.id} matched. ${template.description.slice(0, 800)} Native subset executed ${request.method} ${url}; matchers and variables outside the supported subset were rejected before sending. A template match is a detection, not proof of exploitability.`,
              [ctx.baselines[0]!, ...evidence],
              [
                `Template: ${template.id}`,
                `Severity: ${template.severity}`,
                `Matched: ${request.condition.toUpperCase()} of ${request.matchers.length} matcher(s)`,
              ],
              template.severity === "critical"
                ? "high"
                : template.severity === "unknown"
                  ? "info"
                  : (template.severity as "info" | "low" | "medium" | "high"),
            );
            findings.push(output.findings[0]!);
            break;
          }
        }
      }
    }
    return {
      findings,
      message: `${templates.length} template(s) parsed, ${executed} request(s) sent.${skipped.length ? ` Skipped: ${skipped.slice(0, 5).join("; ")}` : ""}`,
      inconclusive: templates.length === 0,
    };
  },
};

export const nucleiChecks = [nucleiTemplate];
