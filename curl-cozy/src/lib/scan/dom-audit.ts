import { parse as parseJs, type Node as JsNode } from "acorn";
import { parse as parseHtml, type DefaultTreeAdapterMap } from "parse5";
import { flowId } from "../flows";
import type { BrowserResource, Exchange, ScanCheckContext } from "./types";
import { h } from "./extended-checks";

export type DomContext = "html" | "script" | "url";
export interface DomSource {
  kind: "fragment" | "query" | "url" | "input" | "unsupported";
  name?: string;
  label: string;
  decoded: boolean;
  base64: boolean;
  params?: boolean;
}
export interface DomCandidate {
  id: string;
  source: DomSource;
  sink: string;
  context: DomContext;
  script: string;
  line: number;
  column: number;
  excerpt: string;
  families: string[];
}
export interface DomScriptAudit {
  url: string;
  evidenceId: string;
  sources: string[];
  sinks: string[];
  parsed: boolean;
}
export interface DomAudit {
  runtimeScripts?: string[];
  id: string;
  url: string;
  scripts: DomScriptAudit[];
  candidates: DomCandidate[];
  notes: string[];
}
export interface PreparedDomAudit {
  report: DomAudit;
  resources: BrowserResource[];
  evidence: Exchange[];
}
type HtmlNode = DefaultTreeAdapterMap["node"];
type Ast = JsNode & {
  name?: unknown;
  value?: unknown;
  expression?: unknown;
  computed?: unknown;
  property?: unknown;
  object?: unknown;
  callee?: unknown;
  arguments?: unknown[];
  left?: unknown;
  right?: unknown;
  id?: unknown;
  params?: unknown[];
  init?: unknown;
  source?: unknown;
};
interface Unit {
  url: string;
  evidenceId: string;
  code: string;
  line: number;
  base?: string;
  ast?: Ast;
}
const bytes = (s: string) => new TextEncoder().encode(s).length;
function attr(node: HtmlNode, name: string) {
  return "attrs" in node ? node.attrs.find((a) => a.name === name)?.value : undefined;
}
const children = (node: HtmlNode): HtmlNode[] => ("childNodes" in node ? node.childNodes : []);
function jsType(type: string | undefined) {
  return (
    !type ||
    [
      "module",
      "text/javascript",
      "application/javascript",
      "application/ecmascript",
      "text/ecmascript",
    ].includes(type.split(";")[0]!.toLowerCase().trim())
  );
}
function absolute(value: string, base: string) {
  try {
    const url = new URL(value, base);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.href.length > 4096
    )
      return null;
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}
function astNode(value: unknown): value is Ast {
  return (
    !!value &&
    typeof value === "object" &&
    "type" in value &&
    typeof value.type === "string" &&
    "start" in value
  );
}
function nodes(root: Ast) {
  const result: Ast[] = [],
    pending = [root];
  while (pending.length && result.length < 50000) {
    const node = pending.pop()!;
    result.push(node);
    for (const value of Object.values(node)) {
      if (astNode(value)) pending.push(value);
      else if (Array.isArray(value))
        for (const item of value) if (astNode(item)) pending.push(item);
    }
  }
  return { values: result.sort((a, b) => a.start - b.start), limited: pending.length > 0 };
}
const literal = (value: unknown): string | undefined =>
  astNode(value) && value.type === "Literal" && typeof value.value === "string"
    ? value.value
    : undefined;
function member(node: unknown, depth = 0): string {
  if (!astNode(node) || depth > 20) return "";
  if (node.type === "Identifier") return String(node.name);
  if (node.type === "ChainExpression") return member(node.expression, depth + 1);
  if (node.type !== "MemberExpression") return "";
  const property = node.computed
    ? literal(node.property)
    : astNode(node.property)
      ? String(node.property.name)
      : "";
  return property ? `${member(node.object, depth + 1)}.${property}` : "";
}
const unique = (sources: DomSource[]) =>
  [...new Map(sources.map((s) => [JSON.stringify(s), s])).values()].slice(0, 16);
function sourceFor(path: string): DomSource | undefined {
  const canonical = path.replace(/^(?:window|globalThis|self)\./, "");
  if (["location", "document.location"].includes(canonical))
    return { kind: "url", label: path, decoded: false, base64: false };
  if (/^(?:document\.)?location\.(?:hash|search|href)$/.test(canonical)) {
    const kind = canonical.endsWith("hash")
      ? "fragment"
      : canonical.endsWith("search")
        ? "query"
        : "url";
    return { kind, label: path, decoded: false, base64: false };
  }
  if (["document.URL", "document.documentURI", "document.baseURI"].includes(canonical))
    return { kind: "url", label: path, decoded: false, base64: false };
  if (
    ["document.referrer", "document.cookie", "name", "localStorage", "sessionStorage"].includes(
      canonical,
    )
  )
    return { kind: "unsupported", label: path, decoded: false, base64: false };
  return undefined;
}
function infer(root: unknown, bindings: Map<string, DomSource[]>, depth = 0): DomSource[] {
  if (!astNode(root) || depth > 18) return [];
  const path = member(root),
    direct = sourceFor(path);
  if (direct) return [direct];
  if (root.type === "Identifier") return bindings.get(String(root.name)) ?? [];
  if (root.type === "Literal" || root.type.endsWith("FunctionExpression")) return [];
  const read = (value: unknown) => infer(value, bindings, depth + 1);
  if (root.type === "MemberExpression") {
    const sources = read(root.object);
    if (
      path.endsWith(".searchParams") ||
      (!root.computed && astNode(root.property) && root.property.name === "searchParams")
    )
      return sources.map((s) => ({ ...s, kind: "query", params: true, decoded: true }));
    return sources;
  }
  if (["CallExpression", "NewExpression"].includes(root.type)) {
    const callee = member(root.callee),
      args = Array.isArray(root.arguments) ? root.arguments : [];
    if (["document.getElementById", "document.querySelector"].includes(callee)) {
      const value = literal(args[0]);
      if (value && value.length <= 120 && !/[\x00-\x1f]/.test(value)) {
        const selector = callee.endsWith("getElementById")
          ? `[id=${JSON.stringify(value)}]`
          : value;
        return [
          {
            kind: "input",
            name: selector,
            label: `Input ${selector}`,
            decoded: true,
            base64: false,
          },
        ];
      }
    }
    const argumentSources = unique(args.flatMap(read));
    const receiver =
      astNode(root.callee) && root.callee.type === "MemberExpression"
        ? read(root.callee.object)
        : [];
    const method =
      callee.split(".").at(-1) ||
      (astNode(root.callee) && astNode(root.callee.property)
        ? String(root.callee.property.name)
        : "");
    if (callee === "URLSearchParams")
      return argumentSources.map((s) => ({ ...s, kind: "query", params: true, decoded: true }));
    if (method === "get" && receiver.some((s) => s.params)) {
      const name = literal(args[0]);
      return name === undefined || name.length > 200
        ? []
        : receiver.map((s) => ({
            ...s,
            kind: "query",
            name,
            params: false,
            decoded: true,
            label: `URLSearchParams.get(${JSON.stringify(name)})`,
          }));
    }
    if (["decodeURIComponent", "decodeURI", "unescape"].includes(callee))
      return argumentSources.map((s) => ({ ...s, decoded: true }));
    if (callee === "atob") return argumentSources.map((s) => ({ ...s, base64: true }));
    if (method === "split" && literal(args[0]) === "#")
      return receiver.map((s) => ({ ...s, kind: "fragment" }));
    return unique([...receiver, ...argumentSources]);
  }
  return unique(
    Object.entries(root)
      .filter(([key]) => !["loc", "range", "start", "end"].includes(key))
      .flatMap(([, value]) => (Array.isArray(value) ? value.flatMap(read) : read(value))),
  );
}
function sink(node: Ast): { name: string; context: DomContext; value: unknown } | undefined {
  if (node.type === "AssignmentExpression" && astNode(node.left)) {
    const path = member(node.left),
      property = path.split(".").at(-1);
    if (["innerHTML", "outerHTML", "srcdoc"].includes(property ?? ""))
      return { name: property!, context: "html", value: node.right };
    if (
      [
        "location",
        "window.location",
        "document.location",
        "location.href",
        "window.location.href",
        "document.location.href",
      ].includes(path)
    )
      return { name: path, context: "url", value: node.right };
    if (property === "href") return { name: path, context: "url", value: node.right };
  }
  if (!["CallExpression", "NewExpression"].includes(node.type)) return undefined;
  const path = member(node.callee),
    property = path.split(".").at(-1),
    args = Array.isArray(node.arguments) ? node.arguments : [];
  if (["document.write", "document.writeln"].includes(path))
    return { name: path, context: "html", value: args[0] };
  if (property === "insertAdjacentHTML") return { name: property, context: "html", value: args[1] };
  if (
    [
      "html",
      "append",
      "prepend",
      "before",
      "after",
      "replaceWith",
      "createContextualFragment",
    ].includes(property ?? "")
  )
    return { name: property!, context: "html", value: args[0] };
  if (
    [
      "eval",
      "window.eval",
      "globalThis.eval",
      "Function",
      "window.Function",
      "setTimeout",
      "setInterval",
      "window.setTimeout",
      "window.setInterval",
    ].includes(path)
  )
    return {
      name: path,
      context: "script",
      value: path.endsWith("Function") ? args.at(-1) : args[0],
    };
  if (
    [
      "location.assign",
      "location.replace",
      "window.location.assign",
      "window.location.replace",
    ].includes(path)
  )
    return { name: path, context: "url", value: args[0] };
  if (property === "setAttribute") {
    const name = literal(args[0])?.toLowerCase();
    if (name?.startsWith("on"))
      return { name: `setAttribute(${name})`, context: "script", value: args[1] };
    if (["href", "src", "action"].includes(name ?? ""))
      return { name: `setAttribute(${name})`, context: "url", value: args[1] };
  }
  return undefined;
}
function parse(unit: Unit, notes: string[]) {
  try {
    unit.ast = parseJs(unit.code, {
      ecmaVersion: "latest",
      sourceType: "module",
      locations: true,
      allowReturnOutsideFunction: true,
    }) as Ast;
  } catch {
    try {
      unit.ast = parseJs(unit.code, {
        ecmaVersion: "latest",
        sourceType: "script",
        locations: true,
        allowReturnOutsideFunction: true,
      }) as Ast;
    } catch {
      notes.push(`Could not parse ${unit.url}; dynamic or unsupported syntax remains untested.`);
    }
  }
}
export async function auditDomScripts(
  ctx: ScanCheckContext,
  runtimeScripts: string[] = [],
): Promise<PreparedDomAudit> {
  const baseline = ctx.baselines[0]!;
  const report: DomAudit = {
    id: flowId(),
    url: ctx.request.url,
    scripts: [],
    candidates: [],
    notes: [],
  };
  const resources: BrowserResource[] = [],
    evidence = [baseline];
  const units: Unit[] = [],
    queue: string[] = [],
    seen = new Set<string>();
  const tree = parseHtml(baseline.response!.responseBody, { sourceCodeLocationInfo: true });
  const all: HtmlNode[] = [],
    pending: HtmlNode[] = [tree];
  while (pending.length && all.length < 20000) {
    const n = pending.pop()!;
    all.push(n);
    pending.push(...children(n).slice().reverse());
  }
  if (pending.length) report.notes.push("HTML node limit reached.");
  const baseHref = all.find(
    (n) => "tagName" in n && n.tagName === "base" && attr(n, "href") !== undefined,
  );
  const base = baseHref
    ? (absolute(attr(baseHref, "href")!, ctx.request.url) ?? ctx.request.url)
    : ctx.request.url;
  let inline = 0;
  for (const node of all) {
    if (!("tagName" in node)) continue;
    if (
      node.tagName === "script" &&
      jsType(attr(node, "type")) &&
      attr(node, "nomodule") === undefined
    ) {
      const src = attr(node, "src");
      if (src !== undefined) {
        const url = absolute(src, base);
        if (url) queue.push(url);
        else report.notes.push("Unsupported script URL was not fetched.");
      } else {
        const code = children(node)
          .map((n) => ("value" in n ? n.value : ""))
          .join("");
        units.push({
          url: `${ctx.request.url}#inline-${++inline}`,
          evidenceId: baseline.evidence.id,
          code,
          base,
          line: node.sourceCodeLocation?.startLine ?? 1,
        });
      }
    }
    for (const a of node.attrs)
      if (
        a.name.startsWith("on") ||
        ((a.name === "href" || a.name === "action") && /^javascript:/i.test(a.value))
      ) {
        units.push({
          url: `${ctx.request.url}#${node.tagName.slice(0, 80)}[${a.name.slice(0, 80)}]-${++inline}`,
          evidenceId: baseline.evidence.id,
          code: a.value.replace(/^javascript:/i, ""),
          line: node.sourceCodeLocation?.startLine ?? 1,
        });
      }
  }
  if (units.length > 100) {
    units.length = 100;
    report.notes.push("Inline script limit reached.");
  }
  // These URLs were observed only while rendering the original, unmodified page.
  // They are still subject to the shared script loader's scope and budgets.
  for (const value of runtimeScripts.slice(0, 16)) {
    const url = absolute(value, ctx.request.url);
    if (url) queue.push(url);
  }
  let resourceBytes = 0;
  for (const unit of units) parse(unit, report.notes);
  const addImports = (unit: Unit) => {
    if (!unit.ast) return;
    for (const n of nodes(unit.ast).values) {
      const value = [
        "ImportDeclaration",
        "ExportNamedDeclaration",
        "ExportAllDeclaration",
        "ImportExpression",
      ].includes(n.type)
        ? literal(n.source)
        : undefined;
      if (value) {
        if (/^(?:\.\.?\/|\/|https?:\/\/)/.test(value)) {
          const url = absolute(value, unit.base ?? unit.url);
          if (url) queue.push(url);
        } else
          report.notes.push(
            `Bare module import is not statically resolved; runtime discovery may resolve it through an import map: ${value.slice(0, 100)}`,
          );
      }
    }
  };
  for (const unit of units) addImports(unit);
  while (queue.length && seen.size < 16 && resourceBytes < 1_000_000) {
    const url = queue.shift()!;
    if (seen.has(url)) continue;
    seen.add(url);
    if (!ctx.loadScript) {
      report.notes.push(`Script loader unavailable: ${url}`);
      continue;
    }
    let x: Exchange;
    try {
      x = await ctx.loadScript(url);
    } catch (error) {
      report.notes.push(
        `Script not fetched: ${url}: ${error instanceof Error ? error.message : "unavailable"}`,
      );
      continue;
    }
    evidence.push(x);
    const response = x.response;
    if (
      !response ||
      response.status < 200 ||
      response.status >= 300 ||
      /(?:text\/html|application\/json)/i.test(h(x, "content-type"))
    ) {
      report.notes.push(`Script response was unavailable or not JavaScript: ${url}`);
      continue;
    }
    const size = bytes(response.responseBody);
    const charset = /;\s*charset\s*=\s*["']?([^;"'\s]+)/i
      .exec(h(x, "content-type"))?.[1]
      ?.toLowerCase();
    if (charset && !["utf-8", "utf8", "us-ascii"].includes(charset)) {
      report.notes.push(`Unsupported script charset: ${url}`);
      continue;
    }
    if (size > 256000 || resourceBytes + size > 1_000_000) {
      report.notes.push(`Script byte limit reached: ${url}`);
      continue;
    }
    resourceBytes += size;
    const unit: Unit = { url, evidenceId: x.evidence.id, code: response.responseBody, line: 1 };
    parse(unit, report.notes);
    units.push(unit);
    addImports(unit);
    resources.push({ url, body: response.responseBody, headers: response.responseHeaders });
  }
  if (queue.length)
    report.notes.push(
      "External script count/byte limit reached; remaining scripts were not fetched.",
    );
  const bindings = new Map<string, DomSource[]>(),
    functions = new Map<string, Ast>();
  const groups = units.map((unit) => ({
    unit,
    walk: unit.ast ? nodes(unit.ast) : { values: [], limited: false },
  }));
  for (const { walk } of groups)
    for (const n of walk.values) {
      if (n.type === "FunctionDeclaration" && astNode(n.id)) functions.set(String(n.id.name), n);
      if (
        n.type === "VariableDeclarator" &&
        astNode(n.id) &&
        astNode(n.init) &&
        ["FunctionExpression", "ArrowFunctionExpression"].includes(n.init.type)
      )
        functions.set(String(n.id.name), n.init);
    }
  for (let pass = 0; pass < 5; pass++)
    for (const { walk } of groups)
      for (const n of walk.values) {
        const target =
          n.type === "VariableDeclarator"
            ? n.id
            : n.type === "AssignmentExpression"
              ? n.left
              : undefined;
        const value = n.type === "VariableDeclarator" ? n.init : n.right;
        if (astNode(target) && target.type === "Identifier") {
          const name = String(target.name),
            sources = infer(value, bindings);
          if (sources.length)
            bindings.set(name, unique([...(bindings.get(name) ?? []), ...sources]));
        }
        if (n.type === "CallExpression") {
          const f = functions.get(member(n.callee));
          if (f && Array.isArray(f.params) && Array.isArray(n.arguments))
            f.params.forEach((param, index) => {
              if (astNode(param) && param.type === "Identifier") {
                const name = String(param.name);
                const sources = infer((n.arguments as unknown[])[index], bindings);
                if (sources.length)
                  bindings.set(name, unique([...(bindings.get(name) ?? []), ...sources]));
              }
            });
        }
      }
  for (const { unit, walk } of groups) {
    const sources: string[] = [],
      sinks: string[] = [];
    if (walk.limited) report.notes.push(`AST node limit reached: ${unit.url}`);
    for (const node of walk.values) {
      const direct = sourceFor(member(node));
      if (direct) sources.push(direct.label);
      const target = sink(node);
      if (!target) continue;
      sinks.push(target.name);
      for (const source of infer(target.value, bindings)) {
        if (source.params) continue;
        const candidate: DomCandidate = {
          id: flowId(),
          source,
          sink: target.name.slice(0, 1000),
          context: target.context,
          script: unit.url,
          line: unit.line + (node.loc?.start.line ?? 1) - 1,
          column: (node.loc?.start.column ?? 0) + 1,
          excerpt: unit.code
            .slice(Math.max(0, node.start - 80), Math.min(unit.code.length, node.end + 80))
            .slice(0, 800),
          families:
            target.context === "html"
              ? ["html-element", "double-quoted-attribute", "single-quoted-attribute"]
              : target.context === "script"
                ? ["javascript-expression", "single-quoted-javascript", "double-quoted-javascript"]
                : ["javascript-url"],
        };
        if (
          report.candidates.length < 40 &&
          !report.candidates.some(
            (c) =>
              c.script === candidate.script &&
              c.line === candidate.line &&
              c.sink === candidate.sink &&
              JSON.stringify(c.source) === JSON.stringify(candidate.source),
          )
        )
          report.candidates.push(candidate);
      }
    }
    report.scripts.push({
      url: unit.url,
      evidenceId: unit.evidenceId,
      sources: [...new Set(sources)].slice(0, 30).map((s) => s.slice(0, 1000)),
      sinks: [...new Set(sinks)].slice(0, 30).map((s) => s.slice(0, 1000)),
      parsed: !!unit.ast,
    });
  }
  report.notes = [...new Set(report.notes)].map((s) => s.slice(0, 1000)).slice(0, 40);
  return { report, resources, evidence };
}
