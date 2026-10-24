import { parse, type DefaultTreeAdapterMap } from "parse5";
import type { HttpRequest } from "../traffic";
import type { Exchange } from "./types";

export interface CrawlOptions {
  maxUrls: number;
  maxDepth: number;
}
export interface CrawlPage {
  request: HttpRequest;
  exchange: Exchange;
}
export function crawlUrl(raw: string, base: string, seed: string): string | undefined {
  try {
    const url = new URL(raw, base),
      origin = new URL(seed);
    if (
      !/^https?:$/.test(url.protocol) ||
      url.origin !== origin.origin ||
      url.username ||
      url.password ||
      url.href.length > 4096 ||
      /\$\{|[{}<>]/.test(raw)
    )
      return;
    url.hash = "";
    if (
      /\.(?:png|jpe?g|gif|svg|ico|woff2?|ttf|mp4|mp3|pdf|zip|gz|css)$/i.test(url.pathname) ||
      /(?:^|\/)(?:logout|signout|delete|remove|destroy)(?:\/|$)/i.test(url.pathname)
    )
      return;
    return url.href;
  } catch {
    return;
  }
}
export function crawlLinks(body: string, contentType: string, base: string): string[] {
  if (body.length > 256000) body = body.slice(0, 256000);
  const links: string[] = [];
  let scriptSource = body,
    scriptBase = base;
  if (/html/i.test(contentType)) {
    type Node = DefaultTreeAdapterMap["node"];
    type Element = DefaultTreeAdapterMap["element"];
    const nodes: Element[] = [];
    let visited = 0;
    const walk = (node: Node, depth = 0) => {
      if (++visited > 10000 || depth > 100) return;
      if ("tagName" in node) nodes.push(node);
      if ("childNodes" in node) for (const child of node.childNodes) walk(child, depth + 1);
    };
    const doc = parse(body);
    walk(doc);
    const attr = (el: Element, name: string) => el.attrs.find((a) => a.name === name)?.value;
    const documentBase = nodes.find((el) => el.tagName === "base" && attr(el, "href"));
    let resolvedBase = base;
    try {
      if (documentBase) resolvedBase = new URL(attr(documentBase, "href")!, base).href;
    } catch {
      /* invalid base */
    }
    scriptBase = resolvedBase;
    scriptSource = nodes
      .filter((el) => el.tagName === "script" && !attr(el, "src"))
      .flatMap((el) =>
        el.childNodes
          .filter((n) => n.nodeName === "#text")
          .map((n) => ("value" in n ? n.value : "")),
      )
      .join("\n");
    for (const el of nodes) {
      const raw = ["a", "area"].includes(el.tagName)
        ? attr(el, "href")
        : ["iframe", "script"].includes(el.tagName)
          ? attr(el, "src")
          : undefined;
      if (raw) {
        try {
          links.push(new URL(raw, resolvedBase).href);
        } catch {
          /* invalid link */
        }
      }
      if (links.length >= 500) break;
    }
    for (const form of nodes.filter((el) => el.tagName === "form").slice(0, 100)) {
      if ((attr(form, "method") ?? "get").toLowerCase() !== "get") continue;
      try {
        const url = new URL(attr(form, "action") || base, resolvedBase);
        url.search = "";
        for (const input of nodes.filter((el) => el.tagName === "input").slice(0, 200)) {
          let parent: Node | undefined = input.parentNode ?? undefined;
          while (parent && parent !== form)
            parent = "parentNode" in parent ? (parent.parentNode ?? undefined) : undefined;
          if (parent !== form || !attr(input, "name")) continue;
          const type = (attr(input, "type") ?? "text").toLowerCase();
          if (
            ["password", "file", "submit", "button", "reset"].includes(type) ||
            attr(input, "disabled") !== undefined
          )
            continue;
          if (["checkbox", "radio"].includes(type) && attr(input, "checked") === undefined)
            continue;
          url.searchParams.append(attr(input, "name")!, attr(input, "value") ?? "");
        }
        links.push(url.href);
      } catch {
        /* invalid action */
      }
      if (links.length >= 500) break;
    }
  }
  if (/(?:javascript|ecmascript|html)/i.test(contentType)) {
    for (const match of scriptSource.matchAll(
      /["'`]((?:https?:\/\/|\/|\.\.\/|\.\/)[^\s"'`<>\\]{1,2048})["'`]/g,
    )) {
      try {
        links.push(new URL(match[1]!, scriptBase).href);
      } catch {
        /* invalid literal */
      }
      if (links.length >= 500) break;
    }
  }
  return links.slice(0, 500);
}
/** Bounded sequential GET discovery. Never executes scripts or submits write forms. */
export async function crawl(
  seed: HttpRequest,
  options: CrawlOptions,
  send: (request: HttpRequest, label: string) => Promise<Exchange>,
  allowed: (url: string) => boolean,
  progress: (fetched: number, queued: number, urls: string[]) => void,
): Promise<CrawlPage[]> {
  const first = crawlUrl(seed.url, seed.url, seed.url);
  if (!first || !allowed(first))
    throw Error("Crawl seed is outside Target Scope or is not a crawlable URL.");
  const queue = [{ url: first, depth: 0 }],
    seen = new Set([first]),
    shapes = new Set<string>();
  const pages: CrawlPage[] = [];
  const headers = Object.fromEntries(
    Object.entries(seed.headers).filter(
      ([key]) =>
        !/^(?:host|content-.*|if-.*|range|origin|referer|x-http-method-override|x-method-override|x-http-method|x-original-url|x-rewrite-url)$/i.test(
          key,
        ),
    ),
  );
  const enqueue = (raw: string, base: string, depth: number) => {
    const url = crawlUrl(raw, base, seed.url);
    if (
      !url ||
      !allowed(url) ||
      seen.has(url) ||
      queue.length >= options.maxUrls ||
      depth > options.maxDepth
    )
      return;
    const parsed = new URL(url);
    const shape =
      parsed.origin + parsed.pathname + "?" + [...parsed.searchParams.keys()].sort().join("&");
    if (shapes.has(shape)) return;
    shapes.add(shape);
    seen.add(url);
    queue.push({ url, depth });
  };
  const seedUrl = new URL(first);
  shapes.add(
    seedUrl.origin + seedUrl.pathname + "?" + [...seedUrl.searchParams.keys()].sort().join("&"),
  );
  for (let i = 0; i < queue.length; i++) {
    const item = queue[i]!;
    if (!allowed(item.url)) continue;
    const request = { method: "GET", url: item.url, headers: { ...headers }, body: "" };
    const exchange = await send(request, `Crawl GET ${i + 1}`);
    pages.push({ request, exchange });
    const response = exchange.response;
    if (response && !exchange.evidence.error) {
      const header = (name: string) =>
        Object.entries(response.responseHeaders).find(([k]) => k.toLowerCase() === name)?.[1] ?? "";
      if (response.status >= 300 && response.status < 400)
        enqueue(header("location"), item.url, item.depth + 1);
      if (response.status >= 200 && response.status < 300)
        for (const raw of crawlLinks(response.responseBody, header("content-type"), item.url))
          enqueue(raw, item.url, item.depth + 1);
    }
    progress(
      pages.length,
      queue.length,
      pages.map((p) => p.request.url),
    );
  }
  return pages;
}
