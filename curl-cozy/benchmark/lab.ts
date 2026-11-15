/* eslint-disable @typescript-eslint/no-unused-expressions -- compact `condition ? reply : reply;` handlers */
/**
 * A local lab of endpoints with known behaviour. Each case is labelled vulnerable, safe or noise, so
 * a scan can be scored: findings on vulnerable cases are detections, findings on safe/noise cases are
 * false positives. Everything binds to 127.0.0.1.
 */
import http from "node:http";
import { randomBytes } from "node:crypto";
import {
  evalMiniPhp,
  evalMiniPython,
  PASSWD,
  SqlSyntaxError,
  evalMiniJs,
  phpInclude,
  readJwt,
  readVirtualFile,
  renderTemplate,
  runCommandLine,
  signJwt,
  sqlWhere,
} from "./emulators";

type Req = {
  method: string;
  rawPath: string;
  path: string;
  query: URLSearchParams;
  headers: http.IncomingHttpHeaders;
  body: string;
};
type Res = http.ServerResponse;
type Handler = (req: Req, res: Res) => Promise<void> | void;

const STRONG = randomBytes(32).toString("hex");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const send = (
  res: Res,
  status: number,
  body: string,
  type = "text/html; charset=utf-8",
  headers: Record<string, string | string[]> = {},
) => {
  res.writeHead(status, { "content-type": type, ...headers });
  res.end(body);
};
const json = (
  res: Res,
  status: number,
  value: unknown,
  headers: Record<string, string | string[]> = {},
) => send(res, status, JSON.stringify(value), "application/json", headers);
const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const page = (body: string) =>
  `<!doctype html><html><head><title>Lab</title></head><body>${body}</body></html>`;
const parseJson = (body: string): Record<string, unknown> | undefined => {
  try {
    const v = JSON.parse(body);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
};

/** The value of an input wherever the request carries it: query string, form body or JSON body. */
function param(req: Req, name: string): string | null {
  const fromQuery = req.query.get(name);
  if (fromQuery !== null) return fromQuery;
  const type = String(req.headers["content-type"] ?? "");
  if (type.includes("application/x-www-form-urlencoded"))
    return new URLSearchParams(req.body).get(name);
  if (type.includes("json")) {
    const value = parseJson(req.body)?.[name];
    return value === undefined || value === null ? null : String(value);
  }
  return null;
}

const routes = new Map<string, Handler>();
const route = (path: string, handler: Handler) => routes.set(path, handler);

// ── SQL injection ──────────────────────────────────────────────────────────────────────
route("/v/sqli/error", (req, res) => {
  try {
    json(res, 200, { results: sqlWhere(`id = ${param(req, "id") ?? ""}`).rows });
  } catch (error) {
    if (error instanceof SqlSyntaxError)
      return send(res, 500, `<h1>Database error</h1><pre>${escapeHtml(error.message)}</pre>`);
    throw error;
  }
});
const blind =
  (clause: (v: string) => string, read: (req: Req) => string) => async (req: Req, res: Res) => {
    try {
      const result = sqlWhere(clause(read(req)));
      if (result.delayMs) await sleep(result.delayMs);
      json(res, 200, { results: result.rows });
    } catch {
      json(res, 200, { results: [] });
    }
  };
route(
  "/v/sqli/boolean",
  blind(
    (v) => `id = ${v}`,
    (r) => param(r, "id") ?? "",
  ),
);
route(
  "/v/sqli/boolean-str",
  blind(
    (v) => `name = '${v}'`,
    (r) => param(r, "name") ?? "",
  ),
);
route(
  "/v/sqli/boolean-json",
  blind(
    (v) => `id = ${v}`,
    (r) => param(r, "id") ?? "",
  ),
);
route(
  "/v/sqli/time",
  blind(
    (v) => `id = ${v}`,
    (r) => param(r, "id") ?? "",
  ),
);
route(
  "/v/sqli/time-str",
  blind(
    (v) => `name = '${v}'`,
    (r) => param(r, "name") ?? "",
  ),
);
route("/s/sqli/param", (req, res) => {
  const id = param(req, "id") ?? "";
  json(res, 200, { results: /^\d+$/.test(id) ? sqlWhere(`id = ${id}`).rows : [] });
});
route("/s/sqli/validate", (req, res) =>
  /^\d+$/.test(param(req, "id") ?? "")
    ? json(res, 200, { results: sqlWhere(`id = ${param(req, "id")}`).rows })
    : json(res, 400, { error: "invalid id" }),
);
route("/s/sqli/orm-error", (req, res) => {
  // Any odd input fails the same way, with no database details.
  const id = param(req, "id") ?? "";
  /^\d+$/.test(id)
    ? json(res, 200, { results: sqlWhere(`id = ${id}`).rows })
    : json(res, 500, { error: "Internal Server Error" });
});

// ── Noise ──────────────────────────────────────────────────────────────────────────────
route("/n/random", (_req, res) =>
  json(res, 200, {
    token: randomBytes(8).toString("hex"),
    ts: Date.now(),
    items: Array.from({ length: 1 + Math.floor(Math.random() * 3) }, () => Math.random()),
  }),
);
route("/n/slow", async (req, res) => {
  await sleep(Math.floor(Math.random() * 400));
  json(res, 200, { id: param(req, "id"), ok: true });
});
route("/n/docs-sql", (_req, res) =>
  send(
    res,
    200,
    page(
      "<h1>MySQL error reference</h1><p>If you see <code>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near</code> your query is malformed.</p><p>Example: <code>uid=0(root) gid=0(root) groups=0(root)</code> and <code>root:x:0:0:root:/root:/bin/bash</code>.</p>",
    ),
  ),
);
route("/n/page", (req, res) =>
  send(
    res,
    200,
    page(
      `<form><input type="hidden" name="csrf" value="${randomBytes(12).toString("hex")}"><p>Rendered at ${Date.now()}</p><p>Query: ${escapeHtml(param(req, "q") ?? "")}</p></form>`,
    ),
  ),
);

// ── Command injection ──────────────────────────────────────────────────────────────────
route("/v/cmd/ping", (req, res) =>
  send(res, 200, runCommandLine(`ping -c1 ${param(req, "host") ?? ""}`), "text/plain"),
);
route("/v/cmd/filtered", (req, res) => {
  const host = param(req, "host") ?? "";
  if (/[;|]|&&/.test(host)) return send(res, 400, "Invalid characters in host", "text/plain");
  send(res, 200, runCommandLine(`ping -c1 ${host}`), "text/plain");
});
// The filter looks for the word "id" and for nothing else.
route("/v/cmd/filtered-word", (req, res) => {
  const host = param(req, "host") ?? "";
  if (/\bid\b/i.test(host)) return send(res, 400, "Forbidden command", "text/plain");
  send(res, 200, runCommandLine(`ping -c1 ${host}`), "text/plain");
});
route("/s/cmd/ping", (req, res) => {
  const host = param(req, "host") ?? "";
  if (!/^[A-Za-z0-9.-]+$/.test(host)) return send(res, 400, "Invalid host", "text/plain");
  send(res, 200, runCommandLine(`ping -c1 ${host}`), "text/plain");
});

// ── Template and expression injection ──────────────────────────────────────────────────
for (const [name, delimiters] of [
  ["jinja", "jinja"],
  ["el", "el"],
  ["erb", "erb"],
] as const)
  route(`/v/ssti/${name}`, (req, res) =>
    send(res, 200, page(`<p>Hello ${renderTemplate(param(req, "name") ?? "", delimiters)}</p>`)),
  );
route("/s/ssti/literal", (req, res) =>
  send(res, 200, page(`<p>Hello ${escapeHtml(param(req, "name") ?? "")}</p>`)),
);
route("/v/code/eval", (req, res) => {
  try {
    json(res, 200, { result: evalMiniJs(param(req, "expr") ?? "") });
  } catch (error) {
    send(
      res,
      500,
      `<pre>${escapeHtml(String(error instanceof Error ? error.message : error))}\n    at eval (eval at calc (/srv/app.js:14:9))</pre>`,
    );
  }
});
route("/v/code/php", (req, res) => {
  try {
    send(res, 200, `<pre>${escapeHtml(evalMiniPhp(param(req, "expr") ?? ""))}</pre>`);
  } catch (error) {
    send(res, 500, `<b>${escapeHtml(String(error instanceof Error ? error.message : error))}</b>`);
  }
});
route("/v/code/py", (req, res) => {
  try {
    json(res, 200, { output: evalMiniPython(param(req, "expr") ?? "") });
  } catch (error) {
    json(res, 500, { error: String(error instanceof Error ? error.message : error) });
  }
});
route("/s/code/echo", (req, res) => json(res, 200, { received: param(req, "expr") ?? "" }));

// ── Files and redirects ────────────────────────────────────────────────────────────────
const fileHandler =
  (options: { decodeTwice?: boolean; stripDotDotOnce?: boolean } = {}) =>
  (req: Req, res: Res) => {
    const content = readVirtualFile("/var/www/files/", param(req, "name") ?? "", options);
    content === undefined
      ? send(res, 404, "file not found", "text/plain")
      : send(res, 200, content, "text/plain");
  };
route("/v/files", fileHandler());
route("/v/files/double", fileHandler({ decodeTwice: true }));
route("/v/files/filtered", fileHandler({ stripDotDotOnce: true }));
route("/v/lfi", (req, res) => {
  const content = phpInclude("/var/www/pages/", param(req, "page") ?? "");
  content === undefined
    ? send(res, 200, page("<p>Page not found</p>"))
    : send(res, 200, page(`<pre>${escapeHtml(content)}</pre>`));
});
route("/s/files", (req, res) => {
  const name = param(req, "name") ?? "";
  name === "readme.txt"
    ? send(res, 200, "public readme\n", "text/plain")
    : send(res, 404, "file not found", "text/plain");
});
route("/v/redirect", (req, res) =>
  send(res, 302, "", "text/plain", { location: param(req, "url") ?? "/" }),
);
route("/s/redirect", (req, res) => {
  const url = param(req, "url") ?? "/";
  /^\/(?![/\\])/.test(url)
    ? send(res, 302, "", "text/plain", { location: url })
    : send(res, 400, "Invalid redirect target", "text/plain");
});

// ── XML ────────────────────────────────────────────────────────────────────────────────
type XmlStyle = "plain" | "sax" | "dotnet" | "lxml" | "generic";
/** What an XML endpoint says when the document is malformed (what a parser error looks like differs by stack). */
function xmlFailure(style: XmlStyle, detail: string): { status: number; body: string } {
  switch (style) {
    case "sax":
      return {
        status: 500,
        body: `org.xml.sax.SAXParseException; lineNumber: 1; columnNumber: 20; ${detail}\n\tat com.sun.org.apache.xerces.internal.parsers.AbstractSAXParser.parse(AbstractSAXParser.java:1243)`,
      };
    case "dotnet":
      return {
        status: 500,
        body: `System.Xml.XmlException: ${detail} Line 1, position 12.\n   at System.Xml.XmlTextReaderImpl.Throw(Exception e)`,
      };
    case "lxml":
      return { status: 400, body: `lxml.etree.XMLSyntaxError: ${detail}, line 1, column 12` };
    case "generic":
      return { status: 400, body: JSON.stringify({ error: "Invalid request" }) };
    default:
      return { status: 400, body: `XML parsing error: ${detail}` };
  }
}
function parseXml(
  body: string,
  mode: "external" | "internal" | "none",
  style: XmlStyle = "plain",
): { status: number; body: string } {
  if (/<!DOCTYPE/i.test(body) && mode === "none")
    return style === "generic"
      ? { status: 403, body: JSON.stringify({ error: "Forbidden" }) }
      : { status: 403, body: "DOCTYPE is disallowed" };
  const entities = new Map<string, string>();
  for (const m of body.matchAll(/<!ENTITY\s+(\w+)\s+(?:SYSTEM\s+"([^"]+)"|"([^"]*)")\s*>/g)) {
    if (m[2]) {
      if (mode !== "external") continue;
      const file = m[2].replace(/^file:\/\//, "");
      entities.set(m[1]!, readVirtualFile("/", file) ?? "");
    } else entities.set(m[1]!, m[3] ?? "");
  }
  const stack: string[] = [];
  for (const m of body
    .replace(/<!DOCTYPE[\s\S]*?\]>/i, "")
    .matchAll(/<(\/?)([A-Za-z_][\w:-]*)[^>]*?(\/?)>/g)) {
    if (m[3]) continue;
    if (!m[1]) stack.push(m[2]!);
    else {
      const open = stack.pop();
      if (open !== m[2]) return xmlFailure(style, `mismatched tag ${open ?? "(none)"} / ${m[2]}`);
    }
  }
  if (stack.length) return xmlFailure(style, "unexpected end of document");
  let text = body
    .replace(/<!DOCTYPE[\s\S]*?\]>/i, "")
    .replace(/<[^>]*>/g, "")
    .trim();
  text = text.replace(/&(\w+);/g, (m, name: string) =>
    ["amp", "lt", "gt", "quot", "apos"].includes(name) ? m : (entities.get(name) ?? m),
  );
  return { status: 200, body: `<response><echo>${text}</echo></response>` };
}
const xmlRoute = (
  path: string,
  mode: "external" | "internal" | "none",
  style: XmlStyle,
  type = "application/xml",
  wrap?: (inner: string) => string,
) =>
  route(path, (req, res) => {
    const result = parseXml(
      path.endsWith("/param") ? (param(req, "payload") ?? "") : req.body,
      mode,
      style,
    );
    const ok = result.status === 200;
    send(
      res,
      result.status,
      ok && wrap ? wrap(result.body) : result.body,
      ok ? type : style === "generic" ? "application/json" : "text/plain",
    );
  });
const soap = (inner: string) =>
  `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>${inner}</soap:Body></soap:Envelope>`;
xmlRoute("/v/xml/xxe", "external", "plain");
xmlRoute("/v/xml/entities", "internal", "plain");
xmlRoute("/v/xml/param", "external", "plain");
xmlRoute("/v/xml/sax", "internal", "sax");
xmlRoute("/v/xml/dotnet", "internal", "dotnet", "text/xml", soap);
xmlRoute("/v/xml/lxml", "external", "lxml", "text/xml");
xmlRoute("/v/xml/soap", "external", "plain", "text/xml", soap);
xmlRoute("/s/xml/parse", "none", "generic");
xmlRoute("/s/xml/param", "none", "generic");

// ── CORS ───────────────────────────────────────────────────────────────────────────────
route("/v/cors/reflect", (req, res) =>
  json(
    res,
    200,
    { user: "alice" },
    req.headers.origin
      ? {
          "access-control-allow-origin": String(req.headers.origin),
          "access-control-allow-credentials": "true",
          vary: "Origin",
        }
      : {},
  ),
);
route("/v/cors/suffix", (req, res) => {
  const origin = String(req.headers.origin ?? "");
  // A sloppy "ends with our host" test; the cases reach this lab as `localhost`, because the check cannot derive host variants from an IP address.
  let host = "";
  try {
    host = new URL(origin).hostname;
  } catch {
    /* not a URL */
  }
  json(
    res,
    200,
    { user: "alice" },
    host.endsWith("localhost")
      ? {
          "access-control-allow-origin": origin,
          "access-control-allow-credentials": "true",
          vary: "Origin",
        }
      : {},
  );
});
route("/v/cors/null", (req, res) =>
  json(
    res,
    200,
    { user: "alice" },
    req.headers.origin === "null"
      ? {
          "access-control-allow-origin": "null",
          "access-control-allow-credentials": "true",
          vary: "Origin",
        }
      : {},
  ),
);
route("/v/cors/prefix", (req, res) => {
  const origin = String(req.headers.origin ?? "");
  json(
    res,
    200,
    { user: "alice" },
    origin.includes("localhost")
      ? {
          "access-control-allow-origin": origin,
          "access-control-allow-credentials": "true",
          vary: "Origin",
        }
      : {},
  );
});
route("/s/cors/strict", (req, res) =>
  json(
    res,
    200,
    { user: "alice" },
    req.headers.origin === "https://app.example.com"
      ? {
          "access-control-allow-origin": "https://app.example.com",
          "access-control-allow-credentials": "true",
          vary: "Origin",
        }
      : { vary: "Origin" },
  ),
);
route("/s/cors/none", (_req, res) => json(res, 200, { user: "alice" }));

// ── Access control ─────────────────────────────────────────────────────────────────────
// A front proxy applies the ACL to the URL it received, but the application routes on X-Original-URL.
const overrideHandler: Handler = (req, res) => {
  if (req.rawPath.startsWith("/v/acl/admin")) return send(res, 403, "Forbidden", "text/plain");
  const effective = String(
    req.headers["x-original-url"] ?? req.headers["x-rewrite-url"] ?? req.rawPath,
  );
  effective.startsWith("/v/acl/admin")
    ? json(res, 200, { panel: "admin", users: 3 })
    : send(res, 404, "Not found", "text/plain");
};
route("/", overrideHandler);
route("/v/acl/override", overrideHandler);
route("/v/acl/admin/panel", overrideHandler);
route("/v/acl/admin/users", overrideHandler);
route("/v/acl/internal", (req, res) => {
  const forwarded = [
    req.headers["x-real-ip"],
    req.headers["x-client-ip"],
    req.headers["x-forwarded-for"],
  ]
    .map(String)
    .join(",");
  forwarded.includes("127.0.0.1")
    ? json(res, 200, { internal: true, secrets: ["db-password"] })
    : send(res, 403, "Forbidden", "text/plain");
});
route("/v/acl/internal-xff", (req, res) =>
  String(req.headers["x-forwarded-for"] ?? "")
    .split(",")[0]
    ?.trim() === "127.0.0.1"
    ? json(res, 200, { internal: true })
    : send(res, 403, "Forbidden", "text/plain"),
);
route("/v/acl/download", (req, res) =>
  String(req.headers.referer ?? "").includes("127.0.0.1")
    ? json(res, 200, { file: "report.pdf" })
    : send(res, 403, "Forbidden", "text/plain"),
);
route("/s/acl/internal", (_req, res) => send(res, 403, "Forbidden", "text/plain"));
route("/s/acl/download", (_req, res) => send(res, 403, "Forbidden", "text/plain"));
route("/s/acl/admin", (_req, res) => send(res, 403, "Forbidden", "text/plain"));
route("/v/auth/account", (_req, res) =>
  json(res, 200, { account: "alice", email: "alice@example.com" }),
);
const VALID_TOKEN = "valid-token-1";
route("/s/auth/account", (req, res) =>
  req.headers.authorization === `Bearer ${VALID_TOKEN}`
    ? json(res, 200, { account: "alice", email: "alice@example.com" })
    : json(res, 401, { error: "unauthorized" }),
);

// ── JWT ────────────────────────────────────────────────────────────────────────────────
const bearer = (req: Req) => String(req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
const jwtRoute =
  (secret: string, options: { acceptNone?: boolean; verify?: boolean }) => (req: Req, res: Res) => {
    const claims = readJwt(bearer(req), secret, options);
    claims
      ? json(res, 200, { user: claims["sub"], plan: "pro" })
      : json(res, 401, { error: "invalid token" });
  };
route("/v/jwt/none", jwtRoute(STRONG, { acceptNone: true }));
route("/v/jwt/weak", jwtRoute("secret", {}));
route("/v/jwt/nosig", jwtRoute(STRONG, { verify: false }));
route("/v/jwt/stripped", (req, res) => {
  const token = bearer(req);
  const claims = token.endsWith(".")
    ? readJwt(token, STRONG, { verify: false })
    : readJwt(token, STRONG, {});
  claims
    ? json(res, 200, { user: claims["sub"], plan: "pro" })
    : json(res, 401, { error: "invalid token" });
});
route("/s/jwt/strict", jwtRoute(STRONG, {}));

// ── GraphQL ────────────────────────────────────────────────────────────────────────────
function topLevelFields(query: string): { alias?: string; name: string }[] {
  const open = query.indexOf("{");
  const close = query.lastIndexOf("}");
  if (open < 0 || close < open) return [];
  // Drop nested selections and argument lists, leaving the top-level `alias: name` items.
  let inner = query.slice(open + 1, close);
  for (let previous = ""; previous !== inner;) {
    previous = inner;
    inner = inner.replace(/\([^()]*\)|\{[^{}]*\}/g, "");
  }
  return [...inner.matchAll(/(?:(\w+)\s*:\s*)?\b(\w+)\b/g)].map((m) => ({
    ...(m[1] ? { alias: m[1] } : {}),
    name: m[2]!,
  }));
}
const graphql =
  (options: {
    introspection: boolean;
    suggestions: boolean;
    batching: boolean;
    maxAliases?: number;
  }) =>
  (req: Req, res: Res) => {
    const body = (() => {
      try {
        return JSON.parse(req.body) as unknown;
      } catch {
        return undefined;
      }
    })();
    const run = (op: unknown): Record<string, unknown> => {
      const query = String((op as { query?: unknown } | undefined)?.query ?? "");
      if (query.includes("__schema"))
        return options.introspection
          ? {
              data: {
                __schema: {
                  queryType: { name: "Query" },
                  mutationType: null,
                  subscriptionType: null,
                  types: [{ kind: "OBJECT", name: "Query", fields: [{ name: "user" }] }],
                },
              },
            }
          : { errors: [{ message: "GraphQL introspection is not allowed" }] };
      const data: Record<string, unknown> = {};
      const fields = topLevelFields(query);
      if (options.maxAliases !== undefined && fields.length > options.maxAliases)
        return {
          errors: [
            { message: `Query is too complex: at most ${options.maxAliases} fields per operation` },
          ],
        };
      for (const field of fields) {
        if (field.name === "__typename") data[field.alias ?? "__typename"] = "Query";
        else if (field.name === "user") data[field.alias ?? "user"] = { id: 1, name: "alice" };
        else
          return {
            errors: [
              {
                message: `Cannot query field "${field.name}" on type "Query".${options.suggestions ? ' Did you mean "user"?' : ""}`,
              },
            ],
          };
      }
      return { data };
    };
    if (Array.isArray(body))
      return options.batching
        ? json(res, 200, body.map(run))
        : json(res, 400, { errors: [{ message: "Batching is not supported" }] });
    json(res, 200, run(body));
  };
route("/v/graphql/open", graphql({ introspection: true, suggestions: true, batching: true }));
route("/v/graphql/suggest", graphql({ introspection: false, suggestions: true, batching: false }));
route(
  "/s/graphql/closed",
  graphql({ introspection: false, suggestions: false, batching: false, maxAliases: 10 }),
);

// ── Passive findings ───────────────────────────────────────────────────────────────────
route("/v/passive/bad", (_req, res) =>
  send(
    res,
    200,
    page("<h1>Home</h1><!-- TODO: remove debug password=admin123 -->"),
    "text/html; charset=utf-8",
    {
      "set-cookie": ["sid=abc123; Path=/", "prefs=dark; Path=/"],
      server: "Apache/2.4.1 (Ubuntu)",
      "x-powered-by": "PHP/7.0.1",
    },
  ),
);
route("/s/passive/good", (_req, res) =>
  send(res, 200, page("<h1>Home</h1>"), "text/html; charset=utf-8", {
    "set-cookie": ["sid=abc123; Path=/; HttpOnly; SameSite=Strict"],
    "content-security-policy":
      "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cache-control": "no-store",
  }),
);
route("/v/err/stack", (_req, res) =>
  send(
    res,
    200,
    page(
      "<b>Warning</b>: mysqli_connect(): (HY000/2002): Connection refused in <b>/var/www/html/db.php</b> on line <b>12</b><br><pre>java.lang.NullPointerException\n\tat com.example.UserService.load(UserService.java:42)\n\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)</pre>",
    ),
  ),
);
route("/s/err/generic", (_req, res) =>
  send(res, 200, page("<p>Something went wrong. Reference: 7f3a9c</p>")),
);
route("/v/reflect/html", (req, res) =>
  send(res, 200, page(`<p>Search results for: ${param(req, "q") ?? ""}</p>`)),
);
route("/s/reflect/escaped", (req, res) =>
  send(res, 200, page(`<p>Search results for: ${escapeHtml(param(req, "q") ?? "")}</p>`)),
);
route("/s/reflect/none", (_req, res) => send(res, 200, page("<p>No search</p>")));

// ── Methods ────────────────────────────────────────────────────────────────────────────
route("/v/methods/trace", (req, res) => {
  if (req.method === "TRACE")
    return send(
      res,
      200,
      `TRACE ${req.rawPath} HTTP/1.1\r\n${Object.entries(req.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join("\r\n")}\r\n`,
      "message/http",
    );
  if (req.method === "OPTIONS")
    return send(res, 204, "", "text/plain", { allow: "GET, POST, PUT, DELETE, TRACE, OPTIONS" });
  json(res, 200, { ok: true });
});
route("/s/methods/ok", (req, res) =>
  req.method === "GET"
    ? json(res, 200, { ok: true })
    : send(res, req.method === "OPTIONS" ? 204 : 405, "", "text/plain", { allow: "GET" }),
);

// ── Business logic, NoSQL, uploads ─────────────────────────────────────────────────────
route("/v/biz/cart", (req, res) => {
  const body = parseJson(req.body);
  // Typed (a string is rejected) but no range rules: negative and huge quantities are accepted.
  if (typeof body?.["quantity"] !== "number")
    return json(res, 400, { error: "quantity must be a number" });
  json(res, 200, {
    ok: true,
    quantity: body?.["quantity"],
    total: Number(body?.["quantity"]) * Number(body?.["price"] ?? 10),
  });
});
route("/s/biz/cart", (req, res) => {
  const quantity = Number(parseJson(req.body)?.["quantity"]);
  Number.isInteger(quantity) && quantity >= 1 && quantity <= 100
    ? json(res, 200, { ok: true, quantity, total: quantity * 10 })
    : json(res, 400, { error: "quantity must be an integer between 1 and 100" });
});
const NOSQL_USERS = ["alice", "admin", "bob", "carol"];
route("/v/nosql/users", (req, res) => {
  const name = parseJson(req.body)?.["name"];
  let results = NOSQL_USERS;
  if (typeof name === "string") results = NOSQL_USERS.filter((u) => u === name);
  else if (name && typeof name === "object") {
    const op = name as Record<string, unknown>;
    if (typeof op["$regex"] === "string") {
      try {
        const re = new RegExp(op["$regex"]);
        results = NOSQL_USERS.filter((u) => re.test(u));
      } catch {
        return json(res, 500, { error: "MongoServerError: $regex has to be a string" });
      }
    } else if ("$ne" in op) results = NOSQL_USERS.filter((u) => u !== op["$ne"]);
  }
  json(res, 200, { users: results });
});
route("/s/nosql/users", (req, res) => {
  const name = parseJson(req.body)?.["name"];
  typeof name === "string"
    ? json(res, 200, { users: NOSQL_USERS.filter((u) => u === name) })
    : json(res, 400, { error: "name must be a string" });
});
/** The bytes of the first file part of a multipart body (the part that has a filename). */
function filePartBytes(body: string): string {
  const match =
    /filename="[^"]*"[^\r\n]*(?:\r\n[^\r\n]+)*\r\n\r\n([\s\S]*?)(?:\r\n--[^\r\n]+)?$/.exec(body);
  return match?.[1] ?? "";
}
const uploadHandler = (strict: boolean) => (req: Req, res: Res) => {
  const filename = /filename="([^"]*)"/.exec(req.body)?.[1] ?? "";
  if (!strict) return json(res, 200, { stored: `uploads/${filename}` });
  const bytes = filePartBytes(req.body);
  const magic = bytes.startsWith("GIF8") || bytes.startsWith("\u0089PNG") || bytes.startsWith("ÿØ");
  /\.(jpe?g|png|gif)$/i.test(filename) && !/\.(php|phtml)/i.test(filename) && magic
    ? json(res, 200, { stored: `uploads/${randomBytes(6).toString("hex")}.bin` })
    : json(res, 400, { error: "unsupported file" });
};
route("/v/upload", uploadHandler(false));
// Trusts the Content-Type of the part and ignores the file name and the bytes.
route("/v/upload/content-type", (req, res) =>
  /Content-Type: image\/(jpeg|png|gif)/i.test(req.body)
    ? json(res, 200, { stored: `uploads/${/filename="([^"]*)"/.exec(req.body)?.[1] ?? ""}` })
    : json(res, 400, { error: "images only" }),
);
const uploadName = (body: string) => /filename="([^"]*)"/.exec(body)?.[1] ?? "";
const uploadBytes = filePartBytes;
// A blacklist of exactly ".php": ".phtml", ".php.jpg" and ".PhP" get through.
route("/v/upload/blacklist", (req, res) =>
  /\.php$/.test(uploadName(req.body))
    ? json(res, 400, { error: "php files are not allowed" })
    : json(res, 200, { stored: `uploads/${uploadName(req.body)}` }),
);
// Only looks at the first bytes, whatever the name is.
route("/v/upload/magic", (req, res) => {
  const bytes = uploadBytes(req.body);
  bytes.startsWith("GIF8") || bytes.startsWith("\u0089PNG") || bytes.startsWith("\u00ff\u00d8")
    ? json(res, 200, { stored: `uploads/${uploadName(req.body)}` })
    : json(res, 400, { error: "not an image" });
});
route("/s/upload", uploadHandler(true));

// ── Server ─────────────────────────────────────────────────────────────────────────────
export type Lab = { origin: string; close: () => Promise<void> };
export async function startLab(): Promise<Lab> {
  const server = http.createServer(async (incoming, res) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of incoming) chunks.push(chunk as Buffer);
      const rawPath = (incoming.url ?? "/").split("?")[0]!;
      let decoded = rawPath;
      try {
        decoded = decodeURIComponent(rawPath);
      } catch {
        /* use raw */
      }
      const req: Req = {
        method: incoming.method ?? "GET",
        rawPath: decoded === rawPath ? rawPath : decoded,
        path: rawPath,
        query: new URL(incoming.url ?? "/", "http://lab").searchParams,
        headers: incoming.headers,
        body: Buffer.concat(chunks).toString("latin1"),
      };
      const handler = routes.get(rawPath) ?? routes.get(decoded);
      if (!handler) return send(res, 404, "Not found", "text/plain");
      await handler(req, res);
    } catch (error) {
      if (!res.headersSent) send(res, 500, `lab error: ${String(error)}`, "text/plain");
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("lab did not start");
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

export { signJwt, PASSWD, VALID_TOKEN, STRONG };
