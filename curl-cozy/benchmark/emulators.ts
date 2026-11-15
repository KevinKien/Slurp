/**
 * Small emulators of vulnerable server behaviour, so the lab needs no database, shell or template engine.
 * Nothing here evaluates attacker input with `eval`; each parser handles a fixed grammar.
 */
import { createHmac } from "node:crypto";
import { posix } from "node:path";

// ── SQL ────────────────────────────────────────────────────────────────────────────────
export const USERS = [
  { id: 1, name: "alice", role: "admin" },
  { id: 2, name: "bob", role: "user" },
  { id: 3, name: "carol", role: "user" },
];
export class SqlSyntaxError extends Error {
  constructor(public near: string) {
    super(
      `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${near}' at line 1`,
    );
  }
}
type Tok = { t: "num" | "str" | "id" | "op" | "end"; v: string };
function sqlTokens(sql: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < sql.length) {
    const c = sql[i]!;
    if (/\s/.test(c)) i++;
    else if (sql.startsWith("--", i) && (i + 2 >= sql.length || /\s/.test(sql[i + 2]!))) break;
    else if (c === "#") break;
    else if (sql.startsWith("/*", i)) {
      const end = sql.indexOf("*/", i + 2);
      if (end < 0) throw new SqlSyntaxError(sql.slice(i));
      i = end + 2;
    } else if (c === "'") {
      let j = i + 1;
      let value = "";
      for (;;) {
        if (j >= sql.length) throw new SqlSyntaxError(sql.slice(i));
        if (sql[j] === "'" && sql[j + 1] === "'") {
          value += "'";
          j += 2;
        } else if (sql[j] === "'") break;
        else value += sql[j++];
      }
      out.push({ t: "str", v: value });
      i = j + 1;
    } else if (/[0-9]/.test(c)) {
      let j = i;
      while (j < sql.length && /[0-9.]/.test(sql[j]!)) j++;
      out.push({ t: "num", v: sql.slice(i, j) });
      i = j;
    } else if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < sql.length && /[A-Za-z0-9_]/.test(sql[j]!)) j++;
      out.push({ t: "id", v: sql.slice(i, j) });
      i = j;
    } else if (/[=<>!(),+\-*]/.test(c)) {
      const two = sql.slice(i, i + 2);
      if (["<>", "!=", "<=", ">="].includes(two)) {
        out.push({ t: "op", v: two });
        i += 2;
      } else {
        out.push({ t: "op", v: c });
        i++;
      }
    } else throw new SqlSyntaxError(sql.slice(i));
  }
  out.push({ t: "end", v: "" });
  return out;
}
export type SqlResult = { rows: typeof USERS; delayMs: number };
/** `SELECT * FROM users WHERE <clause>`: AND/OR/NOT, comparisons, LIKE, SLEEP(n), literals, parentheses. */
export function sqlWhere(clause: string): SqlResult {
  const tokens = sqlTokens(clause);
  let delayMs = 0;
  const rows = USERS.filter((row) => {
    let p = 0;
    const peek = () => tokens[p]!;
    const next = () => tokens[p++]!;
    const fail = (): never => {
      throw new SqlSyntaxError(clause.slice(Math.max(0, clause.length - 20)).replace(/\s+$/, ""));
    };
    const kw = (word: string) => peek().t === "id" && peek().v.toUpperCase() === word;
    type V = string | number | boolean | null;
    const primary = (): V => {
      const tok = next();
      if (tok.t === "num") return Number(tok.v);
      if (tok.t === "str") return tok.v;
      if (tok.t === "op" && tok.v === "(") {
        if (peek().t === "id" && peek().v.toUpperCase() === "SELECT") {
          // (SELECT expr [FROM table | FROM (SELECT expr) alias]) as a scalar subquery
          next();
          const v = orExpr();
          if (kw("FROM")) {
            next();
            if (peek().t === "op" && peek().v === "(") {
              next();
              if (!kw("SELECT")) fail();
              next();
              orExpr();
              if (next().v !== ")") fail();
              if (peek().t === "id" && !["AND", "OR", "FROM"].includes(peek().v.toUpperCase()))
                next();
            } else next();
          }
          if (next().v !== ")") fail();
          return v;
        }
        const v = orExpr();
        if (next().v !== ")") fail();
        return v;
      }
      if (tok.t === "op" && tok.v === "-") return -Number(primary());
      if (tok.t === "id") {
        const word = tok.v.toUpperCase();
        if (word === "NOT") return !truthy(comparison());
        if (word === "NULL") return null;
        if (word === "TRUE") return 1;
        if (word === "FALSE") return 0;
        if (peek().t === "op" && peek().v === "(") {
          next();
          const arg = peek().v === ")" ? 0 : orExpr();
          if (next().v !== ")") fail();
          if (word === "SLEEP") {
            delayMs = Math.max(delayMs, Math.min(6000, Number(arg) * 1000));
            return 0;
          }
          if (word === "IF") return arg;
          return fail();
        }
        if (tok.v.toLowerCase() === "id") return row.id;
        if (tok.v.toLowerCase() === "name") return row.name;
        if (tok.v.toLowerCase() === "role") return row.role;
        return fail();
      }
      return fail();
    };
    const truthy = (v: V) =>
      typeof v === "string" ? Number(v) !== 0 && v !== "" && !Number.isNaN(Number(v)) : Boolean(v);
    const sum = (): V => {
      let left = primary();
      while (peek().t === "op" && ["+", "-", "*"].includes(peek().v)) {
        const op = next().v;
        const right = Number(primary());
        left =
          op === "+"
            ? Number(left) + right
            : op === "-"
              ? Number(left) - right
              : Number(left) * right;
      }
      return left;
    };
    const comparison = (): V => {
      const left = sum();
      const t = peek();
      if (t.t === "op" && ["=", "<>", "!=", "<", ">", "<=", ">="].includes(t.v)) {
        next();
        const right = sum();
        const loose = (a: V, b: V) =>
          typeof a === "number" || typeof b === "number"
            ? Number(a) === Number(b)
            : String(a).toLowerCase() === String(b).toLowerCase();
        switch (t.v) {
          case "=":
            return loose(left, right);
          case "<>":
          case "!=":
            return !loose(left, right);
          case "<":
            return Number(left) < Number(right);
          case ">":
            return Number(left) > Number(right);
          case "<=":
            return Number(left) <= Number(right);
          default:
            return Number(left) >= Number(right);
        }
      }
      if (kw("LIKE")) {
        next();
        const pattern = String(sum());
        const re = new RegExp(
          `^${pattern
            .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
            .replace(/%/g, ".*")
            .replace(/_/g, ".")}$`,
          "i",
        );
        return re.test(String(left));
      }
      return left;
    };
    const andExpr = (): V => {
      let left = comparison();
      while (kw("AND") || (peek().t === "op" && peek().v === "&")) {
        next();
        const right = comparison();
        left = truthy(left) && truthy(right);
      }
      return left;
    };
    const orExpr = (): V => {
      let left = andExpr();
      while (kw("OR")) {
        next();
        const right = andExpr();
        left = truthy(left) || truthy(right);
      }
      return left;
    };
    const result = orExpr();
    if (peek().t !== "end") fail();
    return truthy(result);
  });
  return { rows, delayMs };
}

// ── Shell ──────────────────────────────────────────────────────────────────────────────
export const PASSWD =
  "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n";
export const FILES: Record<string, string> = {
  "/etc/passwd": PASSWD,
  "/etc/hostname": "lab-host\n",
  "/windows/win.ini":
    "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n",
  "/var/www/files/readme.txt": "public readme\n",
};
function shellWords(line: string): string[] {
  const words: string[] = [];
  let cur = "";
  let had = false;
  let i = 0;
  while (i < line.length) {
    const c = line[i]!;
    if (c === "'") {
      const end = line.indexOf("'", i + 1);
      cur += end < 0 ? line.slice(i + 1) : line.slice(i + 1, end);
      had = true;
      i = end < 0 ? line.length : end + 1;
    } else if (c === '"') {
      let j = i + 1;
      while (j < line.length && line[j] !== '"') cur += line[j++];
      had = true;
      i = j + 1;
    } else if (/\s/.test(c)) {
      if (had || cur) words.push(cur);
      cur = "";
      had = false;
      i++;
    } else if (c === "\\" && i + 1 < line.length) {
      cur += line[i + 1];
      i += 2;
    } else {
      cur += c;
      i++;
    }
  }
  if (had || cur) words.push(cur);
  return words;
}
function expandShell(line: string, depth: number): string {
  let out = line.replace(/\$\{IFS\}|\$IFS\$9|\$IFS/g, " ").replace(/\$\(\)/g, "");
  out = out.replace(
    /\$\(([^()]*)\)|`([^`]*)`/g,
    (_m, a: string | undefined, b: string | undefined) =>
      depth > 2 ? "" : runCommandLine(a ?? b ?? "", depth + 1).trim(),
  );
  return out;
}
function runSimple(command: string, depth: number): string {
  const words = shellWords(expandShell(command, depth));
  const [name, ...args] = words;
  if (!name) return "";
  switch (name) {
    case "ping":
      return `PING ${args[args.length - 1] ?? ""} 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.05 ms\n`;
    case "id":
      return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n";
    case "whoami":
      return "www-data\n";
    case "echo":
      return `${args.join(" ")}\n`;
    case "printf": {
      const format = args[0] ?? "";
      const rest = args.slice(1);
      let k = 0;
      return format.replace(/%s/g, () => rest[k++] ?? "").replace(/\\n/g, "\n");
    }
    case "cat":
      return args.map((a) => FILES[a] ?? `cat: ${a}: No such file or directory\n`).join("");
    case "sleep":
      return "";
    case "uname":
      return "Linux\n";
    case "base64": {
      return "";
    }
    default:
      return `sh: 1: ${name}: not found\n`;
  }
}
/** `a; b | c && d || e & f \n g` runs every part (like `sh -c`) and joins their output. */
export function runCommandLine(line: string, depth = 0): string {
  let out = "";
  for (const part of line.split(/\r?\n|;|\|\||\||&&|&/)) {
    const piece = part.trim();
    if (piece) out += runSimple(piece, depth);
  }
  return out;
}

// ── Templates and expressions ──────────────────────────────────────────────────────────
function arithmetic(expr: string): number | undefined {
  const tokens = expr.match(/\d+(?:\.\d+)?|[()+\-*/]/g);
  if (!tokens || tokens.join("") !== expr.replace(/\s+/g, "")) return undefined;
  let p = 0;
  const factor = (): number => {
    const t = tokens[p++];
    if (t === "(") {
      const v = add();
      p++;
      return v;
    }
    if (t === "-") return -factor();
    return Number(t);
  };
  const mul = (): number => {
    let v = factor();
    while (tokens[p] === "*" || tokens[p] === "/")
      v = tokens[p++] === "*" ? v * factor() : v / factor();
    return v;
  };
  const add = (): number => {
    let v = mul();
    while (tokens[p] === "+" || tokens[p] === "-") v = tokens[p++] === "+" ? v + mul() : v - mul();
    return v;
  };
  const value = add();
  return p === tokens.length && Number.isFinite(value) ? value : undefined;
}
/** Renders `{{ expr }}`, `${expr}` and `<%= expr %>` as arithmetic, like an engine that evaluates them. */
export function renderTemplate(
  template: string,
  delimiters: "jinja" | "el" | "erb" | "all",
): string {
  const patterns: RegExp[] = [];
  if (delimiters === "jinja" || delimiters === "all") patterns.push(/\{\{([^{}]*)\}\}/g);
  if (delimiters === "el" || delimiters === "all") patterns.push(/\$\{([^{}]*)\}/g);
  if (delimiters === "erb" || delimiters === "all") patterns.push(/<%=([^%]*)%>/g);
  let out = template;
  for (const pattern of patterns)
    out = out.replace(pattern, (m, expr: string) => String(arithmetic(expr.trim()) ?? m));
  return out;
}
export const evaluateArithmetic = arithmetic;

// ── Paths ──────────────────────────────────────────────────────────────────────────────
export function readVirtualFile(
  base: string,
  name: string,
  options: { decodeTwice?: boolean; stripDotDotOnce?: boolean } = {},
): string | undefined {
  let value = name;
  if (options.decodeTwice) {
    try {
      value = decodeURIComponent(value);
    } catch {
      /* keep */
    }
  }
  if (options.stripDotDotOnce) value = value.replace(/\.\.\//g, "").replace(/\.\.\\/g, "");
  value = value.replace(/\\/g, "/").replace(/\0.*$/, "");
  const resolved = posix.normalize(posix.join(base, value));
  return FILES[resolved];
}

// ── JWT ────────────────────────────────────────────────────────────────────────────────
const b64 = (value: Buffer | string) => Buffer.from(value).toString("base64url");
export function signJwt(
  claims: Record<string, unknown>,
  secret: string,
  alg: "HS256" | "none" = "HS256",
): string {
  const header = b64(JSON.stringify({ alg, typ: "JWT" }));
  const payload = b64(JSON.stringify(claims));
  const signature =
    alg === "none" ? "" : b64(createHmac("sha256", secret).update(`${header}.${payload}`).digest());
  return `${header}.${payload}.${signature}`;
}
export function readJwt(
  token: string,
  secret: string | undefined,
  options: { acceptNone?: boolean; verify?: boolean },
): Record<string, unknown> | undefined {
  const [h, p, s] = token.split(".");
  if (!h || !p) return undefined;
  try {
    const header = JSON.parse(Buffer.from(h, "base64url").toString()) as { alg?: string };
    const claims = JSON.parse(Buffer.from(p, "base64url").toString()) as Record<string, unknown>;
    if (options.verify === false) return claims;
    if (String(header.alg).toLowerCase() === "none") return options.acceptNone ? claims : undefined;
    if (header.alg !== "HS256" || secret === undefined) return undefined;
    const expected = b64(createHmac("sha256", secret).update(`${h}.${p}`).digest());
    return s === expected ? claims : undefined;
  } catch {
    return undefined;
  }
}

// ── Mini JavaScript expressions (a server that evals user input) ───────────────────────
export function evalMiniJs(source: string): string {
  const src = source.trim();
  let i = 0;
  const ws = () => {
    while (/\s/.test(src[i] ?? "")) i++;
  };
  const fail = (what: string): never => {
    throw new Error(what);
  };
  type V = string | number;
  const primary = (): V => {
    ws();
    const c = src[i];
    if (c === "(") {
      i++;
      const v = add();
      ws();
      if (src[i++] !== ")") fail("SyntaxError: missing ) after argument list");
      return v;
    }
    if (c === "-") {
      i++;
      return -Number(primary());
    }
    if (c === "'" || c === '"') {
      const end = src.indexOf(c, i + 1);
      if (end < 0) fail("SyntaxError: Invalid or unexpected token");
      const v = src.slice(i + 1, end);
      i = end + 1;
      return v;
    }
    const num = /^\d+(?:\.\d+)?/.exec(src.slice(i));
    if (num) {
      i += num[0].length;
      return Number(num[0]);
    }
    const id = /^[A-Za-z_$][\w$]*/.exec(src.slice(i));
    if (id) {
      i += id[0].length;
      ws();
      if (id[0] === "String" && src[i] === "(") {
        i++;
        const v = add();
        ws();
        if (src[i++] !== ")") fail("SyntaxError: missing ) after argument list");
        return String(v);
      }
      return fail(`ReferenceError: ${id[0]} is not defined`);
    }
    return fail("SyntaxError: Unexpected token");
  };
  const mul = (): V => {
    let v = primary();
    for (;;) {
      ws();
      if (src[i] !== "*" && src[i] !== "/") return v;
      const op = src[i++];
      const r = primary();
      v = op === "*" ? Number(v) * Number(r) : Number(v) / Number(r);
    }
  };
  function add(): V {
    let v = mul();
    for (;;) {
      ws();
      if (src[i] !== "+" && src[i] !== "-") return v;
      const op = src[i++];
      const r = mul();
      v =
        op === "+"
          ? typeof v === "string" || typeof r === "string"
            ? String(v) + String(r)
            : v + r
          : Number(v) - Number(r);
    }
  }
  const value = add();
  ws();
  if (i < src.length) fail("SyntaxError: Unexpected token");
  return String(value);
}

/** PHP-style include(): absolute paths, file:// and php://filter wrappers, otherwise relative to `base`. */
export function phpInclude(base: string, input: string): string | undefined {
  const wrapped = /^php:\/\/filter\/(?:read=)?convert\.base64-encode\/resource=(.*)$/.exec(input);
  const target = (wrapped ? wrapped[1]! : input).replace(/^file:\/\//, "");
  const path = target.startsWith("/")
    ? posix.normalize(target)
    : posix.normalize(posix.join(base, target));
  const content = FILES[path];
  if (content === undefined) return undefined;
  return wrapped ? Buffer.from(content).toString("base64") : content;
}

// ── PHP- and Python-like evaluators (a server that evals user input in that language) ──
function literalOrArithmetic(source: string): string | undefined {
  const text = source.trim();
  const quoted = /^(['"])(.*)\1$/s.exec(text);
  if (quoted) return quoted[2]!;
  const value = arithmetic(text);
  return value === undefined ? undefined : String(value);
}
/** `echo 1013*2111;` prints the product; `echo '1013*2111';` prints the text. Anything else is a parse error. */
export function evalMiniPhp(source: string): string {
  const m = /^\s*echo\s+(.+?)\s*;?\s*$/s.exec(source);
  const out = m ? literalOrArithmetic(m[1]!) : undefined;
  if (out === undefined)
    throw new Error(
      "PHP Parse error: syntax error, unexpected token in Command line code on line 1",
    );
  return out;
}
/** `print(1013*2111)` prints the product; `print('1013*2111')` prints the text. Anything else raises. */
export function evalMiniPython(source: string): string {
  const m = /^\s*print\((.+)\)\s*$/s.exec(source);
  const out = m ? literalOrArithmetic(m[1]!) : undefined;
  if (out === undefined) {
    const name = /^\s*([A-Za-z_]\w*)/.exec(source)?.[1];
    throw new Error(
      name ? `NameError: name '${name}' is not defined` : "SyntaxError: invalid syntax",
    );
  }
  return out;
}
