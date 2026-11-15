/** Re-indents a GraphQL document. It tokenizes, so it works on queries pasted onto one line. */

type Token = { text: string; kind: "name" | "punct" | "string" | "number" | "comment" | "spread" };

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < source.length) {
    const c = source[i]!;
    if (/\s/.test(c)) {
      i++;
    } else if (c === "#") {
      let end = source.indexOf("\n", i);
      if (end < 0) end = source.length;
      tokens.push({ text: source.slice(i, end).trimEnd(), kind: "comment" });
      i = end;
    } else if (source.startsWith('"""', i)) {
      const end = source.indexOf('"""', i + 3);
      const stop = end < 0 ? source.length : end + 3;
      tokens.push({ text: source.slice(i, stop), kind: "string" });
      i = stop;
    } else if (c === '"') {
      let j = i + 1;
      while (j < source.length && source[j] !== '"') j += source[j] === "\\" ? 2 : 1;
      tokens.push({ text: source.slice(i, j + 1), kind: "string" });
      i = j + 1;
    } else if (source.startsWith("...", i)) {
      tokens.push({ text: "...", kind: "spread" });
      i += 3;
    } else if (/[A-Za-z_]/.test(c)) {
      let j = i + 1;
      while (j < source.length && /[A-Za-z0-9_]/.test(source[j]!)) j++;
      tokens.push({ text: source.slice(i, j), kind: "name" });
      i = j;
    } else if (/[-0-9]/.test(c)) {
      let j = i + 1;
      while (j < source.length && /[0-9.eE+-]/.test(source[j]!)) j++;
      tokens.push({ text: source.slice(i, j), kind: "number" });
      i = j;
    } else {
      tokens.push({ text: c, kind: "punct" });
      i++;
    }
  }
  return tokens;
}

const isValueEnd = (t: Token) =>
  t.kind === "name" ||
  t.kind === "number" ||
  t.kind === "string" ||
  t.text === ")" ||
  t.text === "}";

/** Parts that stay on the field's line: `alias: field`, `@directive`, `... on Type`, `$variable`. */
function continuesLine(tokens: Token[], index: number): boolean {
  const before = tokens[index - 1];
  const beforeThat = tokens[index - 2];
  const token = tokens[index]!;
  if (!before) return false;
  if (before.text === ":" || before.text === "@" || before.text === "$") return true;
  if (before.kind === "spread") return true;
  if (before.text === "on" && beforeThat?.kind === "spread") return true;
  return token.text === "@";
}

/** Commas separate values inside (...) and [...]; between fields they are optional noise. */
function withoutFieldCommas(tokens: Token[]): Token[] {
  let nesting = 0;
  return tokens.filter((token) => {
    if (token.text === "(" || token.text === "[") nesting++;
    if (token.text === ")" || token.text === "]") nesting = Math.max(0, nesting - 1);
    return token.text !== "," || nesting > 0;
  });
}

export function formatQuery(source: string): string {
  const tokens = withoutFieldCommas(tokenize(source));
  let out = "";
  let depth = 0; // selection-set and definition braces
  let paren = 0; // arguments, variable definitions and lists
  let valueBraces = 0; // object values inside arguments
  let atLineStart = true;
  const newline = (extra = "") => {
    out = out.trimEnd() + "\n" + extra + "  ".repeat(depth);
    atLineStart = true;
  };
  const write = (text: string, space: boolean) => {
    const spaced = space && !atLineStart && !/[\s([$]$/.test(out);
    out += (spaced ? " " : "") + text;
    atLineStart = false;
  };
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    const prev = tokens[index - 1];
    const next = tokens[index + 1];
    if (token.kind === "comment") {
      if (!atLineStart) out += " ";
      out += token.text;
      newline();
    } else if (token.text === ",") {
      if (paren > 0 || valueBraces > 0) write(",", false);
    } else if (token.text === "{" && paren > 0) {
      valueBraces++;
      write("{", true);
    } else if (token.text === "}" && valueBraces > 0) {
      valueBraces--;
      write("}", true);
    } else if (token.text === "{") {
      write("{", true);
      depth++;
      newline();
    } else if (token.text === "}") {
      depth = Math.max(0, depth - 1);
      newline();
      write("}", false);
      if (!next) continue;
      if (depth === 0) newline("\n");
      else if (next.text !== "}") newline();
    } else if (token.text === "(" || token.text === "[") {
      paren++;
      write(token.text, token.text === "[");
    } else if (token.text === ")" || token.text === "]") {
      paren = Math.max(0, paren - 1);
      write(token.text, false);
    } else if (token.text === ":" || token.text === "!") {
      write(token.text, false);
    } else if (token.text === "=") {
      write("=", true);
    } else if (token.text === "$") {
      write("$", true);
    } else if (token.text === "@") {
      write("@", true);
    } else {
      const startsField =
        depth > 0 &&
        paren === 0 &&
        valueBraces === 0 &&
        prev !== undefined &&
        isValueEnd(prev) &&
        !continuesLine(tokens, index);
      if (startsField && !atLineStart) newline();
      const tight =
        prev?.text === "$" ||
        prev?.text === "@" ||
        (prev?.kind === "spread" && token.text !== "on") ||
        prev?.text === "(" ||
        prev?.text === "[";
      write(token.text, !tight);
    }
  }
  return out.trim() + "\n";
}
