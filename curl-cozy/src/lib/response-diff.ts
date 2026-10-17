export interface ComparableResponse {
  status: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
}
export interface DiffOptions {
  ignoredHeaders: string[];
  ignoredPaths: string[];
}
export const defaultDiffOptions: DiffOptions = {
  ignoredHeaders: ["date", "set-cookie", "x-request-id", "x-correlation-id"],
  ignoredPaths: [],
};
export interface DiffLine {
  kind: "same" | "added" | "removed";
  text: string;
}
function removePath(value: unknown, path: string) {
  const parts = path.startsWith("/")
    ? path
        .slice(1)
        .split("/")
        .map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"))
    : path
        .replace(/^\$\.?/, "")
        .replace(/\[(\d+)\]/g, ".$1")
        .split(".");
  if (!parts.length || parts.some((s) => !s)) return;
  let node = value;
  for (const key of parts.slice(0, -1)) {
    if (!node || typeof node !== "object" || !Object.hasOwn(node, key)) return;
    node = (node as Record<string, unknown>)[key];
  }
  const last = parts.at(-1)!;
  if (node && typeof node === "object" && Object.hasOwn(node, last)) {
    // Keep array positions stable when masking a numeric element.
    if (Array.isArray(node)) node[Number(last)] = "<ignored>";
    else delete (node as Record<string, unknown>)[last];
  }
}
function stable(value: unknown, depth = 0): unknown {
  if (depth > 64) throw Error("JSON nesting exceeds comparison limit");
  if (Array.isArray(value)) return value.map((v) => stable(v, depth + 1));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, stable(v, depth + 1)]),
    );
  return value;
}
export function normalizedResponse(
  response: ComparableResponse,
  options: DiffOptions = defaultDiffOptions,
) {
  let body = response.responseBody.replace(/\r\n/g, "\n");
  let json = false;
  try {
    const value: unknown = JSON.parse(body);
    for (const path of options.ignoredPaths.slice(0, 50)) removePath(value, path);
    body = JSON.stringify(stable(value), null, 2);
    json = true;
  } catch {
    /* Compare non-JSON bodies as text, preserving whitespace. */
  }
  const ignored = new Set(options.ignoredHeaders.map((s) => s.trim().toLowerCase()));
  const headers = Object.fromEntries(
    Object.entries(response.responseHeaders)
      .map(([k, v]) => [k.toLowerCase(), v])
      .filter(([k]) => !ignored.has(k!))
      .sort(([a], [b]) => a!.localeCompare(b!)),
  );
  return { status: response.status, headers, body, json };
}
/** Bounded LCS for readable changes; equality is always computed on the full response. */
export function lineDiff(left: string, right: string): { lines: DiffLine[]; truncated: boolean } {
  const allA = left.split("\n"),
    allB = right.split("\n");
  const a = allA.slice(0, 700),
    b = allB.slice(0, 700);
  const width = b.length + 1,
    matrix = new Uint16Array((a.length + 1) * width);
  for (let i = a.length - 1; i >= 0; i--)
    for (let j = b.length - 1; j >= 0; j--)
      matrix[i * width + j] =
        a[i] === b[j]
          ? matrix[(i + 1) * width + j + 1]! + 1
          : Math.max(matrix[(i + 1) * width + j]!, matrix[i * width + j + 1]!);
  const lines: DiffLine[] = [];
  let i = 0,
    j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      lines.push({ kind: "same", text: a[i++]! });
      j++;
    } else if (
      j < b.length &&
      (i === a.length || matrix[i * width + j + 1]! >= matrix[(i + 1) * width + j]!)
    )
      lines.push({ kind: "added", text: b[j++]! });
    else lines.push({ kind: "removed", text: a[i++]! });
  }
  return { lines, truncated: allA.length > 700 || allB.length > 700 };
}
export function compareResponses(
  left: ComparableResponse,
  right: ComparableResponse,
  options: DiffOptions = defaultDiffOptions,
) {
  const a = normalizedResponse(left, options),
    b = normalizedResponse(right, options);
  const statusChanged = a.status !== b.status,
    headersChanged = JSON.stringify(a.headers) !== JSON.stringify(b.headers),
    bodyChanged = a.body !== b.body;
  return {
    left: a,
    right: b,
    statusChanged,
    headersChanged,
    bodyChanged,
    equal: !statusChanged && !headersChanged && !bodyChanged,
  };
}
