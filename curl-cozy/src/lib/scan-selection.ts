import type { HttpRequest } from "./traffic";
import type { ScanParameter } from "./scan/types";
/** Bounded, explicit candidates; selection is always a separate user action. */
export function scanParameters(request: HttpRequest): ScanParameter[] {
  const result: ScanParameter[] = [],
    counts = new Map<string, number>();
  try {
    for (const [name] of new URL(request.url).searchParams) {
      const occurrence = counts.get(name) ?? 0;
      counts.set(name, occurrence + 1);
      if (name && result.length < 100) result.push({ kind: "query", name, occurrence });
    }
  } catch {
    /* Templates may not be URLs until profile resolution. */
  }
  try {
    const root: unknown = JSON.parse(request.body);
    let visited = 0;
    const visit = (value: unknown, path: string, depth: number) => {
      if (++visited > 1000 || depth > 12 || result.length >= 100) return;
      if (value !== null && typeof value === "object") {
        for (const [key, child] of Object.entries(value)) {
          if (visited > 1000 || result.length >= 100) break;
          visit(child, path + "/" + key.replace(/~/g, "~0").replace(/\//g, "~1"), depth + 1);
        }
      } else if (path) result.push({ kind: "json", pointer: path });
    };
    visit(root, "", 0);
  } catch {
    /* Non-JSON bodies have no supported scalar parameters. */
  }
  return result;
}
