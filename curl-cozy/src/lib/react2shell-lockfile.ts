/**
 * Offline check of a lockfile or package.json against the React2Shell advisory (CVE-2025-55182):
 * which resolved versions of `next` and the `react-server-dom-*` packages are in the affected range.
 * The version table mirrors crates/web-server/data/react2shell-advisory.json (a test keeps them equal).
 */
import { load } from "js-yaml";

export const ADVISORY = {
  cve: "CVE-2025-55182",
  react: { major: 19, patched: { "19.0": "19.0.1", "19.1": "19.1.2", "19.2": "19.2.1" } as Record<string, string> },
  next: {
    notAffectedBelow: 15,
    canary: { "14.3": 77 } as Record<string, number>,
    patched: { "15.0": "15.0.5", "15.1": "15.1.9", "15.2": "15.2.6", "15.3": "15.3.6", "15.4": "15.4.8", "15.5": "15.5.7", "16.0": "16.0.7" } as Record<string, string>,
  },
};

export type Version = { major: number; minor: number; patch: number; pre?: string };
export type Verdict =
  | { status: "vulnerable"; fixed: string }
  | { status: "patched"; since: string }
  | { status: "not_affected"; reason: string }
  | { status: "prerelease" }
  | { status: "unknown"; reason: string };

export function parseVersion(text: string): Version | undefined {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(text.trim());
  if (!match) return undefined;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]), ...(match[4] ? { pre: match[4] } : {}) };
}

const patchOf = (fixed: string) => Number(fixed.split(".")[2]);

function assess(version: Version, patched: Record<string, string>): Verdict {
  if (version.pre) return { status: "prerelease" };
  const fixed = patched[`${version.major}.${version.minor}`];
  if (fixed) return version.patch >= patchOf(fixed) ? { status: "patched", since: fixed } : { status: "vulnerable", fixed };
  const minors = Object.keys(patched).map((k) => k.split(".").map(Number) as [number, number]);
  const newest = Math.max(-1, ...minors.filter(([major]) => major === version.major).map(([, minor]) => minor));
  if ((newest >= 0 && version.minor > newest) || minors.some(([major]) => major < version.major)) return { status: "patched", since: "a release after the fixed versions" };
  return { status: "unknown", reason: "branch not in the advisory table" };
}

export function assessNext(version: Version): Verdict {
  if (version.major < ADVISORY.next.notAffectedBelow) {
    const first = ADVISORY.next.canary[`${version.major}.${version.minor}`];
    const canary = Number(/^canary\.(\d+)/.exec(version.pre ?? "")?.[1]);
    if (first !== undefined && canary >= first) return { status: "prerelease" };
    return { status: "not_affected", reason: "Next.js before 15 does not bundle the affected React Server Components build" };
  }
  return assess(version, ADVISORY.next.patched);
}

export function assessReact(version: Version): Verdict {
  if (version.major < ADVISORY.react.major) return { status: "not_affected", reason: "React before 19 has no affected Server Components packages" };
  if (version.major > ADVISORY.react.major) return { status: "patched", since: "a later major release" };
  return assess(version, ADVISORY.react.patched);
}

const SERVER_DOM = new Set(["react-server-dom-webpack", "react-server-dom-parcel", "react-server-dom-turbopack"]);
const INTERESTING = new Set(["next", "react", ...SERVER_DOM]);

export type Item = { name: string; version: string; where: string; verdict?: Verdict; context?: boolean };
export type Report = {
  format: string;
  items: Item[];
  /** Only a version range was found (package.json): not a resolved version. */
  declared: { name: string; range: string }[];
  overall: "vulnerable" | "review" | "clear" | "none" | "unreadable";
  message: string;
};

function judge(name: string, version: string): Pick<Item, "verdict" | "context"> {
  const parsed = parseVersion(version);
  if (name === "react") return { context: true };
  if (!parsed) return { verdict: { status: "unknown", reason: "not a plain version" } };
  return { verdict: name === "next" ? assessNext(parsed) : assessReact(parsed) };
}

const add = (items: Item[], name: string, version: unknown, where: string) => {
  if (INTERESTING.has(name) && typeof version === "string" && version) items.push({ name, version: version.replace(/\(.*$/, ""), where, ...judge(name, version.replace(/\(.*$/, "")) });
};

function fromPackageLock(data: Record<string, unknown>, items: Item[]) {
  const packages = data["packages"] as Record<string, { version?: string }> | undefined;
  if (packages) {
    for (const [path, entry] of Object.entries(packages)) add(items, path.split("node_modules/").pop() ?? "", entry?.version, path || "(root)");
    return;
  }
  const walk = (dependencies: Record<string, { version?: string; dependencies?: Record<string, unknown> }> | undefined, trail: string) => {
    for (const [name, entry] of Object.entries(dependencies ?? {})) {
      add(items, name, entry?.version, `${trail}${name}`);
      walk(entry?.dependencies as never, `${trail}${name} > `);
    }
  };
  walk(data["dependencies"] as never, "");
}

function fromPnpm(text: string, items: Item[]) {
  const doc = load(text) as Record<string, unknown> | undefined;
  const seen = new Set<string>();
  const key = /^\/?((?:@[^/@]+\/)?[^/@]+)@(\d[^\s(]*)/;
  const legacy = /^\/((?:@[^/]+\/)?[^/]+)\/(\d[^\s_/(]*)/;
  for (const section of ["packages", "snapshots"]) {
    for (const k of Object.keys((doc?.[section] as object) ?? {})) {
      const m = key.exec(k) ?? legacy.exec(k);
      if (m && !seen.has(`${m[1]}@${m[2]}`)) {
        seen.add(`${m[1]}@${m[2]}`);
        add(items, m[1]!, m[2], `${section}: ${k}`);
      }
    }
  }
  for (const [importer, value] of Object.entries((doc?.["importers"] as Record<string, Record<string, unknown>>) ?? {})) {
    for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
      for (const [name, entry] of Object.entries((value?.[group] as Record<string, { version?: string }>) ?? {})) {
        const version = typeof entry === "string" ? entry : entry?.version;
        if (typeof version === "string" && !seen.has(`${name}@${version.replace(/\(.*$/, "")}`)) add(items, name, version, `importer ${importer} (${group})`);
      }
    }
  }
}

function fromYarn(text: string, items: Item[]) {
  let names: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line) && line.trimEnd().endsWith(":")) {
      names = line
        .trimEnd()
        .slice(0, -1)
        .split(",")
        .map((spec) => spec.trim().replace(/^"|"$/g, ""))
        .map((spec) => spec.slice(0, spec.lastIndexOf("@") > 0 ? spec.indexOf("@", 1) : undefined))
        .filter(Boolean);
    } else {
      const version = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line)?.[1];
      if (version && names.length) {
        for (const name of new Set(names)) add(items, name, version, `yarn.lock: ${name}@${version}`);
        names = [];
      }
    }
  }
}

function fromBun(text: string, items: Item[]) {
  // "packages": { "next": ["next@15.1.2", "", { ... }, "sha512-..."], ... }
  for (const m of text.matchAll(/\[\s*"((?:@[^/"@]+\/)?[^/"@]+)@(\d[^"]*)"/g)) add(items, m[1]!, m[2], `bun.lock: ${m[1]}@${m[2]}`);
}

function fromAnywhere(text: string, items: Item[]) {
  for (const m of text.matchAll(/\b(next|react|react-server-dom-(?:webpack|parcel|turbopack))@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\b/g)) add(items, m[1]!, m[2], `${m[1]}@${m[2]}`);
}

export function checkLockfile(input: string): Report {
  const text = input.trim();
  const empty: Report = { format: "", items: [], declared: [], overall: "unreadable", message: "Paste a lockfile or package.json." };
  if (!text) return empty;
  const items: Item[] = [];
  const declared: Report["declared"] = [];
  let format = "";
  try {
    if (text.startsWith("{")) {
      let data: Record<string, unknown> | undefined;
      try {
        data = JSON.parse(text);
      } catch {
        data = undefined; // bun.lock is JSON with comments and trailing commas
      }
      if (data && ("lockfileVersion" in data || "packages" in data)) {
        format = "package-lock.json";
        fromPackageLock(data, items);
      } else if (data && ("dependencies" in data || "devDependencies" in data)) {
        format = "package.json";
        for (const group of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
          for (const [name, range] of Object.entries((data[group] as Record<string, string>) ?? {})) if (INTERESTING.has(name)) declared.push({ name, range: String(range) });
        }
      } else if (!data) {
        format = "bun.lock";
        fromBun(text, items);
      }
    } else if (/^lockfileVersion\s*:/m.test(text)) {
      format = "pnpm-lock.yaml";
      fromPnpm(text, items);
    } else if (/^# yarn lockfile|^__metadata:/m.test(text)) {
      format = "yarn.lock";
      fromYarn(text, items);
    }
    if (!format) {
      format = "text";
      fromAnywhere(text, items);
    }
  } catch (error) {
    return { ...empty, format, message: `Could not read the file: ${error instanceof Error ? error.message : "invalid content"}` };
  }
  const judged = items.filter((i) => i.verdict);
  const vulnerable = judged.filter((i) => i.verdict!.status === "vulnerable");
  const review = judged.filter((i) => ["prerelease", "unknown"].includes(i.verdict!.status));
  let overall: Report["overall"];
  let message: string;
  if (vulnerable.length) {
    overall = "vulnerable";
    message = `${vulnerable.length} resolved version${vulnerable.length > 1 ? "s are" : " is"} in the affected range for ${ADVISORY.cve}.`;
  } else if (review.length) {
    overall = "review";
    message = "No affected version was found, but some versions are pre-releases or could not be judged.";
  } else if (judged.length) {
    overall = "clear";
    message = `Every resolved next / react-server-dom-* version is patched or outside the affected range for ${ADVISORY.cve}.`;
  } else if (declared.length) {
    overall = "review";
    message = "Only version ranges were found in package.json. Use the lockfile: a range does not say which version is installed.";
  } else {
    overall = "none";
    message = "No next or react-server-dom-* package found, so this advisory does not apply to what was pasted.";
  }
  return { format, items, declared, overall, message };
}
