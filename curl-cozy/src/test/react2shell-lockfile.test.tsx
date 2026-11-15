import { readFileSync } from "node:fs";
import path from "node:path";
import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { React2ShellTool } from "@/components/react2shell-tool";
import { ADVISORY, assessNext, assessReact, checkLockfile, parseVersion } from "@/lib/react2shell-lockfile";

const v = (text: string) => parseVersion(text)!;

it("keeps the version table equal to the one the backend audit uses", () => {
  const data = JSON.parse(readFileSync(path.resolve(process.cwd(), "../crates/web-server/data/react2shell-advisory.json"), "utf8"));
  expect(data.cve).toBe(ADVISORY.cve);
  expect(data.next.patched).toEqual(ADVISORY.next.patched);
  expect(data.next.affected_canary).toEqual(ADVISORY.next.canary);
  expect(data.react_server_dom.patched).toEqual(ADVISORY.react.patched);
  expect(Number.parseInt(data.next.not_affected_below)).toBe(ADVISORY.next.notAffectedBelow);
  expect(data.react_server_dom.affected_major).toBe(ADVISORY.react.major);
});

it("judges Next.js against the patched release of its branch", () => {
  expect(assessNext(v("15.1.8"))).toEqual({ status: "vulnerable", fixed: "15.1.9" });
  expect(assessNext(v("16.0.6"))).toEqual({ status: "vulnerable", fixed: "16.0.7" });
  for (const version of ["15.0.5", "15.5.7", "15.5.10", "16.0.7", "16.1.5", "17.0.0"]) expect(assessNext(v(version)).status, version).toBe("patched");
  for (const version of ["14.2.35", "13.5.6"]) expect(assessNext(v(version)).status, version).toBe("not_affected");
  for (const version of ["14.3.0-canary.77", "15.2.0-canary.4", "16.0.0-rc.1"]) expect(assessNext(v(version)).status, version).toBe("prerelease");
  expect(assessNext(v("14.3.0-canary.76")).status).toBe("not_affected");
});

it("judges the react-server-dom packages by release line", () => {
  for (const version of ["19.0.0", "19.1.0", "19.1.1", "19.2.0"]) expect(assessReact(v(version)).status, version).toBe("vulnerable");
  for (const version of ["19.0.1", "19.1.2", "19.2.1", "19.3.0", "20.0.0"]) expect(assessReact(v(version)).status, version).toBe("patched");
  expect(assessReact(v("18.3.1")).status).toBe("not_affected");
  expect(parseVersion("15.1")).toBeUndefined();
  expect(parseVersion("15.1.2+build.5")).toEqual({ major: 15, minor: 1, patch: 2 });
});

const lock = (versions: Record<string, string>) =>
  JSON.stringify({ name: "app", lockfileVersion: 3, packages: { "": { name: "app" }, ...Object.fromEntries(Object.entries(versions).map(([name, version]) => [`node_modules/${name}`, { version }])) } });

it("reads package-lock.json (including nested copies) and flags the affected version", () => {
  const report = checkLockfile(JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/next": { version: "15.1.2" }, "node_modules/foo/node_modules/next": { version: "15.1.9" }, "node_modules/react": { version: "19.1.0" }, "node_modules/react-server-dom-webpack": { version: "19.1.0" }, "node_modules/lodash": { version: "4.17.21" } } }));
  expect(report.format).toBe("package-lock.json");
  expect(report.overall).toBe("vulnerable");
  expect(report.items.map((i) => `${i.name}@${i.version}:${i.verdict?.status ?? "context"}`)).toEqual(["next@15.1.2:vulnerable", "next@15.1.9:patched", "react@19.1.0:context", "react-server-dom-webpack@19.1.0:vulnerable"]);
  expect(checkLockfile(JSON.stringify({ lockfileVersion: 1, dependencies: { next: { version: "15.0.4", dependencies: { "react-server-dom-turbopack": { version: "19.0.1" } } } } })).items.map((i) => i.where)).toEqual(["next", "next > react-server-dom-turbopack"]);
  expect(checkLockfile(lock({ next: "15.5.7", react: "19.2.1" })).overall).toBe("clear");
  expect(checkLockfile(lock({ lodash: "4.17.21" })).overall).toBe("none");
});

it("reads pnpm-lock.yaml in the v6, v9 and importer layouts", () => {
  const v9 = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      next:\n        specifier: ^15.1.0\n        version: 15.1.2(react-dom@19.0.0(react@19.0.0))(react@19.0.0)\npackages:\n  next@15.1.2:\n    resolution: {integrity: sha512-x}\n  react@19.0.0:\n    resolution: {integrity: sha512-y}\nsnapshots:\n  next@15.1.2(react-dom@19.0.0(react@19.0.0))(react@19.0.0):\n    dependencies: {}\n";
  const report = checkLockfile(v9);
  expect(report.format).toBe("pnpm-lock.yaml");
  expect(report.overall).toBe("vulnerable");
  expect(report.items.filter((i) => i.name === "next")).toHaveLength(1);
  const v6 = "lockfileVersion: '6.0'\npackages:\n  /next@15.5.7(react@19.1.2):\n    resolution: {integrity: sha512-x}\n  /@scope/other@1.0.0:\n    resolution: {integrity: sha512-z}\n";
  expect(checkLockfile(v6).overall).toBe("clear");
  expect(checkLockfile("lockfileVersion: 5.4\npackages:\n  /next/15.0.1_react@19.0.0:\n    resolution: {}\n").overall).toBe("vulnerable");
});

it("reads yarn.lock classic and berry, and bun.lock", () => {
  const classic = '# yarn lockfile v1\n\n"@scope/x@^1.0.0":\n  version "1.0.0"\n\nnext@^15.0.0, next@^15.1.0:\n  version "15.1.2"\n  resolved "https://registry.yarnpkg.com/next/-/next-15.1.2.tgz"\n';
  const a = checkLockfile(classic);
  expect(a.format).toBe("yarn.lock");
  expect(a.items.map((i) => `${i.name}@${i.version}`)).toEqual(["next@15.1.2"]);
  expect(a.overall).toBe("vulnerable");
  const berry = '__metadata:\n  version: 8\n\n"next@npm:^15.5.0":\n  version: 15.5.7\n  resolution: "next@npm:15.5.7"\n';
  expect(checkLockfile(berry).overall).toBe("clear");
  const bun = '{\n  "lockfileVersion": 1,\n  "workspaces": { "": { "name": "app" } },\n  "packages": {\n    "next": ["next@15.0.4", "", { "dependencies": {} }, "sha512-x"],\n    "@swc/helpers": ["@swc/helpers@0.5.15", "", {}, "sha512-y"],\n  }\n}\n';
  const b = checkLockfile(bun);
  expect(b.format).toBe("bun.lock");
  expect(b.overall).toBe("vulnerable");
  expect(b.items).toHaveLength(1);
});

it("treats package.json as ranges only and never as proof either way", () => {
  const report = checkLockfile(JSON.stringify({ name: "app", dependencies: { next: "^15.1.0", react: "^19.0.0", lodash: "^4" } }));
  expect(report.format).toBe("package.json");
  expect(report.items).toEqual([]);
  expect(report.declared).toEqual([{ name: "next", range: "^15.1.0" }, { name: "react", range: "^19.0.0" }]);
  expect(report.overall).toBe("review");
  expect(report.message).toContain("lockfile");
});

it("falls back to plain next@version text and rejects empty or unreadable input", () => {
  expect(checkLockfile("next@15.0.1 react@19.0.0").overall).toBe("vulnerable");
  expect(checkLockfile("   ").overall).toBe("unreadable");
  expect(checkLockfile("just some prose").overall).toBe("none");
  expect(checkLockfile("lockfileVersion: [unclosed").overall).toBe("unreadable");
});

it("shows the result table and the verdict banner", () => {
  render(<React2ShellTool />);
  fireEvent.change(screen.getByLabelText("Lockfile or package.json"), { target: { value: lock({ next: "15.1.2" }) } });
  fireEvent.click(screen.getByRole("button", { name: "Check" }));
  expect(screen.getByRole("status").textContent).toContain("in the affected range for CVE-2025-55182");
  expect(screen.getByText("Vulnerable: upgrade to 15.1.9 or later")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Lockfile or package.json"), { target: { value: lock({ next: "16.1.5" }) } });
  fireEvent.click(screen.getByRole("button", { name: "Check" }));
  expect(screen.getByRole("status").textContent).toContain("patched or outside the affected range");
});
