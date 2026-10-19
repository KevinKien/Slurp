import { checkRegistry } from "@/lib/scan/registry";
import type { ScanRun } from "@/lib/scan/types";
export function ScanCoverage({ run }: { run?: ScanRun | null }) {
  return (
    <details className="rounded-lg border bg-card p-4">
      <summary className="cursor-pointer text-sm font-medium">
        Scan coverage · {checkRegistry.filter((x) => x.status === "implemented").length} implemented
        · {checkRegistry.filter((x) => x.status === "experimental").length} experimental ·{" "}
        {checkRegistry.filter((x) => x.status === "planned").length} planned
      </summary>
      <p className="my-3 text-xs text-muted-foreground">
        Coverage lists check modules, not vulnerability counts. Experimental checks need contextual
        verification. Planned modules do not execute. Automatic-only checks run on new proxy
        captures.
      </p>
      {run && (
        <p className="mb-3 text-xs" aria-label="Scan result coverage">
          {run.checks.filter((x) => x.status === "passed" || x.status === "findings").length}{" "}
          completed results · {run.checks.filter((x) => x.status === "skipped").length} skipped ·{" "}
          {run.checks.filter((x) => x.status === "inconclusive").length} inconclusive ·{" "}
          {run.findings.filter((x) => x.checkId === "js-endpoints").length} endpoint discoveries ·{" "}
          {run.findings.filter((x) => x.checkId !== "js-endpoints").length} other findings
        </p>
      )}
      <div className="max-h-80 overflow-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b">
              <th className="p-2">Check</th>
              <th className="p-2">Status</th>
              <th className="p-2">Impact</th>
              <th className="p-2">Execution</th>
              <th className="p-2">Verification / requirements</th>
            </tr>
          </thead>
          <tbody>
            {checkRegistry.map((item) => (
              <tr key={item.id} className="border-b align-top">
                <td className="p-2">
                  {item.name}
                  <span className="block text-muted-foreground">{item.category}</span>
                </td>
                <td className="p-2">{item.status}</td>
                <td className="p-2">{item.impact}</td>
                <td className="p-2">{item.execution}</td>
                <td className="p-2">
                  {item.verification}
                  <span className="block text-muted-foreground">{item.requirements}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
