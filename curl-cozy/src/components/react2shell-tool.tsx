import { useRef, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { ADVISORY, checkLockfile, type Report, type Verdict } from "@/lib/react2shell-lockfile";
import { cn } from "@/lib/utils";

const label = (verdict?: Verdict) => {
  switch (verdict?.status) {
    case "vulnerable":
      return { text: `Vulnerable: upgrade to ${verdict.fixed} or later`, tone: "text-destructive" };
    case "patched":
      return { text: `Patched (${verdict.since})`, tone: "text-primary" };
    case "not_affected":
      return { text: `Not affected: ${verdict.reason}`, tone: "text-muted-foreground" };
    case "prerelease":
      return { text: "Pre-release of an affected branch: patch level cannot be decided", tone: "text-warning" };
    case "unknown":
      return { text: `Cannot judge: ${verdict.reason}`, tone: "text-warning" };
    default:
      return { text: "Context (not judged)", tone: "text-muted-foreground" };
  }
};

const banner: Record<Report["overall"], string> = {
  vulnerable: "border-destructive/40 bg-destructive/5 text-destructive",
  review: "border-warning/40 bg-warning/5 text-warning",
  clear: "border-primary/30 bg-primary/5 text-primary",
  none: "border-border bg-card text-muted-foreground",
  unreadable: "border-border bg-card text-muted-foreground",
};

/** Paste or open a lockfile; nothing leaves the browser. */
export function React2ShellTool() {
  const [input, setInput] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const file = useRef<HTMLInputElement>(null);

  const readFile = (selected: File | undefined) => {
    if (!selected) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result ?? "");
      setInput(text);
      setReport(checkLockfile(text));
    };
    reader.onerror = () => toast.error("Could not read the file");
    reader.readAsText(selected);
  };

  return (
    <div className="space-y-4">
      <p className="text-xs leading-5 text-muted-foreground">
        Checks the resolved versions of <code>next</code> and <code>react-server-dom-webpack/parcel/turbopack</code> against {ADVISORY.cve} (React2Shell). Paste <code>package-lock.json</code>, <code>pnpm-lock.yaml</code>, <code>yarn.lock</code> or <code>bun.lock</code>. A <code>package.json</code> only gives version ranges, which cannot show what is installed. The check runs in your browser and nothing is sent anywhere.
      </p>
      <label className="block space-y-2 text-xs text-muted-foreground">
        <span>Lockfile or package.json</span>
        <textarea aria-label="Lockfile or package.json" className="inspector-input min-h-44 w-full font-mono text-xs" spellCheck={false} value={input} onChange={(e) => setInput(e.target.value)} />
      </label>
      <div className="flex flex-wrap gap-2">
        <Button onClick={() => setReport(checkLockfile(input))}>Check</Button>
        <input ref={file} type="file" className="hidden" aria-label="Open lockfile" onChange={(e) => readFile(e.target.files?.[0])} />
        <Button variant="outline" onClick={() => file.current?.click()}>
          Open file…
        </Button>
      </div>
      {report && (
        <div className="space-y-3" role="status">
          <div className={cn("rounded border px-3 py-2 text-sm", banner[report.overall])}>
            {report.format && <span className="mr-2 rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">{report.format}</span>}
            {report.message}
          </div>
          {report.items.length > 0 && (
            <table className="w-full text-left text-xs">
              <thead className="text-[10px] text-muted-foreground">
                <tr>
                  <th className="py-1 pr-3">Package</th>
                  <th className="py-1 pr-3">Version</th>
                  <th className="py-1 pr-3">Result</th>
                  <th className="py-1">Found in</th>
                </tr>
              </thead>
              <tbody>
                {report.items.map((item, i) => {
                  const result = label(item.verdict);
                  return (
                    <tr key={i} className="border-t border-border align-top">
                      <td className="py-1.5 pr-3 font-mono">{item.name}</td>
                      <td className="py-1.5 pr-3 font-mono">{item.version}</td>
                      <td className={cn("py-1.5 pr-3", result.tone)}>{result.text}</td>
                      <td className="py-1.5 font-mono text-[10px] text-muted-foreground">{item.where}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          {report.declared.length > 0 && (
            <ul className="text-xs text-muted-foreground">
              {report.declared.map((d) => (
                <li key={d.name} className="font-mono">
                  {d.name}: {d.range} (range)
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
