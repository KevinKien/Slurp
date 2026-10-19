import type { DomAudit } from "@/lib/scan/dom-audit";
export function DomAuditReport({ audits }: { audits: DomAudit[] | undefined }) {
  if (!audits?.length) return null;
  return (
    <details className="min-w-0 rounded border border-border p-3">
      <summary className="cursor-pointer text-sm">
        DOM script audit ({audits.reduce((n, a) => n + a.scripts.length, 0)} scripts)
      </summary>
      <div className="mt-3 max-h-96 space-y-4 overflow-auto text-xs">
        {audits.map((audit) => (
          <section key={audit.id} className="min-w-0 space-y-3" aria-label="DOM script audit">
            <p className="break-all font-medium">{audit.url}</p>
            <p className="text-muted-foreground">
              Static candidates guide payload selection. Browser callbacks and controls determine
              findings.
            </p>
            {!!audit.runtimeScripts?.length && (
              <div className="space-y-1">
                <p className="font-medium">
                  Runtime script dependencies ({audit.runtimeScripts.length})
                </p>
                <p className="text-muted-foreground">
                  Observed on the original page. Only eligible scripts are captured and audited
                  below; exclusions appear in the analysis notes.
                </p>
                {audit.runtimeScripts.map((url) => (
                  <p key={url} className="break-all font-mono">
                    {url}
                  </p>
                ))}
              </div>
            )}
            <div className="overflow-auto">
              <table className="w-full text-left" aria-label="Audited scripts">
                <thead>
                  <tr>
                    {["Script", "Parsed", "Sources", "Sinks"].map((h) => (
                      <th key={h} className="p-2">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {audit.scripts.map((script, i) => (
                    <tr key={i} className="border-t border-border">
                      <td className="p-2 break-all">{script.url}</td>
                      <td className="p-2">{script.parsed ? "Yes" : "No"}</td>
                      <td className="p-2 break-all">
                        {script.sources.join(", ") || "None identified"}
                      </td>
                      <td className="p-2 break-all">
                        {script.sinks.join(", ") || "None identified"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {audit.candidates.map((c) => (
              <div key={c.id} className="space-y-1 rounded bg-muted p-3">
                <p className="font-medium break-all">
                  {c.source.label}
                  {c.source.name !== undefined ? ` [${c.source.name}]` : ""} → {c.sink} ·{" "}
                  {c.context}
                </p>
                <p className="break-all">
                  {c.script}:{c.line}:{c.column}
                </p>
                <pre className="whitespace-pre-wrap break-all">{c.excerpt}</pre>
                <p>Payload families: {c.families.join(", ")}</p>
              </div>
            ))}
            {!audit.candidates.length && (
              <p>No supported static source-to-sink candidate was identified.</p>
            )}
            {audit.notes.map((note, i) => (
              <p key={i} className="break-all text-muted-foreground">
                {note}
              </p>
            ))}
          </section>
        ))}
      </div>
    </details>
  );
}
