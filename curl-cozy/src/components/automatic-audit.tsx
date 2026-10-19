import { useEffect, useState } from "react";
import { fetchAutomaticAudit, setAutomaticAudit, type AutomaticAuditStatus } from "@/lib/scan-api";
import { Button } from "./ui/button";

export function AutomaticAudit() {
  const [status, setStatus] = useState<AutomaticAuditStatus | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let current = true;
    const update = () => void fetchAutomaticAudit().then(value => {
      if (current) { setStatus(value); setError(""); }
    }).catch(error => { if (current) setError(error instanceof Error ? error.message : "Could not load automatic audit status"); });
    update();
    const timer = setInterval(update, 3000);
    return () => { current = false; clearInterval(timer); };
  }, []);
  return <section className="rounded-lg border bg-card p-4" aria-label="Automatic capture audit">
    <div className="flex flex-wrap items-center gap-3">
      <h2 className="mr-auto font-medium">Automatic capture audit</h2>
      {status && <><span role="status" className="text-xs text-muted-foreground">{status.enabled ? "Enabled" : "Paused"} · {status.active} active · {status.queued} queued · {status.completed} completed</span>
        <Button variant="outline" size="sm" disabled={busy} onClick={async () => {
          setBusy(true);
          try { setStatus(await setAutomaticAudit(!status.enabled)); setError(""); }
          catch (error) { setError(error instanceof Error ? error.message : "Could not change automatic audit"); }
          finally { setBusy(false); }
        }}>{status.enabled ? "Pause automatic audit" : "Resume automatic audit"}</Button></>}
    </div>
    {status && (status.skipped > 0 || status.errors > 0) && <p className="mt-2 text-xs text-warning">{status.skipped} skipped (queue pressure or unsupported captures) · {status.errors} save errors. Missing or skipped checks are not a clean scan result.</p>}
    {error && <p role="alert" className="mt-2 text-xs text-destructive">{error}</p>}
  </section>;
}
