import { ResponseDiffButton } from './response-diff';
import { useEffect, useState } from "react";
import { History, RotateCcw } from "lucide-react";
import { Button } from "./ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./ui/dialog";
import { CodePane } from "./code-pane";
import { fetchReplayRun, fetchReplayRuns } from "@/lib/replay-features-api";
import { runSummary, type ReplayRun, type ReplayRunSummary } from "@/lib/replay-features";
import { requestText, responseText, type HttpRequest } from "@/lib/traffic";

export function ReplayRuns({
  workspace,
  tab,
  runs,
  onRestore,
}: {
  workspace: string | null;
  tab: number;
  runs: ReplayRun[];
  onRestore: (request: HttpRequest) => void;
}) {
  const [open, setOpen] = useState(false),
    [list, setList] = useState<ReplayRunSummary[]>([]),
    [more, setMore] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [selected, setSelected] = useState(""),
    [detail, setDetail] = useState<ReplayRun | null>(null),
    [compareId,setCompareId]=useState(''),
    [baseline,setBaseline]=useState<ReplayRun|null>(null),
    [retry, setRetry] = useState(0);
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setBusy(true);
    setError("");
    setSelected("");
    setDetail(null);
    if (!workspace) {
      setList(runs.map(runSummary));
      setMore(false);
      setBusy(false);
      return;
    }
    void fetchReplayRuns(workspace, tab)
      .then(
        (page) => {
          if (!cancelled) {
            setList(page.data);
            setMore(page.has_more);
          }
        },
        (e) => {
          if (!cancelled) {
            setError(e instanceof Error ? e.message : "Could not load runs");
            setList(runs.map(runSummary));
            setMore(false);
          }
        },
      )
      .finally(() => {
        if (!cancelled) setBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, workspace, tab, runs, retry]);
  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setDetail(null);
    setError("");
    const local = runs.find((run) => run.id === selected);
    if (local) {
      setDetail(local);
      return;
    }
    if (!workspace) return;
    setBusy(true);
    void fetchReplayRun(workspace, tab, selected)
      .then(
        (run) => {
          if (!cancelled) setDetail(run);
        },
        (e) => {
          if (!cancelled) setError(e instanceof Error ? e.message : "Could not load run");
        },
      )
      .finally(() => {
        if (!cancelled) setBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected, workspace, tab, runs]);
  useEffect(()=>{
    setBaseline(null);if(!compareId)return;
    const local=runs.find(run=>run.id===compareId);
    if(local){setBaseline(local);return;}
    if(!workspace)return;
    let active=true;
    fetchReplayRun(workspace,tab,compareId).then(run=>{if(active)setBaseline(run);},error=>{if(active)setError(String(error));});
    return()=>{active=false;};
  },[compareId,workspace,tab,runs]);
  const loadMore = async () => {
    if (!workspace || busy) return;
    setBusy(true);
    setError("");
    try {
      const page = await fetchReplayRuns(workspace, tab, list.length);
      setList((prev) => [...prev, ...page.data]);
      setMore(page.has_more);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load runs");
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        <History />
        Send history
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="flex h-[85vh] max-w-5xl flex-col bg-card">
          <DialogHeader>
            <DialogTitle>Replay send history</DialogTitle>
            <DialogDescription>
              Each send keeps its request and response or error. Restore a sent request to edit and
              send it again.
            </DialogDescription>
          </DialogHeader>
          <div className="flex gap-2">
            <select
              aria-label="Replay run"
              className="inspector-input min-w-0 flex-1 text-xs"
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
            >
              <option value="">Select a send ({list.length} loaded)</option>
              {list.map((run) => (
                <option key={run.id} value={run.id}>
                  {new Date(run.timestamp).toLocaleString()} · {run.error ? "Error" : run.status} ·{" "}
                  {run.duration} ms · {run.method} {run.url}
                </option>
              ))}
            </select>
            {more && (
              <Button variant="outline" size="sm" disabled={busy} onClick={() => void loadMore()}>
                Load older
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              disabled={!detail}
              onClick={() => {
                if (detail) {
                  onRestore({ ...detail.request, headers: { ...detail.request.headers } });
                  setOpen(false);
                }
              }}
            >
              <RotateCcw />
              Restore sent request
            </Button>
          </div>
          {error && (
            <div role="alert" className="text-xs text-destructive">
              {error}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSelected("");
                  setRetry((n) => n + 1);
                }}
              >
                Retry
              </Button>
            </div>
          )}
          {busy ? (
            <p role="status" className="text-xs text-muted-foreground">
              Loading send history…
            </p>
          ) : !list.length ? (
            <p className="text-sm text-muted-foreground">No sends yet.</p>
          ) : null}
          {detail&&<div className="flex flex-wrap items-center gap-2"><span>{detail.profileName?`Profile: ${detail.profileName}`:'No authentication profile'}</span><select aria-label="Compare Replay send" className="inspector-input min-w-0 flex-1 text-xs" value={compareId} onChange={e=>setCompareId(e.target.value)}><option value="">Compare with another send</option>{list.filter(run=>run.id!==detail.id).map(run=><option key={run.id} value={run.id}>{new Date(run.timestamp).toLocaleString()} · {run.status??'Error'} · {run.url}</option>)}</select>{baseline?.response&&detail.response&&<ResponseDiffButton left={baseline.response} right={detail.response}/>}</div>}
          {detail?.scriptResult && <details className="max-h-40 overflow-auto text-xs"><summary>Saved after-response script {detail.scriptResult.error ? "· Failed" : "· Succeeded"}</summary><pre className="whitespace-pre-wrap">{detail.afterResponse}</pre><p className="text-destructive">{detail.scriptResult.error}</p><pre className="whitespace-pre-wrap">{detail.scriptResult.logs.join("\n")}</pre><p>Updated: {Object.keys(detail.scriptResult.updates).join(", ") || "none"}</p></details>}
          {detail && (
            <div className="grid min-h-0 flex-1 grid-cols-2 gap-2">
              <div className="flex min-h-0 min-w-0 flex-col overflow-hidden rounded border border-border">
                <CodePane
                  title="Sent request"
                  body={requestText(detail.request)}
                  raw={requestText(detail.request)}
                  headers={detail.request.headers}
                />
              </div>
              <div className="flex min-h-0 min-w-0 flex-col overflow-hidden rounded border border-border">
                {detail.error ? (
                  <p role="alert" className="overflow-auto p-4 text-xs text-destructive">
                    {detail.error}
                  </p>
                ) : detail.response ? (
                  <CodePane
                    title="Saved response"
                    body={detail.response.responseBody}
                    raw={responseText(detail.response)}
                    headers={detail.response.responseHeaders}
                  />
                ) : (
                  <p className="p-4 text-xs text-muted-foreground">No response</p>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
