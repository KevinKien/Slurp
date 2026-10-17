import { useMemo, useState } from "react";
import { Button } from "./ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./ui/dialog";
import { CodePane } from "./code-pane";
import {
  compareResponses,
  defaultDiffOptions,
  lineDiff,
  type ComparableResponse,
} from "@/lib/response-diff";
export function ResponseDiff({
  left,
  right,
  leftLabel = "Baseline",
  rightLabel = "Compared response",
}: {
  left: ComparableResponse;
  right: ComparableResponse;
  leftLabel?: string;
  rightLabel?: string;
}) {
  const [ignoredHeaders, setHeaders] = useState(defaultDiffOptions.ignoredHeaders.join(", "));
  const [ignoredPaths, setPaths] = useState("");
  const [mode, setMode] = useState<"changes" | "body" | "headers">("changes");
  const diff = useMemo(
    () =>
      compareResponses(left, right, {
        ignoredHeaders: ignoredHeaders
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        ignoredPaths: ignoredPaths
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      }),
    [left, right, ignoredHeaders, ignoredPaths],
  );
  const lines = useMemo(
    () => lineDiff(diff.left.body, diff.right.body),
    [diff.left.body, diff.right.body],
  );
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 text-xs">
      <div className="grid gap-2 sm:grid-cols-2">
        <label>
          Ignore response headers
          <input
            aria-label="Ignore response headers"
            className="inspector-input mt-1 w-full"
            value={ignoredHeaders}
            onChange={(e) => setHeaders(e.target.value)}
          />
        </label>
        <label>
          Ignore JSON paths (comma-separated)
          <input
            aria-label="Ignore JSON paths"
            placeholder="timestamp, meta.requestId, /data/updatedAt"
            className="inspector-input mt-1 w-full"
            value={ignoredPaths}
            onChange={(e) => setPaths(e.target.value)}
          />
        </label>
      </div>
      <p role="status">
        {diff.equal ? "Responses match after normalization." : "Responses differ."} Status:{" "}
        {left.status} → {right.status} · Headers {diff.headersChanged ? "changed" : "match"} · Body{" "}
        {diff.bodyChanged ? "changed" : "matches"}
      </p>
      <div className="flex gap-2">
        {(["changes", "body", "headers"] as const).map((value) => (
          <Button
            key={value}
            size="sm"
            variant={mode === value ? "secondary" : "ghost"}
            onClick={() => setMode(value)}
          >
            {value === "changes"
              ? "Highlighted changes"
              : value === "body"
                ? "Full normalized bodies"
                : "Headers"}
          </Button>
        ))}
      </div>
      {mode === "changes" ? (
        <div className="min-h-0 flex-1 overflow-auto rounded border border-border bg-background font-mono">
          <p className="sticky top-0 border-b border-border bg-card p-2">
            − {leftLabel} · + {rightLabel}
          </p>
          {lines.truncated && (
            <p className="p-2 text-warning">
              Highlight preview is limited to the first 700 lines. Equality uses the full body; use
              Full normalized bodies to inspect everything.
            </p>
          )}
          {lines.lines.map((line, index) => (
            <pre
              key={index}
              className={`whitespace-pre-wrap break-all px-3 py-0.5 ${line.kind === "added" ? "bg-primary/10 text-primary" : line.kind === "removed" ? "bg-destructive/10 text-destructive" : "text-muted-foreground"}`}
            >
              {line.kind === "added" ? "+" : line.kind === "removed" ? "−" : " "} {line.text}
            </pre>
          ))}
        </div>
      ) : (
        <div className="grid min-h-0 flex-1 grid-cols-2 gap-2">
          {[diff.left, diff.right].map((value, index) => (
            <div
              key={index}
              className="flex min-h-0 min-w-0 flex-col overflow-hidden rounded border border-border"
            >
              <CodePane
                title={index ? rightLabel : leftLabel}
                body={mode === "body" ? value.body : JSON.stringify(value.headers, null, 2)}
                raw={mode === "body" ? value.body : JSON.stringify(value.headers, null, 2)}
                headers={value.headers}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
export function ResponseDiffButton({
  left,
  right,
  label = "Compare responses",
}: {
  left: ComparableResponse;
  right: ComparableResponse;
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        {label}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="flex h-[85vh] max-w-6xl flex-col bg-card">
          <DialogHeader>
            <DialogTitle>Response comparison</DialogTitle>
            <DialogDescription>
              Compare status, headers and JSON or text. Ignore fields that change between requests.
            </DialogDescription>
          </DialogHeader>
          <ResponseDiff left={left} right={right} />
        </DialogContent>
      </Dialog>
    </>
  );
}
