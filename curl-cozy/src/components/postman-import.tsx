import { useRef, useState } from "react";
import { FileJson } from "lucide-react";
import { Button } from "./ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./ui/dialog";
import {
  MAX_POSTMAN_BYTES,
  mergePostmanVariables,
  missingPostmanVariables,
  parsePostmanCollection,
  parsePostmanEnvironment,
  type PostmanImport,
  type PostmanRequest,
} from "@/lib/postman-import";
import { readBrunoFiles } from "@/lib/bruno-import-client";
import type { ReplayVariables } from "@/lib/replay-features";

export function PostmanImportDialog({
  variables,
  slots,
  onImport,
  format = "postman",
}: {
  format?: "postman" | "bruno";
  variables: ReplayVariables;
  slots: number;
  onImport: (requests: PostmanRequest[], variables: ReplayVariables) => void;
}) {
  const bruno = format === "bruno";
  const sourceName = bruno ? "Bruno" : "Postman";
  const [open, setOpen] = useState(false),
    [collection, setCollection] = useState<PostmanImport | null>(null),
    [environment, setEnvironment] = useState<ReturnType<typeof parsePostmanEnvironment> | null>(
      null,
    ),
    [selected, setSelected] = useState<Set<number>>(new Set()),
    [error, setError] = useState(""),
    [fileError, setFileError] = useState(""),
    [busy, setBusy] = useState(false),
    [includeVariables, setIncludeVariables] = useState(true),
    [overwrite, setOverwrite] = useState(false);
  const generation = useRef(0);
  const changeOpen = (value: boolean) => {
    generation.current++;
    setOpen(value);
    setBusy(false);
    setCollection(null);
    setEnvironment(null);
    setSelected(new Set());
    setError("");
    setFileError("");
    setIncludeVariables(true);
    setOverwrite(false);
  };
  const readFiles = async (files: File[], kind: "collection" | "environment") => {
    if (!files.length) return;
    const version = ++generation.current;
    setBusy(true);
    setError("");
    setFileError("");
    if (kind === "collection") {
      setCollection(null);
      setEnvironment(null);
      setSelected(new Set());
    } else setEnvironment(null);
    try {
      if (files.reduce((sum, file) => sum + file.size, 0) > MAX_POSTMAN_BYTES)
        throw Error("Selected files exceed the 10 MB total limit.");
      if (files.length > 500) throw Error("Select at most 500 request files.");
      if (bruno && files.some((file) => file.size > 2_000_000))
        throw Error("Bruno files must be 2 MB or smaller.");
      const sources = await Promise.all(
        files.map(async (file) => ({ name: file.name, source: await file.text() })),
      );
      if (version !== generation.current) return;
      if (kind === "collection") {
        const result = bruno
          ? await readBrunoFiles("collection", sources)
          : parsePostmanCollection(sources[0]!.source);
        if (version !== generation.current) return;
        setCollection(result);
        setSelected(
          new Set(
            result.requests
              .filter((r) => r.request)
              .slice(0, Math.max(0, slots))
              .map((r) => r.id),
          ),
        );
      } else {
        const result = bruno
          ? await readBrunoFiles("environment", sources)
          : parsePostmanEnvironment(sources[0]!.source);
        if (version === generation.current) setEnvironment(result);
      }
    } catch (e) {
      if (version === generation.current)
        setFileError(e instanceof Error ? e.message : "Could not read file.");
    } finally {
      if (version === generation.current) setBusy(false);
    }
  };
  const incoming = includeVariables ? { ...collection?.variables, ...environment?.variables } : {};
  let merged = variables,
    mergeError = "";
  try {
    merged = mergePostmanVariables(variables, incoming, overwrite);
  } catch (e) {
    mergeError = (e as Error).message;
  }
  const chosen = collection?.requests.filter((r) => selected.has(r.id) && r.request) ?? [];
  const missing = missingPostmanVariables(chosen, merged);
  const conflicts = Object.keys(incoming).filter((key) => Object.hasOwn(variables, key));
  const importSelected = () => {
    try {
      if (!chosen.length) throw Error("Select at least one request.");
      if (chosen.length > slots) throw Error(`Only ${slots} Replay tab slots are available.`);
      if (mergeError) throw Error(mergeError);
      onImport(chosen, merged);
      changeOpen(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed.");
    }
  };
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => changeOpen(true)}>
        <FileJson />
        Import {sourceName}
      </Button>
      <Dialog open={open} onOpenChange={changeOpen}>
        <DialogContent className="flex max-h-[85vh] max-w-3xl flex-col bg-card">
          <DialogHeader>
            <DialogTitle>
              Import {sourceName}
              {bruno ? " requests" : " Collection"}
            </DialogTitle>
            <DialogDescription>
              {bruno
                ? "Select one or more Bruno .bru request files."
                : "Select requests from a Collection v2.0 or v2.1 JSON file."}{" "}
              Each selected request becomes a Replay tab. No requests or scripts are executed.
            </DialogDescription>
          </DialogHeader>
          <div className="min-h-0 overflow-auto space-y-4 pr-1">
            <label className="block space-y-2 text-xs">
              <span>
                {bruno
                  ? "Request .bru files (2 MB each, 10 MB total)"
                  : "Collection JSON (up to 10 MB)"}
              </span>
              <input
                aria-label={bruno ? "Bruno request files" : "Postman collection file"}
                type="file"
                multiple={bruno}
                accept={bruno ? ".bru" : ".json,application/json"}
                className="block w-full text-xs"
                disabled={busy}
                onChange={(e) => {
                  const files = Array.from(e.target.files ?? []);
                  e.target.value = "";
                  void readFiles(files, "collection");
                }}
              />
            </label>
            {busy && (
              <p role="status" className="text-xs text-muted-foreground">
                Reading file…
              </p>
            )}
            {fileError && (
              <p role="alert" className="text-xs text-destructive">
                {fileError}
              </p>
            )}
            {collection && (
              <>
                <div className="space-y-2 rounded border border-border p-3 text-xs">
                  <p className="font-medium">
                    {collection.name} · {collection.requests.length} requests · {slots} available
                    tab slots
                  </p>
                  <p className="text-muted-foreground">
                    Replay supports up to 100 tabs. Unsupported requests are disabled; review their
                    warnings below.
                  </p>
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={includeVariables}
                      onChange={(e) => setIncludeVariables(e.target.checked)}
                    />
                    {bruno
                      ? "Import environment variables"
                      : "Import collection and environment variables"}
                  </label>
                  <label className="block space-y-2">
                    <span>
                      {bruno
                        ? "Environment .bru (optional, up to 2 MB)"
                        : "Environment JSON (optional, up to 10 MB; environment values take precedence over collection values)"}
                    </span>
                    <input
                      aria-label={bruno ? "Bruno environment file" : "Postman environment file"}
                      type="file"
                      accept={bruno ? ".bru" : ".json,application/json"}
                      className="block w-full text-xs"
                      disabled={busy}
                      onChange={(e) => {
                        const files = Array.from(e.target.files ?? []);
                        e.target.value = "";
                        void readFiles(files, "environment");
                      }}
                    />
                  </label>
                  {(environment || fileError) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={busy}
                      onClick={() => {
                        setEnvironment(null);
                        setFileError("");
                      }}
                    >
                      Clear environment
                    </Button>
                  )}
                  {environment && (
                    <p>
                      Environment loaded · {Object.keys(environment.variables).length} variables
                    </p>
                  )}
                  {includeVariables && (
                    <p>
                      {Object.keys(incoming).length} incoming variables · {conflicts.length}{" "}
                      existing names. Existing workspace values are kept by default.
                    </p>
                  )}
                  {includeVariables && conflicts.length > 0 && (
                    <>
                      <p className="break-words text-muted-foreground">
                        Conflicts: {conflicts.join(", ")}
                      </p>
                      <label className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={overwrite}
                          onChange={(e) => setOverwrite(e.target.checked)}
                        />
                        Overwrite existing workspace variables
                      </label>
                    </>
                  )}
                  {missing.length > 0 && (
                    <p className="break-words text-warning">
                      Missing variables: {missing.join(", ")}. Add them in Variables before sending.
                      Dynamic variables and nested variable references are not resolved
                      automatically.
                    </p>
                  )}
                  {[...collection.warnings, ...(environment?.warnings ?? [])].map((warning, i) => (
                    <p key={i} className="text-warning">
                      {warning}
                    </p>
                  ))}
                </div>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      setSelected(
                        new Set(
                          collection.requests
                            .filter((r) => r.request)
                            .slice(0, Math.max(0, slots))
                            .map((r) => r.id),
                        ),
                      )
                    }
                  >
                    Select up to {slots}
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => setSelected(new Set())}>
                    Clear selection
                  </Button>
                  <span>{chosen.length} selected</span>
                </div>
                <div className="max-h-72 overflow-auto rounded border border-border divide-y divide-border">
                  {collection.requests.map((item) => (
                    <div key={item.id} className="space-y-2 p-3 text-xs">
                      <label className="flex items-start gap-2">
                        <input
                          className="mt-1 shrink-0"
                          type="checkbox"
                          aria-label={`Import ${item.name}`}
                          checked={selected.has(item.id)}
                          disabled={
                            !item.request || (!selected.has(item.id) && selected.size >= slots)
                          }
                          onChange={(e) => {
                            const checked = e.target.checked;
                            setSelected((prev) => {
                              const next = new Set(prev);
                              if (checked) next.add(item.id);
                              else next.delete(item.id);
                              return next;
                            });
                          }}
                        />
                        <span className="min-w-0">
                          <span className="block break-words font-medium">{item.name}</span>
                          {item.request && (
                            <span className="block break-all font-mono text-muted-foreground">
                              {item.request.method} {item.request.url}
                            </span>
                          )}
                        </span>
                      </label>
                      {item.warnings.map((warning, i) => (
                        <p key={i} className="break-words text-warning">
                          {warning}
                        </p>
                      ))}
                      {item.scripts.length > 0 && (
                        <details>
                          <summary className="cursor-pointer text-muted-foreground">
                            Original {sourceName} scripts (preview, not imported)
                          </summary>
                          <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded bg-secondary p-2 font-mono">
                            {item.scripts.join("\n\n")}
                          </pre>
                        </details>
                      )}
                    </div>
                  ))}
                </div>
              </>
            )}
            {(error || mergeError) && (
              <p role="alert" className="text-xs text-destructive">
                {error || mergeError}
              </p>
            )}
          </div>
          <div className="flex shrink-0 justify-end gap-2">
            <Button variant="outline" onClick={() => changeOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={
                busy || !!fileError || !!mergeError || !chosen.length || chosen.length > slots
              }
              onClick={importSelected}
            >
              Import {chosen.length} request{chosen.length === 1 ? "" : "s"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
