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
import { MAX_BURP_BYTES } from "@/lib/burp-import";
import { readBurpExport } from "@/lib/burp-import-client";
import type { ReplayVariables } from "@/lib/replay-features";

export type ImportFormat = "postman" | "bruno" | "burp";

interface FormatConfig {
  sourceName: string;
  title: string;
  description: string;
  accept: string;
  inputLabel: string;
  fileLabel: string;
  variableLabel: string;
  environmentLabel: string;
  environmentInputLabel: string;
  environmentAccept: string;
  maxTotalBytes: number;
  /** Per-file ceiling, used by formats that accept several files. */
  perFileBytes?: number;
  maxFiles: number;
  multiple: boolean;
  supportsEnvironment: boolean;
  note?: string;
}

const FORMATS: Record<ImportFormat, FormatConfig> = {
  postman: {
    sourceName: "Postman",
    title: "Import Postman Collection",
    description:
      "Select requests from a Collection v2.0 or v2.1 JSON file. Each selected request becomes a Replay tab. No requests or scripts are executed.",
    accept: ".json,application/json",
    inputLabel: "Postman collection file",
    fileLabel: "Collection JSON (up to 10 MB)",
    variableLabel: "Import collection and environment variables",
    environmentLabel:
      "Environment JSON (optional, up to 10 MB; environment values take precedence over collection values)",
    environmentInputLabel: "Postman environment file",
    environmentAccept: ".json,application/json",
    maxTotalBytes: MAX_POSTMAN_BYTES,
    maxFiles: 1,
    multiple: false,
    supportsEnvironment: true,
  },
  bruno: {
    sourceName: "Bruno",
    title: "Import Bruno requests",
    description:
      "Select one or more Bruno .bru request files. Each selected request becomes a Replay tab. No requests or scripts are executed.",
    accept: ".bru",
    inputLabel: "Bruno request files",
    fileLabel: "Request .bru files (2 MB each, 10 MB total)",
    variableLabel: "Import environment variables",
    environmentLabel: "Environment .bru (optional, up to 2 MB)",
    environmentInputLabel: "Bruno environment file",
    environmentAccept: ".bru",
    maxTotalBytes: MAX_POSTMAN_BYTES,
    perFileBytes: 2_000_000,
    maxFiles: 500,
    multiple: true,
    supportsEnvironment: true,
  },
  burp: {
    sourceName: "Burp",
    title: "Import Burp export",
    description:
      "Select a Burp XML export of saved items (right-click → Save items, with base64 encoding enabled) or a prub JSON project export. Each selected request becomes a Replay tab; responses and scripts are not imported.",
    accept: ".xml,.burp,.json,application/xml,text/xml,application/json",
    inputLabel: "Burp export file",
    fileLabel: "Burp XML export or prub JSON (up to 10 MB)",
    variableLabel: "",
    environmentLabel: "",
    environmentInputLabel: "",
    environmentAccept: "",
    maxTotalBytes: MAX_BURP_BYTES,
    maxFiles: 1,
    multiple: false,
    supportsEnvironment: false,
    note: "A .burp project file is a proprietary binary format. Export the items as XML from Burp, or convert the project with the community prub tool and import its JSON.",
  },
};

export function PostmanImportDialog({
  variables,
  slots,
  onImport,
  format = "postman",
}: {
  format?: ImportFormat;
  variables: ReplayVariables;
  slots: number;
  onImport: (requests: PostmanRequest[], variables: ReplayVariables) => void;
}) {
  const config = FORMATS[format];
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
      if (files.reduce((sum, file) => sum + file.size, 0) > config.maxTotalBytes)
        throw Error(
          format === "burp"
            ? "File exceeds the 10 MB limit."
            : "Selected files exceed the 10 MB total limit.",
        );
      if (files.length > config.maxFiles)
        throw Error(`Select at most ${config.maxFiles.toLocaleString("en-US")} request files.`);
      const perFileBytes = config.perFileBytes;
      if (perFileBytes && files.some((file) => file.size > perFileBytes))
        throw Error(
          `${config.sourceName} files must be ${Math.round(perFileBytes / 1_000_000)} MB or smaller.`,
        );
      const sources = await Promise.all(
        files.map(async (file) => ({ name: file.name, source: await file.text() })),
      );
      if (version !== generation.current) return;
      const first = sources[0];
      if (!first) throw Error("Could not read the selected file.");
      if (kind === "collection") {
        const result =
          format === "bruno"
            ? await readBrunoFiles("collection", sources)
            : format === "burp"
              ? await readBurpExport(first.name, first.source)
              : parsePostmanCollection(first.source);
        if (version !== generation.current) return;
        setCollection(result);
        setSelected(
          new Set(
            result.requests
              .filter((request) => request.request)
              .slice(0, Math.max(0, slots))
              .map((request) => request.id),
          ),
        );
      } else {
        const result =
          format === "bruno"
            ? await readBrunoFiles("environment", sources)
            : parsePostmanEnvironment(first.source);
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
  const chosen =
    collection?.requests.filter((request) => selected.has(request.id) && request.request) ?? [];
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
        Import {config.sourceName}
      </Button>
      <Dialog open={open} onOpenChange={changeOpen}>
        <DialogContent className="flex max-h-[85vh] max-w-3xl flex-col bg-card">
          <DialogHeader>
            <DialogTitle>{config.title}</DialogTitle>
            <DialogDescription>{config.description}</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 overflow-auto space-y-4 pr-1">
            <label className="block space-y-2 text-xs">
              <span>{config.fileLabel}</span>
              <input
                aria-label={config.inputLabel}
                type="file"
                multiple={config.multiple}
                accept={config.accept}
                className="block w-full text-xs"
                disabled={busy}
                onChange={(e) => {
                  const files = Array.from(e.target.files ?? []);
                  e.target.value = "";
                  void readFiles(files, "collection");
                }}
              />
            </label>
            {config.note && <p className="text-xs text-muted-foreground">{config.note}</p>}
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
                  {config.supportsEnvironment && (
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={includeVariables}
                        onChange={(e) => setIncludeVariables(e.target.checked)}
                      />
                      {config.variableLabel}
                    </label>
                  )}
                  {config.supportsEnvironment && (
                    <label className="block space-y-2">
                      <span>{config.environmentLabel}</span>
                      <input
                        aria-label={config.environmentInputLabel}
                        type="file"
                        accept={config.environmentAccept}
                        className="block w-full text-xs"
                        disabled={busy}
                        onChange={(e) => {
                          const files = Array.from(e.target.files ?? []);
                          e.target.value = "";
                          void readFiles(files, "environment");
                        }}
                      />
                    </label>
                  )}
                  {config.supportsEnvironment && (environment || fileError) && (
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
                  {config.supportsEnvironment && includeVariables && (
                    <p>
                      {Object.keys(incoming).length} incoming variables · {conflicts.length}{" "}
                      existing names. Existing workspace values are kept by default.
                    </p>
                  )}
                  {config.supportsEnvironment && includeVariables && conflicts.length > 0 && (
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
                            .filter((request) => request.request)
                            .slice(0, Math.max(0, slots))
                            .map((request) => request.id),
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
                            Original {config.sourceName} scripts (preview, not imported)
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
