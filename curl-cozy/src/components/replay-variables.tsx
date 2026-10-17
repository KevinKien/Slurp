import { useState } from "react";
import { Braces, Plus, X } from "lucide-react";
import { Button } from "./ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./ui/dialog";
import { variableName, type ReplayVariables } from "@/lib/replay-features";

export function ReplayVariablesEditor({
  variables,
  onApply,
}: {
  variables: ReplayVariables;
  onApply: (value: ReplayVariables) => void;
}) {
  const [open, setOpen] = useState(false),
    [rows, setRows] = useState<[string, string][]>([]),
    [error, setError] = useState("");
  const apply = () => {
    const seen = new Set<string>();
    for (const [name, value] of rows) {
      if (!variableName.test(name)) {
        setError(
          "Names must start with a letter or underscore and contain letters, digits, _, . or -.",
        );
        return;
      }
      if (seen.has(name)) {
        setError(`Duplicate variable: ${name}`);
        return;
      }
      seen.add(name);
      if (new TextEncoder().encode(value).length > 64_000) {
        setError(`Value too large: ${name}`);
        return;
      }
    }
    onApply(Object.fromEntries(rows));
    setOpen(false);
  };
  return (
    <>
      <Button
        variant="outline"
        size="sm"
        onClick={() => {
          setRows(Object.entries(variables));
          setError("");
          setOpen(true);
        }}
      >
        <Braces />
        Variables{Object.keys(variables).length > 0 && ` (${Object.keys(variables).length})`}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="flex max-h-[80vh] max-w-2xl flex-col bg-card">
          <DialogHeader>
            <DialogTitle>Shared Replay variables</DialogTitle>
            <DialogDescription>
              Use {"{{base_url}}"} or {"{{token}}"} in URL, headers and body. Values are shared
              across tabs and stored with the selected workspace. Temporary sessions keep them in
              memory.
            </DialogDescription>
          </DialogHeader>
          <div className="min-h-0 overflow-auto">
            <div className="mb-2 grid grid-cols-[1fr_2fr_28px] gap-2 text-xs text-muted-foreground">
              <span>Name</span>
              <span>Value</span>
            </div>
            {rows.map(([name, value], i) => (
              <div key={i} className="mb-2 grid grid-cols-[1fr_2fr_28px] gap-2">
                <input
                  aria-label={`Variable name ${i + 1}`}
                  className="inspector-input min-w-0 font-mono text-xs"
                  value={name}
                  maxLength={100}
                  onChange={(e) =>
                    setRows((prev) => prev.map((r, n) => (n === i ? [e.target.value, r[1]] : r)))
                  }
                />
                <input
                  aria-label={`Variable value ${i + 1}`}
                  className="inspector-input min-w-0 font-mono text-xs"
                  value={value}
                  onChange={(e) =>
                    setRows((prev) => prev.map((r, n) => (n === i ? [r[0], e.target.value] : r)))
                  }
                />
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  aria-label={`Remove variable ${i + 1}`}
                  onClick={() => setRows((prev) => prev.filter((_, n) => n !== i))}
                >
                  <X />
                </Button>
              </div>
            ))}
          </div>
          {error && (
            <p role="alert" className="text-xs text-destructive">
              {error}
            </p>
          )}
          <div className="flex justify-between">
            <Button
              variant="outline"
              size="sm"
              disabled={rows.length >= 100}
              onClick={() => setRows((prev) => [...prev, ["", ""]])}
            >
              <Plus />
              Add variable
            </Button>
            <Button size="sm" onClick={apply}>
              Apply variables
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
