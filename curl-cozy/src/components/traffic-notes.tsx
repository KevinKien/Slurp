import { useState } from "react";
import { StickyNote } from "lucide-react";
import { Button } from "./ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./ui/dialog";
export function TrafficNotes({
  notes,
  onSave,
}: {
  notes: string;
  onSave: (notes: string) => Promise<void>;
}) {
  const [open, setOpen] = useState(false),
    [draft, setDraft] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="h-7 text-[10px]"
        title={notes || "Add notes"}
        onClick={() => {
          setDraft(notes);
          setError("");
          setOpen(true);
        }}
      >
        <StickyNote className="size-3" />
        {notes ? "Edit notes" : "Add notes"}
      </Button>
      <Dialog
        open={open}
        onOpenChange={(value) => {
          if (!busy) setOpen(value);
        }}
      >
        <DialogContent className="bg-card">
          <DialogHeader>
            <DialogTitle>Request notes</DialogTitle>
            <DialogDescription>Keep findings and context with this request.</DialogDescription>
          </DialogHeader>
          <textarea
            aria-label="Request notes"
            className="inspector-input min-h-48 text-sm"
            maxLength={16000}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
          />
          {error && (
            <p role="alert" className="text-xs text-destructive">
              {error}
            </p>
          )}
          <Button
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setError("");
              try {
                await onSave(draft);
                setOpen(false);
              } catch (e) {
                setError(e instanceof Error ? e.message : "Could not save notes");
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? "Saving…" : "Save notes"}
          </Button>
        </DialogContent>
      </Dialog>
    </>
  );
}
