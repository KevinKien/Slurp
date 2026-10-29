import { useRef, useState } from 'react';
import { Download, Upload } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { exportWorkspace, importWorkspace, type Workspace } from '@/lib/api';

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : 'Something went wrong');

function Option({ id, checked, disabled, onChange, label, hint }: { id: string; checked: boolean; disabled?: boolean; onChange: (value: boolean) => void; label: string; hint: string }) {
  return (
    <div className="flex items-start gap-3">
      <Checkbox id={id} className="mt-0.5" checked={checked} disabled={disabled} onCheckedChange={(value) => onChange(value === true)} />
      <label htmlFor={id} className="text-sm">
        {label}
        <span className="block text-[11px] text-muted-foreground">{hint}</span>
      </label>
    </div>
  );
}

/** Choose what goes into a `.slurp` file, then download it. */
export function ExportWorkspaceDialog({ workspace, open, onOpenChange }: { workspace: Workspace; open: boolean; onOpenChange: (open: boolean) => void }) {
  const [profiles, setProfiles] = useState(true);
  const [intruder, setIntruder] = useState(true);
  const [redact, setRedact] = useState(false);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    try {
      const { blob, filename } = await exportWorkspace(workspace.id, { profiles, intruder, redact });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      toast.success(`Exported “${workspace.name}”`);
      onOpenChange(false);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card">
        <DialogHeader>
          <DialogTitle>Export “{workspace.name}”</DialogTitle>
          <DialogDescription>
            Saves traffic, WebSocket history, Replay tabs and runs, scans, Flows and the Authorization Matrix to a .slurp file.
            Anyone with the file can read its contents, including any credentials in captured requests.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <Option id="export-redact" checked={redact} onChange={setRedact} label="Redact secrets" hint="Masks Authorization, Cookie and token-like values in headers and saved documents. Request and response bodies are not scanned." />
          <Option id="export-profiles" checked={profiles && !redact} disabled={redact} onChange={setProfiles} label="Include authentication profiles" hint="Cookies, tokens and headers saved for the Authorization Matrix. Never included when redacting." />
          <Option id="export-intruder" checked={intruder} onChange={setIntruder} label="Include Intruder data" hint="Payload lists, runs and results. These can be large." />
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={busy} onClick={() => void save()}>
            <Download />
            {busy ? 'Exporting…' : 'Export .slurp'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/** Creates a new workspace from a chosen .slurp file; existing workspaces are never modified. */
export function ImportWorkspaceButton() {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);

  const choose = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true);
    try {
      const { workspace } = await importWorkspace(file);
      toast.success(`Imported as “${workspace.name}” (${workspace.request_count} requests)`);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
      if (input.current) input.current.value = '';
    }
  };

  return (
    <>
      <input ref={input} type="file" accept=".slurp" className="hidden" aria-label="Choose .slurp file" onChange={(e) => void choose(e.target.files?.[0])} />
      <Button type="button" variant="outline" size="sm" className="h-9" disabled={busy} title="Import a .slurp file as a new workspace" onClick={() => input.current?.click()}>
        <Upload />
        {busy ? 'Importing…' : 'Import .slurp'}
      </Button>
    </>
  );
}
