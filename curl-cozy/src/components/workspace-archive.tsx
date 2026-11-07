import { useRef, useState } from 'react';
import { Download, Upload } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { exportWorkspace, importWorkspace, type Workspace } from '@/lib/api';
import { useInspector } from '@/components/inspector';

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

const DOCUMENT_LABELS: Record<string, string> = {
  replay_tabs: 'Replay tabs',
  flow_documents: 'Flows',
  auth_profiles: 'authentication profiles',
  intruder_documents: 'Intruder setup',
};

/** Import a chosen .slurp file as a new workspace, or merge it into an existing one. */
export function ImportWorkspaceButton() {
  const { workspaces, retryHistory } = useInspector();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<'new' | 'merge'>('new');
  const [target, setTarget] = useState('');
  const [busy, setBusy] = useState(false);

  const close = () => {
    setFile(null);
    setMode('new');
    if (input.current) input.current.value = '';
  };

  const run = async () => {
    if (!file) return;
    const mergeInto = mode === 'merge' ? target || workspaces[0]?.id : undefined;
    setBusy(true);
    try {
      const result = await importWorkspace(file, mergeInto);
      if (result.merged) {
        const skipped = result.skipped ? `, ${result.skipped} already there` : '';
        const kept = result.kept_documents.length ? `. Kept existing ${result.kept_documents.map((d) => DOCUMENT_LABELS[d] ?? d).join(', ')}` : '';
        toast.success(`Merged into “${result.workspace.name}” (${result.rows - result.skipped} added${skipped})${kept}`);
        retryHistory(true);
      } else {
        toast.success(`Imported as “${result.workspace.name}” (${result.workspace.request_count} requests)`);
      }
      close();
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <input ref={input} type="file" accept=".slurp" className="hidden" aria-label="Choose .slurp file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
      <Button type="button" variant="outline" size="sm" className="h-9" title="Import a .slurp file" onClick={() => input.current?.click()}>
        <Upload />
        Import .slurp
      </Button>
      <Dialog open={file !== null} onOpenChange={(open) => !open && !busy && close()}>
        <DialogContent className="bg-card">
          <DialogHeader>
            <DialogTitle>Import {file?.name}</DialogTitle>
            <DialogDescription>Choose where the contents of this file go. Nothing existing is overwritten.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 text-sm">
            <label className="flex items-start gap-3">
              <input type="radio" name="import-mode" className="mt-1" checked={mode === 'new'} onChange={() => setMode('new')} />
              <span>
                Create a new workspace
                <span className="block text-[11px] text-muted-foreground">Everything in the file becomes its own workspace.</span>
              </span>
            </label>
            <label className="flex items-start gap-3">
              <input type="radio" name="import-mode" className="mt-1" checked={mode === 'merge'} disabled={!workspaces.length} onChange={() => setMode('merge')} />
              <span className="flex-1">
                Merge into an existing workspace
                <span className="block text-[11px] text-muted-foreground">
                  Requests, runs and results the workspace does not have are added; ones it already has are skipped. Its own Replay tabs, Flows, profiles and Intruder setup are kept.
                </span>
                <select
                  aria-label="Workspace to merge into"
                  className="inspector-input mt-2 h-9 w-full text-sm"
                  disabled={mode !== 'merge'}
                  value={target || workspaces[0]?.id || ''}
                  onChange={(e) => setTarget(e.target.value)}
                >
                  {workspaces.map((w) => (
                    <option key={w.id} value={w.id}>
                      {w.name} ({w.request_count} requests)
                    </option>
                  ))}
                </select>
              </span>
            </label>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" disabled={busy} onClick={close}>
              Cancel
            </Button>
            <Button disabled={busy} onClick={() => void run()}>
              <Upload />
              {busy ? 'Importing…' : mode === 'merge' ? 'Merge' : 'Import'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
