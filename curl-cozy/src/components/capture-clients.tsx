import { useCallback, useEffect, useState } from 'react';
import { Copy, MonitorSmartphone, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { createCaptureClient, deleteCaptureClient, fetchCaptureClients, type CaptureClient, type Workspace } from '@/lib/api';

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : 'Something went wrong');

/** "3 min ago" style label; clients poll continuously, so anything recent counts as online. */
function seen(value: string | null) {
  if (!value) return 'never connected';
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 90) return 'online now';
  if (seconds < 3600) return `last seen ${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `last seen ${Math.round(seconds / 3600)} h ago`;
  return `last seen ${new Date(value).toLocaleDateString()}`;
}

function copy(text: string) {
  void navigator.clipboard.writeText(text).then(() => toast.success('Copied'), () => toast.error('Could not copy'));
}

function CommandBox({ label, text }: { label: string; text: string }) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
        {label}
        <Button variant="ghost" size="sm" className="h-6 px-2 text-[11px]" onClick={() => copy(text)}>
          <Copy className="size-3" />
          Copy
        </Button>
      </div>
      <pre className="overflow-x-auto rounded border border-border bg-background p-2 font-mono text-[11px] leading-relaxed">{text}</pre>
    </div>
  );
}

function NewClientDialog({ workspaces, open, onOpenChange, onCreated }: { workspaces: Workspace[]; open: boolean; onOpenChange: (open: boolean) => void; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [workspaceId, setWorkspaceId] = useState('');
  const [scope, setScope] = useState('');
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ client: CaptureClient; token: string } | null>(null);

  const close = (next: boolean) => {
    onOpenChange(next);
    if (!next) {
      setCreated(null);
      setName('');
      setScope('');
    }
  };

  const create = async () => {
    setBusy(true);
    try {
      setCreated(await createCaptureClient(name.trim(), workspaceId || workspaces[0]?.id || ''));
      onCreated();
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const server = typeof window !== 'undefined' ? window.location.origin : 'https://your-server';
  const scopeArg = scope.trim() ? scope.split(',').map((h) => h.trim()).filter(Boolean).join(',') : 'example.com,*.example.com';
  const base = `slurp client --server ${server} --scope ${scopeArg}`;

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="bg-card">
        {created ? (
          <>
            <DialogHeader>
              <DialogTitle>Run the client on “{created.client.name}”</DialogTitle>
              <DialogDescription>
                Uploads go to workspace “{created.client.workspace_name}”. The token is shown only now; if you lose it, delete this client and create a new one.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-3">
              <CommandBox label="macOS / Linux" text={`SLURP_CLIENT_TOKEN=${created.token} ${base}`} />
              <CommandBox label="Windows PowerShell" text={`$env:SLURP_CLIENT_TOKEN="${created.token}"; ${base}`} />
              <p className="text-[11px] text-muted-foreground">
                Then point the browser or tool at the client's proxy (http://127.0.0.1:8888) and trust the CA it prints. Only hosts in <code>--scope</code> are uploaded; add <code>--redact</code> to mask credentials first.
              </p>
            </div>
            <div className="flex justify-end">
              <Button onClick={() => close(false)}>Done</Button>
            </div>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Add capture client</DialogTitle>
              <DialogDescription>A client captures traffic on another machine and uploads it here, into the workspace you choose.</DialogDescription>
            </DialogHeader>
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                void create();
              }}
            >
              <label className="block text-xs">
                Client name
                <input className="inspector-input mt-1 h-9 w-full text-sm" placeholder="e.g. work-laptop" maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />
              </label>
              <label className="block text-xs">
                Upload into workspace
                <select className="inspector-input mt-1 h-9 w-full text-sm" value={workspaceId || workspaces[0]?.id || ''} onChange={(e) => setWorkspaceId(e.target.value)}>
                  {workspaces.map((w) => (
                    <option key={w.id} value={w.id}>
                      {w.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block text-xs">
                Hosts to upload (comma separated, optional here)
                <input className="inspector-input mt-1 h-9 w-full text-sm" placeholder="api.example.com,*.example.com" value={scope} onChange={(e) => setScope(e.target.value)} />
                <span className="text-[11px] text-muted-foreground">Used to prepare the command. Everything else stays on the client's machine.</span>
              </label>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => close(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={busy || !name.trim() || !workspaces.length}>
                  Create client
                </Button>
              </div>
            </form>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

/** Remote machines that capture traffic and upload it into a workspace of this server. */
export function CaptureClients({ workspaces }: { workspaces: Workspace[] }) {
  const [clients, setClients] = useState<CaptureClient[]>([]);
  const [adding, setAdding] = useState(false);
  const [revoking, setRevoking] = useState<CaptureClient | null>(null);

  const load = useCallback(() => {
    fetchCaptureClients().then(setClients, () => undefined);
  }, []);
  useEffect(() => {
    load();
    const timer = setInterval(load, 15_000);
    return () => clearInterval(timer);
  }, [load, workspaces.length]);

  return (
    <section className="shrink-0 border-t border-border px-6 py-4">
      <div className="flex items-center gap-3">
        <MonitorSmartphone className="size-4 text-muted-foreground" />
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-medium">Capture clients</h2>
          <p className="text-[11px] text-muted-foreground">Other machines running <code>slurp client</code> that upload traffic into a workspace here.</p>
        </div>
        <Button variant="outline" size="sm" className="h-8 text-xs" onClick={() => setAdding(true)}>
          <Plus className="size-3" />
          Add client
        </Button>
      </div>
      {clients.length > 0 && (
        <ul className="mt-3 divide-y divide-border rounded border border-border">
          {clients.map((c) => (
            <li key={c.id} className="flex items-center gap-3 px-3 py-2 text-xs">
              <span className={`size-1.5 rounded-full ${seen(c.last_seen_at) === 'online now' ? 'bg-primary' : 'bg-muted-foreground/40'}`} />
              <span className="font-medium">{c.name}</span>
              <span className="text-muted-foreground">→ {c.workspace_name ?? 'deleted workspace'}</span>
              <span className="ml-auto text-muted-foreground">{seen(c.last_seen_at)}</span>
              <Button variant="ghost" size="icon" className="size-7 text-muted-foreground" aria-label={`Revoke ${c.name}`} title="Revoke this client" onClick={() => setRevoking(c)}>
                <Trash2 />
              </Button>
            </li>
          ))}
        </ul>
      )}
      <NewClientDialog workspaces={workspaces} open={adding} onOpenChange={setAdding} onCreated={load} />
      <Dialog open={revoking !== null} onOpenChange={(open) => !open && setRevoking(null)}>
        <DialogContent className="bg-card">
          <DialogHeader>
            <DialogTitle>Revoke “{revoking?.name}”?</DialogTitle>
            <DialogDescription>Its token stops working immediately. Traffic it already uploaded stays in the workspace.</DialogDescription>
          </DialogHeader>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setRevoking(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={async () => {
                if (!revoking) return;
                try {
                  await deleteCaptureClient(revoking.id);
                  toast.success('Client revoked');
                  setRevoking(null);
                  load();
                } catch (e) {
                  toast.error(errorMessage(e));
                }
              }}
            >
              Revoke client
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </section>
  );
}
