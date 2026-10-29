import { useMemo, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { ExportWorkspaceDialog, ImportWorkspaceButton } from '@/components/workspace-archive';
import { ArrowUpRight, Check, Download, Folder, Layers, Pencil, Plus, Radio, Search, Trash2, TriangleAlert, X } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { cn } from '@/lib/utils';
import { clearTraffic, type Workspace } from '@/lib/api';
import { TEMP_WORKSPACE } from '@/lib/session';
import { ALL_WORKSPACES, useInspector } from '@/components/inspector';

const MAX_NAME = 60;
const DEFAULT_ID = 'default';

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : 'Something went wrong');

function Badge({ children, tone }: { children: React.ReactNode; tone: 'primary' | 'muted' }) {
  return (
    <span
      className={cn(
        'rounded px-1.5 py-0.5 text-[10px] font-medium',
        tone === 'primary' ? 'bg-primary/10 text-primary' : 'bg-secondary text-muted-foreground',
      )}
    >
      {children}
    </span>
  );
}

function WorkspaceRow({ workspace }: { workspace: Workspace }) {
  const { view, setView, renameWorkspace, activateWorkspace, deleteWorkspace } = useInspector();
  const navigate = useNavigate();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(workspace.name);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [busy, setBusy] = useState(false);
  const isDefault = workspace.id === DEFAULT_ID;
  const viewing = view === workspace.id;

  // Wrap each backend call so failures surface as a toast and the buttons are not double-submitted.
  const run = async (action: () => Promise<void>, success?: string) => {
    setBusy(true);
    try {
      await action();
      if (success) toast.success(success);
      return true;
    } catch (e) {
      toast.error(errorMessage(e));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const saveName = async () => {
    const next = name.trim();
    if (next === workspace.name) return setEditing(false);
    if (await run(() => renameWorkspace(workspace.id, next), 'Workspace renamed')) setEditing(false);
  };

  return (
    <li className={cn('flex flex-wrap items-center gap-3 border-b border-border px-6 py-3', viewing && 'bg-primary/5')}>
      <Folder className="size-4 shrink-0 text-muted-foreground" />
      <div className="min-w-0 flex-1">
        {editing ? (
          <form
            className="flex items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void saveName();
            }}
          >
            <input
              autoFocus
              aria-label={`Rename workspace ${workspace.name}`}
              className="inspector-input h-8 w-64 max-w-full text-sm"
              maxLength={MAX_NAME}
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Escape') {
                  setName(workspace.name);
                  setEditing(false);
                }
              }}
            />
            <Button type="submit" size="icon" variant="ghost" className="size-8" disabled={busy || !name.trim()} aria-label="Save name">
              <Check />
            </Button>
            <Button
              type="button"
              size="icon"
              variant="ghost"
              className="size-8"
              aria-label="Cancel rename"
              onClick={() => {
                setName(workspace.name);
                setEditing(false);
              }}
            >
              <X />
            </Button>
          </form>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-medium">{workspace.name}</span>
            {viewing && <Badge tone="muted">Viewing</Badge>}
            {workspace.active && <Badge tone="primary">Capturing</Badge>}
            {isDefault && <Badge tone="muted">Built-in</Badge>}
          </div>
        )}
        <div className="mt-1 text-[11px] text-muted-foreground">
          <span className="font-mono">{workspace.request_count}</span> requests · created{' '}
          {new Date(workspace.created_at).toLocaleDateString()}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-1">
        <Button
          variant="outline"
          size="sm"
          className="h-8 text-xs"
          onClick={() => {
            setView(workspace.id);
            void navigate({ to: '/' });
          }}
        >
          View history
          <ArrowUpRight className="size-3" />
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-8 text-xs"
          disabled={busy || workspace.active}
          title="Capture newly proxied traffic into this workspace"
          onClick={() => run(() => activateWorkspace(workspace.id), `Now capturing into “${workspace.name}”`)}
        >
          <Radio className="size-3" />
          Capture here
        </Button>
        <Button variant="ghost" size="icon" className="size-8 text-muted-foreground" aria-label={`Export ${workspace.name}`} title="Export as .slurp file" disabled={busy} onClick={() => setExporting(true)}>
          <Download />
        </Button>
        <Button variant="ghost" size="icon" className="size-8 text-muted-foreground" aria-label={`Rename ${workspace.name}`} disabled={busy} onClick={() => setEditing(true)}>
          <Pencil />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="size-8 text-muted-foreground"
          aria-label={`Delete ${workspace.name}`}
          disabled={busy || isDefault}
          title={isDefault ? 'The default workspace cannot be deleted' : 'Delete workspace'}
          onClick={() => setConfirmDelete(true)}
        >
          <Trash2 />
        </Button>
      </div>
      <ExportWorkspaceDialog workspace={workspace} open={exporting} onOpenChange={setExporting} />
      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <DialogContent className="bg-card">
          <DialogHeader>
            <DialogTitle>Delete “{workspace.name}”?</DialogTitle>
            <DialogDescription>
              This permanently deletes the workspace and its {workspace.request_count} captured requests.
              {workspace.active && ' Capturing will switch back to the Default workspace.'}
            </DialogDescription>
          </DialogHeader>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={busy}
              onClick={async () => {
                if (await run(() => deleteWorkspace(workspace.id), 'Workspace deleted')) setConfirmDelete(false);
              }}
            >
              Delete workspace
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </li>
  );
}

/** The in-memory session: not saved anywhere, gone when the tool closes. */
function TemporaryRow() {
  const { view, setView, session, chooseTemporary } = useInspector();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const capturing = session?.target === 'temporary';
  const count = session?.temporary_count ?? 0;

  const run = async (action: () => Promise<void>, success: string) => {
    setBusy(true);
    try {
      await action();
      toast.success(success);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <li className={cn('flex flex-wrap items-center gap-3 border-b border-border px-6 py-3', view === TEMP_WORKSPACE && 'bg-warning/5')}>
      <TriangleAlert className="size-4 shrink-0 text-warning" />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="truncate text-sm font-medium">Temporary session</span>
          {view === TEMP_WORKSPACE && <Badge tone="muted">Viewing</Badge>}
          {capturing && <Badge tone="primary">Capturing</Badge>}
          <span className="rounded bg-warning/10 px-1.5 py-0.5 text-[10px] font-medium text-warning">Not saved</span>
        </div>
        <div className="mt-1 text-[11px] text-muted-foreground">
          <span className="font-mono">{count}</span> requests in memory only; lost when the tool closes
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-1">
        <Button
          variant="outline"
          size="sm"
          className="h-8 text-xs"
          onClick={() => {
            setView(TEMP_WORKSPACE);
            void navigate({ to: '/' });
          }}
        >
          View history
          <ArrowUpRight className="size-3" />
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-8 text-xs"
          disabled={busy || capturing}
          title="Keep new requests in memory only"
          onClick={() => run(chooseTemporary, 'New requests are kept in memory only')}
        >
          <Radio className="size-3" />
          Capture here
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="size-8 text-muted-foreground"
          aria-label="Clear temporary session"
          disabled={busy || count === 0}
          onClick={() => run(() => clearTraffic(TEMP_WORKSPACE), 'Temporary session cleared')}
        >
          <Trash2 />
        </Button>
      </div>
    </li>
  );
}

export function WorkspacesView() {
  const { workspaces, view, setView, createWorkspace, proxyStatus, session } = useInspector();
  const navigate = useNavigate();
  const [newName, setNewName] = useState('');
  const [query, setQuery] = useState('');
  const [creating, setCreating] = useState(false);

  const total = useMemo(() => workspaces.reduce((n, w) => n + w.request_count, 0), [workspaces]);
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? workspaces.filter((w) => w.name.toLowerCase().includes(q)) : workspaces;
  }, [workspaces, query]);
  const offline = proxyStatus !== 'connected' && workspaces.length === 0;

  const create = async () => {
    setCreating(true);
    try {
      const w = await createWorkspace(newName);
      setNewName('');
      toast.success(`Workspace “${w.name}” created`);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setCreating(false);
    }
  };

  return (
    <>
      <div className="flex shrink-0 flex-col gap-1 px-6 py-5">
        <h1 className="text-xl font-semibold">Workspaces</h1>
        <p className="text-xs text-muted-foreground">
          Group captured requests so you can find them again later. New traffic is saved into the workspace marked
          “Capturing”.
        </p>
      </div>

      {offline ? (
        <div role="status" className="mx-6 rounded border border-border bg-card p-4 text-sm text-muted-foreground">
          Workspaces are stored by the proxy. Start it with <code className="font-mono text-foreground">slurp</code>{' '}
          and this page will connect automatically.
        </div>
      ) : (
        <>
          <form
            className="flex shrink-0 items-center gap-2 px-6 pb-4"
            onSubmit={(e) => {
              e.preventDefault();
              void create();
            }}
          >
            <input
              aria-label="New workspace name"
              className="inspector-input h-9 w-72 max-w-full text-sm"
              placeholder="New workspace name"
              maxLength={MAX_NAME}
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
            <Button type="submit" size="sm" className="h-9" disabled={creating || !newName.trim()}>
              <Plus />
              Create workspace
            </Button>
            <ImportWorkspaceButton />
            <div className="relative ml-auto min-w-0 max-w-64 flex-1">
              <Search className="absolute left-3 top-2.5 size-3.5 text-muted-foreground" />
              <input
                aria-label="Search workspaces"
                className="inspector-input h-9 w-full pl-9 text-xs"
                placeholder="Search workspaces…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
          </form>

          <ul className="min-h-0 flex-1 overflow-auto border-t border-border">
            {!query && (
              <li className={cn('flex items-center gap-3 border-b border-border px-6 py-3', view === ALL_WORKSPACES && 'bg-primary/5')}>
                <Layers className="size-4 shrink-0 text-muted-foreground" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">All saved workspaces</span>
                    {view === ALL_WORKSPACES && <Badge tone="muted">Viewing</Badge>}
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    <span className="font-mono">{total}</span> saved requests across {workspaces.length} workspaces
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 text-xs"
                  onClick={() => {
                    setView(ALL_WORKSPACES);
                    void navigate({ to: '/' });
                  }}
                >
                  View history
                  <ArrowUpRight className="size-3" />
                </Button>
              </li>
            )}
            {visible.map((w) => (
              <WorkspaceRow key={w.id} workspace={w} />
            ))}
            {!query && session && (session.target !== 'workspace' || session.temporary_count > 0) && <TemporaryRow />}
            {!visible.length && (
              <li className="flex h-32 items-center justify-center text-sm text-muted-foreground">
                No workspace matches “{query}”.
              </li>
            )}
          </ul>
        </>
      )}
    </>
  );
}
