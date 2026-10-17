import { useState } from 'react';
import { Folder, Plus, TriangleAlert } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import type { Workspace } from '@/lib/api';

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : 'Something went wrong');

interface Props {
  workspaces: Workspace[];
  onChoose: (id: string) => Promise<void>;
  onCreate: (name: string) => Promise<void>;
  onTemporary: () => Promise<void>;
}

/**
 * Blocks the app until the user decides where captured requests are saved. Shown every time the
 * tool starts: pick a workspace, create one, or go on without one (nothing saved).
 */
export function WorkspaceGate({ workspaces, onChoose, onCreate, onTemporary }: Props) {
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);

  // One place for the busy flag and error toast so no action can be double-submitted.
  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    try {
      await action();
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center overflow-auto bg-background/95 p-4 backdrop-blur-sm">
      <div role="dialog" aria-modal="true" aria-labelledby="gate-title" className="w-full max-w-lg rounded-lg border border-border bg-card shadow-lg">
        <div className="border-b border-border px-6 py-5">
          <h2 id="gate-title" className="text-lg font-semibold">
            Choose a workspace
          </h2>
          <p className="mt-1.5 text-xs leading-5 text-muted-foreground">
            Captured, intercepted and replayed requests are saved into the workspace you pick, so you can find them again later.
          </p>
        </div>

        <div className="max-h-64 overflow-auto border-b border-border">
          {workspaces.length === 0 ? (
            <p className="px-6 py-4 text-xs text-muted-foreground">Loading workspaces…</p>
          ) : (
            <ul>
              {workspaces.map((w) => (
                <li key={w.id}>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => run(() => onChoose(w.id))}
                    className="flex w-full items-center gap-3 border-b border-border/50 px-6 py-3 text-left text-sm last:border-0 hover:bg-muted disabled:opacity-60"
                  >
                    <Folder className="size-4 shrink-0 text-muted-foreground" />
                    <span className="min-w-0 flex-1 truncate">{w.name}</span>
                    <span className="font-mono text-[11px] text-muted-foreground">{w.request_count} requests</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <form
          className="flex items-center gap-2 border-b border-border px-6 py-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim() && !busy) void run(() => onCreate(name));
          }}
        >
          <input
            aria-label="New workspace name"
            className="inspector-input h-9 min-w-0 flex-1 text-sm"
            placeholder="New workspace name"
            maxLength={60}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <Button type="submit" size="sm" className="h-9" disabled={busy || !name.trim()}>
            <Plus />
            Create and start
          </Button>
        </form>

        <div className="px-6 py-4">
          <Button variant="ghost" size="sm" className="h-8 px-2 text-xs text-muted-foreground" disabled={busy} onClick={() => run(onTemporary)}>
            Continue without a workspace
          </Button>
          <p className="mt-1.5 flex items-start gap-1.5 text-[11px] leading-4 text-warning">
            <TriangleAlert className="mt-px size-3 shrink-0" />
            Nothing is saved. Requests are kept in memory only and are lost when you close the tool.
          </p>
        </div>
      </div>
    </div>
  );
}
