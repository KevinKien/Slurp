import { useCallback, useEffect, useState } from 'react';
import { ArrowRightLeft, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { createReverseProxy, deleteReverseProxy, fetchReverseProxies, setReverseProxyEnabled, type ReverseProxy } from '@/lib/api';

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : 'Something went wrong');
const isLoopback = (listen: string) => /^(127\.|\[::1\]|localhost)/.test(listen);

/** Listeners that forward every request to one fixed upstream, for clients that cannot use a proxy. */
export function ReverseProxySettings() {
  const [state, setState] = useState<{ available: boolean; rules: ReverseProxy[] } | null>(null);
  const [name, setName] = useState('');
  const [listen, setListen] = useState('127.0.0.1:9000');
  const [upstream, setUpstream] = useState('');
  const [tls, setTls] = useState(false);
  const [keepHost, setKeepHost] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    fetchReverseProxies().then(setState, () => undefined);
  }, []);
  useEffect(() => {
    load();
    const timer = setInterval(load, 10_000);
    return () => clearInterval(timer);
  }, [load]);

  const run = async (action: () => Promise<unknown>, success?: string) => {
    setBusy(true);
    try {
      await action();
      if (success) toast.success(success);
      load();
      return true;
    } catch (e) {
      toast.error(errorMessage(e));
      return false;
    } finally {
      setBusy(false);
    }
  };

  if (!state?.available) return null;

  const create = async () => {
    const ok = await run(() => createReverseProxy({ name: name.trim() || upstream.trim(), listen: listen.trim(), upstream: upstream.trim(), tls, rewrite_host: !keepHost }), 'Reverse proxy started');
    if (ok) {
      setName('');
      setUpstream('');
    }
  };

  return (
    <section className="mt-8 space-y-3 border-b border-border pb-6" aria-label="Reverse proxies">
      <h2 className="text-sm font-medium">Reverse proxies</h2>
      <p className="text-xs leading-5 text-muted-foreground">
        Listen on an address and forward every request to one upstream, capturing it in History. Use it when the client cannot be given a proxy: change its URL to the listener instead,
        for example <code>http://127.0.0.1:9000</code> in place of <code>https://api.example.com</code>.
      </p>
      <form
        className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]"
        onSubmit={(e) => {
          e.preventDefault();
          void create();
        }}
      >
        <input aria-label="Reverse proxy listen address" className="inspector-input h-9 text-sm" placeholder="Listen, e.g. 127.0.0.1:9000" value={listen} onChange={(e) => setListen(e.target.value)} />
        <input aria-label="Reverse proxy upstream" className="inspector-input h-9 text-sm" placeholder="Upstream, e.g. https://api.example.com" value={upstream} onChange={(e) => setUpstream(e.target.value)} />
        <Button type="submit" size="sm" className="h-9" disabled={busy || !listen.trim() || !upstream.trim()}>
          <Plus />
          Add
        </Button>
        <input aria-label="Reverse proxy name" className="inspector-input h-9 text-sm sm:col-span-3" placeholder="Name (optional)" maxLength={60} value={name} onChange={(e) => setName(e.target.value)} />
        <label className="flex items-center gap-2 text-xs sm:col-span-3">
          <input type="checkbox" checked={tls} onChange={(e) => setTls(e.target.checked)} />
          Serve HTTPS on the listener (certificate signed by the Slurp CA, so the client must trust it)
        </label>
        <label className="flex items-center gap-2 text-xs sm:col-span-3">
          <input type="checkbox" checked={keepHost} onChange={(e) => setKeepHost(e.target.checked)} />
          Keep the client's Host header (by default the upstream's own host is sent)
        </label>
      </form>
      {state.rules.length > 0 && (
        <ul className="divide-y divide-border rounded border border-border text-xs">
          {state.rules.map((rule) => (
            <li key={rule.id} className="flex items-start gap-3 px-3 py-2">
              <ArrowRightLeft className={`mt-0.5 size-4 shrink-0 ${rule.running ? 'text-primary' : 'text-muted-foreground'}`} />
              <div className="min-w-0 flex-1">
                <div className="font-medium">
                  {rule.name}
                  {rule.tls && <span className="ml-2 rounded bg-secondary px-1.5 py-0.5 text-[10px] font-normal text-muted-foreground">HTTPS listener</span>}
                  {!isLoopback(rule.listen) && <span className="ml-2 rounded bg-warning/10 px-1.5 py-0.5 text-[10px] font-normal text-warning">Reachable from the network, no authentication</span>}
                </div>
                <div className="truncate font-mono text-[11px] text-muted-foreground">
                  {rule.listen} → {rule.upstream}
                </div>
                {rule.error && <div className="text-destructive" role="alert">{rule.error}</div>}
              </div>
              <Switch aria-label={`${rule.running ? 'Stop' : 'Start'} ${rule.name}`} checked={rule.running} disabled={busy} onCheckedChange={(on) => void run(() => setReverseProxyEnabled(rule.id, on))} />
              <Button variant="ghost" size="icon" className="size-7 shrink-0 text-muted-foreground" aria-label={`Delete ${rule.name}`} disabled={busy} onClick={() => void run(() => deleteReverseProxy(rule.id), 'Reverse proxy deleted')}>
                <Trash2 />
              </Button>
            </li>
          ))}
        </ul>
      )}
      <p className="text-xs leading-5 text-muted-foreground">
        Redirects and cookies that name the upstream are passed through unchanged. Existing connections finish when a reverse proxy is stopped.
      </p>
    </section>
  );
}
