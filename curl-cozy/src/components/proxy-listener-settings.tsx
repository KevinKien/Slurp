import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { fetchProxyInterfaces, proxyListenerSettings, type ProxyLocalInterface, type ProxyListenerSettings } from '@/lib/api';

export function ProxyListenerSettingsPanel() {
  const [current, setCurrent] = useState<ProxyListenerSettings | null>(null);
  const [port, setPort] = useState('');
  const [host, setHost] = useState('');
  const [interfaces, setInterfaces] = useState<ProxyLocalInterface[]>([]);
  const [detectError, setDetectError] = useState('');
  const [detecting, setDetecting] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    setError('');
    proxyListenerSettings().then(value => {
      if (active) { setCurrent(value); setHost(value.host); setPort(String(value.port)); }
    }).catch(reason => { if (active) setError(reason instanceof Error ? reason.message : 'Could not load proxy settings'); });
    return () => { active = false; };
  }, [retry]);
  useEffect(() => {
    let active = true;
    setDetecting(true); setDetectError('');
    fetchProxyInterfaces().then(value => { if (active) setInterfaces(value); })
      .catch(reason => { if (active) setDetectError(reason instanceof Error ? reason.message : 'Could not detect IP addresses'); })
      .finally(() => { if (active) setDetecting(false); });
    return () => { active = false; };
  }, [refresh]);
  const choices = new Map([
    ['127.0.0.1', 'Localhost — 127.0.0.1'],
    ['0.0.0.0', 'All IPv4 interfaces — 0.0.0.0'],
    ...interfaces.filter(item => item.address !== '127.0.0.1').map(item => [item.address, `${item.address} (${item.name})`] as [string, string]),
  ]);
  if (current && !choices.has(current.host)) choices.set(current.host, `${current.host} (current)`);
  if (host && !choices.has(host)) choices.set(host, `${host} (selected)`);
  const valid = host.trim().length > 0 && /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535;
  async function apply() {
    if (!valid || busy) return;
    setBusy(true); setError(''); setSaved(false);
    try {
      const value = await proxyListenerSettings({ host: host.trim(), port: Number(port) });
      setCurrent(value); setHost(value.host); setPort(String(value.port)); setSaved(true);
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not update proxy listener'); }
    finally { setBusy(false); }
  }
  return <section className="mt-8 border-b border-border pb-6">
    <div className="flex flex-wrap items-center justify-between gap-4">
      <div><h2 className="text-sm font-medium">Proxy listener</h2>
        <p className="mt-1 text-xs text-muted-foreground">Apply immediately and save for the next startup. Existing connections stay open.</p>
        {current && <p className="mt-1 font-mono text-xs text-muted-foreground">Listening on {current.host.includes(':') ? `[${current.host}]` : current.host}:{current.port}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <select aria-label="Proxy IP address" className="inspector-input max-w-full text-xs" value={host} disabled={!current || busy} onChange={event => { setHost(event.target.value); setSaved(false); }}>
          {!host && <option value="">Select IP address</option>}
          {[...choices].map(([address, label]) => <option key={address} value={address}>{label}</option>)}
        </select>
        <Button variant="ghost" size="sm" disabled={detecting || busy} onClick={() => setRefresh(value => value + 1)}>{detecting ? 'Detecting…' : 'Refresh IPs'}</Button>
        <input aria-label="Proxy port" type="number" min={1} max={65535} step={1} className="inspector-input w-24 text-xs" value={port} disabled={!current || busy} onChange={event => { setPort(event.target.value); setSaved(false); }}/>
        <Button size="sm" disabled={!current || !valid || busy || (Number(port) === current.port && host.trim() === current.host)} onClick={() => void apply()}>{busy ? 'Applying…' : 'Apply'}</Button>
      </div>
    </div>
    <p className="mt-2 text-xs text-muted-foreground">Use 127.0.0.1 for this machine only, a specific LAN IP for that interface, or 0.0.0.0 for both localhost and all IPv4 interfaces. Devices on those networks can access the proxy if allowed by your firewall. Configure clients with the actual LAN IP, not 0.0.0.0. SLURP_PROXY_ADDR overrides the saved address at startup.</p>
    {detectError && <p role="alert" className="mt-2 text-xs text-destructive">{detectError} Use Refresh IPs to try again.</p>}
    {error && <div role="alert" className="mt-2 text-xs text-destructive">{error}{!current && <Button variant="ghost" size="sm" onClick={() => setRetry(value => value + 1)}>Retry</Button>}</div>}
    {saved && <p role="status" className="mt-2 text-xs text-muted-foreground">Proxy listener updated and saved.</p>}
  </section>;
}
