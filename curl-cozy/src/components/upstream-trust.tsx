import { useCallback, useEffect, useRef, useState } from 'react';
import { ShieldCheck, Trash2, Upload } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { addTrustedCa, fetchUpstreamTrust, removeTrustedCa, setTrustSystemStore, type UpstreamTrust } from '@/lib/api';

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : 'Something went wrong');

/** `staging-ca.crt` → `staging-ca`: the name a trusted CA is stored under. */
const nameFromFile = (file: string) => file.replace(/\.(pem|crt|cer)$/i, '').replace(/[^A-Za-z0-9._-]/g, '-').replace(/^[.-]+/, '').slice(0, 60) || 'custom-ca';

const readText = (file: File) =>
  new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(new Error('Could not read the file'));
    reader.readAsText(file);
  });

/** Trust a private CA (internal site, dev or staging) instead of turning certificate checks off. */
export function UpstreamTrustSettings() {
  const [trust, setTrust] = useState<UpstreamTrust | null>(null);
  const [busy, setBusy] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const load = useCallback(() => {
    fetchUpstreamTrust().then(setTrust, () => undefined);
  }, []);
  useEffect(load, [load]);

  const run = async (action: () => Promise<unknown>, success: string) => {
    setBusy(true);
    try {
      await action();
      toast.success(success);
      load();
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const upload = async (file: File | undefined) => {
    if (!file) return;
    let pem: string;
    try {
      pem = await readText(file);
    } catch (e) {
      toast.error(errorMessage(e));
      return;
    }
    await run(() => addTrustedCa(nameFromFile(file.name), pem), `Trusting certificates from ${file.name}`);
    if (input.current) input.current.value = '';
  };

  return (
    <section className="mt-8 space-y-3 border-b border-border pb-6" aria-label="Trusted upstream CAs">
      <h2 className="text-sm font-medium">Trusted upstream CAs</h2>
      <p className="text-xs leading-5 text-muted-foreground">
        Slurp verifies the certificates of the servers it connects to. For an internal site or a development or staging server signed by a private CA,
        add that CA here (PEM or .crt) rather than disabling verification. It applies to the proxy, Replay, Flows, Intruder and scans, immediately.
        A self-signed server certificate can be added the same way.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <input ref={input} type="file" accept=".pem,.crt,.cer" className="hidden" aria-label="Choose CA certificate file" onChange={(e) => void upload(e.target.files?.[0])} />
        <Button variant="outline" size="sm" disabled={busy} onClick={() => input.current?.click()}>
          <Upload className="size-4" />
          Add CA certificate
        </Button>
      </div>
      {trust && trust.cas.length > 0 && (
        <ul className="divide-y divide-border rounded border border-border text-xs">
          {trust.cas.map((ca) => (
            <li key={`${ca.name}-${ca.fingerprint_sha256}`} className="flex items-start gap-3 px-3 py-2">
              <ShieldCheck className="mt-0.5 size-4 shrink-0 text-primary" />
              <div className="min-w-0 flex-1">
                <div className="font-medium">
                  {ca.name}
                  {ca.source === 'env' && <span className="ml-2 rounded bg-secondary px-1.5 py-0.5 text-[10px] font-normal text-muted-foreground">SLURP_UPSTREAM_CA_FILE</span>}
                  {ca.expired && <span className="ml-2 rounded bg-destructive/10 px-1.5 py-0.5 text-[10px] font-normal text-destructive">Expired</span>}
                  {!ca.is_ca && <span className="ml-2 rounded bg-warning/10 px-1.5 py-0.5 text-[10px] font-normal text-warning">Server certificate</span>}
                </div>
                <div className="truncate text-muted-foreground" title={ca.subject}>{ca.subject}</div>
                <div className="truncate font-mono text-[10px] text-muted-foreground" title={ca.fingerprint_sha256}>
                  SHA-256 {ca.fingerprint_sha256} · expires {new Date(ca.not_after * 1000).toLocaleDateString()}
                </div>
              </div>
              {ca.source === 'file' && (
                <Button variant="ghost" size="icon" className="size-7 shrink-0 text-muted-foreground" aria-label={`Remove ${ca.name}`} disabled={busy} onClick={() => void run(() => removeTrustedCa(ca.name), `Stopped trusting ${ca.name}`)}>
                  <Trash2 />
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {trust && (
        <div className="flex items-start justify-between gap-4 rounded border border-border p-3">
          <div>
            <div className="text-xs font-medium">Also trust this computer’s certificate store</div>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Use the CAs already installed in the operating system, such as a corporate CA. {trust.system ? `${trust.system_certificates} certificates loaded.` : ''}
              {trust.system_locked ? ' Kept on by SLURP_UPSTREAM_TRUST_SYSTEM.' : ''}
            </p>
          </div>
          <Switch aria-label="Trust the system certificate store" checked={trust.system} disabled={busy || trust.system_locked} onCheckedChange={(on) => void run(() => setTrustSystemStore(on), on ? 'System certificate store trusted' : 'System certificate store no longer trusted')} />
        </div>
      )}
      <p className="text-xs leading-5 text-muted-foreground">
        You can also place PEM files in <code>~/.slurp/trusted-cas/</code> or set <code>SLURP_UPSTREAM_CA_FILE</code> (comma-separated paths). Only add CAs you trust: any certificate they sign will be accepted.
      </p>
    </section>
  );
}
