import { ArrowDownToLine } from 'lucide-react';
import { API_BASE } from '@/lib/api';
import { Button } from '@/components/ui/button';

export function DownloadCaButton({ compact = false }: { compact?: boolean }) {
  return <Button asChild variant="outline" size="sm">
    <a href={`${API_BASE}/api/ca.crt`} download="ca.crt" title="Download CA certificate" aria-label="Download CA certificate">
      <ArrowDownToLine className="size-4"/>
      <span className={compact ? 'hidden sm:inline' : undefined}>{compact ? 'CA certificate' : 'Download ca.crt'}</span>
    </a>
  </Button>;
}

export function CaCertificateSettings() {
  return <section className="mt-8 space-y-3 border-b border-border pb-6" aria-label="CA certificate">
    <h2 className="text-sm font-medium">HTTPS CA certificate</h2>
    <p className="text-xs leading-5 text-muted-foreground">Download the CA certificate used by this Slurp proxy and install it in your client’s trusted certificate store to capture HTTPS and WSS traffic.</p>
    <DownloadCaButton/>
    <p className="text-xs leading-5 text-muted-foreground">macOS: import into Keychain Access and enable trust. Windows: import into Trusted Root Certification Authorities. Linux: add to your system CA store. Browsers with their own certificate store may need a separate import.</p>
    <p className="text-xs leading-5 text-muted-foreground">Windows curl (Schannel): if you see CERT_TRUST_REVOCATION_STATUS_UNKNOWN, add <code>--ssl-revoke-best-effort</code> when using <code>--cacert</code>. Slurp’s local CA has no online revocation service.</p>
  </section>;
}
