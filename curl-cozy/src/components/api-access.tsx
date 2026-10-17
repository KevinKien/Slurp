import { useEffect, useState } from 'react';
import { API_BASE } from '@/lib/api';
import { authorizedFetch, getApiToken, setApiToken } from '@/lib/api-auth';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
export function ApiAccessGate() {
  const [open, setOpen] = useState(false), [value, setValue] = useState(''), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  useEffect(() => {
    setOpen(!getApiToken());
    const required = () => setOpen(true);
    window.addEventListener('slurp:authorization-required', required);
    return () => window.removeEventListener('slurp:authorization-required', required);
  }, []);
  return <Dialog open={open}><DialogContent className="bg-card" onEscapeKeyDown={e=>e.preventDefault()} onPointerDownOutside={e=>e.preventDefault()}><DialogHeader><DialogTitle>Connect to Slurp</DialogTitle><DialogDescription>Open the link printed when Slurp starts, or paste that link here to connect this browser securely.</DialogDescription></DialogHeader><form onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');try{setApiToken(value);const response=await authorizedFetch(`${API_BASE}/api/info`);if(!response.ok)throw Error('Connection rejected. Use the startup link from this Slurp instance.');window.location.reload();}catch(error){setError(error instanceof Error?error.message:'Could not connect');}finally{setBusy(false);}}} className="space-y-3"><input type="password" autoComplete="off" aria-label="Slurp connection link or token" className="inspector-input w-full" value={value} onChange={e=>setValue(e.target.value)} />{error&&<p role="alert" className="text-sm text-destructive">{error}</p>}<Button type="submit" disabled={busy||!value.trim()}>{busy?'Connecting…':'Connect'}</Button></form></DialogContent></Dialog>;
}
