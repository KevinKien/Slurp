import { websocketRequest } from '@/lib/websocket-request';
import { useEffect, useState, type ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { RequestMenu } from '@/components/request-menu';
import type { HttpRequest } from '@/lib/traffic';
import { nextReplayTabId } from '@/lib/replay-tabs';
import { Search, Radio } from 'lucide-react';
import { API_BASE } from '@/lib/api';
import { useInspector } from '@/components/inspector';
import { Button } from '@/components/ui/button';

type Connection = {id:string;workspace_id:string;url:string;host:string;opened_at:string;closed_at:string|null;error:string|null;frames:number;request?:HttpRequest|null};
type Frame = {id:number;direction:string;timestamp:string;opcode:number;fin:boolean;compressed:boolean;masked:boolean;size:number;text:string|null;hex:string;truncated:boolean;dropped?:boolean};
const opcode = (n:number) => ({0:'Continuation',1:'Text',2:'Binary',8:'Close',9:'Ping',10:'Pong'}[n] ?? `Opcode ${n}`);
const time = (s:string) => new Date(s).toLocaleString();
async function read<T>(path:string, signal:AbortSignal):Promise<T> {
  const response = await fetch(`${API_BASE}${path}`,{signal});
  if (!response.ok) throw new Error(`Could not load WebSocket traffic (${response.status})`);
  return response.json();
}

export function ProtocolTabs({children}:{children:ReactNode}) {
  const [tab,setTab]=useState<'http'|'websocket'>('http');
  return <div className="flex h-full min-h-0 flex-col">
    <div role="tablist" aria-label="Traffic protocol" className="flex shrink-0 gap-1 border-b border-border px-4 py-2">
      {(['http','websocket'] as const).map(value=><button key={value} type="button" role="tab" aria-selected={tab===value} onClick={()=>setTab(value)} className={`rounded px-3 py-1.5 text-xs font-medium ${tab===value?'bg-secondary text-foreground':'text-muted-foreground hover:text-foreground'}`}>{value==='http'?'HTTP':'WebSocket'}</button>)}
    </div>
    <div role="tabpanel" hidden={tab!=='http'} className={`min-h-0 min-w-0 flex-1 flex-col overflow-hidden ${tab==='http'?'flex':'hidden'}`}>{children}</div>
    {tab==='websocket'&&<div role="tabpanel" className="min-h-0 flex-1"><WebSocketTraffic/></div>}
  </div>;
}

export function WebSocketTraffic() {
  const {view,scope,scopeEnabled,sessions,setSessions,setActive}=useInspector();
  const [connections,setConnections]=useState<Connection[]>([]),[selected,setSelected]=useState('');
  const [before,setBefore]=useState<string[]>([]),[cursors,setCursors]=useState<number[]>([]);
  const [frames,setFrames]=useState<Frame[]>([]),[chosen,setChosen]=useState<Frame|null>(null);
  const [query,setQuery]=useState(''),[error,setError]=useState('');
  const workspace=view==='all'?'':view;
  const cursor=cursors.at(-1)??0;
  const connectionCursor=before.at(-1)??'';
  useEffect(()=>{setConnections([]);setSelected('');setBefore([]);setQuery('');},[workspace]);
  useEffect(()=>{setSelected('');},[scope,scopeEnabled]);
  useEffect(()=>{setFrames([]);setChosen(null);setCursors([]);},[selected,workspace]);
  useEffect(()=>{
    const controller=new AbortController();let timer:ReturnType<typeof setTimeout>;
    async function refresh() {
      try {
        const p=new URLSearchParams({limit:'100'});if(workspace)p.set('workspace',workspace);if(connectionCursor)p.set('before',connectionCursor);
        const rows=await read<Connection[]>(`/api/websockets?${p}`,controller.signal);
        if(controller.signal.aborted)return;
        setConnections(rows);setError('');
      } catch(e) {if(!controller.signal.aborted)setError(e instanceof Error?e.message:'Could not load connections');}
      if(!controller.signal.aborted)timer=setTimeout(refresh,1500);
    }
    void refresh();return()=>{controller.abort();clearTimeout(timer);};
  },[workspace,connectionCursor]);
  useEffect(()=>{
    if(!selected)return;
    const controller=new AbortController();let timer:ReturnType<typeof setTimeout>;
    setFrames([]);setChosen(null);
    async function refresh() {
      try {
        const p=new URLSearchParams({after:String(cursor),limit:'100'});if(workspace)p.set('workspace',workspace);
        const rows=await read<Frame[]>(`/api/websockets/${encodeURIComponent(selected)}/frames?${p}`,controller.signal);
        if(controller.signal.aborted)return;
        setFrames(rows);setChosen(current=>current&&rows.find(f=>f.id===current.id)||rows[0]||null);setError('');
      } catch(e) {if(!controller.signal.aborted)setError(e instanceof Error?e.message:'Could not load messages');}
      if(!controller.signal.aborted)timer=setTimeout(refresh,1000);
    }
    void refresh();return()=>{controller.abort();clearTimeout(timer);};
  },[selected,workspace,cursor]);
  const domains=scope.split(/[\s,]+/).filter(Boolean).map(s=>s.toLowerCase());
  const visible=connections.filter(c=>!scopeEnabled||!domains.length||domains.includes(c.host.toLowerCase().replace(/\.$/,'')));
  const filtered=frames.filter(f=>`${f.text??f.hex} ${opcode(f.opcode)}`.toLowerCase().includes(query.toLowerCase()));
  const connection=connections.find(c=>c.id===selected);
  return <div className="flex h-full min-h-0 flex-col">
    <div className="shrink-0 border-b border-border px-4 py-3"><h1 className="flex items-center gap-2 text-sm font-semibold"><Radio className="size-4"/>WebSocket traffic</h1><p className="mt-1 text-xs text-muted-foreground">Live WS/WSS connections and frames. Intercept holds handshakes and messages; right-click to send to Replay.</p></div>
    {error&&<p role="alert" className="px-4 py-2 text-xs text-destructive">{error}</p>}
    <div className="flex min-h-0 flex-1 max-md:flex-col">
      <aside aria-label="WebSocket connections" className="flex w-80 shrink-0 flex-col border-r border-border max-md:h-44 max-md:w-full max-md:border-b">
        <div className="min-h-0 flex-1 overflow-auto">{visible.length===0?<p className="p-4 text-xs text-muted-foreground">No WebSocket connections. Route your app through the Slurp proxy to capture traffic.</p>:visible.map(c=><RequestMenu key={c.id} request={c.request??{method:"GET",url:c.url,headers:{},body:""}}><button type="button" key={c.id} onClick={()=>setSelected(c.id)} className={`block w-full border-b border-border px-3 py-3 text-left text-xs ${selected===c.id?'bg-secondary':'hover:bg-secondary/50'}`}><span className="block break-all font-mono">{c.url}</span><span className="mt-1 block text-muted-foreground">{c.closed_at?'Closed':'Open'} · {c.frames} frames · {time(c.opened_at)}</span></button></RequestMenu>)}</div>
        <div className="flex justify-between border-t p-2"><Button size="sm" variant="ghost" disabled={!before.length} onClick={()=>{setBefore(p=>p.slice(0,-1));setSelected('');}}>Previous</Button><Button size="sm" variant="ghost" disabled={connections.length<100} onClick={()=>{setBefore(p=>[...p,connections.at(-1)!.opened_at]);setSelected('');}}>Older</Button></div>
      </aside>
      <section className="flex min-h-0 min-w-0 flex-1 flex-col" aria-label="WebSocket messages">
        {!selected?<p className="p-6 text-xs text-muted-foreground">Select a connection to inspect its messages.</p>:<>
          <div className="shrink-0 border-b border-border px-3 py-2 text-xs"><p className="break-all font-mono">{connection?.url??'Selected connection'}</p>{connection&&<Button asChild size="sm" variant="outline" className="mt-2"><Link to="/replay" onClick={()=>{const id=nextReplayTabId(sessions);const request=websocketRequest(connection.request??{method:'GET',url:connection.url,headers:{},body:''});request.body=chosen&&!chosen.truncated&&!chosen.compressed?(chosen.text??chosen.hex):'';setSessions(p=>[...p,{id,name:new URL(connection.url).pathname,wsKind:chosen&&chosen.text===null?'binary':'text',request}]);setActive(id);}}>Send to Replay</Link></Button>}{connection?.error&&<p className="text-destructive">{connection.error}</p>}<label className="mt-2 flex items-center gap-2"><Search className="size-3.5"/><input aria-label="Search WebSocket messages" placeholder="Search this page (text or hex)…" value={query} onChange={e=>setQuery(e.target.value)} className="min-w-0 flex-1 bg-transparent py-1 outline-none"/></label></div>
          <div className="min-h-0 flex-1 overflow-auto"><table className="w-full text-left text-xs"><thead className="sticky top-0 bg-background text-muted-foreground"><tr><th className="p-2">Direction</th><th>Type</th><th>Size</th><th>Time</th><th>Preview</th></tr></thead><tbody>{filtered.map(f=><RequestMenu key={f.id} websocketKind={f.text===null?'binary':'text'} disabled={f.truncated||f.compressed} request={()=>({...websocketRequest(connection?.request??{method:'GET',url:connection?.url??'',headers:{},body:''}),body:f.text??f.hex})}><tr key={f.id} onClick={()=>setChosen(f)} className={`cursor-pointer border-t border-border ${chosen?.id===f.id?'bg-secondary':'hover:bg-secondary/50'}`}><td className="whitespace-nowrap p-2">{f.direction==='client_to_server'?'↑ Client → Server':'↓ Server → Client'}</td><td>{opcode(f.opcode)}{!f.fin?' (fragment)':''}{f.compressed?' (compressed)':''}{f.dropped?' · Dropped':''}</td><td className="whitespace-nowrap pr-2">{f.size} B</td><td className="whitespace-nowrap pr-2">{new Date(f.timestamp).toLocaleTimeString()}</td><td className="max-w-60 truncate font-mono">{(f.text??f.hex).slice(0,160)}</td></tr></RequestMenu>)}</tbody></table>{!frames.length&&<p className="p-4 text-xs text-muted-foreground">Waiting for messages…</p>}</div>
          <div className="flex shrink-0 items-center justify-between border-t p-2 text-xs text-muted-foreground"><Button size="sm" variant="ghost" disabled={!cursors.length} onClick={()=>setCursors(p=>p.slice(0,-1))}>Previous</Button><span>Page {cursors.length+1} · {frames.length} frames</span><Button size="sm" variant="ghost" disabled={frames.length<100} onClick={()=>setCursors(p=>[...p,frames.at(-1)!.id])}>Next</Button></div>
          {chosen&&<div className="flex h-1/3 min-h-28 shrink-0 flex-col border-t border-border"><div className="px-3 py-2 text-xs text-muted-foreground">{opcode(chosen.opcode)} · {time(chosen.timestamp)} · {chosen.masked?'Masked':'Unmasked'}{chosen.compressed?' · Compressed payload (hex)':''}{chosen.truncated?' · Preview limited to 64 KiB':''}</div><pre tabIndex={0} className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all px-3 pb-3 font-mono text-xs">{chosen.text??chosen.hex.match(/.{1,2}/g)?.join(' ')??''}</pre></div>}
        </>}
      </section>
    </div>
  </div>;
}
