import { websocketProtocols } from '@/lib/api-auth';
import { useEffect, useRef, useState } from 'react';
import { useInspector } from '@/components/inspector';
import { Button } from '@/components/ui/button';
import { API_BASE } from '@/lib/api';
import { nextReplayTabId } from '@/lib/replay-tabs';
import { resolveReplayRequest } from '@/lib/replay-features';
import { isWebSocketRequest } from '@/lib/websocket-request';
import type { HttpRequest } from '@/lib/traffic';
export type WebSocketReplayEvent={direction:string;kind:string;body:string;time:string;truncated?:boolean};
export function WebSocketReplay() {
 const {sessions,setSessions,active,setActive,session:workspace,variables}=useInspector();
 const tab=sessions.find(s=>s.id===active)??sessions[0]!;
 const [headers,setHeaders]=useState(JSON.stringify(tab.request.headers,null,2));
 const kind=tab.wsKind??'text';const setKind=(value:string)=>setSessions(p=>p.map(t=>t.id===tab.id?{...t,wsKind:value==='binary'?'binary':'text'}:t));
 const [status,setStatus]=useState('Disconnected'),[error,setError]=useState('');
 const socket=useRef<WebSocket|null>(null);
 const update=(patch:Partial<HttpRequest>)=>setSessions(p=>p.map(t=>t.id===tab.id?{...t,request:{...t.request,...patch}}:t));
 const log=(event:WebSocketReplayEvent)=>setSessions(p=>p.map(t=>{
  if(t.id!==tab.id)return t;
  const entry={...event,body:event.body.slice(0,65536),truncated:event.body.length>65536};
  const messages=[...(t.wsMessages??[]),entry].slice(-200);
  let size=messages.reduce((n,m)=>n+m.body.length,0);while(size>1_000_000&&messages.length>1)size-=messages.shift()!.body.length;
  return {...t,wsMessages:messages};
 }));
 useEffect(()=>()=>{const ws=socket.current;socket.current=null;ws?.close();},[workspace?.workspace_id,workspace?.target]);
 const disconnect=()=>{const ws=socket.current;socket.current=null;ws?.close();setStatus('Disconnected');};
 const connect=()=>{
  try {
   const parsed:unknown=JSON.parse(headers);
   if(!parsed||typeof parsed!=='object'||Array.isArray(parsed)||Object.values(parsed).some(v=>typeof v!=='string'))throw new Error('Headers must be a JSON object of string values.');
   const request=resolveReplayRequest({...tab.request,headers:parsed as Record<string,string>},variables,"websocket");
   if(!/^wss?:\/\//i.test(request.url))throw new Error('Use a ws:// or wss:// URL.');
   disconnect();setError('');setStatus('Connecting');
   const ws=new WebSocket(`${API_BASE.replace(/^http/,'ws')}/api/replay/websocket`, websocketProtocols());socket.current=ws;
   ws.onopen=()=>{if(socket.current===ws)ws.send(JSON.stringify({url:request.url,headers:request.headers}));};
   ws.onmessage=event=>{if(socket.current!==ws)return;try{const data=JSON.parse(event.data);if(data.type==='connected'){setStatus('Connected');log({direction:'system',kind:'handshake',body:`101 Switching Protocols\n${JSON.stringify(data.headers,null,2)}`,time:new Date().toISOString()});}if(data.type==='error')setError(data.error);if(data.type==='closed')setStatus('Disconnected');if(data.type==='message')log({...data,time:new Date().toISOString()});}catch{setError('Invalid response from WebSocket Replay.');}};
   ws.onerror=()=>{if(socket.current===ws)setError('Could not connect to WebSocket Replay.');};
   ws.onclose=()=>{if(socket.current===ws){socket.current=null;setStatus('Disconnected');}};
  }catch(e){setError(e instanceof Error?e.message:'Connection failed');}
 };
 const send=()=>{try{if(status!=='Connected'||socket.current?.readyState!==WebSocket.OPEN)throw new Error('Connect before sending a message.');const body=resolveReplayRequest(tab.request,variables,"websocket").body;socket.current.send(JSON.stringify({type:'send',kind,body}));}catch(e){setError(e instanceof Error?e.message:'Send failed');}};
 const add=(ws:boolean)=>{const id=nextReplayTabId(sessions);setSessions(p=>[...p,{id,name:ws?'WebSocket request':'Untitled request',request:{method:'GET',url:'',headers:ws?{Upgrade:'websocket'}:{},body:''}}]);setActive(id);};
 const close=(id:number)=>{if(sessions.length===1)return;setSessions(p=>p.filter(t=>t.id!==id));if(active===id)setActive(sessions.find(t=>t.id!==id)!.id);};
 return <div className="flex h-full min-h-0 flex-col">
  <div className="shrink-0 px-6 py-3"><h1 className="text-xl font-semibold">Replay</h1><p className="mt-1 text-xs text-muted-foreground">Edit a WebSocket handshake, connect, and send messages. Supports public WS/WSS hosts on standard ports. Connections close when leaving this tab.</p></div>
  <div className="flex shrink-0 items-center gap-1 overflow-x-auto border-y border-border px-3 py-2">{sessions.map(t=><div key={t.id} className={`flex shrink-0 items-center rounded text-xs ${t.id===active?'bg-secondary':''}`}><button type="button" className="px-3 py-2" onClick={()=>setActive(t.id)}>{isWebSocketRequest(t.request)?'WS':'HTTP'} · {t.name}</button><button type="button" aria-label={`Close ${t.name}`} disabled={sessions.length===1} className="px-2" onClick={()=>close(t.id)}>×</button></div>)}<Button size="sm" variant="ghost" onClick={()=>add(true)}>+ WS</Button><Button size="sm" variant="ghost" onClick={()=>add(false)}>+ HTTP</Button></div>
  <div className="flex shrink-0 gap-2 border-b border-border p-3"><span className="self-center rounded bg-secondary px-2 py-1 text-xs">WS</span><input aria-label="WebSocket URL" className="inspector-input min-w-0 flex-1 font-mono text-xs" value={tab.request.url} onChange={e=>update({url:e.target.value})}/><Button size="sm" onClick={connect} disabled={status==='Connecting'}>{status==='Connected'?'Reconnect':'Connect'}</Button><Button size="sm" variant="outline" onClick={disconnect} disabled={status==='Disconnected'}>Disconnect</Button></div>
  <div className="flex shrink-0 items-center justify-between border-b px-3 py-2 text-xs"><span role="status">{status}</span><input aria-label="WebSocket tab name" className="bg-transparent text-right outline-none" value={tab.name} onChange={e=>setSessions(p=>p.map(t=>t.id===tab.id?{...t,name:e.target.value.slice(0,200),customName:true}:t))}/></div>
  {error&&<p role="alert" className="shrink-0 px-3 py-2 text-xs text-destructive">{error}</p>}
  <div className="flex min-h-0 flex-1 max-md:flex-col">
   <div className="flex min-h-0 w-1/2 flex-col border-r border-border max-md:w-full">
    <label className="shrink-0 p-3 text-xs font-medium" htmlFor="ws-replay-headers">Handshake headers (JSON)</label><textarea id="ws-replay-headers" aria-label="WebSocket headers" className="inspector-input mx-3 h-32 shrink-0 resize-y font-mono text-xs" value={headers} onChange={e=>{setHeaders(e.target.value);try{const parsed=JSON.parse(e.target.value);if(parsed&&typeof parsed==='object'&&!Array.isArray(parsed)&&Object.values(parsed).every(v=>typeof v==='string'))update({headers:{...Object.fromEntries(Object.entries(parsed).filter(([k])=>k.toLowerCase()!=='upgrade')),Upgrade:'websocket'}});}catch{/* Keep invalid drafts editable. */}}}/>
    <div className="flex shrink-0 items-center justify-between p-3"><label htmlFor="ws-message-kind" className="text-xs">Message</label><select id="ws-message-kind" aria-label="WebSocket message type" className="inspector-input text-xs" value={kind} onChange={e=>setKind(e.target.value)}><option value="text">Text</option><option value="binary">Binary (hex)</option></select></div>
    <textarea aria-label="WebSocket message" className="mx-3 min-h-20 flex-1 resize-none bg-transparent font-mono text-xs outline-none" placeholder={kind==='text'?'Message to send (supports {{variables}})':'Hex bytes, e.g. 48 65 6c 6c 6f'} value={tab.request.body} onChange={e=>update({body:e.target.value})}/><div className="flex shrink-0 justify-end p-3"><Button onClick={send} disabled={status!=='Connected'}>Send message</Button></div>
   </div>
   <div className="flex min-h-0 min-w-0 flex-1 flex-col"><div className="flex shrink-0 items-center justify-between border-b p-3 text-xs"><span>Messages · up to 200</span><Button size="sm" variant="ghost" onClick={()=>setSessions(p=>p.map(t=>t.id===tab.id?{...t,wsMessages:[]}:t))}>Clear messages</Button></div><div aria-label="WebSocket Replay messages" className="min-h-0 flex-1 overflow-auto">{!(tab.wsMessages?.length)&&<p className="p-4 text-xs text-muted-foreground">Connect and send a message to inspect the exchange.</p>}{tab.wsMessages?.map((m,i)=><div key={i} className="border-b border-border p-3"><p className="mb-2 text-[10px] text-muted-foreground">{m.direction==='outgoing'?'↑ Client → Server':m.direction==='incoming'?'↓ Server → Client':'Handshake'} · {m.kind}{m.truncated?' · Preview limited to 64 KiB':''} · {new Date(m.time).toLocaleTimeString()}</p><pre className="whitespace-pre-wrap break-all font-mono text-xs">{m.body}</pre>{m.direction!=='system'&&<Button size="sm" variant="ghost" className="mt-2" disabled={m.truncated} onClick={()=>{update({body:m.body});setKind(m.kind==='binary'?'binary':'text');}}>Use as message</Button>}</div>)}</div></div>
  </div>
 </div>;
}
