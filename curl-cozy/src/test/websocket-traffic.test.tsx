vi.mock('@tanstack/react-router',()=>({Link:({children,...props}:React.PropsWithChildren<Record<string,unknown>>)=><a {...props}>{children}</a>}));
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
const state=vi.hoisted(()=>({view:'temporary',scope:'',scopeEnabled:false,sessions:[] as {id:number}[],setSessions:vi.fn(),setActive:vi.fn()}));
vi.mock('@/components/inspector',()=>({useInspector:()=>state}));
import { ProtocolTabs } from '@/components/websocket-traffic';
const connection={id:'ws-1',workspace_id:'temporary',url:'ws://example.com/events',host:'example.com',opened_at:'2026-10-17T10:00:00Z',closed_at:null,error:null,frames:2};
const frame={id:1,direction:'server_to_client',timestamp:'2026-10-17T10:00:00Z',opcode:1,fin:true,compressed:false,masked:false,size:5,text:'hello',hex:'68656c6c6f',truncated:false};
beforeEach(()=>{vi.stubGlobal('DOMRect',class { static fromRect({x=0,y=0,width=0,height=0}:DOMRectInit={}) { return {x,y,width,height,left:x,top:y,right:x+width,bottom:y+height,toJSON:()=>({})}; } });state.view='temporary';state.scope='';state.scopeEnabled=false;vi.stubGlobal('fetch',vi.fn(async(input:string)=>({ok:true,json:async()=>input.includes('/frames?')?[frame]:[connection]})));});
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
it('shows captured messages in the WebSocket tab and preserves the HTTP draft',async()=>{
 render(<ProtocolTabs><textarea aria-label="HTTP draft" defaultValue="keep this"/></ProtocolTabs>);
 fireEvent.click(screen.getByRole('tab',{name:'WebSocket'}));
 fireEvent.click(await screen.findByText(connection.url));
 await screen.findByText('↓ Server → Client');
 expect(screen.getAllByText('hello').length).toBeGreaterThan(0);
 expect(fetch).toHaveBeenCalledWith(expect.stringContaining('workspace=temporary'),expect.anything());
 fireEvent.change(screen.getByLabelText('Search WebSocket messages'),{target:{value:'absent'}});
 expect(screen.queryByText('↓ Server → Client')).not.toBeInTheDocument();
 fireEvent.click(screen.getByRole('tab',{name:'HTTP'}));
 expect(screen.getByLabelText('HTTP draft')).toHaveValue('keep this');
});
it('discards stale messages after switching workspace',async()=>{
 let resolve:((value:unknown)=>void)|undefined;
 vi.mocked(fetch).mockImplementation(async input=> input.toString().includes('/frames?')?await new Promise<Response>(r=>{resolve=r as (value:unknown)=>void;}):({ok:true,json:async()=>state.view==='temporary'?[connection]:[]} as Response));
 const ui=render(<ProtocolTabs><div>HTTP</div></ProtocolTabs>);
 fireEvent.click(screen.getByRole('tab',{name:'WebSocket'}));fireEvent.click(await screen.findByText(connection.url));
 await waitFor(()=>expect(resolve).toBeDefined());
 state.view='other';ui.rerender(<ProtocolTabs><div>HTTP</div></ProtocolTabs>);
 resolve?.({ok:true,json:async()=>[frame]});
 await waitFor(()=>expect(screen.queryByText(connection.url)).not.toBeInTheDocument());
 expect(screen.queryByText('hello')).not.toBeInTheDocument();
});

it('sends a selected WebSocket message to Replay from the right-click menu',async()=>{
 render(<ProtocolTabs><div>HTTP</div></ProtocolTabs>);
 fireEvent.click(screen.getByRole('tab',{name:'WebSocket'}));fireEvent.click(await screen.findByText(connection.url));
 const message=await screen.findByText('↓ Server → Client');fireEvent.contextMenu(message);
 fireEvent.click(screen.getByRole('menuitem',{name:'Send to Replay'}));
 const update=state.setSessions.mock.calls.at(-1)![0];
 expect(update([])[0].request).toMatchObject({url:connection.url,body:'hello',method:'GET'});
 expect(state.setActive).toHaveBeenCalled();
});
