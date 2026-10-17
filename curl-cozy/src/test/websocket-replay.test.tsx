import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { HttpRequest } from '@/lib/traffic';
const state=vi.hoisted(()=>({active:1,session:{target:'workspace',workspace_id:'one'},variables:{token:'abc'},sessions:[] as {id:number;name:string;request:HttpRequest;wsMessages?:unknown[]}[],setSessions:vi.fn(),setActive:vi.fn()}));
vi.mock('@/components/inspector',()=>({useInspector:()=>state}));
import { WebSocketReplay } from '@/components/websocket-replay';
class FakeSocket {
 static OPEN=1;static instances:FakeSocket[]=[];readyState=1;
 onopen:(()=>void)|null=null;onmessage:((e:{data:string})=>void)|null=null;onclose:(()=>void)|null=null;onerror:(()=>void)|null=null;
 send=vi.fn();close=vi.fn();constructor(public url:string){FakeSocket.instances.push(this);}
}
beforeEach(()=>{FakeSocket.instances=[];vi.stubGlobal('WebSocket',FakeSocket);state.sessions=[{id:1,name:'WS events',request:{method:'GET',url:'wss://example.com/events',headers:{upgrade:'websocket',Authorization:'Bearer {{token}}'},body:'hello {{token}}'}}];state.setSessions.mockImplementation(update=>{state.sessions=update(state.sessions);});});
afterEach(()=>{cleanup();vi.unstubAllGlobals();vi.clearAllMocks();});
it('edits a handshake, resolves variables, sends messages and displays replies',()=>{
 const ui=render(<WebSocketReplay/>);
 fireEvent.change(screen.getByLabelText('WebSocket URL'),{target:{value:'wss://example.com/edited'}});ui.rerender(<WebSocketReplay/>);
 fireEvent.click(screen.getByRole('button',{name:'Connect'}));
 const ws=FakeSocket.instances[0]!;act(()=>ws.onopen?.());
 expect(JSON.parse(ws.send.mock.calls[0]![0])).toMatchObject({url:'wss://example.com/edited',headers:{Authorization:'Bearer abc'}});
 act(()=>ws.onmessage?.({data:JSON.stringify({type:'connected',headers:[]})}));
 fireEvent.click(screen.getByRole('button',{name:'Send message'}));
 expect(JSON.parse(ws.send.mock.calls.at(-1)![0])).toEqual({type:'send',kind:'text',body:'hello abc'});
 act(()=>ws.onmessage?.({data:JSON.stringify({type:'message',direction:'incoming',kind:'text',body:'server reply'})}));ui.rerender(<WebSocketReplay/>);
 expect(screen.getByText('server reply')).toBeInTheDocument();
 ui.unmount();expect(ws.close).toHaveBeenCalled();
});
it('disconnects and ignores stale messages when changing workspace',()=>{
 const ui=render(<WebSocketReplay/>);fireEvent.click(screen.getByRole('button',{name:'Connect'}));const ws=FakeSocket.instances[0]!;
 state.session={target:'workspace',workspace_id:'two'};ui.rerender(<WebSocketReplay/>);
 expect(ws.close).toHaveBeenCalled();
 act(()=>ws.onmessage?.({data:JSON.stringify({type:'message',direction:'incoming',kind:'text',body:'stale reply'})}));
 expect(screen.queryByText('stale reply')).not.toBeInTheDocument();state.session={target:'workspace',workspace_id:'one'};
});
