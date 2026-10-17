import { WebSocketReplay, type WebSocketReplayEvent } from "@/components/websocket-replay";
import { isWebSocketRequest } from "@/lib/websocket-request";
import { ProtocolTabs } from "@/components/websocket-traffic";
import { useAuthProfiles } from '@/components/auth-profiles-provider';
import { ProfileSelector } from '@/components/auth-profiles';
import { ResponseDiffButton } from '@/components/response-diff';
import { ProxyListenerSettingsPanel } from '@/components/proxy-listener-settings';
import type { PostmanRequest } from '@/lib/postman-import';
import { PostmanImportDialog } from '@/components/postman-import';
import { runReplayScript } from '@/lib/replay-script';
import type { ScriptResult } from '@/lib/replay-script-engine';
import { createContext, useContext, useState, useRef, useEffect, useLayoutEffect, useCallback, useMemo, type ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { Workflow, Bookmark, TriangleAlert, Bot, Check, Hand, Activity, ArrowDownToLine, ArrowUpFromLine, ArrowUpRight, ChevronDown, ChevronRight, Clock3, Code2, Filter, Folder, Globe, Layers, List, MoreHorizontal, PanelLeftClose, PanelLeftOpen, Plus, Radio, Search, Settings2, ShieldCheck, Terminal, Trash2, Wifi, WifiOff, X, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/components/ui/resizable';
import { ReplayVariablesEditor } from '@/components/replay-variables';
import { ReplayRuns } from '@/components/replay-runs';
import { TrafficNotes } from '@/components/traffic-notes';
import { normalizeVariables, replayQuery, setReplayQuery, resolveReplayRequest, type ReplayVariables, type ReplayRun } from '@/lib/replay-features';
import { saveReplayRun, updateTrafficAnnotation } from '@/lib/replay-features-api';
import { RequestMenu } from '@/components/request-menu';
import { CodePane } from '@/components/code-pane';
import { type Traffic, type HttpRequest, methods, importTraffic, parseCurl, parseRawRequest, requestText, responseText, sizeLabel, mapApiEntries, mapApiEntry } from '@/lib/traffic';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';
import { WorkspaceGate } from '@/components/workspace-gate';
import { TEMP_WORKSPACE } from '@/lib/session';
import { nextReplayTabId, normalizeStoredTabs, pickActive, serializeTabs } from '@/lib/replay-tabs';
import { sendHttpRequest } from '@/lib/replay.functions';
import { updateScope as apiUpdateScope, fetchTrafficDetail, fetchTraffic, clearTraffic as apiClearTraffic, fetchWorkspaces, createWorkspace as apiCreateWorkspace, renameWorkspace as apiRenameWorkspace, deleteWorkspace as apiDeleteWorkspace, activateWorkspace as apiActivateWorkspace, fetchIntercept, updateInterceptSettings as apiUpdateInterceptSettings, forwardHeld as apiForwardHeld, dropHeld as apiDropHeld, forwardAllHeld as apiForwardAllHeld, fetchSession, useTemporarySession as apiUseTemporary, saveReplay as apiSaveReplay, fetchReplayTabs as apiFetchReplayTabs, saveReplayTabs as apiSaveReplayTabs, type TrafficFilters, type Workspace, type HeldItem, type InterceptSettings, type InterceptEdit, type SessionInfo } from '@/lib/api';
import { useTrafficStream, type ConnectionStatus, type InterceptEvent } from '@/lib/ws';

type ReplayOutcome={status:number;headers:Record<string,string>;body:string;duration:number}|{error:string};

type Session = {wsKind?:"text"|"binary";wsMessages?:WebSocketReplayEvent[];afterResponse?:string;scriptResult?:ScriptResult|undefined;runs?:ReplayRun[];id:number;name:string;customName?:boolean;request:HttpRequest;response?:Traffic;error?:string|undefined;loading?:boolean};
type State = {commitScriptVariables:(workspace:string|null,patch:ReplayVariables)=>Promise<void>;getReplayWorkspace:()=>string|null;variables:ReplayVariables;setVariables:(value:ReplayVariables)=>void;annotateTraffic:(row:Traffic,patch:{bookmarked?:boolean;notes?:string})=>Promise<void>;ensureTrafficDetails:(row:Traffic)=>Promise<Traffic>;historyTotal:number;historyLoading:boolean;historyMore:boolean;historyError:string;loadMoreHistory:()=>Promise<void>;retryHistory:(reset?:boolean)=>void;setHistoryQuery:(query:TrafficFilters)=>void;traffic:Traffic[];setTraffic:React.Dispatch<React.SetStateAction<Traffic[]>>;sessions:Session[];setSessions:React.Dispatch<React.SetStateAction<Session[]>>;active:number;setActive:(id:number)=>void;timeout:number;setTimeout:(value:number)=>void;scope:string;setScope:(value:string)=>void;updateScope:(domains:string[],enabled:boolean)=>Promise<void>;scopeEnabled:boolean;setScopeEnabled:(value:boolean)=>void;proxyStatus:ConnectionStatus;workspaces:Workspace[];view:string;setView:(id:string)=>void;createWorkspace:(name:string)=>Promise<Workspace>;renameWorkspace:(id:string,name:string)=>Promise<void>;deleteWorkspace:(id:string)=>Promise<void>;activateWorkspace:(id:string)=>Promise<void>;held:HeldItem[];intercept:InterceptSettings;setIntercept:(update:Partial<InterceptSettings>)=>Promise<void>;forwardHeld:(id:string,edit?:InterceptEdit)=>Promise<void>;dropHeld:(id:string)=>Promise<void>;forwardAllHeld:()=>Promise<void>;session:SessionInfo|null;chooseWorkspace:(id:string)=>Promise<void>;chooseTemporary:()=>Promise<void>;saveReplay:(request:HttpRequest,outcome:ReplayOutcome)=>Promise<Traffic|null>;};
const Context=createContext<State|null>(null);
export function useInspector(){ const value=useContext(Context); if(!value) throw new Error('Inspector provider missing'); return value; }
const blankRequest:HttpRequest={method:'GET',url:'https://httpbin.org/get',headers:{Accept:'application/json'},body:''};
export const ALL_WORKSPACES='all';
const VIEW_KEY='intercept.viewWorkspace';
// Match the backend's timestamp + UUID order, including sub-millisecond captures.
const compareHistory=(a:Traffic,b:Traffic)=>Date.parse(a.timestamp)-Date.parse(b.timestamp)
 || (a.timestamp.match(/\.(\d+)/)?.[1]??'').padEnd(9,'0').localeCompare((b.timestamp.match(/\.(\d+)/)?.[1]??'').padEnd(9,'0'))
 || (a.apiId&&b.apiId?(a.apiId<b.apiId?-1:a.apiId>b.apiId?1:0):a.id-b.id);

export function InspectorProvider({children}:{children:ReactNode}) {
 const [traffic,setTraffic]=useState<Traffic[]>([]),[sessions,setSessions]=useState<Session[]>([{id:1,name:'Untitled request',request:blankRequest}]),[active,setActive]=useState(1),[timeout,setTimeout]=useState(15000),[scope,setScope]=useState(''),[scopeEnabled,setScopeEnabled]=useState(false);
 const [variables,setVariables]=useState<ReplayVariables>({});
 const [workspaces,setWorkspaces]=useState<Workspace[]>([]),[view,setViewState]=useState(ALL_WORKSPACES);
 const [session,setSession]=useState<SessionInfo|null>(null),[held,setHeld]=useState<HeldItem[]>([]),[intercept,setInterceptState]=useState<InterceptSettings>({requests:false,responses:false});
 const replayWorkspaceRef=useRef<string|null>(null);replayWorkspaceRef.current=session?.target==='workspace'?session.workspace_id:null;
 const getReplayWorkspace=useCallback(()=>replayWorkspaceRef.current,[]);
 // The view is read from callbacks that must not re-subscribe on every change, so mirror it in a ref.
 const viewRef=useRef(ALL_WORKSPACES);
 // Once the view was restored or chosen explicitly, the proxy's active workspace must not override it.
 const viewDecided=useRef(false);
 const [historyTotal,setHistoryTotal]=useState(0),[historyLoading,setHistoryLoading]=useState(false),[historyMore,setHistoryMore]=useState(false),[historyError,setHistoryError]=useState('');
 const historyQuery=useRef<TrafficFilters>({});
 const historySeen=useRef(new Set<string>());
 const historyCursor=useRef<string|null>(null),historyGeneration=useRef(0),historyBusy=useRef(false);


 // The proxy is the source of truth for what is held; re-read it on connect and after any failed action.
 const syncIntercept=useCallback(()=>fetchIntercept().then(state=>{setInterceptState(state.settings);setHeld(state.held);if(state.scope){setScope(state.scope.domains.join('\n'));setScopeEnabled(state.scope.enabled);}}).catch(()=>{}),[]);
 const updateScope=useCallback(async(domains:string[],enabled:boolean)=>{
  const saved=await apiUpdateScope({domains,enabled});
  setScope(saved.domains.join('\n'));setScopeEnabled(saved.enabled);
 },[]);
 useEffect(()=>{
  const apply=(event:Event)=>{const scope=(event as CustomEvent).detail;setScope(scope.domains.join('\n'));setScopeEnabled(scope.enabled);};
  window.addEventListener('httpdebugger:scope',apply);
  return ()=>window.removeEventListener('httpdebugger:scope',apply);
 },[]);
 const onIntercept=useCallback((event:InterceptEvent)=>{
  if(event.type==='queued') setHeld(prev=>prev.some(h=>h.id===event.item.id)?prev:[...prev,event.item]);
  else if(event.type==='resolved') setHeld(prev=>prev.filter(h=>h.id!==event.id));
  else setInterceptState(event.settings);
 },[]);
 // Workspaces and the session (has one been chosen, how much is held in memory) change together.
 const refreshWorkspaces=useCallback(()=>Promise.all([fetchWorkspaces().then(setWorkspaces),fetchSession().then(setSession)]).then(()=>{},()=>{}),[]);

 // Merge proxy entries into local state: keep local-only rows (imports/replays), reuse ids for known apiIds.
 const syncFromProxy=useCallback(async()=>{
  const generation=++historyGeneration.current;
  const ws=viewRef.current;
  historyBusy.current=true;setHistoryLoading(true);setHistoryError('');historyCursor.current=null;setHistoryMore(false);
  try {
   const res=await fetchTraffic({history:true,limit:100,...historyQuery.current,...(ws!==ALL_WORKSPACES&&{workspace:ws})});
   if(generation!==historyGeneration.current)return;
   historyCursor.current=res.next_cursor??null;setHistoryMore(!!res.next_cursor);setHistoryTotal(res.total);
   const fetched=mapApiEntries(res.data).map(row=>({...row,bodyLoaded:!res.summary}));
   historySeen.current=new Set(res.data.map(r=>r.id));
   setTraffic(prev=>{
    const known=new Map(prev.filter(r=>r.apiId).map(r=>[r.apiId as string,r.id]));
    const local=prev.filter(r=>!r.apiId);
    return [...fetched.map(r=>({...r,id:known.get(r.apiId as string)??r.id})),...local];
   });
  } catch(error) {
   if(generation===historyGeneration.current)setHistoryError(error instanceof Error?error.message:'Could not load history');
   throw error;
  } finally {if(generation===historyGeneration.current){historyBusy.current=false;setHistoryLoading(false);}}
 },[]);
 const loadMoreHistory=useCallback(async()=>{
  if(historyBusy.current||!historyCursor.current)return;
  const generation=historyGeneration.current,cursor=historyCursor.current,ws=viewRef.current;
  historyBusy.current=true;setHistoryLoading(true);setHistoryError('');
  try{
   const res=await fetchTraffic({history:true,limit:100,...historyQuery.current,cursor,...(ws!==ALL_WORKSPACES&&{workspace:ws})});
   if(generation!==historyGeneration.current)return;
   historyCursor.current=res.next_cursor??null;setHistoryMore(!!res.next_cursor);setHistoryTotal(res.total);
   const fetched=mapApiEntries(res.data).map(row=>({...row,bodyLoaded:!res.summary}));
   res.data.forEach(r=>historySeen.current.add(r.id));
   setTraffic(prev=>{const known=new Set(prev.map(r=>r.apiId));return [...prev,...fetched.filter(r=>!known.has(r.apiId))];});
  }catch(error){if(generation===historyGeneration.current)setHistoryError(error instanceof Error?error.message:'Could not load more history');}
  finally{if(generation===historyGeneration.current){historyBusy.current=false;setHistoryLoading(false);}}
 },[]);
 // Keep a small body cache; paged list rows retain metadata only.
 const detailCache=useRef(new Map<string,Promise<Traffic>>());
 const ensureTrafficDetails=useCallback(async(row:Traffic):Promise<Traffic>=>{
  if(!row.apiId||row.bodyLoaded!==false)return row;
  const cache=detailCache.current;
  let pending=cache.get(row.apiId);
  if(!pending){
   pending=fetchTrafficDetail(row.apiId).then(entry=>({...mapApiEntry(entry),id:row.id,bodyLoaded:true}));
   cache.set(row.apiId,pending);
   if(cache.size>10)cache.delete(cache.keys().next().value!);
   pending.catch(()=>{cache.delete(row.apiId!);});
  }
  return {...await pending,bookmarked:row.bookmarked??false,notes:row.notes??''};
 },[]);
 const annotateTraffic=useCallback(async(row:Traffic,patch:{bookmarked?:boolean;notes?:string})=>{
  const saved=row.apiId?await updateTrafficAnnotation(row.apiId,patch):patch;
  setTraffic(prev=>prev.map(item=>item.id===row.id?{...item,...saved}:item));
  if(historyQuery.current.bookmarked)void syncFromProxy().catch(()=>{});
 },[syncFromProxy]);
 useEffect(()=>{
  const apply=(event:Event)=>{const update=(event as CustomEvent).detail;setTraffic(prev=>prev.map(row=>row.apiId===update.id?{...row,bookmarked:update.bookmarked,notes:update.notes}:row));if(historyQuery.current.bookmarked)void syncFromProxy().catch(()=>{});};
  window.addEventListener('httpdebugger:annotation',apply);return ()=>window.removeEventListener('httpdebugger:annotation',apply);
 },[syncFromProxy]);
 const setHistoryQuery=useCallback((query:TrafficFilters)=>{
  if(JSON.stringify(query)===JSON.stringify(historyQuery.current))return;
  historyQuery.current=query;void syncFromProxy().catch(()=>{});
 },[syncFromProxy]);

 const setView=useCallback((id:string)=>{
  viewRef.current=id;viewDecided.current=true;setViewState(id);
  try{localStorage.setItem(VIEW_KEY,id);}catch{}
  syncFromProxy().catch(()=>{});
 },[syncFromProxy]);

 // Initial load: restore the saved view, then load captured traffic. Errors remain visible in History.
 useEffect(()=>{
  try{const saved=localStorage.getItem(VIEW_KEY);if(saved){viewRef.current=saved;viewDecided.current=true;setViewState(saved);}}catch{}
  syncFromProxy().catch(()=>{});
  refreshWorkspaces();
 },[syncFromProxy,refreshWorkspaces]);

 // Request counts change with every captured entry; refresh them at most twice a second.
 const countTimer=useRef<ReturnType<typeof globalThis.setTimeout>|undefined>(undefined);
 const refreshCountsSoon=useCallback(()=>{
  if(countTimer.current)return;
  countTimer.current=globalThis.setTimeout(()=>{countTimer.current=undefined;refreshWorkspaces();},500);
 },[refreshWorkspaces]);

 // Upsert by apiId so repeated events (and our own saves) don't duplicate rows; ignore entries outside the viewed workspace
 const addEntry=useCallback((entry:Traffic)=>{
  if(viewRef.current!==ALL_WORKSPACES&&entry.workspaceId!==viewRef.current) return;
  // "All" means all saved workspaces; the in-memory session only shows when it is selected.
  if(viewRef.current===ALL_WORKSPACES&&entry.workspaceId===TEMP_WORKSPACE) return;
  const query=historyQuery.current;
  if(query.bookmarked&&!entry.bookmarked)return;
  if(query.method&&query.method!==entry.method)return;
  if(query.status_class&&Math.floor(entry.status/100)!==query.status_class)return;
  if(query.domains?.length&&!query.domains.includes(new URL(entry.url).hostname.toLowerCase().replace(/\.$/,'')))return;
  if(query.search&&!`${entry.url} ${JSON.stringify(entry.headers)} ${JSON.stringify(entry.responseHeaders)} ${entry.notes??''}`.toLowerCase().includes(query.search.toLowerCase()))return;
  if(entry.apiId&&!historySeen.current.has(entry.apiId)){historySeen.current.add(entry.apiId);setHistoryTotal(n=>n+1);}
  const listed=entry.apiId?{...entry,body:'',responseBody:'',bodyLoaded:false}:entry;
  setTraffic(prev=>{
   const i=entry.apiId?prev.findIndex(r=>r.apiId===entry.apiId):-1;
   if(i<0) return [listed,...prev];
   const next=[...prev];next[i]={...listed,id:prev[i]!.id};return next;
  });
 },[]);
 const onNewEntry = useCallback((entry:Traffic)=>{ refreshCountsSoon(); addEntry(entry); },[refreshCountsSoon,addEntry]);
 const onCleared = useCallback((workspaceId?:string)=>{
  void syncFromProxy().catch(()=>{});
  setTraffic(prev=>prev.filter(r=>!r.apiId||(workspaceId!==undefined&&r.workspaceId!==workspaceId)));
  refreshWorkspaces();
 },[refreshWorkspaces,syncFromProxy]);
 const { status: proxyStatus } = useTrafficStream(onNewEntry, onCleared, refreshWorkspaces, onIntercept);

 // (Re)sync after the socket connects so events missed while offline are picked up
 useEffect(()=>{ if(proxyStatus==='connected'){ syncFromProxy().catch(()=>{}); refreshWorkspaces(); syncIntercept(); } },[proxyStatus,syncFromProxy,refreshWorkspaces,syncIntercept]);

 // A viewed workspace that no longer exists (deleted here or elsewhere) falls back to all workspaces
 useEffect(()=>{ if(workspaces.length&&view!==ALL_WORKSPACES&&view!==TEMP_WORKSPACE&&!workspaces.some(w=>w.id===view)) setView(ALL_WORKSPACES); },[workspaces,view,setView]);

 // With no saved view (first visit), start on wherever the proxy is already capturing.
 useEffect(()=>{
  if(!session||viewDecided.current) return;
  if(session.target==='workspace'&&session.workspace_id) setView(session.workspace_id);
  else if(session.target==='temporary') setView(TEMP_WORKSPACE);
 },[session,setView]);

 // Mutations reload the list afterwards so the UI reflects what the backend actually stored.
 const createWorkspace=useCallback(async(name:string)=>{const w=await apiCreateWorkspace(name);await refreshWorkspaces();return w;},[refreshWorkspaces]);
 const renameWorkspace=useCallback(async(id:string,name:string)=>{await apiRenameWorkspace(id,name);await refreshWorkspaces();},[refreshWorkspaces]);
 const deleteWorkspace=useCallback(async(id:string)=>{await apiDeleteWorkspace(id);await refreshWorkspaces();},[refreshWorkspaces]);
 const activateWorkspace=useCallback(async(id:string)=>{await apiActivateWorkspace(id);await refreshWorkspaces();},[refreshWorkspaces]);

 // Choosing a target also switches the view to it, so new requests show up where the user is looking.
 const chooseWorkspace=useCallback(async(id:string)=>{await apiActivateWorkspace(id);await refreshWorkspaces();setView(id);},[refreshWorkspaces,setView]);
 const chooseTemporary=useCallback(async()=>{await apiUseTemporary();await refreshWorkspaces();setView(TEMP_WORKSPACE);},[refreshWorkspaces,setView]);

 // Store a replayed request next to captured traffic. Returns null when the proxy could not save it.
 const saveReplay=useCallback(async(request:HttpRequest,outcome:ReplayOutcome):Promise<Traffic|null>=>{
  try{
   const ok='status' in outcome;
   const saved=await apiSaveReplay({method:request.method,url:request.url,request_headers:Object.entries(request.headers),request_body:request.body,status_code:ok?outcome.status:0,response_headers:ok?Object.entries(outcome.headers):[],response_body:ok?outcome.body:'',duration_ms:ok?outcome.duration:0,error:ok?null:outcome.error});
   const row=mapApiEntry(saved);addEntry(row);refreshCountsSoon();return row;
  }catch{return null;}
 },[addEntry,refreshCountsSoon]);

 // ── Replay tabs follow the workspace requests are being saved to ──
 // With no workspace (unchosen or temporary) they stay local and are lost on reload, like everything else.
 const activeWorkspaceId=session?.target==='workspace'?session.workspace_id:null;
 const variablesWorkspace=useRef<string|null>(null);
 const [tabsWorkspace,setTabsWorkspace]=useState<string|null>(null); // workspace the on-screen tabs belong to
 const pendingTabs=useRef<{workspaceId:string;json:string;doc:unknown}|null>(null);
 const tabsTimer=useRef<ReturnType<typeof globalThis.setTimeout>|undefined>(undefined);
 const lastSavedTabs=useRef<string|null>(null);
 const flushTabs=useCallback((keepalive=false)=>{
  globalThis.clearTimeout(tabsTimer.current);tabsTimer.current=undefined;
  const pending=pendingTabs.current;if(!pending) return Promise.resolve();
  pendingTabs.current=null;lastSavedTabs.current=pending.json;
  // Best effort: on failure forget what we think is saved so the next change tries again.
  return apiSaveReplayTabs(pending.workspaceId,pending.doc,{keepalive}).catch(()=>{lastSavedTabs.current=null;toast.error('Replay changes could not be saved to the workspace.');});
 },[]);

 useEffect(()=>{
  if(variablesWorkspace.current!==activeWorkspaceId){setVariables({});setSessions(prev=>prev.map(tab=>({...tab,runs:[],loading:false})));variablesWorkspace.current=activeWorkspaceId;}
  setTabsWorkspace(null); // stop saving the old tabs under the new workspace while loading
  if(proxyStatus!=='connected'||!activeWorkspaceId){ void flushTabs(); return; }
  let cancelled=false;
  void flushTabs().then(()=>apiFetchReplayTabs(activeWorkspaceId)).then(doc=>{
   if(cancelled) return;
   const loadedVariables=normalizeVariables(doc);setVariables(loadedVariables);
   const tabs=normalizeStoredTabs(doc);
   if(tabs.length){
    const activeTab=pickActive(tabs,(doc as {active?:unknown}|null)?.active);
    setSessions(tabs.map(t=>({...t})));setActive(activeTab);
    lastSavedTabs.current=JSON.stringify(serializeTabs(tabs,activeTab,loadedVariables));
   } else lastSavedTabs.current=null; // nothing stored yet: what is on screen becomes this workspace's first save
   setTabsWorkspace(activeWorkspaceId);
  }).catch(()=>{});
  return ()=>{cancelled=true;};
 },[activeWorkspaceId,proxyStatus,flushTabs]);

 // Apply Replay edits/results made by MCP to the currently open saved workspace.
 useEffect(()=>{
  const onReplay=(event:Event)=>{
   const data=(event as CustomEvent).detail;
   if(!activeWorkspaceId||data.workspace_id!==activeWorkspaceId) return;
   if(data.type==='replay_changed'){
    const loadedVariables=normalizeVariables(data.document);setVariables(loadedVariables);
    const tabs=normalizeStoredTabs(data.document);
    const nextActive=pickActive(tabs,data.document?.active);
    globalThis.clearTimeout(tabsTimer.current);pendingTabs.current=null;
    lastSavedTabs.current=JSON.stringify(serializeTabs(tabs,nextActive,loadedVariables));
    setSessions(prev=>tabs.map(tab=>{const existing=prev.find(t=>t.id===tab.id);return {...tab,...(existing?.response&&JSON.stringify(existing.request)===JSON.stringify(tab.request)?{response:existing.response}:{})};}));
    setActive(nextActive);setTabsWorkspace(activeWorkspaceId);
   }else if(data.type==='replay_result'){
    const entry=mapApiEntry(data.entry);
    setSessions(prev=>prev.map(tab=>tab.id===data.tab_id?{...tab,response:entry,error: data.entry.error??undefined,loading:false}:tab));
   }
  };
  window.addEventListener('httpdebugger:replay',onReplay);
  return ()=>window.removeEventListener('httpdebugger:replay',onReplay);
 },[activeWorkspaceId]);

 // Debounced autosave; skips when nothing that is persisted changed (e.g. a response arrived).
 useEffect(()=>{
  if(!activeWorkspaceId||tabsWorkspace!==activeWorkspaceId) return;
  const doc=serializeTabs(sessions,active,variables);const json=JSON.stringify(doc);
  if(json===lastSavedTabs.current&&!pendingTabs.current) return;
  pendingTabs.current={workspaceId:activeWorkspaceId,json,doc};
  globalThis.clearTimeout(tabsTimer.current);
  tabsTimer.current=globalThis.setTimeout(()=>{void flushTabs();},700);
 },[sessions,active,variables,activeWorkspaceId,tabsWorkspace,flushTabs]);

 const scriptCommitQueue=useRef<Promise<void>>(Promise.resolve());
 const commitScriptVariables=useCallback((workspace:string|null,patch:ReplayVariables)=>{
  const commit=scriptCommitQueue.current.catch(()=>{}).then(async()=>{
   if(getReplayWorkspace()===workspace){setVariables(prev=>({...prev,...patch}));return;}
   if(!workspace)return;
   await flushTabs();
   const doc=await apiFetchReplayTabs(workspace) as Record<string,unknown>;
   await apiSaveReplayTabs(workspace,{...doc,variables:{...normalizeVariables(doc),...patch}});
  });
  scriptCommitQueue.current=commit;return commit;
 },[getReplayWorkspace,flushTabs]);

 // Don't lose the last edits when the tab is closed or the provider goes away.
 useEffect(()=>{
  const onHide=()=>{void flushTabs(true);};
  window.addEventListener('pagehide',onHide);
  return ()=>{window.removeEventListener('pagehide',onHide);void flushTabs(true);};
 },[flushTabs]);

 const setIntercept=useCallback(async(update:Partial<InterceptSettings>)=>{setInterceptState(await apiUpdateInterceptSettings(update));},[]);
 // Actions leave the list alone until the proxy confirms, and re-sync when it refuses (e.g. the item timed out).
 const settle=useCallback(async(action:()=>Promise<void>,remove?:(prev:HeldItem[])=>HeldItem[])=>{
  try{await action();if(remove)setHeld(remove);}catch(e){void syncIntercept();throw e;}
 },[syncIntercept]);
 const forwardHeld=useCallback((id:string,edit?:InterceptEdit)=>settle(()=>apiForwardHeld(id,edit),prev=>prev.filter(h=>h.id!==id)),[settle]);
 const dropHeld=useCallback((id:string)=>settle(()=>apiDropHeld(id),prev=>prev.filter(h=>h.id!==id)),[settle]);
 const forwardAllHeld=useCallback(()=>settle(()=>apiForwardAllHeld(),()=>[]),[settle]);

 return <Context.Provider value={{commitScriptVariables,getReplayWorkspace,variables,setVariables,annotateTraffic,ensureTrafficDetails,historyTotal,historyLoading,historyMore,historyError,loadMoreHistory,retryHistory:(reset=false)=>{void (!reset&&historyCursor.current?loadMoreHistory():syncFromProxy()).catch(()=>{});},setHistoryQuery,traffic,setTraffic,sessions,setSessions,active,setActive,timeout,setTimeout,scope,setScope,updateScope,scopeEnabled,setScopeEnabled,proxyStatus,workspaces,view,setView,createWorkspace,renameWorkspace,deleteWorkspace,activateWorkspace,held,intercept,setIntercept,forwardHeld,dropHeld,forwardAllHeld,session,chooseWorkspace,chooseTemporary,saveReplay}}>{children}</Context.Provider>;
}
function Status({status}:{status:number}){return <span className={cn('inline-flex min-w-9 justify-center rounded px-1.5 py-0.5 font-mono text-[10px] font-medium',status>=400?'bg-destructive/15 text-destructive':status>=300?'bg-warning/10 text-warning':status>=200?'bg-success/10 text-success':'bg-muted text-muted-foreground')}>{status||'—'}</span>;}
function Method({method}:{method:string}){return <span className={cn('font-mono text-[11px] font-medium',method==='GET'?'text-primary':method==='POST'?'text-method-post':method==='PUT'||method==='PATCH'?'text-method-put':method==='DELETE'?'text-destructive':'text-muted-foreground')}>{method}</span>;}

function WorkspaceSwitcher(){
 const {workspaces,view,setView,proxyStatus,session}=useInspector();
 const current=workspaces.find(w=>w.id===view);
 const label=view===ALL_WORKSPACES?'All saved workspaces':view===TEMP_WORKSPACE?'Temporary session':current?.name??'Workspace';
 const offline=proxyStatus!=='connected'&&!workspaces.length;
 // The in-memory session is only listed while it is in use or still holds requests.
 const showTemp=!!session&&(session.target!=='workspace'||session.temporary_count>0);
 return <DropdownMenu><DropdownMenuTrigger asChild><Button variant="ghost" size="sm" className="h-8 gap-2 px-2 text-xs" aria-label="Switch workspace" disabled={offline} title={offline?'Start the proxy to use workspaces':'Switch workspace'}><Folder className={cn('size-3.5',view===TEMP_WORKSPACE?'text-warning':'text-muted-foreground')}/><span className="max-w-40 truncate">{label}</span><ChevronDown className="size-3 text-muted-foreground"/></Button></DropdownMenuTrigger><DropdownMenuContent align="end" className="w-64"><DropdownMenuLabel className="text-[10px] tracking-[1.5px] text-muted-foreground">VIEW HISTORY OF</DropdownMenuLabel><DropdownMenuItem onSelect={()=>setView(ALL_WORKSPACES)}><Layers className="size-3.5"/>All saved workspaces{view===ALL_WORKSPACES&&<Check className="ml-auto size-3.5"/>}</DropdownMenuItem>{workspaces.map(w=><DropdownMenuItem key={w.id} onSelect={()=>setView(w.id)}><Folder className="size-3.5"/><span className="truncate">{w.name}</span>{w.active&&<span title="New traffic is captured here" className="rounded bg-primary/10 px-1 text-[9px] text-primary">CAPTURING</span>}<span className="ml-auto font-mono text-[10px] text-muted-foreground">{w.request_count}</span>{view===w.id&&<Check className="size-3.5"/>}</DropdownMenuItem>)}{showTemp&&<DropdownMenuItem onSelect={()=>setView(TEMP_WORKSPACE)}><TriangleAlert className="size-3.5 text-warning"/><span className="truncate">Temporary session</span>{session?.target==='temporary'&&<span title="New traffic is kept in memory only" className="rounded bg-warning/10 px-1 text-[9px] text-warning">CAPTURING</span>}<span className="ml-auto font-mono text-[10px] text-muted-foreground">{session?.temporary_count??0}</span>{view===TEMP_WORKSPACE&&<Check className="size-3.5"/>}</DropdownMenuItem>}<DropdownMenuSeparator/><DropdownMenuItem asChild><Link to="/workspaces"><Settings2 className="size-3.5"/>Manage workspaces…</Link></DropdownMenuItem></DropdownMenuContent></DropdownMenu>;
}

export function InspectorShell({children}:{children:ReactNode}) {
 const {traffic,sessions,proxyStatus,workspaces,held,session,createWorkspace,chooseWorkspace,chooseTemporary}=useInspector();const gateOpen=proxyStatus==='connected'&&session?.target==='unchosen';const [collapsed,setCollapsed]=useState(false);
 const nav=[{label:'Dashboard',to:'/dashboard' as const,icon:ShieldCheck},{label:'Intercept',to:'/intercept' as const,icon:Hand,count:held.length||undefined},{label:'HTTP History',to:'/' as const,icon:List,count:traffic.length},{label:'Replay',to:'/replay' as const,icon:Terminal,count:sessions.length},{label:'Intruder',to:'/intruder' as const,icon:Layers},{label:'Flows',to:'/flows' as const,icon:Workflow},{label:'Profiles',to:'/profiles' as const,icon:ShieldCheck},{label:'Authorization Matrix',to:'/matrix' as const,icon:Layers},{label:'Workspaces',to:'/workspaces' as const,icon:Folder,count:workspaces.length||undefined},{label:'Scope & Filters',to:'/scope' as const,icon:Filter},{label:'Tools',to:'/tools' as const,icon:Code2},{label:'MCP',to:'/mcp' as const,icon:Bot},{label:'Settings',to:'/settings' as const,icon:Settings2}];
 return <><div className="inspector-shell flex flex-col overflow-hidden" inert={gateOpen||undefined}><header className="flex h-14 shrink-0 items-center border-b border-border bg-card px-5"><Link to="/" className="flex items-center gap-2.5"><span className="flex size-7 items-center justify-center rounded bg-primary text-primary-foreground"><Activity className="size-5" strokeWidth={2.2}/></span><span className="text-lg font-semibold">Slurp<span className="text-primary">.</span></span></Link><span className="ml-3 hidden rounded border border-border px-1.5 py-0.5 font-mono text-[9px] text-muted-foreground sm:block">Sip traffic</span><div className="ml-auto flex items-center gap-5"><span className="hidden items-center gap-2 text-xs text-muted-foreground sm:flex"><span className={cn('size-1.5 rounded-full',proxyStatus==='connected'?'bg-primary':proxyStatus==='connecting'?'bg-warning animate-pulse':'bg-destructive')}/>{proxyStatus==='connected'?'Proxy connected':proxyStatus==='connecting'?'Connecting…':'Proxy offline'}</span><span className="h-5 border-l border-border"/><WorkspaceSwitcher/><span className="flex size-7 items-center justify-center rounded bg-secondary text-[10px] font-medium">AM</span></div></header>
 <div className="flex min-h-0 flex-1"><aside className={cn('flex shrink-0 flex-col border-r border-border bg-card transition-[width]',collapsed?'w-14':'w-52 max-md:w-14')}><div className={cn('flex h-16 items-center justify-between px-4',collapsed&&'px-2')}><span className={cn('text-[10px] font-medium tracking-[1.5px] text-muted-foreground max-md:hidden',collapsed&&'hidden')}>WORKSPACE</span><Button variant="ghost" size="icon" className="size-7 text-muted-foreground" onClick={()=>setCollapsed(!collapsed)} aria-label="Toggle sidebar" title="Toggle sidebar">{collapsed?<PanelLeftOpen/>:<PanelLeftClose/>}</Button></div><nav className="space-y-1 px-2">{nav.map(({label,to,icon:Icon,count})=><Button key={label} asChild variant="ghost" className="h-10 w-full justify-start rounded px-3 text-[12px] font-normal text-muted-foreground"><Link to={to} activeOptions={{exact:true}} activeProps={{className:'nav-active'}} title={label}><Icon className="size-4"/><span className={cn('max-md:hidden',collapsed&&'hidden')}>{label}</span>{count!==undefined&&<span className={cn('ml-auto rounded bg-background/50 px-1.5 py-0.5 font-mono text-[10px] max-md:hidden',collapsed&&'hidden')}>{count}</span>}</Link></Button>)}</nav></aside><main className="flex min-w-0 flex-1 flex-col">{session?.target==='temporary'&&<div role="status" className="flex shrink-0 items-center gap-2 border-b border-warning/30 bg-warning/10 px-6 py-1.5 text-xs text-warning"><TriangleAlert className="size-3.5 shrink-0"/><span>Temporary session: requests are kept in memory only and are lost when the tool closes.</span><Link to="/workspaces" className="ml-auto shrink-0 underline underline-offset-2">Choose a workspace</Link></div>}{children}</main></div><footer className="flex h-7 shrink-0 items-center justify-between border-t border-border bg-card px-4 font-mono text-[10px] text-muted-foreground"><span className="flex items-center gap-2"><span>Slurp v1.0.0</span><span className="mx-2 text-border">|</span><ShieldCheck className="size-3 text-primary"/>HTTPS replay<span className="mx-2 text-border">|</span>{traffic.length} requests</span><span className="flex items-center gap-2"><span className={cn('size-1 rounded-full',proxyStatus==='connected'?'bg-primary':'bg-destructive')}/>{proxyStatus==='connected'?'Proxy connected':'Proxy offline'}</span></footer></div>{gateOpen&&<WorkspaceGate workspaces={workspaces} onChoose={chooseWorkspace} onCreate={async name=>{const w=await createWorkspace(name);await chooseWorkspace(w.id);}} onTemporary={chooseTemporary}/>}</>;
}
function ImportDialog({open,onOpenChange}:{open:boolean;onOpenChange:(value:boolean)=>void}) {
 const {setTraffic}=useInspector();const [text,setText]=useState('');const input=useRef<HTMLInputElement>(null);
 const load=(source:string)=>{try{const rows=importTraffic(source);if(!rows.length)throw new Error('The file contains no requests.');setTraffic(prev=>{let id=Math.max(0,...prev.map(r=>r.id));return [...rows.map(r=>({...r,id:++id})).reverse(),...prev];});toast.success(`Imported ${rows.length} requests`);onOpenChange(false);setText('');}catch(e){toast.error(e instanceof Error?e.message:'Import failed');}};
 return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent className="bg-card"><DialogHeader><DialogTitle>Import traffic</DialogTitle><DialogDescription>HAR, JSON, or cURL</DialogDescription></DialogHeader><input ref={input} type="file" accept=".har,.json,.txt,.curl" className="hidden" onChange={async e=>{const file=e.target.files?.[0];if(!file)return;if(file.size>20_000_000){toast.error('Maximum file size is 20 MB.');return;}load(await file.text());e.target.value='';}}/><Button variant="outline" onClick={()=>input.current?.click()}><ArrowUpFromLine/>Choose file</Button><span className="text-center text-xs text-muted-foreground">or paste a cURL command / JSON</span><textarea aria-label="Import content" className="inspector-input min-h-44 font-mono text-xs" value={text} onChange={e=>setText(e.target.value)} placeholder={'curl https://httpbin.org/get -H "Accept: application/json"'}/><Button disabled={!text.trim()} onClick={()=>load(text)}>Import requests<ArrowUpRight/></Button></DialogContent></Dialog>;
}
/** Chooses which workspace receives newly captured requests, and creates workspaces on the spot. */
export function CaptureControl(){
 const {workspaces,session,proxyStatus,setView,createWorkspace,chooseWorkspace,chooseTemporary}=useInspector();
 const [creating,setCreating]=useState(false),[name,setName]=useState(''),[busy,setBusy]=useState(false);
 const current=workspaces.find(w=>w.active);
 const temporary=session?.target==='temporary';
 const offline=proxyStatus!=='connected'&&!workspaces.length;
 const fail=(e:unknown)=>toast.error(e instanceof Error?e.message:'Something went wrong');
 // Choosing also shows that workspace, otherwise new requests would arrive in a list the user is not looking at.
 const choose=async(w:Workspace)=>{
  if(w.active){setView(w.id);return;}
  try{await chooseWorkspace(w.id);toast.success(`New requests will be saved to \u201c${w.name}\u201d`);}catch(e){fail(e);}
 };
 const chooseNone=async()=>{
  try{await chooseTemporary();toast.warning('No workspace: new requests are kept in memory and lost when the tool closes');}catch(e){fail(e);}
 };
 const create=async()=>{
  setBusy(true);
  try{const w=await createWorkspace(name);await chooseWorkspace(w.id);setCreating(false);setName('');toast.success(`Workspace \u201c${w.name}\u201d created \u2014 new requests will be saved to it`);}
  catch(e){fail(e);}
  finally{setBusy(false);}
 };
 return <><DropdownMenu modal={false}><DropdownMenuTrigger asChild><Button variant="outline" size="sm" disabled={offline} title={offline?'Start the proxy to choose a workspace':'Choose where new requests are saved'} aria-label="Capture workspace"><Radio className={temporary?'text-warning':'text-primary'}/><span className="max-sm:hidden text-muted-foreground">Saving to</span><span className={cn('max-w-32 truncate',temporary&&'text-warning')}>{current?.name??(temporary?'Not saved':'\u2014')}</span><ChevronDown className="size-3"/></Button></DropdownMenuTrigger><DropdownMenuContent align="end" className="w-64"><DropdownMenuLabel className="text-[10px] tracking-[1.5px] text-muted-foreground">SAVE NEW REQUESTS TO</DropdownMenuLabel>{workspaces.map(w=><DropdownMenuItem key={w.id} onSelect={()=>{void choose(w);}}><Folder className="size-3.5"/><span className="truncate">{w.name}</span><span className="ml-auto font-mono text-[10px] text-muted-foreground">{w.request_count}</span>{w.active&&<Check className="size-3.5 text-primary" aria-label="Currently saving here"/>}</DropdownMenuItem>)}<DropdownMenuSeparator/><DropdownMenuItem onSelect={()=>{void chooseNone();}}><TriangleAlert className="size-3.5 text-warning"/><span>No workspace (memory only)</span>{temporary&&<Check className="ml-auto size-3.5 text-warning" aria-label="Currently saving here"/>}</DropdownMenuItem><DropdownMenuItem onSelect={()=>setCreating(true)}><Plus className="size-3.5"/>New workspace…</DropdownMenuItem></DropdownMenuContent></DropdownMenu>
 <Dialog open={creating} onOpenChange={o=>{if(!busy){setCreating(o);if(!o)setName('');}}}><DialogContent className="bg-card"><DialogHeader><DialogTitle>New workspace</DialogTitle><DialogDescription>New requests will be saved to this workspace until you pick another one.</DialogDescription></DialogHeader><form className="flex flex-col gap-4" onSubmit={e=>{e.preventDefault();if(name.trim()&&!busy)void create();}}><input autoFocus aria-label="Workspace name" className="inspector-input text-sm" placeholder="e.g. Login flow" maxLength={60} value={name} onChange={e=>setName(e.target.value)}/><div className="flex justify-end gap-2"><Button type="button" variant="outline" disabled={busy} onClick={()=>{setCreating(false);setName('');}}>Cancel</Button><Button type="submit" disabled={busy||!name.trim()}>Create and save here</Button></div></form></DialogContent></Dialog></>;
}
function HttpHistoryView(){
 const {annotateTraffic,ensureTrafficDetails,historyTotal,historyLoading,historyMore,historyError,loadMoreHistory,retryHistory,setHistoryQuery,traffic,setTraffic,sessions,setSessions,setActive,scope,scopeEnabled,view,workspaces}=useInspector();const [selected,setSelected]=useState(1048),[search,setSearch]=useState(''),[method,setMethod]=useState('All methods'),[status,setStatus]=useState('All statuses'),[showImport,setShowImport]=useState(false),[clear,setClear]=useState(false),[sort,setSort]=useState(false);
 const [bookmarkedOnly,setBookmarkedOnly]=useState(false);
 const scrollRef=useRef<HTMLDivElement>(null);
 const [viewport,setViewport]=useState({top:0,height:400});
 useEffect(()=>{if(scrollRef.current)scrollRef.current.scrollTop=0;setViewport(v=>({...v,top:0}));},[view]);
 useEffect(()=>{
  const timer=globalThis.setTimeout(()=>{setHistoryQuery({...(bookmarkedOnly&&{bookmarked:true}),...(search.trim()&&{search:search.trim()}),...(method!=='All methods'&&{method}),...(status!=='All statuses'&&{status_class:Number(status[0])}),...(scopeEnabled&&scope.trim()&&{domains:scope.split('\n')}),...(sort&&{ascending:true})});if(scrollRef.current)scrollRef.current.scrollTop=0;setViewport(v=>({...v,top:0}));},250);
  return ()=>globalThis.clearTimeout(timer);
 },[search,method,status,scope,scopeEnabled,sort,bookmarkedOnly,setHistoryQuery]);
 useEffect(()=>{
  const node=scrollRef.current;if(!node)return;
  const measure=()=>setViewport({top:node.scrollTop,height:node.clientHeight||400});
  measure();if(typeof ResizeObserver==='undefined')return;
  const observer=new ResizeObserver(measure);observer.observe(node);return ()=>observer.disconnect();
 },[]);
 const displayIds=useMemo(()=>{const ordered=[...traffic].sort(compareHistory);const base=sort?0:Math.max(0,historyTotal-traffic.length);return new Map(ordered.map((r,index)=>[r.id,base+index+1]));},[traffic,historyTotal,sort]);
 const rows=traffic.filter(r=>(!bookmarkedOnly||r.bookmarked)&&(method==='All methods'||r.method===method)&&(status==='All statuses'||Math.floor(r.status/100)===Number(status[0]))&&(!scopeEnabled||!scope.trim()||scope.split('\n').includes(new URL(r.url).hostname.toLowerCase().replace(/\.$/,'')))&&(r.apiId||`${r.method} ${r.url} ${r.status} ${displayIds.get(r.id)} ${r.notes??''}`.toLowerCase().includes(search.toLowerCase())));rows.sort((a,b)=>sort?displayIds.get(a.id)!-displayIds.get(b.id)!:displayIds.get(b.id)!-displayIds.get(a.id)!);
 // Preserve the visible rows when live captures prepend to the list.
 const previousFirst=useRef<{id:number|undefined;view:string;sort:boolean}>({id:undefined,view,sort});
 useLayoutEffect(()=>{
  const previous=previousFirst.current,node=scrollRef.current;
  if(node&&node.scrollTop>36&&!sort&&previous.view===view&&previous.sort===sort&&previous.id!==undefined){
   const shift=rows.findIndex(row=>row.id===previous.id);
   if(shift>0){node.scrollTop+=shift*32;setViewport({top:node.scrollTop,height:node.clientHeight||400});}
  }
  previousFirst.current={id:rows[0]?.id,view,sort};
 });
 const start=Math.min(rows.length,Math.max(0,Math.floor(Math.max(0,viewport.top-36)/32)-8));
 const end=Math.min(rows.length,Math.ceil((viewport.top+viewport.height)/32)+8);
 useEffect(()=>{
  if(historyMore&&!historyLoading&&!historyError&&viewport.top+viewport.height>=rows.length*32-320)void loadMoreHistory();
 },[viewport,rows.length,historyMore,historyLoading,historyError,loadMoreHistory]);
 const selectedRow=rows.find(r=>r.id===selected)??rows[0];
 const [detail,setDetail]=useState<Traffic|null>(null),[detailError,setDetailError]=useState(''),[detailRetry,setDetailRetry]=useState(0);
 useEffect(()=>{
  let cancelled=false;setDetail(null);setDetailError('');
  if(selectedRow?.bodyLoaded===false)void ensureTrafficDetails(selectedRow).then(row=>{if(!cancelled)setDetail(row);},error=>{if(!cancelled)setDetailError(error instanceof Error?error.message:'Could not load request');});
  return ()=>{cancelled=true;};
 },[selectedRow,ensureTrafficDetails,detailRetry]);
 const current=detail&&selectedRow&&detail.id===selectedRow.id?{...detail,bookmarked:selectedRow.bookmarked??false,notes:selectedRow.notes??''}:selectedRow;

 const replay=async(row:Traffic)=>{try{const r=await ensureTrafficDetails(row);const id=nextReplayTabId(sessions);setSessions(prev=>[...prev,{id,name:new URL(r.url).pathname,request:{method:r.method,url:r.url,headers:r.headers,body:r.body}}]);setActive(id);}catch(error){toast.error(error instanceof Error?error.message:'Could not load request');}};
 const exportLog=async()=>{try{const exported=[];for(const row of traffic)exported.push(await ensureTrafficDetails(row));const url=URL.createObjectURL(new Blob([JSON.stringify(exported,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='slurp-traffic.json';a.click();URL.revokeObjectURL(url);toast.success('Loaded traffic exported');}catch(error){toast.error(error instanceof Error?error.message:'Export failed');}};
 return <><div className="flex h-20 shrink-0 items-center justify-between px-6"><div><div className="flex items-center gap-3"><h1 className="text-xl font-semibold">HTTP History</h1><span className="rounded bg-secondary px-2 py-0.5 font-mono text-[10px] text-muted-foreground">{traffic.length} requests</span></div><p className="mt-1.5 text-xs text-muted-foreground">Captured traffic in your workspace</p></div><div className="flex items-center gap-2"><CaptureControl/><span className="mx-1 h-5 border-l border-border"/><Button variant="outline" size="sm" onClick={()=>setShowImport(true)}><ArrowUpFromLine/><span className="max-sm:hidden">Import</span></Button><Button variant="outline" size="sm" onClick={exportLog} title="Export loaded requests"><ArrowDownToLine/><span className="max-sm:hidden">Export</span><ChevronDown className="size-3"/></Button><span className="mx-1 h-5 border-l border-border"/><Button variant="ghost" size="icon" className="size-8 text-muted-foreground" onClick={()=>setClear(true)} aria-label="Clear history" title="Clear history"><Trash2/></Button></div></div>
 <div className="mx-6 mb-4 flex shrink-0 items-center gap-2"><div className="relative min-w-0 flex-1"><Search className="absolute left-3 top-2.5 size-3.5 text-muted-foreground"/><input aria-label="Search traffic" placeholder="Search requests by URL, path, or keyword…" className="inspector-input h-9 w-full pl-9 text-xs" value={search} onChange={e=>setSearch(e.target.value)}/>{search&&<Button aria-label="Clear search" variant="ghost" className="absolute right-0 top-0 size-9" onClick={()=>setSearch('')}><X/></Button>}</div><select aria-label="Filter by method" className="inspector-input h-9 w-32 text-xs max-sm:w-20" value={method} onChange={e=>setMethod(e.target.value)}>{['All methods',...methods].map(m=><option key={m}>{m}</option>)}</select><select aria-label="Filter by status" className="inspector-input h-9 w-32 text-xs max-sm:w-20" value={status} onChange={e=>setStatus(e.target.value)}>{['All statuses','2xx Success','3xx Redirect','4xx Client error','5xx Server error'].map(s=><option key={s}>{s}</option>)}</select><Button variant={bookmarkedOnly?"secondary":"outline"} size="icon" className="size-9" title="Show bookmarked requests" aria-label="Show bookmarked requests" aria-pressed={bookmarkedOnly} onClick={()=>setBookmarkedOnly(!bookmarkedOnly)}><Bookmark className={cn(bookmarkedOnly&&"fill-primary text-primary")}/></Button><Button asChild variant="outline" size="icon" className="size-9" title="Scope and filters"><Link to="/scope"><Filter/></Link></Button></div>
 <div className="min-h-0 flex-1"><ResizablePanelGroup orientation="vertical"><ResizablePanel defaultSize="52%" minSize="20%"><div className="flex h-full flex-col border-t border-border"><div ref={scrollRef} aria-label="History requests" onScroll={e=>setViewport({top:e.currentTarget.scrollTop,height:e.currentTarget.clientHeight})} className="min-h-0 flex-1 overflow-auto"><table className="w-full table-fixed border-collapse text-left text-xs" style={{minWidth:850}}><thead className="sticky top-0 z-10 bg-card text-[10px] font-medium text-muted-foreground"><tr className="h-9 border-b border-border"><th className="w-24 pl-5"><Button variant="ghost" className="h-6 p-0 text-[10px]" onClick={()=>setSort(!sort)}>ID<ChevronDown className="size-3"/></Button></th><th className="w-20">Method</th><th className="w-36">Host</th><th>Path</th><th className="w-20">Status</th><th className="w-20">Size</th><th className="w-24">Time</th><th className="w-28">Timestamp</th><th className="w-10"/></tr></thead><tbody>{start>0&&<tr aria-hidden="true"><td colSpan={9} style={{height:start*32,padding:0,border:0}}/></tr>}{rows.slice(start,end).map(r=>{const url=new URL(r.url);return <RequestMenu key={r.id} request={()=>ensureTrafficDetails(r)}><tr tabIndex={0} aria-selected={current?.id===r.id} onClick={()=>setSelected(r.id)} onKeyDown={e=>{if(e.key==='Enter')setSelected(r.id);}} className={cn('traffic-row h-8 border-b border-border/40',current?.id===r.id&&'selected')}><td className="pl-3 font-mono text-[11px] text-muted-foreground"><span className="inline-flex items-center gap-1"><Button variant="ghost" size="icon" className="size-6" aria-label={`${r.bookmarked?'Remove bookmark':'Bookmark'} request ${displayIds.get(r.id)}`} title={r.notes||'Bookmark request'} onClick={e=>{e.stopPropagation();void annotateTraffic(r,{bookmarked:!r.bookmarked}).catch(error=>toast.error(error instanceof Error?error.message:'Could not save bookmark'));}}><Bookmark className={cn('size-3',r.bookmarked&&'fill-primary text-primary')}/></Button>{displayIds.get(r.id)}{r.notes&&<span title={r.notes} className="size-1 rounded-full bg-primary"/>}</span></td><td><Method method={r.method}/>{r.source==='replay'&&<span title="Sent from Replay" className="ml-1.5 rounded bg-secondary px-1 text-[9px] text-muted-foreground">REPLAY</span>}</td><td className="truncate pr-3 text-muted-foreground">{url.host}</td><td className="truncate pr-3 font-mono text-[11px]">{url.pathname}<span className="text-muted-foreground">{url.search}</span></td><td><Status status={r.status}/></td><td className="font-mono text-[10px] text-muted-foreground">{sizeLabel(r.size)}</td><td className={cn('font-mono text-[10px]',r.duration>200?'text-warning':'text-muted-foreground')}>{r.duration}<span className="ml-1 text-muted-foreground">ms</span></td><td className="font-mono text-[10px] text-muted-foreground">{new Date(r.timestamp).toLocaleTimeString('en-GB')}</td><td><Button asChild variant="ghost" className="size-6 p-0 text-muted-foreground" title="Send to Replay" onClick={e=>{e.stopPropagation();replay(r);}}><Link to="/replay" aria-label={`Replay request ${displayIds.get(r.id)}`}><ArrowUpRight className="size-3"/></Link></Button></td></tr></RequestMenu>;})}{end<rows.length&&<tr aria-hidden="true"><td colSpan={9} style={{height:(rows.length-end)*32,padding:0,border:0}}/></tr>}</tbody></table>{historyLoading&&<div role="status" className="p-3 text-center text-xs text-muted-foreground">Loading requests…</div>}{historyError&&<div role="alert" className="p-3 text-center text-xs">{historyError}<Button variant="ghost" size="sm" onClick={()=>retryHistory()}>Retry</Button></div>}{!rows.length&&!historyLoading&&<div className="flex h-40 flex-col items-center justify-center gap-3 text-muted-foreground"><Search className="size-6"/><span>No matching requests</span><Button variant="ghost" size="sm" onClick={()=>{setSearch('');setMethod('All methods');setStatus('All statuses');setBookmarkedOnly(false);}}>Reset filters</Button></div>}</div><div className="flex h-8 shrink-0 items-center justify-between border-t border-border bg-card px-5 text-[10px] text-muted-foreground"><span>Showing <span className="text-foreground">{rows.length}</span> of {Math.max(historyTotal,traffic.length)} requests{historyMore?' · Scroll to load more':''}</span><span className="flex items-center gap-2"><span className="size-1.5 rounded-full bg-primary"/>{traffic.some(r=>r.apiId)?`Live proxy capture${workspaces.find(w=>w.active)?` \u2192 ${workspaces.find(w=>w.active)?.name}`:''}`:traffic.length?'Imported traffic':'No captured traffic'}</span></div></div></ResizablePanel><ResizableHandle className="h-1 w-full cursor-row-resize bg-border"/><ResizablePanel defaultSize="48%" minSize="20%">{current?<RequestMenu request={()=>ensureTrafficDetails(current)}><div className="flex h-full flex-col"><div className="flex h-11 shrink-0 items-center justify-between border-b border-border bg-card px-5"><div className="flex min-w-0 items-center gap-3"><Method method={current.method}/><Status status={current.status}/><span className="truncate font-mono text-[11px]">{current.url}</span></div><div className="ml-3 flex shrink-0 items-center gap-2"><TrafficNotes key={current.id} notes={current.notes??''} onSave={notes=>annotateTraffic(current,{notes})}/><span className="hidden items-center gap-1.5 text-[10px] text-muted-foreground lg:flex"><Clock3 className="size-3"/>{current.duration} ms<span className="mx-1">·</span>{sizeLabel(current.size)}</span><Button asChild variant="secondary" size="sm" className="h-7 text-[10px]" onClick={()=>replay(current)}><Link to="/replay"><Terminal className="size-3"/>Send to Replay<ArrowUpRight className="size-3"/></Link></Button></div></div>{current.bodyLoaded===false?<div className="flex flex-1 items-center justify-center gap-2 text-xs text-muted-foreground" role={detailError?'alert':'status'}>{detailError||'Loading request details…'}{detailError&&<Button variant="ghost" size="sm" onClick={()=>setDetailRetry(n=>n+1)}>Retry details</Button>}</div>:<ResizablePanelGroup orientation="horizontal"><ResizablePanel defaultSize="50%" minSize="25%"><CodePane title="Request" body={requestText(current)} raw={requestText(current)} headers={current.headers}/></ResizablePanel><ResizableHandle/><ResizablePanel defaultSize="50%" minSize="25%"><CodePane title="Response" body={current.responseBody} raw={responseText(current)} headers={current.responseHeaders} extra={<span className="ml-1 font-mono text-[10px] text-muted-foreground">{current.responseHeaders['content-type']?.includes('json')?'JSON':'TEXT'}</span>}/></ResizablePanel></ResizablePanelGroup>}</div></RequestMenu>:<div className="flex h-full items-center justify-center text-muted-foreground">No request selected</div>}</ResizablePanel></ResizablePanelGroup></div>
 <ImportDialog open={showImport} onOpenChange={setShowImport}/><Dialog open={clear} onOpenChange={setClear}><DialogContent className="bg-card"><DialogHeader><DialogTitle>Clear HTTP history?</DialogTitle><DialogDescription>{view===ALL_WORKSPACES?`This removes all captured requests from ALL workspaces, including the temporary session (${traffic.length} shown).`:view===TEMP_WORKSPACE?`This removes the ${traffic.length} requests held in the temporary session.`:`This removes all ${traffic.length} requests from the workspace \u201c${workspaces.find(w=>w.id===view)?.name??''}\u201d.`} Export your log first to keep a copy.</DialogDescription></DialogHeader><div className="flex justify-end gap-2"><Button variant="outline" onClick={()=>setClear(false)}>Cancel</Button><Button variant="destructive" onClick={async()=>{try{await apiClearTraffic(view===ALL_WORKSPACES?undefined:view);setTraffic([]);setClear(false);retryHistory(true);toast.success('History cleared');}catch(error){toast.error(error instanceof Error?error.message:'Could not clear history');}}}>Clear history</Button></div></DialogContent></Dialog></>;
}

/** Editable raw HTTP request. Valid edits update the request immediately; invalid text is kept and flagged. */
function RawEditor({request,onChange,onError}:{request:HttpRequest;onChange:(patch:Partial<HttpRequest>)=>void;onError:(message:string|null)=>void}){
 const [text,setText]=useState(()=>{try{return requestText(request);}catch{return `${request.method} ${request.url} HTTP/1.1\n\n${request.body}`;}});
 const [error,setError]=useState<string|null>(null);
 // Leaving the tab drops the draft, so it must no longer block Send.
 useEffect(()=>()=>onError(null),[onError]);
 const edit=(value:string)=>{
  setText(value);
  try{onChange(parseRawRequest(value,request.url));setError(null);onError(null);}
  catch(e){const message=e instanceof Error?e.message:'Invalid request';setError(message);onError(message);}
 };
 return <div className="flex min-h-0 flex-1 flex-col"><textarea aria-label="Raw request" aria-invalid={!!error} className="min-h-0 flex-1 resize-none bg-background px-5 py-3 font-mono text-xs leading-6 outline-none" value={text} onChange={e=>edit(e.target.value)} spellCheck={false} autoCapitalize="off" autoCorrect="off" wrap="off"/>{error?<p role="alert" className="shrink-0 border-t border-destructive/40 bg-destructive/10 px-5 py-2 text-xs text-destructive">{error} Send is disabled until this is fixed.</p>:<p className="shrink-0 border-t border-border px-5 py-2 text-[10px] text-muted-foreground">Edit anything: method, path, Host, headers, body. Changes apply to the request you send. HTTPS only; Host and Content-Length are set automatically.</p>}</div>;
}
const EMPTY_RUNS:ReplayRun[]=[];
function HttpReplayView(){
 const authProfiles=useAuthProfiles();
 const {commitScriptVariables,getReplayWorkspace,variables,setVariables,sessions,setSessions,active,setActive,setTraffic,timeout,proxyStatus,saveReplay,session:sessionInfo,workspaces}=useInspector();const send=sendHttpRequest;const [editorTab,setEditorTab]=useState('Body'),[renaming,setRenaming]=useState<number|null>(null),[draft,setDraft]=useState(''),skipCommit=useRef(false),[rawError,setRawError]=useState<string|null>(null),[curlOpen,setCurlOpen]=useState(false),[curl,setCurl]=useState(''),[bodyMode,setBodyMode]=useState('JSON');
 const workspaceId=sessionInfo?.target==='workspace'?sessionInfo.workspace_id:null;
 const session=sessions.find(s=>s.id===active)??sessions[0];if(!session)return null;
 const update=(patch:Partial<HttpRequest>)=>setSessions(prev=>prev.map(s=>s.id===session.id?{...s,request:{...s.request,...patch}}:s));
 const importRequests=(items:PostmanRequest[],nextVariables:ReplayVariables)=>{
 const tabs=items.map(item=>({id:nextReplayTabId(sessions),name:item.name,customName:true,request:item.request!}));
 if(sessions.length+tabs.length>100)throw new Error('Replay supports up to 100 tabs. Close some tabs before importing.');
 const doc=serializeTabs([...sessions,...tabs],tabs[0]?.id??active,nextVariables);
 if(new TextEncoder().encode(JSON.stringify(doc)).length>5_000_000)throw new Error('Import would exceed the 5 MB workspace Replay document limit. Select fewer requests.');
 setSessions(prev=>[...prev,...tabs]);setVariables(nextVariables);if(tabs[0])setActive(tabs[0].id);setEditorTab('Body');setRawError(null);
 toast.success(`Imported ${tabs.length} requests`);
 };
 const add=()=>{const id=nextReplayTabId(sessions);setSessions(prev=>[...prev,{id,name:'Untitled request',request:{...blankRequest}}]);setActive(id);};
 const startRename=(s:Session)=>{skipCommit.current=false;setDraft(s.name);setRenaming(s.id);};
 const commitRename=(id:number)=>{if(skipCommit.current){skipCommit.current=false;return;}const name=draft.trim().slice(0,60);if(name)setSessions(prev=>prev.map(s=>s.id===id?{...s,name,customName:true}:s));setRenaming(null);};
 const close=(id:number)=>{if(sessions.length===1)return;setSessions(prev=>prev.filter(s=>s.id!==id));if(active===id)setActive(sessions.find(s=>s.id!==id)?.id??1);};
 const execute=async()=>{
  if(rawError){toast.error(`Fix the raw request first: ${rawError}`);return;}
  if(session.loading)return;
  let request:HttpRequest;
  let identity:ReturnType<NonNullable<typeof authProfiles>['createSession']>|undefined;
  try{identity=authProfiles?.createSession(undefined,variables);request=identity?identity.resolve(session.request,identity.variables):resolveReplayRequest(session.request,variables);}catch(error){toast.error(error instanceof Error?error.message:'Could not resolve variables');return;}
  const afterResponse=session.afterResponse??'',scriptVariables={...(identity?.variables??variables)};
  const id=session.id,workspace=workspaceId,template={...session.request,headers:{...session.request.headers}},started=Date.now();
  setSessions(prev=>prev.map(s=>s.id===id?{...s,loading:true,error:undefined,scriptResult:undefined}:s));
  let response:Traffic|undefined,errorMessage:string|undefined,scriptResult:ScriptResult|undefined;
  try{
   const result=await send({data:{...request,method:request.method as 'GET',timeout}});
   const saving=proxyStatus==='connected'&&getReplayWorkspace()===workspace;
   if(!result.ok){if(saving)void saveReplay(request,{error:result.error});throw new Error(result.error);}
   identity?.receive(request.url,result.setCookies??[]);
   const saved=saving?await saveReplay(request,{status:result.status,headers:result.responseHeaders,body:result.responseBody,duration:result.duration}):null;
   response={...request,...result,id:Date.now(),timestamp:new Date().toISOString()};
   const row=response;
   if(getReplayWorkspace()===workspace){
    setSessions(prev=>prev.map(s=>s.id===id?{...s,response:row,error:undefined,loading:!!afterResponse.trim(),name:s.customName?s.name:new URL(request.url).pathname}:s));
    if(!saved)setTraffic(prev=>[{...row,id:Math.max(0,...prev.map(r=>r.id))+1},...prev]);
   }
   if(saving&&!saved)toast.warning('Response received, but it could not be saved to the workspace.');
   toast.success(`${result.status} ${result.statusText}`);
  }catch(error){errorMessage=error instanceof Error?error.message:'Request failed';if(getReplayWorkspace()===workspace)setSessions(prev=>prev.map(s=>s.id===id?{...s,error:errorMessage,loading:false}:s));toast.error(errorMessage);}
  if(response&&afterResponse.trim()){
   scriptResult=await runReplayScript({source:afterResponse,response:{status:response.status,body:response.responseBody,headers:response.responseHeaders},variables:scriptVariables});
   if(!scriptResult.error)try{if(identity?.profile)await identity.commit(scriptResult.updates);else await commitScriptVariables(workspace,scriptResult.updates);}catch(error){scriptResult={...scriptResult,updates:{},error:`Variables could not be saved: ${error instanceof Error?error.message:'API unavailable'}`};}
   if(scriptResult.error)toast.error(`After response: ${scriptResult.error}`);
   const output=scriptResult;
   if(getReplayWorkspace()===workspace)setSessions(prev=>prev.map(s=>s.id===id?{...s,loading:false,scriptResult:output}:s));
  }
  const run:ReplayRun={id:globalThis.crypto?.randomUUID?.()??`${Date.now()}-${Math.random()}`,timestamp:new Date().toISOString(),template,request,...(identity?.profile&&{profileId:identity.profile.id,profileName:identity.profile.name}),...(afterResponse&&{afterResponse}),...(scriptResult&&{scriptResult}),...(response&&{response}),...(errorMessage&&{error:errorMessage}),duration:response?.duration??Date.now()-started};
  if(getReplayWorkspace()===workspace)setSessions(prev=>prev.map(s=>s.id===id?{...s,runs:[run,...(s.runs??[])].slice(0,20)}:s));
  if(workspace)try{const stored=await saveReplayRun(workspace,id,run);if(getReplayWorkspace()===workspace)setSessions(prev=>prev.map(s=>s.id===id?{...s,runs:(s.runs??[]).map(item=>item.id===run.id?stored:item)}:s));}catch(error){toast.warning(`Send history could not be saved: ${error instanceof Error?error.message:'API unavailable'}`);}
 };

 const resolveForProfile=(request:HttpRequest)=>{const identity=authProfiles?.createSession(undefined,variables);return identity?identity.resolve(request,identity.variables):resolveReplayRequest(request,variables);};
 const query=replayQuery(session.request.url);
 const changeQuery=(index:number,key:string,value:string)=>{const next=[...query];next[index]=[key,value];update({url:setReplayQuery(session.request.url,next)});};

 const response=session.response;
 const savedTo=proxyStatus==='connected'&&sessionInfo?.target==='workspace'?workspaces.find(w=>w.id===sessionInfo.workspace_id)?.name??null:null;
 return <><div className="flex min-h-20 shrink-0 flex-wrap items-center justify-between gap-3 px-6 py-3"><div><h1 className="text-xl font-semibold">Replay</h1><p className="mt-1.5 text-xs text-muted-foreground">Compose, send, inspect. Repeat.<span className="ml-3 text-[10px]" title={savedTo?'Tabs are stored with this workspace and restored when you come back':'Without a workspace, tabs are lost when you reload or close the tool'}>{savedTo?`Tabs saved to \u201c${savedTo}\u201d`:'Tabs are not saved (no workspace)'}</span></p></div><div className="flex flex-wrap items-center gap-2"><ProfileSelector/><ReplayVariablesEditor key={workspaceId??'temporary'} variables={variables} onApply={setVariables}/><ReplayRuns key={`${workspaceId}-${session.id}`} workspace={workspaceId} tab={session.id} runs={session.runs??EMPTY_RUNS} onRestore={request=>{update(request);setRawError(null);setEditorTab('Body');}}/><PostmanImportDialog key={`postman-${workspaceId??'temporary'}`} variables={variables} slots={Math.max(0,100-sessions.length)} onImport={importRequests}/><PostmanImportDialog key={`bruno-${workspaceId??'temporary'}`} format="bruno" variables={variables} slots={Math.max(0,100-sessions.length)} onImport={importRequests}/><Button variant="outline" size="sm" onClick={()=>setCurlOpen(true)}><Terminal/>Import cURL</Button></div></div><div className="flex h-10 shrink-0 items-end gap-1 overflow-x-auto border-b border-border px-6">{sessions.map(s=><RequestMenu key={s.id} request={()=>isWebSocketRequest(s.request)?resolveReplayRequest(s.request,variables,"websocket"):resolveForProfile(s.request)}><div className={cn('flex h-9 min-w-36 max-w-56 shrink-0 items-center gap-2 rounded-t border border-b-0 px-3',s.id===session.id?'border-border bg-card':'border-transparent text-muted-foreground')}>{renaming===s.id?<input autoFocus aria-label="Tab name" className="inspector-input h-7 min-w-0 flex-1 px-2 text-xs" value={draft} maxLength={60} onChange={e=>setDraft(e.target.value)} onFocus={e=>e.currentTarget.select()} onBlur={()=>commitRename(s.id)} onKeyDown={e=>{if(e.key==='Enter')commitRename(s.id);else if(e.key==='Escape'){skipCommit.current=true;setRenaming(null);}}}/>:<Button variant="ghost" className="h-7 min-w-0 flex-1 justify-start truncate p-0 text-xs" title="Double-click or press F2 to rename" onClick={()=>setActive(s.id)} onDoubleClick={()=>startRename(s)} onKeyDown={e=>{if(e.key==='F2')startRename(s);}}><Terminal className="size-3 text-primary"/>{isWebSocketRequest(s.request)&&<span aria-hidden="true" className="text-[9px] text-primary">WS</span>}{s.name}</Button>}<Button variant="ghost" size="icon" className="size-5" disabled={sessions.length===1} onClick={()=>close(s.id)} aria-label={`Close session ${s.id}`}><X className="size-3"/></Button></div></RequestMenu>)}<Button variant="ghost" size="icon" className="mb-1 size-7" aria-label="New session" title="New session" onClick={add}><Plus/></Button><Button variant="ghost" size="sm" aria-label="New WebSocket request" onClick={()=>{const id=nextReplayTabId(sessions);setSessions(p=>[...p,{id,name:'WebSocket request',request:{method:'GET',url:'',headers:{Upgrade:'websocket'},body:''}}]);setActive(id);}}>+ WS</Button></div><div className="flex shrink-0 gap-2 border-b border-border bg-card p-4"><select className="inspector-input w-24 font-mono text-xs text-primary" aria-label="Request method" value={session.request.method} onChange={e=>update({method:e.target.value})}>{methods.map(m=><option key={m}>{m}</option>)}</select><div className="relative min-w-0 flex-1"><Globe className="absolute left-3 top-2.5 size-4 text-muted-foreground"/><input aria-label="Request URL" className="inspector-input h-9 w-full pl-9 font-mono text-xs" value={session.request.url} onChange={e=>update({url:e.target.value})} onKeyDown={e=>{if(e.key==='Enter'&&!session.loading)execute();}}/></div><Button className="h-9 min-w-24" disabled={session.loading} onClick={execute}><Zap className={cn(session.loading&&'animate-pulse')}/>{session.loading?'Sending':'Send'}</Button></div><RequestMenu request={()=>resolveForProfile(session.request)} disabled={!!rawError}><div className="min-h-0 flex-1"><ResizablePanelGroup orientation="horizontal"><ResizablePanel defaultSize="50%" minSize="30%"><div className="flex h-full flex-col"><div className="flex h-12 shrink-0 items-center justify-between border-b border-border px-4"><span className="font-medium">Request</span><span className="font-mono text-[10px] text-muted-foreground">HTTPS</span></div><div className="flex h-10 shrink-0 gap-4 border-b border-border px-4">{['Body','Headers','Query Params','Raw','Scripts'].map(t=><Button key={t} variant="ghost" className={cn('h-10 rounded-none border-b-2 px-0 text-xs',t===editorTab?'border-primary text-primary':'border-transparent text-muted-foreground')} onClick={()=>setEditorTab(t)}>{t}{t==='Headers'&&<span className="text-[10px]">{Object.keys(session.request.headers).length}</span>}</Button>)}</div>{editorTab==='Body'?<><div className="flex h-10 shrink-0 items-center justify-between px-4"><div className="flex gap-1">{['JSON','Raw'].map(t=><Button variant="ghost" size="sm" className={cn('h-6',bodyMode===t?'bg-secondary':'text-muted-foreground')} key={t} onClick={()=>setBodyMode(t)}>{t}</Button>)}</div><Button variant="ghost" size="sm" className="h-6 text-[10px] text-muted-foreground" onClick={()=>{try{update({body:JSON.stringify(JSON.parse(session.request.body),null,2)});}catch{toast.error('Body is not valid JSON');}}}><Code2 className="size-3"/>Format</Button></div><textarea className="min-h-0 flex-1 resize-none bg-background px-5 py-2 font-mono text-xs leading-7 outline-none" aria-label="Request body" value={session.request.body} onChange={e=>update({body:e.target.value})} spellCheck={false} placeholder={session.request.method==='GET'?'No request body':'{\n  "key": "value"\n}'}/>{['GET','HEAD'].includes(session.request.method)&&session.request.body&&<p className="px-4 pb-4 text-xs text-warning">Body will not be sent for {session.request.method}.</p>}</>:editorTab==='Scripts'?<div className="flex min-h-0 flex-1 flex-col"><div className="flex shrink-0 flex-wrap items-center justify-between gap-2 px-4 py-3 text-xs"><p className="text-muted-foreground">After response · synchronous JavaScript · {authProfiles?.document.active?'updates selected profile variables':'updates shared workspace variables'}</p><a href="/docs/replay-scripts.html" target="_blank" rel="noopener noreferrer" className="inline-flex shrink-0 items-center gap-1 text-primary underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring" aria-label="Script documentation (opens in a new tab)">Documentation<ArrowUpRight className="size-3"/></a></div><textarea aria-label="After response script" className="min-h-0 flex-1 resize-none bg-background px-4 font-mono text-xs leading-6 outline-none" maxLength={32000} spellCheck={false} value={session.afterResponse??''} onChange={e=>{const code=e.target.value;setSessions(prev=>prev.map(s=>s.id===session.id?{...s,afterResponse:code}:s));}} placeholder={'const body = response.json();\nif (response.status === 200 && body.data?.access_token) {\n  variables.set("token1", body.data.access_token);\n}'}/><p className="px-4 py-2 text-xs text-muted-foreground">Use response.status, response.headers, response.json(), response.text(), variables.get/set(), console.log(). No network or async APIs.</p></div>:editorTab==='Raw'?<RawEditor key={session.id} request={session.request} onChange={update} onError={setRawError}/>:<div className="overflow-auto p-4"><div className="mb-3 grid grid-cols-[1fr_1fr_24px] gap-2 text-[10px] uppercase text-muted-foreground"><span>Name</span><span>Value</span></div>{(editorTab==='Headers'?Object.entries(session.request.headers):query).map(([key,value],i)=><div key={i} className="mb-2 grid grid-cols-[1fr_1fr_24px] gap-2"><input className="inspector-input text-xs" aria-label={`${editorTab} name ${i+1}`} value={key} onChange={e=>{if(editorTab==='Headers'){const entries=Object.entries(session.request.headers);entries[i]=[e.target.value,value];update({headers:Object.fromEntries(entries)});}else changeQuery(i,e.target.value,value);}}/><input className="inspector-input text-xs" aria-label={`${editorTab} value ${i+1}`} value={value} onChange={e=>editorTab==='Headers'?update({headers:{...session.request.headers,[key]:e.target.value}}):changeQuery(i,key,e.target.value)}/><Button variant="ghost" size="icon" className="size-7 text-muted-foreground" aria-label={`Remove ${editorTab} ${i+1}`} onClick={()=>{if(editorTab==='Headers'){update({headers:Object.fromEntries(Object.entries(session.request.headers).filter((_,n)=>n!==i))});}else{update({url:setReplayQuery(session.request.url,query.filter((_,n)=>n!==i))});}}}><X className="size-3"/></Button></div>)}<Button variant="outline" size="sm" onClick={()=>{if(editorTab==='Headers')update({headers:{...session.request.headers,[`X-Header-${Object.keys(session.request.headers).length+1}`]:''}});else changeQuery(query.length,`param${query.length+1}`,'');}}><Plus/>Add {editorTab==='Headers'?'header':'parameter'}</Button></div>}</div></ResizablePanel><ResizableHandle/><ResizablePanel defaultSize="50%" minSize="25%"><div className="flex h-full flex-col">{response&&<div className="flex h-12 shrink-0 items-center gap-3 border-b border-border px-4"><Status status={response.status}/><span className="text-xs">{response.statusText}</span>{session.runs?.find(r=>r.response&&r.response.timestamp!==response.timestamp)?.response&&<ResponseDiffButton left={session.runs.find(r=>r.response&&r.response.timestamp!==response.timestamp)!.response!} right={response} label="Compare previous"/>}<span className="ml-auto font-mono text-[10px] text-muted-foreground">{response.duration} ms · {sizeLabel(response.size)}</span></div>}{session.scriptResult&&<details className="max-h-48 shrink-0 overflow-auto border-b border-border px-4 py-2 text-xs" open={!!session.scriptResult.error}><summary className="cursor-pointer">After response · {session.scriptResult.error?'Failed':`Updated ${Object.keys(session.scriptResult.updates).join(', ')||'no variables'}`}</summary>{session.scriptResult.error&&<p role="alert" className="py-2 text-destructive">{session.scriptResult.error}</p>}<pre className="whitespace-pre-wrap py-2">{session.scriptResult.logs.join('\n')}</pre></details>}{session.error?<div role="alert" className="m-5 rounded border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">{session.error}</div>:response?<div className="min-h-0 flex-1"><CodePane title="Response" body={response.responseBody} raw={responseText(response)} headers={response.responseHeaders}/></div>:<div className="flex h-full flex-col items-center justify-center gap-4"><div className="relative flex size-20 items-center justify-center rounded-lg border border-border bg-card"><Layers className="size-9 text-muted-foreground" strokeWidth={1}/><span className="absolute -bottom-2 -right-2 flex size-7 items-center justify-center rounded bg-primary/10 text-primary"><Zap className="size-4"/></span></div><span className="mt-2 text-sm text-muted-foreground">{session.loading?'Waiting for response…':'No response yet'}</span><span className="font-mono text-[10px] text-muted-foreground">{session.loading?'Request in progress':'—'}</span></div>}</div></ResizablePanel></ResizablePanelGroup></div></RequestMenu><Dialog open={curlOpen} onOpenChange={setCurlOpen}><DialogContent className="bg-card"><DialogHeader><DialogTitle>Import cURL</DialogTitle><DialogDescription>Paste an HTTP cURL command.</DialogDescription></DialogHeader><textarea aria-label="cURL command" className="inspector-input min-h-40 font-mono text-xs" value={curl} onChange={e=>setCurl(e.target.value)} placeholder="curl https://httpbin.org/get"/><Button disabled={!curl.trim()} onClick={()=>{try{update(parseCurl(curl));setCurlOpen(false);setCurl('');toast.success('Request imported');}catch(e){toast.error(e instanceof Error?e.message:'Invalid cURL');}}}>Import request<ArrowUpRight/></Button></DialogContent></Dialog></>;
}
export function ScopeView(){
 const {scope,updateScope,scopeEnabled,proxyStatus}=useInspector();
 const [domain,setDomain]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 const domains=scope.split('\n').filter(Boolean);
 const addDomain=async(event:React.FormEvent)=>{
  event.preventDefault();
  setBusy(true);
  try{
   const raw=domain.trim();
   const hostname=new URL(raw.includes('://')?raw:`https://${raw}`).hostname.toLowerCase().replace(/\.$/,'');
   if(!raw||!hostname||/[\s/:*?#@]/.test(raw)||raw.includes('://'))throw new Error('Enter a hostname only, for example api.example.com.');
   if(domains.includes(hostname))throw new Error('This domain is already in scope.');
   await updateScope([...domains,hostname],true);setDomain('');setError('');
  }catch(e){setError(e instanceof Error?e.message:'Invalid domain');}finally{setBusy(false);}
 };
 const saveScope=async(next:string[],enabled:boolean)=>{setBusy(true);setError('');try{await updateScope(next,enabled);}catch(e){setError(e instanceof Error?e.message:'Could not update scope');}finally{setBusy(false);}};
 return <div className="max-w-3xl p-6"><h1 className="text-xl font-semibold">Scope & Filters</h1><div className="mt-8 border-b border-border pb-6"><h2 className="text-sm font-medium">Target scope</h2><form onSubmit={addDomain} className="mt-4 flex flex-wrap items-center gap-3"><Globe className="size-4 text-muted-foreground"/><input aria-label="Scope hostname" className="inspector-input min-w-0 flex-1 text-sm" value={domain} onChange={e=>{setDomain(e.target.value);setError('');}} placeholder="api.example.com"/><Button type="submit" size="sm" disabled={busy||proxyStatus!=='connected'||!domain.trim()}><Plus className="size-4"/>Add domain</Button><label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={scopeEnabled} disabled={busy||proxyStatus!=='connected'||!domains.length} onChange={e=>void saveScope(domains,e.target.checked)} className="accent-primary"/>In-scope only</label></form>{error&&<p role="alert" className="mt-3 text-xs text-destructive">{error}</p>}<ul className="mt-4 space-y-2">{domains.map(host=><li key={host} className="flex items-center justify-between rounded border border-border px-3 py-2"><span className="min-w-0 truncate font-mono text-xs" title={host}>{host}</span><Button variant="ghost" size="icon" className="size-7 shrink-0" aria-label={`Remove ${host}`} disabled={busy||proxyStatus!=='connected'} onClick={()=>{const remaining=domains.filter(d=>d!==host);void saveScope(remaining,remaining.length>0&&scopeEnabled);}}><X className="size-4"/></Button></li>)}</ul><p className="mt-3 text-xs text-muted-foreground">Scope applies to HTTP History and Intercept. Only matching domains are held; other traffic passes through. Matches exact hostnames. Turn off In-scope only to include all domains.</p></div><div className="mt-6 flex items-center gap-3 text-sm text-muted-foreground"><ShieldCheck className="size-5 text-primary"/>Public HTTPS targets<span className="ml-auto rounded bg-primary/10 px-2 py-1 text-xs text-primary">Enforced</span></div></div>;
}
export function SettingsView(){const {timeout,setTimeout}=useInspector();return <div className="max-w-3xl p-6"><h1 className="text-xl font-semibold">Settings</h1><ProxyListenerSettingsPanel/><div className="mt-8 flex items-center justify-between border-b border-border pb-6"><div><h2 className="text-sm font-medium">Request timeout</h2><p className="mt-1 text-xs text-muted-foreground">Maximum wait for an HTTP response</p></div><select aria-label="Request timeout" className="inspector-input text-xs" value={timeout} onChange={e=>setTimeout(Number(e.target.value))}>{[5000,10000,15000,30000].map(n=><option key={n} value={n}>{n/1000} seconds</option>)}</select></div><div className="mt-6 space-y-3 text-xs text-muted-foreground"><div className="flex justify-between"><span>Appearance</span><span className="text-foreground">Dark</span></div><div className="flex justify-between"><span>Response size limit</span><span className="font-mono text-foreground">2 MB</span></div><div className="flex justify-between"><span>History storage</span><span className="text-foreground">Current session</span></div><div className="flex justify-between"><span>Redirects</span><span className="text-foreground">Manual</span></div></div></div>;}
export function ReplayView() {
 const {sessions,active,session}=useInspector();
 const tab=sessions.find(s=>s.id===active)??sessions[0];
 return tab&&isWebSocketRequest(tab.request)?<WebSocketReplay key={`${session?.workspace_id??session?.target}:${tab.id}`}/>:<HttpReplayView/>;
}

export function HistoryView() { return <ProtocolTabs><HttpHistoryView/></ProtocolTabs>; }
