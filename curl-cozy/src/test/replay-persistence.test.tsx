import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo, Workspace } from "@/lib/api";

const api = vi.hoisted(() => ({
  fetchTraffic: vi.fn(),
  fetchTrafficDetail: vi.fn(),
  clearTraffic: vi.fn(),
  deleteTraffic: vi.fn(),
  fetchWorkspaces: vi.fn(),
  createWorkspace: vi.fn(),
  renameWorkspace: vi.fn(),
  deleteWorkspace: vi.fn(),
  activateWorkspace: vi.fn(),
  fetchIntercept: vi.fn(),
  updateScope: vi.fn(),
  updateInterceptSettings: vi.fn(),
  forwardHeld: vi.fn(),
  dropHeld: vi.fn(),
  forwardAllHeld: vi.fn(),
  fetchSession: vi.fn(),
  useTemporarySession: vi.fn(),
  saveReplay: vi.fn(),
  fetchReplayTabs: vi.fn(),
  saveReplayTabs: vi.fn(),
}));
const featureApi=vi.hoisted(()=>({saveReplayRun:vi.fn(),fetchReplayRuns:vi.fn(),fetchReplayRun:vi.fn(),updateTrafficAnnotation:vi.fn()}));
vi.mock("@/lib/replay-features-api",()=>featureApi);
const scriptRunner=vi.hoisted(()=>vi.fn());
vi.mock('@/lib/replay-script',()=>({runReplayScript:scriptRunner}));
vi.mock('@/lib/bruno-import-client',async()=>{
 const parser=await import('@/lib/bruno-import');
 return {readBrunoFiles:vi.fn(async(kind:string,files:{name:string;source:string}[])=>kind==='environment'?parser.parseBrunoEnvironment(files[0]!):parser.parseBrunoFiles(files))};
});
const send = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => api);
vi.mock("@/lib/ws", () => ({ useTrafficStream: () => ({ status: "connected" }) }));
vi.mock("@/lib/replay.functions", () => ({ sendHttpRequest: send }));
vi.mock("@/components/ui/resizable", () => {
  const Box = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>;
  return { HistoryPanelGroup: Box, ResizablePanelGroup: Box, ResizablePanel: Box, ResizableHandle: () => null };
});
vi.mock("@tanstack/react-start", () => ({ useServerFn: (fn: unknown) => fn }));
vi.mock("@tanstack/react-router", () => ({ Link: ({ children }: { children: React.ReactNode }) => <a>{children}</a> }));

import { InspectorProvider, ReplayView, ScopeView, useInspector } from "@/components/inspector";

const SAVE_DELAY = 700; // the provider's debounce
const wait = (ms: number) => act(() => new Promise<void>((r) => setTimeout(r, ms)));

const workspace = (id: string, name: string): Workspace => ({ id, name, active: false, request_count: 0, created_at: "2026-10-15T00:00:00Z" });
const stored = (id: number, name: string, url: string) => ({
  tabs: [{ id, name, request: { method: "GET", url, headers: { Accept: "application/json" }, body: "" } }],
  active: id,
});

let session: SessionInfo;
let docs: Record<string, unknown>;

const memoryStorage = () => {
  const data = new Map<string, string>();
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
    clear: () => data.clear(),
  };
};

function SwitchTo({ id }: { id: string }) {
  const { chooseWorkspace } = useInspector();
  return <button onClick={() => void chooseWorkspace(id)}>switch to {id}</button>;
}

const renderReplay = () =>
  render(
    <InspectorProvider>
      <SwitchTo id="w2" />
      <ReplayView />
    </InspectorProvider>,
  );

const urlField = () => screen.getByLabelText("Request URL") as HTMLInputElement;
const editUrl = (value: string) => fireEvent.change(urlField(), { target: { value } });
const savedCalls = () => api.saveReplayTabs.mock.calls as [string, { tabs: { request: { url: string } }[]; active: number }][];

beforeEach(() => {
  vi.clearAllMocks();
  featureApi.saveReplayRun.mockImplementation(async (_workspace,_tab,run)=>run);
  featureApi.fetchReplayRuns.mockResolvedValue({data:[],has_more:false});
  featureApi.updateTrafficAnnotation.mockImplementation(async (_id,patch)=>patch);
  vi.stubGlobal("localStorage", memoryStorage());
  session = { target: "workspace", workspace_id: "w1", temporary_count: 0 };
  docs = { w1: stored(5, "Saved tab", "https://saved.example/one"), w2: stored(9, "Other tab", "https://other.example/two") };
  api.fetchTraffic.mockResolvedValue({ data: [], total: 0, limit: 500, offset: 0 });
  api.fetchIntercept.mockResolvedValue({ settings: { requests: false, responses: false }, held: [] });
  api.fetchWorkspaces.mockResolvedValue([workspace("w1", "Project 1"), workspace("w2", "Project 2")]);
  api.fetchSession.mockImplementation(async () => ({ ...session }));
  api.activateWorkspace.mockImplementation(async (id: string) => {
    session = { target: "workspace", workspace_id: id, temporary_count: 0 };
  });
  api.fetchReplayTabs.mockImplementation(async (id: string) => docs[id] ?? { tabs: [], active: null });
  api.saveReplayTabs.mockResolvedValue(undefined);
  api.updateScope.mockImplementation(async (scope: unknown)=>scope);
});
afterEach(cleanup);

describe("Replay tabs are saved per workspace", () => {
  it("applies MCP Replay edits without autosaving stale tabs", async () => {
    renderReplay();
    await screen.findByRole("button", { name: "Saved tab" });
    editUrl("https://local.example/pending");
    const document = stored(5, "MCP renamed", "https://remote.example/edited");
    act(() => { window.dispatchEvent(new CustomEvent("httpdebugger:replay", { detail: { type: "replay_changed", workspace_id: "w1", document } })); });
    expect(await screen.findByRole("button", { name: "MCP renamed" })).toBeInTheDocument();
    expect(urlField().value).toBe("https://remote.example/edited");
    await wait(SAVE_DELAY + 100);
    expect(api.saveReplayTabs).not.toHaveBeenCalled();
    act(() => { window.dispatchEvent(new CustomEvent("httpdebugger:replay", { detail: { type: "replay_changed", workspace_id: "w2", document: stored(9, "Other workspace", "https://other.example/") } })); });
    expect(urlField().value).toBe("https://remote.example/edited");
  });

  it("restores the saved tabs of the workspace that is being used", async () => {
    renderReplay();
    expect(await screen.findByRole("button", { name: "Saved tab" })).toBeInTheDocument();
    expect(urlField().value).toBe("https://saved.example/one");
    expect(api.fetchReplayTabs).toHaveBeenCalledWith("w1");
  });

  it("does not rewrite what it just loaded", async () => {
    renderReplay();
    await screen.findByRole("button", { name: "Saved tab" });
    await wait(SAVE_DELAY + 300);
    expect(api.saveReplayTabs).not.toHaveBeenCalled();
  });

  it("autosaves edits once, after the user pauses", async () => {
    renderReplay();
    await screen.findByRole("button", { name: "Saved tab" });
    editUrl("https://saved.example/a");
    editUrl("https://saved.example/ab");
    editUrl("https://saved.example/abc");
    expect(api.saveReplayTabs).not.toHaveBeenCalled();

    await waitFor(() => expect(api.saveReplayTabs).toHaveBeenCalledTimes(1), { timeout: 3000 });
    const [id, doc] = savedCalls()[0]!;
    expect(id).toBe("w1");
    expect(doc.active).toBe(5);
    expect(doc.tabs[0]!.request.url).toBe("https://saved.example/abc");
  });

  it("a workspace with nothing saved adopts the tabs on screen and saves them", async () => {
    docs["w1"] = { tabs: [], active: null };
    renderReplay();
    await waitFor(() => expect(api.fetchReplayTabs).toHaveBeenCalledWith("w1"));
    await waitFor(() => expect(api.saveReplayTabs).toHaveBeenCalledTimes(1), { timeout: 3000 });
    expect(savedCalls()[0]![1].tabs).toHaveLength(1);
  });

  const stubSendAndSave = () => {
    send.mockResolvedValue({ ok: true, status: 200, statusText: "OK", duration: 3, size: 2, responseHeaders: {}, responseBody: "{}" });
    api.saveReplay.mockResolvedValue({
      id: "e1", timestamp: "2026-10-15T00:00:00Z", method: "GET", url: "https://saved.example/one", host: "saved.example", path: "/one",
      scheme: "https", request_headers: "{}", request_body: [], request_content_type: null, status_code: 200, response_headers: "{}",
      response_body: [], response_content_type: null, duration_ms: 3, request_size: 0, response_size: 2, error: null, workspace_id: "w1", source: "replay",
    });
  };

  it("does not save again when only a response arrives (tab with its own name)", async () => {
    stubSendAndSave();
    docs["w1"] = { tabs: [{ ...(docs["w1"] as { tabs: object[] }).tabs[0], customName: true }], active: 5 };
    renderReplay();
    await screen.findByRole("button", { name: "Saved tab" });
    fireEvent.click(screen.getByRole("button", { name: /^send$/i }));
    await waitFor(() => expect(send).toHaveBeenCalledTimes(1));
    await screen.findByText("200");
    await wait(SAVE_DELAY + 300);
    expect(api.saveReplayTabs).not.toHaveBeenCalled();
  });

  it("never stores responses or in-flight state, only the request and the derived tab name", async () => {
    stubSendAndSave();
    renderReplay();
    await screen.findByRole("button", { name: "Saved tab" });
    fireEvent.click(screen.getByRole("button", { name: /^send$/i }));
    await screen.findByText("200");
    // Without its own name the tab is renamed after the URL path, which is worth saving, once.
    await waitFor(() => expect(api.saveReplayTabs).toHaveBeenCalledTimes(1), { timeout: 3000 });
    await wait(SAVE_DELAY + 300);
    expect(api.saveReplayTabs).toHaveBeenCalledTimes(1);
    const tab = savedCalls()[0]![1].tabs[0]!;
    expect(Object.keys(tab).sort()).toEqual(["id", "name", "request"]);
    expect(tab).toMatchObject({ name: "/one" });
  });

  it("switching workspace saves the pending edit to the old one, then loads the new one", async () => {
    renderReplay();
    await screen.findByRole("button", { name: "Saved tab" });
    editUrl("https://saved.example/unsaved-edit");
    fireEvent.click(screen.getByRole("button", { name: "switch to w2" }));

    expect(await screen.findByRole("button", { name: "Other tab" })).toBeInTheDocument();
    expect(urlField().value).toBe("https://other.example/two");
    // The edit made just before switching reached the workspace it belongs to...
    expect(savedCalls().some(([id, doc]) => id === "w1" && doc.tabs[0]!.request.url === "https://saved.example/unsaved-edit")).toBe(true);
    // ...and the old tabs were never written under the new workspace.
    await wait(SAVE_DELAY + 300);
    expect(savedCalls().filter(([id]) => id === "w2")).toEqual([]);
    expect(api.fetchReplayTabs).toHaveBeenLastCalledWith("w2");
  });

  it("keeps tabs local when no workspace is chosen (nothing is read or written)", async () => {
    session = { target: "temporary", workspace_id: null, temporary_count: 0 };
    renderReplay();
    await waitFor(() => expect(api.fetchSession).toHaveBeenCalled());
    editUrl("https://typed.example/local");
    await wait(SAVE_DELAY + 300);
    expect(api.fetchReplayTabs).not.toHaveBeenCalled();
    expect(api.saveReplayTabs).not.toHaveBeenCalled();
    expect(urlField().value).toBe("https://typed.example/local");
    expect(screen.getByText(/tabs are not saved \(no workspace\)/i)).toBeInTheDocument();
  });

  it("says where the tabs are saved", async () => {
    renderReplay();
    expect(await screen.findByText(/tabs saved to .Project 1./i)).toBeInTheDocument();
  });

  it("retries on the next change after a failed save", async () => {
    api.saveReplayTabs.mockRejectedValueOnce(new Error("proxy hiccup"));
    renderReplay();
    await screen.findByRole("button", { name: "Saved tab" });
    editUrl("https://saved.example/first");
    await waitFor(() => expect(api.saveReplayTabs).toHaveBeenCalledTimes(1), { timeout: 3000 });
    await wait(50);
    editUrl("https://saved.example/second");
    await waitFor(() => expect(api.saveReplayTabs).toHaveBeenCalledTimes(2), { timeout: 3000 });
    expect(savedCalls()[1]![1].tabs[0]!.request.url).toBe("https://saved.example/second");
  });

  it("flushes pending edits when the page is hidden or closed", async () => {
    renderReplay();
    await screen.findByRole("button", { name: "Saved tab" });
    editUrl("https://saved.example/closing");
    window.dispatchEvent(new Event("pagehide"));
    await waitFor(() => expect(api.saveReplayTabs).toHaveBeenCalledTimes(1));
    expect(api.saveReplayTabs).toHaveBeenCalledWith("w1", expect.anything(), { keepalive: true });
  });
});


describe("Shared History and Intercept scope",()=>{
 it("saves domains to the backend and receives updates from other clients",async()=>{
  render(<InspectorProvider><ScopeView /></InspectorProvider>);
  await waitFor(()=>expect(api.fetchIntercept).toHaveBeenCalled());
  fireEvent.change(screen.getByLabelText("Scope hostname"),{target:{value:"API.EXAMPLE.COM"}});
  fireEvent.click(screen.getByRole("button",{name:"Add domain"}));
  await waitFor(()=>expect(api.updateScope).toHaveBeenCalledWith({domains:["api.example.com"],enabled:true}));
  expect(await screen.findByRole("button",{name:"Remove api.example.com"})).toBeInTheDocument();
  expect(screen.getByRole("checkbox")).toBeChecked();
  act(()=>window.dispatchEvent(new CustomEvent("httpdebugger:scope",{detail:{domains:["other.example.com"],enabled:true}})));
  expect(screen.queryByRole("button",{name:"Remove api.example.com"})).not.toBeInTheDocument();
  expect(screen.getByRole("button",{name:"Remove other.example.com"})).toBeInTheDocument();
 });
 it("keeps the old scope if the backend rejects a change",async()=>{
  api.updateScope.mockRejectedValueOnce(new Error("Proxy unavailable"));
  render(<InspectorProvider><ScopeView /></InspectorProvider>);
  fireEvent.change(screen.getByLabelText("Scope hostname"),{target:{value:"api.example.com"}});
  fireEvent.click(screen.getByRole("button",{name:"Add domain"}));
  expect(await screen.findByRole("alert")).toHaveTextContent("Proxy unavailable");
  expect(screen.queryByRole("button",{name:"Remove api.example.com"})).not.toBeInTheDocument();
 });
});

// Exercise pagination through the real root provider and History table.
import { HistoryView } from "@/components/inspector";
const historyEntry = (i: number) => ({
  id: `history-${i}`, timestamp: new Date(Date.UTC(2026, 9, 15, 0, 0, i)).toISOString(),
  method: "GET", url: `https://example.com/item-${i}`, host: "example.com", path: `/item-${i}`, scheme: "https",
  request_headers: "{}", request_body: [], request_content_type: null,
  status_code: 200, response_headers: "{}", response_body: [], response_content_type: null,
  duration_ms: 10, request_size: 0, response_size: 0, error: null, workspace_id: "w1", source: "proxy",
});
const firstHistoryPage = () => ({ data: Array.from({ length: 100 }, (_, i) => historyEntry(200-i)), total: 200, next_cursor: "older-page" });
const renderHistory = () => render(<InspectorProvider><SwitchTo id="w2"/><HistoryView/></InspectorProvider>);

describe("HTTP History pagination and virtualization", () => {
  it("deletes a history request only after the API succeeds", async () => {
    vi.stubGlobal("DOMRect", {fromRect:({x=0,y=0,width=0,height=0}={})=>({x,y,width,height,top:y,left:x,right:x+width,bottom:y+height})});
    let deleted = false;
    api.fetchTraffic.mockImplementation(async()=>({data:deleted?[]:[historyEntry(200)],total:deleted?0:1,next_cursor:null}));
    api.deleteTraffic.mockRejectedValueOnce(new Error("Delete failed"));
    renderHistory();
    const row = (await screen.findByText("/item-200")).closest("tr")!;
    fireEvent.contextMenu(row);
    fireEvent.click(await screen.findByRole("menuitem", {name:"Delete request"}));
    await waitFor(()=>expect(api.deleteTraffic).toHaveBeenCalledWith("history-200"));
    expect(screen.getByText("/item-200")).toBeInTheDocument();
    api.deleteTraffic.mockImplementationOnce(async()=>{deleted=true;});
    fireEvent.contextMenu(row);
    fireEvent.click(await screen.findByRole("menuitem", {name:"Delete request"}));
    await waitFor(()=>expect(screen.queryByText("/item-200")).not.toBeInTheDocument());
  });

  it("renders a bounded set of rows and loads the next page near the bottom", async () => {
    api.fetchTraffic.mockImplementation(async (query) => query.cursor
      ? { data: Array.from({ length: 100 }, (_, i) => historyEntry(100-i)), total: 200, next_cursor: null }
      : firstHistoryPage());
    renderHistory();
    await waitFor(() => expect(screen.getAllByRole("row").length).toBeGreaterThan(2));
    expect(screen.getAllByRole("row").length).toBeLessThan(40);
    expect(api.fetchTraffic.mock.calls.some(([q]) => q.cursor)).toBe(false);
    const scroller = screen.getByLabelText("History requests");
    Object.defineProperty(scroller, "clientHeight", { configurable: true, value: 400 });
    fireEvent.scroll(scroller, { target: { scrollTop: 2800 } });
    await waitFor(() => expect(api.fetchTraffic).toHaveBeenCalledWith(expect.objectContaining({ cursor: "older-page", limit: 100 })));
    await waitFor(() => expect(screen.getByText("/item-100")).toBeTruthy());
    expect(screen.getAllByRole("row").length).toBeLessThan(45);
  });

  it("retries failed pages without discarding existing history", async () => {
    let failed = false;
    api.fetchTraffic.mockImplementation(async (query) => {
      if (!query.cursor) return firstHistoryPage();
      if (!failed) { failed = true; throw new Error("page unavailable"); }
      return { data: [historyEntry(99)], total: 200, next_cursor: null };
    });
    renderHistory();
    await waitFor(() => expect(screen.getAllByRole("row").length).toBeGreaterThan(2));
    const scroller = screen.getByLabelText("History requests");
    Object.defineProperty(scroller, "clientHeight", { configurable: true, value: 400 });
    fireEvent.scroll(scroller, { target: { scrollTop: 2800 } });
    expect(await screen.findByRole("alert")).toHaveTextContent("page unavailable");
    expect(screen.getAllByRole("row").length).toBeGreaterThan(2);
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect(api.fetchTraffic.mock.calls.filter(([q]) => q.cursor)).toHaveLength(2);
  });

  it("searches the backend and resets the cursor when filters change", async () => {
    api.fetchTraffic.mockResolvedValue(firstHistoryPage());
    renderHistory();
    await waitFor(() => expect(screen.getAllByRole("row").length).toBeGreaterThan(2));
    expect(screen.queryByLabelText("Search traffic")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Search and filter requests" }));
    fireEvent.change(screen.getByLabelText("Search traffic"), { target: { value: "unloaded request" } });
    fireEvent.change(screen.getByLabelText("Filter by method"), { target: { value: "POST" } });
    fireEvent.change(screen.getByLabelText("Filter by status"), { target: { value: "4xx Client error" } });
    await waitFor(() => expect(api.fetchTraffic).toHaveBeenCalledWith(expect.objectContaining({ history: true, search: "unloaded request", method: "POST", status_class: 4 })));
    const query = api.fetchTraffic.mock.calls.find(([q]) => q.search === "unloaded request")![0];
    expect(query.cursor).toBeUndefined();
    fireEvent.click(screen.getByRole("button", { name: "Close history search" }));
    expect(screen.queryByLabelText("Search traffic")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Filters active")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Search and filter requests" }));
    expect(screen.getByLabelText("Search traffic")).toHaveValue("unloaded request");
    fireEvent.keyDown(screen.getByLabelText("Search traffic"), { key: "Escape" });
    expect(screen.queryByLabelText("Search traffic")).not.toBeInTheDocument();
  });
});


describe("HTTP History body loading and workspace races", () => {
  it("loads bodies only for selected requests", async () => {
    api.fetchTraffic.mockResolvedValue({ ...firstHistoryPage(), summary: true });
    api.fetchTrafficDetail.mockImplementation(async (id: string) => ({ ...historyEntry(Number(id.split('-')[1])), request_body: Array.from(new TextEncoder().encode('request payload')), response_body: Array.from(new TextEncoder().encode('response payload')) }));
    renderHistory();
    await waitFor(() => expect(api.fetchTrafficDetail).toHaveBeenCalledWith('history-200'));
    expect(await screen.findByText('response payload')).toBeTruthy();
    expect(api.fetchTrafficDetail).toHaveBeenCalledTimes(1);
    const row = screen.getByText('/item-199').closest('tr')!;
    fireEvent.click(row);
    await waitFor(() => expect(api.fetchTrafficDetail).toHaveBeenCalledWith('history-199'));
    expect(api.fetchTrafficDetail).toHaveBeenCalledTimes(2);
  });

  it("ignores an old page that finishes after changing workspace", async () => {
    let resolvePage!: (value: unknown) => void;
    api.fetchTraffic.mockImplementation(async (query) => {
      if (query.workspace === 'w2') return { data: [{ ...historyEntry(999), workspace_id: 'w2' }], total: 1, next_cursor: null };
      if (query.cursor) return new Promise(resolve => { resolvePage = resolve; });
      return firstHistoryPage();
    });
    renderHistory();
    await waitFor(() => expect(screen.getAllByRole('row').length).toBeGreaterThan(2));
    const scroller = screen.getByLabelText('History requests');
    Object.defineProperty(scroller, 'clientHeight', { configurable: true, value: 400 });
    fireEvent.scroll(scroller, { target: { scrollTop: 2800 } });
    await waitFor(() => expect(resolvePage).toBeDefined());
    fireEvent.click(screen.getByRole('button', { name: 'switch to w2' }));
    await screen.findByText('/item-999');
    await act(async () => resolvePage({ data: [historyEntry(99)], total: 200, next_cursor: null }));
    expect(screen.queryByText('/item-99')).toBeNull();
    expect(screen.getByText('/item-999')).toBeTruthy();
  });
});


describe("Replay variables, send history and annotations",()=>{
 it("resolves variables on Send and saves the template and resolved snapshot separately",async()=>{
  docs['w1']={...stored(5,'Saved tab','{{base_url}}/users/{{id}}'),variables:{base_url:'https://example.com',id:'42',token:'secret'}};
  send.mockResolvedValue({ok:true,status:200,statusText:'OK',duration:3,size:2,responseHeaders:{},responseBody:'{}'});
  renderReplay();await screen.findByRole('button',{name:'Saved tab'});
  fireEvent.click(screen.getByRole('button',{name:/^Send$/}));
  await waitFor(()=>expect(send).toHaveBeenCalledWith({data:expect.objectContaining({url:'https://example.com/users/42'})}));
  await waitFor(()=>expect(featureApi.saveReplayRun).toHaveBeenCalledWith('w1',5,expect.objectContaining({template:expect.objectContaining({url:'{{base_url}}/users/{{id}}'}),request:expect.objectContaining({url:'https://example.com/users/42'}),response:expect.objectContaining({status:200})})));
  expect(urlField().value).toBe('{{base_url}}/users/{{id}}');
 });
 it("does not send missing variables or share them with a different workspace",async()=>{
  docs['w1']={...stored(5,'Saved tab','{{missing}}/test'),variables:{token:'workspace-one'}};
  renderReplay();await screen.findByRole('button',{name:'Saved tab'});
  fireEvent.click(screen.getByRole('button',{name:/^Send$/}));expect(send).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button',{name:/Variables/}));expect(screen.getByLabelText('Variable value 1')).toHaveValue('workspace-one');
  fireEvent.keyDown(screen.getByRole('dialog'),{key:'Escape'});
  fireEvent.click(screen.getByRole('button',{name:'switch to w2'}));await screen.findByRole('button',{name:'Other tab'});
  fireEvent.click(screen.getByRole('button',{name:/Variables/}));expect(screen.queryByLabelText('Variable value 1')).toBeNull();
 });
 it("persists variable edits in the workspace document",async()=>{
  renderReplay();await screen.findByRole('button',{name:'Saved tab'});
  fireEvent.click(screen.getByRole('button',{name:/Variables/}));fireEvent.click(screen.getByRole('button',{name:'Add variable'}));
  fireEvent.change(screen.getByLabelText('Variable name 1'),{target:{value:'token'}});
  fireEvent.change(screen.getByLabelText('Variable value 1'),{target:{value:'new-secret'}});
  fireEvent.click(screen.getByRole('button',{name:'Apply variables'}));
  await waitFor(()=>expect(api.saveReplayTabs).toHaveBeenCalledWith('w1',expect.objectContaining({variables:{token:'new-secret'}}),expect.anything()),{timeout:3000});
 });
 it("records success and failure and restores a successful sent request",async()=>{
  send.mockResolvedValueOnce({ok:true,status:201,statusText:'Created',duration:8,size:7,responseHeaders:{},responseBody:'created'}).mockResolvedValueOnce({ok:false,error:'network failure'});
  renderReplay();await screen.findByRole('button',{name:'Saved tab'});
  fireEvent.click(screen.getByRole('button',{name:/^Send$/}));await waitFor(()=>expect(featureApi.saveReplayRun).toHaveBeenCalledTimes(1));
  const first=featureApi.saveReplayRun.mock.calls[0]![2];
  editUrl('https://example.com/changed');fireEvent.click(screen.getByRole('button',{name:/^Send$/}));
  await waitFor(()=>expect(featureApi.saveReplayRun).toHaveBeenCalledTimes(2));expect(featureApi.saveReplayRun.mock.calls[1]![2]).toMatchObject({error:'network failure',request:{url:'https://example.com/changed'}});
  featureApi.fetchReplayRuns.mockResolvedValue({data:[{id:first.id,timestamp:first.timestamp,method:first.request.method,url:first.request.url,status:201,duration:8}],has_more:false});
  fireEvent.click(screen.getByRole('button',{name:'Send history'}));await screen.findByRole('option',{name:/201/});
  fireEvent.change(screen.getByLabelText('Replay run'),{target:{value:first.id}});
  expect(await screen.findByText('created')).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'Restore sent request'}));expect(urlField().value).toBe('https://saved.example/one');
 });
 it("saves bookmarks and notes against the traffic UUID",async()=>{
  api.fetchTraffic.mockResolvedValue({data:[historyEntry(200)],total:1,next_cursor:null});
  renderHistory();await screen.findByText('/item-200');
  fireEvent.click(screen.getByRole('button',{name:'Bookmark request 1'}));
  await waitFor(()=>expect(featureApi.updateTrafficAnnotation).toHaveBeenCalledWith('history-200',{bookmarked:true}));
  await screen.findByRole('button',{name:'Remove bookmark request 1'});
  fireEvent.click(screen.getByRole('button',{name:'Add notes'}));fireEvent.change(screen.getByRole('textbox',{name:'Request notes'}),{target:{value:'Check access control'}});
  fireEvent.click(screen.getByRole('button',{name:'Save notes'}));
  await waitFor(()=>expect(featureApi.updateTrafficAnnotation).toHaveBeenCalledWith('history-200',{notes:'Check access control'}));
  expect(await screen.findByRole('button',{name:'Edit notes'})).toBeTruthy();
 });
 it("retains the notes draft when saving fails",async()=>{
  api.fetchTraffic.mockResolvedValue({data:[historyEntry(200)],total:1,next_cursor:null});
  featureApi.updateTrafficAnnotation.mockRejectedValueOnce(new Error('save refused'));
  renderHistory();await screen.findByText('/item-200');fireEvent.click(screen.getByRole('button',{name:'Add notes'}));
  fireEvent.change(screen.getByRole('textbox',{name:'Request notes'}),{target:{value:'Keep this draft'}});fireEvent.click(screen.getByRole('button',{name:'Save notes'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('save refused');expect(screen.getByRole('textbox',{name:'Request notes'})).toHaveValue('Keep this draft');
 });
});


describe('Replay after response scripts',()=>{
 const setup=async()=>{
  docs['w1']={...stored(5,'Saved tab','https://saved.example/one'),variables:{existing:'keep'},tabs:[{...stored(5,'Saved tab','https://saved.example/one').tabs[0],afterResponse:'variables.set("token1",response.json().token)'}]};
  send.mockResolvedValue({ok:true,status:200,statusText:'OK',duration:3,size:2,responseHeaders:{},responseBody:'{"token":"abc"}'});
  renderReplay();await screen.findByRole('button',{name:'Saved tab'});
 };
 it('saves source, applies changes and records output without rerunning history',async()=>{
  scriptRunner.mockResolvedValue({logs:['saved'],updates:{token1:'abc'}});await setup();
  fireEvent.click(screen.getByRole('button',{name:'Scripts'}));expect(screen.getByLabelText('After response script')).toHaveValue('variables.set("token1",response.json().token)');
  fireEvent.click(screen.getByRole('button',{name:/^Send$/}));
  await waitFor(()=>expect(featureApi.saveReplayRun).toHaveBeenCalledWith('w1',5,expect.objectContaining({afterResponse:expect.any(String),scriptResult:{logs:['saved'],updates:{token1:'abc'}}})));
  await waitFor(()=>expect(api.saveReplayTabs).toHaveBeenCalledWith('w1',expect.objectContaining({variables:{existing:'keep',token1:'abc'}}),expect.anything()));
  fireEvent.click(screen.getByRole('button',{name:'Send history'}));await waitFor(()=>expect(featureApi.fetchReplayRuns).toHaveBeenCalled());expect(scriptRunner).toHaveBeenCalledTimes(1);
 });
 it('keeps the HTTP response and old variables on script failure',async()=>{
  scriptRunner.mockResolvedValue({logs:[],updates:{},error:'interrupted'});await setup();
  fireEvent.click(screen.getByRole('button',{name:/^Send$/}));await waitFor(()=>expect(featureApi.saveReplayRun).toHaveBeenCalled());
  expect(featureApi.saveReplayRun.mock.calls[0]![2]).toMatchObject({response:{status:200},scriptResult:{error:'interrupted'}});
  expect(screen.getByText('interrupted')).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:/Variables/}));expect(screen.getByLabelText('Variable value 1')).toHaveValue('keep');
 });
 it('commits a late result only to its originating workspace',async()=>{
  let finish!:(result:unknown)=>void;scriptRunner.mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));await setup();
  fireEvent.click(screen.getByRole('button',{name:/^Send$/}));await waitFor(()=>expect(scriptRunner).toHaveBeenCalled());
  fireEvent.click(screen.getByRole('button',{name:'switch to w2'}));await screen.findByRole('button',{name:'Other tab'});
  await act(async()=>{finish({logs:[],updates:{token1:'abc'}});});
  await waitFor(()=>expect(api.saveReplayTabs).toHaveBeenCalledWith('w1',expect.objectContaining({variables:{existing:'keep',token1:'abc'}})));
  fireEvent.click(screen.getByRole('button',{name:/Variables/}));expect(screen.queryByLabelText('Variable value 1')).toBeNull();
 });
});


describe('Postman collection Replay import',()=>{
 const upload=async()=>{
  const source=JSON.stringify({info:{name:'My collection',schema:'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'},variable:[{key:'token',value:'incoming'},{key:'host',value:'https://example.com'}],item:[{name:'Auth',item:[{name:'Login',request:{method:'POST',url:'{{host}}/login',body:{mode:'raw',raw:'{}',options:{raw:{language:'json'}}}}}]},{name:'Profile',request:{method:'GET',url:'{{host}}/profile',auth:{type:'bearer',bearer:[{key:'token',value:'{{token}}'}]}}}]});
  const file=new File([source],'collection.json',{type:'application/json'});Object.defineProperty(file,'text',{value:async()=>source});
  fireEvent.click(screen.getByRole('button',{name:'Import Postman'}));
  fireEvent.change(screen.getByLabelText('Postman collection file'),{target:{files:[file]}});
  await screen.findByLabelText('Import Auth / Login');
 };
 it('creates selected named tabs, merges variables and persists without sending',async()=>{
  docs['w1']={...stored(5,'Saved tab','https://saved.example/one'),variables:{token:'existing'}};
  renderReplay();await screen.findByRole('button',{name:'Saved tab'});await upload();
  fireEvent.click(screen.getByLabelText('Import Profile'));
  fireEvent.click(screen.getByRole('button',{name:'Import 1 request'}));
  expect(await screen.findByRole('button',{name:'Auth / Login'})).toBeTruthy();expect(screen.queryByRole('button',{name:'Profile'})).toBeNull();
  expect(urlField()).toHaveValue('{{host}}/login');expect(send).not.toHaveBeenCalled();
  await waitFor(()=>expect(api.saveReplayTabs).toHaveBeenCalledWith('w1',expect.objectContaining({variables:{token:'existing',host:'https://example.com'},tabs:expect.arrayContaining([expect.objectContaining({name:'Auth / Login',customName:true,request:expect.objectContaining({method:'POST',body:'{}'})})])}),expect.anything()));
 });
 it('supports explicit variable overwrite and cancellation',async()=>{
  docs['w1']={...stored(5,'Saved tab','https://saved.example/one'),variables:{token:'existing'}};
  renderReplay();await screen.findByRole('button',{name:'Saved tab'});await upload();
  fireEvent.click(screen.getByRole('button',{name:'Cancel'}));expect(screen.queryByRole('button',{name:'Auth / Login'})).toBeNull();
  await upload();fireEvent.click(screen.getByLabelText('Overwrite existing workspace variables'));fireEvent.click(screen.getByRole('button',{name:'Import 2 requests'}));
  expect(await screen.findByRole('button',{name:'Profile'})).toBeTruthy();
  await waitFor(()=>expect(api.saveReplayTabs).toHaveBeenCalledWith('w1',expect.objectContaining({variables:{token:'incoming',host:'https://example.com'}}),expect.anything()));expect(send).not.toHaveBeenCalled();
 });
 it('discards the import preview when switching workspaces',async()=>{
  renderReplay();await screen.findByRole('button',{name:'Saved tab'});
  const switchButton=screen.getByRole('button',{name:'switch to w2'});await upload();
  fireEvent.click(switchButton);await screen.findByRole('button',{name:'Other tab'});
  fireEvent.click(screen.getByRole('button',{name:'Import Postman'}));expect(screen.queryByLabelText('Import Auth / Login')).toBeNull();expect(send).not.toHaveBeenCalled();
 });
});


describe('Bruno request import into Replay',()=>{
 const bru=(name:string)=>`meta {\n  name: ${name}\n  type: http\n}\npost {\n  url: {{base_url}}/login\n  body: json\n  auth: none\n}\nbody:json {\n  {"user":"${name}"}\n}`;
 const file=(name:string,source:string)=>{const value=new File([source],name);Object.defineProperty(value,'text',{value:async()=>source});return value;};
 it('imports multiple native requests plus environment without sending',async()=>{
  docs['w1']={...stored(5,'Saved tab','https://saved.example/one'),variables:{token:'keep'}};
  renderReplay();await screen.findByRole('button',{name:'Saved tab'});
  fireEvent.click(screen.getByRole('button',{name:'Import Bruno'}));
  const input=screen.getByLabelText('Bruno request files');expect(input).toHaveAttribute('multiple');
  fireEvent.change(input,{target:{files:[file('a.bru',bru('User A')),file('b.bru',bru('User B'))]}});
  await screen.findByLabelText('Import User A');expect(screen.getByLabelText('Import User B')).toBeChecked();
  fireEvent.change(screen.getByLabelText('Bruno environment file'),{target:{files:[file('dev.bru','vars {\n  base_url: https://example.com\n}')]}});
  await screen.findByText('Environment loaded · 1 variables');
  fireEvent.click(screen.getByRole('button',{name:'Import 2 requests'}));
  expect(await screen.findByRole('button',{name:'User A'})).toBeTruthy();expect(screen.getByRole('button',{name:'User B'})).toBeTruthy();expect(send).not.toHaveBeenCalled();
  await waitFor(()=>expect(api.saveReplayTabs).toHaveBeenCalledWith('w1',expect.objectContaining({variables:{token:'keep',base_url:'https://example.com'},tabs:expect.arrayContaining([expect.objectContaining({name:'User B',customName:true})])}),expect.anything()));
 });
 it('disables invalid native files while allowing valid ones to import',async()=>{
  renderReplay();await screen.findByRole('button',{name:'Saved tab'});fireEvent.click(screen.getByRole('button',{name:'Import Bruno'}));
  fireEvent.change(screen.getByLabelText('Bruno request files'),{target:{files:[file('good.bru',bru('Valid request')),file('bad.bru','invalid data')]}});
  await screen.findByLabelText('Import Valid request');expect(screen.getByLabelText('Import bad')).toBeDisabled();
  fireEvent.click(screen.getByRole('button',{name:'Import 1 request'}));expect(await screen.findByRole('button',{name:'Valid request'})).toBeTruthy();expect(send).not.toHaveBeenCalled();
 });
});
