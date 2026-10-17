import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { HeldItem } from "@/lib/api";
import type { InterceptEvent } from "@/lib/ws";

const api = vi.hoisted(() => ({
  fetchTraffic: vi.fn(),
  clearTraffic: vi.fn(),
  fetchWorkspaces: vi.fn(),
  createWorkspace: vi.fn(),
  renameWorkspace: vi.fn(),
  deleteWorkspace: vi.fn(),
  activateWorkspace: vi.fn(),
  fetchIntercept: vi.fn(),
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
const ws = vi.hoisted(() => ({ push: undefined as undefined | ((e: InterceptEvent) => void) }));
vi.mock("@/lib/api", () => api);
vi.mock("@/lib/ws", () => ({
  // Capture the intercept callback so tests can push events like the proxy would.
  useTrafficStream: (
    _a: unknown,
    _b: unknown,
    _c: unknown,
    onIntercept: (e: InterceptEvent) => void,
  ) => {
    ws.push = onIntercept;
    return { status: "connected" };
  },
}));
vi.mock("@/lib/replay.functions", () => ({ sendHttpRequest: vi.fn() }));
vi.mock("@tanstack/react-start", () => ({ useServerFn: (fn: unknown) => fn }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: React.ReactNode }) => <a>{children}</a>,
}));

import { InspectorProvider } from "@/components/inspector";
import { InterceptView } from "@/components/intercept";

const item = (over: Partial<HeldItem> = {}): HeldItem => ({
  id: "r1",
  phase: "request",
  created_at: "2026-10-15T10:00:00Z",
  scheme: "https",
  host: "api.acme.io",
  url: "https://api.acme.io/v1/items",
  method: "GET",
  path: "/v1/items",
  status: null,
  headers: [["host", "api.acme.io"]],
  body: "",
  body_size: 0,
  body_editable: true,
  ...over,
});

const second = item({
  id: "r2",
  method: "POST",
  path: "/v1/other",
  url: "https://api.acme.io/v1/other",
  body: "x",
  body_size: 1,
});

const renderView = async (
  held: HeldItem[] = [item(), second],
  settings = { requests: true, responses: false },
) => {
  api.fetchIntercept.mockResolvedValue({ settings, held });
  render(
    <InspectorProvider>
      <InterceptView />
    </InspectorProvider>,
  );
  if (held.length) await screen.findByLabelText(/held (request|response)/i);
};

const editor = () => screen.getByLabelText(/held (request|response)/i) as HTMLTextAreaElement;

describe("InterceptView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.fetchReplayTabs.mockResolvedValue({ tabs: [], active: null });
    api.saveReplayTabs.mockResolvedValue(undefined);
    api.fetchTraffic.mockRejectedValue(new Error("offline"));
    api.fetchSession.mockResolvedValue({
      target: "workspace",
      workspace_id: "default",
      temporary_count: 0,
    });
    api.fetchWorkspaces.mockResolvedValue([]);
    api.forwardHeld.mockResolvedValue(undefined);
    api.dropHeld.mockResolvedValue(undefined);
    api.forwardAllHeld.mockResolvedValue(undefined);
    api.updateInterceptSettings.mockImplementation(async (u: object) => ({
      requests: false,
      responses: false,
      ...u,
    }));
  });
  afterEach(cleanup);

  it("lists held items and shows the first one as editable HTTP text", async () => {
    await renderView();
    expect(within(screen.getByLabelText("Held items")).getAllByRole("button")).toHaveLength(2);
    expect(editor().value).toBe("GET /v1/items HTTP/1.1\nhost: api.acme.io\n\n");
  });

  it("forwards an unedited item without sending an edit", async () => {
    await renderView();
    fireEvent.click(screen.getByRole("button", { name: /^forward$/i }));
    await waitFor(() => expect(api.forwardHeld).toHaveBeenCalledWith("r1", undefined));
    await waitFor(() =>
      expect(screen.queryByText("/v1/items", { exact: false })).not.toBeInTheDocument(),
    );
  });

  it("forwards an edited item with the parsed edit", async () => {
    await renderView();
    fireEvent.change(editor(), {
      target: { value: "POST /v1/changed?x=1 HTTP/1.1\nhost: api.acme.io\nx-debug: 1\n\npayload" },
    });
    fireEvent.click(screen.getByRole("button", { name: /forward edited/i }));
    await waitFor(() =>
      expect(api.forwardHeld).toHaveBeenCalledWith("r1", {
        method: "POST",
        path: "/v1/changed?x=1",
        headers: [
          ["host", "api.acme.io"],
          ["x-debug", "1"],
        ],
        body: "payload",
      }),
    );
  });

  it("blocks forwarding invalid text and explains why", async () => {
    await renderView();
    fireEvent.change(editor(), { target: { value: "this is not http" } });
    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid request line/i);
    expect(screen.getByRole("button", { name: /^forward( edited)?$/i })).toBeDisabled();
    fireEvent.change(editor(), { target: { value: "GET /ok HTTP/1.1\nhost: api.acme.io\n\n" } });
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    expect(screen.getByRole("button", { name: /forward edited/i })).toBeEnabled();
  });

  it("keeps the item and shows the server's reason when forwarding is refused", async () => {
    api.forwardHeld.mockRejectedValue(new Error("The request path must start with /"));
    await renderView();
    fireEvent.change(editor(), { target: { value: "GET /x HTTP/1.1\nhost: a\n\nedited" } });
    fireEvent.click(screen.getByRole("button", { name: /forward edited/i }));
    await waitFor(() => expect(api.forwardHeld).toHaveBeenCalled());
    expect(editor().value).toContain("edited");
    expect(within(screen.getByLabelText("Held items")).getAllByRole("button")).toHaveLength(2);
  });

  it("drops an item", async () => {
    await renderView();
    fireEvent.click(screen.getByRole("button", { name: /^drop$/i }));
    await waitFor(() => expect(api.dropHeld).toHaveBeenCalledWith("r1"));
  });

  it("keeps each item's draft when switching between items", async () => {
    await renderView();
    fireEvent.change(editor(), { target: { value: "GET /draft HTTP/1.1\nhost: api.acme.io\n\n" } });
    const rows = within(screen.getByLabelText("Held items")).getAllByRole("button");
    fireEvent.click(rows[1]!);
    expect(editor().value).toMatch(/^POST \/v1\/other/);
    fireEvent.click(within(screen.getByLabelText("Held items")).getAllByRole("button")[0]!);
    expect(editor().value).toMatch(/^GET \/draft/);
    fireEvent.click(screen.getByRole("button", { name: /reset/i }));
    expect(editor().value).toMatch(/^GET \/v1\/items/);
  });

  it("shows responses with their status and forwards status edits", async () => {
    await renderView(
      [
        item({
          id: "s1",
          phase: "response",
          status: 200,
          headers: [["content-type", "text/plain"]],
          body: "ok",
        }),
      ],
      {
        requests: false,
        responses: true,
      },
    );
    expect(editor().value).toBe("HTTP/1.1 200 OK\ncontent-type: text/plain\n\nok");
    fireEvent.change(editor(), {
      target: { value: "HTTP/1.1 503 Service Unavailable\ncontent-type: text/plain\n\ndown" },
    });
    fireEvent.click(screen.getByRole("button", { name: /forward edited/i }));
    await waitFor(() =>
      expect(api.forwardHeld).toHaveBeenCalledWith("s1", {
        status: 503,
        headers: [["content-type", "text/plain"]],
        body: "down",
      }),
    );
  });

  it("toggles interception and reflects the proxy's answer", async () => {
    await renderView([], { requests: false, responses: false });
    const requests = screen.getByRole("switch", { name: /intercept requests/i });
    expect(requests).toHaveAttribute("aria-checked", "false");
    fireEvent.click(requests);
    await waitFor(() =>
      expect(api.updateInterceptSettings).toHaveBeenCalledWith({ requests: true }),
    );
    await waitFor(() => expect(requests).toHaveAttribute("aria-checked", "true"));
    expect(screen.getByText(/waiting for traffic/i)).toBeInTheDocument();
  });

  it("explains how to get started when interception is off and nothing is held", async () => {
    await renderView([], { requests: false, responses: false });
    expect(await screen.findByText("Interception is off")).toBeInTheDocument();
  });

  it("adds items pushed by the proxy and removes resolved ones", async () => {
    await renderView([], { requests: true, responses: false });
    act(() => ws.push?.({ type: "queued", item: item({ id: "live", path: "/live" }) }));
    expect(await screen.findByLabelText("Held request")).toBeInTheDocument();
    expect(editor().value).toMatch(/^GET \/live/);
    act(() => ws.push?.({ type: "resolved", id: "live" }));
    await waitFor(() => expect(screen.queryByLabelText("Held request")).not.toBeInTheDocument());
  });

  it("notes binary bodies cannot be edited", async () => {
    await renderView([item({ body: null, body_editable: false, body_size: 2048 })]);
    expect(screen.getByText(/binary or too large to edit/i)).toBeInTheDocument();
  });

  it.each(["request", "response"] as const)(
    "searches a held %s without changing its draft",
    async (phase) => {
      await renderView([
        item({
          phase,
          status: phase === "response" ? 200 : null,
          body: "needle NEEDLE needle",
          body_size: 20,
        }),
      ]);
      const before = editor().value;
      expect(screen.queryByLabelText("Search intercept")).not.toBeInTheDocument();
      fireEvent.click(screen.getByRole("button", { name: "Toggle intercept search" }));
      const input = screen.getByLabelText("Search intercept");
      expect(input).toHaveFocus();
      fireEvent.change(input, { target: { value: "needle" } });
      expect(screen.getByRole("status", { name: "Intercept search results" })).toHaveTextContent(
        "1/3",
      );
      expect(editor().value.slice(editor().selectionStart, editor().selectionEnd)).toBe("needle");
      fireEvent.click(screen.getByRole("button", { name: "Next match" }));
      expect(screen.getByRole("status", { name: "Intercept search results" })).toHaveTextContent(
        "2/3",
      );
      expect(editor().value.slice(editor().selectionStart, editor().selectionEnd)).toBe("NEEDLE");
      fireEvent.click(screen.getByRole("button", { name: "Match case" }));
      expect(screen.getByRole("status", { name: "Intercept search results" })).toHaveTextContent(
        "1/2",
      );
      expect(editor().value).toBe(before);
      expect(screen.getByRole("button", { name: "Reset" })).toBeDisabled();
      fireEvent.keyDown(input, { key: "Escape" });
      expect(screen.queryByLabelText("Search intercept")).not.toBeInTheDocument();
    },
  );

  it("opens Intercept search with Ctrl+F and searches literal text", async () => {
    await renderView([item({ body: "a.b axb a.b", body_size: 11 })]);
    fireEvent.keyDown(editor(), { key: "f", ctrlKey: true });
    const input = screen.getByLabelText("Search intercept");
    fireEvent.change(input, { target: { value: "a.b" } });
    expect(screen.getByRole("status", { name: "Intercept search results" })).toHaveTextContent(
      "1/2",
    );
    fireEvent.keyDown(input, { key: "Enter", shiftKey: true });
    expect(screen.getByRole("status", { name: "Intercept search results" })).toHaveTextContent(
      "2/2",
    );
    fireEvent.change(input, { target: { value: "not-found" } });
    expect(screen.getByRole("status", { name: "Intercept search results" })).toHaveTextContent(
      "0/0",
    );
    expect(screen.getByRole("button", { name: "Next match" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Close intercept search" }));
    expect(screen.queryByLabelText("Search intercept")).not.toBeInTheDocument();
  });
  it("labels HTTP and WS handshakes in the same queue without protocol tabs",async()=>{
    await renderView([item(),item({id:"ws-1",headers:[["Upgrade","websocket"],["Connection","Upgrade"]]})]);
    expect(screen.getByText("WS")).toBeInTheDocument();
    expect(screen.getByText("HTTP")).toBeInTheDocument();
    expect(screen.queryByRole("tablist",{name:"Traffic protocol"})).not.toBeInTheDocument();
  });

 it("shows a held WebSocket payload and forwards or drops it without HTTP edits",async()=>{
  const frame=item({id:"frame-1",method:"WS",websocket:{opcode:1,direction:"client_to_server",fin:true,compressed:false,masked:true,size:5,text:"hello",hex:"68656c6c6f",truncated:false},body_editable:false});
  api.fetchIntercept.mockResolvedValue({settings:{requests:true,responses:true},held:[frame]});
  const ui=render(<InspectorProvider><InterceptView/></InspectorProvider>);
  await screen.findByLabelText("Held WebSocket frame");expect(screen.getByLabelText("WebSocket frame payload")).toHaveTextContent("hello");
  fireEvent.click(screen.getByRole("button",{name:"Forward"}));await waitFor(()=>expect(api.forwardHeld).toHaveBeenCalledWith("frame-1",undefined));
  ui.unmount();
  render(<InspectorProvider><InterceptView/></InspectorProvider>);
  await screen.findByLabelText("Held WebSocket frame");
  fireEvent.click(screen.getByRole("button",{name:"Drop"}));await waitFor(()=>expect(api.dropHeld).toHaveBeenCalledWith("frame-1"));
 });

});
