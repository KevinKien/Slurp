import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo, Workspace } from "@/lib/api";

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
const send = vi.hoisted(() => vi.fn());
const wsStatus = vi.hoisted(() => ({ value: "connected" as "connected" | "disconnected" }));
vi.mock("@/lib/api", () => api);
vi.mock("@/lib/ws", () => ({ useTrafficStream: () => ({ status: wsStatus.value }) }));
vi.mock("@/lib/replay.functions", () => ({ sendHttpRequest: send }));
vi.mock("@/components/ui/resizable", () => {
  const Box = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>;
  return { ResizablePanelGroup: Box, ResizablePanel: Box, ResizableHandle: () => null };
});
vi.mock("@tanstack/react-start", () => ({ useServerFn: (fn: unknown) => fn }));
vi.mock("@tanstack/react-router", () => ({ Link: ({ children }: { children: React.ReactNode }) => <a>{children}</a> }));

import { InspectorProvider, InspectorShell, ReplayView } from "@/components/inspector";

const workspace = (id: string, name: string, active = false): Workspace => ({
  id,
  name,
  active,
  request_count: 0,
  created_at: "2026-10-15T00:00:00Z",
});

const UNCHOSEN: SessionInfo = { target: "unchosen", workspace_id: null, temporary_count: 0 };
const chosen = (id: string): SessionInfo => ({ target: "workspace", workspace_id: id, temporary_count: 0 });

// The "proxy": session state changes when the UI calls the API, like the real backend.
let session: SessionInfo;
let store: Workspace[];

const memoryStorage = () => {
  const data = new Map<string, string>();
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
    clear: () => data.clear(),
  };
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("localStorage", memoryStorage());
  wsStatus.value = "connected";
  session = UNCHOSEN;
  store = [workspace("default", "Default"), workspace("w1", "Staging")];
  api.fetchTraffic.mockResolvedValue({ data: [], total: 0, limit: 500, offset: 0 });
  api.fetchReplayTabs.mockResolvedValue({ tabs: [], active: null });
  api.saveReplayTabs.mockResolvedValue(undefined);
  api.fetchIntercept.mockResolvedValue({ settings: { requests: false, responses: false }, held: [] });
  api.fetchWorkspaces.mockImplementation(async () => store.map((w) => ({ ...w, active: session.workspace_id === w.id })));
  api.fetchSession.mockImplementation(async () => ({ ...session }));
  api.activateWorkspace.mockImplementation(async (id: string) => {
    session = chosen(id);
  });
  api.createWorkspace.mockImplementation(async (name: string) => {
    const w = workspace("new-1", name.trim());
    store = [...store, w];
    return w;
  });
  api.useTemporarySession.mockImplementation(async () => {
    session = { target: "temporary", workspace_id: null, temporary_count: 0 };
  });
});
afterEach(cleanup);

const renderShell = () =>
  render(
    <InspectorProvider>
      <InspectorShell>
        <div>page content</div>
      </InspectorShell>
    </InspectorProvider>,
  );

describe("choosing a workspace when the tool opens", () => {
  it("blocks the app until a workspace is chosen", async () => {
    const { container } = renderShell();
    expect(await screen.findByRole("dialog", { name: /choose a workspace/i })).toBeInTheDocument();
    // Everything behind the dialog is inert, so it cannot be reached by keyboard or mouse.
    expect(container.querySelector(".inspector-shell")).toHaveAttribute("inert");
  });

  it("picking a workspace saves into it, opens the app on it and remembers the view", async () => {
    const { container } = renderShell();
    fireEvent.click(await screen.findByRole("button", { name: /staging/i }));

    await waitFor(() => expect(api.activateWorkspace).toHaveBeenCalledWith("w1"));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(container.querySelector(".inspector-shell")).not.toHaveAttribute("inert");
    expect(localStorage.getItem("intercept.viewWorkspace")).toBe("w1");
    expect(api.fetchTraffic).toHaveBeenLastCalledWith(expect.objectContaining({ workspace: "w1" }));
  });

  it("creating a workspace also makes it the one that is saved to", async () => {
    renderShell();
    fireEvent.change(await screen.findByLabelText("New workspace name"), { target: { value: "  Login flow " } });
    fireEvent.click(screen.getByRole("button", { name: /create and start/i }));

    await waitFor(() => expect(api.createWorkspace).toHaveBeenCalledWith("  Login flow "));
    await waitFor(() => expect(api.activateWorkspace).toHaveBeenCalledWith("new-1"));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("continuing without a workspace keeps requests in memory and shows a persistent warning", async () => {
    renderShell();
    fireEvent.click(await screen.findByRole("button", { name: /continue without a workspace/i }));

    await waitFor(() => expect(api.useTemporarySession).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(await screen.findByText(/requests are kept in memory only and are lost when the tool closes/i)).toBeInTheDocument();
    expect(localStorage.getItem("intercept.viewWorkspace")).toBe("temporary");
    expect(api.activateWorkspace).not.toHaveBeenCalled();
  });

  it("does not ask again once the proxy already has a workspace (e.g. after a page reload)", async () => {
    session = chosen("w1");
    renderShell();
    await waitFor(() => expect(api.fetchSession).toHaveBeenCalled());
    await waitFor(() => expect(api.fetchWorkspaces).toHaveBeenCalled());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByText("page content")).toBeInTheDocument();
    // With no saved view it opens on the workspace being captured into.
    await waitFor(() => expect(localStorage.getItem("intercept.viewWorkspace")).toBe("w1"));
  });

  it("does not show the gate while the proxy is offline", async () => {
    wsStatus.value = "disconnected";
    api.fetchSession.mockRejectedValue(new Error("offline"));
    api.fetchWorkspaces.mockRejectedValue(new Error("offline"));
    api.fetchTraffic.mockRejectedValue(new Error("offline"));
    renderShell();
    await waitFor(() => expect(api.fetchSession).toHaveBeenCalled());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("Replay requests are saved to the workspace", () => {
  const okResult = {
    ok: true,
    status: 200,
    statusText: "OK",
    duration: 5,
    size: 2,
    responseHeaders: { "content-type": "application/json" },
    responseBody: "{}",
  };

  const sendFromReplay = async () => {
    session = chosen("w1");
    render(
      <InspectorProvider>
        <ReplayView />
      </InspectorProvider>,
    );
    await waitFor(() => expect(api.fetchSession).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: /^send$/i }));
    await waitFor(() => expect(send).toHaveBeenCalledTimes(1));
  };

  it("saves the request and its response", async () => {
    send.mockResolvedValue(okResult);
    api.saveReplay.mockResolvedValue({
      id: "e1", timestamp: "2026-10-15T00:00:00Z", method: "GET", url: "https://httpbin.org/get", host: "httpbin.org", path: "/get",
      scheme: "https", request_headers: "{}", request_body: [], request_content_type: null, status_code: 200,
      response_headers: "{}", response_body: [], response_content_type: null, duration_ms: 5, request_size: 0, response_size: 2,
      error: null, workspace_id: "w1", source: "replay",
    });
    await sendFromReplay();

    await waitFor(() =>
      expect(api.saveReplay).toHaveBeenCalledWith({
        method: "GET",
        url: "https://httpbin.org/get",
        request_headers: [["Accept", "application/json"]],
        request_body: "",
        status_code: 200,
        response_headers: [["content-type", "application/json"]],
        response_body: "{}",
        duration_ms: 5,
        error: null,
      }),
    );
  });

  it("also saves failed requests, with the error", async () => {
    send.mockResolvedValue({ ok: false, error: "Replay supports public HTTPS hosts only." });
    api.saveReplay.mockResolvedValue({});
    await sendFromReplay();

    await waitFor(() =>
      expect(api.saveReplay).toHaveBeenCalledWith(
        expect.objectContaining({ status_code: 0, response_body: "", error: "Replay supports public HTTPS hosts only." }),
      ),
    );
  });

  it("still shows the response when saving fails", async () => {
    send.mockResolvedValue(okResult);
    api.saveReplay.mockRejectedValue(new Error("proxy went away"));
    await sendFromReplay();

    await waitFor(() => expect(api.saveReplay).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("200")).toBeInTheDocument();
  });

  it("does not try to save while the proxy is offline", async () => {
    wsStatus.value = "disconnected";
    send.mockResolvedValue(okResult);
    api.fetchSession.mockRejectedValue(new Error("offline"));
    render(
      <InspectorProvider>
        <ReplayView />
      </InspectorProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /^send$/i }));
    await waitFor(() => expect(send).toHaveBeenCalledTimes(1));
    expect(api.saveReplay).not.toHaveBeenCalled();
  });
});
