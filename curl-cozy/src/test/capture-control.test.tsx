import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Workspace } from "@/lib/api";

const ws = (id: string, name: string, active = false): Workspace => ({
  id,
  name,
  active,
  request_count: 0,
  created_at: "2026-10-15T00:00:00Z",
});

// A tiny in-memory stand-in for the proxy's workspace API.
let store: Workspace[] = [];
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
vi.mock("@/lib/api", () => api);
vi.mock("@/lib/ws", () => ({ useTrafficStream: () => ({ status: "connected" }) }));
vi.mock("@/lib/replay.functions", () => ({ sendHttpRequest: vi.fn() }));
vi.mock("@tanstack/react-start", () => ({ useServerFn: (fn: unknown) => fn }));
vi.mock("@tanstack/react-router", () => ({ Link: ({ children }: { children: React.ReactNode }) => <a>{children}</a> }));

import { CaptureControl, InspectorProvider, useInspector } from "@/components/inspector";

function ViewProbe() {
  return <output data-testid="view">{useInspector().view}</output>;
}

const renderControl = () =>
  render(
    <InspectorProvider>
      <CaptureControl />
      <ViewProbe />
    </InspectorProvider>,
  );

const openMenu = async () => {
  const trigger = await screen.findByRole("button", { name: /capture workspace/i });
  await waitFor(() => expect(trigger).toBeEnabled());
  fireEvent.keyDown(trigger, { key: "Enter" });
};

// Node's experimental global localStorage can shadow jsdom's and throw; use a predictable stand-in.
const memoryStorage = () => {
  const data = new Map<string, string>();
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
    clear: () => data.clear(),
  };
};

describe("CaptureControl", () => {
  afterEach(cleanup);

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("localStorage", memoryStorage());
    store = [ws("default", "Default", true), ws("w1", "Staging")];
    api.fetchReplayTabs.mockResolvedValue({ tabs: [], active: null });
    api.saveReplayTabs.mockResolvedValue(undefined);
    api.fetchTraffic.mockRejectedValue(new Error("offline"));
    api.fetchSession.mockResolvedValue({ target: "workspace", workspace_id: "default", temporary_count: 0 });
    api.fetchIntercept.mockResolvedValue({ settings: { requests: false, responses: false }, held: [] });
    api.fetchWorkspaces.mockImplementation(async () => store.map((w) => ({ ...w })));
    api.activateWorkspace.mockImplementation(async (id: string) => {
      store = store.map((w) => ({ ...w, active: w.id === id }));
    });
    api.createWorkspace.mockImplementation(async (name: string) => {
      const w = ws("new-1", name.trim()); // the real backend trims the name
      store = [...store, w];
      return w;
    });
  });

  it("shows the workspace currently receiving traffic", async () => {
    renderControl();
    expect(await screen.findByText("Default")).toBeInTheDocument();
  });

  it("switches the capture target and shows that workspace", async () => {
    renderControl();
    await openMenu();
    fireEvent.click(await screen.findByRole("menuitem", { name: /staging/i }));

    await waitFor(() => expect(api.activateWorkspace).toHaveBeenCalledWith("w1"));
    await waitFor(() => expect(screen.getByTestId("view")).toHaveTextContent("w1"));
  });

  it("lets the user stop saving: no workspace keeps requests in memory only", async () => {
    api.useTemporarySession.mockResolvedValue(undefined);
    renderControl();
    await openMenu();
    fireEvent.click(await screen.findByRole("menuitem", { name: /no workspace/i }));

    await waitFor(() => expect(api.useTemporarySession).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByTestId("view")).toHaveTextContent("temporary"));
  });

  it("creates a workspace, makes it the capture target and shows it", async () => {
    renderControl();
    await openMenu();
    fireEvent.click(await screen.findByRole("menuitem", { name: /new workspace/i }));
    fireEvent.change(await screen.findByLabelText("Workspace name"), { target: { value: "  Login flow " } });
    fireEvent.click(screen.getByRole("button", { name: /create and save here/i }));

    await waitFor(() => expect(api.createWorkspace).toHaveBeenCalledWith("  Login flow "));
    await waitFor(() => expect(api.activateWorkspace).toHaveBeenCalledWith("new-1"));
    await waitFor(() => expect(screen.getByTestId("view")).toHaveTextContent("new-1"));
  });

  it("keeps the dialog open and does not switch when creation fails", async () => {
    api.createWorkspace.mockRejectedValue(new Error("a workspace with this name already exists"));
    renderControl();
    await openMenu();
    fireEvent.click(await screen.findByRole("menuitem", { name: /new workspace/i }));
    fireEvent.change(await screen.findByLabelText("Workspace name"), { target: { value: "Staging" } });
    fireEvent.click(screen.getByRole("button", { name: /create and save here/i }));

    await waitFor(() => expect(api.createWorkspace).toHaveBeenCalled());
    expect(api.activateWorkspace).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Workspace name")).toBeInTheDocument();
    // Still on the workspace the proxy was already capturing into.
    expect(screen.getByTestId("view")).toHaveTextContent("default");
  });
});
