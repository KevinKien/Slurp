import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
  fetchTraffic: vi.fn(),
  clearTraffic: vi.fn(),
  fetchWorkspaces: vi.fn(),
  createWorkspace: vi.fn(),
  renameWorkspace: vi.fn(),
  deleteWorkspace: vi.fn(),
  activateWorkspace: vi.fn(),
  fetchSession: vi.fn(),
  useTemporarySession: vi.fn(),
  saveReplay: vi.fn(),
  fetchReplayTabs: vi.fn(),
  saveReplayTabs: vi.fn(),
}));
vi.mock("@/lib/api", () => api);
vi.mock("@/lib/ws", () => ({ useTrafficStream: () => ({ status: "disconnected" }) }));
vi.mock("@/lib/replay.functions", () => ({ sendHttpRequest: vi.fn() }));
// jsdom has no ResizeObserver, which the resizable panels need; plain containers are enough here.
vi.mock("@/components/ui/resizable", () => {
  const Box = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>;
  return { HistoryPanelGroup: Box, ResizablePanelGroup: Box, ResizablePanel: Box, ResizableHandle: () => null };
});
vi.mock("@tanstack/react-start", () => ({ useServerFn: (fn: unknown) => fn }));
vi.mock("@tanstack/react-router", () => ({ Link: ({ children }: { children: React.ReactNode }) => <a>{children}</a> }));

import { InspectorProvider, ReplayView } from "@/components/inspector";

const renderReplay = () =>
  render(
    <InspectorProvider>
      <ReplayView />
    </InspectorProvider>,
  );

const startRename = () => fireEvent.doubleClick(screen.getByRole("button", { name: /untitled request/i }));

describe("Replay tab names", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.fetchReplayTabs.mockResolvedValue({ tabs: [], active: null });
    api.saveReplayTabs.mockResolvedValue(undefined);
    api.fetchTraffic.mockRejectedValue(new Error("offline"));
    api.fetchSession.mockRejectedValue(new Error("offline"));
    api.fetchWorkspaces.mockRejectedValue(new Error("offline"));
  });
  afterEach(cleanup);

  it("renames a tab on double-click and Enter", async () => {
    renderReplay();
    startRename();
    const input = screen.getByLabelText("Tab name");
    fireEvent.change(input, { target: { value: "Login call" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(await screen.findByRole("button", { name: "Login call" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Tab name")).not.toBeInTheDocument();
  });

  it("renames with F2 and saves on blur", async () => {
    renderReplay();
    fireEvent.keyDown(screen.getByRole("button", { name: /untitled request/i }), { key: "F2" });
    const input = screen.getByLabelText("Tab name");
    fireEvent.change(input, { target: { value: "Via F2" } });
    fireEvent.blur(input);

    expect(await screen.findByRole("button", { name: "Via F2" })).toBeInTheDocument();
  });

  it("Escape cancels without changing the name", async () => {
    renderReplay();
    startRename();
    const input = screen.getByLabelText("Tab name");
    fireEvent.change(input, { target: { value: "Discarded" } });
    fireEvent.keyDown(input, { key: "Escape" });
    // A blur after Escape (focus leaving) must not commit the discarded text.
    fireEvent.blur(input);

    await waitFor(() => expect(screen.queryByLabelText("Tab name")).not.toBeInTheDocument());
    expect(screen.getByRole("button", { name: /untitled request/i })).toBeInTheDocument();
    expect(screen.queryByText("Discarded")).not.toBeInTheDocument();
  });

  it("keeps the old name when the new one is blank", async () => {
    renderReplay();
    startRename();
    const input = screen.getByLabelText("Tab name");
    fireEvent.change(input, { target: { value: "   " } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(await screen.findByRole("button", { name: /untitled request/i })).toBeInTheDocument();
  });
});
