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
const send = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => api);
vi.mock("@/lib/ws", () => ({ useTrafficStream: () => ({ status: "disconnected" }) }));
vi.mock("@/lib/replay.functions", () => ({ sendHttpRequest: send }));
vi.mock("@/components/ui/resizable", () => {
  const Box = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>;
  return { ResizablePanelGroup: Box, ResizablePanel: Box, ResizableHandle: () => null };
});
vi.mock("@tanstack/react-start", () => ({ useServerFn: (fn: unknown) => fn }));
vi.mock("@tanstack/react-router", () => ({ Link: ({ children }: { children: React.ReactNode }) => <a>{children}</a> }));

import { InspectorProvider, ReplayView } from "@/components/inspector";

const openRaw = () => {
  // The editor tab row comes first in the DOM; the body-mode "Raw" button appears later.
  fireEvent.click(screen.getAllByRole("button", { name: "Raw" })[0]!);
  return screen.getByLabelText("Raw request");
};

describe("Replay raw request editor", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.fetchReplayTabs.mockResolvedValue({ tabs: [], active: null });
    api.saveReplayTabs.mockResolvedValue(undefined);
    api.fetchTraffic.mockRejectedValue(new Error("offline"));
    api.fetchSession.mockRejectedValue(new Error("offline"));
    api.fetchWorkspaces.mockRejectedValue(new Error("offline"));
    send.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      duration: 5,
      size: 2,
      responseHeaders: {},
      responseBody: "{}",
    });
    render(
      <InspectorProvider>
        <ReplayView />
      </InspectorProvider>,
    );
  });
  afterEach(cleanup);

  it("starts from the current request as editable text", () => {
    const raw = openRaw() as HTMLTextAreaElement;
    expect(raw.value).toMatch(/^GET \/get HTTP\/1\.1\nHost: httpbin\.org/);
  });

  it("sends the edited request", async () => {
    const raw = openRaw();
    fireEvent.change(raw, {
      target: { value: "POST /anything?x=1 HTTP/1.1\nHost: httpbin.org\nX-Test: 1\n\nhello" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^send$/i }));

    await waitFor(() => expect(send).toHaveBeenCalledTimes(1));
    expect(send).toHaveBeenCalledWith({
      data: {
        method: "POST",
        url: "https://httpbin.org/anything?x=1",
        headers: { "X-Test": "1" },
        body: "hello",
        timeout: 15000,
      },
    });
  });

  it("reflects raw edits in the URL field and blocks sending invalid text", async () => {
    const raw = openRaw();
    fireEvent.change(raw, { target: { value: "GET /changed HTTP/1.1\nHost: example.org" } });
    expect(screen.getByLabelText("Request URL")).toHaveValue("https://example.org/changed");

    fireEvent.change(raw, { target: { value: "this is not http" } });
    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid request line/i);
    fireEvent.click(screen.getByRole("button", { name: /^send$/i }));
    expect(send).not.toHaveBeenCalled();

    fireEvent.change(raw, { target: { value: "GET /fixed HTTP/1.1\nHost: example.org" } });
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /^send$/i }));
    await waitFor(() => expect(send).toHaveBeenCalledTimes(1));
  });

  it("does not stay blocked after leaving the Raw tab with invalid text", async () => {
    fireEvent.change(openRaw(), { target: { value: "garbage" } });
    fireEvent.click(screen.getByRole("button", { name: /^body$/i }));
    fireEvent.click(screen.getByRole("button", { name: /^send$/i }));
    await waitFor(() => expect(send).toHaveBeenCalledTimes(1));
  });
});
