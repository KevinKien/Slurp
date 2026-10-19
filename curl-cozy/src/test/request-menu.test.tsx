import { forwardRef, type AnchorHTMLAttributes } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { RequestMenu } from "@/components/request-menu";
import { toCurl } from "@/lib/request-actions";
const state = vi.hoisted(() => ({ setSessions: vi.fn(), setActive: vi.fn() }));
vi.mock("@/components/inspector", () => ({
  useInspector: () => ({ sessions: [{ id: 4 }], ...state }),
}));
vi.mock("@tanstack/react-router", () => ({
  Link: forwardRef<HTMLAnchorElement, AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }>(
    ({ to, onClick, ...props }, ref) => (
      <a
        {...props}
        ref={ref}
        href={to}
        onClick={(event) => {
          onClick?.(event);
          event.preventDefault();
        }}
      />
    ),
  ),
}));
const request = {
  method: "POST",
  url: "https://example.com/test",
  headers: { "Content-Type": "application/json" },
  body: '{"a":1}',
};
const writeText = vi.fn().mockResolvedValue(undefined);
beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal(
    "DOMRect",
    class {
      static fromRect({ x = 0, y = 0, width = 0, height = 0 }: DOMRectInit = {}) {
        return {
          x,
          y,
          width,
          height,
          left: x,
          top: y,
          right: x + width,
          bottom: y + height,
          toJSON: () => ({}),
        };
      }
    },
  );
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
});
function open() {
  render(
    <RequestMenu request={request}>
      <div>Request target</div>
    </RequestMenu>,
  );
  fireEvent.contextMenu(screen.getByText("Request target"));
}
describe("Request context menu", () => {
  it("offers Send to Replay, Copy cURL and a disabled future Scan", async () => {
    open();
    for (const item of screen.getAllByRole("menuitem", { name: /Scan/ }))
      expect(item).toHaveAttribute("data-disabled");
    fireEvent.click(screen.getByRole("menuitem", { name: "Copy cURL" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(toCurl(request)));
  });
  it("creates a new active Replay tab with an independent header object", () => {
    open();
    fireEvent.click(screen.getByRole("menuitem", { name: "Send to Replay" }));
    const update = state.setSessions.mock.calls[0]![0];
    const tabs = update([{ id: 4 }]);
    expect(tabs[1]).toMatchObject({ id: expect.any(Number), name: "/test", request });
    expect(tabs[1].request.headers).not.toBe(request.headers);
    expect(tabs[1].id).toBeGreaterThan(4);
    expect(state.setActive).toHaveBeenCalledWith(tabs[1].id);
  });
});

it("waits for a lazily loaded request body before copying cURL", async () => {
  render(
    <RequestMenu request={async () => request}>
      <div>Lazy request</div>
    </RequestMenu>,
  );
  fireEvent.contextMenu(screen.getByText("Lazy request"));
  fireEvent.click(screen.getByRole("menuitem", { name: "Copy cURL" }));
  await waitFor(() => expect(writeText).toHaveBeenCalledWith(toCurl(request)));
});

import { ScanContext, type ScanState } from "@/lib/scan-context";
it("opens Scan configuration and loads the selected request without starting it", async () => {
  const prepare = vi.fn(async (read: () => unknown) => {
      await read();
    }),
    start = vi.fn(),
    read = vi.fn(async () => request);
  render(
    <ScanContext.Provider value={{ prepare, start } as unknown as ScanState}>
      <RequestMenu request={read}>
        <div>Scan target</div>
      </RequestMenu>
    </ScanContext.Provider>,
  );
  fireEvent.contextMenu(screen.getByText("Scan target"));
  const item = screen.getByRole("menuitem", { name: "Scan active" });
  expect(item).not.toHaveAttribute("data-disabled");
  expect(item).toHaveAttribute("href", "/dashboard");
  fireEvent.click(item);
  await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
  expect(prepare).toHaveBeenCalledWith(expect.any(Function), "active");
  expect(start).not.toHaveBeenCalled();
});

it("sends a captured WebSocket handshake to an editable WS Replay tab", () => {
  render(
    <RequestMenu
      request={{
        ...request,
        url: "https://example.com/socket",
        headers: { Upgrade: "websocket", Cookie: "session=abc" },
      }}
    >
      <div>WS target</div>
    </RequestMenu>,
  );
  fireEvent.contextMenu(screen.getByText("WS target"));
  fireEvent.click(screen.getByRole("menuitem", { name: "Send to Replay" }));
  const update = state.setSessions.mock.calls[0]![0];
  expect(update([])[0].request).toMatchObject({
    method: "GET",
    url: "wss://example.com/socket",
    headers: { Cookie: "session=abc", Upgrade: "websocket" },
  });
});

it.each(["passive", "active"] as const)(
  "Replay %s scan reads the matching request source",
  async (mode) => {
    const captured = {
      ...request,
      url: "https://example.com/original",
      status: 200,
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: "<h1>Captured</h1>",
    };
    const read = vi.fn(() => ({ ...request, url: "https://example.com/edited" }));
    const passive = vi.fn(() => captured);
    const prepare = vi.fn(async (source: () => unknown) => {
      await source();
    });
    render(
      <ScanContext.Provider value={{ prepare } as unknown as ScanState}>
        <RequestMenu request={read} passiveRequest={passive}>
          <div>Replay scan target</div>
        </RequestMenu>
      </ScanContext.Provider>,
    );
    fireEvent.contextMenu(screen.getByText("Replay scan target"));
    fireEvent.click(screen.getByRole("menuitem", { name: `Scan ${mode}` }));
    await waitFor(() => expect(prepare).toHaveBeenCalled());
    if (mode === "passive") {
      expect(passive).toHaveBeenCalledTimes(1);
      expect(read).not.toHaveBeenCalled();
    } else {
      expect(read).toHaveBeenCalledTimes(1);
      expect(passive).not.toHaveBeenCalled();
    }
  },
);
