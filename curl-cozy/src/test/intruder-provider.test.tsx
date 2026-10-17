import { act, render, waitFor, fireEvent, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { IntruderProvider, useIntruder } from "../components/intruder-provider";
import { newIntruderConfig } from "../lib/intruder";
const mock = vi.hoisted(() => ({
  workspace: null as string | null,
  send: vi.fn(),
  save: vi.fn(),
  fetch: vi.fn(),
}));
vi.mock("../components/inspector", () => ({
  useInspector: () => ({
    session: mock.workspace
      ? { target: "workspace", workspace_id: mock.workspace }
      : { target: "temporary" },
    getReplayWorkspace: () => mock.workspace,
    variables: {},
    timeout: 15000,
  }),
}));
vi.mock("../components/auth-profiles-provider", () => ({ useAuthProfiles: () => null }));
vi.mock("../lib/intruder-api", () => ({
  fetchIntruder: (...a: unknown[]) => mock.fetch(...a),
  saveIntruder: vi.fn(async () => ({ revision: 1 })),
  saveIntruderRun: (...a: unknown[]) => mock.save(...a),
  saveIntruderResult: vi.fn(async () => {}),
}));
vi.mock("../lib/replay.functions", () => ({ sendHttpRequest: mock.send }));
let ctx: NonNullable<ReturnType<typeof useIntruder>>;
function Probe() {
  ctx = useIntruder()!;
  return null;
}
const config = () => ({
  ...newIntruderConfig(),
  request: { method: "GET" as const, url: "https://example.com/§x§", headers: {}, body: "" },
  source: { kind: "list" as const, values: ["a"] },
});
beforeEach(() => {
  mock.workspace = null;
  mock.send.mockReset().mockResolvedValue({
    ok: true,
    status: 200,
    size: 1,
    duration: 1,
    responseHeaders: {},
    responseBody: "ok",
  });
  mock.save.mockReset().mockResolvedValue(undefined);
  mock.fetch.mockReset().mockResolvedValue({ revision: 0, document: config() });
});
it("blocks double start and sends one substituted request", async () => {
  render(
    <IntruderProvider>
      <Probe />
    </IntruderProvider>,
  );
  act(() => ctx.update(config()));
  await act(async () => {
    const first = ctx.start();
    await expect(ctx.start()).rejects.toThrow("active Intruder");
    await first;
  });
  await waitFor(() => expect(ctx.run?.status).toBe("completed"));
  expect(mock.send).toHaveBeenCalledTimes(1);
  expect(mock.send.mock.calls[0]![0].data.url).toBe("https://example.com/a");
});
it("does not send if workspace changes while initial metadata is saving", async () => {
  mock.workspace = "w1";
  let resolve!: () => void;
  mock.save.mockImplementationOnce(
    () =>
      new Promise<void>((r) => {
        resolve = r;
      }),
  );
  const view = render(
    <IntruderProvider>
      <Probe />
    </IntruderProvider>,
  );
  await waitFor(() => expect(ctx.ready).toBe(true));
  let start!: Promise<void>;
  act(() => {
    start = ctx.start();
  });
  await waitFor(() => expect(mock.save).toHaveBeenCalledTimes(1));
  mock.workspace = "w2";
  view.rerender(
    <IntruderProvider>
      <Probe />
    </IntruderProvider>,
  );
  await act(async () => {
    resolve();
    await expect(start).rejects.toThrow("Workspace changed");
  });
  expect(mock.send).not.toHaveBeenCalled();
  expect(mock.save.mock.calls[1]![0]).toBe("w1");
  expect(mock.save.mock.calls[1]![1].status).toBe("stopped");
});

vi.mock("../components/auth-profiles", () => ({ ProfileSelector: () => null }));
vi.mock("../components/request-menu", () => ({
  RequestMenu: ({ children }: { children: import("react").ReactNode }) => children,
}));
import { IntruderView } from "../components/intruder";
it("edits a marked request, previews a payload and executes from the UI", async () => {
  render(
    <IntruderProvider>
      <Probe />
      <IntruderView />
    </IntruderProvider>,
  );
  fireEvent.change(screen.getByLabelText("Request URL"), {
    target: { value: "https://example.com/§id§" },
  });
  fireEvent.change(screen.getByLabelText("Payload list"), { target: { value: "hello world" } });
  fireEvent.change(screen.getByText("Encoding").querySelector("select")!, {
    target: { value: "url" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Preview payload substitution" }));
  await waitFor(() => expect(screen.getByText(/hello%20world/)).toBeInTheDocument());
  fireEvent.click(screen.getByRole("button", { name: "Start" }));
  await waitFor(() => expect(ctx.run?.status).toBe("completed"));
  expect(mock.send.mock.calls[0]![0].data.url).toBe("https://example.com/hello%20world");
});
