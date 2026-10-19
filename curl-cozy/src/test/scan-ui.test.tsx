import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { ScanProvider, useScan } from "../components/scan-provider";
import { ScanView } from "../components/scan";
const mock = vi.hoisted(() => ({ send: vi.fn() }));
vi.mock("../lib/replay.functions", () => ({ sendHttpRequest: mock.send }));
vi.mock("../components/inspector", () => ({
  useInspector: () => ({
    session: { target: "temporary" },
    getReplayWorkspace: () => null,
    variables: {},
    timeout: 15000,
  }),
}));
vi.mock("../components/auth-profiles-provider", () => ({
  useAuthProfiles: () => ({
    ready: true,
    createSession: () => ({ variables: {}, resolve: (r: unknown) => r, receive: vi.fn() }),
  }),
}));
vi.mock("../components/auth-profiles", () => ({ ProfileSelector: () => null }));
vi.mock("../components/request-menu", () => ({
  RequestMenu: ({ children }: { children: import("react").ReactNode }) => children,
}));
let ctx: ReturnType<typeof useScan>;
function Probe() {
  ctx = useScan();
  return null;
}
const request = {
  method: "GET",
  url: "https://example.com/items?q=original",
  headers: {},
  body: "",
};
beforeEach(() => {
  const stored = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => stored.get(k) ?? null,
    setItem: (k: string, v: string) => stored.set(k, v),
  });
  mock.send.mockReset().mockImplementation(async ({ data }) => ({
    ok: true,
    status: 200,
    responseHeaders: { "content-type": "text/plain" },
    responseBody: new URL(data.url).searchParams.get("q"),
    duration: 1,
    size: 10,
  }));
});
it("inspects a History response and renders finding verification and evidence without sending", async () => {
  render(
    <ScanProvider>
      <Probe />
      <ScanView />
    </ScanProvider>,
  );
  await act(async () =>
    ctx.prepare(async () => ({
      ...request,
      status: 200,
      responseHeaders: { "content-type": "text/html" },
      responseBody: "<h1>hello</h1>",
    })),
  );
  expect(screen.getByLabelText("Scan profile")).toHaveValue("default-passive");
  fireEvent.click(screen.getByRole("button", { name: "Inspect response" }));
  await waitFor(() => expect(ctx.run?.status).toBe("completed"));
  expect(
    screen.getByText("HTML response lacks X-Content-Type-Options: nosniff"),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: `View finding ${ctx.run!.findings[0]!.id}` }));
  expect(screen.getByText(ctx.run!.findings[0]!.verification.reason)).toBeInTheDocument();
  expect(screen.queryByText(/All request \/ response evidence/)).not.toBeInTheDocument();
  expect(mock.send).not.toHaveBeenCalled();
});
it("requires sending opt-in and a selected parameter before an active reflection scan", async () => {
  render(
    <ScanProvider>
      <Probe />
      <ScanView />
    </ScanProvider>,
  );
  await act(async () => ctx.prepare(async () => request));
  expect(screen.getByLabelText("Scan profile")).toHaveValue("default-active");
  expect(screen.queryByLabelText("maxRequests")).not.toBeInTheDocument();
  expect(screen.getByLabelText("Allow sending scan requests").parentElement).toHaveTextContent(
    "all selected checks",
  );
  const start = screen.getByRole("button", { name: "Start scan" });
  expect(start).toBeDisabled();
  act(() => ctx.updateDraft({ ...ctx.draft!, checks: ["reflection"] }));
  fireEvent.click(screen.getByLabelText("Query: q (occurrence 1)"));
  fireEvent.change(screen.getByLabelText("rate"), { target: { value: "20" } });
  fireEvent.click(screen.getByLabelText("Allow sending scan requests"));
  expect(start).toBeEnabled();
  expect(mock.send).not.toHaveBeenCalled();
  fireEvent.click(start);
  await waitFor(() => expect(ctx.run?.status).toBe("completed"));
  expect(mock.send).toHaveBeenCalledTimes(4);
  expect(screen.getByText("Input reflected in response")).toBeInTheDocument();
});
it("saves a reusable profile and enables selected intrusive checks without hidden policy gates", async () => {
  render(
    <ScanProvider>
      <Probe />
      <ScanView />
    </ScanProvider>,
  );
  await act(async () => ctx.prepare(async () => request, "active"));
  fireEvent.click(screen.getByRole("button", { name: "Create profile" }));
  fireEvent.change(screen.getByLabelText("Scan profile name"), {
    target: { value: "My API audit" },
  });
  const traversal = screen.getByLabelText(/File path traversal/);
  expect(traversal).toBeEnabled();
  fireEvent.click(traversal);
  fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
  expect(ctx.draft!.checks).toContain("path-traversal");
  expect(ctx.draft!.policy!.allowIntrusive).toBe(true);
  expect(ctx.draft!.allowSending).toBe(false);
  expect(JSON.parse(localStorage.getItem("slurp.scan-profiles.v1")!)).toEqual(
    expect.arrayContaining([expect.objectContaining({ name: "My API audit" })]),
  );
  fireEvent.change(screen.getByLabelText("Scan profile"), { target: { value: "default-active" } });
  expect(ctx.draft!.checks).not.toContain("path-traversal");
  expect(ctx.draft!.policy!.allowIntrusive).toBe(false);
});
it("prepares a passive scan without sending when no response exists", async () => {
  render(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  await act(async () => {
    await ctx.prepare(async () => request, "passive");
  });
  expect(ctx.draft?.mode).toBe("passive");
  expect(ctx.draft?.observed).toBeUndefined();
  expect(mock.send).not.toHaveBeenCalled();
});
