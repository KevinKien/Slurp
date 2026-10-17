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
  expect(screen.getByLabelText("Scan mode")).toHaveValue("passive");
  fireEvent.click(screen.getByRole("button", { name: "Inspect response" }));
  await waitFor(() => expect(ctx.run?.status).toBe("completed"));
  expect(
    screen.getByText("HTML response lacks X-Content-Type-Options: nosniff"),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: `View finding ${ctx.run!.findings[0]!.id}` }));
  expect(
    screen.getByText(
      "The stated configuration is present in the captured response; exploitability is not asserted.",
    ),
  ).toBeInTheDocument();
  expect(screen.getByText(/All request \/ response evidence \(1\)/)).toBeInTheDocument();
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
  expect(screen.getByLabelText("Scan mode")).toHaveValue("active");
  const start = screen.getByRole("button", { name: "Start scan" });
  expect(start).toBeDisabled();
  fireEvent.click(screen.getByLabelText(/Input reflection/));
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
