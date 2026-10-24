import { act, render, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { ScanProvider, useScan } from "../components/scan-provider";
import { newScanPlan, type ScanPlan } from "../lib/scan";
const mock = vi.hoisted(() => ({
  workspace: "w1" as string | null,
  send: vi.fn(),
  save: vi.fn(),
  resolve: vi.fn(),
  create: vi.fn(),
  receive: vi.fn(),
}));
vi.mock("../lib/replay.functions", () => ({ sendHttpRequest: mock.send }));
vi.mock("../lib/scan-api", () => ({
  saveScanRun: (...args: unknown[]) => mock.save(...args),
  validateBrowserSnapshot: vi.fn(),
  lookupDependency: vi.fn(() => {
    throw Error("Unexpected dependency lookup");
  }),
  probeHostHeader: vi.fn(),
  probeHttpProtocol: vi.fn(() => {
    throw Error("Unexpected protocol probe");
  }),
  publishJwtKey: vi.fn(async () => { throw Error("OAST key hosting not configured in fixture"); }),
  issueOastProbe: vi.fn(async () => {
    throw Error("Unexpected OAST call in a non-OAST scan");
  }),
  pollOastProbe: vi.fn(async () => {
    throw Error("Unexpected OAST call in a non-OAST scan");
  }),
}));
vi.mock("../components/inspector", () => ({
  useInspector: () => ({
    session: mock.workspace
      ? { target: "workspace", workspace_id: mock.workspace }
      : { target: "temporary" },
    getReplayWorkspace: () => mock.workspace,
    variables: { token: "shared" },
    timeout: 15000,
  }),
}));
vi.mock("../components/auth-profiles-provider", () => ({
  useAuthProfiles: () => ({
    ready: true,
    createSession: (...args: unknown[]) => mock.create(...args),
  }),
}));
let ctx: ReturnType<typeof useScan>;
function Probe() {
  ctx = useScan();
  return null;
}
const req = {
  method: "GET",
  url: "https://example.com/items",
  headers: { Authorization: "captured" },
  body: "",
};
const response = {
  status: 200,
  responseHeaders: {},
  responseBody: "ok",
  duration: 1,
  size: 2,
  setCookies: ["sid=value"],
};
function active(): ScanPlan {
  return {
    ...newScanPlan(req),
    mode: "active",
    allowSending: true,
    checks: ["error-disclosure"],
    rate: 20,
  };
}
beforeEach(() => {
  mock.workspace = "w1";
  mock.send.mockReset().mockResolvedValue({ ok: true, ...response });
  mock.save.mockReset().mockResolvedValue(undefined);
  mock.resolve
    .mockReset()
    .mockImplementation((r) => ({ ...r, headers: { Authorization: "Bearer profile" } }));
  mock.receive.mockReset();
  mock.create.mockReset().mockReturnValue({
    profile: { id: "a", name: "User A" },
    variables: { token: "profile" },
    resolve: mock.resolve,
    receive: mock.receive,
  });
});
it("snapshots a separate chosen profile for concurrent scans and persists their evidence", async () => {
  render(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  act(() => ctx.start(active(), "a"));
  act(() => ctx.start({ ...active(), request: { ...req, url: "https://example.com/other" } }, "a"));
  await waitFor(() => expect(ctx.busy).toBe(false));
  expect(mock.create).toHaveBeenCalledWith("a", { token: "shared" });
  expect(mock.send.mock.calls[0]![0].data.headers.Authorization).toBe("Bearer profile");
  expect(mock.save.mock.calls[0]![0]).toBe("w1");
  expect(ctx.run?.profileName).toBe("User A");
});
it("never resolves another profile or sends requests for captured passive traffic", async () => {
  render(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  const plan = newScanPlan(req);
  plan.observed = { response };
  act(() => ctx.start(plan));
  await waitFor(() => expect(ctx.busy).toBe(false));
  expect(mock.create).not.toHaveBeenCalled();
  expect(mock.send).not.toHaveBeenCalled();
  expect(ctx.run?.evidence[0]?.request.headers["Authorization"]).toBe("captured");
});
it("saves an in-flight result to its original workspace after a workspace change", async () => {
  let finish!: (v: { ok: true } & typeof response) => void;
  mock.send.mockImplementationOnce(
    () =>
      new Promise((r) => {
        finish = r;
      }),
  );
  const view = render(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  act(() => ctx.start(active()));
  await waitFor(() => expect(mock.send).toHaveBeenCalledTimes(1));
  mock.workspace = "w2";
  view.rerender(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  await act(async () => finish({ ok: true, ...response }));
  await waitFor(() => expect(ctx.busy).toBe(false));
  expect(mock.send).toHaveBeenCalledTimes(1);
  expect(mock.receive).not.toHaveBeenCalled();
  expect(mock.save.mock.calls[0]![0]).toBe("w1");
  expect(mock.save.mock.calls[0]![1].status).toBe("stopped");
  expect(ctx.run).toBeNull();
});
it("retries evidence saving without sending again", async () => {
  mock.save.mockRejectedValueOnce(Error("storage offline"));
  render(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  const plan = newScanPlan(req);
  plan.observed = { response };
  act(() => ctx.start(plan));
  await waitFor(() => expect(ctx.error).toBe("storage offline"));
  const failedId = ctx.run!.id;
  act(() => ctx.start(plan));
  await waitFor(() => expect(ctx.busy).toBe(false));
  expect(ctx.saveErrors?.[failedId]).toBe("storage offline");
  await act(() => ctx.retrySave());
  expect(ctx.error).toBe("");
  expect(mock.save).toHaveBeenCalledTimes(3);
  expect(mock.send).not.toHaveBeenCalled();
});

it("prepares captured response for passive scanning and keeps the draft across navigation", async () => {
  const view = render(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  await act(async () =>
    ctx.prepare(async () => ({
      ...req,
      status: 200,
      responseHeaders: {},
      responseBody: "captured response",
    })),
  );
  expect(ctx.draft?.mode).toBe("passive");
  expect(ctx.draft?.observed?.response.responseBody).toBe("captured response");
  expect(mock.send).not.toHaveBeenCalled();
  view.rerender(
    <ScanProvider>
      <Probe />
      <span>Another route</span>
    </ScanProvider>,
  );
  expect(ctx.draft?.request.url).toBe(req.url);
});
it("discards late request loads after a workspace change", async () => {
  let finish!: (r: typeof req) => void;
  const view = render(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  let pending!: Promise<void>;
  act(() => {
    pending = ctx.prepare(
      () =>
        new Promise((r) => {
          finish = r;
        }),
    );
  });
  mock.workspace = "w2";
  view.rerender(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  await act(async () => {
    finish(req);
    await pending;
  });
  expect(ctx.draft).toBeNull();
  expect(ctx.preparing).toBe(false);
});

it("keeps more than three concurrent tasks and controls only the requested task", async () => {
  const finishes: ((v: unknown) => void)[] = [];
  mock.send.mockImplementation(() => new Promise((resolve) => finishes.push(resolve)));
  render(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  act(() => {
    for (let i = 0; i < 5; i++)
      ctx.start({ ...active(), request: { ...req, url: `https://example.com/items/${i}` } });
  });
  await waitFor(() => expect(mock.send).toHaveBeenCalledTimes(5));
  expect(ctx.localRuns).toHaveLength(5);
  const ids = ctx.localRuns.map((r) => r.id);
  act(() => ctx.pause(ids[0]));
  expect(ctx.localRuns.find((r) => r.id === ids[0])?.status).toBe("paused");
  expect(ctx.localRuns.filter((r) => r.status === "running")).toHaveLength(4);
  act(() => ctx.resume(ids[0]));
  expect(ctx.localRuns.find((r) => r.id === ids[0])?.status).toBe("running");
  act(() => ctx.stop(ids[0]));
  await act(async () => {
    for (const finish of finishes.splice(0)) finish({ ok: true, ...response });
  });
  await waitFor(() => expect(ctx.localRuns.find((r) => r.id === ids[0])?.status).toBe("stopped"));
  expect(ctx.busy).toBe(true);
  act(() => {
    for (const id of ids.slice(1)) ctx.stop(id);
  });
  await act(async () => {
    for (const finish of finishes.splice(0)) finish({ ok: true, ...response });
  });
  await waitFor(() => expect(ctx.busy).toBe(false));
  expect(ctx.localRuns.every((r) => r.status === "stopped")).toBe(true);
});

it("fetches a missing passive response only when the prepared scan is started", async () => {
  render(
    <ScanProvider>
      <Probe />
    </ScanProvider>,
  );
  await act(async () => {
    await ctx.prepare(() => req, "passive");
  });
  expect(mock.send).not.toHaveBeenCalled();
  act(() => ctx.start(ctx.draft!));
  await waitFor(() => expect(ctx.busy).toBe(false));
  expect(mock.send).toHaveBeenCalledTimes(1);
  expect(ctx.run?.plan.mode).toBe("passive");
  expect(ctx.run?.sent).toBe(1);
  expect(ctx.run?.status).toBe("completed");
  expect(ctx.run?.evidence[0]?.request.headers["Authorization"]).toBe("Bearer profile");
});
