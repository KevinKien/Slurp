import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, it, expect, vi } from "vitest";
import { newFlow, newFlowStep } from "../lib/flows";
import { newProfile, type AuthProfile } from "../lib/auth-profiles";
const mock = vi.hoisted(() => ({
  workspace: "w1" as string | null,
  fetch: vi.fn(),
  save: vi.fn(),
  send: vi.fn(),
  flows: vi.fn(),
  saveFlows: vi.fn(),
  saveRun: vi.fn(),
  matrixList: vi.fn(),
  matrixSave: vi.fn(),
}));
vi.mock("@/components/inspector", () => ({
  useInspector: () => ({
    session: mock.workspace
      ? { target: "workspace", workspace_id: mock.workspace }
      : { target: "temporary", workspace_id: null },
    getReplayWorkspace: () => mock.workspace,
    variables: { shared: "same" },
    timeout: 15000,
    sessions: [
      {
        id: 1,
        name: "Account",
        request: {
          method: "GET",
          url: "https://api.example.com/account",
          headers: { Authorization: "stale" },
          body: "",
        },
      },
    ],
  }),
}));
vi.mock("@/lib/security-api", () => ({
  fetchProfiles: mock.fetch,
  saveProfiles: mock.save,
  fetchMatrixRuns: mock.matrixList,
  saveMatrixRun: mock.matrixSave,
  fetchMatrixRun: vi.fn(),
}));
vi.mock("@/lib/flows-api", () => ({
  fetchFlows: mock.flows,
  saveFlows: mock.saveFlows,
  saveFlowRun: mock.saveRun,
}));
vi.mock("@/lib/replay.functions", () => ({ sendHttpRequest: mock.send }));
vi.mock("@tanstack/react-router", () => ({ Link: ({ children }: any) => <a>{children}</a> }));
import { AuthProfilesProvider, useAuthProfiles } from "../components/auth-profiles-provider";
import { ProfileSelector, ProfilesView } from "../components/auth-profiles";
import { FlowsProvider, useFlows } from "../components/flows-provider";
import { MatrixProvider } from "../components/matrix-provider";
import { MatrixView } from "../components/authorization-matrix";
const profile = (id: string): AuthProfile => ({
  ...newProfile(),
  id,
  name: `User ${id.toUpperCase()}`,
  origins: ["https://api.example.com"],
  headers: { Authorization: "Bearer {{token}}" },
  variables: { token: id },
  cookies: [],
});
beforeEach(() => {
  vi.clearAllMocks();
  mock.workspace = "w1";
  mock.fetch.mockImplementation(async () => ({
    revision: 0,
    document: { profiles: [profile("a"), profile("b")], active: "a" },
  }));
  mock.save.mockImplementation(async (_workspace, revision) => ({ revision: revision + 1 }));
  mock.flows.mockResolvedValue({ flows: [], active: null });
  mock.saveRun.mockResolvedValue({});
  mock.saveFlows.mockResolvedValue({});
  mock.matrixList.mockResolvedValue({ data: [], has_more: false });
  mock.matrixSave.mockResolvedValue({});
  mock.send.mockResolvedValue({
    ok: true,
    status: 200,
    statusText: "OK",
    duration: 5,
    size: 2,
    responseHeaders: {},
    responseBody: "{}",
    setCookies: ["sid=a; Secure; Path=/"],
  });
});
let identity: ReturnType<NonNullable<ReturnType<typeof useAuthProfiles>>["createSession"]>;
function Consumer() {
  const auth = useAuthProfiles()!;
  return (
    <>
      <ProfileSelector />
      <button
        disabled={!auth.ready}
        onClick={() => {
          identity = auth.createSession(undefined, { token: "shared", shared: "keep" });
        }}
      >
        Snapshot
      </button>
      <button
        onClick={() => identity.receive("https://api.example.com/login", ["sid=a; Secure; Path=/"])}
      >
        Receive
      </button>
      <button onClick={() => void identity.commit({ token: "new-a" })}>Commit token</button>
      <pre data-testid="profiles">{JSON.stringify(auth.document)}</pre>
      {auth.error && <p role="alert">{auth.error}</p>}
      <button onClick={auth.retry}>Retry</button>
    </>
  );
}
it("isolates login cookies and script token updates by profile", async () => {
  render(
    <AuthProfilesProvider>
      <Consumer />
    </AuthProfilesProvider>,
  );
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "Snapshot" }) as HTMLButtonElement).disabled).toBe(
      false,
    ),
  );
  fireEvent.click(screen.getByText("Snapshot"));
  expect(identity.variables).toEqual({ token: "a", shared: "keep" });
  fireEvent.click(screen.getByText("Receive"));
  fireEvent.click(screen.getByText("Commit token"));
  await waitFor(() => expect(mock.save).toHaveBeenCalled());
  const doc = JSON.parse(screen.getByTestId("profiles").textContent!);
  expect(doc.profiles[0].variables.token).toBe("new-a");
  expect(doc.profiles[0].cookies[0].value).toBe("a");
  expect(doc.profiles[1].variables.token).toBe("b");
  expect(doc.profiles[1].cookies).toEqual([]);
  fireEvent.change(screen.getByLabelText("Authentication profile"), { target: { value: "b" } });
  fireEvent.click(screen.getByText("Snapshot"));
  expect(
    identity.resolve(
      {
        method: "GET",
        url: "https://api.example.com/account",
        headers: { Authorization: "Bearer {{missing_user_a}}", Cookie: "sid=old" },
        body: "",
      },
      identity.variables,
    ).headers,
  ).toEqual({ Authorization: "Bearer b" });
});
it("blocks late credentials and cookies after a workspace switch", async () => {
  const view = render(
    <AuthProfilesProvider>
      <Consumer />
    </AuthProfilesProvider>,
  );
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "Snapshot" }) as HTMLButtonElement).disabled).toBe(
      false,
    ),
  );
  fireEvent.click(screen.getByText("Snapshot"));
  const old = identity;
  mock.workspace = "w2";
  view.rerender(
    <AuthProfilesProvider>
      <Consumer />
    </AuthProfilesProvider>,
  );
  await act(async () => {
    old.receive("https://api.example.com/login", ["sid=late; Secure; Path=/"]);
    await expect(old.commit({ token: "late" })).rejects.toThrow("Workspace changed");
  });
  await waitFor(() => expect(mock.fetch).toHaveBeenCalledWith("w2"));
  expect(screen.getByTestId("profiles").textContent).not.toContain("late");
});
it("surfaces save conflicts and does not overwrite another browser on retry", async () => {
  mock.save.mockRejectedValue(
    new Error("Profiles changed in another browser. Reload profiles before saving."),
  );
  render(
    <AuthProfilesProvider>
      <Consumer />
    </AuthProfilesProvider>,
  );
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "Snapshot" }) as HTMLButtonElement).disabled).toBe(
      false,
    ),
  );
  fireEvent.change(screen.getByLabelText("Authentication profile"), { target: { value: "b" } });
  await screen.findByRole("alert");
  const count = mock.save.mock.calls.length;
  fireEvent.click(screen.getByText("Retry"));
  await act(async () => {
    await Promise.resolve();
  });
  expect(mock.save).toHaveBeenCalledTimes(count);
});
function FlowConsumer() {
  const auth = useAuthProfiles()!,
    flows = useFlows();
  return (
    <>
      <button
        disabled={!auth.ready || !flows.ready}
        onClick={() =>
          flows.start({
            ...newFlow(),
            steps: [
              newFlowStep(
                { method: "POST", url: "https://api.example.com/login", headers: {}, body: "" },
                "Login",
              ),
              newFlowStep(
                { method: "GET", url: "https://api.example.com/account", headers: {}, body: "" },
                "Account",
              ),
            ],
          })
        }
      >
        Run login flow
      </button>
      <pre data-testid="flow">{JSON.stringify(flows.activeRun)}</pre>
    </>
  );
}
it("reuses login cookies in subsequent Flow steps without crossing account jars", async () => {
  render(
    <AuthProfilesProvider>
      <FlowsProvider>
        <FlowConsumer />
      </FlowsProvider>
    </AuthProfilesProvider>,
  );
  await waitFor(() =>
    expect(
      (screen.getByRole("button", { name: "Run login flow" }) as HTMLButtonElement).disabled,
    ).toBe(false),
  );
  fireEvent.click(screen.getByText("Run login flow"));
  await waitFor(() => expect(mock.send).toHaveBeenCalledTimes(2));
  expect(mock.send.mock.calls[0]![0].data.headers).toEqual({ Authorization: "Bearer a" });
  expect(mock.send.mock.calls[1]![0].data.headers).toEqual({
    Authorization: "Bearer a",
    Cookie: "sid=a",
  });
  await waitFor(() =>
    expect(JSON.parse(screen.getByTestId("flow").textContent!).status).toBe("passed"),
  );
});
it("selects requests and profiles in Matrix and stores evidence", async () => {
  render(
    <AuthProfilesProvider>
      <MatrixProvider>
        <MatrixView />
      </MatrixProvider>
    </AuthProfilesProvider>,
  );
  await screen.findByText("User A");
  fireEvent.click(screen.getByLabelText("User A"));
  fireEvent.click(screen.getByLabelText("User B"));
  fireEvent.click(screen.getByLabelText(/Account · GET/));
  fireEvent.change(screen.getByLabelText("Matrix baseline"), { target: { value: "a" } });
  fireEvent.click(screen.getByRole("button", { name: "Run matrix (2 requests)" }));
  await waitFor(() => expect(mock.send).toHaveBeenCalledTimes(2));
  expect(mock.send.mock.calls[0]![0].data.headers.Authorization).toBe("Bearer a");
  expect(mock.send.mock.calls[1]![0].data.headers.Authorization).toBe("Bearer b");
  await waitFor(() => expect(mock.matrixSave).toHaveBeenCalled());
  expect(mock.matrixSave.mock.calls[0]![1].results).toHaveLength(2);
});
it("edits and saves profile origins and headers from the UI", async () => {
  render(
    <AuthProfilesProvider>
      <ProfilesView />
    </AuthProfilesProvider>,
  );
  await screen.findByLabelText("Profile name");
  fireEvent.change(screen.getByLabelText("Profile name"), { target: { value: "Tester A" } });
  fireEvent.change(screen.getByLabelText("Profile allowed origins"), {
    target: { value: "https://api.example.com\n" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply profile" }));
  await waitFor(() => expect(mock.save).toHaveBeenCalled());
  const doc = mock.save.mock.calls.at(-1)![2];
  expect(doc.profiles[0].name).toBe("Tester A");
  expect(doc.profiles[0].origins).toEqual(["https://api.example.com"]);
});
