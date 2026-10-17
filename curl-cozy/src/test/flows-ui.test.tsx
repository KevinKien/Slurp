import { useState } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { newFlowStep, type FlowDocument } from "../lib/flows";
const mock = vi.hoisted(() => ({
  workspace: "w1" as string | null,
  send: vi.fn(),
  fetchFlows: vi.fn(),
  saveFlows: vi.fn(),
  saveFlowRun: vi.fn(),
  fetchFlowRuns: vi.fn(),
  fetchFlowRun: vi.fn(),
  script: vi.fn(),
  variables: { shared: "unchanged" },
}));
vi.mock("@/components/inspector", () => ({
  useInspector: () => ({
    session: mock.workspace
      ? { target: "workspace", workspace_id: mock.workspace }
      : { target: "temporary", workspace_id: null },
    timeout: 15000,
    getReplayWorkspace: () => mock.workspace,
    variables: mock.variables,
    sessions: [
      {
        id: 7,
        name: "Replay login",
        request: { method: "POST", url: "https://example.com/login", headers: {}, body: "{}" },
        afterResponse: "console.log(response.status)",
      },
    ],
  }),
}));
vi.mock("@/lib/replay.functions", () => ({ sendHttpRequest: mock.send }));
vi.mock("@/lib/replay-script", () => ({ runReplayScript: mock.script }));
vi.mock("@/lib/flows-api", () => ({
  fetchFlows: mock.fetchFlows,
  saveFlows: mock.saveFlows,
  saveFlowRun: mock.saveFlowRun,
  fetchFlowRuns: mock.fetchFlowRuns,
  fetchFlowRun: mock.fetchFlowRun,
}));
import { FlowsProvider } from "../components/flows-provider";
import { FlowsView } from "../components/flows";
const response = (body: unknown) => ({
  ok: true,
  status: 200,
  statusText: "OK",
  duration: 5,
  size: 2,
  responseHeaders: {},
  responseBody: JSON.stringify(body),
});
const doc = (): FlowDocument => ({
  active: "flow-1",
  flows: [
    {
      id: "flow-1",
      name: "Login and OTP",
      variables: {},
      steps: [
        {
          ...newFlowStep(
            { method: "POST", url: "https://example.com/login", headers: {}, body: "" },
            "Login",
          ),
          extractors: [{ variable: "challenge", source: "json", path: "challenge" }],
        },
        {
          ...newFlowStep(
            {
              method: "POST",
              url: "https://example.com/2fa",
              headers: {},
              body: '{"challenge":"{{challenge}}","otp":"{{otp}}"}',
            },
            "2FA",
          ),
          pauseBefore: true,
          pauseMessage: "Enter OTP to continue.",
        },
      ],
    },
  ],
});
function App() {
  const [show, setShow] = useState(true);
  return (
    <FlowsProvider>
      <button onClick={() => setShow((v) => !v)}>Navigate</button>
      {show ? <FlowsView /> : <p>Other page</p>}
    </FlowsProvider>
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  mock.workspace = "w1";
  mock.fetchFlows.mockImplementation(async () => structuredClone(doc()));
  mock.saveFlows.mockResolvedValue(undefined);
  mock.saveFlowRun.mockResolvedValue(undefined);
  mock.fetchFlowRuns.mockResolvedValue({ data: [], has_more: false });
  mock.script.mockResolvedValue({ logs: [], updates: {} });
  mock.send
    .mockResolvedValueOnce(response({ challenge: "challenge-a" }))
    .mockResolvedValue(response({ verified: true }));
});
afterEach(cleanup);
describe("Flows UI and root execution state", () => {
  it("runs login, pauses for OTP, survives navigation and continues with isolated variables", async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByLabelText("Flow name")).toHaveValue("Login and OTP"));
    fireEvent.click(screen.getByRole("button", { name: "Run flow" }));
    await screen.findByRole("heading", { name: /Paused before step 2/ });
    expect(mock.send).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Navigate" }));
    expect(screen.getByText("Other page")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Navigate" }));
    fireEvent.click(screen.getByRole("button", { name: "Runs & comparison" }));
    await screen.findByRole("heading", { name: /Paused before step 2/ });
    fireEvent.click(screen.getByRole("button", { name: "Add variable" }));
    fireEvent.change(screen.getByLabelText("Run variable name 2"), { target: { value: "otp" } });
    fireEvent.change(screen.getByLabelText("Run variable value 2"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continue run" }));
    await waitFor(() => expect(mock.send).toHaveBeenCalledTimes(2));
    expect(mock.send.mock.calls[1]![0].data.body).toBe(
      '{"challenge":"challenge-a","otp":"123456"}',
    );
    await waitFor(() =>
      expect(mock.saveFlowRun).toHaveBeenCalledWith(
        "w1",
        expect.objectContaining({
          status: "passed",
          variables: { challenge: "challenge-a", otp: "123456" },
          results: expect.arrayContaining([
            expect.objectContaining({ name: "2FA", status: "passed" }),
          ]),
        }),
      ),
    );
    expect(mock.variables).toEqual({ shared: "unchanged" });
  });
  it("copies a Replay tab into a flow and persists request plus script without sending", async () => {
    mock.fetchFlows.mockResolvedValue({
      active: "flow-1",
      flows: [{ ...doc().flows[0], steps: [] }],
    });
    render(<App />);
    await waitFor(() => expect(screen.getByLabelText("Flow name")).toHaveValue("Login and OTP"));
    fireEvent.change(screen.getByLabelText("Replay tab to add"), { target: { value: "7" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByLabelText("Flow request URL")).toHaveValue(
      "https://example.com/login",
    );
    await waitFor(() =>
      expect(mock.saveFlows).toHaveBeenCalledWith(
        "w1",
        expect.objectContaining({
          flows: [
            expect.objectContaining({
              steps: [
                expect.objectContaining({
                  name: "Replay login",
                  afterResponse: "console.log(response.status)",
                }),
              ],
            }),
          ],
        }),
      ),
    );
    expect(mock.send).not.toHaveBeenCalled();
  });
  it("stops on workspace switches and saves the late response only to the originating workspace", async () => {
    let finish!: (result: unknown) => void;
    mock.send.mockReset();
    mock.send.mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const view = render(<App />);
    await waitFor(() => expect(screen.getByLabelText("Flow name")).toHaveValue("Login and OTP"));
    fireEvent.click(screen.getByRole("button", { name: "Run flow" }));
    await waitFor(() => expect(mock.send).toHaveBeenCalledTimes(1));
    mock.workspace = "w2";
    view.rerender(<App />);
    await act(async () => finish(response({ challenge: "old-workspace" })));
    await waitFor(() =>
      expect(mock.saveFlowRun).toHaveBeenCalledWith(
        "w1",
        expect.objectContaining({
          status: "stopped",
          variables: {},
          results: [
            expect.objectContaining({ response: expect.objectContaining({ status: 200 }) }),
          ],
        }),
      ),
    );
    expect(mock.send).toHaveBeenCalledTimes(1);
    expect(
      mock.saveFlowRun.mock.calls.some(
        ([workspace, run]) => workspace === "w2" && run.variables["challenge"] === "old-workspace",
      ),
    ).toBe(false);
  });
  it("does not send any requests while viewing stored history", async () => {
    const saved = {
      id: "old-run",
      flow: doc().flows[0],
      startedAt: "2026-10-16T00:00:00Z",
      duration: 10,
      status: "passed",
      initialVariables: {},
      variables: { token: "stored" },
      results: [],
      startIndex: 0,
      nextIndex: 2,
      endIndex: 2,
      sendingIndex: null,
      message: "Finished",
    };
    mock.fetchFlowRuns.mockResolvedValue({
      data: [
        {
          id: "old-run",
          flowId: "flow-1",
          name: "Old run",
          startedAt: saved.startedAt,
          duration: 10,
          status: "passed",
          steps: 2,
        },
      ],
      has_more: false,
    });
    mock.fetchFlowRun.mockResolvedValue(saved);
    render(<App />);
    await waitFor(() => expect(screen.getByLabelText("Flow name")).toHaveValue("Login and OTP"));
    fireEvent.click(screen.getByRole("button", { name: "Runs & comparison" }));
    await screen.findByRole("option", { name: /Old run/ });
    fireEvent.change(screen.getByLabelText("Flow run"), { target: { value: "old-run" } });
    await screen.findByText("Finished");
    expect(mock.send).not.toHaveBeenCalled();
    expect(mock.script).not.toHaveBeenCalled();
  });
  it("shows a failed load and retries without silently replacing workspace flows", async () => {
    mock.fetchFlows.mockRejectedValueOnce(Error("Backend not available"));
    render(<App />);
    await screen.findByText("Backend not available");
    expect(screen.getByRole("button", { name: "New flow" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Retry flow storage" }));
    await waitFor(() => expect(screen.getByLabelText("Flow name")).toHaveValue("Login and OTP"));
    expect(mock.saveFlows).not.toHaveBeenCalled();
  });
});

describe("Flow editing and stored run comparison", () => {
  it("creates a flow, applies step settings and saves them without sending", async () => {
    mock.fetchFlows.mockResolvedValue({ flows: [], active: null });
    render(<App />);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "New flow" })).not.toBeDisabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "New flow" }));
    fireEvent.click(screen.getByRole("button", { name: "Add step" }));
    fireEvent.change(screen.getByLabelText("Flow request URL"), {
      target: { value: "https://example.com/login" },
    });
    fireEvent.click(screen.getByLabelText("Pause before step"));
    fireEvent.change(screen.getByLabelText("Pause instructions"), {
      target: { value: "Enter OTP" },
    });
    fireEvent.change(screen.getByLabelText("Expected HTTP status"), {
      target: { value: "200,201" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add extractor" }));
    fireEvent.change(screen.getByLabelText("Extract path 1"), { target: { value: "data.token" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply step changes" }));
    await waitFor(
      () =>
        expect(mock.saveFlows).toHaveBeenCalledWith(
          "w1",
          expect.objectContaining({
            flows: [
              expect.objectContaining({
                steps: [
                  expect.objectContaining({
                    pauseBefore: true,
                    pauseMessage: "Enter OTP",
                    expectedStatus: "200,201",
                    extractors: [{ variable: "token", source: "json", path: "data.token" }],
                  }),
                ],
              }),
            ],
          }),
        ),
      { timeout: 3000 },
    );
    expect(mock.send).not.toHaveBeenCalled();
  });
  it("compares stored request and response snapshots without executing either run", async () => {
    const flow = doc().flows[0]!,
      request = { method: "GET", url: "https://example.com/a", headers: {}, body: "" };
    const result = {
      stepId: flow.steps[0]!.id,
      index: 0,
      name: "Login",
      status: "passed",
      checks: [],
      variablesBefore: {},
      variablesAfter: {},
      duration: 5,
      request,
      response: {
        ...request,
        id: 1,
        timestamp: "2026-10-16T00:00:00Z",
        status: 200,
        statusText: "OK",
        duration: 5,
        size: 2,
        responseHeaders: {},
        responseBody: '{"role":"user"}',
      },
    };
    const first = {
      id: "run-a",
      flow,
      startedAt: "2026-10-16T00:00:00Z",
      duration: 10,
      status: "passed",
      initialVariables: {},
      variables: {},
      results: [result],
      startIndex: 0,
      nextIndex: 2,
      endIndex: 2,
      sendingIndex: null,
      message: "Run A ready",
    };
    const second = {
      ...first,
      id: "run-b",
      startedAt: "2026-10-16T00:01:00Z",
      results: [
        {
          ...result,
          request: { ...request, url: "https://example.com/b" },
          response: { ...result.response, responseBody: '{"role":"admin"}' },
        },
      ],
    };
    mock.fetchFlowRun.mockImplementation(async (_workspace, id) =>
      id === "run-a" ? first : second,
    );
    mock.fetchFlowRuns.mockResolvedValue({
      data: [
        {
          id: "run-a",
          flowId: flow.id,
          name: "Run A",
          startedAt: first.startedAt,
          duration: 10,
          status: "passed",
          steps: 1,
        },
        {
          id: "run-b",
          flowId: flow.id,
          name: "Run B",
          startedAt: second.startedAt,
          duration: 10,
          status: "passed",
          steps: 1,
        },
      ],
      has_more: false,
    });
    render(<App />);
    await screen.findByLabelText("Flow name");
    fireEvent.click(screen.getByRole("button", { name: "Runs & comparison" }));
    await screen.findByRole("option", { name: /Run A/ });
    fireEvent.change(screen.getByLabelText("Flow run"), { target: { value: "run-a" } });
    await screen.findByText("Run A ready");
    fireEvent.change(screen.getByLabelText("Compare flow run"), { target: { value: "run-b" } });
    await screen.findByText("Request changed / Response changed");
    expect(mock.send).not.toHaveBeenCalled();
    expect(mock.script).not.toHaveBeenCalled();
  });
  it("keeps failed autosaves retryable without overwriting the working flow", async () => {
    mock.saveFlows.mockRejectedValueOnce(Error("Disk offline"));
    render(<App />);
    await screen.findByLabelText("Flow name");
    fireEvent.change(screen.getByLabelText("Flow name"), { target: { value: "Renamed flow" } });
    fireEvent.click(screen.getByRole("button", { name: "Rename flow" }));
    await screen.findByText(/Flow changes could not be saved: Disk offline/);
    fireEvent.click(screen.getByRole("button", { name: "Retry flow storage" }));
    await waitFor(() => expect(mock.saveFlows).toHaveBeenCalledTimes(2));
    expect(screen.getByLabelText("Flow name")).toHaveValue("Renamed flow");
    expect(mock.send).not.toHaveBeenCalled();
  });
});
