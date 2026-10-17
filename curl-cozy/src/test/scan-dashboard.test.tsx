import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { ScanDashboard } from "../components/scan-dashboard";
import { newScanPlan, type Finding, type ScanRun } from "../lib/scan";
const mock = vi.hoisted(() => ({
  state: {} as any,
  fetch: vi.fn(),
  pause: vi.fn(),
  resume: vi.fn(),
  stop: vi.fn(),
}));
vi.mock("../lib/scan-context", () => ({ useScan: () => mock.state }));
vi.mock("../lib/scan-api", () => ({
  fetchScanFindings: (...args: unknown[]) => mock.fetch(...args),
}));
const finding: Finding = {
  id: "f1",
  fingerprint: "fp",
  checkId: "reflection",
  title: "Input reflected in response",
  severity: "info",
  confidence: "high",
  status: "verified",
  evidenceIds: ["e1"],
  summary: "Two markers reflected",
  verification: { method: "two probes", outcome: "confirmed", reason: "Matched both markers" },
  excerpts: [],
  remediation: "Review output context",
};
const run: ScanRun = {
  version: 1,
  id: "run1",
  startedAt: "2026-10-16T00:00:00Z",
  status: "running",
  message: "",
  plan: newScanPlan({ method: "GET", url: "https://example.com/items", headers: {}, body: "" }),
  sent: 2,
  bytes: 0,
  baselineStable: true,
  baselineIds: [],
  findings: [finding],
  evidence: [],
  checks: [],
};
beforeEach(() => {
  vi.clearAllMocks();
  mock.state = {
    workspace: null,
    localRuns: [run],
    run,
    busy: true,
    error: "",
    pause: mock.pause,
    resume: mock.resume,
    stop: mock.stop,
  };
  mock.fetch.mockResolvedValue({ data: [], total: 0, has_more: false });
});
it("shows live tasks and findings and controls the active task", () => {
  const onSelect = vi.fn();
  render(
    <ScanDashboard
      tasks={[run]}
      offset={0}
      more={false}
      onPage={vi.fn()}
      onRefresh={vi.fn()}
      onSelect={onSelect}
    />,
  );
  expect(screen.getByText("running")).toBeInTheDocument();
  expect(screen.getByText(finding.title)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Pause" }));
  expect(mock.pause).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole("button", { name: "Stop" }));
  expect(mock.stop).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole("button", { name: "View finding f1" }));
  expect(onSelect).toHaveBeenCalledWith("run1", "f1");
  fireEvent.change(screen.getByLabelText("Dashboard finding status"), {
    target: { value: "suspected" },
  });
  expect(screen.queryByText(finding.title)).not.toBeInTheDocument();
});
it("loads saved findings without loading full run evidence and resets on workspace switch", async () => {
  mock.state = { ...mock.state, workspace: "w1", localRuns: [], run: null, busy: false };
  mock.fetch.mockResolvedValue({
    data: [
      {
        runId: "saved",
        startedAt: run.startedAt,
        url: run.plan.request.url,
        method: "GET",
        finding,
      },
    ],
    total: 1,
    has_more: false,
  });
  const select = vi.fn(),
    props = {
      tasks: [],
      offset: 0,
      more: false,
      onPage: vi.fn(),
      onRefresh: vi.fn(),
      onSelect: select,
    };
  const view = render(<ScanDashboard {...props} />);
  await waitFor(() => expect(screen.getByText(finding.title)).toBeInTheDocument());
  expect(mock.fetch).toHaveBeenCalledWith("w1", 0, "", "", "");
  fireEvent.click(screen.getByRole("button", { name: "View finding f1" }));
  expect(select).toHaveBeenCalledWith("saved", "f1");
  mock.fetch.mockResolvedValue({ data: [], total: 0, has_more: false });
  mock.state = { ...mock.state, workspace: "w2" };
  view.rerender(<ScanDashboard {...props} />);
  await waitFor(() => expect(screen.queryByText(finding.title)).not.toBeInTheDocument());
  await waitFor(() => expect(mock.fetch).toHaveBeenCalledWith("w2", 0, "", "", ""));
});
it("shows saved finding load failures with a retry action", async () => {
  mock.state = { ...mock.state, workspace: "w1", localRuns: [], run: null, busy: false };
  mock.fetch.mockRejectedValueOnce(Error("backend unavailable"));
  render(
    <ScanDashboard
      tasks={[]}
      offset={0}
      more={false}
      onPage={vi.fn()}
      onRefresh={vi.fn()}
      onSelect={vi.fn()}
    />,
  );
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("backend unavailable"));
  mock.fetch.mockResolvedValue({ data: [], total: 0, has_more: false });
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
});
