import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { AutomaticAudit } from "../components/automatic-audit";
const api = vi.hoisted(() => ({ fetch: vi.fn(), set: vi.fn() }));
vi.mock("../lib/scan-api", () => ({ fetchAutomaticAudit: api.fetch, setAutomaticAudit: api.set }));
const status = { enabled: true, active: 1, queued: 2, completed: 3, skipped: 0, errors: 0 };
beforeEach(() => { vi.clearAllMocks(); api.fetch.mockResolvedValue(status); });
it("loads backend status and pauses scheduling", async () => {
  api.set.mockResolvedValue({ ...status, enabled: false });
  render(<AutomaticAudit />);
  fireEvent.click(await screen.findByRole("button", { name: "Pause automatic audit" }));
  await waitFor(() => expect(api.set).toHaveBeenCalledWith(false));
  expect(await screen.findByRole("button", { name: "Resume automatic audit" })).toBeEnabled();
  expect(screen.getByRole("status")).toHaveTextContent("Paused");
});
it("surfaces control failures without claiming success", async () => {
  api.set.mockRejectedValue(Error("permission denied"));
  render(<AutomaticAudit />);
  fireEvent.click(await screen.findByRole("button", { name: "Pause automatic audit" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("permission denied");
  expect(screen.getByRole("status")).toHaveTextContent("Enabled");
});
