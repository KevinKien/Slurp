import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Workspace } from "@/lib/api";
import { WorkspaceGate } from "@/components/workspace-gate";

const ws = (id: string, name: string, request_count = 0): Workspace => ({
  id,
  name,
  request_count,
  active: false,
  created_at: "2026-10-15T00:00:00Z",
});

const setup = (over: Partial<React.ComponentProps<typeof WorkspaceGate>> = {}) => {
  const props = {
    workspaces: [ws("default", "Default", 3), ws("w1", "Staging", 12)],
    onChoose: vi.fn().mockResolvedValue(undefined),
    onCreate: vi.fn().mockResolvedValue(undefined),
    onTemporary: vi.fn().mockResolvedValue(undefined),
    ...over,
  };
  render(<WorkspaceGate {...props} />);
  return props;
};

describe("WorkspaceGate", () => {
  afterEach(cleanup);

  it("is a modal that explains the choice, lists workspaces with their sizes", () => {
    setup();
    const dialog = screen.getByRole("dialog", { name: /choose a workspace/i });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(screen.getByRole("button", { name: /staging/i })).toHaveTextContent("12 requests");
    expect(screen.getByRole("button", { name: /default/i })).toHaveTextContent("3 requests");
  });

  it("chooses an existing workspace", async () => {
    const p = setup();
    fireEvent.click(screen.getByRole("button", { name: /staging/i }));
    await waitFor(() => expect(p.onChoose).toHaveBeenCalledWith("w1"));
  });

  it("creates a workspace from a typed name and ignores blank names", async () => {
    const p = setup();
    const create = screen.getByRole("button", { name: /create and start/i });
    expect(create).toBeDisabled();
    fireEvent.change(screen.getByLabelText("New workspace name"), { target: { value: "  Login flow " } });
    expect(create).toBeEnabled();
    fireEvent.click(create);
    await waitFor(() => expect(p.onCreate).toHaveBeenCalledWith("  Login flow "));
  });

  it("warns that continuing without a workspace saves nothing", async () => {
    const p = setup();
    expect(screen.getByText(/nothing is saved/i)).toBeInTheDocument();
    expect(screen.getByText(/lost when you close the tool/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /continue without a workspace/i }));
    await waitFor(() => expect(p.onTemporary).toHaveBeenCalledTimes(1));
  });

  it("stays open and re-enables the buttons when an action fails", async () => {
    const p = setup({ onChoose: vi.fn().mockRejectedValue(new Error("boom")) });
    fireEvent.click(screen.getByRole("button", { name: /staging/i }));
    await waitFor(() => expect(p.onChoose).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByRole("button", { name: /staging/i })).toBeEnabled());
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("prevents double submission while an action is running", async () => {
    let finish: () => void = () => {};
    const p = setup({ onChoose: vi.fn(() => new Promise<void>((r) => (finish = r))) });
    const staging = screen.getByRole("button", { name: /staging/i });
    fireEvent.click(staging);
    await waitFor(() => expect(staging).toBeDisabled());
    fireEvent.click(staging);
    expect(p.onChoose).toHaveBeenCalledTimes(1);
    finish();
    await waitFor(() => expect(staging).toBeEnabled());
  });
});
