import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ToolsView } from "@/components/tools";

describe("Tools", () => {
  it("round trips Unicode through Base64", () => {
    render(<ToolsView />);
    fireEvent.change(screen.getByLabelText("Input"), { target: { value: "Xin chào" } });
    fireEvent.click(screen.getByRole("button", { name: "Encode" }));
    expect(screen.getByLabelText("Output")).toHaveValue("WGluIGNow6Bv");
    fireEvent.click(screen.getByRole("button", { name: "Swap" }));
    fireEvent.click(screen.getByRole("button", { name: "Decode" }));
    expect(screen.getByLabelText("Output")).toHaveValue("Xin chào");
  });
  it("generates distinct UUIDs in a batch", () => {
    render(<ToolsView />);
    fireEvent.click(screen.getByRole("tab", { name: "UUID generator" }));
    fireEvent.change(screen.getByLabelText("UUID count"), { target: { value: "3" } });
    fireEvent.click(screen.getByRole("button", { name: "Generate UUIDs" }));
    const ids = (screen.getByLabelText("Generated UUIDs") as HTMLTextAreaElement).value.split("\n");
    expect(new Set(ids).size).toBe(3);
    for (const id of ids)
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
  it("decodes without a key and clears stale output for invalid input", async () => {
    render(<ToolsView />);
    fireEvent.click(screen.getByRole("tab", { name: "JWT" }));
    fireEvent.change(screen.getByLabelText("JWT token"), {
      target: { value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Decode JWT" }));
    await waitFor(() =>
      expect((screen.getByLabelText("JWT output") as HTMLTextAreaElement).value).toContain(
        '"sub": "123"',
      ),
    );
    expect(screen.getByRole("status")).toHaveTextContent("not been verified");
    fireEvent.change(screen.getByLabelText("JWT token"), { target: { value: "bad" } });
    fireEvent.click(screen.getByRole("button", { name: "Decode JWT" }));
    await waitFor(() =>
      expect(screen.getByRole("status")).toHaveTextContent("3 dot-separated parts"),
    );
    expect(screen.getByLabelText("JWT output")).toHaveValue("");
  });
});
