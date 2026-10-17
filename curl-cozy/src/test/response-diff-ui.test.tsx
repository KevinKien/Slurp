import { render, screen, fireEvent } from "@testing-library/react";
import { it, expect, vi } from "vitest";
vi.mock("@/components/code-pane", () => ({
  CodePane: ({ title, body }: any) => (
    <section>
      <h3>{title}</h3>
      <pre>{body}</pre>
    </section>
  ),
}));
import { ResponseDiff } from "../components/response-diff";
it("updates comparison when a volatile JSON field is ignored and shows full bodies", () => {
  render(
    <ResponseDiff
      left={{
        status: 200,
        responseHeaders: { Date: "a" },
        responseBody: '{"timestamp":"a","id":1}',
      }}
      right={{
        status: 200,
        responseHeaders: { Date: "b" },
        responseBody: '{"timestamp":"b","id":1}',
      }}
    />,
  );
  expect(screen.getByRole("status").textContent).toContain("Responses differ");
  fireEvent.change(screen.getByLabelText("Ignore JSON paths"), { target: { value: "timestamp" } });
  expect(screen.getByRole("status").textContent).toContain("Responses match");
  fireEvent.click(screen.getByRole("button", { name: "Full normalized bodies" }));
  expect(screen.getByRole("heading", { name: "Baseline" })).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Compared response" })).toBeTruthy();
});
