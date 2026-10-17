import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi, afterEach } from "vitest";
import { CodePane } from "@/components/code-pane";

const props = {
  title: "Response",
  body: "First needle\nsecond NEEDLE\nlast needle",
  raw: "HTTP/1.1 200 OK\nX-Needle: yes\n\nneedle",
  headers: { "X-Needle": "yes" },
};
afterEach(() => vi.restoreAllMocks());
function search(value: string) {
  if (!screen.queryByLabelText("Search response"))
    fireEvent.click(screen.getByRole("button", { name: "Toggle response search" }));
  fireEvent.change(screen.getByLabelText("Search response"), { target: { value } });
}
function counter() {
  return screen.getByRole("status", { name: "Response search results" });
}
describe("Response search", () => {
  it("hides search by default and opens and closes it from the icon", () => {
    const { container } = render(<CodePane {...props} />);
    expect(screen.queryByLabelText("Search response")).not.toBeInTheDocument();
    search("needle");
    expect(screen.getByLabelText("Search response")).toHaveFocus();
    fireEvent.click(screen.getByRole("button", { name: "Close response search" }));
    expect(screen.queryByLabelText("Search response")).not.toBeInTheDocument();
    expect(container.querySelectorAll("mark")).toHaveLength(0);
    expect(screen.getByRole("button", { name: "Toggle response search" })).toHaveFocus();
  });
  it("highlights and navigates all matches in a long response", () => {
    const scroll = vi.fn();
    Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
      configurable: true,
      value: scroll,
    });
    const { container } = render(
      <CodePane {...props} body={"padding\n".repeat(1000) + props.body} />,
    );
    search("needle");
    expect(counter()).toHaveTextContent("1/3");
    expect(container.querySelectorAll("mark")).toHaveLength(3);
    expect(scroll).toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Next match" }));
    expect(counter()).toHaveTextContent("2/3");
    expect(container.querySelector('mark[aria-current="true"]')).toHaveTextContent("NEEDLE");
    fireEvent.keyDown(screen.getByLabelText("Search response"), { key: "Enter", shiftKey: true });
    expect(counter()).toHaveTextContent("1/3");
    fireEvent.click(screen.getByRole("button", { name: "Previous match" }));
    expect(counter()).toHaveTextContent("3/3");
  });
  it("supports case sensitivity, literal punctuation and no results", () => {
    render(<CodePane {...props} body="a.b A.B axb" />);
    search("a.b");
    expect(counter()).toHaveTextContent("1/2");
    fireEvent.click(screen.getByRole("button", { name: "Match case" }));
    expect(counter()).toHaveTextContent("1/1");
    search("[missing]");
    expect(counter()).toHaveTextContent("0/0");
    expect(screen.getByRole("button", { name: "Next match" })).toBeDisabled();
    fireEvent.keyDown(screen.getByLabelText("Search response"), { key: "Escape" });
    expect(screen.queryByLabelText("Search response")).not.toBeInTheDocument();
  });
  it("searches Raw and Headers and resets navigation when content changes", () => {
    const { rerender } = render(<CodePane {...props} />);
    search("needle");
    fireEvent.click(screen.getByRole("button", { name: "Next match" }));
    fireEvent.click(screen.getByRole("button", { name: "Raw" }));
    expect(counter()).toHaveTextContent("1/2");
    fireEvent.click(screen.getByRole("button", { name: "Headers" }));
    expect(counter()).toHaveTextContent("1/1");
    fireEvent.click(screen.getByRole("button", { name: "Pretty" }));
    fireEvent.click(screen.getByRole("button", { name: "Next match" }));
    rerender(<CodePane {...props} body="one needle" />);
    expect(counter()).toHaveTextContent("1/1");
  });
  it("focuses search with the pane keyboard shortcut", () => {
    render(<CodePane {...props} />);
    fireEvent.keyDown(screen.getByRole("button", { name: "Wrap Response" }), {
      key: "f",
      ctrlKey: true,
    });
    expect(screen.getByLabelText("Search response")).toHaveFocus();
  });
});

describe("Request search", () => {
  it("opens, finds and navigates request matches", () => {
    render(<CodePane {...props} title="Request" body="GET /api HTTP/1.1\nHost: api.example.com" />);
    expect(screen.queryByLabelText("Search request")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Toggle request search" }));
    fireEvent.change(screen.getByLabelText("Search request"), { target: { value: "api" } });
    expect(screen.getByRole("status", { name: "Request search results" })).toHaveTextContent("1/2");
    fireEvent.click(screen.getByRole("button", { name: "Next match" }));
    expect(screen.getByRole("status", { name: "Request search results" })).toHaveTextContent("2/2");
    fireEvent.click(screen.getByRole("button", { name: "Close request search" }));
    expect(screen.queryByLabelText("Search request")).not.toBeInTheDocument();
  });
});
