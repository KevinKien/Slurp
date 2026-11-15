import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { act } from "react";
import { beforeEach, expect, it, vi } from "vitest";
import { GraphqlView } from "@/components/graphql";
import { setGraphqlSeed } from "@/lib/graphql/request";
import { sendHttpRequest } from "@/lib/replay.functions";
import { introspection } from "./fixtures/graphql-introspection";

const navigate = vi.fn();
const setSessions = vi.fn();
const setActive = vi.fn();
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => navigate }));
vi.mock("@/components/inspector", () => ({
  useInspector: () => ({ sessions: [{ id: 3 }], setSessions, setActive }),
}));
vi.mock("@/lib/replay.functions", () => ({ sendHttpRequest: vi.fn() }));

const ok = (body: unknown) => ({
  ok: true as const,
  status: 200,
  statusText: "OK",
  duration: 12,
  size: 99,
  responseHeaders: { "content-type": "application/json" },
  setCookies: [],
  responseBody: typeof body === "string" ? body : JSON.stringify(body),
});
const send = vi.mocked(sendHttpRequest);

async function loadSchema() {
  send.mockResolvedValueOnce(ok(introspection));
  fireEvent.change(screen.getByLabelText("GraphQL endpoint"), {
    target: { value: "https://api.example.com/graphql" },
  });
  fireEvent.click(screen.getByRole("button", { name: /Load schema/ }));
  await screen.findByLabelText("Schema explorer");
}

beforeEach(() => {
  sessionStorage.clear();
  send.mockReset();
  navigate.mockReset();
  setSessions.mockReset();
  setActive.mockReset();
});

it("loads a schema through introspection and lists its operations", async () => {
  render(<GraphqlView />);
  await loadSchema();
  const body = JSON.parse(send.mock.calls[0]![0].data.body);
  expect(body.query).toContain("__schema");
  expect(body.operationName).toBe("IntrospectionQuery");
  expect(send.mock.calls[0]![0].data.url).toBe("https://api.example.com/graphql");
  expect(screen.getByText(/types · 4 queries · 1 mutations/)).toBeTruthy();
  for (const name of ["user", "users", "search"])
    expect(screen.getByText(name, { selector: "span.font-mono" })).toBeTruthy();
});

it("turns a field into an operation, sends it and shows GraphQL errors", async () => {
  render(<GraphqlView />);
  await loadSchema();
  const row = document.querySelector('[data-field="user"]') as HTMLElement;
  fireEvent.click(within(row).getByRole("button", { name: "Use" }));
  expect((screen.getByLabelText("GraphQL query") as HTMLTextAreaElement).value).toContain(
    "query User($id: ID!) {",
  );
  fireEvent.click(screen.getByRole("tab", { name: "variables" }));
  expect((screen.getByLabelText("GraphQL variables") as HTMLTextAreaElement).value).toBe(
    '{\n  "id": ""\n}',
  );
  fireEvent.change(screen.getByLabelText("GraphQL variables"), { target: { value: '{"id":"7"}' } });
  send.mockResolvedValueOnce(ok({ data: null, errors: [{ message: "User not found" }] }));
  fireEvent.click(screen.getByRole("button", { name: /^Send$/ }));
  await screen.findByText("User not found");
  const request = send.mock.calls[1]![0].data;
  expect(request.method).toBe("POST");
  expect(JSON.parse(request.body)).toMatchObject({ operationName: "User", variables: { id: "7" } });
  expect(request.headers["Content-Type"]).toBe("application/json");
  expect(screen.getByLabelText("GraphQL response").textContent).toContain('"data": null');
});

it("sends headers entered by the user and rejects invalid ones before sending", async () => {
  render(<GraphqlView />);
  fireEvent.change(screen.getByLabelText("GraphQL endpoint"), {
    target: { value: "https://api.example.com/graphql" },
  });
  fireEvent.change(screen.getByLabelText("GraphQL query"), { target: { value: "{ me { id } }" } });
  fireEvent.click(screen.getByRole("tab", { name: "headers" }));
  fireEvent.change(screen.getByLabelText("GraphQL headers"), {
    target: { value: "this is not a header" },
  });
  fireEvent.click(screen.getByRole("button", { name: /^Send$/ }));
  await waitFor(() => expect(send).not.toHaveBeenCalled());
  send.mockResolvedValueOnce(ok({ data: { me: null } }));
  fireEvent.change(screen.getByLabelText("GraphQL headers"), {
    target: { value: "Authorization: Bearer abc" },
  });
  fireEvent.click(screen.getByRole("button", { name: /^Send$/ }));
  await waitFor(() => expect(send).toHaveBeenCalledTimes(1));
  expect(send.mock.calls[0]![0].data.headers["Authorization"]).toBe("Bearer abc");
});

it("searches the schema and opens a type", async () => {
  render(<GraphqlView />);
  await loadSchema();
  fireEvent.change(screen.getByLabelText("Search schema"), { target: { value: "token" } });
  fireEvent.click(await screen.findByText("User.secret"));
  expect(screen.getByText("secret")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /Back/ }));
  expect(screen.getByRole("tab", { name: "querys" })).toBeTruthy();
});

it("explains a disabled introspection and keeps the editor usable", async () => {
  render(<GraphqlView />);
  send.mockResolvedValueOnce(ok({ errors: [{ message: "GraphQL introspection is not allowed" }] }));
  fireEvent.change(screen.getByLabelText("GraphQL endpoint"), {
    target: { value: "https://api.example.com/graphql" },
  });
  fireEvent.click(screen.getByRole("button", { name: /Load schema/ }));
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toMatch(/not allowed.*import a schema JSON/);
  expect(screen.getByLabelText("GraphQL query")).toBeTruthy();
});

it("opens a request from History, including one that arrives after the page opened", async () => {
  setGraphqlSeed({
    method: "POST",
    url: "https://api.example.com/graphql",
    headers: { Authorization: "Bearer t", "Content-Type": "application/json" },
    body: JSON.stringify({ query: "query Me { me { id } }", variables: { a: 1 } }),
  });
  render(<GraphqlView />);
  expect((screen.getByLabelText("GraphQL endpoint") as HTMLInputElement).value).toBe(
    "https://api.example.com/graphql",
  );
  expect((screen.getByLabelText("GraphQL query") as HTMLTextAreaElement).value).toBe(
    "query Me { me { id } }",
  );
  act(() =>
    setGraphqlSeed({
      method: "POST",
      url: "https://other.example.com/gql",
      headers: {},
      body: JSON.stringify({ query: "{ late }" }),
    }),
  );
  await waitFor(() =>
    expect((screen.getByLabelText("GraphQL endpoint") as HTMLInputElement).value).toBe(
      "https://other.example.com/gql",
    ),
  );
  expect((screen.getByLabelText("GraphQL query") as HTMLTextAreaElement).value).toBe("{ late }");
});

it("sends the operation to Replay as a new tab", async () => {
  render(<GraphqlView />);
  fireEvent.change(screen.getByLabelText("GraphQL endpoint"), {
    target: { value: "https://api.example.com/graphql" },
  });
  fireEvent.change(screen.getByLabelText("GraphQL query"), {
    target: { value: "query Me { me { id } }" },
  });
  fireEvent.click(screen.getByRole("button", { name: /Send to Replay/ }));
  expect(setSessions).toHaveBeenCalledTimes(1);
  const updater = setSessions.mock.calls[0]![0] as (
    previous: { id: number }[],
  ) => { id: number; request: { url: string; body: string } }[];
  const tabs = updater([{ id: 3 }]);
  expect(tabs[0]).toEqual({ id: 3 });
  expect(tabs[1]).toMatchObject({ request: { url: "https://api.example.com/graphql" } });
  expect(JSON.parse(tabs[1]!.request.body).operationName).toBe("Me");
  expect(setActive).toHaveBeenCalledWith(tabs[1]!.id);
  expect(navigate).toHaveBeenCalledWith({ to: "/replay" });
});
