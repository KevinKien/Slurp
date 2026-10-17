import { it, expect, vi } from "vitest";
import {
  MatrixRunner,
  assessCell,
  type MatrixPlan,
  type MatrixCell,
} from "../lib/authorization-matrix";
import { defaultDiffOptions } from "../lib/response-diff";
import { resolveReplayRequest } from "../lib/replay-features";
const plan = (): MatrixPlan => ({
  requests: [
    {
      id: "req",
      name: "Account",
      request: {
        method: "GET",
        url: "https://api.example.com/account",
        headers: { Authorization: "Bearer original", Cookie: "sid=original", "X-API-Key": "old" },
        body: "",
      },
    },
  ],
  identities: [
    { id: "a", name: "A" },
    { id: "b", name: "B" },
  ],
  baselineId: "a",
  options: defaultDiffOptions,
  expectations: {},
  stripHeaders: ["X-API-Key"],
});
const response = {
  ok: true as const,
  status: 200,
  responseHeaders: {},
  responseBody: '{"id":1}',
  duration: 5,
};
function setup(selection = plan()) {
  let current = true;
  const receiveA = vi.fn(),
    receiveB = vi.fn();
  const session = (token: string, receive: typeof receiveA) => ({
    variables: {},
    resolve: (template: any, variables: any) => ({
      ...resolveReplayRequest(template, variables),
      headers: { Authorization: `Bearer ${token}` },
    }),
    receive,
  });
  const send = vi.fn().mockResolvedValue(response);
  const changed = vi.fn();
  const engine = new MatrixRunner(selection, {
    identities: { a: session("a", receiveA), b: session("b", receiveB) },
    send,
    isCurrent: () => current,
    onChange: changed,
  });
  return {
    engine,
    send,
    receiveA,
    receiveB,
    changed,
    changeWorkspace: () => {
      current = false;
    },
  };
}
it("runs each identity sequentially with independent credentials and immutable request snapshots", async () => {
  const selection = plan(),
    run = setup(selection);
  await run.engine.start();
  expect(run.send).toHaveBeenCalledTimes(2);
  expect(run.send.mock.calls[0]![0].headers).toEqual({ Authorization: "Bearer a" });
  expect(run.send.mock.calls[1]![0].headers).toEqual({ Authorization: "Bearer b" });
  expect(run.engine.run.status).toBe("completed");
  expect(selection.requests[0]!.request.headers["Cookie"]).toBe("sid=original");
  expect(run.receiveA).toHaveBeenCalledOnce();
  expect(run.receiveB).toHaveBeenCalledOnce();
});
it("stops further requests and cookie commits when workspace changes in flight", async () => {
  const run = setup();
  run.send.mockImplementation(async () => {
    run.changeWorkspace();
    return response;
  });
  await run.engine.start();
  expect(run.send).toHaveBeenCalledOnce();
  expect(run.receiveA).not.toHaveBeenCalled();
  expect(run.engine.run.results).toHaveLength(1);
  expect(run.engine.run.status).toBe("stopped");
});
it("stop retains in-flight evidence but sends no further cells", async () => {
  const run = setup();
  run.send.mockImplementation(async () => {
    run.engine.stop();
    return response;
  });
  await run.engine.start();
  expect(run.send).toHaveBeenCalledOnce();
  expect(run.engine.run.results[0]!.response?.status).toBe(200);
  expect(run.receiveA).not.toHaveBeenCalled();
});
it("records errors per cell and continues to the next identity", async () => {
  const run = setup();
  run.send.mockResolvedValueOnce({ ok: false, error: "network failure" });
  await run.engine.start();
  expect(run.engine.run.results[0]!.error).toBe("network failure");
  expect(run.engine.run.results[1]!.response?.status).toBe(200);
});
it("validates the selection and does not run automatically on construction", () => {
  const run = setup();
  expect(run.send).not.toHaveBeenCalled();
  expect(() => setup({ ...plan(), identities: [] })).toThrow();
  expect(() => setup({ ...plan(), baselineId: "missing" })).toThrow("baseline");
});
it("classifies expectations and identical successful bodies as review leads", () => {
  const base: MatrixCell = {
    requestId: "r",
    profileId: "a",
    expectation: "observe",
    duration: 5,
    response: { status: 200, responseHeaders: {}, responseBody: '{"id":1}' },
  };
  expect(assessCell({ ...base, profileId: "b" }, base, defaultDiffOptions).kind).toBe("review");
  expect(assessCell({ ...base, expectation: "deny" }, base, defaultDiffOptions).kind).toBe(
    "review",
  );
  expect(
    assessCell(
      { ...base, expectation: "deny", response: { ...base.response!, status: 403 } },
      base,
      defaultDiffOptions,
    ).kind,
  ).toBe("pass");
  expect(
    assessCell({ ...base, response: { ...base.response!, status: 302 } }, base, defaultDiffOptions)
      .kind,
  ).toBe("inconclusive");
  expect(assessCell({ ...base, error: "network" }, base, defaultDiffOptions).kind).toBe(
    "inconclusive",
  );
});
it("bounds JSON-escaped evidence and never treats truncated bodies as an access match", async () => {
  const run = setup();
  run.send.mockResolvedValue({ ...response, responseBody: "\0".repeat(1_000_000) });
  await run.engine.start();
  expect(run.engine.run.results[0]!.evidenceTruncated).toBe(true);
  expect(
    assessCell(run.engine.run.results[1]!, run.engine.run.results[0], defaultDiffOptions).kind,
  ).toBe("inconclusive");
  expect(new TextEncoder().encode(JSON.stringify(run.engine.run)).length).toBeLessThan(12_000_000);
});
