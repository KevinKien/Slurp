import { describe, it, expect, vi } from "vitest";
import { FlowRunner, type FlowSendResult } from "../lib/flow-runner";
import {
  newFlow,
  newFlowStep,
  readFlowPath,
  validateFlowVariables,
  normalizeFlowDocument,
  type Flow,
  type FlowRun,
} from "../lib/flows";
const response = (body: unknown, status = 200): FlowSendResult => ({
  ok: true,
  status,
  statusText: "OK",
  duration: 5,
  size: 2,
  responseHeaders: { "X-Request-ID": "req-1" },
  responseBody: JSON.stringify(body),
});
const make = (count = 2): Flow => ({
  ...newFlow(),
  name: "Login flow",
  steps: Array.from({ length: count }, (_, i) =>
    newFlowStep(
      { method: "POST", url: `https://example.com/step-${i}`, headers: {}, body: "" },
      `Step ${i + 1}`,
    ),
  ),
});
function setup(flow = make(), send = vi.fn().mockResolvedValue(response({ token: "a" }))) {
  const changes: FlowRun[] = [];
  const script = vi.fn().mockResolvedValue({ logs: [], updates: {} });
  let current = true;
  const engine = new FlowRunner(flow, {
    send,
    script,
    onChange: (run) => changes.push(run),
    isCurrent: () => current,
  });
  return {
    engine,
    send,
    script,
    changes,
    changeWorkspace: () => {
      current = false;
    },
  };
}
describe("Flow runner", () => {
  it("extracts a login token for the next request without modifying definitions or other runs", async () => {
    const flow = make();
    flow.variables = { existing: "keep" };
    flow.steps[0]!.extractors = [{ variable: "token", source: "json", path: "data.access_token" }];
    flow.steps[1]!.request.headers = { Authorization: "Bearer {{token}}" };
    const send = vi
      .fn()
      .mockResolvedValueOnce(response({ data: { access_token: "user-a" } }))
      .mockResolvedValueOnce(response({ done: true }));
    const run = setup(flow, send);
    await run.engine.start();
    expect(send.mock.calls[1]![0].headers).toEqual({ Authorization: "Bearer user-a" });
    expect(run.engine.run.status).toBe("passed");
    expect(flow.variables).toEqual({ existing: "keep" });
    expect(run.engine.run.results[0]!.variablesBefore).toEqual({ existing: "keep" });
    const other = setup(
      flow,
      vi.fn().mockResolvedValue(response({ data: { access_token: "user-b" } })),
    );
    await other.engine.start();
    expect(run.engine.run.variables["token"]).toBe("user-a");
    expect(other.engine.run.variables["token"]).toBe("user-b");
  });
  it("pauses for OTP and sends only after explicitly continuing", async () => {
    const flow = make();
    flow.steps[1]!.pauseBefore = true;
    flow.steps[1]!.request.body = '{"otp":"{{otp}}"}';
    const run = setup(flow);
    await run.engine.start();
    expect(run.send).toHaveBeenCalledTimes(1);
    expect(run.engine.run.status).toBe("paused");
    await run.engine.continue({ otp: "123456" });
    expect(run.send.mock.calls[1]![0].body).toBe('{"otp":"123456"}');
    expect(run.engine.run.status).toBe("passed");
  });
  it("can skip a paused step and automatically skips disabled steps", async () => {
    const flow = make(3);
    flow.steps[0]!.pauseBefore = true;
    flow.steps[1]!.enabled = false;
    const run = setup(flow);
    await run.engine.start();
    await run.engine.skip();
    expect(run.send).toHaveBeenCalledTimes(1);
    expect(run.engine.run.results.map((r) => r.status)).toEqual(["skipped", "skipped", "passed"]);
  });
  it("rolls back extracted and scripted variables when a check fails", async () => {
    const flow = make();
    flow.variables = { token: "old" };
    const first = flow.steps[0]!;
    first.extractors = [{ variable: "token", source: "json", path: "token" }];
    first.assertions = [{ path: "verified", operator: "equals", expected: "true" }];
    first.afterResponse = 'variables.set("x","y")';
    const run = setup(flow, vi.fn().mockResolvedValue(response({ token: "new", verified: false })));
    run.script.mockResolvedValue({ logs: ["ran"], updates: { x: "y" } });
    await run.engine.start();
    expect(run.send).toHaveBeenCalledTimes(1);
    expect(run.engine.run.variables).toEqual({ token: "old" });
    expect(run.engine.run.status).toBe("failed");
    expect(run.engine.run.results[0]!.scriptResult?.updates).toEqual({});
  });
  it("rolls back all extractors if a later extractor is missing", async () => {
    const flow = make();
    flow.steps[0]!.extractors = [
      { variable: "a", source: "json", path: "token" },
      { variable: "b", source: "json", path: "missing" },
    ];
    const run = setup(flow);
    await run.engine.start();
    expect(run.engine.run.variables).toEqual({});
    expect(run.engine.run.results[0]!.response?.status).toBe(200);
  });
  it("keeps the HTTP response when script execution fails", async () => {
    const flow = make();
    flow.steps[0]!.afterResponse = "while(true){}";
    const run = setup(flow);
    run.script.mockResolvedValue({ logs: [], updates: {}, error: "interrupted" });
    await run.engine.start();
    expect(run.engine.run.status).toBe("failed");
    expect(run.engine.run.results[0]).toMatchObject({
      response: { status: 200 },
      error: "After response: interrupted",
    });
  });
  it("supports continuing after failure while preserving failed step variables", async () => {
    const flow = make();
    flow.variables = { token: "old" };
    flow.steps[0]!.onFailure = "continue";
    const run = setup(
      flow,
      vi.fn().mockResolvedValueOnce(response({}, 401)).mockResolvedValueOnce(response({})),
    );
    await run.engine.start();
    expect(run.send).toHaveBeenCalledTimes(2);
    expect(run.engine.run.status).toBe("failed");
    expect(run.engine.run.variables).toEqual({ token: "old" });
  });
  it("fails before sending when a required variable is missing", async () => {
    const flow = make();
    flow.steps[0]!.request.url = "{{missing}}/login";
    const run = setup(flow);
    await run.engine.start();
    expect(run.send).not.toHaveBeenCalled();
    expect(run.engine.run.results[0]!.error).toContain("Missing variable");
  });
  it("records network failures and stops subsequent steps", async () => {
    const run = setup(make(), vi.fn().mockResolvedValue({ ok: false, error: "DNS failed" }));
    await run.engine.start();
    expect(run.send).toHaveBeenCalledTimes(1);
    expect(run.engine.run.results[0]!.error).toBe("DNS failed");
  });
  it("stops after an in-flight response and never sends the next step", async () => {
    let finish!: (value: FlowSendResult) => void;
    const run = setup(
      make(),
      vi.fn().mockImplementation(
        () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      ),
    );
    const pending = run.engine.start();
    run.engine.stop();
    finish(response({ token: "new" }));
    await pending;
    expect(run.send).toHaveBeenCalledTimes(1);
    expect(run.engine.run.status).toBe("stopped");
    expect(run.engine.run.results[0]!.response?.status).toBe(200);
    expect(run.engine.run.variables).toEqual({});
  });
  it("stops before the next step when the originating workspace changes", async () => {
    let finish!: (value: FlowSendResult) => void;
    const run = setup(
      make(),
      vi.fn().mockImplementation(
        () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      ),
    );
    const pending = run.engine.start();
    run.changeWorkspace();
    finish(response({ token: "a" }));
    await pending;
    expect(run.send).toHaveBeenCalledTimes(1);
    expect(run.engine.run.status).toBe("stopped");
  });
  it("captures an immutable flow snapshot and request resolved with send-time values", async () => {
    let finish!: (value: FlowSendResult) => void;
    const flow = make(1);
    flow.variables = { token: "before" };
    flow.steps[0]!.request.headers = { Authorization: "{{token}}" };
    const run = setup(
      flow,
      vi.fn().mockImplementation(
        () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      ),
    );
    const pending = run.engine.start();
    flow.variables["token"] = "after";
    flow.steps[0]!.request.url = "https://different.example";
    finish(response({}));
    await pending;
    expect(run.engine.run.flow.steps[0]!.request.url).toBe("https://example.com/step-0");
    expect(run.engine.run.results[0]!.request?.headers["Authorization"]).toBe("before");
  });
  it("runs only a requested step range using an explicit checkpoint", async () => {
    const flow = make(3),
      send = vi.fn().mockResolvedValue(response({}));
    const engine = new FlowRunner(
      flow,
      { send, script: vi.fn(), onChange: vi.fn(), isCurrent: () => true },
      { startIndex: 1, endIndex: 2, variables: { token: "checkpoint" }, parentRunId: "previous" },
    );
    await engine.start();
    expect(send).toHaveBeenCalledTimes(1);
    expect(engine.run.results[0]!.index).toBe(1);
    expect(engine.run.variables["token"]).toBe("checkpoint");
    expect(engine.run.parentRunId).toBe("previous");
  });
  it("extracts header values case-insensitively and serializes JSON objects", async () => {
    const flow = make(1);
    flow.steps[0]!.extractors = [
      { variable: "request_id", source: "header", path: "x-request-id" },
      { variable: "object", source: "json", path: "data" },
    ];
    const run = setup(flow, vi.fn().mockResolvedValue(response({ data: { id: 42 } })));
    await run.engine.start();
    expect(run.engine.run.variables).toEqual({ request_id: "req-1", object: '{"id":42}' });
  });
  it("rejects excessive or invalid flow variables and unsafe property traversal", () => {
    expect(() => validateFlowVariables({ token: "x".repeat(64001) })).toThrow();
    expect(() =>
      validateFlowVariables(
        Object.fromEntries(Array.from({ length: 101 }, (_, i) => ["v" + i, "x"])),
      ),
    ).toThrow();
    expect(readFlowPath({}, "constructor.prototype")).toBeUndefined();
    expect(readFlowPath({ data: [{ id: 42 }] }, "$.data[0].id")).toBe(42);
    expect(readFlowPath({ "a/b": 1 }, "/a~1b")).toBe(1);
  });
  it("rejects damaged stored definitions instead of executing them", () => {
    expect(() => normalizeFlowDocument({ flows: [{ id: "x" }], active: "x" })).toThrow();
  });
});

it("keeps finished history unchanged when stop is called later", async () => {
  const run = setup(make(1));
  await run.engine.start();
  const before = structuredClone(run.engine.run);
  run.engine.stop();
  expect(run.engine.run).toEqual(before);
});
it("compares JSON objects independent of key order", async () => {
  const flow = make(1);
  flow.steps[0]!.assertions = [{ path: "data", operator: "equals", expected: '{"b":2,"a":1}' }];
  const run = setup(flow, vi.fn().mockResolvedValue(response({ data: { a: 1, b: 2 } })));
  await run.engine.start();
  expect(run.engine.run.status).toBe("passed");
});
it("can remove variables when continuing a paused run", async () => {
  const flow = make(1);
  flow.variables = { removed: "x" };
  flow.steps[0]!.pauseBefore = true;
  const run = setup(flow);
  await run.engine.start();
  await run.engine.continue({ otp: "123" });
  expect(run.engine.run.variables).toEqual({ otp: "123" });
});
it("stops large histories before sending more requests", async () => {
  const run = setup(make(10), vi.fn().mockResolvedValue(response({ text: "x".repeat(1_500_000) })));
  await run.engine.start();
  expect(run.engine.run.status).toBe("stopped");
  expect(run.engine.run.message).toContain("size budget");
  expect(run.send.mock.calls.length).toBeLessThan(10);
});
