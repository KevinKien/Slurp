import { describe, it, expect, vi, afterEach } from "vitest";
import {
  newIntruderConfig,
  applyPayload,
  sourceCount,
  payloadAt,
  encodePayload,
} from "../lib/intruder";
import { parsePayloadRows } from "../lib/intruder-import";
import { IntruderRunner } from "../lib/intruder-runner";
async function* chunks(values: string[]) {
  yield* values;
}
async function parse(values: string[], format: "csv" | "txt" = "csv") {
  const rows = [];
  for await (const row of parsePayloadRows(chunks(values), format)) rows.push(row);
  return rows;
}
const config = () => ({
  ...newIntruderConfig(),
  request: { method: "GET" as const, url: "https://example.com/§x§", headers: {}, body: "" },
  source: { kind: "list" as const, values: ["a", "b", "c"] },
  rate: 100,
});
afterEach(() => vi.useRealTimers());
describe("Intruder payloads", () => {
  it("substitutes literally once after variable resolution", () => {
    expect(applyPayload(config().request, "{{token}}§", "none").url).toBe(
      "https://example.com/{{token}}§",
    );
    expect(() => applyPayload({ ...config().request, body: "§x§" }, "x", "none")).toThrow(
      "exactly one",
    );
    expect(() =>
      applyPayload(
        { ...config().request, url: "https://example.com", headers: { X: "§x§" } },
        "x\r\nY: z",
        "none",
      ),
    ).toThrow("invalid request header");
  });
  it("encodes UTF-8 and HTML values", () => {
    expect(encodePayload("é", "base64")).toBe("w6k=");
    expect(encodePayload("é", "hex")).toBe("c3a9");
    expect(encodePayload("a b/", "url")).toBe("a%20b%2F");
    expect(encodePayload('<&"', "html")).toBe("&lt;&amp;&quot;");
  });
  it("generates lazy descending signed integer ranges without precision loss", () => {
    const source = {
      kind: "numbers" as const,
      from: "9007199254740993",
      to: "9007199254740989",
      step: "-2",
      pad: 0,
    };
    expect(sourceCount(source)).toBe(3);
    expect(payloadAt(source, 1)).toBe("9007199254740991");
    expect(payloadAt({ ...source, from: "-2", to: "2", step: "1", pad: 3 }, 0)).toBe("-002");
    expect(() => sourceCount({ ...source, step: "0" })).toThrow();
    expect(() => sourceCount({ ...source, step: "1" })).toThrow();
    expect(() => sourceCount({ ...source, from: "1", to: "1000001", step: "1" })).toThrow();
  });
  it("parses chunked CSV quotes, multiline fields, BOM and CRLF", async () => {
    expect(await parse(["\uFEFFname,value\r", '\n"a', '""b",', '"line1\nline2"\r', "\n"])).toEqual([
      ["name", "value"],
      ['a"b', "line1\nline2"],
    ]);
    expect(await parse(["a\r", "\nb\n\n"], "txt")).toEqual([["a"], ["b"], [""]]);
    await expect(parse(['"unclosed'])).rejects.toThrow("Unclosed");
    await expect(parse(['"a"x'])).rejects.toThrow("Unexpected");
    await expect(parse(["x".repeat(65537)], "txt")).rejects.toThrow("64 KB");
  });
});
const response = {
  ok: true as const,
  status: 200,
  size: 10,
  duration: 1,
  responseHeaders: {},
  responseBody: "hello token",
};
function setup(patch: Partial<ConstructorParameters<typeof IntruderRunner>[1]> = {}, c = config()) {
  const evidence: any[] = [];
  const deps = {
    payload: async (index: number) => c.source.values[index]!,
    resolve: () => c.request,
    receive: vi.fn(),
    send: vi.fn(async () => response),
    current: () => true,
    onChange: vi.fn(),
    onResult: async (result: unknown) => {
      evidence.push(result);
    },
    ...patch,
  };
  const runner = new IntruderRunner(c, deps);
  return { runner, deps, evidence };
}
describe("Intruder execution", () => {
  it("spaces actual sends even when a payload load is delayed", async () => {
    vi.useFakeTimers();
    const times: number[] = [];
    const { runner } = setup(
      {
        payload: async (i) => {
          if (i === 0) await new Promise((r) => setTimeout(r, 100));
          return String(i);
        },
        send: async () => {
          times.push(Date.now());
          return response;
        },
      },
      { ...config(), concurrency: 3, rate: 10 },
    );
    const done = runner.start();
    await vi.runAllTimersAsync();
    await done;
    expect(times).toHaveLength(3);
    expect(times[1]! - times[0]!).toBeGreaterThanOrEqual(100);
    expect(times[2]! - times[1]!).toBeGreaterThanOrEqual(100);
  });
  it("pauses pending sends and stops scheduling after workspace change", async () => {
    vi.useFakeTimers();
    let current = true;
    const { runner, deps } = setup({ current: () => current });
    const done = runner.start();
    await vi.advanceTimersByTimeAsync(1);
    runner.pause();
    await vi.advanceTimersByTimeAsync(100);
    expect(deps.send).toHaveBeenCalledTimes(1);
    runner.resume();
    await vi.advanceTimersByTimeAsync(20);
    current = false;
    await vi.runAllTimersAsync();
    await done;
    expect(runner.run.status).toBe("stopped");
  });
  it("does not retry HTTP when evidence persistence fails", async () => {
    vi.useFakeTimers();
    const { runner, deps } = setup({
      onResult: async () => {
        throw Error("disk full");
      },
    });
    const done = runner.start();
    await vi.runAllTimersAsync();
    await done;
    expect(deps.send).toHaveBeenCalledTimes(1);
    expect(runner.run.status).toBe("failed");
    expect(runner.run.message).toContain("disk full");
  });
  it("stops on missing payload sources", async () => {
    const { runner, deps } = setup({
      payload: async () => {
        throw Error("deleted");
      },
    });
    await runner.start();
    expect(deps.send).not.toHaveBeenCalled();
    expect(runner.run.status).toBe("failed");
  });
  it("bounds evidence and matches full response before truncation", async () => {
    const { runner, evidence } = setup(
      {
        send: async () => ({ ...response, responseBody: "x".repeat(40000) + "needle" }),
        budget: 3001000,
      },
      { ...config(), source: { kind: "list", values: ["a"] }, matchText: "needle" },
    );
    await runner.start();
    expect(evidence[0].matched).toBe(true);
    expect(evidence[0].truncated).toBe(true);
    expect(evidence[0].response.responseBody).toHaveLength(32768);
  });
  it("waits for in-flight requests when stopped and captures evidence", async () => {
    let resolve!: (v: typeof response) => void;
    const { runner, deps, evidence } = setup({
      send: vi.fn(
        () =>
          new Promise<typeof response>((r) => {
            resolve = r;
          }),
      ),
    });
    const done = runner.start();
    await vi.waitFor(() => expect(deps.send).toHaveBeenCalledTimes(1));
    runner.stop();
    resolve(response);
    await done;
    expect(evidence).toHaveLength(1);
    expect(runner.run.status).toBe("stopped");
  });
});
