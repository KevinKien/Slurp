import { flowId } from "./flows";
import {
  applyPayload,
  encodePayload,
  validateIntruderConfig,
  type IntruderConfig,
  type IntruderRun,
  type IntruderResult,
} from "./intruder";
import type { HttpRequest } from "./traffic";
interface SendResult {
  ok: true;
  status: number;
  statusText?: string;
  size: number;
  duration: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
  setCookies?: string[];
}
interface Dependencies {
  payload: (index: number) => Promise<string>;
  resolve: (template: HttpRequest) => HttpRequest;
  receive: (url: string, cookies: string[]) => void;
  send: (request: HttpRequest) => Promise<SendResult | { ok: false; error: string }>;
  current: () => boolean;
  onChange: (run: IntruderRun) => void;
  onResult: (result: IntruderResult) => Promise<void>;
  budget?: number;
  now?: () => number;
}
export class IntruderRunner {
  private state: IntruderRun;
  private cancelled = false;
  private paused = false;
  private started = false;
  private failure = "";
  private nextTime = 0;
  private gate: Promise<void> = Promise.resolve();
  private sendGate: Promise<void> = Promise.resolve();
  private wakeups = new Set<() => void>();
  constructor(
    config: IntruderConfig,
    private deps: Dependencies,
    profile?: { id: string; name: string },
  ) {
    const count = validateIntruderConfig(config);
    this.state = {
      id: flowId(),
      startedAt: new Date().toISOString(),
      config: structuredClone(config),
      count,
      completed: 0,
      launched: 0,
      inFlight: 0,
      bytes: 0,
      status: "running",
      message: "",
      ...(profile && { profileId: profile.id, profileName: profile.name }),
    };
  }
  get run() {
    return this.state;
  }
  get active() {
    return this.started && !["completed", "stopped", "failed"].includes(this.state.status);
  }
  private emit(patch: Partial<IntruderRun> = {}) {
    this.state = { ...this.state, ...patch };
    this.deps.onChange(this.state);
  }
  private wake() {
    for (const wake of [...this.wakeups]) wake();
  }
  pause() {
    if (this.started && !this.cancelled && this.active) {
      this.paused = true;
      this.emit({ status: "paused" });
      this.wake();
    }
  }
  resume() {
    if (this.paused && !this.cancelled) {
      this.paused = false;
      this.emit({ status: "running" });
      this.wake();
    }
  }
  stop() {
    if (this.cancelled || ["completed", "stopped", "failed"].includes(this.state.status)) return;
    this.cancelled = true;
    this.emit({ message: "Stopping; waiting for in-flight requests." });
    this.wake();
  }
  private now() {
    return this.deps.now?.() ?? Date.now();
  }
  private wait(ms: number) {
    return new Promise<void>((resolve) => {
      const wake = () => {
        clearTimeout(timer);
        this.wakeups.delete(wake);
        resolve();
      };
      const timer = setTimeout(wake, Math.min(1000, Math.max(1, ms)));
      this.wakeups.add(wake);
    });
  }
  private async claim(): Promise<number | null> {
    let release!: () => void;
    const previous = this.gate;
    this.gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      while (true) {
        if (this.cancelled || !this.deps.current() || this.state.launched >= this.state.count)
          return null;
        const budget = this.deps.budget ?? 28 * 1024 * 1024;
        if (this.state.bytes + 3_000_000 > budget) {
          this.failure =
            "Evidence budget reached. Start a new run with a later payload offset to continue.";
          this.cancelled = true;
          this.wake();
          return null;
        }
        if (this.state.bytes + (this.state.inFlight + 1) * 3_000_000 > budget) {
          await this.wait(1000);
          continue;
        }
        if (this.paused) {
          await this.wait(1000);
          continue;
        }

        const index = this.state.launched;

        this.emit({ launched: index + 1, inFlight: this.state.inFlight + 1 });
        return index;
      }
    } finally {
      release();
    }
  }
  private async beforeSend() {
    let release!: () => void;
    const previous = this.sendGate;
    this.sendGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      while (true) {
        if (this.cancelled || !this.deps.current()) throw Error("Stopped before sending.");
        if (this.paused) {
          await this.wait(1000);
          continue;
        }
        const wait = this.nextTime - this.now();
        if (wait > 0) {
          await this.wait(wait);
          continue;
        }
        this.nextTime =
          this.now() + Math.max(1000 / this.state.config.rate, this.state.config.delay);
        return;
      }
    } finally {
      release();
    }
  }
  private async worker() {
    while (true) {
      const index = await this.claim();
      if (index === null) return;
      const start = this.now(),
        payloadIndex = this.state.config.start + index;
      let result: IntruderResult = {
        index,
        payloadIndex,
        payload: "",
        encodedPayload: "",
        timestamp: new Date().toISOString(),
        status: null,
        size: 0,
        duration: 0,
        matched: false,
        truncated: false,
      };
      try {
        let payload: string;
        try {
          payload = await this.deps.payload(payloadIndex);
        } catch (error) {
          this.failure =
            "Payload source is unavailable. " +
            (error instanceof Error ? error.message : String(error));
          this.cancelled = true;
          this.wake();
          throw error;
        }
        if (new TextEncoder().encode(payload).length > 16384) throw Error("Payload exceeds 16 KB.");
        result = {
          ...result,
          payload,
          encodedPayload: encodePayload(payload, this.state.config.encoding),
        };
        if (this.cancelled || !this.deps.current()) throw Error("Stopped before sending.");
        const request = applyPayload(
          this.deps.resolve(this.state.config.request),
          payload,
          this.state.config.encoding,
        );
        result = { ...result, request };
        await this.beforeSend();
        const sent = await this.deps.send(request);
        if (!sent.ok) throw Error(sent.error);
        const headers: Record<string, string> = {};
        let bytes = 0,
          truncated = sent.responseBody.length > 32768;
        for (const [name, value] of Object.entries(sent.responseHeaders)) {
          const size = new TextEncoder().encode(JSON.stringify([name, value])).length;
          if (bytes + size > 32768) {
            truncated = true;
            continue;
          }
          headers[name] = value;
          bytes += size;
        }
        const digest = globalThis.crypto?.subtle
          ? await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sent.responseBody))
          : null;
        const bodyHash = digest
          ? Array.from(new Uint8Array(digest), (v) => v.toString(16).padStart(2, "0")).join("")
          : null;
        result = {
          ...result,
          status: sent.status,
          size: sent.size,
          duration: sent.duration,
          matched:
            !!this.state.config.matchText &&
            sent.responseBody.includes(this.state.config.matchText),
          truncated,
          ...(bodyHash && { bodyHash }),
          response: {
            status: sent.status,
            responseHeaders: headers,
            responseBody: sent.responseBody.slice(0, 32768),
          },
        };
        if (!this.cancelled && this.deps.current())
          this.deps.receive(request.url, sent.setCookies ?? []);
      } catch (error) {
        result = { ...result, error: error instanceof Error ? error.message : "Request failed" };
      }
      result = { ...result, duration: Math.max(result.duration, Math.max(0, this.now() - start)) };
      const bytes = new TextEncoder().encode(JSON.stringify(result)).length;
      // Reserve room for all in-flight evidence before scheduling another request.
      this.emit({ bytes: this.state.bytes + bytes });
      try {
        await this.deps.onResult(result);
      } catch (error) {
        this.failure = `Evidence could not be saved: ${error instanceof Error ? error.message : "Storage unavailable"}`;
        this.cancelled = true;
        this.wake();
      }
      this.emit({ completed: this.state.completed + 1, inFlight: this.state.inFlight - 1 });
      this.wake();
    }
  }
  async start() {
    if (this.started) return;
    this.started = true;
    this.emit();
    try {
      const settled = await Promise.allSettled(
        Array.from({ length: this.state.config.concurrency }, () => this.worker()),
      );
      const rejected = settled.find((v) => v.status === "rejected");
      if (rejected?.status === "rejected") throw rejected.reason;
    } catch (error) {
      this.failure = error instanceof Error ? error.message : "Intruder failed";
      this.cancelled = true;
      this.wake();
    }
    const status = this.failure
      ? "failed"
      : this.cancelled || !this.deps.current()
        ? "stopped"
        : "completed";
    this.emit({
      status,
      finishedAt: new Date().toISOString(),
      message:
        this.failure ||
        (status === "stopped"
          ? "Stopped. Already sent requests may have changed server state."
          : ""),
      inFlight: 0,
    });
  }
}
