import { useEffect, useRef, useState, type ReactNode } from "react";
import { sendHttpRequest } from "@/lib/replay.functions";
import { ScanEngine, newScanPlan, type ScanPlan, type ScanRun } from "@/lib/scan";
import { saveScanRun } from "@/lib/scan-api";
import { useInspector } from "./inspector";
import { useAuthProfiles } from "./auth-profiles-provider";
import { ScanContext as Context } from "@/lib/scan-context";
export { useScan } from "@/lib/scan-context";
import type { HttpRequest } from "@/lib/traffic";
/** Root-mounted execution adapter. The Scan UI can use this without owning the runner lifecycle. */
export function ScanProvider({ children }: { children: ReactNode }) {
  const { session, getReplayWorkspace, variables, timeout } = useInspector(),
    auth = useAuthProfiles()!;
  const workspace = session?.target === "workspace" ? session.workspace_id : null,
    key = workspace ?? "@temporary";
  const send = sendHttpRequest;
  const runner = useRef<{ workspace: string | null; engine: ScanEngine } | null>(null),
    locked = useRef(false);
  const [configuringKey, setConfiguringKey] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, ScanPlan>>({}),
    [preparing, setPreparing] = useState(false);
  const prepareVersion = useRef(0);
  useEffect(() => {
    prepareVersion.current++;
    setPreparing(false);
  }, [workspace]);
  const prepare = async (read: () => HttpRequest | Promise<HttpRequest>) => {
    const version = ++prepareVersion.current,
      destination = workspace;
    setPreparing(true);
    setDrafts((prev) => {
      const next = { ...prev };
      delete next[key];
      return next;
    });
    try {
      const source = await read();
      if (version !== prepareVersion.current || getReplayWorkspace() !== destination) return;
      const request: HttpRequest = {
        method: source.method,
        url: source.url,
        headers: { ...source.headers },
        body: source.body,
      };
      const plan = newScanPlan(request);
      const captured = source as HttpRequest & {
        status?: number;
        responseHeaders?: Record<string, string>;
        responseBody?: string;
        size?: number;
        duration?: number;
      };
      if (
        captured.status &&
        captured.status >= 100 &&
        captured.status <= 599 &&
        captured.responseHeaders &&
        typeof captured.responseBody === "string"
      ) {
        plan.observed = {
          response: {
            status: captured.status,
            responseHeaders: { ...captured.responseHeaders },
            responseBody: captured.responseBody,
          },
          ...(captured.size !== undefined && { size: captured.size }),
          ...(captured.duration !== undefined && { duration: captured.duration }),
        };
      } else plan.mode = "active";
      setDrafts((prev) => ({ ...prev, [key]: plan }));
      setConfiguringKey(key);
    } finally {
      if (version === prepareVersion.current) setPreparing(false);
    }
  };
  const [busy, setBusy] = useState(false),
    [runs, setRuns] = useState<Record<string, ScanRun[]>>({}),
    [errors, setErrors] = useState<Record<string, string>>({});
  useEffect(() => {
    if (runner.current?.workspace !== workspace) runner.current?.engine.stop();
  }, [workspace]);
  useEffect(() => () => runner.current?.engine.stop(), []);
  const retrySave = async () => {
    const entry = runner.current;
    if (!entry || entry.workspace !== workspace) return;
    await entry.engine.retrySave();
    setErrors((prev) => ({ ...prev, [key]: entry.engine.persistenceError }));
  };
  const start = (plan: ScanPlan, profileId?: string | null) => {
    if (locked.current || runner.current?.engine.active)
      throw Error("Stop or finish the current scan first.");
    if (runner.current?.engine.persistenceError)
      throw Error(
        "Save the previous scan evidence before starting another scan. Return to its workspace and retry saving.",
      );
    if (!auth.ready) throw Error("Wait for profiles to load.");
    const destination = workspace,
      destinationKey = key;
    // Observed traffic is inspected exactly as captured. Active scans snapshot the chosen profile once.
    const identity = plan.mode === "active" ? auth.createSession(profileId, variables) : null;
    const prepared = {
      ...structuredClone(plan),
      request: identity
        ? identity.resolve(plan.request, identity.variables)
        : structuredClone(plan.request),
    };
    const engine = new ScanEngine(
      prepared,
      {
        send: (request) => send({ data: { ...request, method: request.method as "GET", timeout } }),
        isCurrent: () => getReplayWorkspace() === destination,
        receive: (url, cookies) => identity?.receive(url, cookies),
        onChange: (run) =>
          setRuns((prev) => ({
            ...prev,
            [destinationKey]: [
              run,
              ...(prev[destinationKey] ?? []).filter((r) => r.id !== run.id),
            ].slice(0, 3),
          })),
        ...(destination && { save: (run: ScanRun) => saveScanRun(destination, run) }),
      },
      identity?.profile ? { id: identity.profile.id, name: identity.profile.name } : undefined,
    );
    runner.current = { workspace: destination, engine };
    locked.current = true;
    setBusy(true);
    setErrors((prev) => ({ ...prev, [key]: "" }));
    void engine
      .start()
      .then(() => setErrors((prev) => ({ ...prev, [destinationKey]: engine.persistenceError })))
      .catch((error) =>
        setErrors((prev) => ({
          ...prev,
          [destinationKey]: error instanceof Error ? error.message : "Scan failed",
        })),
      )
      .finally(() => {
        locked.current = false;
        setBusy(false);
      });
  };
  return (
    <Context.Provider
      value={{
        forget: (id) =>
          setRuns((prev) => ({ ...prev, [key]: (prev[key] ?? []).filter((r) => r.id !== id) })),
        workspace,
        draft: drafts[key] ?? null,
        preparing,
        configuring: configuringKey === key,
        setConfiguring: (open) => setConfiguringKey(open ? key : null),
        prepare,
        updateDraft: (plan) => setDrafts((prev) => ({ ...prev, [key]: structuredClone(plan) })),
        run: runs[key]?.[0] ?? null,
        localRuns: runs[key] ?? [],
        busy,
        error: errors[key] ?? "",
        start,
        stop: () => runner.current?.engine.stop(),
        pause: () => runner.current?.engine.pause(),
        resume: () => runner.current?.engine.resume(),
        retrySave,
      }}
    >
      {children}
    </Context.Provider>
  );
}
