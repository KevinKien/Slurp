import { useEffect, useRef, useState, type ReactNode } from "react";
import { sendHttpRequest } from "@/lib/replay.functions";
import { ScanEngine, newScanPlan, type ScanPlan, type ScanRun } from "@/lib/scan";
import {
  saveScanRun,
  probeHttpProtocol,
  probeHostHeader,
  lookupDependency,
  validateBrowserSnapshot,
  issueOastProbe,
  publishJwtKey,
  pollOastProbe,
} from "@/lib/scan-api";
import { useInspector } from "./inspector";
import { useAuthProfiles } from "./auth-profiles-provider";
import { ScanContext as Context } from "@/lib/scan-context";
export { useScan } from "@/lib/scan-context";
import type { HttpRequest } from "@/lib/traffic";
/** Root-mounted execution adapter. The Scan UI can use this without owning the runner lifecycle. */
export function ScanProvider({ children }: { children: ReactNode }) {
  const { session, getReplayWorkspace, variables, timeout, scope, scopeEnabled } = useInspector(),
    auth = useAuthProfiles()!;
  const workspace = session?.target === "workspace" ? session.workspace_id : null,
    key = workspace ?? "@temporary";
  const crawlScope = useRef({ scope, scopeEnabled });
  crawlScope.current = { scope, scopeEnabled };
  const send = sendHttpRequest;
  const runners = useRef(new Map<string, { workspace: string | null; engine: ScanEngine }>());
  const [configuringKey, setConfiguringKey] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, ScanPlan>>({}),
    [preparing, setPreparing] = useState(false);
  const prepareVersion = useRef(0);
  useEffect(() => {
    prepareVersion.current++;
    setPreparing(false);
  }, [workspace]);
  const prepare = async (
    read: () => HttpRequest | Promise<HttpRequest>,
    mode?: "passive" | "active",
  ) => {
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

      if (mode) plan.mode = mode;
      setDrafts((prev) => ({ ...prev, [key]: plan }));
      setConfiguringKey(key);
    } finally {
      if (version === prepareVersion.current) setPreparing(false);
    }
  };
  const [runs, setRuns] = useState<Record<string, ScanRun[]>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [pending, setPending] = useState<Record<string, string | null>>({});
  useEffect(() => {
    for (const entry of runners.current.values())
      if (entry.workspace !== workspace) entry.engine.stop();
  }, [workspace]);
  useEffect(
    () => () => {
      for (const entry of runners.current.values()) entry.engine.stop();
    },
    [],
  );
  const control = (id?: string) => {
    const entry = id
      ? runners.current.get(id)
      : [...runners.current.values()]
          .reverse()
          .find((e) => e.workspace === workspace && e.engine.active);
    return entry?.workspace === workspace ? entry.engine : undefined;
  };
  const retrySave = async (id?: string) => {
    const entry = id
      ? runners.current.get(id)
      : [...runners.current.values()].find(
          (e) => e.workspace === workspace && e.engine.persistenceError,
        );
    if (!entry || entry.workspace !== workspace) return;
    const runId = entry.engine.run.id;
    await entry.engine.retrySave();
    setErrors((prev) => ({ ...prev, [runId]: entry.engine.persistenceError }));
    if (!entry.engine.persistenceError) runners.current.delete(runId);
  };
  const start = (plan: ScanPlan, profileId?: string | null) => {
    if (!auth.ready) throw Error("Wait for profiles to load.");
    const destination = workspace,
      destinationKey = key;
    // Observed traffic is inspected exactly as captured. Active scans snapshot the chosen profile once.
    const identity =
      plan.mode !== "passive" || !plan.observed ? auth.createSession(profileId, variables) : null;
    const prepared = {
      ...structuredClone(plan),
      allowSending:
        plan.allowSending || (!plan.crawlBeforeScan && plan.mode === "passive" && !plan.observed),
      request: identity
        ? identity.resolve(plan.request, identity.variables)
        : structuredClone(plan.request),
    };
    const engine = new ScanEngine(
      prepared,
      {
        allowCrawlUrl: (url) => {
          const current = crawlScope.current;
          return (
            !current.scopeEnabled ||
            !(current.scope ?? "").trim() ||
            current.scope
              .split("\n")
              .map((s) => s.trim().toLowerCase().replace(/\.$/, ""))
              .includes(new URL(url).hostname.toLowerCase().replace(/\.$/, ""))
          );
        },
        browser: validateBrowserSnapshot,
        protocol: probeHttpProtocol,
        hostHeader: probeHostHeader,
        dependencies: lookupDependency,
        oast: {
          publishKey: publishJwtKey,
          issue: issueOastProbe,
          poll: (probe) => pollOastProbe(probe.id),
        },
        allowScriptOrigin: (url) =>
          !!scopeEnabled &&
          (scope ?? "")
            .split("\n")
            .map((s) => s.trim().toLowerCase().replace(/\.$/, ""))
            .includes(new URL(url).hostname.toLowerCase().replace(/\.$/, "")),
        send: (request, options) =>
          send({
            data: {
              ...request,
              method: request.method as "GET",
              timeout: Math.min(
                timeout,
                options?.timeoutMs ?? prepared.policy?.requestTimeoutMs ?? 15000,
              ),
            },
          }),
        isCurrent: () => getReplayWorkspace() === destination,
        receive: (url, cookies) => identity?.receive(url, cookies),
        onChange: (run) =>
          setRuns((prev) => ({
            ...prev,
            [destinationKey]: [run, ...(prev[destinationKey] ?? []).filter((r) => r.id !== run.id)],
          })),
        ...(destination && { save: (run: ScanRun) => saveScanRun(destination, run) }),
      },
      identity?.profile ? { id: identity.profile.id, name: identity.profile.name } : undefined,
    );
    const id = engine.run.id;
    runners.current.set(id, { workspace: destination, engine });
    setPending((prev) => ({ ...prev, [id]: destination }));
    void engine
      .start()
      .then(() => setErrors((prev) => ({ ...prev, [id]: engine.persistenceError })))
      .catch((error) =>
        setErrors((prev) => ({
          ...prev,
          [id]: error instanceof Error ? error.message : "Scan failed",
        })),
      )
      .finally(() => {
        setPending((prev) => {
          const next = { ...prev };
          delete next[id];
          return next;
        });
        if (!engine.persistenceError) runners.current.delete(id);
        if (destination)
          setRuns((prev) => {
            let completed = 0;
            return {
              ...prev,
              [destinationKey]: (prev[destinationKey] ?? []).filter(
                (run) => runners.current.has(run.id) || ++completed <= 3,
              ),
            };
          });
      });
  };
  const localRuns = runs[key] ?? [];
  const saveErrors = Object.fromEntries(
    localRuns.filter((r) => errors[r.id]).map((r) => [r.id, errors[r.id]!]),
  );
  const busy = Object.values(pending).some((destination) => destination === workspace);

  return (
    <Context.Provider
      value={{
        forget: (id) => {
          if (id in pending) return;
          runners.current.delete(id);
          setRuns((prev) => ({ ...prev, [key]: (prev[key] ?? []).filter((r) => r.id !== id) }));
          setErrors((prev) => {
            const next = { ...prev };
            delete next[id];
            return next;
          });
        },
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
        pendingRunIds: Object.keys(pending).filter((id) => pending[id] === workspace),
        error: Object.values(saveErrors).join("; "),
        saveErrors,
        start,
        stop: (id) => control(id)?.stop(),
        pause: (id) => control(id)?.pause(),
        resume: (id) => control(id)?.resume(),
        retrySave,
      }}
    >
      {children}
    </Context.Provider>
  );
}
