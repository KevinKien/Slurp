import { useEffect, useRef, useState, type ReactNode } from "react";
import { sendHttpRequest } from "@/lib/replay.functions";
import { useInspector } from "./inspector";
import { useAuthProfiles } from "./auth-profiles-provider";
import {
  applyPayload,
  newIntruderConfig,
  payloadAt,
  validateIntruderConfig,
  type IntruderConfig,
  type IntruderRun,
  type IntruderResult,
} from "@/lib/intruder";
import { IntruderRunner } from "@/lib/intruder-runner";
import * as api from "@/lib/intruder-api";
import { resolveReplayRequest } from "@/lib/replay-features";
import type { HttpRequest } from "@/lib/traffic";
interface Store {
  config: IntruderConfig;
  revision: number;
  ready: boolean;
  dirty: boolean;
  error: string;
  conflict: boolean;
}
import { Context } from "@/lib/intruder-context";
export { useIntruder } from "@/lib/intruder-context";
const TEMP = "@temporary";
const empty = (ready = false): Store => ({
  config: newIntruderConfig(),
  revision: 0,
  ready,
  dirty: false,
  error: "",
  conflict: false,
});
export function IntruderProvider({ children }: { children: ReactNode }) {
  const { session, getReplayWorkspace, variables, timeout } = useInspector(),
    auth = useAuthProfiles();
  const workspace = session?.target === "workspace" ? session.workspace_id : null,
    key = workspace ?? TEMP;
  const send = sendHttpRequest;
  const [stores, setStores] = useState<Record<string, Store>>({ [TEMP]: empty(true) }),
    [running, setRunning] = useState<{ workspace: string | null; run: IntruderRun } | null>(null),
    [runs, setRuns] = useState<Record<string, IntruderRun[]>>({}),
    [details, setDetails] = useState<Record<string, IntruderResult[]>>({}),
    [errors, setErrors] = useState<Record<string, string>>({}),
    [starting, setStarting] = useState(false);
  const ref = useRef(stores);
  ref.current = stores;
  const queues = useRef(new Map<string, Promise<void>>()),
    timers = useRef(new Map<string, ReturnType<typeof setTimeout>>()),
    loading = useRef(new Set<string>());
  const engineRef = useRef<{ workspace: string | null; engine: IntruderRunner } | null>(null),
    startingRef = useRef(false);
  const incoming = useRef(new Map<string, HttpRequest>());
  const pending = useRef(new Map<string, IntruderResult[]>());
  const pendingRun = useRef(new Map<string, IntruderRun>());
  const updateStore = (id: string, fn: (s: Store) => Store) => {
    const next = { ...ref.current, [id]: fn(ref.current[id] ?? empty()) };
    ref.current = next;
    setStores(next);
  };
  const persist = (id: string): Promise<void> => {
    clearTimeout(timers.current.get(id));
    timers.current.delete(id);
    if (id === TEMP) return Promise.resolve();
    const task = (queues.current.get(id) ?? Promise.resolve())
      .catch(() => {})
      .then(async () => {
        const entry = ref.current[id];
        if (!entry?.dirty || entry.conflict) return;
        const snapshot = structuredClone(entry.config);
        try {
          validateIntruderConfig(snapshot, false);
          const saved = await api.saveIntruder(id, entry.revision, snapshot);
          updateStore(id, (s) => ({
            ...s,
            revision: saved.revision,
            dirty: JSON.stringify(snapshot) !== JSON.stringify(s.config),
            error: "",
          }));
        } catch (error) {
          const message = error instanceof Error ? error.message : "Could not save Intruder";
          updateStore(id, (s) => ({
            ...s,
            error: message,
            conflict: /another browser|409/i.test(message),
          }));
          throw error;
        }
      });
    queues.current.set(id, task);
    return task;
  };
  const load = async (id: string) => {
    if (id === TEMP || loading.current.has(id)) return;
    loading.current.add(id);
    clearTimeout(timers.current.get(id));
    timers.current.delete(id);
    try {
      await queues.current.get(id)?.catch(() => {});
      const value = await api.fetchIntruder(id);
      const config = value.document ?? newIntruderConfig();
      const received = incoming.current.get(id);
      if (received) {
        config.request = received;
        incoming.current.delete(id);
      }
      validateIntruderConfig(config, false);
      updateStore(id, () => ({
        config,
        revision: value.revision,
        ready: true,
        dirty: !!received,
        error: "",
        conflict: false,
      }));
      if (received) void persist(id).catch(() => {});
    } catch (error) {
      updateStore(id, (s) => ({
        ...s,
        error: error instanceof Error ? error.message : "Could not load Intruder",
      }));
    } finally {
      loading.current.delete(id);
    }
  };
  useEffect(() => {
    if (engineRef.current?.workspace !== workspace) engineRef.current?.engine.stop();
    if (workspace && !ref.current[key]?.ready) void load(workspace);
    return () => {
      if (workspace) void persist(workspace).catch(() => {});
    };
  }, [workspace]);
  useEffect(
    () => () => {
      engineRef.current?.engine.stop();
      for (const id of timers.current.keys()) void persist(id).catch(() => {});
    },
    [],
  );
  const edit = (config: IntruderConfig) => {
    if (!ref.current[key]?.ready) throw Error("Wait for Intruder to load.");
    updateStore(key, (s) => ({ ...s, config: structuredClone(config), dirty: key !== TEMP }));
    if (key !== TEMP) {
      clearTimeout(timers.current.get(key));
      timers.current.set(
        key,
        setTimeout(() => void persist(key).catch(() => {}), 600),
      );
    }
  };
  const start = async () => {
    if (pending.current.size || pendingRun.current.size)
      throw Error(
        "Save pending evidence for the previous run before starting another run. Return to its workspace and retry evidence saving.",
      );
    if (startingRef.current || engineRef.current?.engine.active)
      throw Error("Stop or finish the active Intruder run first.");
    startingRef.current = true;
    setStarting(true);
    try {
      const config = structuredClone(ref.current[key]?.config ?? newIntruderConfig());
      const count = validateIntruderConfig(config);
      if (!workspace && count > 200)
        throw Error(
          "Temporary runs support up to 200 requests. Select a saved workspace for larger runs.",
        );
      const destination = workspace,
        destinationKey = key;
      const identity = auth?.createSession(undefined, variables);
      const resolved = identity
        ? identity.resolve(config.request, identity.variables)
        : resolveReplayRequest(config.request, variables);
      // Catch profiles that replace the marked authentication field before sending anything.
      applyPayload(resolved, "preview", config.encoding);
      const pageCache = new Map<number, Promise<string[]>>();
      const payload = async (index: number) => {
        if (config.source.kind !== "file") return payloadAt(config.source, index);
        if (!destination) throw Error("Payload files require a saved workspace.");
        const offset = Math.floor(index / 128) * 128;
        if (!pageCache.has(offset)) {
          const id = config.source.id;
          pageCache.set(
            offset,
            api.fetchPayloadPage(destination, id, offset).then((page) => page.values),
          );
          if (pageCache.size > 3) pageCache.delete(pageCache.keys().next().value!);
        }
        const value = (await pageCache.get(offset)!)[index - offset];
        if (value === undefined) throw Error("Payload file changed or is unavailable.");
        return value;
      };

      let engine!: IntruderRunner;
      engine = new IntruderRunner(
        config,
        {
          payload,
          resolve: () =>
            identity
              ? identity.resolve(config.request, identity.variables)
              : resolveReplayRequest(config.request, variables),
          receive: (url, cookies) => identity?.receive(url, cookies),
          send: (request) =>
            send({ data: { ...request, method: request.method as "GET", timeout } }),
          current: () => getReplayWorkspace() === destination,
          budget: destination ? 28 * 1024 * 1024 : 8 * 1024 * 1024,
          onChange: (run) => {
            setRunning({ workspace: destination, run });
            setRuns((prev) => ({
              ...prev,
              [destinationKey]: [
                run,
                ...(prev[destinationKey] ?? []).filter((r) => r.id !== run.id),
              ].slice(0, 5),
            }));
          },
          onResult: async (result) => {
            setDetails((prev) =>
              Object.fromEntries([
                ...Object.entries(prev)
                  .filter(([id]) => id !== engine.run.id)
                  .slice(-4),
                [
                  engine.run.id,
                  [...(prev[engine.run.id] ?? []), result].slice(destination ? -3 : -200),
                ],
              ]),
            );
            if (destination)
              try {
                await api.saveIntruderResult(destination, engine.run.id, result);
              } catch (error) {
                const id = engine.run.id;
                pending.current.set(id, [...(pending.current.get(id) ?? []), result]);
                throw error;
              }
          },
        },
        identity?.profile ? { id: identity.profile.id, name: identity.profile.name } : undefined,
      );
      if (destination) await api.saveIntruderRun(destination, engine.run);
      if (getReplayWorkspace() !== destination) {
        if (destination)
          await api.saveIntruderRun(destination, {
            ...engine.run,
            status: "stopped",
            finishedAt: new Date().toISOString(),
            message: "Workspace changed before sending.",
          });
        throw Error("Workspace changed before the attack started. No requests were sent.");
      }
      engineRef.current = { workspace: destination, engine };
      setErrors((prev) => ({ ...prev, [destinationKey]: "" }));
      void engine.start().then(async () => {
        if (!destination) return;
        const run = engine.run;
        pendingRun.current.set(run.id, run);
        try {
          await api.saveIntruderRun(destination, run);
          if (!pending.current.get(run.id)?.length) pendingRun.current.delete(run.id);
        } catch (error) {
          setErrors((prev) => ({
            ...prev,
            [destinationKey]: error instanceof Error ? error.message : "Could not save run status",
          }));
        }
        if (pending.current.get(run.id)?.length)
          setErrors((prev) => ({
            ...prev,
            [destinationKey]:
              "Some result evidence could not be saved. Retry evidence saving; requests will not be sent again.",
          }));
      });
    } finally {
      startingRef.current = false;
      setStarting(false);
    }
  };
  const entry = stores[key] ?? empty(),
    run = running?.workspace === workspace ? running.run : null;
  return (
    <Context.Provider
      value={{
        workspace,
        config: entry.config,
        ready: entry.ready,
        dirty: entry.dirty,
        error: entry.error,
        update: edit,
        receive: (request) => {
          if (!entry.ready) {
            incoming.current.set(key, structuredClone(request));
            return;
          }
          edit({ ...entry.config, request: structuredClone(request) });
        },
        reload: () => void load(key),
        retry: () => {
          if (!entry.ready) void load(key);
          else void persist(key).catch(() => {});
        },
        run,
        localRuns: runs[key] ?? [],
        results: run ? (details[run.id] ?? []) : [],
        getLocalResults: (id) => details[id] ?? [],
        active: !!engineRef.current?.engine.active,
        starting,
        start,
        pause: () => engineRef.current?.engine.pause(),
        resume: () => engineRef.current?.engine.resume(),
        stop: () => engineRef.current?.engine.stop(),
        runError: errors[key] ?? "",
        retryEvidence: async () => {
          if (!workspace || !run) return;
          for (const result of pending.current.get(run.id) ?? [])
            await api.saveIntruderResult(workspace, run.id, result);
          pending.current.delete(run.id);
          const meta = pendingRun.current.get(run.id);
          if (meta) await api.saveIntruderRun(workspace, meta);
          pendingRun.current.delete(run.id);
          setErrors((prev) => ({ ...prev, [key]: "" }));
        },
      }}
    >
      {children}
    </Context.Provider>
  );
}
