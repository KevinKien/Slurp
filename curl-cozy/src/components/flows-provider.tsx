import { useAuthProfiles } from './auth-profiles-provider';
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useInspector } from "./inspector";
import { sendHttpRequest } from "@/lib/replay.functions";
import { runReplayScript } from "@/lib/replay-script";
import { FlowRunner, type FlowRunOptions } from "@/lib/flow-runner";
import {
  emptyFlowDocument,
  normalizeFlowDocument,
  validateFlowDocument,
  type FlowDocument,
  type Flow,
  type FlowRun,
} from "@/lib/flows";
import type { ReplayVariables } from "@/lib/replay-features";
import { fetchFlows, saveFlows, saveFlowRun } from "@/lib/flows-api";
interface WorkspaceState {
  document: FlowDocument;
  loaded: boolean;
  loading: boolean;
  error: string;
  dirty: boolean;
}
interface FlowsState {
  workspace: string | null;
  document: FlowDocument;
  loading: boolean;
  ready: boolean;
  error: string;
  dirty: boolean;
  update: (document: FlowDocument) => void;
  retry: () => void;
  activeRun: FlowRun | null;
  localRuns: FlowRun[];
  start: (flow: Flow, options?: FlowRunOptions) => void;
  resume: (variables: ReplayVariables) => Promise<void>;
  skip: () => Promise<void>;
  stop: () => void;
  runSaveError: string;
  retryRunSave: () => void;
}
const Context = createContext<FlowsState | null>(null);
export const useFlows = () => {
  const state = useContext(Context);
  if (!state) throw Error("Flows provider missing");
  return state;
};
const tempKey = "@temporary";
export function FlowsProvider({ children }: { children: ReactNode }) {
  const authProfiles=useAuthProfiles();
  const { session, timeout, getReplayWorkspace } = useInspector(),
    send = sendHttpRequest;
  const workspace = session?.target === "workspace" ? session.workspace_id : null,
    key = workspace ?? tempKey;
  const [stores, setStores] = useState<Record<string, WorkspaceState>>({
    [tempKey]: {
      document: emptyFlowDocument(),
      loaded: true,
      loading: false,
      error: "",
      dirty: false,
    },
  });
  const storesRef = useRef(stores);
  storesRef.current = stores;
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  const saveQueues = useRef(new Map<string, Promise<void>>());
  const runner = useRef<{ workspace: string | null; engine: FlowRunner } | null>(null);
  const [running, setRunning] = useState<{ workspace: string | null; run: FlowRun } | null>(null);
  const [runs, setRuns] = useState<Record<string, FlowRun[]>>({});
  const [runSaveError, setRunSaveError] = useState("");
  const runQueues = useRef(new Map<string, Promise<void>>());
  const updateStore = (id: string, fn: (state: WorkspaceState) => WorkspaceState) => {
    const prev = storesRef.current[id] ?? {
      document: emptyFlowDocument(),
      loaded: false,
      loading: false,
      error: "",
      dirty: false,
    };
    const next = { ...storesRef.current, [id]: fn(prev) };
    storesRef.current = next;
    setStores(next);
  };
  const persist = (id: string) => {
    clearTimeout(timers.current.get(id));
    timers.current.delete(id);
    const entry = storesRef.current[id];
    if (id === tempKey || !entry?.dirty) return;
    const doc = structuredClone(entry.document);
    const task = (saveQueues.current.get(id) ?? Promise.resolve())
      .catch(() => {})
      .then(() => saveFlows(id, doc));
    saveQueues.current.set(id, task);
    void task.then(
      () => {
        updateStore(id, (state) => ({
          ...state,
          dirty: JSON.stringify(state.document) !== JSON.stringify(doc),
          error: "",
        }));
      },
      (error) => {
        updateStore(id, (state) => ({
          ...state,
          error: `Flow changes could not be saved: ${error instanceof Error ? error.message : "API unavailable"}`,
        }));
      },
    );
  };
  const load = (id: string) => {
    if (id === tempKey) return;
    updateStore(id, (state) => ({ ...state, loading: true, error: "" }));
    void fetchFlows(id)
      .then(
        (raw) => {
          const document = normalizeFlowDocument(raw);
          updateStore(id, (state) =>
            state.dirty
              ? { ...state, loading: false }
              : { document, loaded: true, loading: false, error: "", dirty: false },
          );
        },
        (error) => {
          updateStore(id, (state) => ({
            ...state,
            loading: false,
            error: error instanceof Error ? error.message : "Could not load flows",
          }));
        },
      )
      .catch((error) =>
        updateStore(id, (state) => ({ ...state, loading: false, error: String(error) })),
      );
  };
  useEffect(() => {
    if (runner.current && runner.current.workspace !== workspace && runner.current.engine.active)
      runner.current.engine.stop("Workspace changed. No further steps will be sent.");
    if (workspace && !storesRef.current[key]?.loaded && !storesRef.current[key]?.loading)
      load(workspace);
    return () => {
      if (workspace) persist(workspace);
    };
  }, [workspace]);
  useEffect(
    () => () => {
      runner.current?.engine.stop("Browser session ended.");
      for (const id of timers.current.keys()) persist(id);
    },
    [],
  );
  const queueRun = (destination: string | null, run: FlowRun) => {
    if (!destination) return;
    const queueKey = `${destination}:${run.id}`;
    const task = (runQueues.current.get(queueKey) ?? Promise.resolve())
      .catch(() => {})
      .then(() => saveFlowRun(destination, run));
    runQueues.current.set(queueKey, task);
    void task.then(
      () => {
        if (runner.current?.engine.run.id === run.id) setRunSaveError("");
      },
      (error) => {
        if (runner.current?.engine.run.id === run.id)
          setRunSaveError(
            `Run history could not be saved: ${error instanceof Error ? error.message : "API unavailable"}`,
          );
      },
    );
  };
  const start = (flow: Flow, options?: FlowRunOptions) => {
    if (runner.current?.engine.active)
      throw Error("Stop or finish the current run before starting another.");
    if (workspace && !storesRef.current[key]?.loaded)
      throw Error("Wait for this workspace to load.");
    const destination = workspace;
    const identity=authProfiles?.createSession(options?.profileId,options?.variables??flow.variables);
    const engine = new FlowRunner(
      flow,
      {
        ...(identity && {resolve:identity.resolve}),
        send: async (request) => {
          const result=await send({ data: { ...request, method: request.method as "GET", timeout } });
          if(result.ok && getReplayWorkspace()===destination && runner.current?.engine.run.status!=='stopped')identity?.receive(request.url,result.setCookies??[]);
          return result;
        },
        script: runReplayScript,
        isCurrent: () => getReplayWorkspace() === destination,
        onChange: (run) => {
          setRunning({ workspace: destination, run });
          setRuns((prev) => ({
            ...prev,
            [destination ?? tempKey]: [
              run,
              ...(prev[destination ?? tempKey] ?? []).filter((old) => old.id !== run.id),
            ].slice(0, 10),
          }));
          queueRun(destination, run);
        },
      },
      identity?{...options,variables:options?.parentRunId?{...identity.variables,...options.variables}:identity.variables,...(identity.profile&&{profileId:identity.profile.id,profileName:identity.profile.name})}:options,
    );
    runner.current = { workspace: destination, engine };
    setRunSaveError("");
    void engine.start();
  };
  const entry = stores[key] ?? {
    document: emptyFlowDocument(),
    loaded: false,
    loading: true,
    error: "",
    dirty: false,
  };
  const activeRun = running?.workspace === workspace ? running.run : null;
  return (
    <Context.Provider
      value={{
        workspace,
        document: entry.document,
        loading: entry.loading,
        ready: entry.loaded,
        error: entry.error,
        dirty: entry.dirty,
        update: (document) => {
          validateFlowDocument(document);
          if (!entry.loaded) throw Error("Wait for this workspace to load.");
          updateStore(key, (state) => ({ ...state, document, dirty: !!workspace }));
          if (workspace) {
            clearTimeout(timers.current.get(key));
            timers.current.set(
              key,
              setTimeout(() => persist(key), 700),
            );
          }
        },
        retry: () => {
          if (workspace) {
            if (entry.loaded && entry.dirty) persist(workspace);
            else load(workspace);
          }
        },
        activeRun,
        localRuns: runs[key] ?? [],
        start,
        resume: async (variables) => {
          if (runner.current?.workspace === workspace)
            await runner.current.engine.continue(variables);
        },
        skip: async () => {
          if (runner.current?.workspace === workspace) await runner.current.engine.skip();
        },
        stop: () => runner.current?.engine.stop(),
        runSaveError: running?.workspace === workspace ? runSaveError : "",
        retryRunSave: () => {
          if (running) queueRun(running.workspace, running.run);
        },
      }}
    >
      {children}
    </Context.Provider>
  );
}
