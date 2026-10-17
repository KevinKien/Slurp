import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { sendHttpRequest } from "@/lib/replay.functions";
import { useInspector } from "./inspector";
import { useAuthProfiles } from "./auth-profiles-provider";
import { MatrixRunner, type MatrixPlan, type MatrixRun } from "@/lib/authorization-matrix";
import { saveMatrixRun } from "@/lib/security-api";
interface State {
  run: MatrixRun | null;
  localRuns: MatrixRun[];
  busy: boolean;
  error: string;
  start: (plan: MatrixPlan) => void;
  stop: () => void;
  retrySave: () => void;
}
const Context = createContext<State | null>(null);
export const useMatrix = () => {
  const state = useContext(Context);
  if (!state) throw Error("Matrix provider missing");
  return state;
};
export function MatrixProvider({ children }: { children: ReactNode }) {
  const auth = useAuthProfiles()!,
    { session, getReplayWorkspace, variables, timeout } = useInspector();
  const workspace = session?.target === "workspace" ? session.workspace_id : null,
    key = workspace ?? "@temporary";
  const send = sendHttpRequest;
  const runner = useRef<{ workspace: string | null; engine: MatrixRunner } | null>(null);
  const [runs, setRuns] = useState<Record<string, MatrixRun[]>>({}),
    [active, setActive] = useState<{ workspace: string | null; run: MatrixRun } | null>(null),
    [errors, setErrors] = useState<Record<string, string>>({});
  const persist = (destination: string | null, run: MatrixRun) => {
    if (!destination) return;
    void saveMatrixRun(destination, run).then(
      () => setErrors((prev) => ({ ...prev, [destination]: "" })),
      (error) =>
        setErrors((prev) => ({
          ...prev,
          [destination]: error instanceof Error ? error.message : "Could not save matrix evidence",
        })),
    );
  };
  useEffect(() => {
    if (runner.current && runner.current.workspace !== workspace) runner.current.engine.stop();
  }, [workspace]);
  useEffect(() => () => runner.current?.engine.stop(), []);
  const start = (plan: MatrixPlan) => {
    if (runner.current?.engine.active) throw Error("Stop the current matrix run first.");
    if (!auth.ready) throw Error("Wait for profiles to load.");
    const destination = workspace;
    const identities = Object.fromEntries(
      plan.identities.map((identity) => [
        identity.id,
        auth.createSession(identity.id === "@anonymous" ? null : identity.id, variables),
      ]),
    );
    const engine = new MatrixRunner(plan, {
      identities,
      send: (request) => send({ data: { ...request, method: request.method as "GET", timeout } }),
      isCurrent: () => getReplayWorkspace() === destination,
      onChange: (run) => {
        setActive({ workspace: destination, run });
        setRuns((prev) => ({
          ...prev,
          [destination ?? "@temporary"]: [
            run,
            ...(prev[destination ?? "@temporary"] ?? []).filter((r) => r.id !== run.id),
          ].slice(0, 10),
        }));
        if (run.status !== "running") persist(destination, run);
      },
    });
    runner.current = { workspace: destination, engine };
    void engine.start();
  };
  return (
    <Context.Provider
      value={{
        run: active?.workspace === workspace ? active.run : null,
        localRuns: runs[key] ?? [],
        busy: !!runner.current?.engine.active,
        start,
        stop: () => runner.current?.engine.stop(),
        error: errors[key] ?? "",
        retrySave: () => {
          if (active?.workspace === workspace) persist(workspace, active.run);
        },
      }}
    >
      {children}
    </Context.Provider>
  );
}
