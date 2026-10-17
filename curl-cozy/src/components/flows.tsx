import { ProfileSelector } from './auth-profiles';
import { useEffect, useState } from "react";
import { ArrowDown, ArrowUp, Copy, Play, Plus, Trash2, Workflow } from "lucide-react";
import { Button } from "./ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./ui/dialog";
import { useInspector } from "./inspector";
import { useFlows } from "./flows-provider";
import { FlowStepEditor, FlowVariablesForm } from "./flow-forms";
import { FlowRuns } from "./flow-runs";
import {
  flowId,
  newFlow,
  newFlowStep,
  validateFlow,
  type Flow,
  type FlowRun,
  type FlowStep,
} from "@/lib/flows";
import type { FlowRunOptions } from "@/lib/flow-runner";
export function FlowsView() {
  const { workspace } = useFlows();
  return <FlowsWorkspaceView key={workspace ?? "@temporary"} />;
}
function FlowsWorkspaceView() {
  const state = useFlows(),
    { sessions, variables: replayVariables } = useInspector();
  const [tab, setTab] = useState<"build" | "runs">("build"),
    [stepId, setStepId] = useState(""),
    [name, setName] = useState(""),
    [error, setError] = useState(""),
    [variablesOpen, setVariablesOpen] = useState(false),
    [replayTab, setReplayTab] = useState("");
  const flow =
    state.document.flows.find((flow) => flow.id === state.document.active) ??
    state.document.flows[0];
  const step = flow?.steps.find((step) => step.id === stepId) ?? flow?.steps[0];
  const busy =
    !!state.activeRun &&
    (["running", "paused"].includes(state.activeRun.status) ||
      state.activeRun.sendingIndex !== null);
  useEffect(() => {
    setName(flow?.name ?? "");
    setStepId("");
    setError("");
    setVariablesOpen(false);
  }, [flow?.id]);
  const safely = (fn: () => void) => {
    try {
      fn();
      setError("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Flow operation failed");
    }
  };
  const replace = (value: Flow) => {
    state.update({
      ...state.document,
      flows: state.document.flows.map((flow) => (flow.id === value.id ? value : flow)),
    });
  };
  const addFlow = (value: Flow) => {
    state.update({ flows: [...state.document.flows, value], active: value.id });
    setTab("build");
  };
  const cloneFlow = (source: Flow, variables = source.variables) => {
    const copy = structuredClone(source);
    addFlow({
      ...copy,
      id: flowId(),
      name: `${source.name} copy`.slice(0, 200),
      variables: structuredClone(variables),
      steps: copy.steps.map((step) => ({ ...step, id: flowId() })),
    });
  };
  const start = (flow: Flow, options?: FlowRunOptions) =>
    safely(() => {
      state.start(flow, options);
      setTab("runs");
    });
  const addStep = (value: FlowStep) => {
    if (!flow) return;
    replace({ ...flow, steps: [...flow.steps, value] });
    setStepId(value.id);
  };
  const move = (source: string, target: number) => {
    if (!flow) return;
    const from = flow.steps.findIndex((step) => step.id === source);
    if (from < 0 || target < 0 || target >= flow.steps.length) return;
    const steps = [...flow.steps],
      item = steps.splice(from, 1)[0]!;
    steps.splice(target, 0, item);
    replace({ ...flow, steps });
  };
  const cloneRun = (run: FlowRun) => safely(() => cloneFlow(run.flow, run.initialVariables));
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <header className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-border px-6 py-4">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold">
            <Workflow className="size-5" />
            Flows
          </h1>
          <div className="mt-3"><ProfileSelector/></div>
          <p className="mt-1 text-xs text-muted-foreground">
            Build and test API sequences with isolated run variables.{" "}
            <a
              href="/docs/flows.html"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              Documentation ↗
            </a>
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Selected flow"
            className="inspector-input max-w-64 text-xs"
            disabled={!state.ready}
            value={flow?.id ?? ""}
            onChange={(e) =>
              safely(() => state.update({ ...state.document, active: e.target.value }))
            }
          >
            <option value="" disabled>
              Select a flow
            </option>
            {state.document.flows.map((flow) => (
              <option key={flow.id} value={flow.id}>
                {flow.name}
              </option>
            ))}
          </select>
          <Button
            variant="outline"
            size="sm"
            disabled={!state.ready || state.document.flows.length >= 50}
            onClick={() => safely(() => addFlow(newFlow()))}
          >
            <Plus />
            New flow
          </Button>
          {flow && (
            <Button
              size="sm"
              disabled={!state.ready || busy || !flow.steps.some((step) => step.enabled)}
              onClick={() => start(flow)}
            >
              <Play />
              Run flow
            </Button>
          )}
        </div>
      </header>
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-border px-6 py-2 text-xs">
        <Button
          variant={tab === "build" ? "secondary" : "ghost"}
          size="sm"
          onClick={() => setTab("build")}
        >
          Build
        </Button>
        <Button
          variant={tab === "runs" ? "secondary" : "ghost"}
          size="sm"
          onClick={() => setTab("runs")}
        >
          Runs & comparison
        </Button>
        <span className="ml-auto text-muted-foreground">
          {state.workspace
            ? state.dirty
              ? "Saving changes…"
              : "Saved to workspace"
            : "Temporary session · changes are lost on reload"}
        </span>
        {state.activeRun && (
          <Button
            variant="ghost"
            size="sm"
            className="max-w-72 truncate"
            onClick={() => setTab("runs")}
          >
            {state.activeRun.flow.name} · {state.activeRun.status}
          </Button>
        )}
      </div>
      {state.loading && (
        <p role="status" className="px-6 py-3 text-xs">
          Loading flows…
        </p>
      )}
      {(error || state.error) && (
        <div
          role="alert"
          className="flex shrink-0 flex-wrap items-center gap-2 border-b border-destructive/40 px-6 py-3 text-xs text-destructive"
        >
          {error || state.error}
          {state.error && (
            <Button variant="ghost" size="sm" onClick={state.retry}>
              Retry flow storage
            </Button>
          )}
        </div>
      )}
      {tab === "runs" ? (
        <div className="min-h-0 flex-1 overflow-auto">
          <FlowRuns onStart={start} onClone={cloneRun} />
        </div>
      ) : !flow ? (
        <div className="flex min-h-48 flex-1 flex-col items-center justify-center gap-3 px-6 text-center">
          <Workflow className="size-10 text-muted-foreground" />
          <p className="text-sm">
              Create a flow to organize and run a sequence of API requests.
          </p>
          <p className="text-xs text-muted-foreground">
            Start with a blank step or copy requests from your Replay tabs. No requests are sent
            until you run the flow.
          </p>
        </div>
      ) : (
        <>
          <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-4 py-3">
            <input
              aria-label="Flow name"
              className="inspector-input min-w-28 flex-1 text-xs"
              value={name}
              maxLength={200}
              onChange={(e) => setName(e.target.value)}
            />
            <Button
              variant="outline"
              size="sm"
              onClick={() => safely(() => replace({ ...flow, name: name.trim() }))}
            >
              Rename flow
            </Button>
            <Button variant="outline" size="sm" onClick={() => setVariablesOpen(true)}>
              Initial variables ({Object.keys(flow.variables).length})
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={state.document.flows.length >= 50}
              onClick={() => safely(() => cloneFlow(flow))}
            >
              <Copy />
              Clone flow
            </Button>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Delete flow"
              title="Delete definition; run history is retained"
              onClick={() =>
                safely(() =>
                  state.update({
                    flows: state.document.flows.filter((item) => item.id !== flow.id),
                    active: state.document.flows.find((item) => item.id !== flow.id)?.id ?? null,
                  }),
                )
              }
            >
              <Trash2 />
            </Button>
          </div>
          <div className="min-h-0 flex-1 overflow-auto">
            <div className="grid min-h-full md:grid-cols-[260px_minmax(0,1fr)]">
              <section className="space-y-3 border-b border-border p-4 md:border-b-0 md:border-r">
                <div className="flex items-center justify-between">
                  <h2 className="text-xs font-medium">Steps ({flow.steps.length}/50)</h2>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={flow.steps.length >= 50}
                    onClick={() =>
                      safely(() => addStep(newFlowStep(undefined, `Step ${flow.steps.length + 1}`)))
                    }
                  >
                    <Plus />
                    Add step
                  </Button>
                </div>
                <div className="flex gap-1">
                  <select
                    aria-label="Replay tab to add"
                    className="inspector-input min-w-0 flex-1 text-xs"
                    value={replayTab}
                    onChange={(e) => setReplayTab(e.target.value)}
                  >
                    <option value="">Choose Replay tab</option>
                    {sessions.map((session) => (
                      <option key={session.id} value={session.id}>
                        {session.name}
                      </option>
                    ))}
                  </select>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={!replayTab || flow.steps.length >= 50}
                    onClick={() =>
                      safely(() => {
                        const selected = sessions.find((tab) => tab.id === Number(replayTab));
                        if (!selected) throw Error("Replay tab no longer exists.");
                        addStep({
                          ...newFlowStep(selected.request, selected.name),
                          afterResponse: selected.afterResponse ?? "",
                        });
                      })
                    }
                  >
                    Add
                  </Button>
                </div>
                <p className="text-[10px] text-muted-foreground">
                  Drag steps or use arrows to reorder. Changes apply to future runs.
                </p>
                {flow.steps.map((item, index) => (
                  <div
                    key={item.id}
                    draggable
                    onDragStart={(e) => e.dataTransfer.setData("text/plain", item.id)}
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      safely(() => move(e.dataTransfer.getData("text/plain"), index));
                    }}
                    className={`space-y-2 rounded border p-3 text-xs ${item.id === step?.id ? "border-primary bg-primary/5" : "border-border"}`}
                  >
                    <button
                      className="w-full break-words text-left font-medium"
                      onClick={() => setStepId(item.id)}
                    >
                      {index + 1}. {item.name}
                      {!item.enabled ? " · Disabled" : ""}
                      {item.pauseBefore ? " · Pause" : ""}
                    </button>
                    <p className="truncate font-mono text-[10px] text-muted-foreground">
                      {item.request.method} {item.request.url || "Enter a URL"}
                    </p>
                    <div className="flex flex-wrap gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-6"
                        aria-label={`Move step ${index + 1} up`}
                        disabled={index === 0}
                        onClick={() => safely(() => move(item.id, index - 1))}
                      >
                        <ArrowUp />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-6"
                        aria-label={`Move step ${index + 1} down`}
                        disabled={index === flow.steps.length - 1}
                        onClick={() => safely(() => move(item.id, index + 1))}
                      >
                        <ArrowDown />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 px-1 text-[10px]"
                        disabled={busy}
                        onClick={() => start(flow, { startIndex: index, endIndex: index + 1 })}
                      >
                        Run step
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 px-1 text-[10px]"
                        disabled={busy}
                        onClick={() => start(flow, { endIndex: index + 1 })}
                      >
                        Run until here
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="ml-auto size-6"
                        aria-label={`Delete step ${index + 1}`}
                        onClick={() =>
                          safely(() =>
                            replace({
                              ...flow,
                              steps: flow.steps.filter((step) => step.id !== item.id),
                            }),
                          )
                        }
                      >
                        <Trash2 />
                      </Button>
                    </div>
                  </div>
                ))}
              </section>
              <section className="min-w-0 p-4">
                {step ? (
                  <FlowStepEditor
                    key={`${flow.id}:${step.id}`}
                    step={step}
                    onSave={(step) => {
                      const next = {
                        ...flow,
                        steps: flow.steps.map((item) => (item.id === step.id ? step : item)),
                      };
                      validateFlow(next);
                      replace(next);
                    }}
                  />
                ) : (
                  <p className="text-xs text-muted-foreground">
                    Add a step or copy a Replay request to begin.
                  </p>
                )}
              </section>
            </div>
          </div>
          <Dialog open={variablesOpen} onOpenChange={setVariablesOpen}>
            <DialogContent className="max-h-[80vh] max-w-2xl overflow-auto bg-card">
              <DialogHeader>
                <DialogTitle>Flow initial variables</DialogTitle>
                <DialogDescription>
                  New runs copy these values. Extractors and scripts update only the current run,
                  keeping other runs and Replay variables unchanged.
                </DialogDescription>
              </DialogHeader>
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  safely(() => {
                    replace({ ...flow, variables: structuredClone(replayVariables) });
                    setVariablesOpen(false);
                  })
                }
              >
                Copy Replay variables into this flow
              </Button>
              <FlowVariablesForm
                key={flow.id}
                variables={flow.variables}
                onApply={(variables) => {
                  replace({ ...flow, variables });
                  setVariablesOpen(false);
                }}
              />
            </DialogContent>
          </Dialog>
        </>
      )}
    </div>
  );
}
