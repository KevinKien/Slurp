import { createContext, useContext } from "react";
import type { HttpRequest } from "./traffic";
import type { IntruderConfig, IntruderRun, IntruderResult } from "./intruder";
interface State {
  workspace: string | null;
  config: IntruderConfig;
  ready: boolean;
  dirty: boolean;
  error: string;
  update: (config: IntruderConfig) => void;
  receive: (request: HttpRequest) => void;
  retry: () => void;
  reload: () => void;
  run: IntruderRun | null;
  localRuns: IntruderRun[];
  results: IntruderResult[];
  getLocalResults: (id: string) => IntruderResult[];
  active: boolean;
  starting: boolean;
  start: () => Promise<void>;
  pause: () => void;
  resume: () => void;
  stop: () => void;
  runError: string;
  retryEvidence: () => Promise<void>;
}
export const Context = createContext<State | null>(null);
export const useIntruder = () => useContext(Context);
