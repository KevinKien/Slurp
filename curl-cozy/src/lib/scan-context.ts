import { createContext, useContext } from "react";
import type { HttpRequest } from "./traffic";
import type { ScanPlan, ScanRun } from "./scan/types";
export interface ScanState {
  workspace: string | null;
  draft: ScanPlan | null;
  preparing: boolean;
  configuring: boolean;
  setConfiguring: (open: boolean) => void;
  updateDraft: (plan: ScanPlan) => void;
  prepare: (read: () => HttpRequest | Promise<HttpRequest>) => Promise<void>;
  forget: (id: string) => void;
  run: ScanRun | null;
  localRuns: ScanRun[];
  busy: boolean;
  error: string;
  start: (plan: ScanPlan, profileId?: string | null) => void;
  stop: () => void;
  pause: () => void;
  resume: () => void;
  retrySave: () => Promise<void>;
}
export const ScanContext = createContext<ScanState | null>(null);
export const useOptionalScan = () => useContext(ScanContext);
export const useScan = () => {
  const state = useOptionalScan();
  if (!state) throw Error("Scan provider missing.");
  return state;
};
