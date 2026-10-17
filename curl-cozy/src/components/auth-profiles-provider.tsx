import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useInspector } from "./inspector";
import {
  emptyProfiles,
  prepareProfileRequest,
  receiveCookies,
  validateProfiles,
  type AuthProfile,
  type ProfilesDocument,
  type ProfileCookie,
} from "@/lib/auth-profiles";
import { fetchProfiles, saveProfiles } from "@/lib/security-api";
import { resolveReplayRequest, type ReplayVariables } from "@/lib/replay-features";
import type { HttpRequest } from "@/lib/traffic";
interface Store {
  document: ProfilesDocument;
  revision: number;
  ready: boolean;
  dirty: boolean;
  error: string;
  conflict: boolean;
}
export interface ProfileSession {
  profile: AuthProfile | null;
  variables: ReplayVariables;
  resolve: (
    template: HttpRequest,
    variables: ReplayVariables,
    stripCredentials?: string[],
  ) => HttpRequest;
  receive: (url: string, cookies: string[]) => void;
  commit: (updates: ReplayVariables) => Promise<void>;
}
interface State {
  document: ProfilesDocument;
  ready: boolean;
  dirty: boolean;
  error: string;
  workspace: string | null;
  update: (fn: (doc: ProfilesDocument) => ProfilesDocument) => void;
  reload: () => void;
  retry: () => void;
  createSession: (id?: string | null, base?: ReplayVariables) => ProfileSession;
}
const Context = createContext<State | null>(null);
const TEMP = "@temporary";
const initial = (ready = false): Store => ({
  document: emptyProfiles(),
  revision: 0,
  ready,
  dirty: false,
  error: "",
  conflict: false,
});
// Optional outside the root provider to support embedding the existing Replay/Flows views.
export const useAuthProfiles = () => useContext(Context);
export function AuthProfilesProvider({ children }: { children: ReactNode }) {
  const { session, getReplayWorkspace } = useInspector();
  const workspace = session?.target === "workspace" ? session.workspace_id : null;
  const key = workspace ?? TEMP;
  const [stores, setStores] = useState<Record<string, Store>>({ [TEMP]: initial(true) });
  const ref = useRef(stores);
  ref.current = stores;
  const queues = useRef(new Map<string, Promise<void>>());
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  const loading = useRef(new Set<string>());
  const change = (id: string, fn: (store: Store) => Store) => {
    const next = { ...ref.current, [id]: fn(ref.current[id] ?? initial()) };
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
        const snapshot = structuredClone(entry.document);
        try {
          const result = await saveProfiles(id, entry.revision, snapshot);
          change(id, (s) => ({
            ...s,
            revision: result.revision,
            dirty: JSON.stringify(s.document) !== JSON.stringify(snapshot),
            error: "",
          }));
        } catch (error) {
          const message = error instanceof Error ? error.message : "Could not save profiles";
          change(id, (s) => ({
            ...s,
            error: message,
            conflict: /another browser|changed in|409/i.test(message),
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
    try {
      await queues.current.get(id)?.catch(() => {});
      const result = await fetchProfiles(id);
      validateProfiles(result.document);
      change(id, () => ({
        document: result.document,
        revision: result.revision,
        ready: true,
        dirty: false,
        error: "",
        conflict: false,
      }));
    } catch (error) {
      change(id, (s) => ({
        ...s,
        error: error instanceof Error ? error.message : "Could not load profiles",
      }));
    } finally {
      loading.current.delete(id);
    }
  };
  useEffect(() => {
    if (workspace && !ref.current[key]?.ready) void load(workspace);
    return () => {
      if (workspace) void persist(workspace).catch(() => {});
    };
  }, [workspace]);
  useEffect(
    () => () => {
      for (const id of timers.current.keys()) void persist(id).catch(() => {});
    },
    [],
  );
  const edit = (id: string, fn: (doc: ProfilesDocument) => ProfilesDocument) => {
    const entry = ref.current[id];
    if (!entry?.ready) throw Error("Wait for profiles to load.");
    const document = fn(entry.document);
    validateProfiles(document);
    change(id, (s) => ({ ...s, document, dirty: id !== TEMP }));
    if (id !== TEMP) {
      clearTimeout(timers.current.get(id));
      timers.current.set(
        id,
        setTimeout(() => {
          void persist(id).catch(() => {});
        }, 500),
      );
    }
  };
  const createSession = (profileId?: string | null, base: ReplayVariables = {}): ProfileSession => {
    const source = ref.current[key];
    const selected = profileId === undefined ? source?.document.active : profileId;
    if (!source?.ready) throw Error("Wait for profiles to load.");
    const stored = selected ? source?.document.profiles.find((p) => p.id === selected) : null;
    if (selected && !stored) throw Error("Selected profile no longer exists.");
    const profile = stored ? structuredClone(stored) : null;
    let jar: ProfileCookie[] = profile?.cookies ?? [];
    const variables = { ...base, ...profile?.variables };
    const destination = workspace,
      storeKey = key;
    const current = () => getReplayWorkspace() === destination;
    return {
      profile,
      variables,
      resolve: (template, values, stripCredentials) => {
        const managed = profile
          ? ["authorization", "cookie", ...Object.keys(profile.headers).map((k) => k.toLowerCase())]
          : [];
        const source = managed.length
          ? {
              ...template,
              headers: Object.fromEntries(
                Object.entries(template.headers).filter(
                  ([name]) => !managed.includes(name.toLowerCase()),
                ),
              ),
            }
          : template;
        let request = resolveReplayRequest(source, values);
        if (stripCredentials)
          request = {
            ...request,
            headers: Object.fromEntries(
              Object.entries(request.headers).filter(
                ([name]) =>
                  !/^(authorization|cookie)$/i.test(name) &&
                  !stripCredentials.some((key) => key.toLowerCase() === name.toLowerCase()),
              ),
            ),
          };
        return profile ? prepareProfileRequest(request, profile, values, jar) : request;
      },
      receive: (url, lines) => {
        if (!profile || !current()) return;
        jar = receiveCookies(jar, url, lines);
        try {
          edit(storeKey, (doc) => ({
            ...doc,
            profiles: doc.profiles.map((p) =>
              p.id === profile.id ? { ...p, cookies: receiveCookies(p.cookies, url, lines) } : p,
            ),
          }));
        } catch (error) {
          change(storeKey, (s) => ({
            ...s,
            error: `Cookies could not be saved: ${error instanceof Error ? error.message : "Invalid cookie jar"}`,
          }));
        }
      },
      commit: async (updates) => {
        if (!profile) throw Error("No profile selected.");
        if (!current()) throw Error("Workspace changed; profile updates were discarded.");
        edit(storeKey, (doc) => {
          if (!doc.profiles.some((p) => p.id === profile.id)) throw Error("Profile was deleted.");
          return {
            ...doc,
            profiles: doc.profiles.map((p) =>
              p.id === profile.id ? { ...p, variables: { ...p.variables, ...updates } } : p,
            ),
          };
        });
        await persist(storeKey);
      },
    };
  };
  const entry = stores[key] ?? initial();
  return (
    <Context.Provider
      value={{
        workspace,
        document: entry.document,
        ready: entry.ready,
        dirty: entry.dirty,
        error: entry.error,
        update: (fn) => edit(key, fn),
        reload: () => {
          void load(key);
        },
        retry: () => {
          if (!entry.ready) void load(key);
          else void persist(key).catch(() => {});
        },
        createSession,
      }}
    >
      {children}
    </Context.Provider>
  );
}
