import { useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { Button } from "./ui/button";
import { useAuthProfiles } from "./auth-profiles-provider";
import { newProfile, validateProfiles, type AuthProfile } from "@/lib/auth-profiles";
import { flowId } from "@/lib/flows";
export function ProfileSelector() {
  const auth = useAuthProfiles();
  if (!auth) return null;
  return (
    <label className="flex items-center gap-2 text-xs">
      <span>Profile</span>
      <select
        aria-label="Authentication profile"
        className="inspector-input max-w-44 text-xs"
        disabled={!auth.ready}
        value={auth.document.active ?? ""}
        onChange={(e) => auth.update((doc) => ({ ...doc, active: e.target.value || null }))}
      >
        <option value="">None (request credentials)</option>
        {auth.document.profiles.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}
          </option>
        ))}
      </select>
      <Link to="/profiles" className="text-primary hover:underline">
        Manage
      </Link>
      {auth.error && (
        <span title={auth.error} className="text-destructive">
          Profile changes not saved
        </span>
      )}
    </label>
  );
}
export function ProfilesView() {
  const auth = useAuthProfiles();
  if (!auth) return <p className="p-6">Profiles are unavailable.</p>;
  return <ProfilesWorkspace key={auth.workspace ?? "temporary"} />;
}
function ProfilesWorkspace() {
  const auth = useAuthProfiles()!;
  const [selected, setSelected] = useState(""),
    [draft, setDraft] = useState<AuthProfile | null>(null),
    [headers, setHeaders] = useState("{}"),
    [variables, setVariables] = useState("{}"),
    [error, setError] = useState("");
  const profile =
    auth.document.profiles.find((p) => p.id === selected) ?? auth.document.profiles[0];
  useEffect(() => {
    setDraft(profile ? structuredClone(profile) : null);
    setHeaders(JSON.stringify(profile?.headers ?? {}, null, 2));
    setVariables(JSON.stringify(profile?.variables ?? {}, null, 2));
    setError("");
  }, [profile?.id]);
  const safely = (fn: () => void) => {
    try {
      fn();
      setError("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Profile update failed");
    }
  };
  const save = () =>
    safely(() => {
      if (!draft) return;
      const value = {
        ...draft,
        origins: draft.origins.map((s) => s.trim()).filter(Boolean),
        headers: JSON.parse(headers),
        variables: JSON.parse(variables),
        cookies: profile?.cookies ?? [],
      };
      const next = {
        ...auth.document,
        profiles: auth.document.profiles.map((p) => (p.id === value.id ? value : p)),
      };
      validateProfiles(next);
      auth.update(() => next);
    });
  const add = () =>
    safely(() => {
      const value = newProfile();
      auth.update((doc) => ({ ...doc, profiles: [...doc.profiles, value] }));
      setSelected(value.id);
    });
  return (
    <div className="h-full overflow-auto p-6 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Profiles</h1>
          <p className="mt-2 text-muted-foreground">
            Keep account credentials, variables and cookies separate across Replay, Flows and
            Authorization Matrix.
          </p>
        </div>
        <Button size="sm" disabled={!auth.ready} onClick={add}>
          New profile
        </Button>
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <ProfileSelector />
        <span className="text-muted-foreground">
          {!auth.workspace
            ? "Temporary: lost on reload"
            : auth.dirty
              ? "Unsaved changes"
              : "Saved with this workspace"}
        </span>
        <a
          href="/docs/security-testing.html"
          target="_blank"
          rel="noreferrer"
          className="text-primary hover:underline"
        >
          Documentation
        </a>
      </div>
      {auth.error && (
        <div role="alert" className="mt-3 text-destructive">
          {auth.error}
          <Button variant="ghost" size="sm" onClick={auth.retry}>
            Retry saving
          </Button>
          <Button variant="ghost" size="sm" onClick={auth.reload}>
            Reload profiles (discard local changes)
          </Button>
        </div>
      )}
      {!auth.ready && <p className="mt-5">Loading profiles…</p>}
      {error && (
        <p role="alert" className="mt-3 text-destructive">
          {error}
        </p>
      )}
      {profile && draft ? (
        <div className="mt-6 grid gap-5 lg:grid-cols-[200px_1fr]">
          <div className="space-y-2">
            {auth.document.profiles.map((p) => (
              <Button
                key={p.id}
                variant={p.id === profile.id ? "secondary" : "ghost"}
                className="w-full justify-start"
                onClick={() => setSelected(p.id)}
              >
                {p.name}
              </Button>
            ))}
          </div>
          <div className="min-w-0 space-y-4">
            <label className="block">
              Profile name
              <input
                aria-label="Profile name"
                className="inspector-input mt-1 w-full"
                maxLength={200}
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
            </label>
            <label className="block">
              Allowed origins (one HTTP(S) origin per line)
              <textarea
                aria-label="Profile allowed origins"
                placeholder="https://api.example.com"
                className="inspector-input mt-1 min-h-20 w-full font-mono"
                value={draft.origins.join("\n")}
                onChange={(e) => setDraft({ ...draft, origins: e.target.value.split("\n") })}
              />
            </label>
            <div className="grid gap-4 xl:grid-cols-2">
              <label>
                Headers (JSON object)
                <textarea
                  aria-label="Profile headers"
                  placeholder={'{"Authorization":"Bearer {{token}}"}'}
                  className="inspector-input mt-1 min-h-40 w-full font-mono"
                  value={headers}
                  onChange={(e) => setHeaders(e.target.value)}
                />
              </label>
              <label>
                Variables (JSON object of strings)
                <textarea
                  aria-label="Profile variables"
                  className="inspector-input mt-1 min-h-40 w-full font-mono"
                  value={variables}
                  onChange={(e) => setVariables(e.target.value)}
                />
              </label>
            </div>
            <p className="text-muted-foreground">
              Profile variables override shared Replay variables. Use Authorization: Bearer{" "}
              {"{{token}}"} and save a token with variables.set("token",
              response.json().access_token) in Replay Scripts.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={save}>
                Apply profile
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  safely(() => {
                    const copy = {
                      ...structuredClone(profile),
                      id: flowId(),
                      name: `${profile.name} copy`.slice(0, 200),
                      cookies: [],
                    };
                    auth.update((doc) => ({ ...doc, profiles: [...doc.profiles, copy] }));
                    setSelected(copy.id);
                  })
                }
              >
                Clone without cookies
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() =>
                  safely(() => {
                    auth.update((doc) => ({
                      ...doc,
                      active: doc.active === profile.id ? null : doc.active,
                      profiles: doc.profiles.filter((p) => p.id !== profile.id),
                    }));
                    setSelected("");
                  })
                }
              >
                Delete profile
              </Button>
            </div>
            <div className="flex items-center justify-between border-t border-border pt-4">
              <h2 className="text-sm font-medium">Cookie jar ({profile.cookies.length})</h2>
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  auth.update((doc) => ({
                    ...doc,
                    profiles: doc.profiles.map((p) =>
                      p.id === profile.id ? { ...p, cookies: [] } : p,
                    ),
                  }))
                }
              >
                Clear cookies
              </Button>
            </div>
            <div className="overflow-auto">
              <table className="w-full text-left">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Domain</th>
                    <th>Path</th>
                    <th>Flags</th>
                    <th>Expires</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {profile.cookies.map((c) => (
                    <tr key={`${c.domain}:${c.path}:${c.name}`} className="border-t border-border">
                      <td className="py-2">{c.name}</td>
                      <td>
                        {c.domain}
                        {c.hostOnly ? " (host only)" : ""}
                      </td>
                      <td>{c.path}</td>
                      <td>
                        {[c.secure ? "Secure" : "", c.httpOnly ? "HttpOnly" : "", c.sameSite]
                          .filter(Boolean)
                          .join(", ")}
                      </td>
                      <td>
                        {c.expires === null ? "Session" : new Date(c.expires).toLocaleString()}
                      </td>
                      <td>
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Delete cookie ${c.name}`}
                          onClick={() =>
                            auth.update((doc) => ({
                              ...doc,
                              profiles: doc.profiles.map((p) =>
                                p.id === profile.id
                                  ? {
                                      ...p,
                                      cookies: p.cookies.filter(
                                        (item) =>
                                          !(
                                            item.name === c.name &&
                                            item.domain === c.domain &&
                                            item.path === c.path
                                          ),
                                      ),
                                    }
                                  : p,
                              ),
                            }))
                          }
                        >
                          Remove
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!profile.cookies.length && (
                <p className="py-4 text-muted-foreground">
                  Send a login request with this profile to capture Set-Cookie automatically.
                </p>
              )}
            </div>
          </div>
        </div>
      ) : auth.ready ? (
        <p className="mt-8 text-muted-foreground">
          Create a profile for each account you want to test.
        </p>
      ) : null}
    </div>
  );
}
