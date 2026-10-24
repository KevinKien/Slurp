import { useEffect, useState } from "react";
import { toast } from "sonner";
import { scanChecks, type ScanPlan, type CheckId } from "@/lib/scan";
import { defaultScanPolicy, metadata } from "@/lib/scan/registry";
import { Button } from "./ui/button";

type Profile = { id: string; name: string; mode: "passive" | "active"; checks: CheckId[] };
const storageKey = "slurp.scan-profiles.v1";
const specialized: Profile[] = [
  { id: "default-discovery-passive", name: "Parameter discovery (captured)", mode: "passive", checks: ["parameter-hints"] },
  {
    id: "default-discovery",
    name: "Hidden input discovery",
    mode: "active",
    checks: ["hidden-parameters"],
  },
  {
    id: "default-business",
    name: "Business input validation",
    mode: "active",
    checks: ["business-negative", "business-dates"],
  },
  {
    id: "default-jwt-keys",
    name: "JWT key-source attacks",
    mode: "active",
    checks: ["jwt-jwk", "jwt-jku", "jwt-x5u", "jwt-kid"],
  },
  {
    id: "default-jwt-confusion",
    name: "JWT algorithm confusion",
    mode: "active",
    checks: ["jwt-signature", "jwt-confusion"],
  },
  { id: "default-cors", name: "CORS policy", mode: "active", checks: ["cors", "cors-trust"] },
  {
    id: "default-jwt-local",
    name: "JWT weak signing secret (local)",
    mode: "passive",
    checks: ["jwt-weak-secret"],
  },
  {
    id: "default-nosql",
    name: "NoSQL parser audit",
    mode: "active",
    checks: ["nosql-injection", "nosql-operators"],
  },
  {
    id: "default-dependencies",
    name: "JavaScript dependencies (OSV)",
    mode: "passive",
    checks: ["dependency-audit"],
  },
  { id: "default-jwt", name: "JWT active", mode: "active", checks: ["jwt-signature"] },
  {
    id: "default-graphql",
    name: "GraphQL active",
    mode: "active",
    checks: ["graphql-introspection", "graphql-batching"],
  },
  {id:"default-host-header",name:"Host header injection",mode:"active",checks:["host-header"]},
  {
    id: "default-protocol",
    name: "HTTP protocol",
    mode: "active",
    checks: ["http-framing", "http-methods", "header-injection"],
  },
];
const defaults: Profile[] = [
  {
    id: "default-passive",
    name: "Passive audit",
    mode: "passive",
    checks: scanChecks.filter((c) => !c.active).map((c) => c.id),
  },
  {
    id: "default-active",
    name: "Active standard",
    mode: "active",
    checks: scanChecks
      .filter(
        (c) =>
          c.active &&
          metadata(c.id).impact !== "intrusive" &&
          metadata(c.id).category !== "Browser" &&
          metadata(c.id).category !== "OAST",
      )
      .map((c) => c.id),
  },
  {
    id: "default-browser-xss",
    name: "Browser XSS",
    mode: "active",
    checks: ["browser-xss", "dom-xss"],
  },
  ...specialized,
];
function load(): Profile[] {
  try {
    const data: unknown = JSON.parse(localStorage.getItem(storageKey) ?? "null");
    if (Array.isArray(data))
      return [
        ...data.filter(
          (p): p is Profile =>
            p &&
            typeof p.id === "string" &&
            typeof p.name === "string" &&
            p.name.trim() &&
            ["passive", "active"].includes(p.mode) &&
            Array.isArray(p.checks) &&
            p.checks.every((id: unknown) =>
              scanChecks.some((c) => c.id === id && c.active === (p.mode === "active")),
            ),
        ),
        ...specialized.filter((p) => !data.some((saved) => saved?.id === p.id)),
      ];
  } catch {
    /* Use built-in profiles if browser storage is unavailable. */
  }
  return defaults;
}
export function applyScanProfile(plan: ScanPlan, profile: Profile): ScanPlan {
  const intrusive = profile.checks.some((id) => metadata(id).impact === "intrusive");
  return {
    ...plan,
    mode: profile.mode,
    checks: [...profile.checks],
    allowSending: false,
    policy: {
      ...defaultScanPolicy,
      maxImpact: intrusive ? "intrusive" : profile.mode === "passive" ? "passive" : "medium",
      includeExperimental: true,
      allowIntrusive: intrusive,
    },
  };
}
export function ScanProfilePicker({
  plan,
  onChange,
}: {
  plan: ScanPlan;
  onChange: (plan: ScanPlan) => void;
}) {
  const [profiles, setProfiles] = useState(load);
  const [selected, setSelected] = useState("");
  const [editing, setEditing] = useState<Profile | null>(null);
  const mode = plan.mode === "passive" ? "passive" : "active";
  const available = profiles.filter((p) => p.mode === mode);
  const requestKey = JSON.stringify(plan.request);
  useEffect(() => {
    const profile = available.find((p) => p.id === selected) ?? available[0];
    if (profile) {
      setSelected(profile.id);
      onChange(applyScanProfile(plan, profile));
    } else {
      setSelected("");
      onChange({ ...plan, checks: [], allowSending: false });
    }
    setEditing(null);
    // Apply once for each request/mode; edits to parameters must retain the current draft.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestKey, mode]);
  const persist = (next: Profile[]) => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(next));
      setProfiles(next);
      return true;
    } catch {
      toast.error("Could not save scan profiles in browser storage.");
      return false;
    }
  };
  const current = available.find((p) => p.id === selected);
  return (
    <div className="space-y-3 rounded border p-3">
      <h3 className="font-medium text-sm">Scan {mode}</h3>
      <div className="flex flex-wrap gap-2 items-center">
        <label className="text-sm">
          Scan profile{" "}
          <select
            aria-label="Scan profile"
            className="rounded border bg-background p-2"
            value={selected}
            onChange={(e) => {
              const profile = available.find((p) => p.id === e.target.value);
              if (profile) {
                setSelected(profile.id);
                setEditing(null);
                onChange(applyScanProfile(plan, profile));
              }
            }}
          >
            <option value="" disabled>
              Select profile
            </option>
            {available.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() =>
            setEditing({
              id: crypto.randomUUID(),
              name: "",
              mode,
              checks: current ? [...current.checks] : [],
            })
          }
        >
          Create profile
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={!current}
          onClick={() => current && setEditing(structuredClone(current))}
        >
          Edit profile
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={!current}
          onClick={() => {
            const next = profiles.filter((p) => p.id !== selected);
            if (persist(next)) {
              const fallback = next.find((p) => p.mode === mode);
              setSelected(fallback?.id ?? "");
              setEditing(null);
              onChange(
                fallback
                  ? applyScanProfile(plan, fallback)
                  : { ...plan, checks: [], allowSending: false },
              );
            }
          }}
        >
          Delete profile
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        {plan.checks.length} checks selected. Profiles are saved in this browser and shared across
        workspaces.
      </p>
      {plan.checks.includes("dependency-audit") && (
        <p className="text-xs text-muted-foreground">
          OSV lookup sends library names and versions only. JavaScript source and target credentials
          stay local.
        </p>
      )}
      {current && !editing && (
        <details>
          <summary className="cursor-pointer text-xs">View selected checks</summary>
          <ul className="list-disc pl-5 text-xs">
            {current.checks.map((id) => (
              <li key={id}>{scanChecks.find((c) => c.id === id)?.name}</li>
            ))}
          </ul>
        </details>
      )}
      {editing && (
        <div className="space-y-3 border-t pt-3">
          <label className="text-sm">
            Profile name{" "}
            <input
              aria-label="Scan profile name"
              className="rounded border bg-background p-2"
              maxLength={80}
              value={editing.name}
              onChange={(e) => setEditing({ ...editing, name: e.target.value })}
            />
          </label>
          <div className="grid gap-2 sm:grid-cols-2">
            {scanChecks
              .filter((c) => c.active === (mode === "active"))
              .map((c) => (
                <label key={c.id} className="flex gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={editing.checks.includes(c.id)}
                    onChange={(e) =>
                      setEditing({
                        ...editing,
                        checks: e.target.checked
                          ? [...editing.checks, c.id]
                          : editing.checks.filter((id) => id !== c.id),
                      })
                    }
                  />
                  <span>
                    {c.name}
                    {metadata(c.id).category === "Browser" && (
                      <span className="block text-xs text-muted-foreground">
                        Requires Chrome or Chromium on the Slurp host.
                      </span>
                    )}
                    {metadata(c.id).category === "OAST" && (
                      <span className="block text-xs text-muted-foreground">
                        Requires a reachable OAST collector.{" "}
                        <a
                          className="underline"
                          href="/docs/scan.html#oast"
                          target="_blank"
                          rel="noreferrer"
                        >
                          Setup guide
                        </a>
                      </span>
                    )}
                    {metadata(c.id).impact === "intrusive" && (
                      <span className="block text-xs text-amber-500">
                        Intrusive: selecting this check enables intrusive probes.
                      </span>
                    )}
                    {metadata(c.id).status === "experimental" && (
                      <span className="block text-xs text-muted-foreground">Experimental</span>
                    )}
                  </span>
                </label>
              ))}
          </div>
          <Button
            type="button"
            size="sm"
            disabled={!editing.name.trim() || !editing.checks.length}
            onClick={() => {
              const saved = { ...editing, name: editing.name.trim() };
              const next = [...profiles.filter((p) => p.id !== saved.id), saved];
              if (persist(next)) {
                setSelected(saved.id);
                onChange(applyScanProfile(plan, saved));
                setEditing(null);
              }
            }}
          >
            Save profile
          </Button>{" "}
          <Button type="button" size="sm" variant="outline" onClick={() => setEditing(null)}>
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
}
