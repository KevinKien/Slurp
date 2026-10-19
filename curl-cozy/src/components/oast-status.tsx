import { useEffect, useState } from "react";
import { fetchOastStatus } from "@/lib/scan-api";
export function OastStatus() {
  const [message, setMessage] = useState("Checking OAST collector…");
  useEffect(() => {
    let current = true;
    void fetchOastStatus()
      .then((status) => {
        if (current)
          setMessage(
            status.enabled
              ? `OAST collector configured: HTTP${status.dns ? " + DNS" : ""}. The callback address must be reachable from the target.`
              : status.error || "OAST collector is not configured.",
          );
      })
      .catch(() => {
        if (current) setMessage("Could not read OAST collector status.");
      });
    return () => {
      current = false;
    };
  }, []);
  return (
    <p className="text-xs text-muted-foreground" role="status">
      {message}{" "}
      <a className="underline" href="/docs/scan.html#oast" target="_blank" rel="noreferrer">
        OAST setup
      </a>
    </p>
  );
}
