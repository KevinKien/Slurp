import { createFileRoute } from "@tanstack/react-router";
import { ScanView } from "@/components/scan";
export const Route = createFileRoute("/dashboard")({
  head: () => ({ meta: [{ title: "Dashboard — Slurp" }] }),
  component: ScanView,
});
