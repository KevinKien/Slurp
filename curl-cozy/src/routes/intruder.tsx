import { createFileRoute } from "@tanstack/react-router";
import { IntruderView } from "@/components/intruder";
export const Route = createFileRoute("/intruder")({
  head: () => ({ meta: [{ title: "Intruder — Slurp" }] }),
  component: IntruderView,
});
