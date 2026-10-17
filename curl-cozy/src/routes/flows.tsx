import { createFileRoute } from "@tanstack/react-router";
import { FlowsView } from "@/components/flows";
export const Route = createFileRoute("/flows")({
  head: () => ({
    meta: [
      { title: "Flows — Slurp" },
      { name: "description", content: "Build, run and compare multi-step API workflows." },
    ],
  }),
  component: FlowsView,
});
