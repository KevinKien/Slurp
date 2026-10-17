import { createFileRoute } from "@tanstack/react-router";
import { ToolsView } from "@/components/tools";

export const Route = createFileRoute("/tools")({
  head: () => ({ meta: [{ title: "Tools — Slurp" }] }),
  component: ToolsView,
});
