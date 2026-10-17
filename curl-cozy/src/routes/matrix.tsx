import { createFileRoute } from "@tanstack/react-router";
import { MatrixView } from "@/components/authorization-matrix";
export const Route = createFileRoute("/matrix")({
  head: () => ({ meta: [{ title: "Authorization Matrix — Slurp" }] }),
  component: MatrixView,
});
