import { createFileRoute } from "@tanstack/react-router";
import { ProfilesView } from "@/components/auth-profiles";
export const Route = createFileRoute("/profiles")({
  head: () => ({ meta: [{ title: "Profiles — Slurp" }] }),
  component: ProfilesView,
});
