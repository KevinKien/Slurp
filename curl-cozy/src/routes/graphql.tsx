import { createFileRoute } from "@tanstack/react-router";
import { GraphqlView } from "@/components/graphql";

export const Route = createFileRoute("/graphql")({
  head: () => ({
    meta: [
      { title: "GraphQL — Slurp" },
      { name: "description", content: "Explore a GraphQL schema, build operations and send them." },
    ],
  }),
  component: GraphqlView,
});
