import { createFileRoute } from "@tanstack/react-router";
import { HistoryView } from '@/components/inspector';
export const Route = createFileRoute("/")({
  head: () => ({meta: [
    {title:'HTTP History — Slurp'},
    {name:'description',content:'Inspect HTTP traffic, filter requests and explore request and response details in Slurp.'},
    {property:'og:title',content:'HTTP History — Slurp'},
    {property:'og:description',content:'A focused workspace for HTTP traffic inspection and replay.'},
    {property:'og:type',content:'website'},
    {name:'twitter:card',content:'summary_large_image'},
  ]}),
  component: HistoryView,
});
