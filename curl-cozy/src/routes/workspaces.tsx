import { createFileRoute } from '@tanstack/react-router';
import { WorkspacesView } from '@/components/workspaces';

export const Route = createFileRoute('/workspaces')({
  head: () => ({
    meta: [
      { title: 'Workspaces — Slurp' },
      { name: 'description', content: 'Organize captured HTTP traffic into workspaces and find old requests again.' },
      { property: 'og:title', content: 'Workspaces — Slurp' },
      { property: 'og:type', content: 'website' },
    ],
  }),
  component: WorkspacesView,
});
