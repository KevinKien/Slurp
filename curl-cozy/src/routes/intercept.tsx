import { createFileRoute } from '@tanstack/react-router';
import { InterceptView } from '@/components/intercept';

export const Route = createFileRoute('/intercept')({
  head: () => ({
    meta: [
      { title: 'Intercept — Slurp' },
      { name: 'description', content: 'Hold HTTP requests and responses, review or edit them, then forward them on.' },
      { property: 'og:title', content: 'Intercept — Slurp' },
      { property: 'og:type', content: 'website' },
    ],
  }),
  component: InterceptView,
});
