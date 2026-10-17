import { createFileRoute } from '@tanstack/react-router';
import { McpView } from '@/components/mcp-docs';

export const Route = createFileRoute('/mcp')({
  head: () => ({
    meta: [
      { title: 'MCP — Slurp' },
      { name: 'description', content: 'Connect AI assistants to captured HTTP traffic through the MCP server.' },
      { property: 'og:title', content: 'MCP — Slurp' },
      { property: 'og:type', content: 'website' },
    ],
  }),
  component: McpView,
});
