import { useEffect, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { fetchInfo } from '@/lib/api';
import { useInspector } from '@/components/inspector';

const FALLBACK_EXE = 'slurp';

/** Quote one argument for a POSIX shell. */
const shq = (v: string) => (/^[\w@%+=:,./-]+$/.test(v) ? v : `'${v.replace(/'/g, `'\\''`)}'`);

function CopyBlock({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard can be unavailable (insecure context); the text stays selectable.
    }
  };
  return (
    <div className="relative rounded border border-border bg-background">
      <Button
        variant="ghost"
        size="icon"
        className="absolute right-1 top-1 size-7 text-muted-foreground"
        aria-label={`Copy ${label}`}
        title="Copy to clipboard"
        onClick={copy}
      >
        {copied ? <Check /> : <Copy />}
      </Button>
      <pre className="overflow-x-auto p-4 pr-12 font-mono text-xs leading-6">{text}</pre>
    </div>
  );
}

const TOOLS: { name: string; summary: string; params: string; destructive?: boolean }[] = [
  { name: 'list_traffic', summary: 'List captured requests (newest first) as compact summaries.', params: 'limit, offset, host, method, status, search, workspace' },
  { name: 'get_traffic', summary: 'One request/response in full: headers and bodies as text (truncated).', params: 'id, max_body_bytes' },
  { name: 'get_stats', summary: 'Request count, bytes, error count and top hosts.', params: 'workspace' },
  { name: 'list_workspaces', summary: 'Workspaces with request counts; "active" is where new traffic is captured.', params: '—' },
  { name: 'search_history', summary: 'Search History by URL/headers, domain, method, status and workspace.', params: 'search, host, method, status, workspace, limit, offset' },
  { name: 'list_replay', summary: 'Read saved Replay tabs and requests.', params: 'workspace' },
  { name: 'create_replay', summary: 'Create a Replay tab from history or a custom request.', params: 'workspace, traffic_id, name, request' },
  { name: 'edit_replay', summary: 'Edit method, URL, headers, body or tab name.', params: 'workspace, tab_id, request, name' },
  { name: 'rename_replay', summary: 'Rename a Replay tab.', params: 'workspace, tab_id, name' },
  { name: 'send_replay', summary: 'Send a saved request to an HTTP(S) target, including localhost and LAN; save and display the response.', params: 'workspace, tab_id, timeout_ms, max_body_bytes' },
  { name: 'clear_traffic', summary: 'Permanently delete traffic: one workspace, or everything when omitted.', params: 'workspace', destructive: true },
];

const PROMPTS = [
  'List the failed requests (status 500) captured in the “Staging” workspace.',
  'Show me the request and response for the last POST to /api/v1/checkout.',
  'Which hosts did my app talk to in the “Login flow” workspace? Summarize the stats.',
  'Compare the headers of the two most recent requests to api.example.com.',
  'Create a Replay tab from the last checkout request, rename it Checkout test, change its JSON body, and send it.',
];

type Client = 'claude-code' | 'json' | 'custom';

export function McpView() {
  const { proxyStatus, workspaces } = useInspector();
  const [exe, setExe] = useState<string | null>(null);
  const [client, setClient] = useState<Client>('claude-code');
  const [useDetectedPath, setUseDetectedPath] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchInfo()
      .then((info) => !cancelled && setExe(info.executable))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const command = useDetectedPath && exe ? exe : FALLBACK_EXE;
  const snippets: Record<Client, { title: string; hint: string; text: string }> = {
    'claude-code': {
      title: 'Claude Code',
      hint: 'Run once in your terminal.',
      text: `claude mcp add slurp -- ${shq(command)} mcp`,
    },
    json: {
      title: 'JSON config',
      hint: 'For Claude Desktop, Cursor and other clients that read an mcpServers block.',
      text: JSON.stringify({ mcpServers: { slurp: { command, args: ['mcp'] } } }, null, 2),
    },
    custom: {
      title: 'Custom API address',
      hint: 'If the proxy API is not on 127.0.0.1:5174, pass its address.',
      text: `${shq(command)} mcp --api http://127.0.0.1:5174`,
    },
  };
  const active = snippets[client];

  return (
    <div className="min-h-0 flex-1 overflow-auto">
      <div className="max-w-4xl space-y-10 p-6">
        <header>
          <h1 className="text-xl font-semibold">MCP</h1>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Let an AI assistant search captured traffic and create, edit, rename and send Replay requests. The{' '}
            <a className="underline underline-offset-2" href="https://modelcontextprotocol.io" target="_blank" rel="noreferrer">
              Model Context Protocol
            </a>{' '}
            server runs on your machine and talks to this app’s proxy; Replay requests are sent to the target you choose.
          </p>
          <div className="mt-4 flex items-center gap-2 text-xs text-muted-foreground" role="status">
            <span className={cn('size-1.5 rounded-full', proxyStatus === 'connected' ? 'bg-primary' : 'bg-destructive')} />
            {proxyStatus === 'connected'
              ? `Proxy is running — ${workspaces.length} workspace${workspaces.length === 1 ? '' : 's'} available to MCP clients.`
              : 'Proxy is offline. The MCP server reads from the running proxy, so start slurp first.'}
          </div>
        </header>

        <section aria-labelledby="mcp-setup">
          <h2 id="mcp-setup" className="text-sm font-medium">1. Connect a client</h2>
          <p className="mt-1 text-xs text-muted-foreground">
            The client launches <code className="font-mono">slurp mcp</code> itself (stdio). Keep the proxy
            running in another terminal.
            {!useDetectedPath && ' Add the directory containing slurp to the PATH used by your MCP client so it can find the executable.'}
          </p>
          {exe && <label className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
            <input type="checkbox" checked={useDetectedPath} onChange={event => setUseDetectedPath(event.target.checked)} className="accent-primary" />
            Use detected binary path (this machine only)
          </label>}
          <div className="mt-4 flex gap-1">
            {(Object.keys(snippets) as Client[]).map((c) => (
              <Button
                key={c}
                variant="ghost"
                size="sm"
                className={cn('h-7 text-xs', client === c ? 'bg-secondary' : 'text-muted-foreground')}
                onClick={() => setClient(c)}
              >
                {snippets[c].title}
              </Button>
            ))}
          </div>
          <p className="mb-2 mt-3 text-xs text-muted-foreground">{active.hint}</p>
          <CopyBlock label={active.title} text={active.text} />
        </section>

        <section aria-labelledby="mcp-tools">
          <h2 id="mcp-tools" className="text-sm font-medium">2. Available tools</h2>
          <div className="mt-3 overflow-x-auto rounded border border-border">
            <table className="w-full min-w-[640px] border-collapse text-left text-xs">
              <thead className="bg-card text-[10px] text-muted-foreground">
                <tr className="h-9 border-b border-border">
                  <th className="pl-4">Tool</th>
                  <th>What it does</th>
                  <th className="pr-4">Arguments</th>
                </tr>
              </thead>
              <tbody>
                {TOOLS.map((t) => (
                  <tr key={t.name} className="border-b border-border/40 align-top last:border-0">
                    <td className="whitespace-nowrap py-2.5 pl-4 pr-3 font-mono text-[11px] text-primary">
                      {t.name}
                      {t.destructive && <span className="ml-2 rounded bg-destructive/15 px-1 text-[9px] text-destructive">DESTRUCTIVE</span>}
                    </td>
                    <td className="py-2.5 pr-3">{t.summary}</td>
                    <td className="py-2.5 pr-4 font-mono text-[10px] text-muted-foreground">{t.params}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section aria-labelledby="mcp-workspaces">
          <h2 id="mcp-workspaces" className="text-sm font-medium">3. Workspaces and MCP</h2>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            Pass a workspace <strong className="text-foreground">name</strong> (case-insensitive) or id in the{' '}
            <code className="font-mono">workspace</code> argument to focus on one group of requests; leave it out to search
            all saved workspaces. Use <code className="font-mono">temporary</code> for requests kept in memory without a workspace. Use <code className="font-mono">list_workspaces</code> to see what exists. Entries returned by MCP
            include their <code className="font-mono">workspace_id</code>.
          </p>
        </section>

        <section aria-labelledby="mcp-prompts">
          <h2 id="mcp-prompts" className="text-sm font-medium">4. Things to ask</h2>
          <ul className="mt-3 space-y-2">
            {PROMPTS.map((p) => (
              <li key={p} className="rounded border border-border bg-card px-4 py-2.5 text-xs">
                {p}
              </li>
            ))}
          </ul>
        </section>

        <section aria-labelledby="mcp-safety" className="rounded border border-border bg-card p-4">
          <h2 id="mcp-safety" className="text-sm font-medium">Good to know</h2>
          <ul className="mt-2 list-disc space-y-1.5 pl-5 text-xs leading-5 text-muted-foreground">
            <li>Captured traffic can contain tokens, cookies and personal data; an assistant connected over MCP can read all of it.</li>
            <li>Replay tools can change saved tabs; send_replay sends a real request and can change remote data. clear_traffic deletes captured history.</li>
            <li>Bodies are returned as text and truncated (4 KB by default); binary bodies are described, not included.</li>
          </ul>
        </section>
      </div>
    </div>
  );
}
