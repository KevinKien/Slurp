# Slurp

**Sip traffic.**

Slurp is an HTTP/HTTPS inspection and API testing tool with a Rust proxy, a browser-based workspace, and an MCP server. Capture traffic, edit and replay requests, chain API workflows, and review scan findings from one interface.

## Features

- **Dashboard:** monitor scan tasks and review saved findings and evidence.
- **HTTP History:** search and filter captured traffic, browse large histories with incremental loading and virtual scrolling, bookmark requests, and add notes.
- **Intercept:** hold requests and responses for inspection, editing, forwarding, or dropping. Pending items are not automatically dropped by a timeout.
- **WebSocket:** capture WS/WSS connections and bidirectional frames in HTTP History → WebSocket. Intercept labels HTTP and WS handshakes in one queue; Send to Replay opens an editable WebSocket request. Browse paginated messages, search the current page, and inspect text or hex payloads.
- **Replay:** edit requests in multiple tabs, import cURL, Postman collections and Bruno `.bru` files, use shared variables and after-response scripts, and review send history.
- **Flows:** chain API requests into multi-step workflows and pass values between steps.
- **Profiles and Authorization Matrix:** manage account variables, headers and cookie jars, compare responses, and test requests across accounts.
- **Intruder:** substitute payloads with configurable concurrency, rate limits, matching, and saved results.
- **Scope & Filters:** focus History and Intercept on configured target domains.
- **Tools:** Base64, URL, HTML and hex encoding/decoding, UUID generation, and JWT decoding.
- **MCP:** search and read history; create, edit, rename and send saved Replay requests from an MCP client.
- **Workspaces:** keep saved traffic, Replay tabs and testing data organized locally.

## Run a packaged build

Use a build matching your operating system and CPU architecture. The standalone executable includes the web UI; no Node.js is needed to run it.

macOS/Linux:

```sh
./slurp
```

Windows PowerShell:

```powershell
.\slurp.exe
```

The browser opens to **http://127.0.0.1:5174/dashboard** after the web server binds. Use `--no-open` to skip opening a browser. Keep the terminal open; press **Ctrl+C** to stop Slurp. Stop existing Slurp servers first to avoid port conflicts.

| Component | Default address |
|---|---|
| Web UI | `http://127.0.0.1:5174/dashboard` |
| REST API | `http://127.0.0.1:5174` |
| WebSocket | `ws://127.0.0.1:5174/api/ws` |
| HTTP/HTTPS proxy | `127.0.0.1:8888` |

Saved proxy listener settings may override the default proxy address. UI, API and WebSocket share a single Rust web server. Older directory releases using `node start.mjs` remain separate builds; rebuild to get the standalone executable.

## Capture traffic

1. Start Slurp and open the web UI.
2. Choose a saved workspace or a temporary session. Temporary traffic is held in memory and is lost when the backend exits.
3. Configure your browser or HTTP client to use `127.0.0.1:8888` as its HTTP/HTTPS proxy, or use the address shown in **Settings → Proxy listener**.
4. For HTTPS interception, install and trust Slurp's `ca.crt` in the browser or operating system used by the client. Startup prints platform-specific installation instructions.
5. Browse the target application and inspect requests in **HTTP History**. Enable request/response interception in **Intercept** when needed.

For a local HTTPS capture check on macOS/Linux:

```sh
curl --proxy http://127.0.0.1:8888 \
  --cacert "$HOME/.slurp/ca.crt" \
  https://httpbin.org/get
```

On Windows PowerShell:

```powershell
curl.exe --proxy http://127.0.0.1:8888 --cacert "$env:USERPROFILE\.slurp\ca.crt" https://httpbin.org/get
```

The proxy captures HTTP, HTTPS, WS and WSS traffic. Replay, Scan, Flows, Intruder and Matrix can send HTTP(S) requests to public hosts, localhost and LAN addresses on custom ports. HTTP senders pin DNS results, validate TLS certificates, do not follow redirects, and retain bounded response sizes and timeouts.

## Certificates and local data

On normal backend startup, Slurp creates a root CA when needed and reuses it on subsequent starts. The certificate, private key, database and proxy listener configuration live in the current user's data directory:

| Platform | Directory | Typical example |
|---|---|---|
| macOS | `$HOME/.slurp/` | `/Users/alice/.slurp/` |
| Linux | `$HOME/.slurp/` | `/home/alice/.slurp/` |
| Windows | `%USERPROFILE%\.slurp\` | `C:\Users\alice\.slurp\` |

- `ca.crt`: root CA certificate to install in client trust stores.
- `ca.key`: private CA key; keep it private.
- `traffic.db`: local SQLite database for saved workspaces and testing data.
- `proxy-address`: saved proxy listener address.

If `.slurp` is absent and the legacy `.httpdebugger` directory exists, startup renames it to `.slurp`, preserving the existing CA and workspace data. If both directories exist, Slurp uses `.slurp` without merging them. Stop older instances before upgrading.

## Build from source

Install Rust stable, Node.js, Bun, and the native build tools listed in [BUILD.md](BUILD.md). From the repository root:

```sh
node scripts/build.mjs
```

Build on the OS and architecture you want to distribute. Output goes to `dist/slurp-<version>-<os>-<arch>-standalone/`; existing output directories are not overwritten.

To build only the backend:

```sh
node scripts/build.mjs --backend-only
```

The backend-only executable does not include frontend assets. The normal standalone build includes them; both executables run without Node.js.

The [build workflow](.github/workflows/build.yml) produces separate Windows, Linux and macOS artifacts through GitHub Actions. See [BUILD.md](BUILD.md) for prerequisites, platform details and runtime instructions.

## Local development

On macOS/Linux, start both development servers from the repository root:

```sh
./dev.sh
```

The script installs frontend dependencies if needed and starts the Rust backend and Vite UI. To change development ports:

```sh
API_PORT=15174 FRONTEND_PORT=15173 PROXY_PORT=18888 ./dev.sh
```

Alternatively, start the backend and frontend in separate terminals, including on Windows:

```sh
# Terminal 1, repository root
cargo run -p slurp
```

```sh
# Terminal 2, repository root
cd curl-cozy
bun install --frozen-lockfile
npm run dev
```

### Configuration

| Environment variable | Purpose | Default |
|---|---|---|
| `SLURP_API_ADDR` | Backend API/WebSocket bind address | `127.0.0.1:5174` |
| `SLURP_PROXY_ADDR` | Override the saved proxy listener at startup | Saved address, otherwise `127.0.0.1:8888` |
| `SLURP_ALLOWED_ORIGINS` | Additional allowed browser origins, comma-separated | No additional origins |
| `VITE_PROXY_API_URL` | Frontend API URL, supplied at build/dev time | `http://127.0.0.1:5174` |
| `VITE_PROXY_WS_URL` | Frontend WebSocket URL, supplied at build/dev time | `ws://127.0.0.1:5174/api/ws` |

Legacy `HTTPDEBUGGER_*` backend equivalents remain supported; `SLURP_*` takes priority. Standalone builds use same-origin API/WebSocket URLs, so `SLURP_API_ADDR` changes the UI and API address together without rebuilding. Separate Vite development builds require matching frontend API/WebSocket URLs.

Change the running proxy IP/port under **Settings → Proxy listener**. The backend detects local interface IPs; applying a listener change does not require restarting it. Use the actual LAN IP when configuring another device.

## MCP

Start the proxy backend first. Configure your MCP client to launch the backend executable with the `mcp` argument:

```json
{
  "mcpServers": {
    "slurp": {
      "command": "slurp",
      "args": ["mcp"]
    }
  }
}
```

Add the directory containing `slurp` (`slurp.exe` on Windows) to the PATH available to your MCP client. The MCP page defaults to this portable command; enable **Use detected binary path** for a configuration tied to the current machine. For a different API address, use `args: ["mcp", "--api", "http://127.0.0.1:15174"]`. The MCP process communicates over stdio and connects to the already-running backend. The **MCP** page provides client configuration examples.

## Guides

- [MCP client setup: Claude, Codex, DeepSeek Harness, OpenCode and Antigravity](curl-cozy/public/docs/mcp.html)
- [Building and distributing Slurp](BUILD.md)
- [Replay scripting](curl-cozy/public/docs/replay-scripts.html)
- [Flows](curl-cozy/public/docs/flows.html)
- [Profiles, Response Diff and Authorization Matrix](curl-cozy/public/docs/security-testing.html)
- [Intruder](curl-cozy/public/docs/intruder.html)
- [Scan engine](curl-cozy/docs/scan-engine.md)

The HTML guides are also available through their corresponding documentation links in the web UI. Flows, Intruder, Matrix and scan execution rely on the browser staying open; unfinished runs do not automatically resume after reload. Scan findings include verification details and evidence; review them before treating a result as a confirmed vulnerability.

### WebSocket capture

Configure your client to use the Slurp proxy. WSS also requires trusting the Slurp CA, just like HTTPS. Open **HTTP History → WebSocket** to inspect captured connections and their frames. Intercept uses one queue with HTTP/WS badges. Choose **Send to Replay** from a captured connection or handshake to edit its URL and headers, connect, and send text or binary hex messages. Replay supports shared variables in the URL, headers and message body; request drafts are saved with the workspace. Capture follows the selected workspace; temporary traffic stays in memory. Scope applies to newly opened WebSocket connections.

The HTTP request interception switch can hold the opening handshake. After the handshake, **Intercept requests** holds Client → Server WebSocket frames and **Intercept responses** holds Server → Client frames in the same queue as HTTP. Forward relays the original wire bytes; Drop removes the selected frame. Held frames show a text/hex preview up to 64 KiB and have no automatic timeout. Turning a direction off or forwarding all releases its held frames unchanged. Use Replay to send edited messages. WebSocket Replay opens a separate connection and supports editing and resending messages. It accepts public WS hosts on port 80 and WSS hosts on port 443, pins validated DNS addresses, validates TLS certificates, and does not follow redirects. Replay limits messages to 1 MB, keeps a bounded in-memory transcript, and disconnects when leaving the active request tab. Binary and compressed payloads are shown as hex. Replay automatically decodes gzip, Brotli, deflate and zstd HTTP responses before display, with the response limit applied to decoded bytes. Each stored frame preview is limited to 64 KiB; the complete frame is forwarded. Clear history also clears WebSocket captures without interrupting live connections or recreating their deleted records.
