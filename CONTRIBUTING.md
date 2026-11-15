# Contributing to Slurp

Thanks for helping. Bug reports, fixes, new scan checks, docs and tests are all welcome.

## Before you start

- **Security issues:** do not open a public issue. Follow [SECURITY.md](SECURITY.md).
- **Large changes:** open an issue first. That avoids work on something that does not fit, for example a check that needs exploit payloads or a destructive request.
- **Contributor License Agreement:** a pull request can only be merged after you agree to the [CLA](CLA.md). The CLA bot asks once, on your first pull request. You keep the copyright to your work. The CLA lets the project also distribute it under other licenses, including in commercial editions of Slurp.

## Project layout

| Path | What it is |
|---|---|
| `crates/proxy-core` | MITM proxy, TLS, HTTP/2, WebSocket, SOCKS5, reverse proxy and traffic storage |
| `crates/web-server` | REST and WebSocket API, automatic audits and server-side scan helpers |
| `crates/mcp-server` | MCP server for AI assistants |
| `crates/cli` | The `slurp` executable |
| `curl-cozy/` | Web UI (React, TanStack Router, Vite) and the client-side scan engine |
| `curl-cozy/public/docs/` | Built-in documentation |
| `curl-cozy/benchmark/` | Scan benchmark against deliberately vulnerable local labs |

## Development setup

See [BUILD.md](BUILD.md) for the requirements. Then:

```sh
cd curl-cozy && bun install   # or: npm install --no-package-lock
```

Run the API and proxy, then the UI in a second terminal:

```sh
cargo run -p slurp
```

```sh
cd curl-cozy && npm run dev
```

## Checks to run before a pull request

```sh
cargo test --workspace
```

```sh
cd curl-cozy && npx tsc --noEmit && npm run lint && npm test
```

Format the files you changed with `npx prettier --write <files>` (UI) and `cargo fmt` (Rust). Avoid reformatting unrelated code in the same pull request.

## Writing scan checks and audits

Slurp is used against real systems, so checks must be safe and must not overstate findings.

- **Register the check.** Add it in `curl-cozy/src/lib/scan/registry.ts` and in `CheckId` (`types.ts`). Server-side checks also go in the allowed list in `crates/web-server/src/scan.rs`. Start new checks as `experimental`.
- **Pick the right intensity.** Use `passive`, `light`, `active` or `intrusive`, and keep requests bounded.
- **Never ship weaponised exploits.** That means no destructive requests (reinstalling, deleting, writing configuration) and no payloads that execute commands on the target. Prefer version comparison, differential responses and out-of-band canaries.
- **Be honest about evidence.** A version banner is not proof of exploitation. An unknown version is informational, not "vulnerable". Set `confidence` and `verification` to match what was actually observed.
- **Do not forward the user's credentials** to anything the user did not target.
- **Add tests.** Cover a positive case, a negative case and at least one look-alike that must not be flagged. Promoting a check to `stable` needs benchmark evidence (see `curl-cozy/benchmark/RESULTS.md`).
- **Regenerate the scan docs.** Run `curl-cozy/benchmark/docs.py` when the registry changes.

## Commits and pull requests

- Keep each pull request focused on one change and describe what it does and how you tested it.
- Use short, imperative commit messages, for example `fix: ignore image responses in no-auth check`.
- Never commit secrets, captured traffic, `.slurp` workspaces, databases or CA keys. `.gitignore` covers the usual paths.
- Test fixtures must be synthetic. Do not include traffic or data from real targets, bug bounty programs or customers.

## Code of conduct

Be respectful and constructive. Harassment or abuse leads to removal from the project.
