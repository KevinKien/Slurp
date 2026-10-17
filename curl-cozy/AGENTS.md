<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

- Keep inspector state in a root-mounted provider so history and replay sessions survive navigation without exposing imported private traffic to a shared database.
- Use leaf routes for history, replay, scope and settings, sharing the inspector shell at the root for consistent navigation.
- Parse cURL with shell-quote without executing commands; imports remain browser-side to prevent command execution and unintended uploads.
- Replay uses the Rust `/api/replay/send` endpoint with HTTP(S) target validation supporting public, localhost and LAN destinations, DNS address pinning, no automatic redirects, bounded response sizes and timeouts. Keep these restrictions shared by Replay, Flows, Intruder, Matrix and Scan.
