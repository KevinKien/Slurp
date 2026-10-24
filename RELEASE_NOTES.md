# Slurp v1.0.1

**Sip traffic.**

Slurp v1.0.1 improves HTTP History, local API testing, documentation, and macOS installation.

## HTTP History

- Delete individual requests from the right-click menu. Captured requests are removed from storage only after the API succeeds; failed deletions leave the request visible.
- Export loaded requests as JSON or HAR 1.2.
- Open search and filters from a toolbar icon to leave more room for traffic. Filters remain active when the search panel is closed.
- Resize table columns and retain their widths in the browser.
- Keep the vertical split between the request list and detail viewer after navigating away or reloading the page.

## Request testing

- Support HTTP and HTTPS destinations on localhost and LAN networks in Replay, Flows, Intruder, Authorization Matrix, Scan, and saved Replay requests sent through MCP.
- Share destination validation and DNS address pinning across HTTP request senders, while retaining timeouts, response-size limits, and disabled automatic redirects.
- Add line numbers to the Replay raw request editor.
- Place Send history next to Send for quicker access to previous results.

## Certificates and documentation

- Download the public CA certificate from the header or Settings.
- Add a documentation index at `/docs`, accessible from the footer.
- Apply a consistent dark theme to the documentation pages.
- Replace Vietnamese documentation and sample test text with English.
- Improve the Settings page layout to support scrolling.

## macOS distribution

- Install Slurp from a DMG by dragging **Slurp.app** into **Applications**.
- Provide separate app packages for Intel and Apple Silicon, requiring macOS 12 or newer.
- Provide a universal CLI archive containing both Intel and Apple Silicon executables, with the web UI and API embedded.
- Open the browser when the app is ready, return to the UI from the menu bar or Dock, and stop the backend with **Quit Slurp**.
- Write app logs to `~/Library/Logs/Slurp/slurp.log` and report backend startup failures.
- Include SHA-256 checksums for distribution files.

## Versioning

- Use a shared release version for Rust crates, the UI footer, HAR creator metadata, and package names.
- Display **Slurp v1.0.1** in the footer.

## Upgrade notes

- Stop the previous Slurp instance before launching v1.0.1. Export any traffic in a Temporary session first; temporary traffic is lost when the process stops.
- Existing workspaces and CA files remain in `~/.slurp`.
- macOS packages use ad-hoc signing and are not notarized. On first launch, macOS may require **System Settings → Privacy & Security → Open Anyway**.
- HAR export includes the requests currently loaded in HTTP History and the text snapshots available to Slurp. It does not reconstruct original binary payloads or detailed network timings.
- Local HTTP destination support does not change the separate destination restrictions for WebSocket Replay.

## Validation

- Passed 52 History, Replay, and session regression tests, plus focused HAR export and Tools tests.
- Verified request deletion, footer version, and split-layout persistence in a real browser.
- Verified macOS app startup and shutdown on Intel, DMG integrity, architecture metadata, signatures, and artifact checksums.
- Built Apple Silicon packages and verified their architecture and signatures; runtime testing on Apple Silicon hardware remains outstanding.
