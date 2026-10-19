# Building Slurp

Slurp's standalone release embeds the web UI in the Rust executable. Running `slurp` starts the proxy and a single web server for the UI, API and WebSocket. Node.js is required to build the UI, not to run the release.

## Requirements

- Rust stable with Cargo.
- Node.js 22.12+ or Node.js 24+, with npm.
- Bun 1.x to install frontend dependencies from `curl-cozy/bun.lock`.
- CMake for native crypto-library configurations that require it.
- macOS: Xcode Command Line Tools (`xcode-select --install`).
- Linux (Ubuntu/Debian): `sudo apt-get install build-essential pkg-config cmake`.
- Windows: Visual Studio Build Tools with **Desktop development with C++**, a Windows SDK and the Rust MSVC toolchain.

## Build on macOS, Linux or Windows

From the repository root:

```sh
node scripts/build.mjs
```

The script installs frontend dependencies with `bun install --frozen-lockfile` if absent, type-checks the frontend, builds its browser assets, then compiles Rust with `--release --locked --features embedded-ui`. Assets, docs, workers and QuickJS WASM are embedded at compile time. No Node server is shipped.

Build on the OS and CPU architecture you want to distribute; this script does not cross-compile. Do not set `CARGO_BUILD_TARGET`. Output is:

```text
dist/slurp-<version>-<os>-<arch>-standalone/
  slurp       # slurp.exe on Windows
  README.txt
```

Existing output is never overwritten; move the old directory aside before rebuilding. Rebuild the executable after any frontend change.

## Distribution packages

After building, run on the same OS:

```sh
node scripts/package.mjs
```

Packages and SHA-256 checksums are written to `dist/artifacts/`:

- macOS Intel: `slurp-<version>-macos-x64.dmg`.
- macOS Apple Silicon: `slurp-<version>-macos-arm64.dmg`.
- macOS Terminal: `slurp-<version>-macos-<arch>-cli.tar.gz`; a separate `macos-universal-cli.tar.gz` supports both CPU families.
- Linux: `slurp-<version>-linux-<arch>`, an executable binary. After downloading, run `chmod +x slurp-*` if the download removed executable permissions.
- Windows: `slurp-<version>-windows-<arch>.exe`, a standalone executable.

The UI and API are embedded in each executable. These are native builds, not renamed binaries from another OS. To package an existing native standalone directory, use `node scripts/package.mjs --input <directory>`.

### Install the macOS app

Requires macOS 12 or newer. Open the DMG and drag **Slurp.app** onto **Applications**, then launch it from Applications or Launchpad. It starts the bundled Rust backend and opens the web UI in your browser. Use **Open Slurp** in the menu bar or reopen the Dock icon to return to the UI. Use **Quit Slurp** (Cmd+Q with Slurp active) to stop both the app and its backend. Closing the browser leaves the backend running. Startup failures, such as a port conflict with a CLI instance, show an error instead of starting a second server.

The app, its executables and DMG use free **ad-hoc signatures**, not Developer ID signing or notarization. macOS may block a downloaded app on first launch; use **System Settings → Privacy & Security → Open Anyway** if available. No Apple Developer account is required to build these packages.

Data and CA remain in `~/.slurp`. GUI logs are in `~/Library/Logs/Slurp/slurp.log`. Do not run the GUI and CLI on the same ports at the same time. The CLI archive contains a plain `slurp` executable with the embedded UI/API; it is distinct from `--backend-only`, which omits UI assets.

To package a cross-compiled ARM64 binary on an Intel Mac, place it in `dist/slurp-<version>-macos-arm64-standalone/slurp` and run `node scripts/package.mjs --arch arm64`. The script verifies the binary's architecture and cross-compiles the native launcher against the macOS SDK.

Combine the native CLI packages into a single universal CLI archive:

```sh
node scripts/package-macos-cli.mjs --intel dist/artifacts/slurp-1.1.0-macos-x64-cli.tar.gz --arm64 dist/artifacts/slurp-1.1.0-macos-arm64-cli.tar.gz
```

## Run

macOS/Linux:

```sh
./slurp
```

Windows PowerShell:

```powershell
.\slurp.exe
```

The browser opens to **http://127.0.0.1:5174/dashboard** after the server binds. Use `--no-open` to skip opening a browser, for example on a headless Linux machine. If the browser cannot be opened, use the URL printed in the terminal. Stop with Ctrl+C.

Proxy defaults to **127.0.0.1:8888** unless saved settings override it. UI, API and WebSocket share port **5174**; `SLURP_API_ADDR` changes all three together without rebuilding the UI. For example on macOS/Linux:

```sh
SLURP_API_ADDR=127.0.0.1:15174 ./slurp --no-open
```

No Node.js, npm or Bun is needed on the destination machine. Copy the executable to a compatible machine of the same OS/architecture. Linux artifacts built on Ubuntu 22.04 require compatible system libraries; these are not static musl builds.

Startup creates or loads the CA and workspace data in `~/.slurp` on macOS/Linux or `%USERPROFILE%\.slurp` on Windows. Install `ca.crt` in the client trust store for HTTPS interception.

Download the running proxy's public CA from the **CA certificate** button in the web header or **Settings → HTTPS CA certificate**. The download endpoint is `/api/ca.crt`.

Windows curl using Schannel may report `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` because the local CA has no online CRL/OCSP service. Allow unavailable revocation status while retaining certificate verification:

```powershell
curl.exe -x http://127.0.0.1:8888 --cacert "$HOME\.slurp\ca.crt" --ssl-revoke-best-effort https://httpbin.org/get
```

## Backend only

```sh
node scripts/build.mjs --backend-only
```

This requires Rust and Node to run the build script, but no frontend dependencies. Output ends in `-backend`. The binary serves the API without an embedded UI and does not open a browser.

## Development

`./dev.sh` still starts Vite at port 5173 and the Rust API at port 5174. The separate UI uses the Rust sender API too. For a Rust-served local UI without embedding, run `npm run build:standalone` in `curl-cozy`, then `cargo run -p slurp -- --no-open` from the root. The debug backend serves `curl-cozy/dist-rust` by default; `SLURP_UI_DIR` can point to another asset directory.

## GitHub Actions

The [build workflow](.github/workflows/build.yml) runs native Ubuntu, Windows and macOS builds. Select **Actions → Build Slurp → Run workflow**, or push a version tag such as `v1.1.0`. Download the platform artifacts: macOS DMG/CLI, Linux binary, or Windows EXE, each with a SHA-256 checksum. Separate macOS runners build Apple Silicon (`macos-15`, ARM64) and Intel (`macos-15-intel`, x64) DMGs and native CLI archives. A follow-up job combines the two CLI executables into one universal macOS archive. The Ubuntu and Windows runners build x64. The workflow does not publish a GitHub Release or deploy the app.

## Release version

The version in the root `Cargo.toml` (`[workspace.package]`) is the single source for Rust crates, the UI footer, HAR creator metadata, and package names. Update it before a release, run `cargo check --offline` to refresh `Cargo.lock`, then rebuild the UI and binaries. Ordinary commits do not change the release version. After committing a release, create a matching tag such as `v1.1.0` to trigger the release build workflow.
