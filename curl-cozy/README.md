# Slurp

**Sip traffic.**

Thiết kế một ứng dụng web HTTP Traffic Inspector & Replay Client với giao diện dark mode chuyên nghiệp lấy cảm hứng từ Caido (theo ảnh đính kèm).

Các tính năng chính:
1. Giao diện tổng quan (phong cách Caido):
- Sidebar bên trái điều hướng: HTTP History, Replay (Repeater), Scope/Filters, Settings.
- Dark theme hiện đại, tinh gọn với font monospace cho code, status code badge (xanh lá cho 2xx, vàng cho 3xx, đỏ cho 4xx/5xx).

2. Tab HTTP History:
- Bảng hiển thị danh sách traffic: ID, Method, Host, Path, Status, Size, Response Time, Timestamp.
- Thanh tìm kiếm và bộ lọc nhanh (theo Method GET/POST/PUT..., Status code, Path hoặc từ khóa).
- Khung xem chi tiết Request và Response chia đôi (Split pane) ở nửa dưới màn hình với các tab Raw, Pretty (định dạng JSON/HTML/Text), và Headers.
- Nút "Send to Replay" trên mỗi request để chuyển dữ liệu sang chế độ chỉnh sửa và gửi lại.

3. Tab Replay (Repeater):
- Quản lý nhiều phiên làm việc theo tab (Sessions).
- Trình tùy chỉnh request: chọn Method, nhập URL, chỉnh sửa Headers, Query Parameters và Request Body (JSON/Raw).
- Hỗ trợ dán trực tiếp câu lệnh cURL để tự động điền form.
- Nút "Send" để gửi request và hiển thị kết quả Response trả về ngay bên cạnh (Status code, Duration, Response Headers, Response Body formatted).

4. Quản lý dữ liệu & Import:
- Có sẵn bộ dữ liệu mẫu (mock traffic) phong phú khi mở app lần đầu để trải nghiệm ngay.
- Tính năng Import file HAR, cURL hoặc file JSON để nạp thêm traffic logs vào lịch sử.
- Nút Clear history và Export log.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/efc2073b-a11e-4518-abea-acb10d480401).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```

## Proxy listener settings

Open **Settings → Proxy listener**, select an IP address and enter a port from 1 to 65535, and select **Apply**.
Use `127.0.0.1` for local access only, a specific local LAN IP for that interface,
or `0.0.0.0` to accept connections on localhost and all IPv4 interfaces at once.
The IP selector detects IPv4 addresses on the backend host, including LAN and VPN
interfaces, with their interface names. Use **Refresh IPs** after a network change.
Other devices connect to the machine's LAN IP (for example `192.168.1.10:8888`),
not to `0.0.0.0`. Access from connected networks depends on the firewall.

Existing HTTP connections and HTTPS tunnels remain open when settings change.
Switching between a specific IP and `0.0.0.0` on the same port briefly closes the
listening socket before rebinding; new connections may need to retry during this
transition. If binding or saving fails, the backend restores the previous listener.
A restoration failure is reported explicitly and can be recovered by applying a
valid address again.

The setting applies to the running backend, across all workspaces, and is saved to
`~/.slurp/proxy-address`. At startup,
`SLURP_PROXY_ADDR` takes precedence over the saved address; without either,
the default is `127.0.0.1:8888`. Update the proxy configuration in your browser or
device after changing the port. The API and web interface keep their existing ports.


## Account testing

- **Profiles** stores per-account variables, headers and cookie jars with the selected workspace.
- Select a profile in **Replay** or **Flows** to use that account. Replay scripts save variable updates to the selected profile; Flow variables stay isolated to the run.
- **Response Diff** compares response status, headers and normalized JSON/text, with ignored header names and JSON paths.
- **Authorization Matrix** sends selected Replay requests under selected profiles and preserves request/response evidence. Set expected access per cell and compare results with a baseline.

See the in-app [account testing guide](public/docs/security-testing.html) for setup, cookie behavior, limits and result interpretation.


## Intruder

Mark one request value with `§value§`, choose a manual payload list, streamed TXT/CSV import or lazy number range, then run with concurrency and rate limits. History, Replay and Intercept expose **Send to Intruder** in their request menus. Profiles, cookie jars, payload encoding, pause/resume/stop, response matching and paginated evidence are supported.

See the [Intruder guide](public/docs/intruder.html) for setup, storage limits and execution behavior. Saved runs execute while this browser remains open; they never auto-resume after reload.

## Scan engine

The Dashboard at `/dashboard` shows scan tasks and findings. The endpoint scan engine provides passive inspection, bounded active probes, baseline controls, finding verification metadata and immutable local evidence. `ScanProvider` connects it to Replay and Profiles. Right-click a History, Replay or Intercept request and choose **Scan** to configure checks and inspect findings, verification details and captured evidence. Active scans require explicit sending opt-in; captured History responses support passive inspection.

See the [scan engine developer guide](docs/scan-engine.md) for supported checks, execution examples, verification limits and API details.

## Slurp CLI

Run the backend with `cargo run -p slurp` (or the built `target/debug/slurp` binary). MCP clients use `slurp mcp`. Configuration uses `SLURP_API_ADDR`, `SLURP_PROXY_ADDR` and `SLURP_ALLOWED_ORIGINS`; legacy `HTTPDEBUGGER_*` equivalents remain accepted, with `SLURP_*` taking priority. Data and CA certificates live in `~/.slurp` on macOS/Linux and `%USERPROFILE%\.slurp` on Windows. When `.slurp` does not exist, startup renames the legacy `.httpdebugger` directory to `.slurp`, preserving workspaces and client trust. If both directories exist, `.slurp` is used without merging or overwriting either directory. Stop older Slurp instances before upgrading. Newly generated CA certificates use the Slurp name.

Default standalone addresses: UI `http://127.0.0.1:5174/dashboard` (Vite development UI remains on port 5173), API `http://127.0.0.1:5174`, WebSocket `ws://127.0.0.1:5174/api/ws`, proxy `http://127.0.0.1:8888`.

For native Windows, Linux and macOS release scripts and CI artifacts, see [BUILD.md](../BUILD.md).

Standalone releases embed the browser UI and use the Rust `/api/replay/send` endpoint. Run `slurp` directly; Node.js is only needed at build time. See the [root README](../README.md).
