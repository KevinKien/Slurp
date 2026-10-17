#!/usr/bin/env bash
# Run the proxy/API (Rust) and the web UI (Vite) together. Ctrl+C stops both.
#
#   ./dev.sh                         # UI :5173, proxy :8888, API :5174
#   API_PORT=15174 PROXY_PORT=18888 ./dev.sh   # move them if another tool (e.g. Caido) owns the defaults
#   FRONTEND_PORT=3000 ./dev.sh      # use another UI port
#
# The UI is kept off the API port; the UI is told where the API is.
set -euo pipefail
cd "$(dirname "$0")"

FRONTEND_PORT="${FRONTEND_PORT:-5173}"
API_PORT="${API_PORT:-5174}"
PROXY_PORT="${PROXY_PORT:-8888}"

for port in "$API_PORT" "$PROXY_PORT" "$FRONTEND_PORT"; do
  if lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Port $port is already in use. Stop whatever is using it (see: lsof -iTCP:$port -sTCP:LISTEN) or pick other ports (API_PORT, PROXY_PORT, FRONTEND_PORT)." >&2
    exit 1
  fi
done

# The project ships a bun.lock; use bun when available, otherwise npm without writing a lockfile.
if [ ! -d curl-cozy/node_modules ]; then
  echo "Installing frontend dependencies..."
  if command -v bun >/dev/null 2>&1; then (cd curl-cozy && bun install); else (cd curl-cozy && npm install --no-package-lock); fi
fi

cleanup() {
  trap - INT TERM EXIT
  # Both children share this script's process group; stop them together.
  kill 0 2>/dev/null || true
}
trap cleanup INT TERM EXIT

SLURP_API_ADDR="127.0.0.1:$API_PORT" SLURP_PROXY_ADDR="127.0.0.1:$PROXY_PORT" cargo run -p slurp &
api=$!
(cd curl-cozy && VITE_PROXY_API_URL="http://127.0.0.1:$API_PORT" VITE_PROXY_WS_URL="ws://127.0.0.1:$API_PORT/api/ws" exec ./node_modules/.bin/vite dev --port "$FRONTEND_PORT" --strictPort) &
web=$!

echo
echo "  Web UI : http://localhost:$FRONTEND_PORT"
echo "  Proxy  : http://127.0.0.1:$PROXY_PORT   API: http://127.0.0.1:$API_PORT"
echo "  Ctrl+C to stop both."
echo

# Exit (and stop the other one) as soon as either process dies.
while kill -0 "$api" 2>/dev/null && kill -0 "$web" 2>/dev/null; do sleep 1; done
