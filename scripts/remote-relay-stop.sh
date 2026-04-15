#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${1:-$ROOT_DIR/relay-only.env}"
PID_FILE="${PID_FILE:-$ROOT_DIR/.relay-only.pid}"

if [ -f "$ENV_FILE" ]; then
  set -a
  . "$ENV_FILE"
  set +a
fi

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8787}"
probe_host="$HOST"
if [ "$probe_host" = "0.0.0.0" ]; then
  probe_host="127.0.0.1"
fi

pid=""
if [ -f "$PID_FILE" ]; then
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
    pid=""
    rm -f "$PID_FILE"
  fi
fi

if [ -z "$pid" ] && command -v ss >/dev/null 2>&1; then
  pid="$(ss -ltnp "( sport = :$PORT )" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)"
fi

if [ -z "$pid" ]; then
  echo "Relay is not running"
  exit 0
fi

if ! RELAY_PROBE_HOST="$probe_host" RELAY_PROBE_PORT="$PORT" node -e '
const host = process.env.RELAY_PROBE_HOST;
const port = Number(process.env.RELAY_PROBE_PORT);
const request = require("node:http").get({
  host,
  port,
  path: "/healthz",
  timeout: 1000
}, (response) => {
  process.exit(response.statusCode === 200 ? 0 : 1);
});
request.on("timeout", () => request.destroy());
request.on("error", () => process.exit(1));
' >/dev/null 2>&1; then
  echo "Port ${PORT} is in use, but the relay health check did not succeed"
  exit 1
fi

kill "$pid"
rm -f "$PID_FILE"
echo "Stopped relay PID $pid"
