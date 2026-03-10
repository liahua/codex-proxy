#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${1:-$ROOT_DIR/relay-only.env}"
PID_FILE="${PID_FILE:-$ROOT_DIR/.relay-only.pid}"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js 22+ is required on the remote host."
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required on the remote host."
  exit 1
fi

node_major="$(node -p 'process.versions.node.split(".")[0]')"
if [ "${node_major}" -lt 22 ]; then
  echo "Node.js 22+ is required. Current: $(node -v)"
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  cp "$ROOT_DIR/scripts/relay-only.env.example" "$ENV_FILE"
  echo "Created $ENV_FILE. Set RELAY_SHARED_SECRET and rerun."
  exit 1
fi

set -a
. "$ENV_FILE"
set +a

cd "$ROOT_DIR"

if [ -z "${RELAY_SHARED_SECRET:-}" ] || [ "${RELAY_SHARED_SECRET}" = "replace-me" ]; then
  echo "Set RELAY_SHARED_SECRET in $ENV_FILE before starting the relay."
  exit 1
fi

mkdir -p "${RELAY_STORAGE_DIR:-$ROOT_DIR/data/chunked-requests}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
mkdir -p "$LOG_DIR"

if [ ! -d "$ROOT_DIR/node_modules" ]; then
  npm ci --omit=dev
fi

if [ -f "$PID_FILE" ]; then
  old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
    echo "Relay is already running with PID $old_pid"
    exit 0
  fi
fi

nohup env \
  HOST="${HOST:-0.0.0.0}" \
  PORT="${PORT:-8787}" \
  RELAY_STORAGE_DIR="${RELAY_STORAGE_DIR:-$ROOT_DIR/data/chunked-requests}" \
  RELAY_REQUEST_TTL_MS="${RELAY_REQUEST_TTL_MS:-900000}" \
  RELAY_SHARED_SECRET="${RELAY_SHARED_SECRET}" \
  npm run start:relay \
  > "$LOG_DIR/relay.out" \
  2> "$LOG_DIR/relay.err" &

pid="$!"
echo "$pid" > "$PID_FILE"
sleep 1

if ! kill -0 "$pid" 2>/dev/null; then
  echo "Relay failed to start. Check $LOG_DIR/relay.err"
  exit 1
fi

echo "Relay started"
echo "PID: $pid"
echo "Health: curl http://127.0.0.1:${PORT:-8787}/healthz"
echo "Logs: $LOG_DIR/relay.out $LOG_DIR/relay.err"
