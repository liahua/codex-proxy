#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="${PID_FILE:-$ROOT_DIR/.relay-only.pid}"

if [ ! -f "$PID_FILE" ]; then
  echo "Relay is not running"
  exit 0
fi

pid="$(cat "$PID_FILE" 2>/dev/null || true)"
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
  kill "$pid"
  echo "Stopped relay PID $pid"
else
  echo "Stale PID file removed"
fi

rm -f "$PID_FILE"
