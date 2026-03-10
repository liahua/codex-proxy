#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTEN_HOST="${MITM_LISTEN_HOST:-127.0.0.1}"
LISTEN_PORT="${MITM_LISTEN_PORT:-8080}"

exec mitmdump \
  --set confdir="${MITM_CONF_DIR:-$HOME/.mitmproxy}" \
  --set block_global=false \
  --listen-host "$LISTEN_HOST" \
  --listen-port "$LISTEN_PORT" \
  --mode regular \
  --ssl-insecure \
  --set stream_large_bodies=10m \
  -s "$SCRIPT_DIR/addon.py"
