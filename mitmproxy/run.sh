#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTEN_HOST="${MITM_LISTEN_HOST:-127.0.0.1}"
LISTEN_PORT="${MITM_LISTEN_PORT:-8080}"
STREAM_LARGE_BODIES="${MITM_STREAM_LARGE_BODIES:-100k}"

exec mitmdump \
  --set confdir="${MITM_CONF_DIR:-$HOME/.mitmproxy}" \
  --set block_global=false \
  --listen-host "$LISTEN_HOST" \
  --listen-port "$LISTEN_PORT" \
  --mode regular \
  --ssl-insecure \
  --set stream_large_bodies="$STREAM_LARGE_BODIES" \
  -s "$SCRIPT_DIR/addon.py"
