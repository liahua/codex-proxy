#!/usr/bin/env sh
set -eu
# Enable pipefail when supported by the current shell (bash, zsh, ksh, etc.).
(set -o pipefail) >/dev/null 2>&1 && set -o pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LISTEN_HOST="${MITM_LISTEN_HOST:-127.0.0.1}"
LISTEN_PORT="${MITM_LISTEN_PORT:-15001}"
STREAM_LARGE_BODIES="${MITM_STREAM_LARGE_BODIES:-100k}"
LOG_FILE="${MITM_LOG_FILE-/tmp/codex-mitmproxy.log}"

if [ -n "$LOG_FILE" ]; then
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "[run.sh] writing mitmdump logs to: $LOG_FILE"
  mitmdump \
    --set confdir="${MITM_CONF_DIR:-$HOME/.mitmproxy}" \
    --set block_global=false \
    --listen-host "$LISTEN_HOST" \
    --listen-port "$LISTEN_PORT" \
    --mode regular \
    --ssl-insecure \
    --set stream_large_bodies="$STREAM_LARGE_BODIES" \
    -s "$SCRIPT_DIR/addon.py" \
    2>&1 | tee -a "$LOG_FILE"
else
  exec mitmdump \
    --set confdir="${MITM_CONF_DIR:-$HOME/.mitmproxy}" \
    --set block_global=false \
    --listen-host "$LISTEN_HOST" \
    --listen-port "$LISTEN_PORT" \
    --mode regular \
    --ssl-insecure \
    --set stream_large_bodies="$STREAM_LARGE_BODIES" \
    -s "$SCRIPT_DIR/addon.py"
fi
