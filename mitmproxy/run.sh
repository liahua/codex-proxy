#!/usr/bin/env sh
set -eu
# Enable pipefail when supported by the current shell (bash, zsh, ksh, etc.).
(set -o pipefail) >/dev/null 2>&1 && set -o pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LISTEN_HOST="${MITM_LISTEN_HOST:-127.0.0.1}"
LISTEN_PORT="${MITM_LISTEN_PORT:-15001}"
LOG_FILE="${MITM_LOG_FILE-/tmp/codex-mitmproxy.log}"
UPSTREAM_PROXY="${MITM_UPSTREAM_PROXY:-}"
MODE="${MITM_MODE:-regular}"

if [ -n "$UPSTREAM_PROXY" ]; then
  MODE="upstream:${UPSTREAM_PROXY}"
fi

if [ -n "$LOG_FILE" ]; then
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "[run.sh] writing mitmdump logs to: $LOG_FILE"
  echo "[run.sh] mitmdump mode: $MODE"
  mitmdump \
    --set confdir="${MITM_CONF_DIR:-$HOME/.mitmproxy}" \
    --set block_global=false \
    --listen-host "$LISTEN_HOST" \
    --listen-port "$LISTEN_PORT" \
    --mode "$MODE" \
    --ssl-insecure \
    -s "$SCRIPT_DIR/addon.py" \
    2>&1 | tee -a "$LOG_FILE"
else
  exec mitmdump \
    --set confdir="${MITM_CONF_DIR:-$HOME/.mitmproxy}" \
    --set block_global=false \
    --listen-host "$LISTEN_HOST" \
    --listen-port "$LISTEN_PORT" \
    --mode "$MODE" \
    --ssl-insecure \
    -s "$SCRIPT_DIR/addon.py"
fi
