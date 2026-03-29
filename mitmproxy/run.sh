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
ADDON_MODE="${MITM_ADDON_MODE:-record-only}"

case "$ADDON_MODE" in
  relay)
    ADDON_SCRIPT="$SCRIPT_DIR/addon.py"
    ;;
  record-only|record_only|record)
    ADDON_SCRIPT="$SCRIPT_DIR/record_only_addon.py"
    ;;
  *)
    echo "[run.sh] unsupported MITM_ADDON_MODE: $ADDON_MODE" >&2
    exit 1
    ;;
esac

if [ -n "$UPSTREAM_PROXY" ]; then
  MODE="upstream:${UPSTREAM_PROXY}"
fi

if [ -n "$LOG_FILE" ]; then
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "[run.sh] writing mitmdump logs to: $LOG_FILE"
  echo "[run.sh] mitmdump mode: $MODE"
  echo "[run.sh] addon mode: $ADDON_MODE"
  mitmdump \
    --set confdir="${MITM_CONF_DIR:-$HOME/.mitmproxy}" \
    --set block_global=false \
    --listen-host "$LISTEN_HOST" \
    --listen-port "$LISTEN_PORT" \
    --mode "$MODE" \
    --ssl-insecure \
    -s "$ADDON_SCRIPT" \
    2>&1 | tee -a "$LOG_FILE"
else
  exec mitmdump \
    --set confdir="${MITM_CONF_DIR:-$HOME/.mitmproxy}" \
    --set block_global=false \
    --listen-host "$LISTEN_HOST" \
    --listen-port "$LISTEN_PORT" \
    --mode "$MODE" \
    --ssl-insecure \
    -s "$ADDON_SCRIPT"
fi
