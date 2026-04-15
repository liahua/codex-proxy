#!/usr/bin/env sh
set -eu
# Enable pipefail when supported by the current shell (bash, zsh, ksh, etc.).
(set -o pipefail) >/dev/null 2>&1 && set -o pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LISTEN_HOST="${MITM_LISTEN_HOST:-127.0.0.1}"
LISTEN_PORT="${MITM_LISTEN_PORT:-15334}"
LOG_FILE="${MITM_LOG_FILE:-$PWD/codex-mitmproxy.log}"
UPSTREAM_PROXY="${MITM_UPSTREAM_PROXY:-}"
MODE="${MITM_MODE:-regular}"
ADDON_MODE="${MITM_ADDON_MODE:-relay}"
INTERNAL_LOG_FILE="${MITM_INTERNAL_LOG_FILE:-}"

export MITM_RECORD_OUTPUT_FILE="${MITM_RECORD_OUTPUT_FILE:-$LOG_FILE}"

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

mkdir -p "$(dirname "$MITM_RECORD_OUTPUT_FILE")"
echo "[run.sh] writing matched traffic logs to: $MITM_RECORD_OUTPUT_FILE"
echo "[run.sh] mitmdump mode: $MODE"
echo "[run.sh] addon mode: $ADDON_MODE"

if [ -n "$INTERNAL_LOG_FILE" ]; then
  mkdir -p "$(dirname "$INTERNAL_LOG_FILE")"
  echo "[run.sh] writing mitmdump internal logs to: $INTERNAL_LOG_FILE"
  exec mitmdump \
    --set confdir="${MITM_CONF_DIR:-$HOME/.mitmproxy}" \
    --set block_global=false \
    --listen-host "$LISTEN_HOST" \
    --listen-port "$LISTEN_PORT" \
    --mode "$MODE" \
    --ssl-insecure \
    -s "$ADDON_SCRIPT" \
    >>"$INTERNAL_LOG_FILE" 2>&1
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
