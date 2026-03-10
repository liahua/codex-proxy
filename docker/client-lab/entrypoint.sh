#!/usr/bin/env bash
set -euo pipefail

MITM_LOG=/tmp/mitm.log
CODEX_HOME_DIR="${CODEX_HOME_DIR:-/root/.codex}"
MITM_CONF_DIR="${MITM_CONF_DIR:-/root/.mitmproxy}"
MITM_CA_PEM="$MITM_CONF_DIR/mitmproxy-ca-cert.pem"
SYSTEM_CA_CRT="/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt"

mkdir -p "$CODEX_HOME_DIR"

if [ -f /shared-codex/auth.json ]; then
  cp /shared-codex/auth.json "$CODEX_HOME_DIR/auth.json"
fi

if [ -f /shared-codex/config.toml ]; then
  cp /shared-codex/config.toml "$CODEX_HOME_DIR/config.toml"
fi

/app/mitmproxy/run.sh >"$MITM_LOG" 2>&1 &
MITM_PID=$!

cleanup() {
  if kill -0 "$MITM_PID" >/dev/null 2>&1; then
    kill "$MITM_PID" >/dev/null 2>&1 || true
    wait "$MITM_PID" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

for _ in $(seq 1 30); do
  if python3 - <<'PY'
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 8080))
    print("ready")
finally:
    s.close()
PY
  then
    break
  fi
  sleep 1
done

if ! python3 - <<'PY'
import socket, sys
s = socket.socket()
try:
    s.connect(("127.0.0.1", 8080))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
then
  echo "mitm did not become ready"
  cat "$MITM_LOG" || true
  exit 1
fi

for _ in $(seq 1 30); do
  if [ -f "$MITM_CA_PEM" ]; then
    break
  fi
  sleep 1
done

if [ ! -f "$MITM_CA_PEM" ]; then
  echo "mitm CA certificate was not generated"
  cat "$MITM_LOG" || true
  exit 1
fi

cp "$MITM_CA_PEM" "$SYSTEM_CA_CRT"
update-ca-certificates >/dev/null 2>&1 || true

export CODEX_HOME="$CODEX_HOME_DIR"

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec /app/run_codex_inspect.sh
