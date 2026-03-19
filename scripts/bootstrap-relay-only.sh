#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/liahua/codex-proxy.git}"
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/codex-proxy}"
HOST_VALUE="${HOST_VALUE:-0.0.0.0}"
PORT_VALUE="${PORT_VALUE:-8787}"
SECRET_VALUE="${SECRET_VALUE:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --port)
      PORT_VALUE="$2"
      shift 2
      ;;
    --host)
      HOST_VALUE="$2"
      shift 2
      ;;
    --secret)
      SECRET_VALUE="$2"
      shift 2
      ;;
    --branch)
      BRANCH="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

if [ -z "$SECRET_VALUE" ]; then
  echo "Usage: $0 --secret <relay-shared-secret> [--dir /opt/codex-proxy] [--port 8787] [--host 0.0.0.0]"
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is required on the remote host."
  exit 1
fi

mkdir -p "$(dirname "$INSTALL_DIR")"
if [ ! -d "$INSTALL_DIR/.git" ]; then
  git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
else
  git -C "$INSTALL_DIR" fetch origin "$BRANCH"
  git -C "$INSTALL_DIR" checkout "$BRANCH"
  git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
fi

cat > "$INSTALL_DIR/relay-only.env" <<EOF
HOST=$HOST_VALUE
PORT=$PORT_VALUE
RELAY_STORAGE_DIR=./data/chunked-requests
RELAY_REQUEST_TTL_MS=900000
RELAY_SHARED_SECRET=$SECRET_VALUE
# RELAY_PROTOCOL_V2_ENABLED=true
# RELAY_ENCRYPTION_KEYS={"default":"replace-with-base64-32-byte-key"}
EOF

chmod +x "$INSTALL_DIR/scripts/remote-relay-up.sh" "$INSTALL_DIR/scripts/remote-relay-stop.sh"
"$INSTALL_DIR/scripts/remote-relay-up.sh" "$INSTALL_DIR/relay-only.env"
