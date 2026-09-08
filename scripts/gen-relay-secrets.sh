#!/usr/bin/env bash
# Generates the two secrets the relay and its clients share:
#   RELAY_SHARED_SECRET  - the simple bearer-style auth on every relay call
#   RELAY_ENCRYPTION_KEY - base64 32-byte AES-256-GCM key for request/response bodies
#
# Usage:
#   ./scripts/gen-relay-secrets.sh            # print both secrets
#   ./scripts/gen-relay-secrets.sh --env      # print them as env assignments
set -euo pipefail

SHARED_SECRET="$(openssl rand -hex 32)"
ENCRYPTION_KEY="$(openssl rand -base64 32)"

if [ "${1:-}" = "--env" ]; then
  cat <<EOF
RELAY_SHARED_SECRET=${SHARED_SECRET}
RELAY_ENCRYPTION_KEYS={"default":"${ENCRYPTION_KEY}"}
CHUNK_RELAY_SHARED_SECRET=${SHARED_SECRET}
CHUNK_RELAY_ENCRYPTION_KEY=${ENCRYPTION_KEY}
EOF
  exit 0
fi

cat <<EOF
shared secret : ${SHARED_SECRET}
encryption key: ${ENCRYPTION_KEY}

server side (deploy/.env):
  RELAY_SHARED_SECRET=${SHARED_SECRET}
  RELAY_ENCRYPTION_KEYS={"default":"${ENCRYPTION_KEY}"}

client side (client/codex-relay.env):
  CHUNK_RELAY_SHARED_SECRET=${SHARED_SECRET}
  CHUNK_RELAY_ENCRYPTION_KEY=${ENCRYPTION_KEY}
EOF
