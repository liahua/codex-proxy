#!/usr/bin/env bash
set -euo pipefail

PROMPT="Print only the word ping."

export http_proxy="${http_proxy:-http://127.0.0.1:8080}"
export https_proxy="${https_proxy:-http://127.0.0.1:8080}"
export HTTP_PROXY="${HTTP_PROXY:-$http_proxy}"
export HTTPS_PROXY="${HTTPS_PROXY:-$https_proxy}"
export ALL_PROXY="${ALL_PROXY:-$http_proxy}"

echo "running codex via proxy ${http_proxy}"
echo "workspace: $(pwd)"

codex exec --skip-git-repo-check "$PROMPT"
status=$?
sleep 2
exit "$status"
