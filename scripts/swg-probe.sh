#!/usr/bin/env bash
# Replays the relay's streamed response shape through a corporate web gateway,
# one dimension at a time, to find what makes the gateway cut the stream.
# Runs curl straight at the relay (through the gateway if SWG_PROXY is set),
# never through mitmproxy, so the addon and httpx are out of the picture.
#
#   RELAY_SECRET=... SWG_PROXY=http://proxysg.example.com:8080 scripts/swg-probe.sh
#
# Env:
#   RELAY_BASE   relay origin, default https://codex.liahuas.top
#   RELAY_SECRET x-relay-secret value (required)
#   SWG_PROXY    proxy URL for curl -x; empty = direct
#   REPEAT       runs per case, default 3
#   MAXTIME      curl --max-time per run, default 90
#   DURATION     seconds for the long cases, default 40
#   CASES        space-separated case names to run, default all
#   OUT          result file, default ./swg-probe-<timestamp>.log
#   WITH_DELAY=1 also run the silent-delay cases (needed only if polling is chosen)
set -u

RELAY_BASE="${RELAY_BASE:-https://codex.liahuas.top}"
RELAY_BASE="${RELAY_BASE%/}"
RELAY_SECRET="${RELAY_SECRET:-}"
SWG_PROXY="${SWG_PROXY:-}"
REPEAT="${REPEAT:-3}"
MAXTIME="${MAXTIME:-90}"
DURATION="${DURATION:-40}"
CASES="${CASES:-}"
OUT="${OUT:-./swg-probe-$(date +%Y%m%d-%H%M%S).log}"
WITH_DELAY="${WITH_DELAY:-0}"

if [ -z "$RELAY_SECRET" ]; then
  echo "RELAY_SECRET is required" >&2
  exit 2
fi

PROXY_ARGS=()
if [ -n "$SWG_PROXY" ]; then
  PROXY_ARGS=(-x "$SWG_PROXY")
fi

FMT='code=%{http_code} down=%{size_download} t=%{time_total}s ttfb=%{time_starttransfer}s v=%{http_version} exit=%{exitcode} err="%{errormsg}"'
RUN_ID="$(date +%s)-$$"

log() { printf '%s\n' "$*" | tee -a "$OUT"; }

# run <case> <method> <path-with-query>
run() {
  local name="$1" method="$2" path="$3" i line
  for i in $(seq 1 "$REPEAT"); do
    local label="${RUN_ID}-${name}-${i}"
    local sep='?'
    case "$path" in *\?*) sep='&';; esac
    local url="${RELAY_BASE}${path}${sep}label=${label}"
    local started
    started="$(date +%H:%M:%S)"
    if [ "$method" = "POST" ]; then
      line="$(curl "${PROXY_ARGS[@]}" -sS -o /dev/null --max-time "$MAXTIME" -w "$FMT" \
        -X POST -H 'content-type: application/json' -H 'accept: text/event-stream' \
        -H "x-relay-secret: $RELAY_SECRET" -d "{\"requestId\":\"${label}\"}" "$url" 2>&1)"
    else
      line="$(curl "${PROXY_ARGS[@]}" -sS -o /dev/null --max-time "$MAXTIME" -w "$FMT" \
        -H "x-relay-secret: $RELAY_SECRET" "$url" 2>&1)"
    fi
    log "$name run=$i start=$started $line"
  done
}

want() {
  [ -z "$CASES" ] && return 0
  case " $CASES " in *" $1 "*) return 0;; esac
  return 1
}

log "# swg-probe run=$RUN_ID date=$(date -Is) host=$(hostname)"
log "# relay=$RELAY_BASE proxy=${SWG_PROXY:-direct} repeat=$REPEAT maxtime=$MAXTIME duration=$DURATION"
log "# $(curl --version | head -1)"
log "# columns: code down=bytes t=total ttfb=first-byte v=http-version exit=curl-exit err=curl-error"

D="$DURATION"
# R0 exact replica: POST on the probe path, relay headers, encrypted frames, 9KB/s.
want R0 && run R0-replica    POST "/relay/probe/drip?d=$D"
# R1 content type only.
want R1 && run R1-ct-sse     POST "/relay/probe/drip?d=$D&ct=text/event-stream"
want R1 && run R1-ct-text    POST "/relay/probe/drip?d=$D&ct=text/plain"
# R2 relay-specific response headers removed.
want R2 && run R2-nohdr      POST "/relay/probe/drip?d=$D&hdr=0"
# R3 body entropy: SSE text instead of ciphertext.
want R3 && run R3-ascii      POST "/relay/probe/drip?d=$D&body=ascii"
# R3b everything plain at once: text/plain, no relay headers, ascii body.
want R3 && run R3-allplain   POST "/relay/probe/drip?d=$D&body=ascii&hdr=0&ct=text/plain"
# R4 byte rate down to 100B/s: time wall vs byte wall.
want R4 && run R4-slow       POST "/relay/probe/drip?d=$D&rate=100"
# R5 60KB/s for 15s (~900KB): a byte-count trigger shows up before 15s.
want R5 && run R5-fast       POST "/relay/probe/drip?d=15&rate=60000"
# R6 20s at replica settings: the safe-duration line.
want R6 && run R6-short      POST "/relay/probe/drip?d=20"
# R7 GET instead of POST.
want R7 && run R7-get        GET  "/relay/probe/drip?d=$D"
# R8 replica on the real complete path, in case policy keys on the URL.
want R8 && run R8-realpath   POST "/relay/v5/request/complete?probe=drip&d=$D"

if [ "$WITH_DELAY" = "1" ]; then
  # Silent server for N seconds, then a small JSON answer: long-poll budget.
  want D1 && run D1-delay20  GET "/relay/probe/delay?ms=20000"
  want D1 && run D1-delay30  GET "/relay/probe/delay?ms=30000"
  want D1 && run D1-delay45  GET "/relay/probe/delay?ms=45000"
fi

log "# done $(date -Is) -> $OUT"
