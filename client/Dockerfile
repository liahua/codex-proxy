# Client-side interceptor: mitmproxy loaded with the codex-proxy relay addon.
# It rewrites Codex traffic into chunked, encrypted, delta relay calls aimed at
# the relay server, and decrypts the relay's response frames before handing the
# response back to the local Codex CLI.
FROM python:3.12-slim-bookworm

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      "mitmproxy==10.4.2" \
      "httpx==0.27.2" \
      "cryptography>=42" \
      "brotli" \
      "zstandard"

WORKDIR /app
COPY mitmproxy /app/mitmproxy
RUN chmod +x /app/mitmproxy/run.sh

ENV MITM_LISTEN_HOST=0.0.0.0 \
    MITM_LISTEN_PORT=15334 \
    MITM_CONF_DIR=/mitm-conf \
    MITM_ADDON_MODE=relay \
    MITM_LOG_FILE=/mitm-logs/codex-mitmproxy.log \
    MITM_ERROR_LOG_FILE=/mitm-logs/codex-mitmproxy-errors.log

EXPOSE 15334

CMD ["/app/mitmproxy/run.sh"]
