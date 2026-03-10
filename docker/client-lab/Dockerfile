FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates curl python3 python3-pip \
  && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages mitmproxy==10.1.6 httpx==0.27.2
RUN npm install -g @openai/codex@0.113.0

COPY mitmproxy /app/mitmproxy
COPY docker/client-lab/entrypoint.sh /app/entrypoint.sh
COPY docker/client-lab/run_codex_inspect.sh /app/run_codex_inspect.sh

RUN chmod +x /app/entrypoint.sh /app/mitmproxy/run.sh /app/run_codex_inspect.sh

ENTRYPOINT ["/app/entrypoint.sh"]
