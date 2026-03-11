# mitmproxy addon

`mitmproxy/addon.py` 用于拦截本地流量并转发到远程 `codex-proxy`。

支持两类链路：

- 对话链路：`WSS`（`/backend-api/codex/responses`）
- 非对话链路：`HTTP/HTTPS REST`（例如 metrics）

## 常用环境变量

最小必填（通常只配这 4 个就能跑起来）：

- `CHUNK_RELAY_ENABLED=true`
- `CHUNK_RELAY_BASE_URL=https://relay.your-company.com`
- `CHUNK_RELAY_SHARED_SECRET=replace-me`
- `CHUNK_RELAY_WS_ENABLED=true`

WSS 对话转发常用：

- `CHUNK_RELAY_MATCH_HOSTS=ab.chatgpt.com`
- `CHUNK_RELAY_MATCH_PATHS=/otlp/v1/metrics`
- `CHUNK_RELAY_WS_BASE_URL=wss://relay.your-company.com/relay/v1/codex/ws`
- `CHUNK_RELAY_WS_MATCH_HOSTS=chatgpt.com`
- `CHUNK_RELAY_WS_MATCH_PATHS=/backend-api/codex/responses`

WS 第二模式（可选）：

- `CHUNK_RELAY_WS_MODE=ws`（默认；可设为 `http`）
- `CHUNK_RELAY_WS_HTTP_URL=https://relay.your-company.com/relay/v1/codex/ws-http`（仅 `CHUNK_RELAY_WS_MODE=http` 时可选）

## 示例

```bash
export CHUNK_RELAY_BASE_URL=https://relay.your-company.com
export CHUNK_RELAY_SHARED_SECRET=replace-me
export CHUNK_RELAY_ENABLED=true
export CHUNK_RELAY_WS_ENABLED=true
export CHUNK_RELAY_WS_BASE_URL=wss://relay.your-company.com/relay/v1/codex/ws
./mitmproxy/run.sh
```

默认配置文件：`mitmproxy/config.yaml`。
