# mitmproxy addon

这个目录提供一个专门给 `codex-proxy` 使用的 `addon.py`。

当前 addon 支持两种模式：

- HTTP body relay: 把大请求体拆成多个小块上传到外网 relay，再把原始请求改写成一个很小的 `/relay/v1/chunked/complete`
- WebSocket relay: 拦截 Codex CLI 到 `/backend-api/codex/responses` 的握手，改写到 `/relay/v1/codex/ws`，并把大 `client -> server` WS 消息拆成多个小控制消息

这样做的关键点是：

- 大请求体或大 WS 消息不会直接经过统一网关
- HTTP 模式下仍然能把真实 Codex 的 SSE 响应回给客户端
- WS 模式下仍然能把真实 Codex 的 WebSocket 响应回给 Codex CLI

## 环境变量

- `CHUNK_RELAY_ENABLED=true`
- `CHUNK_RELAY_BASE_URL=https://your-external-relay.example.com`
- `CHUNK_RELAY_SHARED_SECRET=optional-secret`
- `CHUNK_RELAY_THRESHOLD_BYTES=102400`
- `CHUNK_RELAY_CHUNK_SIZE_BYTES=65536`
- `CHUNK_RELAY_TIMEOUT_SECONDS=120`
- `CHUNK_RELAY_UPLOAD_RETRIES=3`
- `CHUNK_RELAY_RETRY_BACKOFF_MS=400`
- `CHUNK_RELAY_MATCH_HOSTS=127.0.0.1,localhost,ab.chatgpt.com`
- `CHUNK_RELAY_MATCH_PATHS=/v1/responses,/otlp/v1/metrics`
- `CHUNK_RELAY_HEADER_ALLOWLIST=authorization,content-type,accept,user-agent,statsig-api-key,x-session-id,x-codex-session-id`
- `CHUNK_RELAY_WS_ENABLED=true`
- `CHUNK_RELAY_WS_BASE_URL=ws://your-external-relay.example.com/relay/v1/codex/ws`
- `CHUNK_RELAY_WS_MATCH_HOSTS=chatgpt.com`
- `CHUNK_RELAY_WS_MATCH_PATHS=/backend-api/codex/responses`
- `CHUNK_RELAY_WS_THRESHOLD_BYTES=20000`
- `CHUNK_RELAY_WS_CHUNK_SIZE_BYTES=8000`
- `CHUNK_RELAY_WS_MODE=ws` (`ws` 为默认分片透传模式；`http` 为把 WS 请求体转换为 HTTP/HTTPS 请求)
- `CHUNK_RELAY_WS_HTTP_URL=https://your-external-relay.example.com/relay/v1/codex/ws-http` (仅 `CHUNK_RELAY_WS_MODE=http` 时可选；不配则回退到 `CHUNK_RELAY_BASE_URL + /relay/v1/codex/ws-http`)

## 示例

```bash
export CHUNK_RELAY_BASE_URL=https://your-external-relay.example.com
export CHUNK_RELAY_SHARED_SECRET=replace-me
export CHUNK_RELAY_ENABLED=true
export CHUNK_RELAY_MATCH_HOSTS=ab.chatgpt.com
export CHUNK_RELAY_MATCH_PATHS=/otlp/v1/metrics
export CHUNK_RELAY_WS_ENABLED=true
export CHUNK_RELAY_WS_BASE_URL=ws://your-external-relay.example.com/relay/v1/codex/ws
export CHUNK_RELAY_WS_MATCH_HOSTS=chatgpt.com
/home/liahua/IdeaProject/codex-proxy/mitmproxy/run.sh
```

默认配置文件在 [`config.yaml`](/home/liahua/IdeaProject/codex-proxy/mitmproxy/config.yaml)。
