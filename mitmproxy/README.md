# mitmproxy addon

`mitmproxy/addon.py` 用于拦截本地流量并转发到远程 `codex-proxy`。

支持两类链路：

- 对话链路：`WSS`（`/backend-api/codex/responses`）
- 非对话链路：`HTTP/HTTPS REST`（例如 metrics）

## 常用环境变量

最小必填（通常只配这 5 个就能跑起来）：

- `CHUNK_RELAY_ENABLED=true`
- `CHUNK_RELAY_BASE_URL=https://relay.your-company.com`
- `CHUNK_RELAY_SHARED_SECRET=replace-me`
- `CHUNK_RELAY_WS_ENABLED=true`
- `CHUNK_RELAY_WS_BASE_URL=wss://relay.your-company.com/relay/v1/codex/ws`

WSS 对话转发常用：

- `CHUNK_RELAY_MATCH_HOSTS=ab.chatgpt.com`
- `CHUNK_RELAY_MATCH_PATHS=/otlp/v1/metrics`
- `CHUNK_RELAY_WS_MATCH_HOSTS=chatgpt.com,ab.chatgpt.com`
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

说明：当前通过 `./mitmproxy/run.sh` 直接加载 `addon.py`，不再使用 `mitmproxy/config.yaml`。

## 安装依赖

```bash
pip install -U mitmproxy
```

如果使用依赖 `httpx` 的历史版本 addon，再补一条：

```bash
pip install -U httpx
```


## 关于请求体切分

- 超过阈值才会切分：`CHUNK_RELAY_THRESHOLD_BYTES`（默认 `102400`，即 100KB，可改）
- 每个 chunk 大小：`CHUNK_RELAY_CHUNK_SIZE_BYTES`（默认 `20480`，即 20KB，可改）
- WS 大消息切分同理：`CHUNK_RELAY_WS_THRESHOLD_BYTES`（默认 `102400`）和 `CHUNK_RELAY_WS_CHUNK_SIZE_BYTES`（默认 `20480`）

`run.sh` 会设置 `stream_large_bodies`（默认 `100k`），让 mitmproxy 对大包走流式落盘。可用 `MITM_STREAM_LARGE_BODIES` 覆盖。


## 排障

如果看到 `error establishing server connection` 且目标 IP 不是你的 relay 地址，通常是客户端把其它站点流量也发给了 mitm。

- 这类日志不一定影响 Codex 对话链路。
- 关键是确认对话请求 host/path 能命中：`CHUNK_RELAY_WS_MATCH_HOSTS` 和 `CHUNK_RELAY_WS_MATCH_PATHS`。
- 当前 addon 默认会匹配 `chatgpt.com,ab.chatgpt.com`，路径按前缀匹配（默认 `/backend-api/codex/responses`）。
- 你的 relay 连通性请用 `curl http://<relay-host>:<port>/healthz` 验证；`ping` 不通不能单独说明 HTTP 不通（很多服务器禁 ICMP）。
