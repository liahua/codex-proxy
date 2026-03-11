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
- `CHUNK_RELAY_BLOCK_NON_MATCHED=true`（默认开启；仅允许 relay/chatgpt 命中主机，避免系统其它流量触发外网连接报错）
- `CHUNK_RELAY_CONSOLE_LOG=true`（默认开启；在请求进入时先打印完整 HTTP 请求，请求返回后打印完整 HTTP 响应，若失败则打印错误上下文，并打印 WS 消息）

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



> 补充：WebSocket 建连是 HTTP Upgrade；升级成功后是 WS 帧协议。若连接阶段失败，可在本地看到 `【HTTP Flow Error】` 的完整请求与错误信息。

## 排障

如果看到 `error establishing server connection`，通常是两类原因：

- 本机把与 Codex 无关的系统流量也走了该代理（会尝试连接各种外部 IP）；
- relay 地址不可达。

建议按顺序检查：

1. 只让 Codex 客户端走这个代理，不要全局代理系统流量。
2. 保持 `CHUNK_RELAY_BLOCK_NON_MATCHED=true`（默认），非命中主机会直接 403，不再尝试外连。
3. 验证 relay 连通性（以 HTTP 为准）：

```bash
curl -sv http://<relay-host>:<port>/healthz
```

> `ping` 不通不一定代表 HTTP 不通（很多云主机会禁 ICMP）。

