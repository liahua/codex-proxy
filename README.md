# codex-proxy

一个独立的 Node 22 代理项目。

## Quick Start

远程中继模式，不需要 `CODEX_*`：

```bash
cd /home/liahua/IdeaProject/codex-proxy
npm install
RELAY_SHARED_SECRET=replace-me npm run start:relay
```

本机代理模式，直接复用当前机器的 `~/.codex/auth.json`：

```bash
cd /home/liahua/IdeaProject/codex-proxy
npm install
npm run start:codex
```

健康检查：

```bash
curl http://127.0.0.1:8787/healthz
```

## 两种模式

### 1. `relay-only`

远程服务只做中继：

- 接收 mitm 上传的 HTTP chunks
- 接收 Codex WebSocket relay
- 重组后把原始请求继续发到真实上游
- 不需要配置 `CODEX_REFRESH_TOKEN` / `CODEX_ACCESS_TOKEN`

最简启动：

```bash
cd /home/liahua/IdeaProject/codex-proxy
npm install
RELAY_SHARED_SECRET=replace-me npm run start:relay
```

### 2. `proxy-mode`

这个服务自己直接调用 Codex `/v1/responses`：

- 适合你本机直接把它当 Codex 代理用
- 需要 Codex 认证
- 可以直接复用当前机器已经登录的 `~/.codex/auth.json`

最简启动：

```bash
cd /home/liahua/IdeaProject/codex-proxy
npm install
npm run start:codex
```

默认监听：

- `http://127.0.0.1:8787`

健康检查：

```bash
curl http://127.0.0.1:8787/healthz
```

`start:codex` 会自动读取：

- `~/.codex/auth.json`
- 其中的 `tokens.refresh_token`
- 其中的 `tokens.account_id`

如果你想改路径，也可以：

```bash
CODEX_HOME=/path/to/codex-home npm run start:codex
```

或：

```bash
CODEX_AUTH_FILE=/path/to/auth.json npm run start:codex
```

启动脚本在 [`scripts/start-with-codex-auth.js`](/home/liahua/IdeaProject/codex-proxy/scripts/start-with-codex-auth.js)。

## 什么时候用哪个模式

- 你的目标是“本地 Codex CLI 已登录，远程只做分片重组和转发”：用 `relay-only`
- 你的目标是“直接访问这个服务的 `/v1/responses`，让它自己代发 Codex”：用 `proxy-mode`

## 项目说明

这个项目是按 `openclaw` 和它依赖的 `pi-ai` 里 `openai-codex` provider 的实现细节整理出来的，核心结论是：

- 上游接口不是 `api.openai.com`，而是 `https://chatgpt.com/backend-api/codex/responses`
- 认证不是 OpenAI API key，而是 ChatGPT OAuth access token
- 必要头部包括 `Authorization: Bearer <token>`、`chatgpt-account-id`、`OpenAI-Beta: responses=experimental`
- `accountId` 来自 access token 的 JWT claim: `https://api.openai.com/auth.chatgpt_account_id`
- refresh token 通过 `https://auth.openai.com/oauth/token` 交换新 access token

## 能力范围

- 提供 `POST /v1/responses`
- 支持流式 SSE 透传
- 支持 `CODEX_REFRESH_TOKEN` 自动刷新 access token
- 可选允许客户端自己通过 `Authorization: Bearer ...` 提供 token
- 提供分片 relay 接口：`/relay/v1/chunked/init`、`/relay/v1/chunked/chunks/:id/:index`、`/relay/v1/chunked/complete`
- 提供 `GET /healthz` 和 `GET /v1/models`

当前刻意只做 Responses 代理，不做 `/v1/chat/completions` 适配层。

## 手工运行

```bash
cd /home/liahua/IdeaProject/codex-proxy
cp .env.example .env
node src/server.js
```

或：

```bash
npm start
```

如果你已经有 `CODEX_REFRESH_TOKEN` / `CODEX_ACCESS_TOKEN`，也可以直接用这条路。

## 配置

常用环境变量：

- `HOST` / `PORT`: 监听地址和端口
- `RELAY_STORAGE_DIR`: 外网 relay 暂存分片的目录
- `RELAY_REQUEST_TTL_MS`: 分片请求的保留时长
- `RELAY_SHARED_SECRET`: 可选，要求分片上传和 complete 请求都带 `x-relay-secret`

只有 `proxy-mode` 需要的变量：

- `CODEX_BASE_URL`: 默认 `https://chatgpt.com/backend-api`
- `CODEX_CLIENT_ID`: 默认使用 `pi-ai` 里 `openai-codex` OAuth flow 的 client id
- `CODEX_ACCESS_TOKEN`: 直接提供 access token
- `CODEX_REFRESH_TOKEN`: 提供 refresh token，代理会自动刷新 access token
- `CODEX_ACCOUNT_ID`: 当 refresh 响应暂时拿不到可解析的 token 时可显式指定
- `CODEX_DEFAULT_MODEL`: 默认模型，默认 `gpt-5.4`
- `CODEX_ALLOWED_MODELS`: 逗号分隔的允许模型列表
- `ALLOW_CLIENT_AUTH_BEARER`: 设为 `true` 后，代理允许客户端请求头里的 Bearer token 覆盖服务端 token

认证优先级：

1. 如果 `ALLOW_CLIENT_AUTH_BEARER=true` 且请求头带 `Authorization: Bearer ...`，优先用客户端 token
2. 否则使用 `CODEX_ACCESS_TOKEN`
3. 否则使用 `CODEX_REFRESH_TOKEN` 自动换取 access token

## 请求示例

```bash
curl http://127.0.0.1:8787/v1/responses \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gpt-5.4",
    "stream": true,
    "instructions": "You are a precise coding assistant.",
    "input": [
      {
        "role": "user",
        "content": [
          { "type": "input_text", "text": "Explain quicksort in 5 lines." }
        ]
      }
    ]
  }'
```

## 返回行为

- 如果客户端请求 `stream: true`，上游 SSE 会原样透传
- 如果客户端请求 `stream: false`，代理会直接透传上游的非流式响应

## 分片中继方案

为了解决“统一网关会拦截所有大于 100KB 的请求体”这个约束，项目里额外提供了两套 relay 方案：

- HTTP body relay:
  本地 `mitmproxy` addon 拦截大 HTTP 请求体，把原始 body 拆成多个小块上传到 `/relay/v1/chunked/*`，再把原始请求改写成一个很小的 `/relay/v1/chunked/complete`。外网服务拼接请求体后会按原始 `method + url + headers + raw body` 转发；如果目标是 Codex `/v1/responses`，则仍然走专用的 Codex 认证与转发逻辑。这一层也适用于 `ab.chatgpt.com/otlp/v1/metrics` 这类大遥测 POST。

- WebSocket message relay:
  本地 `mitmproxy` addon 拦截 Codex CLI 到 `/backend-api/codex/responses` 的 WebSocket 握手，把它改写到 `/relay/v1/codex/ws`。对超过阈值的 `client -> server` WS 消息，addon 拆成多条小控制消息；外网 relay 重组原始 WS 消息后再转发到真实 Codex，`server -> client` 消息直接透传回本地客户端。

专用脚本在 [`mitmproxy/addon.py`](/home/liahua/IdeaProject/codex-proxy/mitmproxy/addon.py)，说明在 [`mitmproxy/README.md`](/home/liahua/IdeaProject/codex-proxy/mitmproxy/README.md)。

当前这套 relay 还额外做了两层保护：

- 本地 addon 对每个 chunk 做重试上传，并携带 `x-chunk-size`、`x-chunk-sha256`
- 外网 relay 在 HTTP `complete` 或 WS 重组阶段校验总长度和整包 `sha256`，防止 silent corruption

## 本地验证

```bash
npm test
```

## Docker 联调

如果你想用双容器模拟“真实 Codex CLI + mitm + relay”链路，直接看 [`docker-compose.yml`](/home/liahua/IdeaProject/codex-proxy/docker-compose.yml) 和 [`docker/README.md`](/home/liahua/IdeaProject/codex-proxy/docker/README.md)。

当前 compose 已经验证过真实 Codex CLI 的网络形态，并跑通了 WebSocket relay：

- 真实 Codex CLI 命中的域名和路径
- `/backend-api/codex/responses` 是 WebSocket，不是大 HTTP POST
- `client -> server` 的 `response.create` 帧会达到数十 KB，适合在 WS 消息层做分片
- relay 已经能在 Docker 联调里完成“改写握手 -> 分片 -> 重组 -> 请求真实 Codex -> 返回响应”
- HTTP relay 现在也可以用于大 `metrics` 请求，不再只限于 `/v1/responses`
