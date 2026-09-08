# codex-proxy

把受限网络里的 Codex CLI 接到自己的 CPA（CLIProxyAPI）上。

```
Codex CLI ──► 本地 mitmproxy ──► https://codex.liahuas.top ──► CPA ──► OpenAI
              (分片/增量/加密)      (cloudflared + 中继容器)
```

服务端只做一件事：解密、拼接、还原请求，然后转发给 CPA，由 CPA 用它自己的凭据去访问 OpenAI。
服务端不持有任何 OpenAI/ChatGPT 凭据。

## 两种客户端接入方式

| | 直连模式 | 拦截模式 |
|---|---|---|
| 客户端要装什么 | 只改 `~/.codex/config.toml` | mitmproxy + 本仓库的 addon |
| 鉴权 | `RELAY_SHARED_SECRET` 当 bearer token | 同一个 secret |
| 请求分片 | ✗ | ✓ 每个出站 POST < 20KB |
| 增量传递 | ✗ | ✓ 历史不重复上传 |
| 请求/响应加密 | 只有 TLS | ✓ 额外一层 AES-256-GCM |
| 适用场景 | 网络没限制，图省事 | 网关限制 body 大小 / 阻断 WebSocket |

两种方式共用同一个服务端和同一个 secret。

---

## 一、服务端

### 部署

```bash
cd deploy
cp .env.example .env
../scripts/gen-relay-secrets.sh --env    # 把生成的两个值填进 .env
docker compose up -d --build
curl http://127.0.0.1:8788/healthz
```

容器只监听 `127.0.0.1:8788`，并加入 CPA 所在的 docker 网络，直接用 `http://cli-proxy-api:8317` 访问 CPA，不额外暴露端口。

### 域名上报

用已有的 cloudflared 隧道（和 `code.liahuas.top` 同一条）：

```bash
# 1. ~/.cloudflared/config.yml 的 ingress 里，在 catch-all 之前加：
#   - hostname: codex.liahuas.top
#     service: http://127.0.0.1:8788

cloudflared --config ~/.cloudflared/config.yml tunnel ingress validate
cloudflared --config ~/.cloudflared/config.yml tunnel route dns <tunnel-id> codex.liahuas.top
systemctl --user restart cloudflared.service

curl https://codex.liahuas.top/healthz
```

改配置前先备份，重启后逐个复验隧道上的其它域名——重启会同时影响它们。

### 服务端配置

`deploy/.env`：

| 变量 | 说明 |
|---|---|
| `RELAY_SHARED_SECRET` | 客户端唯一需要的鉴权凭据 |
| `RELAY_ENCRYPTION_KEYS` | `{"default":"<base64 32 字节>"}`，与客户端的 key 对应 |
| `CPA_BASE_URL` | CPA 地址，默认 `http://cli-proxy-api:8317` |
| `CPA_API_KEY` | CPA 的 api-key |
| `CPA_MODEL_MAP` | Codex 的 model id → CPA 实际提供的 model |
| `CPA_FORCE_MODEL` | 强制所有请求使用某个 model（可选） |
| `CPA_STRIP_TOOL_NAMES` | 剥离与 CPA 注入的 hosted tool 冲突的客户端工具，默认 `image_gen` |
| `CPA_DROP_UNMATCHED` | 非 Codex 流量（遥测等）直接丢弃，不外发 |
| `RELAY_DIRECT_ENABLED` | 是否开放直连模式，默认开 |

`CPA_STRIP_TOOL_NAMES` 是必要的：Codex CLI 会带一个 `image_gen` 命名空间工具，CPA 会注入 hosted 的 `image_generation`，两者同时出现时上游会整个请求报
`Function 'image_gen.imagegen' conflicts with a hosted tool in the same request.`

---

## 二、客户端 · 直连模式

`~/.codex/config.toml`：

```toml
model = "gpt-5.5"
model_provider = "codex-relay"

[model_providers.codex-relay]
name = "codex-relay"
base_url = "https://codex.liahuas.top/v1"
env_key = "CODEX_RELAY_SECRET"
wire_api = "responses"
```

```bash
export CODEX_RELAY_SECRET=<RELAY_SHARED_SECRET>
codex
```

服务端会把 `/v1/responses`、`/v1/responses/compact`、`/v1/models` 以及 `/backend-api/codex/*` 的等价路径都转到 CPA，并换上 CPA 的 api-key。secret 也可以放在 `x-relay-secret` 头里。

---

## 三、客户端 · 拦截模式

### 启动

```bash
cd client
cp codex-relay.env.example codex-relay.env   # 填入服务端给的 secret 和 key
docker compose up -d --build
```

mitmproxy 监听 `127.0.0.1:15334`，CA 证书生成在 `client/mitm-conf/mitmproxy-ca-cert.pem`。

### 让 Codex CLI 走它

```bash
export HTTPS_PROXY=http://127.0.0.1:15334
export SSL_CERT_FILE=$PWD/client/mitm-conf/mitmproxy-ca-cert.pem
codex
```

这条路径用 Codex CLI 自己的 ChatGPT 登录态发请求，但请求体不会真的发到 chatgpt.com——addon 会拦截改写到中继。CA 证书必须让 Codex CLI 信任，否则 TLS 拦截不成立。

Codex CLI 默认走 WebSocket，addon 会用 501 拒绝握手，让它回退到 HTTPS；日志里会看到几行 `Reconnecting...`，属于正常现象。

### 客户端配置

`client/codex-relay.env`：

| 变量 | 说明 | 默认 |
|---|---|---|
| `CHUNK_RELAY_BASE_URL` | 中继地址 | — |
| `CHUNK_RELAY_SHARED_SECRET` | 服务端签发的 secret | — |
| `CHUNK_RELAY_ENCRYPTION_KEY` | base64 32 字节 AES key，缺失直接启动失败 | — |
| `CHUNK_RELAY_CHUNK_SIZE_BYTES` | 单片大小 | `20480` |
| `CHUNK_RELAY_MATCH_HOSTS` | 拦截哪些 host | `chatgpt.com,ab.chatgpt.com` |
| `CHUNK_RELAY_WS_BLOCK_STATUS` | 拒绝 WS 握手用的状态码 | `501` |
| `CHUNK_RELAY_MAX_DELTA_SNAPSHOTS` | 本地保留多少个可复用快照 | `32` |

---

## 四、协议（v4）

只有 v4 一种协议。没有明文模式，也没有降级路径：客户端没有 key 就直接启动失败。

三条上传路径，服务端各有一组 `init` / `chunks/:id/:index` / `complete`：

- **full** — 整个请求体。gzip 后 AES-256-GCM 加密，切片上传。第一轮对话走这里。
- **delta** — 只上传新增的 `input` 尾巴 + 非 `input` 字段，服务端用上一轮的快照拼回完整请求，并校验 canonical body 的 sha256。
- **refs** — 请求里凡是与上一轮响应文本完全相同的字符串，替换成 `$relayRef` 占位，服务端展开。

请求侧：

- 元数据（method / path / targetUrl / headers / 各种 sha256）加密后放在 `init` 的信封里
- 每个分片单独用随机 nonce 加密，带 `x-chunk-iv`、`x-chunk-tag`、`x-chunk-sha256`
- 服务端校验单片 sha256、拼接后的压缩体 sha256、解压后的 body sha256

响应侧：

- 服务端把上游响应切成 `meta` + 若干 `data` 帧，逐帧 AES-256-GCM 加密后流式写回
- 状态码、content-type 和快照 id 额外以明文头下发，客户端才能在 body 到达前就开始流式解密；正文本身始终是密文
- addon 在 `responseheaders` 阶段挂上流式解密器，边收边解，SSE 不会被憋到最后一次性吐出

### 实测（203 KB 历史的第二轮）

```
turn 1 full   →  上行 1014 B（1 片）
turn 2 delta  →  上行  541 B（1 片），完整请求体本应 208242 B，省了 99.7%
```

单个出站请求体最大 20 KB，远低于常见的 100 KB 网关限制。

### delta 的适用边界

delta 只在新请求的 `input` 是已知快照的**前缀增长**时才成立。Codex CLI 有时会改写靠前的 item，这时会自动回退到 full 上传——正确性优先，不会为了省流量而拼错请求。

---

## 五、验证

```bash
npm test

# 不经过 mitmproxy，直接按 v4 协议打服务端
node scripts/smoke-relay.mjs \
  --base-url https://codex.liahuas.top \
  --secret "$RELAY_SHARED_SECRET" \
  --key "$RELAY_ENCRYPTION_KEY" \
  --model gpt-5.5 --history-kb 200
```

`smoke-relay.mjs` 会跑 full + delta 两轮，打印每轮的上行字节数、分片数和增量节省比例；任何一轮不是 200 或不是密文都会以非零码退出。

---

## 六、排障

| 现象 | 原因 |
|---|---|
| `conflicts with a hosted tool` | `CPA_STRIP_TOOL_NAMES` 没生效，或请求体是压缩的而服务端解不开 |
| 响应要等模型全部生成完才一次性出现 | 流式解密没挂上；检查响应头里有没有 `x-relay-upstream-status` |
| `unknown encryption keyId` | 两端 key id 或 key 本身不一致 |
| 401 | secret 不一致 |
| 409 `base snapshot unavailable` | 服务端快照已过期（`RELAY_SNAPSHOT_TTL_MS`），客户端会自动回退 full |
| Codex CLI 一直 `Reconnecting` | TLS 拦截没生效（CA 没被信任），或响应没有流式返回 |

日志：

```bash
docker logs -f codex-relay          # 服务端，含路由与协议事件
docker logs -f codex-mitm           # 客户端 addon
tail -f client/logs/codex-mitmproxy.log
```

日志里的 `authorization`、`x-relay-secret` 等敏感头会被替换成 `<redacted sha256:xxxxxxxx>`，只保留指纹用于比对。
