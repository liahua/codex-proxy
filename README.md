# codex-proxy

把受限网络里的 Codex CLI 接到自己的 CPA（CLIProxyAPI）上。

```
Codex CLI ──► 本地 mitmproxy ──► https://codex.liahuas.top ──► CPA ──► OpenAI
 (api-key)    (分片/增量/加密)      (cloudflared + 中继容器)
```

Codex CLI 配成普通的 api-key provider，直接对着 `codex.liahuas.top` 说话——**不需要 ChatGPT
订阅登录，不需要 `auth.json`**。OpenAI 凭据只存在于 CPA 里，中继和客户端都不持有。

mitmproxy 这一层只为一件事存在：公司网关限制出站请求体大小、并且会拆 TLS。它把请求切成小片、
额外加一层 AES-256-GCM，再发往中继。网络没有这些限制的机器可以完全不装它。

## 两种客户端接入方式

两种模式的 `~/.codex/config.toml` 完全一样，区别只在于要不要在本地挂一个 mitmproxy。

| | 直连模式 | 拦截模式 |
|---|---|---|
| 客户端要装什么 | 只改 `~/.codex/config.toml` | 再加 mitmproxy + 本仓库的 addon |
| 鉴权 | `RELAY_SHARED_SECRET` 当 bearer token | 同一个 secret |
| 请求分片 | ✗ | ✓ 每个出站 POST < 20KB |
| 增量传递 | ✗ | ✓ 历史不重复上传 |
| 请求/响应加密 | 只有 TLS | ✓ 额外一层 AES-256-GCM，可抗网关拆 TLS |
| 适用场景 | 网络没限制 | 网关限制 body 大小、或会拆 TLS |

两种方式共用同一个服务端、同一份 config.toml、同一个 secret。

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
| `CPA_MODEL_MAP` | 可选的 model 别名映射，**默认关闭**，不改写客户端选的模型 |
| `CPA_FORCE_MODEL` | 强制所有请求使用某个 model（可选） |
| `CPA_STRIP_TOOL_NAMES` | 剥离与 CPA 注入的 hosted tool 冲突的客户端工具，默认 `image_gen` |
| `CPA_DROP_UNMATCHED` | 非 Codex 流量（遥测等）直接丢弃，不外发 |
| `RELAY_SNAPSHOT_KEY_ID` | 快照落盘加密用的 key id，默认取 `RELAY_ENCRYPTION_KEYS` 的第一个 |
| `RELAY_DIRECT_ENABLED` | 是否开放直连模式，默认开 |

`CPA_STRIP_TOOL_NAMES` 现在是防御性配置。Codex CLI 只在用 ChatGPT 订阅登录时才会带
`image_gen` 命名空间工具；它和 CPA 注入的 hosted `image_generation` 同时出现，上游会整个请求报
`Function 'image_gen.imagegen' conflicts with a hosted tool in the same request.`
走 api-key provider 不发这个工具，所以这条配置留着不碍事，但已经不是必需的。

---

## 二、客户端 · 直连模式

`~/.codex/config.toml`：

```toml
model_provider = "codex-relay"
model = "gpt-5.5"                # 只是默认值，不是限制

[model_providers.codex-relay]
name = "codex-relay"
base_url = "https://codex.liahuas.top/v1"
env_key = "CODEX_RELAY_SECRET"
wire_api = "responses"
```

```bash
export CODEX_RELAY_SECRET=<RELAY_SHARED_SECRET>
codex
codex exec -m gpt-6-astra "..."   # 任意 CPA 提供的模型
```

### 模型

**model 不做限制。** 客户端要什么模型就原样发给 CPA，CPA 有的都能用：

```bash
curl -s https://codex.liahuas.top/v1/models -H "Authorization: Bearer $CODEX_RELAY_SECRET"
```

实测 `gpt-5.5`、`gpt-6-astra`、`gpt-5.6-terra` 都能直接 `-m` 切换。个别模型（如
`gpt-5.3-codex-spark`）是上游拒绝，与中继无关。

服务端默认**不**改写 model——静默替换比清晰报错更糟。确实需要给某个名字做别名时才打开
`CPA_MODEL_MAP`。

服务端会把 `/v1/responses`、`/v1/responses/compact`、`/v1/models` 以及 `/backend-api/codex/*`
的等价路径都转到 CPA，并换上 CPA 的 api-key。secret 也可以放在 `x-relay-secret` 头里。

### 为什么不用 `chatgpt_base_url`

CPA 有一条 `/backend-api/codex` 路由标着 "chatgpt_base_url compatible"，看起来更"原生"，但它
**只在 Codex CLI 走 ChatGPT 登录态时才生效**。实测没有 `auth.json` 时 Codex 会忽略
`chatgpt_base_url`，直接去打 `https://api.openai.com/v1/responses`：

```
ERROR: unexpected status 401 Unauthorized: Missing bearer or basic authentication in header,
       url: https://api.openai.com/v1/responses
```

既然已经不走 codex 认证，这条路用不了；自定义 provider 才是对的接法。

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

配置和直连模式**完全一样**，只多两个环境变量：

```bash
export CODEX_RELAY_SECRET=<RELAY_SHARED_SECRET>
export HTTPS_PROXY=http://127.0.0.1:15334
export SSL_CERT_FILE=$PWD/client/mitm-conf/mitmproxy-ca-cert.pem
codex
```

Codex CLI 以为自己在直连 `codex.liahuas.top`，addon 把请求截下来切片加密后再转发到同一个域名。
CA 证书必须让 Codex CLI 信任，否则 TLS 拦不下来。

addon 会跳过自己发往 `codex.liahuas.top/relay/**` 的分片上传——中继和客户端现在是同一个域名，
没有这个判断就会无限递归拦截自己。

遥测（`ab.chatgpt.com/otlp/*`）不在拦截范围内，会从客户端直接外发；受限网络里它失败是无害的，
Codex CLI 不依赖它。

### 客户端配置

`client/codex-relay.env`：

| 变量 | 说明 | 默认 |
|---|---|---|
| `CHUNK_RELAY_BASE_URL` | 中继地址 | — |
| `CHUNK_RELAY_SHARED_SECRET` | 服务端签发的 secret | — |
| `CHUNK_RELAY_ENCRYPTION_KEY` | base64 32 字节 AES key，缺失直接启动失败 | — |
| `CHUNK_RELAY_CHUNK_SIZE_BYTES` | 单片大小 | `20480` |
| `CHUNK_RELAY_MATCH_HOSTS` | 拦截哪些 host，就是中继自己的域名 | `codex.liahuas.top` |
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

### 落盘

delta 要求服务端保留上一轮的完整请求体，否则拼不回来。这些快照按 `RELAY_ENCRYPTION_KEYS`
的 key 做 AES-256-GCM 加密后才写盘（`snapshots/*/body.json`、`response-snapshots/*/texts.json`
都是 `{v,alg,keyId,iv,tag,ciphertext}` 信封），24 小时过期。

这挡住的是读到卷、宿主备份、VM 快照的人；**挡不住**攻破运行中的中继进程的人——密钥本来就在它内存里。

### 实测（203 KB 历史的第二轮）

```
turn 1 full   →  上行 1014 B（1 片）
turn 2 delta  →  上行  541 B（1 片），完整请求体本应 208242 B，省了 99.7%
```

单个出站请求体最大 20 KB，远低于常见的 100 KB 网关限制。

### delta 的适用边界

delta 只在新请求的 `input` 是已知快照的**前缀增长**时才成立。Codex CLI 有时会改写靠前的 item，
这时自动回退 full 上传——正确性优先，不会为了省流量拼错请求。

实测一次真实会话（3 次工具调用）：**6 次 full、3 次 delta**。上面那个 99.7% 是理想情况下的
上限，不是日常收益；真正保证「过得了 100KB 网关」的是切片，不是增量。

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
