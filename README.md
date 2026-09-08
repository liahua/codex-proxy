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
| `RELAY_KEEP_PER_CONVERSATION` | 每个会话保留几份快照，默认 `2`（少于 2 会让客户端必然 409） |
| `RELAY_MAX_SNAPSHOTS` | 快照总数上限，默认 `200` |
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
| `CHUNK_RELAY_MAX_SNAPSHOTS` | 本地保留多少个会话的快照 | `32` |
| `CHUNK_RELAY_MAX_SNAPSHOT_BYTES` | 本地快照总字节上限 | `268435456` |
| `CHUNK_RELAY_ZSTD_LEVEL` | zstd 压缩级别 | `3` |

---

## 四、协议（v5）

只有一条路径，没有明文模式，也没有降级：客户端没有 key 直接启动失败。

**每个请求发的都是"完整 body 的 zstd 压缩结果"**，唯一的变化是压缩时用不用字典：

```
init      加密信封（method/path/headers/各种 sha256/baseSnapshotId）
chunks    AES-256-GCM 分片，每片带 iv/tag/sha256
complete  服务端解密拼接 → zstd 解压 → 校验 sha256 → 转发 → 存快照 → 加密响应
```

### 增量是压缩的副产品

两端各存一份**完全相同的字节**（服务端存的就是客户端压缩时用的那份），客户端把新 body 拿
上一轮的快照当 zstd 字典压一遍。zstd 在字典里找到没变的历史，只输出新增部分的引用——
**不需要 diff 算法，也不对 OpenAI 的数据结构做任何假设**。乱序、中途改写、回退到更短的历史，
全都天然支持。

两端存的是原始字节而不是规范化 JSON，所以 Python 客户端和 Node 服务端不需要就
JSON 序列化顺序达成一致，字典逐字节相同是构造出来的。

### base 选择：三级

```
1. 本会话最近一份快照      → 常规轮次
2. 没有 → 任意会话最近一份 → 新会话开场（大量 instructions/tools 是共用的）
3. 都没有 → 不用字典       → 真冷启动
```

会话用 `prompt_cache_key` 标识（OpenAI 自己用来标记"同一段可缓存对话前缀"的字段）。
两端都**按会话保留**，所以并发的多个 Codex 会话各用各的 base，不会互相顶掉。

客户端总是同时算一遍无字典压缩，**取小的发**——选到不合适的 base 只会变慢一点点，绝不会变胖。

### 失配自愈

`baseSnapshotId` 放在 init 的加密信封里，服务端在**上传任何分片之前**就能校验：

```
init → 409 {code:"base_snapshot_unavailable"} → 客户端丢弃该 base，无字典重压，重发一次
```

服务端每个会话保留 2 份快照，因为客户端在响应流完之前拿不到新的 snapshot id——
只留 1 份会让它紧接着发出的下一个请求必然 409。

### 完整性

服务端重建出的 body 必须匹配客户端算的 `bodySha256`，否则**拒绝转发**。
用错字典能解压出看似合理的字节，这个校验是唯一的防线。

### 落盘

快照是完整请求体，按 `RELAY_ENCRYPTION_KEYS` 的 key 做 AES-256-GCM 加密后才写盘
（`{v,alg,keyId,iv,tag,ciphertext}` 信封）。这挡住的是读到卷、宿主备份、VM 快照的人；
**挡不住**攻破运行中中继进程的人——密钥本来就在它内存里。

### 实测

真实 Codex 会话（五步工具调用，同一 session）：

```
turn 1   body  39,022 B → wire 15,262 B   (冷启动，无 base)
turn 2   body  39,508 B → wire    344 B   (115x)
turn 3   body  39,994 B → wire    185 B   (216x)
turn 4   body  40,484 B → wire    182 B   (222x)
turn 5   body  40,972 B → wire    184 B   (223x)
turn 6   body  41,460 B → wire    164 B   (253x)
```

新会话的开场请求借用上一个会话的快照：`38,938 B → 254 B (153x)`，
否则会是 15 KB。

并发两个会话交替发送：各用各的 base，0 次 rebase，128x–251x。

500 KB 上下文的合成用例：`519,901 B → 104 B`，单片。

**每个出站请求体都是 1 片、几百字节**——这才是"总流量和突发形态不暴露"的实际含义，
单纯把大 body 切小并不能解决这个问题。

## 五、验证

```bash
npm test

# 不经过 mitmproxy，直接按 v5 协议打服务端
node scripts/smoke-relay.mjs \
  --base-url https://codex.liahuas.top \
  --secret "$RELAY_SHARED_SECRET" \
  --key "$RELAY_ENCRYPTION_KEY" \
  --model gpt-5.5 --history-kb 500
```

`smoke-relay.mjs` 会跑冷启动 + 增量两轮，打印每轮的 body 大小、实际上行字节和分片数；
任何一轮不是 200 或不是密文都会以非零码退出。

---

## 六、排障

| 现象 | 原因 |
|---|---|
| `conflicts with a hosted tool` | `CPA_STRIP_TOOL_NAMES` 没生效，或请求体是压缩的而服务端解不开 |
| 响应要等模型全部生成完才一次性出现 | 流式解密没挂上；检查响应头里有没有 `x-relay-upstream-status` |
| 每个请求都是冷启动大小 | 客户端没拿到 base；看 mitm 日志里的 `base updated` 和 `rebasing` |
| `unknown encryption keyId` | 两端 key id 或 key 本身不一致 |
| 401 | secret 不一致 |
| 频繁 `rebasing` | 服务端快照被过早淘汰；调大 `RELAY_KEEP_PER_CONVERSATION` 或 `RELAY_MAX_SNAPSHOTS` |
| `assembled body checksum mismatch` | 两端字典不一致，服务端已拒绝转发（这是预期的保护） |
| Codex CLI 一直 `Reconnecting` | TLS 拦截没生效（CA 没被信任），或响应没有流式返回 |

日志：

```bash
docker logs -f codex-relay          # 服务端，含路由与协议事件
docker logs -f codex-mitm           # 客户端 addon
tail -f client/logs/codex-mitmproxy.log
```

日志里的 `authorization`、`x-relay-secret` 等敏感头会被替换成 `<redacted sha256:xxxxxxxx>`，只保留指纹用于比对。
