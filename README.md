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

## 只有一条客户端路径

**中继拒绝直连。** 服务端只认 v5 中继协议，任何直接打过来的 Codex 请求都会 404。

这是刻意的：如果本地 addon 没跑起来，你会立刻拿到一个明确的错误，而不是让一个未分片、
未额外加密的大请求直接撞上网关——那种失败是无声的，等你发现时已经暴露了。

所以客户端必须两样都有：

| | |
|---|---|
| `~/.codex/config.toml` | 把 Codex 指到 `https://codex.liahuas.top/v1`，secret 当 api-key |
| 本地 mitmproxy + 本仓库 addon | 拦截、分片、增量、加密 |

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
| `RELAY_KEEP_PER_CONVERSATION` | 每个会话保留几份快照，默认 `5`（少于 2 会让客户端必然 409） |
| `RELAY_MAX_SNAPSHOTS` | 快照总数上限，默认 `500` |
| `RELAY_MAX_SNAPSHOT_BYTES` | 快照总字节上限，默认 `2GB`——比个数更重要，快照是完整请求体 |

`CPA_STRIP_TOOL_NAMES` 现在是防御性配置。Codex CLI 只在用 ChatGPT 订阅登录时才会带
`image_gen` 命名空间工具；它和 CPA 注入的 hosted `image_generation` 同时出现，上游会整个请求报
`Function 'image_gen.imagegen' conflicts with a hosted tool in the same request.`
走 api-key provider 不发这个工具，所以这条配置留着不碍事，但已经不是必需的。

---

## 二、客户端

### 1. Codex CLI 配置

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

### 2. 启动本地拦截器

```bash
cd client
cp codex-relay.env.example codex-relay.env   # 填入服务端给的 secret 和 key
docker compose up -d --build
```

mitmproxy 监听 `127.0.0.1:15334`，CA 证书生成在 `client/mitm-conf/mitmproxy-ca-cert.pem`。

### 3. 让 Codex 走它

```bash
export CODEX_RELAY_SECRET=<RELAY_SHARED_SECRET>
export HTTPS_PROXY=http://127.0.0.1:15334
export SSL_CERT_FILE=$PWD/client/mitm-conf/mitmproxy-ca-cert.pem
codex
codex exec -m gpt-6-astra "..."   # 任意 CPA 提供的模型
```

Codex CLI 以为自己在直连 `codex.liahuas.top`，addon 把请求截下来压缩加密后再转发到同一个域名。
CA 证书必须让 Codex CLI 信任，否则 TLS 拦不下来——**拦不下来就会 404**，不会静默直连。

addon 会跳过自己发往 `codex.liahuas.top/relay/**` 的分片上传——中继和客户端是同一个域名，
没有这个判断就会无限递归拦截自己。

遥测（`ab.chatgpt.com/otlp/*`）不在拦截范围内，会从客户端直接外发；受限网络里它失败是无害的，
Codex CLI 不依赖它。

### 模型

**model 不做限制。** 客户端要什么模型就原样发给 CPA，CPA 有的都能用。看有哪些（在中继所在主机上）：

```bash
curl -s http://127.0.0.1:8317/v1/models -H "Authorization: Bearer $CPA_API_KEY"
```

实测 `gpt-5.5`、`gpt-6-astra`、`gpt-5.6-terra` 都能直接 `-m` 切换。个别模型（如
`gpt-5.3-codex-spark`）是上游拒绝，与中继无关。

服务端默认**不**改写 model——静默替换比清晰报错更糟。确实需要给某个名字做别名时才打开
`CPA_MODEL_MAP`。

### 为什么不用 `chatgpt_base_url`

CPA 有一条 `/backend-api/codex` 路由标着 "chatgpt_base_url compatible"，看起来更"原生"，但它
**只在 Codex CLI 走 ChatGPT 登录态时才生效**。实测没有 `auth.json` 时 Codex 会忽略
`chatgpt_base_url`，直接去打 `https://api.openai.com/v1/responses`：

```
ERROR: unexpected status 401 Unauthorized: Missing bearer or basic authentication in header,
       url: https://api.openai.com/v1/responses
```

既然已经不走 codex 认证，这条路用不了；自定义 provider 才是对的接法。

### 客户端配置

`client/codex-relay.env`：

| 变量 | 说明 | 默认 |
|---|---|---|
| `CHUNK_RELAY_BASE_URL` | 中继地址 | — |
| `CHUNK_RELAY_SHARED_SECRET` | 服务端签发的 secret | — |
| `CHUNK_RELAY_ENCRYPTION_KEY` | base64 32 字节 AES key，缺失直接启动失败 | — |
| `CHUNK_RELAY_CHUNK_SIZE_BYTES` | 单片大小 | `20480` |
| `CHUNK_RELAY_MAX_SNAPSHOTS` | 本地保留多少个会话的快照 | `32` |
| `CHUNK_RELAY_MAX_SNAPSHOT_BYTES` | 本地快照总字节上限 | `268435456` |
| `CHUNK_RELAY_SNAPSHOT_TTL_SECONDS` | 本地快照保留时长 | `86400` |
| `CHUNK_RELAY_ZSTD_LEVEL` | zstd 压缩级别 | `3` |
| `CHUNK_RELAY_MATCH_HOSTS` | 拦截哪些 host，就是中继自己的域名 | `codex.liahuas.top` |

---

## 三、协议（v5）

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

### 客户端重启后取回 base

客户端(mitmproxy)重启、崩溃或重部署后，内存里的快照全没了。这时它本该冷启动——实测冷启动
只有 ~2.5×，1MB 上下文 = 400KB / 21 个分片，正是最该避免的突发。

但服务端磁盘上还留着这个会话的快照。客户端会先 `POST /relay/v5/snapshot/fetch`（带
`conversationKey`）把它取回来当字典，那一轮就塌回一片。取不到本会话的（比如开的是全新会话），
`allowCrossConversation` 让服务端返回任意最近快照——开场请求的 instructions/tools 是共用的，
实测跨会话 base 把 38,917 B 压到 268 B（145×）。

**这是拿一次大下行换一次大上行。** 快照 body 最大 ~1MB，取回是个大 download；出站只发一个 tiny
请求。如果你的网关**下行也限流**，用 `CHUNK_RELAY_FETCH_REMOTE_BASE=false` 关掉，退回冷启动。

它只补"客户端丢了、服务端还有"这一半；服务端也丢了（重启/TTL/淘汰）就只能冷启动。

### 完整性

服务端重建出的 body 必须匹配客户端算的 `bodySha256`，否则**拒绝转发**。
用错字典能解压出看似合理的字节，这个校验是唯一的防线。

### 快照的自动清理

三层限制，服务端和客户端各有一套：

| | 服务端 | 客户端 |
|---|---|---|
| 过期时间 | `RELAY_SNAPSHOT_TTL_MS`，默认 24h | `CHUNK_RELAY_SNAPSHOT_TTL_SECONDS`，默认 24h |
| 每会话保留 | `RELAY_KEEP_PER_CONVERSATION`，默认 5 | 1（只压最新的 base，旧的没用） |
| 总量上限 | 500 份 / 2GB，超了从最旧的会话开始删 | 32 个会话 / 256MB |

服务端保留 5 份而不是 1 份，是因为客户端在响应流完之前拿不到新的 snapshot id——
只留 1 份会让它紧接着发出的下一个请求必然 409。5 份也能扛住并发和重试导致的乱序完成。

**清理是懒执行的**：只在写入新快照时触发。空闲的中继会把过期快照留到下一个请求为止，
所以 TTL 是"最长保留"而不是"准时删除"。

当前状态可以直接看：

```bash
curl -s https://codex.liahuas.top/healthz
# {"snapshots":{"snapshots":33,"conversations":16,"bytes":2981000}, ...}
```

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

## 四、验证

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

## 五、排障

| 现象 | 原因 |
|---|---|
| `conflicts with a hosted tool` | `CPA_STRIP_TOOL_NAMES` 没生效，或请求体是压缩的而服务端解不开 |
| 响应要等模型全部生成完才一次性出现 | 流式解密没挂上；检查响应头里有没有 `x-relay-upstream-status` |
| 每个请求都是冷启动大小 | 客户端没拿到 base；看 mitm 日志里的 `base updated` 和 `rebasing` |
| Codex 报 404 `direct requests are refused` | 拦截器没生效：mitm 没起、代理没设、或 CA 没被信任。**这是设计如此**——宁可报错也不让请求裸奔出去 |
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
