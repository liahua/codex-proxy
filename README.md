# codex-proxy

一个用于 Codex 请求转发/中继的 Node.js 服务。

## 1) 远程机器推荐：`relay-only`

### 云上一键启动（含拉代码）

如果你在云服务器上还没拉代码，可以直接执行：

```bash
curl -fsSL https://raw.githubusercontent.com/liahua/codex-proxy/work/scripts/bootstrap-relay-only.sh -o /tmp/bootstrap-relay-only.sh
bash /tmp/bootstrap-relay-only.sh --branch work --secret '换成你自己的强随机密钥'
```

这个脚本会自动完成：`git clone/pull`、生成 `relay-only.env`、安装依赖并启动 relay。

> 如果仓库已经在机器上，也可以直接用下面的“快速启动”。

### 快速启动

```bash
npm install
cp scripts/relay-only.env.example .env
# 按需修改 .env 里的 5 个核心变量
npm run start:relay
```

可直接参考这份最小 `.env`：

```env
HOST=0.0.0.0
PORT=8787
RELAY_STORAGE_DIR=./data/chunked-requests
RELAY_REQUEST_TTL_MS=900000
RELAY_SHARED_SECRET=replace-with-your-secret
```

健康检查：

```bash
curl http://127.0.0.1:8787/healthz
```

### 环境变量

下面这份表按“代码实际读取”整理，包含每个字段怎么用、是否有默认值、默认值是什么。

#### 服务端：`src/config.js`

| 变量 | 怎么用 | 有默认值 | 默认值 |
|---|---|---|---|
| `HOST` | relay 服务监听地址 | 是 | `0.0.0.0` |
| `PORT` | relay 服务监听端口 | 是 | `8787` |
| `RELAY_STORAGE_DIR` | 保存 `init/chunks/complete` 中间文件的目录 | 是 | `./data/chunked-requests` |
| `RELAY_REQUEST_TTL_MS` | 单个 `requestId` 暂存多久后视为过期，单位毫秒 | 是 | `900000` |
| `RELAY_SHARED_SECRET` | 校验请求头 `x-relay-secret`；为空时不做共享密钥校验 | 是 | 空字符串 `""` |
| `RELAY_PROTOCOL_V2_ENABLED` | 是否启用 `/relay/v2/chunked/*` 加密协议 | 是 | `false` |
| `RELAY_ENCRYPTION_KEYS` | v2 使用的密钥映射，JSON 格式，值为 base64 编码的 32 字节密钥 | 是 | 空对象 `{}` |
| `RELAY_DEBUG_LOG` | 打印 relay 路由命中、chunk 接收、组装完成、上游响应状态等调试日志 | 是 | `false` |
| `RELAY_DEBUG_LOG_BODY` | 在 debug 日志里附带请求体预览 | 是 | `false` |
| `RELAY_DEBUG_BODY_MAX_BYTES` | debug 日志中请求体预览的最大字节数 | 是 | `2048` |

说明：

- 生产环境至少应显式设置 `RELAY_SHARED_SECRET`。
- `RELAY_DEBUG_LOG_BODY=true` 时，才会用到 `RELAY_DEBUG_BODY_MAX_BYTES`。
- 默认值来源是 [src/config.js](/home/liahua/IdeaProject/codex-proxy/src/config.js)。

#### mitm 客户端 addon：`mitmproxy/addon.py`

| 变量 | 怎么用 | 有默认值 | 默认值 |
|---|---|---|---|
| `CHUNK_RELAY_ENABLED` | 是否启用 chunk relay 客户端逻辑 | 是 | `true` |
| `CHUNK_RELAY_BASE_URL` | 远端 relay 服务基地址；addon 会拼出 `/relay/v1/chunked/*` | 是 | 空字符串 `""` |
| `CHUNK_RELAY_SHARED_SECRET` | 上传 `init/chunks/complete` 时写入请求头 `x-relay-secret` | 是 | 空字符串 `""` |
| `CHUNK_RELAY_PROTOCOL_VERSION` | relay 客户端协议版本，支持 `v1`/`v2` | 是 | `v1` |
| `CHUNK_RELAY_ENCRYPTION_KEY_ID` | v2 请求/响应加密使用的 key id | 是 | `default` |
| `CHUNK_RELAY_ENCRYPTION_KEY` | v2 使用的 base64 编码 32 字节密钥 | 否 | 无 |
| `CHUNK_RELAY_CHUNK_SIZE_BYTES` | 单个 chunk 的大小，命中的 `POST` 请求体会按这个值切分 | 是 | `20480` |
| `CHUNK_RELAY_TIMEOUT_SECONDS` | addon 访问远端 relay 时的 HTTP 超时秒数；适用于 `init`、`chunk` 上传和最终 `complete` 请求 | 是 | `600` |
| `CHUNK_RELAY_UPLOAD_RETRIES` | `init` 和 `chunk` 上传失败时的最大重试次数 | 是 | `3` |
| `CHUNK_RELAY_RETRY_BACKOFF_MS` | 每次重试前的退避时间，单位毫秒 | 是 | `400` |
| `CHUNK_RELAY_MATCH_HOSTS` | host 命中集合；支持精确 host，如 `chatgpt.com`，也支持子域匹配，如 `.chatgpt.com` 或 `*.chatgpt.com`；命中后执行 `POST -> relay`、`GET -> 放过`、`WS -> 503` | 是 | `127.0.0.1,localhost,chatgpt.com,ab.chatgpt.com` |
| `CHUNK_RELAY_CONSOLE_LOG` | 是否在 mitm 控制台输出详细日志 | 是 | `true` |

说明：

- 只有 host 命中 `CHUNK_RELAY_MATCH_HOSTS` 才会触发规则；未命中一律透传。
- 命中 host 且是 `POST` 时，只有在 `CHUNK_RELAY_ENABLED=true` 且 `CHUNK_RELAY_BASE_URL` 非空时才会真正走 relay；否则直接返回 `503`。
- 默认值来源是 [mitmproxy/addon.py](/home/liahua/IdeaProject/codex-proxy/mitmproxy/addon.py)。

#### mitm 启动脚本：`mitmproxy/run.sh`

| 变量 | 怎么用 | 有默认值 | 默认值 |
|---|---|---|---|
| `MITM_LISTEN_HOST` | `mitmdump` 监听地址 | 是 | `127.0.0.1` |
| `MITM_LISTEN_PORT` | `mitmdump` 监听端口 | 是 | `15001` |
| `MITM_LOG_FILE` | `mitmdump` 进程日志文件，记录 addon 的 `print`、mitm 自身日志、连接报错等标准输出/错误输出 | 是 | `/tmp/codex-mitmproxy.log` |
| `MITM_UPSTREAM_PROXY` | 如果设置，`run.sh` 会把运行模式改成 `upstream:<proxy>` | 是 | 空字符串 `""` |
| `MITM_MODE` | `mitmdump --mode` 的原始值；当 `MITM_UPSTREAM_PROXY` 非空时会被覆盖 | 是 | `regular` |
| `MITM_CONF_DIR` | `mitmdump --set confdir`，用于证书和 mitm 配置目录 | 是 | `$HOME/.mitmproxy` |

说明：

- `MITM_UPSTREAM_PROXY` 的优先级高于 `MITM_MODE`。
- addon 的结构化 flow 日志现在也会进入 `MITM_LOG_FILE`，前缀为 `http_inspect `。
- 默认值来源是 [mitmproxy/run.sh](/home/liahua/IdeaProject/codex-proxy/mitmproxy/run.sh)。

#### 部署脚本：`scripts/bootstrap-relay-only.sh`

| 变量 | 怎么用 | 有默认值 | 默认值 |
|---|---|---|---|
| `REPO_URL` | 首次部署时 `git clone` 的仓库地址 | 是 | `https://github.com/liahua/codex-proxy.git` |
| `BRANCH` | 要部署的分支名 | 是 | `main` |
| `INSTALL_DIR` | 代码拉取和运行目录 | 是 | `/opt/codex-proxy` |
| `HOST_VALUE` | 生成 `relay-only.env` 时写入 `HOST` | 是 | `0.0.0.0` |
| `PORT_VALUE` | 生成 `relay-only.env` 时写入 `PORT` | 是 | `8787` |
| `SECRET_VALUE` | 生成 `relay-only.env` 时写入 `RELAY_SHARED_SECRET` | 是 | 空字符串 `""` |

说明：

- 这个脚本主要用于远端首次启动，实际 relay 进程读取的是生成后的 `relay-only.env`。
- `SECRET_VALUE` 虽然有默认值，但脚本要求它必须显式传入，空值会直接退出。

#### 部署脚本：`scripts/remote-relay-up.sh`

| 变量 | 怎么用 | 有默认值 | 默认值 |
|---|---|---|---|
| `PID_FILE` | 记录 relay 进程 PID 的文件路径 | 是 | `$ROOT_DIR/.relay-only.pid` |
| `LOG_DIR` | relay 标准输出和错误输出目录 | 是 | `$ROOT_DIR/logs` |
| `HOST` | 启动 relay 进程时导出的监听地址 | 是 | `0.0.0.0` |
| `PORT` | 启动 relay 进程时导出的监听端口 | 是 | `8787` |
| `RELAY_STORAGE_DIR` | 启动 relay 进程时导出的分片暂存目录 | 是 | `$ROOT_DIR/data/chunked-requests` |
| `RELAY_REQUEST_TTL_MS` | 启动 relay 进程时导出的请求保留时长 | 是 | `900000` |
| `RELAY_SHARED_SECRET` | 启动 relay 进程时导出的共享密钥 | 否 | 无默认值，必须在 env 文件中设置 |

说明：

- 脚本会先加载 `relay-only.env`，再给 `npm run start:relay` 注入这些变量。
- `RELAY_SHARED_SECRET` 为空或为 `replace-me` 时，脚本会拒绝启动。

调试日志示例：

```env
RELAY_DEBUG_LOG=true
RELAY_DEBUG_LOG_BODY=true
RELAY_DEBUG_BODY_MAX_BYTES=4096
```

开启后可看到类似日志：

```text
[relay-debug] {"event":"relay_route_matched","method":"POST","path":"/relay/v1/chunked/complete",...}
[relay-debug] {"event":"relay_complete_assembled","requestId":"...","path":"/v1/responses","bytes":123456,"bodyPreview":{...}}
```

### 协议行为

- 用户本地到远程中继：
  - HTTP/HTTPS 请求（例如 responses、responses/compact、metrics）会按规则走 relay。
  - Codex 的 WebSocket upgrade 会被 mitm 直接拦截并返回 `503`，让客户端自动回退到 HTTP/HTTPS。
- 远程中继到上游：服务端在 `complete` 阶段按 `targetUrl + method + headers + assembledBody` 原样转发。
- v1 和 v2 现在都会先对请求体做 gzip，再上传到 relay；relay 组装后会先解压，再把原始请求体转发给 upstream。
- 若启用 `v2`：本地 addon 到远端 relay 之间的请求元数据、gzip 后的请求体以及 relay 返回的响应体都会做 `AES-256-GCM` 加密；v1 保持明文 chunk 上传。
- relay 内部 gzip 只存在于客户端到 relay 这一跳；upstream 不会看到 `content-encoding: gzip`。
- 当前不支持原始业务请求自带 `content-encoding`，命中 relay 时会直接失败。

v2 最小示例：

服务端：

```env
RELAY_PROTOCOL_V2_ENABLED=true
RELAY_ENCRYPTION_KEYS={"default":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}
RELAY_SHARED_SECRET=replace-with-your-secret
```

mitm 客户端：

```env
CHUNK_RELAY_PROTOCOL_VERSION=v2
CHUNK_RELAY_ENCRYPTION_KEY_ID=default
CHUNK_RELAY_ENCRYPTION_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
CHUNK_RELAY_SHARED_SECRET=replace-with-your-secret
CHUNK_RELAY_BASE_URL=https://your-relay-host:8787
```

说明：

- `RELAY_ENCRYPTION_KEYS` 是服务端的 `keyId -> base64 密钥` 映射。
- `CHUNK_RELAY_ENCRYPTION_KEY_ID` 必须命中服务端映射中的 key。
- `CHUNK_RELAY_ENCRYPTION_KEY` 必须与服务端对应 key 的值完全一致。
- 密钥要求是 32 字节，生成示例：`openssl rand -base64 32`
- 请求上传的 metadata 中：
  `bodySize/bodySha256` 表示原始未压缩请求体，
  `compressedBodySize/compressedBodySha256` 表示 gzip 后上传体。

## 2) mitmproxy 配套

mitm 脚本与变量说明见：

- [mitmproxy/README.md](/home/liahua/IdeaProject/codex-proxy/mitmproxy/README.md)
- [mitmproxy/addon.py](/home/liahua/IdeaProject/codex-proxy/mitmproxy/addon.py)

先安装 Python 依赖：

```bash
python3 -m pip install -r requirements.txt
```

## 3) 最小请求示例

服务端不再直接接收 `/v1/responses`。正常使用方式是通过 `mitmproxy/addon.py` 走 relay。

如果你要手工验证 relay 协议，可以按下面三步：

```bash
curl http://127.0.0.1:8787/relay/v1/chunked/init \
  -H 'Content-Type: application/json' \
  -H 'x-relay-secret: replace-with-your-secret' \
  -d '{
    "requestId":"req_1",
    "method":"POST",
    "path":"/v1/responses",
    "targetUrl":"https://chatgpt.com/backend-api/codex/responses",
    "headers":{"content-type":"application/json"},
    "bodySize":17,
    "chunkCount":1
  }'
```

然后上传 chunk，再调用 `/relay/v1/chunked/complete`。

## 4) 测试

```bash
npm test
```
