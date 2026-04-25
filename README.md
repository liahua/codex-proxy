# codex-proxy

这个分支现在有两种用途：

- `record-only`：给 Codex 挂一个本地 MITM 监控层，把 HTTP 和 WebSocket 流量完整记录下来，不改写请求。
- `relay`：把匹配到的 HTTP 请求改写到 relay 服务，relay 负责加密分片、服务端拼接、request delta 和 response refs，再转发给真实上游。

默认启动模式是 `relay`。如果只想抓包观察，显式设置 `MITM_ADDON_MODE=record-only`。

## 你能拿到什么

- HTTP 请求头
- HTTP 请求体
- HTTP 响应头
- HTTP 响应体
- WebSocket 握手请求头
- WebSocket 握手响应头和状态码
- WebSocket 每一条消息
- WebSocket 关闭事件

body 记录分两层：

- `raw`：原始字节内容
- `decoded`：如果能识别，会额外做解压和转码，尽量给出可读文本或 JSON

当前支持的转码包括：

- `gzip`
- `deflate`
- `br`
- `zstd`
- `utf-8`
- `json`

## 目录说明

- [mitmproxy/run.sh](/home/liahua/IdeaProject/codex-proxy/mitmproxy/run.sh)：启动 mitmdump 的脚本
- [mitmproxy/record_only_addon.py](/home/liahua/IdeaProject/codex-proxy/mitmproxy/record_only_addon.py)：只记录、不改写的 addon
- [mitmproxy/README.md](/home/liahua/IdeaProject/codex-proxy/mitmproxy/README.md)：MITM 详细操作手册
- [requirements.txt](/home/liahua/IdeaProject/codex-proxy/requirements.txt)：Python 依赖

## 5 分钟上手

### 1. 安装依赖

```bash
python3 -m pip install -r requirements.txt
```

### 2. 启动 mitm

默认是 relay 模式：

```bash
./mitmproxy/run.sh
```

如果你只想记录、不改写请求：

```bash
export MITM_ADDON_MODE=record-only
./mitmproxy/run.sh
```

### 3. 让 Codex 走这个代理

把 Codex 的代理指到 mitm：

```bash
export http_proxy=http://127.0.0.1:15334
export https_proxy=http://127.0.0.1:15334
export HTTP_PROXY=$http_proxy
export HTTPS_PROXY=$https_proxy
```

如果你的运行环境也看 `ALL_PROXY`，再补一条：

```bash
export ALL_PROXY=$http_proxy
```

### 4. 安装 mitm CA 证书

第一次使用 mitmproxy，需要把 mitm 生成的 CA 证书导入到运行 Codex 的环境里。

默认位置：

```bash
$HOME/.mitmproxy/mitmproxy-ca-cert.pem
```

如果不导入，HTTPS 和 WSS 流量会因为证书校验失败而看不到完整内容。

### 5. 看日志

默认日志文件：

```bash
$PWD/codex-mitmproxy.log
```

实时看日志：

```bash
tail -f ./codex-mitmproxy.log
```

你会看到两类结构化日志：

- `http_inspect ...`
- `ws_inspect ...`

## 最常用启动方式

### 记录所有流量

```bash
export MITM_ADDON_MODE=record-only
export MITM_RECORD_MATCH_HOSTS=
export MITM_RECORD_BODY_MAX_BYTES=0
./mitmproxy/run.sh
```

说明：

- `MITM_RECORD_MATCH_HOSTS=` 为空，表示记录所有 host
- `MITM_RECORD_BODY_MAX_BYTES=0` 表示不截断 body

### 只记录 Codex 相关域名

```bash
export MITM_ADDON_MODE=record-only
export MITM_RECORD_MATCH_HOSTS=chatgpt.com,.chatgpt.com,openai.com,.openai.com
export MITM_RECORD_BODY_MAX_BYTES=0
./mitmproxy/run.sh
```

说明：

- `chatgpt.com` 匹配裸域
- `.chatgpt.com` 匹配子域
- 两种通常要一起写

### 改日志文件位置

```bash
export MITM_LOG_FILE=$PWD/logs/mitm.log
export MITM_ERROR_LOG_FILE=$PWD/logs/mitm-errors.log
./mitmproxy/run.sh
```

## 日志里会长什么样

HTTP 请求：

```text
http_inspect {"event":"http_request","url":"https://chatgpt.com/...","headers":{...},"body":{"raw":{...},"decoded":{...}}}
```

HTTP 响应：

```text
http_inspect {"event":"http_response","status_code":200,"headers":{...},"body":{"raw":{...},"decoded":{...}}}
```

非 2xx / 网络错误精简日志：

```text
http_error_summary {"event":"http_error_summary","status_code":502,"url":"https://...","request_body":{...},"response_body":{...}}
```

WebSocket 握手和消息：

```text
ws_inspect {"event":"websocket_start","response_status_code":101,"request_headers":{...},"response_headers":{...}}
ws_inspect {"event":"websocket_message","from_client":true,"message_type":"text","content":{"raw":{...},"decoded":{...}}}
ws_inspect {"event":"websocket_end","close_code":1000}
```

注意：`relay` 模式会阻断 WebSocket，让 Codex 回退到 HTTP；如果你要记录 WebSocket 消息，使用 `MITM_ADDON_MODE=record-only`。

## 环境变量

### mitm 启动

| 变量 | 说明 | 默认值 |
|---|---|---|
| `MITM_ADDON_MODE` | addon 模式 | `relay` |
| `MITM_LISTEN_HOST` | mitm 监听地址 | `127.0.0.1` |
| `MITM_LISTEN_PORT` | mitm 监听端口 | `15334` |
| `MITM_LOG_FILE` | 完整匹配流量日志路径 | `$PWD/codex-mitmproxy.log` |
| `MITM_ERROR_LOG_FILE` | 非 2xx / 网络错误精简日志路径 | `$PWD/codex-mitmproxy-errors.log` |
| `MITM_ERROR_BODY_MAX_BYTES` | error 精简日志里请求/响应 body 最大记录字节数；`0` 表示不截断 | `8192` |
| `MITM_UPSTREAM_PROXY` | 如果你的网络本身还要再过一层上游代理，可以填这里 | 空 |
| `MITM_MODE` | mitmdump 原始模式 | `regular` |
| `MITM_CONF_DIR` | mitm 配置目录和证书目录 | `$HOME/.mitmproxy` |

### record-only 记录范围

| 变量 | 说明 | 默认值 |
|---|---|---|
| `MITM_RECORD_MATCH_HOSTS` | 要记录的 host；为空表示全部记录 | 空 |
| `MITM_RECORD_CONSOLE_LOG` | 是否在控制台输出简短日志 | `true` |
| `MITM_RECORD_BODY_MAX_BYTES` | body 最大记录字节数；`0` 表示不截断 | `0` |

### relay delta / response refs

`CHUNK_RELAY_PROTOCOL_VERSION=v4` 会启用 request delta 和 response refs：第一次请求仍然按现有 chunk relay 上传完整 body；relay 成功转发后保存一个请求快照和 response 可引用文本；后续请求如果 `input` 是上一次快照的前缀增长，mitm 只上传新增的 `input` tail 和当前非 `input` 字段。下一轮 request 如果完整字符串命中 response 文本，mitm 用 `$relayRef` 占位发出。relay 在服务端展开 ref、拼回完整 JSON 后再发给上游。当前 refs 只做精确字符串命中，不做模糊 diff。

失败时会自动回退现有 full chunk：

- relay 没有 base snapshot
- 当前 `input` 不是已知快照的前缀增长
- relay 校验拼接后的 canonical body hash 失败
- relay 没有对应 response ref 文本

如果 delta/ref init payload 超过 `CHUNK_RELAY_DELTA_INIT_MAX_BYTES`，mitm 不会回退 full chunk，而是把 delta/ref JSON gzip 后按 `CHUNK_RELAY_CHUNK_SIZE_BYTES` 分片，并用 `CHUNK_RELAY_ENCRYPTION_KEY` 做 AES-256-GCM 加密上传。没有可用加密 key 或加密分片上传失败时会 fail closed，避免第 N 轮增量超过公司出站 payload 限制。

`relay-only.env` 会被 shell `source`，所以 `RELAY_ENCRYPTION_KEYS` 这类 JSON 值需要用单引号包住，例如 `RELAY_ENCRYPTION_KEYS='{"default":"..."}'`。

相关环境变量：

| 变量 | 说明 | 默认值 |
|---|---|---|
| `CHUNK_RELAY_PROTOCOL_VERSION` | 客户端 relay 协议；支持 `v1`、`v2`、`v4`；`v4` 启用 request delta 和 response refs，full fallback 仍走 v1 chunk | `v1` |
| `CHUNK_RELAY_BASE_URL` | relay 服务地址；relay 模式必填 | 空 |
| `CHUNK_RELAY_SHARED_SECRET` | mitm 调 relay 时发送的共享密钥；relay 配了 `RELAY_SHARED_SECRET` 时必填 | 空 |
| `CHUNK_RELAY_CHUNK_SIZE_BYTES` | full chunk 和加密 delta/ref chunk 的单片大小 | `20480` |
| `CHUNK_RELAY_DELTA_INIT_MAX_BYTES` | 单次 delta/ref inline init 最大字节数；超过后切到加密分片上传 | `95000` |
| `CHUNK_RELAY_ENCRYPTION_KEY_ID` | 加密分片使用的 key id，需要和 relay 端 `RELAY_ENCRYPTION_KEYS` 对应 | `default` |
| `CHUNK_RELAY_ENCRYPTION_KEY` | base64 32 字节 AES key；v2 必填，v4 大 delta/ref 加密分片时必填 | 空 |
| `CHUNK_RELAY_MAX_DELTA_SNAPSHOTS` | mitm 本地最多保留多少个可复用快照索引 | `32` |
| `CHUNK_RELAY_RESPONSE_REF_MIN_CHARS` | mitm 只替换长度不小于该值的 response 文本 | `64` |
| `CHUNK_RELAY_MAX_RESPONSE_SNAPSHOTS` | mitm 本地最多保留多少个 response snapshot 索引 | `16` |
| `RELAY_SNAPSHOT_TTL_MS` | relay 服务端快照保留时间 | `86400000` |
| `RELAY_RESPONSE_SNAPSHOT_TTL_MS` | relay 服务端 response snapshot 保留时间 | `86400000` |
| `RELAY_RESPONSE_REF_MIN_CHARS` | relay response 文本候选的最小长度 | `64` |
| `RELAY_ENCRYPTION_KEYS` | relay 端 key map，JSON 格式；`relay-only.env` 里需要单引号包住 | `{}` |

## 排障

### 看不到 HTTPS 或 WSS 内容

通常是 mitm CA 证书没有导入到运行 Codex 的环境。

先检查证书是否已经生成：

```bash
ls -l $HOME/.mitmproxy/mitmproxy-ca-cert.pem
```

### 日志里全是无关流量

你把系统级代理也挂到了 mitm 上。

解决方式：

- 只让 Codex 走代理，不要全局代理整台机器
- 或者设置 `MITM_RECORD_MATCH_HOSTS`，只收 Codex 相关域名

### body 太大，日志难看

把记录长度收短：

```bash
export MITM_RECORD_BODY_MAX_BYTES=65536
./mitmproxy/run.sh
```

### 只想验证 mitm 有没有工作

先启动：

```bash
./mitmproxy/run.sh
```

再开另一个终端：

```bash
curl -x http://127.0.0.1:15334 http://example.com
```

如果日志里出现 `http_inspect`，说明链路通了。
