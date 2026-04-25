# MITM 操作手册

这份手册讲两件事：

- `record-only`：把 Codex 的 HTTP 和 WebSocket 流量完整记录下来。
- `relay`：把匹配到的 HTTP 请求改写到 relay 服务，由 relay 做加密分片、服务端拼接、request delta 和 response refs。

默认是 `relay`。如果目标只是观察流量，用 `MITM_ADDON_MODE=record-only`。

## 文件说明

- [run.sh](/home/liahua/IdeaProject/codex-proxy/mitmproxy/run.sh)：启动 mitmdump
- [record_only_addon.py](/home/liahua/IdeaProject/codex-proxy/mitmproxy/record_only_addon.py)：记录 HTTP 和 WebSocket 的 addon

## 启动步骤

### 1. 安装依赖

```bash
python3 -m pip install -r /home/liahua/IdeaProject/codex-proxy/requirements.txt
```

### 2. 启动 mitm

```bash
export MITM_ADDON_MODE=record-only
export MITM_RECORD_MATCH_HOSTS=
export MITM_RECORD_BODY_MAX_BYTES=0
./run.sh
```

默认行为：

- 监听 `127.0.0.1:15334`
- 日志写到当前目录的 `codex-mitmproxy.log`
- 记录所有 host
- body 不截断

### 3. 让 Codex 走代理

```bash
export http_proxy=http://127.0.0.1:15334
export https_proxy=http://127.0.0.1:15334
export HTTP_PROXY=$http_proxy
export HTTPS_PROXY=$https_proxy
export ALL_PROXY=$http_proxy
```

### 4. 安装 CA 证书

mitmproxy 首次启动后会生成本地 CA：

```bash
$HOME/.mitmproxy/mitmproxy-ca-cert.pem
```

把它导入到运行 Codex 的环境，否则 HTTPS/WSS 只能看到连接失败，拿不到完整内容。

## 记录内容

### HTTP

每次请求都会记录：

- 请求方法
- URL
- 请求头
- 请求体
- 响应状态码
- 响应头
- 响应体

### WebSocket

每条连接都会记录：

- 握手请求头
- 握手响应状态码
- 握手响应头
- 每一条消息
- 关闭码和关闭原因

### body 转码

body 会同时记录：

- `raw`：原始数据
- `decoded`：能解压或能转文本时的可读版本

当前会尝试处理：

- `gzip`
- `deflate`
- `br`
- `zstd`
- `utf-8`
- `json`

## 只记录指定域名

如果你不想把系统其他流量打进日志，可以缩小范围：

```bash
export MITM_ADDON_MODE=record-only
export MITM_RECORD_MATCH_HOSTS=chatgpt.com,.chatgpt.com,openai.com,.openai.com
./run.sh
```

匹配规则：

- `chatgpt.com`：匹配裸域
- `.chatgpt.com`：匹配所有子域

## 日志位置

默认：

```bash
$PWD/codex-mitmproxy.log
```

改路径：

```bash
export MITM_LOG_FILE=$PWD/mitm.log
export MITM_ERROR_LOG_FILE=$PWD/mitm-errors.log
./run.sh
```

实时查看：

```bash
tail -f ./codex-mitmproxy.log
```

精简错误日志只记录非 2xx 响应和网络错误，默认写到当前目录：

```bash
tail -f ./codex-mitmproxy-errors.log
```

## 结构化日志格式

HTTP：

```text
http_inspect {"event":"http_request",...}
http_inspect {"event":"http_response",...}
http_inspect {"event":"http_error",...}
http_error_summary {"event":"http_error_summary","status_code":502,"request_body":{...},"response_body":{...}}
```

WebSocket：

```text
ws_inspect {"event":"websocket_start",...}
ws_inspect {"event":"websocket_message",...}
ws_inspect {"event":"websocket_end",...}
```

注意：`relay` 模式会阻断 WebSocket，让 Codex 回退到 HTTP；如果你要记录 WebSocket 消息，使用 `MITM_ADDON_MODE=record-only`。

## 环境变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `MITM_ADDON_MODE` | addon 模式 | `relay` |
| `MITM_LISTEN_HOST` | 监听地址 | `127.0.0.1` |
| `MITM_LISTEN_PORT` | 监听端口 | `15334` |
| `MITM_LOG_FILE` | 完整匹配流量日志路径 | `$PWD/codex-mitmproxy.log` |
| `MITM_ERROR_LOG_FILE` | 非 2xx / 网络错误精简日志路径 | `$PWD/codex-mitmproxy-errors.log` |
| `MITM_ERROR_BODY_MAX_BYTES` | error 精简日志里请求/响应 body 最大记录字节数；`0` 表示不截断 | `8192` |
| `MITM_UPSTREAM_PROXY` | 上游代理地址 | 空 |
| `MITM_MODE` | mitmdump 模式 | `regular` |
| `MITM_CONF_DIR` | mitm 配置/证书目录 | `$HOME/.mitmproxy` |
| `MITM_RECORD_MATCH_HOSTS` | 要记录的 host；为空表示全部记录 | 空 |
| `MITM_RECORD_CONSOLE_LOG` | 是否输出简短控制台日志 | `true` |
| `MITM_RECORD_BODY_MAX_BYTES` | body 最大记录字节数；`0` 表示不截断 | `0` |
| `CHUNK_RELAY_PROTOCOL_VERSION` | relay addon 协议；支持 `v1`、`v2`、`v4`；`v4` 会优先只上传新增 input，并用 response ref 占位可复用文本 | `v1` |
| `CHUNK_RELAY_BASE_URL` | relay 服务地址；relay 模式必填 | 空 |
| `CHUNK_RELAY_SHARED_SECRET` | 调 relay 时附带的共享密钥 | 空 |
| `CHUNK_RELAY_CHUNK_SIZE_BYTES` | full chunk 和加密 delta/ref chunk 的单片大小 | `20480` |
| `CHUNK_RELAY_DELTA_INIT_MAX_BYTES` | v4 delta/ref inline init 最大字节数；超过后切到 AES-256-GCM 加密分片上传 | `95000` |
| `CHUNK_RELAY_ENCRYPTION_KEY_ID` | 加密分片使用的 key id，需要和 relay 端 `RELAY_ENCRYPTION_KEYS` 对应 | `default` |
| `CHUNK_RELAY_ENCRYPTION_KEY` | base64 32 字节 AES key；v2 必填，v4 大 delta/ref 加密分片时必填 | 空 |
| `CHUNK_RELAY_MAX_DELTA_SNAPSHOTS` | mitm 本地可复用快照索引数量 | `32` |
| `CHUNK_RELAY_RESPONSE_REF_MIN_CHARS` | v4 response ref 最小替换文本长度 | `64` |
| `CHUNK_RELAY_MAX_RESPONSE_SNAPSHOTS` | mitm 本地可复用 response snapshot 数量 | `16` |

`relay-only.env` 使用 shell `source` 加载，relay 端的 `RELAY_ENCRYPTION_KEYS` 要写成 `RELAY_ENCRYPTION_KEYS='{"default":"..."}'`，否则 JSON 的双引号会被 shell 去掉。

## 常见问题

### HTTPS 连不上

通常是 CA 证书没有导入。

### WebSocket 没看到消息

先确认：

- Codex 的流量确实走了这个代理
- WSS 握手没有因为证书失败提前断掉

### 日志太大

限制 body 长度：

```bash
export MITM_RECORD_BODY_MAX_BYTES=65536
./run.sh
```
