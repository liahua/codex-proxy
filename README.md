# codex-proxy

这个分支的用途只有一个：给 Codex 挂一个本地 MITM 监控层，把 HTTP 和 WebSocket 流量完整记录下来。

它不会改写请求，不会阻断请求，也不会接管上游转发。Codex 该怎么访问外网，还是怎么访问；这里只负责记录。

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

默认就是 record-only 模式：

```bash
./mitmproxy/run.sh
```

如果你想明确写出来：

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
/tmp/codex-mitmproxy.log
```

实时看日志：

```bash
tail -f /tmp/codex-mitmproxy.log
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

WebSocket 握手和消息：

```text
ws_inspect {"event":"websocket_start","response_status_code":101,"request_headers":{...},"response_headers":{...}}
ws_inspect {"event":"websocket_message","from_client":true,"message_type":"text","content":{"raw":{...},"decoded":{...}}}
ws_inspect {"event":"websocket_end","close_code":1000}
```

## 环境变量

### mitm 启动

| 变量 | 说明 | 默认值 |
|---|---|---|
| `MITM_ADDON_MODE` | addon 模式；这个分支建议使用 `record-only` | `record-only` |
| `MITM_LISTEN_HOST` | mitm 监听地址 | `127.0.0.1` |
| `MITM_LISTEN_PORT` | mitm 监听端口 | `15001` |
| `MITM_LOG_FILE` | 日志文件路径 | `/tmp/codex-mitmproxy.log` |
| `MITM_UPSTREAM_PROXY` | 如果你的网络本身还要再过一层上游代理，可以填这里 | 空 |
| `MITM_MODE` | mitmdump 原始模式 | `regular` |
| `MITM_CONF_DIR` | mitm 配置目录和证书目录 | `$HOME/.mitmproxy` |

### record-only 记录范围

| 变量 | 说明 | 默认值 |
|---|---|---|
| `MITM_RECORD_MATCH_HOSTS` | 要记录的 host；为空表示全部记录 | 空 |
| `MITM_RECORD_CONSOLE_LOG` | 是否在控制台输出简短日志 | `true` |
| `MITM_RECORD_BODY_MAX_BYTES` | body 最大记录字节数；`0` 表示不截断 | `0` |

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
curl -x http://127.0.0.1:15001 http://example.com
```

如果日志里出现 `http_inspect`，说明链路通了。
