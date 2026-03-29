# MITM 操作手册

这份手册只讲一件事：怎么把 Codex 的 HTTP 和 WebSocket 流量完整记录下来。

核心原则：

- 不改写请求
- 不阻断请求
- 不替代上游
- 只记录

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

- 监听 `127.0.0.1:15001`
- 日志写到 `/tmp/codex-mitmproxy.log`
- 记录所有 host
- body 不截断

### 3. 让 Codex 走代理

```bash
export http_proxy=http://127.0.0.1:15001
export https_proxy=http://127.0.0.1:15001
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
/tmp/codex-mitmproxy.log
```

改路径：

```bash
export MITM_LOG_FILE=$PWD/mitm.log
./run.sh
```

实时查看：

```bash
tail -f /tmp/codex-mitmproxy.log
```

## 结构化日志格式

HTTP：

```text
http_inspect {"event":"http_request",...}
http_inspect {"event":"http_response",...}
http_inspect {"event":"http_error",...}
```

WebSocket：

```text
ws_inspect {"event":"websocket_start",...}
ws_inspect {"event":"websocket_message",...}
ws_inspect {"event":"websocket_end",...}
```

## 环境变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `MITM_ADDON_MODE` | addon 模式 | `record-only` |
| `MITM_LISTEN_HOST` | 监听地址 | `127.0.0.1` |
| `MITM_LISTEN_PORT` | 监听端口 | `15001` |
| `MITM_LOG_FILE` | 日志路径 | `/tmp/codex-mitmproxy.log` |
| `MITM_UPSTREAM_PROXY` | 上游代理地址 | 空 |
| `MITM_MODE` | mitmdump 模式 | `regular` |
| `MITM_CONF_DIR` | mitm 配置/证书目录 | `$HOME/.mitmproxy` |
| `MITM_RECORD_MATCH_HOSTS` | 要记录的 host；为空表示全部记录 | 空 |
| `MITM_RECORD_CONSOLE_LOG` | 是否输出简短控制台日志 | `true` |
| `MITM_RECORD_BODY_MAX_BYTES` | body 最大记录字节数；`0` 表示不截断 | `0` |

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
