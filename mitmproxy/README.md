# MITM 抓包模式（record-only）

这个目录里有两个 addon：

- [`addon.py`](addon.py) — 中继模式。把匹配到的请求改写成加密分片的 v5 relay 调用，
  **主 README 的「客户端 · 拦截模式」是它的完整文档**，这里不重复。
- [`record_only_addon.py`](record_only_addon.py) — 只记录、不改写。排查问题时用。

## 什么时候用 record-only

想看清 Codex CLI 到底发了什么、收到了什么，而不希望任何改写介入的时候。它会完整记录
HTTP 请求/响应的头和 body，以及 WebSocket 的握手和每一条消息。

```bash
export MITM_ADDON_MODE=record-only
export MITM_RECORD_MATCH_HOSTS=          # 空 = 记录所有 host
export MITM_RECORD_BODY_MAX_BYTES=0      # 0 = body 不截断
./mitmproxy/run.sh
```

让被观察的进程走它：

```bash
export HTTPS_PROXY=http://127.0.0.1:15334
export SSL_CERT_FILE=$HOME/.mitmproxy/mitmproxy-ca-cert.pem
```

日志默认写到 `$PWD/codex-mitmproxy.log`，每行是一条 JSON：

```text
http_inspect {"event":"http_request","url":"...","headers":{...},"body":{"raw":{...},"decoded":{...}}}
http_inspect {"event":"http_response","status_code":200,...}
ws_inspect   {"event":"websocket_message","from_client":true,...}
```

`body.decoded` 会尽量解压和转码（gzip / deflate / br / zstd / utf-8 / json），
`body.raw` 是原始字节。`authorization`、`x-relay-secret` 这类头会被替换成
`<redacted sha256:xxxxxxxx>`，只留指纹用于比对。

## 环境变量

| 变量 | 说明 | 默认 |
|---|---|---|
| `MITM_ADDON_MODE` | `relay` 或 `record-only` | `relay` |
| `MITM_LISTEN_HOST` / `MITM_LISTEN_PORT` | 监听地址 | `127.0.0.1` / `15334` |
| `MITM_LOG_FILE` | 流量日志路径 | `$PWD/codex-mitmproxy.log` |
| `MITM_ERROR_LOG_FILE` | 非 2xx / 网络错误精简日志 | `$PWD/codex-mitmproxy-errors.log` |
| `MITM_RECORD_MATCH_HOSTS` | 记录哪些 host，空 = 全部 | 空 |
| `MITM_RECORD_BODY_MAX_BYTES` | body 截断字节数，`0` 不截断 | `0` |
| `MITM_UPSTREAM_PROXY` | 如果本机还要再过一层代理 | 空 |
| `MITM_CONF_DIR` | mitm 配置和证书目录 | `$HOME/.mitmproxy` |

## 常见问题

**看不到 HTTPS/WSS 内容** — CA 证书没被目标进程信任。检查
`$HOME/.mitmproxy/mitmproxy-ca-cert.pem` 是否存在并被 `SSL_CERT_FILE` 指到。

**日志里全是无关流量** — 别做全局代理，或者设 `MITM_RECORD_MATCH_HOSTS` 收窄。

**验证 mitm 有没有工作**：

```bash
curl -x http://127.0.0.1:15334 http://example.com
```

日志里出现 `http_inspect` 就说明链路通了。
