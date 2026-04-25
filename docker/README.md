# Docker Lab

这个目录给出一套双容器测试台：

- `relay`: 跑当前 `codex-proxy`，保留 relay/转发服务能力
- `client-lab`: 容器内安装真实 `codex` CLI 和 `mitmproxy`，通过 `http_proxy` 把 Codex 的出站请求导向 mitm

当前这一版 compose 重点验证 HTTP relay 链路。验证目标是：

1. `client-lab` 里的真实 `codex` CLI 能在容器内启动
2. `codex` 的 HTTP/WS 请求全部经过本地 mitm
3. WebSocket 会被显式阻断，让 Codex 走 HTTP fallback
4. 对超阈值的 HTTP POST，会走 body 分片 relay
5. `relay` 重组 HTTP body 后再请求真实上游
6. 如果把 `CHUNK_RELAY_PROTOCOL_VERSION` 设成 `v4` 并把 `CHUNK_RELAY_MATCH_HOSTS` 扩到 Codex requests 域名，后续请求可以验证 request delta 和 response refs
7. delta/ref init 超过阈值时，会切到 AES-256-GCM 加密分片上传
8. 最终响应仍然能回到 `codex` CLI

## 运行

```bash
cd /home/liahua/IdeaProject/codex-proxy
docker compose up --abort-on-container-exit --exit-code-from client-lab
```

宿主机会把 `/home/liahua/.codex` 只读挂到容器的 `/shared-codex`，入口脚本会把其中的 `auth.json` 和 `config.toml` 复制到容器内本地 `CODEX_HOME`。

## 结果判断

- `client-lab` 成功运行后，检查容器里的 `/tmp/codex-http.jsonl` 和 `/tmp/codex-ws.jsonl`
- `codex-ws.jsonl` 里应该看到 WebSocket 被阻断或回退
- `codex-http.jsonl` 里在大 metrics 请求时应该看到请求被改写到 `/relay/v1/chunked/complete`
- v4 delta/ref 测试需要额外设置 `CHUNK_RELAY_PROTOCOL_VERSION`、`CHUNK_RELAY_MATCH_HOSTS` 和加密 key
- 非 2xx 响应和网络错误会精简记录到仓库根目录的 `codex-mitmproxy-errors.log`
- `relay` 容器日志里应该看到 HTTP chunk 被接收、组装和转发
- `codex` CLI 应该仍然返回最终答案
- 失败时，先看 `client-lab` 标准输出和 `/tmp/mitm.log`
