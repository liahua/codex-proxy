# Docker Lab

这个目录给出一套双容器测试台：

- `relay`: 跑当前 `codex-proxy`，保留 relay/转发服务能力
- `client-lab`: 容器内安装真实 `codex` CLI 和 `mitmproxy`，通过 `http_proxy` 把 Codex 的出站请求导向 mitm

当前这一版 compose 不只是侦察流量，已经能直接验证 WebSocket relay。验证目标是：

1. `client-lab` 里的真实 `codex` CLI 能在容器内启动
2. `codex` 的 HTTP/WS 请求全部经过本地 mitm
3. addon 把 Codex 的 WS 握手改写到 `relay`
4. addon 对超阈值的 `client -> server` WS 消息做分片注入
5. 对超阈值的 `ab.chatgpt.com/otlp/v1/metrics` HTTP POST，也会走 body 分片 relay
6. `relay` 重组 WS 消息或 HTTP body 后再请求真实上游
7. 最终响应仍然能回到 `codex` CLI

## 运行

```bash
cd /home/liahua/IdeaProject/codex-proxy
docker compose up --abort-on-container-exit --exit-code-from client-lab
```

宿主机会把 `/home/liahua/.codex` 只读挂到容器的 `/shared-codex`，入口脚本会把其中的 `auth.json` 和 `config.toml` 复制到容器内本地 `CODEX_HOME`。

## 结果判断

- `client-lab` 成功运行后，检查容器里的 `/tmp/codex-http.jsonl` 和 `/tmp/codex-ws.jsonl`
- `codex-ws.jsonl` 里应该看到 `websocket_chunk_split`
- `codex-http.jsonl` 里在大 metrics 请求时应该看到请求被改写到 `/relay/v1/chunked/complete`
- `relay` 容器日志里应该看到 `ws relay reassembled chunk_id=...`
- `codex` CLI 应该仍然返回最终答案
- 失败时，先看 `client-lab` 标准输出和 `/tmp/mitm.log`
