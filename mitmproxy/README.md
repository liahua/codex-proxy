# mitmproxy addon

`mitmproxy/addon.py` 用于拦截本地流量并转发到远程 `codex-proxy`。

当前只有两种行为：

- 命中 `CHUNK_RELAY_MATCH_HOSTS` 的 HTTP `POST` 请求：走 chunk relay。
- 命中 `CHUNK_RELAY_MATCH_HOSTS` 的 WebSocket upgrade：直接返回 `503`，让客户端自动回退到 HTTP/HTTPS。

其余非命中流量默认继续透传。

## 环境变量

### addon：`mitmproxy/addon.py`

| 变量 | 怎么用 | 有默认值 | 默认值 |
|---|---|---|---|
| `CHUNK_RELAY_ENABLED` | 是否启用 relay 客户端逻辑 | 是 | `true` |
| `CHUNK_RELAY_BASE_URL` | 远端 relay 服务基地址 | 是 | 空字符串 `""` |
| `CHUNK_RELAY_SHARED_SECRET` | 上传 `init/chunks/complete` 时附带到 `x-relay-secret` | 是 | 空字符串 `""` |
| `CHUNK_RELAY_CHUNK_SIZE_BYTES` | `POST` 请求体切 chunk 的大小 | 是 | `20480` |
| `CHUNK_RELAY_TIMEOUT_SECONDS` | addon 请求 relay 的超时秒数；适用于 `init`、`chunk` 上传和最终 `complete` 请求 | 是 | `600` |
| `CHUNK_RELAY_UPLOAD_RETRIES` | 上传失败最大重试次数 | 是 | `3` |
| `CHUNK_RELAY_RETRY_BACKOFF_MS` | 重试前退避时间，单位毫秒 | 是 | `400` |
| `CHUNK_RELAY_MATCH_HOSTS` | host 命中集合；支持精确 host，也支持 `.chatgpt.com` 或 `*.chatgpt.com` 这种子域匹配 | 是 | `127.0.0.1,localhost,chatgpt.com,ab.chatgpt.com` |
| `CHUNK_RELAY_CONSOLE_LOG` | 是否在控制台打印详细日志 | 是 | `true` |

规则说明：

- host 未命中 `CHUNK_RELAY_MATCH_HOSTS`：直接放过。
- host 命中后：`POST -> relay`，`GET -> 放过`，`WebSocket upgrade -> 503`。
- 如果 host 命中但 `CHUNK_RELAY_ENABLED=false` 或 `CHUNK_RELAY_BASE_URL` 为空，`POST` 不会回退直连，而是直接返回 `503`。
- `CHUNK_RELAY_MATCH_HOSTS=.chatgpt.com` 或 `CHUNK_RELAY_MATCH_HOSTS=*.chatgpt.com` 会匹配 `ab.chatgpt.com` 这类子域，但不会匹配裸域 `chatgpt.com`；如果要同时匹配裸域和子域，请同时写 `chatgpt.com,.chatgpt.com`。
- addon 的结构化 flow 日志现在也会进入 `MITM_LOG_FILE`，前缀为 `http_inspect `。

### 启动脚本：`mitmproxy/run.sh`

| 变量 | 怎么用 | 有默认值 | 默认值 |
|---|---|---|---|
| `MITM_LISTEN_HOST` | `mitmdump` 监听地址 | 是 | `127.0.0.1` |
| `MITM_LISTEN_PORT` | `mitmdump` 监听端口 | 是 | `15001` |
| `MITM_LOG_FILE` | `mitmdump` 进程日志文件路径 | 是 | `/tmp/codex-mitmproxy.log` |
| `MITM_UPSTREAM_PROXY` | 如设置，运行模式改为 `upstream:<proxy>` | 是 | 空字符串 `""` |
| `MITM_MODE` | `mitmdump --mode` 原始值；会被 `MITM_UPSTREAM_PROXY` 覆盖 | 是 | `regular` |
| `MITM_CONF_DIR` | mitm 证书和配置目录 | 是 | `$HOME/.mitmproxy` |

## 示例

```bash
export CHUNK_RELAY_BASE_URL=https://relay.your-company.com:443
export CHUNK_RELAY_SHARED_SECRET=replace-me
export CHUNK_RELAY_ENABLED=true
./mitmproxy/run.sh
```

说明：当前通过 `./mitmproxy/run.sh` 直接加载 `addon.py`，不再使用 `mitmproxy/config.yaml`。完整字段说明也可参考仓库根目录的 [README.md](/home/liahua/IdeaProject/codex-proxy/README.md)。

## 安装依赖

```bash
python3 -m pip install -r requirements.txt
```

## 关于请求体切分

- 命中 `CHUNK_RELAY_MATCH_HOSTS` 的 HTTP `POST` 请求会始终走中继。
- 每个 chunk 大小由 `CHUNK_RELAY_CHUNK_SIZE_BYTES` 控制，默认 `20480`（20KB）。
- 若中继未启用或 `CHUNK_RELAY_BASE_URL` 未配置，命中 host 的 `POST` 请求会直接返回 `503`，不会回退直连。

## 排障

如果看到 `error establishing server connection`，通常是两类原因：

- 本机把与 Codex 无关的系统流量也走了该代理；
- relay 地址不可达。

建议按顺序检查：

1. 只让 Codex 客户端走这个代理，不要全局代理系统流量。
2. 验证 relay 连通性：

```bash
curl -sv http://<relay-host>:<port>/healthz
```
