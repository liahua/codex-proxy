# codex-proxy

一个用于 Codex 请求转发/中继的 Node.js 服务，支持两种模式：

- `relay-only`：给远程机器用，只做中继。
- `proxy-mode`：给本机或内网服务用，直接代理 Codex `/v1/responses`。

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
# 按需修改 .env 里的 5 个变量
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

### 远程机器需要配置的环境变量（只这 5 个）

| 变量 | 含义 | 默认值 | 是否必须显式填写 |
|---|---|---|---|
| `HOST` | 服务监听地址（网卡/IP） | `0.0.0.0` | 否 |
| `PORT` | 服务监听端口 | `8787` | 否 |
| `RELAY_STORAGE_DIR` | 分片临时目录 | `./data/chunked-requests` | 否 |
| `RELAY_REQUEST_TTL_MS` | 分片请求保留时长（毫秒） | `900000`（15 分钟） | 否 |
| `RELAY_SHARED_SECRET` | 中继鉴权密钥（请求头 `x-relay-secret`） | 空字符串 | 是（生产必须） |

> 结论：只需要关心上面 5 个变量。前 4 项可直接用默认值；`RELAY_SHARED_SECRET` 请务必设置为你自己的随机字符串。

变量默认值来源：`src/config.js`，示例文件见 `scripts/relay-only.env.example`。

### 排障日志（可选）

如果你要在 relay 服务端确认“是否命中中继”和“中继收到的请求体内容”，可开启以下变量：

| 变量 | 含义 | 默认值 |
|---|---|---|
| `RELAY_DEBUG_LOG` | 打印中继路由命中、分片接收、重组完成、上游响应状态等结构化日志 | `false` |
| `RELAY_DEBUG_LOG_BODY` | 在 debug 日志中附带请求体预览（截断） | `false` |
| `RELAY_DEBUG_BODY_MAX_BYTES` | 请求体预览最大字节数 | `2048` |

示例：

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

### 协议行为（relay-only）

- 用户本地到远程中继：
  - 对话链路：`WSS`（Codex responses）
  - 非对话链路（例如 metrics）：`HTTP/HTTPS REST`
- 远程中继到上游：由中继按目标接口继续转发。

## 2) 本机可选：`proxy-mode`

适合“直接把本服务当 `/v1/responses` 代理”使用。

```bash
npm install
npm run start:codex
```

默认监听 `127.0.0.1:8787`（见 `scripts/start-with-codex-auth.js`）。

## 3) mitmproxy 配套

mitm 脚本与变量说明见：

- `mitmproxy/README.md`
- `mitmproxy/addon.py`

先安装 Python 依赖：

```bash
pip install -U mitmproxy
```

如果你运行的是依赖 `httpx` 的历史 addon 版本，再执行：

```bash
pip install -U httpx
```

## 4) 最小请求示例

```bash
curl http://127.0.0.1:8787/v1/responses \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gpt-5.4",
    "stream": true,
    "input": [{"role":"user","content":[{"type":"input_text","text":"hello"}]}]
  }'
```

## 5) 测试

```bash
npm test
```
