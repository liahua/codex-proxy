# codex-proxy

一个用于 Codex 请求转发/中继的 Node.js 服务，支持两种模式：

- `relay-only`：给远程机器用，只做中继。
- `proxy-mode`：给本机或内网服务用，直接代理 Codex `/v1/responses`。

## 1) 远程机器推荐：`relay-only`

### 快速启动

```bash
npm install
cp scripts/relay-only.env.example .env
# 按需修改 .env 里的 5 个变量
npm run start:relay
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
| `RELAY_SHARED_SECRET` | 中继鉴权密钥（请求头 `x-relay-secret`） | 空字符串 | 建议填写 |

> 结论：不是所有项都必须手填。`HOST/PORT/RELAY_STORAGE_DIR/RELAY_REQUEST_TTL_MS` 都有默认值；生产环境建议至少配置 `RELAY_SHARED_SECRET`。

变量默认值来源：`src/config.js`，示例文件见 `scripts/relay-only.env.example`。

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
