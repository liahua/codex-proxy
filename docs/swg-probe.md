# SWG 流式断连探针：远程同学操作手册

## 背景，一段话

codex 经 mitmproxy 拦截器走 relay 时，长响应在 25 秒左右被企业 SWG（`proxysg.*:8080`）掐断，
`terminal=False`，codex 读超时后重试，请求体越滚越大，最后报"请求失败"。
已经确认的事实只有一条：**relay 的真实流式响应在 SWG 这一跳上跑到约 25 秒就断**。
同一 SWG 下 httpbin 的慢速下载有时能跑 57 秒，所以这不是"所有流式响应一律 25 秒"的通用策略，
而是 relay 这条流量的某个特征触发的。公共端点（httpbin、cloudflare、httpstat.us）各有各的上限和拦截，
数据不可用，这一轮只在 relay 自己的域名上测。

SWG 这一跳上，relay 真实响应的样子（见 `src/relay.js` 的 `streamEncryptedResponse`）：

| 维度 | 真实值 |
|---|---|
| 请求 | `POST /relay/v5/request/complete`，JSON 体，`accept: text/event-stream` |
| 响应内容类型 | `application/octet-stream`（不是 text/event-stream，那是 addon 解密后回给 codex 的） |
| 响应头 | `x-relay-response-encrypted`、`x-relay-upstream-status`、`x-relay-upstream-content-type`、`x-relay-snapshot-id`、`x-relay-snapshot-body-sha256`、`cache-control: no-store` |
| 响应体 | chunked，AES-256-GCM 帧，高熵二进制 |
| 速率 | 约 9KB/s，持续几十秒 |

探针把这些维度做成开关，一次只变一个，看哪一个变了就不再被掐。

## 服务端已部署的探针

两个端点，都需要 `x-relay-secret`，都不碰上游模型。

`POST|GET /relay/probe/drip` 参数：

| 参数 | 默认 | 含义 |
|---|---|---|
| `d` | 40 | 持续秒数，上限 300 |
| `rate` | 9000 | 每秒字节数 |
| `tick` | 250 | 每隔多少毫秒写一块 |
| `ct` | application/octet-stream | 响应 content-type |
| `hdr` | 1 | 1 带全部 x-relay-* 头和 cache-control，0 不带 |
| `body` | frames | frames 真实加密帧；random 裸随机字节；ascii SSE 明文 |
| `label` | 空 | 回显到 relay 日志，便于对时 |

默认值就是真实响应的复刻。`POST /relay/v5/request/complete?probe=drip&...` 是同一探针挂在真实路径上，
用来排除 SWG 按 URL 下策略的可能。

`GET /relay/probe/delay?ms=30000`：静默 N 毫秒后回一小段 JSON。只在最终落到轮询方案时用来定长轮询预算。

每次探针结束，relay 端都会打一行日志，含 `bytesSent`、`elapsedMs` 和 `clientGone`：

```bash
docker logs codex-relay 2>&1 | grep relay-probe
```

`clientGone=true` 表示 relay 这一侧也看到了连接被关，SWG 是两头都断；`false` 而客户端却断了，
说明 SWG 只掐了客户端一侧，relay 还在往一个黑洞里写。这个区别决定轮询方案里 relay 要不要主动探活。

## 怎么跑

前置：curl 7.75 以上（`%{exitcode}` 需要），能拿到 relay secret。
**不要经过 mitmproxy**，脚本直接用 curl 打 SWG，把 addon 和 httpx 排除在外。

```bash
cd codex-proxy
RELAY_SECRET='<x-relay-secret>' \
SWG_PROXY='http://proxysg.<site>.com:8080' \
scripts/swg-probe.sh
```

默认每条跑 3 遍，每条 40 秒，全套约 20 分钟。跑完会在当前目录生成 `swg-probe-<时间>.log`。
如果 SWG 对这个域名先弹风险确认页，先用浏览器确认一次再跑，脚本不处理确认页。

只想先跑最关键的一条确认探针能复现：

```bash
RELAY_SECRET=... SWG_PROXY=... CASES="R0" scripts/swg-probe.sh
```

用例一览：

| 用例 | 变了什么 | 回答的问题 |
|---|---|---|
| R0-replica | 什么都不变 | 探针能不能复现 25 秒断。**R0 不复现，后面全部作废** |
| R1-ct-sse / R1-ct-text | 只改 content-type | 是不是内容类型触发 |
| R2-nohdr | 去掉 x-relay-* 头 | 是不是自定义头触发 |
| R3-ascii | 体改成 SSE 明文 | 是不是高熵二进制触发了扫描 |
| R3-allplain | 明文 + text/plain + 无自定义头 | 三项一起改能不能过，作为上限 |
| R4-slow | 速率降到 100B/s | 时长墙还是字节墙 |
| R5-fast | 15 秒内推 900KB | 有没有字节维度的触发 |
| R6-short | 20 秒复刻 | 20 秒安全线是否成立 |
| R7-get | 改成 GET | 请求方法是否相关 |
| R8-realpath | 挂在真实 complete 路径 | SWG 是否按 URL 下策略 |

## 要发回来的东西

1. `swg-probe-<时间>.log` 整个文件。
2. 同一时段 relay 端的 `docker logs codex-relay 2>&1 | grep relay-probe` 输出。
3. 如果 R0 没复现，另外跑一次真实的 codex 长请求（让模型输出所有工具 schema 那种），
   把 mitmproxy 日志里 `torn down` 那几行和时间一起发回来，用来和探针对时。

## 判读

先看 R0。三遍里至少两遍在 20 到 40 秒之间 `exit=28` 或 `exit=18`、`down` 明显小于 `rate*d`，
就是复现了。R0 三遍都 200 跑完，说明触发条件不在探针复刻的维度里，看 R8；R8 也过，
再按"要发回来的东西"第 3 条补真实流量对时。

R0 复现后，找**第一条能三遍跑完的用例**，按修改成本从低到高：

| 跑完的用例 | 结论 | 修法 |
|---|---|---|
| R1 或 R2 | 内容类型或自定义头触发 | relay 改外层响应头，几行改动 |
| R3-ascii | 高熵二进制触发扫描 | relay 帧改 base64 文本外壳，content-type 用 text/plain，体积涨三分之一 |
| R3-allplain 过而 R1、R2、R3-ascii 单项都不过 | 多个特征叠加触发 | 三项一起改，仍不动架构 |
| R4-slow 过而 R0 不过，或 R5 不到 15 秒就断 | 字节墙 | 轮询，把单次响应压小；再跑 `WITH_DELAY=1` 定长轮询预算 |
| R7 或 R8 单独有差异 | 按方法或 URL 下策略 | 相应改请求形态 |
| 全部被掐，只有 R6 过 | 针对该域名的纯时长墙 | 轮询，或申请域名加白 |

拿到日志后由 relay 这边判读，远程同学不需要自己下结论，把两份日志发回来即可。
