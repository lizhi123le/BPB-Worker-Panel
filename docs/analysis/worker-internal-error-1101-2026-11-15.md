# BPB Worker 日志「internal error; reference = …」全量分析报告

- 报告时间：2026-11-15（样本时间 2026-11-15 04:09:24 **GMT-8** = 2026-11-15 20:09:24 **Asia/Shanghai**）
- 样本 Worker：`<worker-name>`，脚本版本 `<version-id>`，域名 `<random-subdomain>.<free-domain>`
  （样本中的 Worker 名 / 域名 / 账号 ID / 版本 ID / requestId 均已脱敏：它们是线上标识，不宜进公开仓库）
- 分析对象：本仓库（BPB-Worker-Panel，package 版本 5.1.1）`src/` 全量代码 + `dist/` 已构建产物
- 结论性质：**~~平台侧错误文案为主因~~ → 已于 2026-11-15 20:38 由实机验证改判：`WS_DOWNLINK_BPS`（下行令牌桶）过大导致 isolate 级发送队列无界堆积，被平台以 `internal error; reference=…` 收口（见 §9）。2026-11-16 又拿到配对日志，证明其中一类是平台 `loadShed`（见 §10）**

> ⚠️ **追记（2026-11-15 20:38，用户实机验证）**：把 `WS_DOWNLINK_BPS` 从 `20000000` 调到 `10000000` 后，同类报错在 10 分钟内明显减少。
> 本文 §0–§8 保留当时的推理链与实测证据（有独立价值：它证明了本仓库代码路径**不会**产生这条文案），但根因判定以 **§9** 为准。
> 对 §0 的修正：R1/R4 应合并为「资源侧被平台包装」，且**它不是代码 bug 文案，而是 isolate 内存压力的产物**；`/hosting/tour` 是**受害者路径**，不是肇事路径。
>
> ⚠️ **追记二（2026-11-16 01:39，用户提供配对日志）**：同一 requestId 的 invocation 记录显示 `outcome = loadShed`、`wallTimeMs = 1,168,505`（**19 分 28 秒**）、`cpuTimeMs = 20` —— 这是**平台把长连接 load-shed 掉**，不是应用异常。详见 §10。

---

## 0. 结论速览（原始版本，已被 §9 修正）

| 编号 | 根因假设 | 判定 | 支持证据 | 反证 / 待验证 |
|---|---|---|---|---|
| **R1** | **Workers 运行时内部错误（平台侧 `Internal`）** | **最可能** | ① 消息文本是平台固定模板，不是你代码抛的 JS 错误；② 三个 reference 全是 **24 字符**，与平台内部错误 reference 格式一致；③ 三条日志落在**同一毫秒**（04:09:24.236），是并发突发而非单点业务异常；④ 已实测：本仓库 HEAD 对这个路径**不会抛异常**（见 §4） | 需核对 dashboard 的 `Errors by invocation status` 中 `Internal` 类比是否为 0、以及 `status.cloudflare.com` |
| **R2** | **handler 返回之后、响应流阶段的失败**（顶层 `try/catch` 结构性抓不到） | 很可能并存 | 伪装反代有 3 处直接把**上游 body 流**交给客户端（`camouflage.ts:1257/1414/1438`）；实测证明上游 body 中途断流时，异常发生在**读 body 时**而不是 `fetch()` 里（§4.2 案例 3/4） | 若日志里同请求还有 `console.*` 业务面包屑，可定位到具体分支 |
| **R3** | **线上部署代码 ≠ 本仓库 HEAD**（旧版 BPB / 第三方一键部署包） | 必须先排除 | Worker 名为随机生成（`falling-bonus-ec6f`）、域名在第三方免费域（`.kdns.fr`），不像本仓库标准部署；旧版 BPB/cfnew 血统没有本仓库这套 try/catch 与伪装降级 | 用 `scriptVersion.id` 反查部署版本（§6 步骤 1） |
| **R4** | 资源超限被平台包装（CPU/内存） | **~~可能性低~~ → 已确认（见 §9）** | 当时理由：超限通常报 `1102` / `Exceeded CPU Time Limits`，文案不同。**实际**：isolate 堆耗尽/内部流控失败时，平台给的就是 `internal error; reference=…`，与 1102 是两条不同的收口路径 | 已由 `WS_DOWNLINK_BPS` 20M→10M 的对照实验证实 |

**一句话**：你看到的不是「你的代码写错了」造成的异常，而是 Workers 运行时给出的通用内部错误（reference 是给 Cloudflare 支持定位用的句柄，不是错误原因本身）。但你的部署里确实有两类「结构性风险」会让这类报错变多，且都不需要改业务逻辑就能收口——见 §6、§7。

---

## 1. 样本逐字段解析

你贴的 JSON 是 **Workers Logs 的 invocation/exception 记录**（不是你的 `console.log`）。

| 字段 | 值 | 含义 |
|---|---|---|
| `message` / `$metadata.error` | `internal error; reference = ni8bi9ah4m5092accuedb03g` | 平台侧格式化消息；`reference` 是 24 字符支持句柄，**只能由 Cloudflare 侧解引用**，代码里拿不到 |
| `level` / `type` | `error` / `cf-worker` | 由 Workers 运行时写入，不是你打印的 |
| `timestamp` / `timestampNs` | `1794744564236` | 三条样本完全相同 → 同一毫秒突发 |
| `$workers.scriptName` | `falling-bonus-ec6f` | 真正执行本次请求的 Worker |
| `$workers.scriptVersion.id` | `<version-id>` | **决定性线索**：拿去和 dashboard/`wrangler deployments list` 对，可确定线上跑的是哪版代码 |
| `$workers.eventType` / `executionModel` | `fetch` / `stateless` | 普通 fetch 请求，无 Durable Object |
| `$workers.event.request` | `GET https://…/hosting/tour` | 只有 request、**没有 response** → 该次调用未成功产出响应 |
| `eventSize` | `927` | 事件体积，正常量级 |
| `$metadata.account` | `<account-id>…` | 账号 ID（敏感：公开贴日志时建议打码） |
| `trigger` | `GET /hosting/tour` | 触发路径 |

> 样本里三个 reference：`10n7usqm6b7f4d2m1mqf8iqr`、`sniqgjpe2dpsgkqug5udkdok`、`ni8bi9ah4m5092accuedb03g` —— 均为 **24 字符**，与平台内部错误 reference 形态一致（`24-character reference`）。

---

## 2. 「internal error; reference = …」到底是谁发的

Cloudflare 把失败分成三类（[Errors and exceptions](https://developers.cloudflare.com/workers/observability/errors/)）：

| 分类 | 触发者 | 日志里的 message 长什么样 |
|---|---|---|
| `Uncaught Exception` | **你的代码**抛了没人接的异常 | 真实 JS 错误文本，如 `TypeError: fetch failed`、`The script will never generate a response` |
| `Exceeded CPU / Memory` | 资源限制 | `Worker exceeded CPU time limit`、`Memory limit would be exceeded before EOF` |
| **`Internal`** | **Workers 运行时自身** | **`internal error; reference = <24字符>`** ← 你的样本 |

**关键推论**：`internal error; reference = …` 是运行时内部失败的**固定文案**（可公开复现的例子：`wrangler` 本地开发下 fetch 某个 URL 时报 `Error: internal error; reference = 6l146mk9fjeqkmojhhc9rifs`，见 [workers-sdk#10947](https://github.com/cloudflare/workers-sdk/issues/10947)）。

也就是说：

1. **这句文案不可能由本仓库代码产生**——`src/` 里没有任何一处输出该字符串（全文检索确认）。
2. 你的代码有顶层 `try { … } catch (error) { return await renderError(error) }`（[worker.ts:54–174](src/worker.ts#L54-L174)），任何被 `await` 的异常都会变成一张 **500 的 BPB 错误页**，而不是这条平台文案。
3. 因此这条日志要么发生在 **catch 之外**（返回后的流阶段 / `waitUntil` / 平台层），要么 **线上根本不是这份代码**。

### 2.1 一条容易踩的混淆点

本仓库的伪装设计会**主动伪造一张「Cloudflare 1101 Worker threw exception」页面**（[camouflage.ts:316–396](src/common/camouflage.ts#L316-L396)，状态码 500，[camouflage.ts:405](src/common/camouflage.ts#L405)），用于熔断降级/限流拦截。

- 你在**浏览器里**看到 1101 页 → 可能只是自己在演戏（正常）；
- 你在**Workers Logs 里**看到 `internal error; reference=…` → 是真事，与上面那张假页无关。

两者必须分开判断，否则会一直修错方向。

---

## 3. 这类请求为什么这么多

`/hosting/tour` 不是你的路由，也不是随机字符串——它是**两个真实存在于路径字典里的词**：

| 位置 | 内容 |
|---|---|
| [ratelimit.ts:73](src/common/ratelimit.ts#L73) | `"hosting"` 在公共路径字典里 |
| [ratelimit.ts:100](src/common/ratelimit.ts#L100) | `"tour"` 在公共路径字典里 |
| [ratelimit.ts:162–166](src/common/ratelimit.ts#L162-L166) | `isPathInDictionary()`：**每段都在字典内 → 判定为「合法伪装路径」** |

带来的连锁效果：

1. `guardPermanentBlacklist` 直接豁免（[firstCheck.ts:53](src/common/firstCheck.ts#L53)）——不查黑名单；
2. 速率限制也整段跳过（[firstCheck.ts:94](src/common/firstCheck.ts#L94) 的 `if (!isPathInDictionary(segments))`）——**每 IP 每小时 6 次的限制不生效**；
3. 直接进入 `camouflageProxy`（[camouflage.ts:1268](src/common/camouflage.ts#L1268)），**真的向伪装上游发一个子请求**并把响应流回给访客。

所以：扫描器（或任意爬虫）只要按字典词组合扫路径，就能无成本地驱动你的 Worker 反复出站 + 改写 HTML。日志里 `hosting/tour`、`timeline/toolbox`、`hosting` 这类组合都是同一批机器人。这不是被攻击，是全网背景噪音；但要接受一个代价：**每一次这样的请求都会把上游的异常（断流、超长 body、坏 header）直接搬进你的 Worker**，这正是 R2 的来源。

---

## 4. 本仓库 HEAD 对这条请求的真实行为（已实测）

### 4.1 静态路径推演

```
GET /hosting/tour
└─ worker.ts:54  fetch()
   ├─ worker.ts:63  init()                 → 解出 globalConfig.pathName
   ├─ worker.ts:100 initHttp()             → 凭据校验 + 解析 subPath
   ├─ worker.ts:131 switch(path)           → path = "hosting"，无匹配
   ├─ worker.ts:163 pathName !== '/'       → 不走根路径分支
   ├─ worker.ts:167 guardNonBuiltinPath()
   │   ├─ firstCheck.ts:89 黑名单           → isPathInDictionary=true → 豁免
   │   ├─ firstCheck.ts:94 限流             → 字典内 → 不限流、不计数
   │   └─ firstCheck.ts:107 camouflageProxy()
   │       ├─ resolveMaskTarget()           → FALLBACK/homepage/URL 抽一个上游
   │       ├─ maskRequestAllowed()          → 熔断令牌桶
   │       ├─ 文本 + 有 content-length < 1MB → 缓冲改写 + 缓存（camouflage.ts:1364）
   │       ├─ 文本 + 未知长度/超 1MB        → 边流边改写（camouflage.ts:1403 → 1257）
   │       └─ 非文本                         → 直接回上游流（camouflage.ts:1414）
   └─ 任何 throw → 顶层 catch → renderError() → 500 错误页
```

### 4.2 实测结果（`.build/worker.reference.js`，esbuild+terser 后的真实 bundle，Node 桩环境）

复现脚本：`.build/repro-1101.mjs`（本地临时文件，不入库）。结果：

| 场景 | handler 是否抛异常 | 状态码 | 实际返回 |
|---|---|---|---|
| 1. `/hosting/tour`，上游正常 | **否** | 200 | 上游 HTML，且 host 已改写为面板域名（伪装成立） |
| 2. `/hosting/tour`，上游 DNS 失败 | **否** | 200 | 内建 nginx 欢迎页（`camouflage.ts:1445` 兜底） |
| 3. 文本流中途断流（走流式改写分支） | **否** | 200 | **handler 正常返回**；读 body 时才抛 `upstream connection reset` |
| 4. 二进制流中途断流（直接 passthrough） | **否** | 200 | 同上 |
| 5. 缺 `UUID`/`TR_PASS` | **否** | 500 | BPB 错误页（`renderError` 正常工作，说明错误页资源完好） |
| 6. KV 未绑定 | **否** | 500 | 同上 |

**这张表说明两件事：**

- **① HEAD 版本没有任何一条路径会产出 `internal error; reference=…`**（连上游彻底失败都被接住了）；
- **② 案例 3/4 是结构性缺口**：异常发生在 handler **返回之后**，顶层的 `try/catch` 已经退出作用域，代码再也接不住。线上这类失败就会以「runtime 侧错误 + 客户端拿到坏响应」的形式出现——**这是本仓库唯一无法靠顶层 catch 兜底的类别**。

---

## 5. 资源侧：从「基本排除」到「确认为主因」的修正

**当时的推理（错的部分）**：以为超限一定报 `1102`。实际平台有两条收口路径：

| 收口路径 | 触发条件 | 日志文案 |
|---|---|---|
| 配额判定 | CPU/内存超限被计量捕获 | `1102` / `Worker exceeded CPU time limit` |
| 运行时内部失败 | 发送队列无界增长、isolate 堆被打爆、流控内部状态失效 | **`internal error; reference = …`** ← 你的样本 |

所以「不是 1102」不能推出「不是资源问题」。**§9 已确认：是第二条。**

**仍然成立的部分**：本仓库有自伤型的资源消耗放大面——字典路径不进限流（§3），扫描器可无成本驱动 HTML 改写与出站；这部分与 WS 下行压力叠加，共同抬高 isolate 的内存/CPU 水位。

---

## 6. 处置清单（按优先级，全部可执行）

> 追记：§6 是「还没找到根因时」的通用排查路径，仍有价值（尤其步骤 1 的版本对账与步骤 2 的分类对账）。**已确认根因后，请直接看 §9.3 的参数校准表。**

### 步骤 1｜先确定线上跑的是哪版代码（10 分钟，决定性）

```bash
# 1) 版本 ID 对账：线上 scriptVersion.id（把日志里的值填进来）
npx wrangler deployments list --name falling-bonus-ec6f

# 2) 抓真实异常（有业务堆栈的才叫「你的 bug」）
npx wrangler tail falling-bonus-ec6f --format=json
npx wrangler tail falling-bonus-ec6f --status=error
```

判读：

- `exceptions` 字段里出现**真实 JS 错误文本** → 那是 `Uncaught Exception`，按调用栈修；
- 只出现 `internal error; reference = …` → 平台侧，记录 reference 即可（见步骤 4）；
- `wrangler tail` 连得上但什么都抓不到、且 dashboard 里 Internal 计数在涨 → 强烈指向 R1/R3。

### 步骤 2｜在 dashboard 里做「分类对账」

Workers & Pages → `falling-bonus-ec6f` → Observability / Metrics：

- 「Errors by invocation status」中 `Internal` vs `Uncaught Exception` vs `Exceeded CPU` 各是多少；
- Workers Logs 过滤器：`$metadata.error EXISTS`、`$workers.outcome = "exception"`（[官方查法](https://developers.cloudflare.com/workers/observability/errors/#debug-exceptions-with-workers-logs)）。

**若 `Internal` 占绝对多数** → 走步骤 4；若 `Uncaught Exception` 多 → 走步骤 3 + §7 加固。

### 步骤 3｜把「返回后流式失败」收口（改代码，见 §7）

这一步能把 R2 这一整类彻底消掉，顺带让日志从「平台 reference」变成「你自己的可读面包屑」。

### 步骤 4｜平台侧的正当处理

1. 打开 [status.cloudflare.com](https://www.cloudflarestatus.com) 看当时是否有 Workers 事故；
2. **最小复现对照**：在同一账号下临时部署一个 `export default { fetch: () => new Response('ok') }`，如果它也 1101 / 也报 `internal error` → 账号级问题，直接开支持单；
3. 开单时附上：`scriptName` + `scriptVersion.id` + 三条 24 字符 reference + 精确到毫秒的时间戳。**reference 是唯一能被 Cloudflare 侧解引用的钥匙**，没有它支持也没法查。

### 步骤 5｜降低噪音（可选，但有实际收益）

- `FALLBACK` / `homepage` / `URL` 设为**一个真实存在、响应稳定、体积小**的站点（如 `FALLBACK=nginx` 用内建页），避免下游断流把异常搬进你的 Worker；
- 对公网域名前置 WAF/Rate Limiting 规则（例如对非 `panel|sub|login|dns-query|<subPath>` 首段路径做挑战），能从源头把扫描流量挡在 Worker 之外。

---

## 7. 代码加固建议（补丁草案，**尚未改动源码**）

三处改动，按收益排序。都不改变正常行为。

### 7.1 顶层兜底不能只有一层（防 `renderError` 自身失败）

现状：`catch (error) { return await renderError(error); }`（[worker.ts:172–174](src/worker.ts#L172-L174)），而 `renderError` 会 `atob` + `DecompressionStream` 解压错误页资源（[handlers.ts:111–131](src/common/handlers.ts#L111-L131)、[handlers.ts:567–578](src/common/handlers.ts#L567-L578)）。构建期若 `htmls['error']` 缺失，`build.js` 会注入空串（[build.js:221–228](scripts/build.js#L221-L228)）→ `atob("")` + 空 gzip → **解压抛错** → 连错误页都发不出去，直接变成平台 1101。

```ts
// worker.ts
} catch (error) {
    try {
        return await renderError(error);
    } catch (fatal) {
        // 错误页自身失败时，退化为最小可用的静态 500（绝不返回未定义/抛到运行时）
        console.error('[fatal] renderError failed:', (fatal as Error)?.message ?? String(fatal));
        return new Response('Internal Server Error', {
            status: 500,
            headers: { 'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff' }
        });
    }
}
```

### 7.2 流式返回必须自带错误兜底（消掉 R2）

三个出口：`camouflage.ts:1414`（二进制 passthrough）、`camouflage.ts:1438`（首页降级 passthrough）、`camouflage.ts:1257`（`streamWithBudgetRewrite`，已有 transform 但没有 `cancel`/error 处理）。建议统一包一层「出错即静默收口」的 transform，**绝不把上游错误状态透传给客户端**：

```ts
/** 把上游 body 包成「出错就收口」的流：上游断流时客户端拿到干净结束，而不是 1101 */
function guardUpstreamStream(source: ReadableStream<Uint8Array> | null, label: string) {
    if (!source) return null;
    const reader = source.getReader();
    return new ReadableStream<Uint8Array>({
        async pull(controller) {
            try {
                const { done, value } = await reader.read();
                if (done) { controller.close(); return; }
                controller.enqueue(value);
            } catch (e) {
                console.warn(`[mask] 上游流中断(${label})，静默收口:`, (e as Error)?.message ?? String(e));
                try { await reader.cancel(); } catch { /* 已关闭 */ }
                try { controller.close(); } catch { /* 已关闭 */ }
            }
        },
        cancel(reason) { void reader.cancel(reason).catch(() => {}); }
    });
}
// 用法：new Response(guardUpstreamStream(resp.body, reqURL.pathname), { ... })
```

### 7.3 让日志可归因（省下未来一半的排查时间）

现在失败时只剩平台 reference，无法对应业务分支。建议在几个关键失败点加**带路径的一行**（注意别打凭据/URL 秘密）：

```ts
console.error('[mask] proxy failed', { path: reqURL.pathname, upstream: maskURL.origin, reason: (error as Error)?.message });
console.error('[stream] upstream dropped', { path, upstream, ... });
```

效果：以后 Workers Logs 里能直接筛 `[mask]` / `[stream]`，与平台 Internal 事件按毫秒对齐，一眼分辨「我的锅」还是「平台的锅」。

> 补充（可选，属设计取舍）：`isPathInDictionary` 命中的路径目前完全不进限流（§3）。若担心扫描器靠字典词驱动出站，可把「字典路径」从「完全豁免」改成「较高阈值的软限流」，代价是极端情况下可能误伤自己的节点流量——**建议先不动，等 Observability 数据出来再定**。

---

## 8. 结论与建议动作

1. **定性**：日志文案属于 Workers 运行时 `Internal` 类，**不是你代码抛的 JS 异常**；reference 只能由 Cloudflare 解引用。
2. **定性证据**：本仓库 HEAD 已实测——该请求在最坏情况下（上游 DNS 失败、body 断流）也**不会**抛出未捕获异常，只会返回 nginx 页 / 坏流。因此线上表现与 HEAD 不一致，**优先核实线上版本（R3）**。
3. **必须做的三件事**：
   - 用 `scriptVersion.id` 与 `wrangler deployments list` 对账，确认线上是否为本仓库构建产物；
   - 打开 dashboard 的 `Internal` / `Uncaught Exception` 分类，确认到底哪一类在涨；
   - 用 `wrangler tail --status=error` 抓一次真实堆栈。
4. **无论 R1 还是 R2，§7.1 + §7.2 都值得落地**：它们把「结构性不可捕获」变成「可捕获 + 可读日志」，顺带消除一类客户端坏响应。
5. **`/hosting/tour` 这类流量本身不是故障**，是全网扫描噪音撞进了你的伪装字典（`hosting`/`tour` 恰好都在字典里）。它被记录下来，只说明 Worker 正常在替这些请求出站。

---

## 9. 根因确认（2026-11-15 20:38 追记）：`WS_DOWNLINK_BPS` 过大

### 9.1 现场数据

| 项 | 值 |
|---|---|
| 变更 | `WS_DOWNLINK_BPS`: `20000000` → `10000000`（字节/秒，20MB/s → 10MB/s） |
| 观察 | 10 分钟内同类 `internal error; reference=…` 明显减少 |
| 意义 | **下行速率上限是本项目唯一的流控点，调低它 = 把之前"名义开着、实际没生效"的背压真正打开** |

### 9.2 机制：为什么"把速率设大"会导致平台 internal error

链路全在 `src/protocols/websocket/common.ts` 的 `remoteSocketToWS()` 里：

1. **平台没有发送侧背压**。`@cloudflare/workers-types` 的 `WebSocket` **没有 `bufferedAmount`**，`send()` 返回 `void`（[common.ts:1255–1264](src/protocols/websocket/common.ts#L1255-L1264)）。客户端收不动时，运行时内部**无界堆积**。
2. **循环是紧循环**：`read() → send() → read()`（[common.ts:1487–1639](src/protocols/websocket/common.ts#L1487-L1639)）。上游比客户端快多少，队列就涨多少。
3. **令牌桶是唯一的替代信号**，而它的**桶容量 = `max(速率, 4 × 64KiB)` = 速率本身**（[common.ts:1283–1284](src/protocols/websocket/common.ts#L1283-L1284)）。也就是说：**`WS_DOWNLINK_BPS` 这个参数同时是"稳态速率"和"单次突发额度"**。
4. 设成 `20000000` 时：
   - 每条新连接可**瞬时灌 20MB** 才开始第一次等待；
   - 4K 实际码率只有 3–6MB/s，令牌**永远够用** → `governor.take()` 几乎不等待（日志里表现为 `capWait≈0`）；
   - 等价于**流控关闭**：队列继续无界增长 → isolate 堆膨胀 + GC（GC 时间全额计入 CPU）→ 平台以 `internal error; reference=…` 收口，**同一 isolate 上的在途请求一起陪葬**。
5. 设成 `10000000` 时：
   - 突发额度砍半（10MB），稳态节流在更低阈值就咬住；
   - `take()` 真开始等待 → 循环**延后 `read()`** → socket 不再收 → TCP 窗口关闭 → 上游自然减速（这正是 [common.ts:1266–1268](src/protocols/websocket/common.ts#L1266-L1268) 说的"端到端背压"）；
   - 队列不再累积，isolate 水位回落。

**这同时解释了最初那个反常识现象**：报错日志里 `trigger` 是 `GET /hosting/tour`（一个扫描器路径），因为 **isolate 是被 WS 下行压死的，扫描请求只是同 isolate 上的受害者**——它拿到的是平台给的 1101，不是自己触发的。

旁证：`WS_SESSION_MAX_MB=900` 在 20MB/s 下 **45 秒**就撞线主动断连（[common.ts:1609–1615](src/protocols/websocket/common.ts#L1609-L1615)），降到 10MB/s 后同样预算能撑 90 秒——断连/重连频率同步减半。

### 9.3 参数校准表（建议值）

| env | 代码默认 | 建议 | 说明 |
|---|---|---|---|
| `WS_DOWNLINK_BPS` | ~~`20 * 1000 * 1000`~~ → **`10 * 1000 * 1000`**（[common.ts:1248](src/protocols/websocket/common.ts#L1248)，2026-11-15 已改默认） | 保持 `10000000`（10MB/s ≈ 80Mbps；4K 场景 8–12，1080p 4–6） | 按「客户端实际下行峰值 × 1.2~1.5」设；**它同时是突发额度，不要设成"带宽上限"那样大** |
| `WS_SESSION_MAX_MB` | `900`（[common.ts:1230](src/protocols/websocket/common.ts#L1230)） | 保持 900 | 单连接字节预算，撞线主动断开让客户端重连（可控断开 > 平台打死 isolate） |
| `WS_MAX_CONNECTIONS` | `128`（[unified.ts:134](src/protocols/websocket/unified.ts#L134)） | 保持 128 | isolate 级并发；调高会线性抬高内存水位 |
| `WS_UPLINK_ISOLATE_MB` | `32`（[unified.ts:163](src/protocols/websocket/unified.ts#L163)） | 保持 32 | 上行积压 isolate 预算（按连接数折算） |
| `WS_DOWNLINK_STATS` | `0` | 校准期设 `1` | 打开后每秒一行 `downlink … cap=… capWait=…ms/…ms` |
| `XP_*`（XHTTP 入站） | 见 [xp/handler.ts:57–66](src/protocols/xp/handler.ts#L57-L66) | 默认即可 | XHTTP 有自己的积压窗口（`XP_MAX_QUEUED_MB=8`、`XP_QUEUE_GRACE_S=15`），比 WS 侧更严格 |

**校准方法**（`capWait` 是唯一可靠信号）：

```bash
npx wrangler tail falling-bonus-ec6f --format=pretty   # 面板 Log Level=debug，或设 WS_DOWNLINK_STATS=1
# 关注每秒一行的：downlink 1234KiB/s frames=… cap=10000000B/s capWait=…ms/1000ms
```

| 观察 | 结论 | 动作 |
|---|---|---|
| `capWait ≈ 0`（长期） | 上限没咬住，客户端比你设的更慢 → 仍在无界堆积 | **继续调低**（每次减半，观察 10 分钟） |
| `capWait` 接近窗口长度（≈1000ms） | 上限才是瓶颈，正常播放可能被它的缓冲影响 | 小幅上调（+20%），或检查线路 |
| `capWait` 居中（几十~几百 ms） | 命中甜点 | 保持 |

### 9.4 两条经验（给下一次）

1. **`internal error; reference=…` 的排查顺序要反过来**：先看「同一时间窗内有没有高带宽/长连接在跑」（WS 下行、XHTTP），再看报错路径。`trigger` 里的路径可能只是**受害者**，尤其是它属于扫描器路径时。
2. **"参数设得宽松 = 更安全"在这个仓库不成立**。`WS_DOWNLINK_BPS` 是安全阀而不是限速器：设大 ≈ 拆掉安全阀。原默认值 `20MB/s` 对常见客户端（3–6MB/s）偏乐观，**已于本次变更新为 `10MB/s`**（[common.ts:1248](src/protocols/websocket/common.ts#L1248)）；其余参数未动。

---

## 10. 追记二（2026-11-16 01:39）：配对日志证明这是平台 `loadShed`

### 10.1 两条记录是同一次调用

| 字段 | 记录 1（exception） | 记录 2（invocation） | 结论 |
|---|---|---|---|
| `requestId` / `rayId` / `traceId` | `<request-id>` / `<ray-id>` / `<trace-id>` | 完全相同 | **同一次请求** |
| `timestampNs` | `1794764359896000000` | 相同 | 同一毫秒 |
| `message` | `internal error; reference = 5vgqrsdcrh6pkdbmkvchg4j0` | `GET https://…/environment` | 失败原因 vs 被影响的请求 |
| `$workers.outcome` | — | **`loadShed`** | ← 关键字段 |
| `$workers.wallTimeMs` | — | **1,168,505 ms = 19 分 28.5 秒** | JS 上下文存活时长 |
| `$workers.cpuTimeMs` | — | **20 ms** | 几乎没在算，只是挂着一条连接 |

### 10.2 这条请求是什么

- 它是 **WebSocket 升级**（`upgrade: websocket` + `sec-websocket-version: 13`），不是普通 GET；
- 路径 `/environment` 是路径字典里的词（[ratelimit.ts:68](src/common/ratelimit.ts#L68)），因此通过了 WS 分支的字典校验（[worker.ts:86–88](src/worker.ts#L86-L88)），正常进入 `handleWebsocket`；
- `sec-websocket-protocol` 里的 early data 解出来是 **VLESS / TCP / 端口 443 → `cdn.jsdelivr.net`**（本仓库既有的 padding 形态，非异常输入）；
- UA `Go-http-client/1.1`，来源广东深圳（NRT 边缘）—— 一条**真实在用的隧道连接**。

### 10.3 `loadShed` 是什么

workerd 的 `EventOutcome` 枚举里有 `loadShed`（workerd `src/workerd/io/outcome.capnp`，2024-07 加入）。官方 logpush 文档的 Outcome 一节较旧，只列了 `ok | canceled | exception | unknown`；`@cloudflare/workers-types` 的完整集合是：

```
ok | canceled | exception | unknown | killSwitch | daemonDown
| exceededCpu | exceededMemory | loadShed | responseStreamDisconnected | scriptNotFound
```

`loadShed` = **运行时主动把这个请求卸载/丢掉**（平台侧限流与瘦身），既不是脚本抛错，也不是你的 CPU/内存额度超限。JS 上下文被杀 → 客户端拿不到响应 → 平台补一条 `1101 internal error; reference = …`。

### 10.4 为什么是 19 分 28 秒

2026-10 起 Cloudflare 调整了运行时更新策略：**例行 runtime update 期间，在途请求/连接最多给 20 分钟宽限**（此前 30 秒），到期中断。

`wallTimeMs = 1,168,505 ms = 19 分 28.5 秒`，正好落在 20 分钟窗口内；三条同类错误落在**同一毫秒**，也是「多条连接在同一次平台事件里一起被 shed」的典型特征，而不是三条独立故障。

> 不能 100% 断定就是 runtime update（也可能是边缘负载 shed），但「≈19.5 分钟 + 同毫秒多条 + cpuTime 仅 20ms」三个特征一起指向平台周期性动作。

### 10.5 与 §9 的关系：这是两个不同类别的错误

| 类别 | 触发 | 日志特征 | 处置 |
|---|---|---|---|
| **A 类**：isolate 压力 | 下行队列无界堆积（`WS_DOWNLINK_BPS` 过大） | 高带宽会话 + `exceededMemory`/`exceededCpu`，或 1101 | §9：默认值已下调到 10MB/s |
| **B 类**：平台 shed（本次样本） | 平台周期性卸载长连接 | **`outcome: loadShed` + `wallTime ≈ 20min` + `cpuTime` 极小** | 代码改不动；靠客户端重连，或服务端主动提前回收 |

判别方法（Workers Logs 过滤器）：

```
$workers.outcome = "loadShed"        → B 类，正常现象
$workers.outcome = "exceededMemory"  → A 类，检查 WS_DOWNLINK_BPS / WS_MAX_CONNECTIONS
$workers.outcome = "exception"       → 真 bug，去抓堆栈
```

### 10.6 已实施：会话生命周期上限（`WS_IDLE_TIMEOUT_S` / `WS_MAX_SESSION_S`）

本仓库 WS 侧原本**没有空闲超时，也没有最大会话时长**（`src/protocols/websocket/` 里只有首字节超时和「按已发送字节」的 `WS_SESSION_MAX_MB`）。后果是：一条**低速/空闲**会话永远触发不了字节预算（本例 19 分钟只花了 20ms CPU），只能等平台 shed。

2026-11-16 已补上两个旋钮（实现见 [common.ts `startWsSessionGuard`](src/protocols/websocket/common.ts#L1750)）：

| env | 默认 | 语义 | 显式 `0` |
|---|---|---|---|
| `WS_IDLE_TIMEOUT_S` | `600`（10 分钟） | 双向都无流量超过该值 → 主动 `close()` | 关闭该项 |
| `WS_MAX_SESSION_S` | `900`（15 分钟） | 单连接存活超过该值 → 主动 `close()` | 关闭该项 |

设计要点：

- **看门狗而非逐块定时器**：每连接一个 `setInterval`（默认 5s 粒度；日志里的 `session guard: idle=… max=…` 只在 env 变化时打一行），流量侧只做 `lastActivity = Date.now()`，热路径零成本；
- **双向判活**：下行（`remoteSocketToWS`）与上行（`makeReadableWebSocketStream` 的 message）都 `touch()`，所以纯上传连接不会被误杀；
- **到期只收口一次**（`expired` 幂等），并随清理钩子自动停表，不留空转定时器；
- 两者都小于平台的 ~20 分钟窗口：**先干净关闭 → 客户端立刻重连 → 日志里不再出现 1101**。

代价：空闲断连会让部分客户端多一次无感重连（绝大多数客户端会自动重连），属可接受取舍。

---

## 附录 A：字段与代码索引

| 主题 | 位置 |
|---|---|
| 顶层 fetch + try/catch | [src/worker.ts:54](src/worker.ts#L54-L174) |
| 路由 switch（`/panel` `/sub` …） | [src/worker.ts:131](src/worker.ts#L131-L170) |
| 非内置路径守卫 | [src/common/firstCheck.ts:66](src/common/firstCheck.ts#L66-L107) |
| 路径字典 + 限流 | [src/common/ratelimit.ts:10](src/common/ratelimit.ts#L10-L166) |
| 伪装反代主入口 | [src/common/camouflage.ts:1268](src/common/camouflage.ts#L1268-L1449) |
| 流式改写（返回后失败点） | [src/common/camouflage.ts:1185](src/common/camouflage.ts#L1185-L1262) |
| 内建 1101 伪装页 / nginx 页 | [src/common/camouflage.ts:300](src/common/camouflage.ts#L300-L424) |
| 错误页渲染（500） | [src/common/handlers.ts:111](src/common/handlers.ts#L111-L131) |
| 错误页资源解压 | [src/common/handlers.ts:567](src/common/handlers.ts#L567-L578) |
| 构建期 HTML 注入 | [scripts/build.js:221](scripts/build.js#L221-L228) |
| WS 下行速率上限（`WS_DOWNLINK_BPS`） | [src/protocols/websocket/common.ts:1232](src/protocols/websocket/common.ts#L1232-L1277) |
| WS 下行令牌桶（容量=速率） | [src/protocols/websocket/common.ts:1283](src/protocols/websocket/common.ts#L1283-L1316) |
| WS 下行紧循环（read→send） | [src/protocols/websocket/common.ts:1487](src/protocols/websocket/common.ts#L1487-L1639) |
| 单连接字节预算（`WS_SESSION_MAX_MB`） | [src/protocols/websocket/common.ts:1217](src/protocols/websocket/common.ts#L1217-L1252) |
| 每秒仪表（`capWait`） | [src/protocols/websocket/common.ts:1547](src/protocols/websocket/common.ts#L1547-L1569) |
| WS 连接上限 / 上行 isolate 预算 | [src/protocols/websocket/unified.ts:134](src/protocols/websocket/unified.ts#L134-L170) |
| 跨请求 Promise 约束（已知坑） | [src/common/common.ts:156](src/common/common.ts#L156-L204) |

## 附录 B：本地复现方法

```powershell
# 依赖已就绪时，直接跑本报告使用的复现脚本（读取 .build/worker.reference.js）
node .build/repro-1101.mjs
# 结果写入 .build/repro-1101.out.json
```

> `.build/` 与 `dist/` 都在 `.gitignore`（本仓库 `.gitignore` 是白名单制：`*` 全忽略 + 显式放行 `src/ scripts/ tools/ docs/`），因此复现脚本只存在于本地，不会污染仓库。

## 附录 C：参考资料

- [Errors and exceptions（错误码 / invocation status 分类）](https://developers.cloudflare.com/workers/observability/errors/)
- [Workers Logs（`$metadata.error EXISTS` 等过滤语法）](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
- [metrics-and-analytics：`Internal error` 的定义](https://cloudflare-docs-github.pages.dev/workers/learning/metrics-and-analytics/)
- [`internal error; reference = …` 的公开复现案例（workers-sdk#10947）](https://github.com/cloudflare/workers-sdk/issues/10947)
- [账号级 1101 现象的社区讨论（2026-11）](https://community.cloudflare.com/t/every-new-worker-returns-error-1101-before-handler-account-level/979326)
