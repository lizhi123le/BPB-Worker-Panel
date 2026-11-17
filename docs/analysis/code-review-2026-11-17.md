# BPB-Worker-Panel v5.1.1 — 缺陷与冗余全面审查报告

> 审查日期：2026-11-17　|　HEAD 工作区干净（`git status` 无改动）　|　`dist/worker.js` 582,728 B、`worker.zip` 269,844 B，与源码同步（无 src 文件晚于产物）
> 审查范围：`src/`（56 文件，约 21.6k 行 TS）+ `src/assets/`（HTML/JS/CSS）+ `scripts/`、`tools/`、仓库配置
> 审查方式：6 个并行静态审计（按文件域切分，互不重叠）+ 主审复核 + 针对性实测验证。全程未修改任何源码。

---

## 0. 审查方法与基线

### 0.1 已建立的客观基线（全部通过）

| 项 | 结果 |
|---|---|
| `tsc --noEmit`（strict） | ✅ 0 error |
| `tools/*.test.mjs`（14 个测试套件；`cipher.mjs`／`ws-test-harness.mjs` 是辅助模块，不计） | ✅ 全部通过 |
| `tsc --noEmit --noUnusedLocals --noUnusedParameters` | ⚠️ 仅 2 处（见 D-01） |
| 构建产物与体积闸门 | ✅ 当前达标（`591~593KB` raw / `275~277KB` zip，落在目标内；**注意：这个区间的波动来自混淆器的离散强度台阶，不是源码增减**，见 H-06） |
| 前端 XSS 汇聚点扫描（`innerHTML`/`eval`/`document.write`） | ✅ 无真实 sink（仅 3 处**注释**命中：`panel/script.js:1319,1376`、`proxy-ip/script.js:45`） |
| 前端令牌存储（`localStorage`/`document.cookie`） | ✅ 0 命中，会话仅走 `HttpOnly; Secure; SameSite=Strict` Cookie |

**这张表本身就是本报告最重要的结论之一**：类型检查、单元测试、构建闸门全绿，而下面 21 条 P1 级缺陷一条都没被它们拦住 —— 其中 **2 条 P1（B-03、G-01）本身就是闸门失效**造成的（另有 P2 的 B-35，同属闸门问题）。原因见 §6「系统性根因」。

### 0.2 严重度定义

| 级别 | 含义 |
|---|---|
| **P0** | 无条件影响全部部署，且不可绕过（本次未发现） |
| **P1** | 特定但常见的配置/输入下功能完全失效、数据静默丢失、或安全防护可被绕过；用户侧表现为「配置都对但连不上 / 订阅少节点 / 面板骗人」 |
| **P2** | 特定条件下部分失效、资源泄漏、可观测性缺失、跨端行为不一致 |
| **P3** | 卫生问题、死代码、重复实现、文档漂移 |

### 0.3 标注约定

- **【实测】**：本次审查中实际运行命令或读取构建产物取证（§8 列出全部取证动作）
- **【静态】**：由代码路径逐行推演得出，未运行内核/客户端验证
- **置信度**：确认 / 很可能 / 疑似
- **文件简写**（本报告全文遵守，避免同名文件歧义）：
  - `common.ts` = `src/protocols/websocket/common.ts`（1921 行，数据面）
  - 引用 `src/common/common.ts`（400 行，工具层）时**一律写全路径**
  - 其余一律写完整相对路径

---

## 1. 结论速览

**代码质量整体在同类 Workers 项目之上**：错误处理意图明确、安全头与脱敏有专门设计、`@utils` 层把「判据」抽得很干净、注释里保留了完整的设计决策与被否决方案。问题不在于「写得糙」，而在于三类结构性偏差：

1. **三端（Xray / sing-box / Clash）平行实现已经漂移**。同一个设置在三端产出不同甚至互斥的结果，而没有任何一处集中定义「什么是正确」。
2. **闸门（smoke / verify）与真实请求形状不一致**，导致绿灯不可信 —— 一条肉眼可见的产物污染（B-03）在 16 个测试 + 构建闸门全绿的情况下持续存在于发布产物中。
3. **失败路径的资源与状态收口不完整**：超时分支不关 socket、失败分支不落缓存、计数只在 happy path 递减。这些缺陷单条都「很难触发」，但在长期运行的 isolate 里是累积性的。

### 缺陷统计

> 统计口径：按条目 ID 计。`P-02` 是 `B-02` 的性能面、`B-32` 第一部分是 `P-01` 的重复登记，**均不重复计数**。

| 级别 | BUG | SECURITY | PERF | REDUNDANCY/DEAD | HYGIENE | 小计 |
|---|---|---|---|---|---|---|
| P0 | 0 | 0 | 0 | 0 | 0 | **0** |
| P1 | 15 | 5 | 1 | 0 | 0 | **21** |
| P2 | 40 | 1 | 3 | 0 | 0 | **44** |
| P3 | 2 | 1 | 0 | 22 | 10 | **35** |
| 合计 | **57** | **7** | **4** | **22** | **10** | **100** |

- **P1 构成**：`B-01…B-14`（14）+ `G-01`（闸门，见 §6）+ `S-01…S-05`（5）+ `P-01`（1）= 21
- **P2 构成**：`B-15…B-56`（40，其中 B-56 为第 2 轮补入）+ `S-06`（1）+ `P-03/P-04/P-05`（3）= 44
- **P3 构成**：`B-54/B-55`（2）+ `S-07`（1）+ `D-01…D-09`+`R-01…R-13`（22）+ `H-01…H-10`（10）= 35

> **类别标注的三处判断说明**（评审两轮均对以下归类提出异议，此处显式记录，读者可按需重排）：
> 1. `S-04`（日志泄露访问目标）定 P1、`S-06`（日志泄露 UUID）定 P2 —— 二者都是隐私/凭据泄露，若按「泄露物敏感度」排序 `S-06` 应更高；此处按「触发广度」排序（`S-04` 对每条连接无条件成立，`S-06` 仅已认证请求）。
> 2. `B-34`（首访设口令竞态）定 P2、`B-55`（首访签发密钥竞态）定 P3 —— 二者同类，仅为控制 P1/P2 规模而分层。
> 3. `P-05`（第三方 CDN 供应链）归入 PERF 列，但其后果（面板被完全接管）与 SECURITY 同级；请把它当 SECURITY 项处理。

### 如果只修 6 件事

| # | 事项 | 收益 |
|---|---|---|
| 1 | **B-01** UUID 小写归一 | 一行改动，消灭「配置全对但节点连不上」这一类最难排查的故障 |
| 2 | **B-10** 字典小写归一 + 违规计数只认「字典外且被限流」的因 | 阻止「正常访客浏览伪装站 → 累积违规 → 永久封禁（成员无 TTL）」；影响**每个默认部署的所有访客** |
| 3 | **B-03** `replaceAll` 改函数式替换 | 构建期产物污染，已实测存在于发布产物中 |
| 4 | **G-01 + B-35 + B-54** 修正 smoke 的订阅 URL、设置请求形状与未知字段透传 | 三端配置生成与设置写入两条主链当前**完全没被闸门执行**；不修则后续所有修复都无法被验证 |
| 5 | **S-02 + B-08/S-01** 缓存键补 method 与 host，**并**处理噪声参数剔除 | 关闭整站级投毒链。三项必须一起改：只补 method/host **完全不触及** S-02（`utm_*` 是无条件剔除的，`GET /?utm_source=<script>` 仍会固化 5 分钟） |
| 6 | **B-02** WARP 失败路径改为「写 stale 标记」而非写账号 | 受限网络下每条连接不再重复付 2 次密钥生成 + 1 次无超时外网请求；面板「更新 WARP」不再撒谎 |

> 第 4 项优先于一切功能修复：当前 `verify`/`smoke` 全绿所覆盖的只有「页面能返回、鉴权会拒绝、限流会生效」，**不覆盖任何一份生成出来的配置，也不覆盖设置是否真的写进去了**。
> B-02 从「第 2 位」降到第 6 位是因为：它只影响 WARP 子集用户，且修复本身需要重新设计失败路径（不是一行级）；B-10 影响面更广而修法更小。

---

## 2. P1 缺陷（21 条）

### B-01｜大写 UUID 部署下，VLESS 鉴权永久失败
- **类型**：BUG / 自伤型故障　**置信度**：确认【静态，逻辑已逐行核对】
- **位置**：`src/protocols/websocket/unified.ts:694-695`、`:781-782`、`:802-828`；`src/common/common.ts:23-26`；`src/common/init.ts:95`
- **证据**：
```ts
// unified.ts:802-828 —— 重建出的 UUID 恒为小写
    return ( byteToHex[...] + ... ).toLowerCase();

// unified.ts:694-695 —— 与小写结果直接全等比较
    const slicedBufferString = stringify(slicedBuffer);
    const isValidUser = slicedBufferString === userID;

// common.ts:24 —— 校验正则带 /i，接受大写
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// init.ts:95 —— 原样落进 globalConfig，全仓无小写化
    userID: UUID,
```
- **问题**：`env.UUID` 只要含任意大写十六进制字符，`isValidUUID` 放行、订阅里原样写出（`xray/outbounds.ts:180 id: userID`），但服务端从首包 16 字节重建的是小写 → 比较恒 false。
- **影响**：面板、登录、订阅全部正常，**每一条 VLESS 连接**（WS 与 XHTTP 两条入站共用 `parseVlHeader`）在首包被判 `invalid user` → `close(1008)`。日志只有 `invalid first packet`（注释刻意不写原因），运维无从判断。Trojan 不受影响（口令是 ASCII 直比），因此现象是「Trojan 能连、VLESS 全挂」。
- **修复**：`init()` 里统一 `userID: String(UUID).toLowerCase()`（客户端发的是 16 字节，大小写不参与线上协议）。
  - 副作用已逐项核对：订阅输出的 `id`（`xray/outbounds.ts:180`、`clash/outbounds.ts:129`、`sing-box/outbounds.ts:119`）、`buildXpExtra`/`getXPaddingIdentifier`、`worker.ts:49,116` 的 8 位前缀、`firstCheck.ts:80` 的 adminPath 全部随之同步或本就 `toLowerCase()`；KV 里 `subPath` 一旦存在即优先（`init.ts:173-176`），老部署订阅 URL 不变。
  - **唯一需要写进变更说明的**：`maskPageSalt` / `maskImgParamName`（`camouflage.ts:660-663,709-712`）由 `userID` 派生，大写部署升级后伪装壳页的类名与图片参数名会整批变化（无害，但页面字节会变）。
  - ⚠️ **不要**顺手把 `parseVlHeader` 的比较换成常量时间实现：`:695` 与 `tryParseVlHeader:782` 是同一判据的两份实现，注释（`:769-775`）明确要求逐字一致；只改一处会让探测路径与解析路径对同一首包给出不同裁决。此处也无可用时序侧信道（失败即 `close(1008)`，无法逐字符二分）。
  - 📌 **修完后必须钉住一条约束**：`globalConfig.userID` 将小写化，而 `resolveSubPath`（`init.ts:160,163,165,187`）仍读 `env.UUID`（旧部署的 `subPath` 因此保留原大小写）。**不要**「顺手统一」成 `globalConfig.userID` —— 那会让所有老部署的订阅 URL 与 `/dns-query/<subPath>` 静默变号。建议在该处加一行注释。
  - 验收标准：fixtures 里加一个**含大写十六进制**的 UUID（现有全部 fixture 都是 `1111…5555` 这类纯数字小写，对 B-01 是零覆盖），断言大小写两种写法都能完成首包鉴权。

---

### B-02｜WARP 注册失败回退内置账号却不落 KV → 每条连接重试注册，至少 +1s 且永不自愈
- **类型**：BUG / PERF　**置信度**：确认【静态，两个独立审计交叉确认】
- **位置**：`src/protocols/warp.ts:51-61`；消费点 `src/kv.ts:48,85-88`；放大点 `src/worker.ts:98,121`、`src/common/handlers.ts:170,363`
- **证据**：
```ts
// warp.ts:51-61 —— 只有成功才写 KV
        await env.kv.put('warpAccounts', JSON.stringify(warpAccounts));
        return warpAccounts;
    } catch (error) {
        console.error('Failed to fetch new WARP accounts:', ...);
        return defaultWarpAccounts;      // ← 没有 kv.put
    }
```
```ts
// kv.ts:48,85-88 —— 每个请求都会读 KV 并在此处重新触发注册
        warpAccounts = normalizeWarpAccounts(await env.kv.get('warpAccounts', { type: 'json' }));
        if (!warpAccounts) warpAccounts = await fetchWarpAccounts(env);
```
- **问题**：`fetchWarpAccounts` 吞掉全部异常并返回内置账号，但**不写 KV**；`getDataset` 每次读不到有效账号就再调一次。而 `getDataset` 由 `setSettings` 调用，`setSettings` 在 **每次 WS 升级（worker.ts:98）与每次 XHTTP 请求（worker.ts:121）** 都执行。
- **影响**（按失败形态分档，勿一概而论）：
  1. 上游**完全不可达**（被墙/超时）：`fetchAccount` 第一次就抛，`throw` 落在 `warp.ts:32→37` 之前，直接进 `catch` → **2 次 X25519 密钥生成 + 1 次无超时外网请求**（`fetchAccount:64-88` 没有 `AbortSignal`，可能挂到平台 fetch 超时）；**不会**有那 1s sleep。
  2. 上游可达但返回异常（缺 `client_id` 等）：走完 `index===0` 分支 → 叠加 `setTimeout(1000)`（`warp.ts:48`），即 **2 次密钥生成 + 1~2 次 fetch + 1s sleep**。
  3. 两种情况都会在**每条 WS 升级与每次 XHTTP 请求**上重演（`worker.ts:98,121`）。
  另：`handlers.ts:558-563` 的 `catch` 是**死代码** —— `fetchWarpAccounts` 内部 `try/catch` 吞掉一切（连 `kv.put` 也在同一 try 内），`/panel/update-warp` 永远回「更新成功」，运维看不到失败。
  顺带：`setSettings` 只需要 `dataset.settings`，但 `getDataset` 无条件多付一次 KV 读 + JSON.parse（warpAccounts 只在 `/sub/warp*` 与 `/panel/get-warp-configs` 用得上）。
- **修复**（⚠️ **不要**直接把内置账号写进 KV —— 见下方警示）：
  1. **推荐**：失败时不写账号，只写 `warpAccountsStaleAt = Date.now()`（KV，`expirationTtl` 10~30 分钟）。`getDataset` 见此键且未过期 → 直接用内置账号、**不调** `fetchWarpAccounts`；键过期或缺失 → 才重新注册。这样失败只付一次代价，且上游恢复后能自愈。
     - 两个落地细节：① `defaultWarpAccounts` 是 `warp.ts:6` 的**模块私有常量**，必须先导出，否则「用内置账号但不调 fetch」这一步无处取数；② 标记写必须「**仅当不存在时**写」（KV 写入 + 一个 isolate 内内存时间戳闸门），否则忙部署在 KV 的 ~60s 可见性延迟内会每个失败请求各写一次，直接冲 `1000 写/日` 的 KV 额度 —— 写失败会让 `getDataset` 抛错，变成全站 500。
  2. **替代**：写账号但附 `warpAccountsSource:'builtin'` 标记，`getDataset` 见该标记即按 TTL 重试。
  3. `fetchWarpAccounts` 返回 `{ accounts, error }`，让 `/panel/update-warp` 能报错；`fetchAccount` 加 `signal: AbortSignal.timeout(8000)`；给 `getDataset` 增加 `onlySettings` 形参让 `setSettings` 跳过 warpAccounts。
  - 🚨 **警示**：若照「失败时直接 `put` 内置账号」实现，`getDataset` 的重新注册条件是 `if (!warpAccounts)`（`kv.ts:85-88`），而 `normalizeWarpAccounts`（`kv.ts:26-34`）只要「≥2 条形状合法」就返回非 null —— 内置账号两条都合法，于是**从此永不重试**，把「每条连接重试」换成「永远不重试」，正好制造本缺陷想消灭的不可自愈状态。

---

### B-03｜构建期 `replaceAll` 把 `$&` 当插值序列，已污染发布产物中的 `/secrets` 字符集
- **类型**：BUG（构建期）　**置信度**：确认【实测：在 `dist` 同批次 smoke 产物中读到污染结果】
- **位置**：`scripts/build.js:63-66`；受害源 `src/assets/secrets/script.js:30`
- **证据**：
```js
// build.js:63-66
const finalScriptCode = await jsMinify(scriptCode);
finalHtml = finalHtml
    .replaceAll('__STYLE__', `<style>${styleCode}</style>`)
    .replaceAll('__SCRIPT__', finalScriptCode.code);     // ← 字符串替换会解释 $&
```
```js
// secrets/script.js:30 —— 字面量里含 $&
const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@$&*_-+;:,.";
```
```text
# .build/smoke/artifact.json（与 dist/worker.js 同批次，2026-11-16 13:06）中 GET /secrets 的真实响应体：
...function generateSubURIPath(){const t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@__SCRIPT__*_-+;:,."
```
- **问题**：`String.replaceAll` 的 replacement 为字符串时仍解释 `$$`/`$&`/`` $` ``/`$'`。`$&` = 「匹配到的子串」= `__SCRIPT__`，于是字符集被替换成占位符本身。terser 已把 `charset.length` 折叠成常量 74 而字符串实际变成 82 字符 → `% 74` 只覆盖前 74 个。
- **影响**：`/secrets` 生成的「Random Subscription URI path」熵与形态被静默改写（`* _ - + ; : , .` 后半段取不到，混进 `_ S C R I P T` 等字母）。更危险的是机制本身：若任一资产出现 `$'` 或 `` $` ``，会分别插入「匹配点之后的整段 HTML / 之前的整段 HTML」，面板页（80KB）会被瞬间撑爆或结构损坏，而两道闸门都看不见。
- **修复**：改函数式替换（仓库内已有正确先例 `handlers.ts:124-125` 的注释就写着「避免把 `$&`/`$'`/`` $` `` 当插值序列」）：
```js
.replaceAll('__SCRIPT__', () => finalScriptCode.code)
.replaceAll('__STYLE__', () => `<style>${styleCode}</style>`)
```
并在 `processHtmlPages()` 里对 `finalHtml` 断言（**位置必须在 `:66` 替换之后、`:69` 的 `htmlMinify` 之前**，minify 会改写 token 形态）：不再含 `__SCRIPT__` / `__STYLE__` / `__VERSION__`。另建议额外断言 `finalScriptCode.code` **不含** `$&`/`$'`/`` $` `` —— 否则下一次是「脚本正文里出现这些序列」而非「资产字符串里出现占位符」，同一个 bug 会以更隐蔽的形式再来一次。

---

### B-04｜Xray「Clean IPs 代理条目」节点路由到不存在的出站 tag `proxy` → 该节点 100% 不可用
- **类型**：BUG（跨端不对称）　**置信度**：确认【实测：`configs.ts:320` 与 `routing.ts:30` 的 tag 已逐行核对】
- **位置**：`src/cores/xray/configs.ts:318-323`、`:470`；`src/cores/xray/routing.ts:30-34`、`:93`
- **证据**：
```ts
// xray/configs.ts:320 —— 该配置里唯一的出站 tag 是 cleanproxy-N
const outbound = buildCleanProxyOutbound(item.value, `cleanproxy-${index}`);
configs.push(await buildConfig(remark, [outbound], false, false, false, false, false, [item.value.server]));
```
```ts
// xray/configs.ts:333 —— 对照：普通 WS 节点的 tag 才叫 "proxy"
const outbound = buildWebsocketOutbound("proxy", protocol, host, port, ...);
```
```ts
// xray/routing.ts:30-34, 93 —— 兜底规则恒指向 "proxy"
const finallOutboundTag = isChain ? "chain" : isWorkerless ? "direct" : "proxy";
const remoteDnsProxy = isBalancer ? "all-proxies" : "proxy";
addRoutingRule(rules, ..., outTag, isBalancer);
```
- **问题**：`buildConfig` 只追加 `dns-out`/`direct`/`block`，代理条目配置里没有任何 `proxy` outbound。sing-box / Clash 用 `appendCleanProxyNodes`（`utils.ts:200-213`）把代理节点并入 selector，因此**只有 Xray 端踩这个坑**。
- **影响**：用户在 Clean IPs/Domains 里写任何 `socks://`、`http://` 条目时，生成的「该条目的独立 xray 订阅」路由悬空：Xray 在启动期或分发期报 `failed to find outbound handler`，客户端显示「导入成功」但节点连不上。
- **修复**：该分支把 outbound tag 直接命名为 `proxy`（与 `:333` 一致）：`buildCleanProxyOutbound(item.value, 'proxy')`；`getXrWarpConfigs` 的同类分支（`:470`）一并处理。更稳的做法是让 `buildConfig` 接收「兜底出站 tag」参数。

---

### B-05｜sing-box：`new URL(remoteDNS)` 无任何防护，非 URL 形态的 remoteDNS 让整份 sing-box 订阅 500
- **类型**：BUG（一端静默失效）　**置信度**：很可能【静态，三端写法已横向对比】
- **位置**：`src/cores/sing-box/dns.ts:49-50`；对照 `src/cores/xray/outbounds.ts:540-543`、`src/cores/clash/dns.ts:59-60`
- **证据**：
```ts
// sing-box/dns.ts:49-50 —— 裸 new URL
const url = new URL(remoteDNS);
const protocol = url.protocol.replace(':', '');
```
```ts
// xray 端已设想过该场景并做了回退（注释明写「remoteDNS 被填成裸 IP 或 tls://」）
// clash 端用正则判断形态
const proxyServerDNS = /^https:\/\//i.test(proxyServerRemoteDNS) ? ... : finalLocalDNS;
```
- **问题**：`remoteDNS` 直接来自 KV（`kv.ts:223` 只校验 `typeof === 'string'`），面板输入框允许任意字符串。填 `8.8.8.8` 或 `dns.google` 时 `new URL` 抛 `TypeError`，`buildDNS` 无 try/catch，异常冒到 `/sub/normal?app=sing-box`。
- **影响**：一个字段填错 → 该部署的 sing-box 订阅**全部不可用**（返回错误页而非配置），xray/clash 订阅照常。用户只会觉得「sing-box 客户端坏了」。
- **修复**：`try { new URL() } catch { … }` 兜底为 `type:"udp"` + 裸地址；同时把 `remoteDNS` 的形态校验前移到 `kv.ts` 的写入侧（与端口数组同样待遇）。

---

### B-06｜sing-box 链式出站与 `dns-remote` 互相依赖成环
- **类型**：BUG　**置信度**：很可能【静态 + 作者注释自认】
- **位置**：`src/cores/sing-box/outbounds.ts:56`、`src/cores/sing-box/dns.ts:52-57`、`:104-119`
- **证据**：
```ts
// outbounds.ts:56 —— 链式出站的服务器域名走 dns-remote
domain_resolver: isDomain(server) ? (isChain ? "dns-remote" : ...) : undefined
```
```ts
// dns.ts:52-57 —— dns-remote 的 detour 是链式分组
const remoteServer: DnsServer = { ..., detour: isChain ? "🔗 最佳延迟 🚀" : "✅ Selector", tag: "dns-remote" };
```
```ts
// dns.ts:108-110 —— 作者记录了环，但只修了 ECH 那条
//   2) 链式：dns-remote 的 detour 是链式分组 …, 而链式出站自身的服务器域名解析也指向 dns-remote → 成环
```
- **问题**：outProxy 是域名（最常见形态）时，解析链式服务器 → 需要先建链式隧道 → 建隧道又要解析服务器域名。
- **影响**：链式订阅在 sing-box 下首跳永远建不起来（「🔗」节点全部不可用）；Xray 无该字段、Clash 的 `proxy-server-nameserver` 显式不带 detour —— 只有 sing-box 踩。
- **修复**：`isChain` 分支改为 `"dns-direct"`，或新增一个无 detour 的 `dns-chain-bootstrap` 专门给链式出站做 bootstrap（语义与 clash 的 `proxy-server-nameserver` 对齐）。

---

### B-07｜Clash：ACL 模板的「纯正则 select 分组」展开为空 → `proxies: []`，整份配置可能加载失败
- **类型**：BUG　**置信度**：很可能【静态确认代码路径；mihomo 报错文案未实测】
- **位置**：`src/cores/acl-template.ts:366-399`、`:403-417`、`:539-548`
- **证据**：
```ts
// acl-template.ts:366-380 —— select 分支无空组兜底
if (type === 'select') {
    proxyList = [];
    for (const p of pg.proxies) {
        if (p === '.*') { proxyList.push('.*'); }
        else if (isRegexPattern(p)) { proxyList.push(...nodeNames.filter(n => new RegExp(p).test(n))); }
        else { proxyList.push(p); }
    }
} else {
    ...
    if (proxyList.length === 0) proxyList = fallbackNodes;   // :398 只有非 select 分支有
}
```
- **问题**：`aclEnabled` 出厂 `true`（`defaults.ts:117`），默认模板是 ACL4SSR 全量模板，其国别分组是 `select` + 纯正则（`(香港|HK|hk|Hongkong)`），而本项目的节点名是 `IPv4优选_01` / `domain` 形态 → 正则一条都匹配不上 → 空数组。`.*` 占位有兜底、非 select 有兜底、sing-box 目标还有 `+direct` 并集兜底（`:668`），**唯独 Clash 的 select 没有**。
- **影响**：生成 `{ name: '🇭🇰 香港节点', type: 'select', proxies: [] }`。mihomo 对空分组的处理**版本相关**：较新版本报 `proxy group ... must have at least one proxy` 而拒载整份配置，较旧版本可能只是该组不可选或被规则引用时报运行期错误 —— 无论哪种，该分组背后的规则全部失效。同一模板在 sing-box 端因 `outbounds: [...new Set([...g.proxies,'direct'])]`（`:668`）兜底存活，构成「同模板 Clash 死、sing-box 活」的跨端差异。
- **修复**：在 `:407` 之后统一加一次空组兜底（select → `[directTag, ...fallbackNodes]`），与 sing-box 侧共用同一归宿。

---

### B-08｜伪装反代缓存键不含 HTTP method：`POST /` 可把首页缓存投毒 5 分钟
- **类型**：BUG / SECURITY（缓存投毒）　**置信度**：确认【静态，两条分支的判据已对比】
- **位置**：`src/common/camouflage.ts:1246-1254`（写入）、`:1385-1386`（有门禁的对照分支）、`:1328`（键构造）、`src/worker.ts:163-164`
- **证据**：
```ts
// :1385-1386 —— 缓冲分支有 GET 门禁
                if (request.method === 'GET') {
// :1246-1254 —— 流式分支的 flush 无条件写缓存
            if (rewritable) cacheHomeEntry(cacheKey, { body: collected, status: resp.status, ... });
// :1328 —— 键 = origin + path + 归一化 query，不含 method
const cacheKey = maskURL.origin + reqURL.pathname + normalizeCacheQuery(...);
// worker.ts:163-164 —— 根路径不区分 method
if (pathName === '/' || pathName === '') return await camouflageProxy(request, env);
```
- **问题**：流式分支（上游无 `content-length`，即 gzip 响应的常态）不判 method。`curl -X POST https://<panel>/` 的上游响应会以「GET /」的键入缓存 5 分钟。
  - **可达前提**：`POST /` 只有在 `xpConfigs === false` 时才落到 `camouflageProxy`；`xpConfigs === true` 时 `isXpPathAllowed([])` 对根路径恒真（`worker.ts:44`），请求进 `handleXp`，永远到不了伪装分支。出厂默认 `xpConfigs = false`（`defaults.ts:52`），所以本缺陷对默认部署成立。
  - **与 S-01 同源**：键（`:1328`）**同时**缺 method 与 host。只补 method 挡不住「A 域正文发给 B 域」，只补 host 挡不住「POST 覆盖 GET 的同键写入」。两者必须一起改（见 §7 第 6 项）。
- **影响**：所有访客的 `GET /` 拿到那份（可能是 405/CSRF 拒绝页，或回显 POST body 的页面）内容。若上游回显 POST body，则等于攻击者在面板源上生成任意 HTML，同源脚本可调 `/panel` 接口读取配置与 `subPath`。即使不回显，伪装首页变成 405 页本身就是强指纹。
- **修复**：`streamWithBudgetRewrite` 增加 `cacheable = request.method === 'GET'` 形参，与 `:1386` 同一判据；更彻底：键前置 method（`'GET ' + origin + …`）。

---

### B-09｜非 GET 请求完全绕过永久黑名单与限流，并被无配额转发到兜底域
- **类型**：SECURITY（防护绕过）+ 资源放大　**置信度**：确认【静态】
- **位置**：`src/common/firstCheck.ts:71-72`；`src/worker.ts:167-169`；`src/common/handlers.ts:317-339`
- **证据**：
```ts
// firstCheck.ts:71-72 —— POST 直接放行，连黑名单都不查
    if (request.method === 'POST') return null;
// worker.ts:167-169 —— 返回 null 后落到 fallback（不是 camouflageProxy）
const guarded = await guardNonBuiltinPath(request, env, ctx);
if (guarded) return guarded;
return await fallback(request);
// handlers.ts:331-339 —— method/body 原样转发，无限次
return await fetch(newRequest);
```
- **影响**：① 已被永久封禁的 IP 把探测改成 POST 即继续畅通；② 得到一条无次数配额的 POST 出口（仅受 isolate CPU 约束）；③ `fallback` 不过滤上游响应头（与 `camouflageProxy` 的头白名单策略不一致），可被用来区分「反代」与「真站」。
- **修复**：POST 至少计入限流与违规计数；`fallback` 补与伪装反代同构的令牌桶与响应头白名单。

---

### B-10｜路径字典大小写敏感，且正常访客会被自动永久封禁
- **类型**：BUG（误伤/封禁放大）　**置信度**：确认机制【静态】；触发面取决于伪装站真实路径构成
- **位置**：`src/common/ratelimit.ts:162-166`；`src/common/firstCheck.ts:94-104`；`src/common/blacklist.ts:11`
- **证据**：
```ts
// ratelimit.ts:162-166 —— 不做 toLowerCase（同文件 :137 的 isBuiltinRouteWord 做了）
return segments.every(seg => PUBLIC_PATH_DICTIONARY.has(seg));
// firstCheck.ts:94-101 —— 字典外即限流（6 次/小时），每次被拒都累加违规
if (!isPathInDictionary(segments)) {
    if (!checkRateLimit(ip) || !(await checkRateLimitShared(kv, ip))) {
        ctx.waitUntil(recordViolationAndMaybeBan(ip, kv, ctx));
        return await cf1101RateLimitedResponse(...);
    }
// blacklist.ts:11 —— 22 次即永久封禁
const PERMANENT_BLACKLIST_THRESHOLD = 22;
```
- **问题**：① `isPathInDictionary` 不做小写归一（`worker.ts:46` 的 `isXpPathAllowed` 与 `ratelimit.ts:137` 都做了），`/Index.html`、`/Images/a.jpg` 全判为字典外；② 字典里**没有** `assets`（已实测确认），也没有 `_next`/`wp-content` 一类最普遍的静态资源目录名。
- **影响**（含触发所需的算术，勿读成「随便浏览就会被封」）：访客打开伪装首页时浏览器并发拉取 6+ 个字典外静态资源 → 第 7 个起 429；**每一次被拒都累加一次违规**，而限流窗口是 6 次/**小时**，因此要凑到阈值 22 需要「一次会话内被拒 ≥22 次」或跨会话累积（非封禁 IP 的 `violation:<ip>` 有 7 天 TTL，`blacklist.ts:163-167`）。现代站点的首页静态资源数量完全可能一次就打满 22；一旦写入 `permanentBlacklist` 则成员**无 TTL**，CGNAT 下一整片用户一起被永久封禁。429 本身也是「这里有面板」的指纹。
- **修复**：① 段名先 `toLowerCase()` 再查表（与 `isBuiltinRouteWord` 对齐）；② **主修**：把违规计数绑定到「**字典外 + 本次被限流**」这个**因**，而不是最终状态码 —— 即把 `firstCheck.ts:100` 的 `recordViolationAndMaybeBan` 挪到 `:97-102` 那个 429 早退分支**之内**（今天的写法其实已经在那儿，真正要改的是**让正常 200 流量根本不进入这条分支**：先做「响应疑似探测」判定，再计数）；③ 静态资源扩展名豁免（复用 `camouflage.ts:1076` 的 `STATIC_ASSET_PATH_RE`）只能作辅助 —— 它只匹配结尾扩展名，`/_next/static/chunks/main-8f2c`（无扩展名 chunk）与 `/api/v1/user` 仍会被判字典外。
  - ⚠️ **不要**改成「camouflageProxy 之后按非 2xx 计数」：那会让 `firstCheck.ts:97-102` 的 429 早退分支不再计数 → `permanentBlacklist` **永远到不了阈值 22，整条永久封禁防线变成死代码**；同时上游 404/403（很常见）会让正常访客无上限累积违规，误封反而更容易。现有测试**不会**发现这个洞（全仓无用例断言 `recordViolationAndMaybeBan` 的调用条件）。

---

### B-11｜竞速拨号用 `Promise.allSettled` 等全批 settle：单跳最坏 25s（且取的不是「最快」）
- **类型**：BUG / PERF　**置信度**：确认【静态】
- **位置**：`src/protocols/websocket/common.ts:225-232`（文档在 `:90-99` 自称「取最快成功的」）；对照 `:380` 的直连竞速用 `Promise.any`
- **证据**：
```ts
const results = await Promise.allSettled(dialPromises);
for (const result of results) { if (result.status !== 'fulfilled' || !result.value?.socket) continue;
```
- **问题**：`allSettled` 要等整批（默认 3 条）全部 settle，单条上限 `PROXY_DIAL_TIMEOUT = 5000ms`；且结果数组按入参顺序排列，取到的是「池序第一个成功者」而非「最快成功者」。同文件另一处 `connectWithDirectRaceDial:380` 用 `Promise.any` —— 两处语义已漂移。
- **影响**：池里只要有一条黑洞候选，首包就被拖到 5s；`batch` 允许 5 批 → 单跳最坏 25s，再叠加回退阶梯（pool → official → direct）最坏 75s。客户端表现「时快时慢/偶发超时」，败者 socket 在此期间白占。
- **修复**：统一成 `Promise.any` 语义（胜者立即写首包、其余 `.then(close)`），并把三处竞速（`connectWithRaceDial`、`connectWithDirectRaceDial`、`dialAndWrite`）合并成一份 `raceDial()`（见 R-03）。

---

### B-12｜SOCKS5 / HTTP CONNECT 隧道全程无超时、无 `try/finally`：失败即泄漏 socket
- **类型**：BUG　**置信度**：确认【静态】
- **位置**：`src/protocols/websocket/common.ts:640-655`、`:713-732`、`:754-778`
- **证据**：
```ts
// socks5Connect —— 建 socket 后整段无 try/catch
const socket = connectSocket({ hostname: proxyHost, port: proxyPort }, fetcher);
const writer = socket.writable.getWriter();
async function readAtLeast(need: number) {
    while (leftover.length < need) {
        const { value, done } = await reader.read();   // ← 无 deadline
        if (done || !value) throw new Error('fail to open socks connection');
```
```ts
// httpConnectTunnel —— opened 在 try 之外，清理只覆盖其后
if (socket.opened) await socket.opened;             // 无超时；reject 时无人关闭
const writer = socket.writable.getWriter();
const reader = socket.readable.getReader();
try {                                                // ← 清理从这里才开始
```
- **问题**：`PROXY_DIAL_TIMEOUT(5000)` 只用于竞速拨号；这两条路径没有 deadline。上游代理「accept 但不复 SOCKS5 应答 / 不回 `\r\n\r\n`」时永久挂起；而 `readAtLeast` 之后抛出的每个分支（`no acceptable methods`、`fail to auth`、`invalid proxy response`）都不 `socket.close()`。
- **影响**：① 一条被黑洞的上游代理可稳定占满连接额度（此时 `remoteSocketToWS` 还没挂载，首字节计时器不生效）；② 每次握手失败泄漏一条半开 TCP + 锁死的 reader/writer，长 isolate 累积到句柄/内存耗尽。
- **修复**：两条路径包 `try { … } catch (err) { 释放 reader/writer 锁; socket.close(); throw err; }`，其中：
  - 释放顺序必须是「先 `try{releaseLock}` 再 `try{close}`」，且各自独立 try —— `releaseLock` 在锁未持有/已释放时会抛；
  - 成功路径可能返回 `wrapLeftoverSocket` 产出的**外层 socket**（`:604-627`），它内部另持 `upstreamReader`（`:609`）：对底层 `socket.close()` 不会释放那个 reader，对外层 `close` 也无从 `releaseLock`。**清理必须针对 inner socket**，并在 wrap 里补 `cancel()` 时 `upstreamReader?.releaseLock()`；
  - 握手总 deadline 要放在最外层（`withTimeout` 只是外层 race，不会取消底层打开）；`await socket.opened` 挪进 try 并用 `withTimeout(..., PROXY_DIAL_TIMEOUT)`。

---

### B-13｜会话字节预算与下行令牌桶绑在「下行泵实例」而非「WS 会话」，回退阶梯每换 socket 就重置
- **类型**：BUG（保护失效）　**置信度**：确认【静态】
- **位置**：`src/protocols/websocket/common.ts:1563-1569`（`byteBudget`/`sentBytes`/`governor` 在函数体内初始化）、`1634-1640`；重置点 `:940,963,984,1000,1023,1098-1102`
- **证据**：
```ts
    // 会话级下行字节预算（默认关闭，见 sessionByteBudget 注释）
    const byteBudget = sessionByteBudget();
    let sentBytes = 0;
    const governor = downlinkRate ? createByteGovernor(downlinkRate, downlinkBurstBytes(downlinkRate)) : null;
    ...
    remoteSocketToWS(activeSocket, ..., () => { try { activeSocket.close?.(); } catch {}; handleRetryConnection(); }, log);
```
- **问题**：`sessionByteBudget()` 的注释写「一条 WebSocket 会话就是一次调用」，但 `byteBudget`/`sentBytes`/`governor` 都在 `remoteSocketToWS` 函数体内初始化，而 `handleTCPOutBound` 在首跳失败或首字节超时会再调一次 `remoteSocketToWS`（回退阶梯最多 4 级，重挂点在 `:940,963,984,1000,1023,1098-1102,1152,1179`）。每次调用都是新的预算与满额突发额度。
  - ⚠️ 上引代码注释里的「默认关闭」**已过时**：`WS_SESSION_MAX_MB_DEFAULT = 900`（`ws/common.ts:1230`）在 `:1250-1252` 被直接返回，即**默认开启 900MB**。因此本缺陷对**每个部署都成立**，不是「开了才有」。
- **影响**：客户端只要让首字节超时发生，就能在同一条 WS 上把预算翻 N 倍（最多 4×900MB），把 `WS_DOWNLINK_BURST_KB` 的突发重复兑现 —— 正是该保护要防的 isolate 被打死场景。
- **修复**：把 `sentBytes`/`byteBudget`/`governor`（以及 `statsOn` 的累计）提升到 WS 会话级（放进 `unified.ts` 的 per-connection 上下文或 `WeakMap<WebSocket, …>`），回退时复用同一实例。
  - ⚠️ **`budgetExceeded` 必须留在 per-mount（局部）**：`:1677` 的 `if (budgetExceeded) safeCloseWebSocket(webSocket)` 在 try/finally 之后执行；若把该标志也提到会话级且首次挂载就超限，第二次重挂会立刻把刚建立的会话关掉（客户端抖动）。
  - 本条**不依赖** G-01：它的新测试可以直接在 `tools/ws-downlink-frame.test.mjs` 的桩上构造「首字节超时 → 重挂」，不要因为「等闸门」而拖延。
  - 顺带修正 `:1230` 附近那段「默认关闭」的过时注释。

---

### B-14｜`resolveUrlEntries` 的去重键把「同 scheme + 同凭据」的不同代理条目合并成一条，静默丢节点
- **类型**：BUG　**置信度**：确认【静态，键值已手工代入验算】
- **位置**：`src/cores/utils.ts:499-510`（去重）+ `:287-310`（键生成）；消费点 `src/common/handlers.ts:173-174`、`src/common/ws-runtime.ts:75`
- **证据**：
```ts
// :499-508 —— 对所有条目一律用「地址:端口」口径去重
for (const item of rawResolved) { const key = extractNodeDedupKey(item); ... }
// :288-307 —— 键生成假定 '@' 之前是裸地址
const atIdx = noComment.lastIndexOf('@');
const bare = atIdx !== -1 ? noComment.slice(0, atIdx).trim() : noComment;
const lastColon = bare.lastIndexOf(':');
    host = bare.slice(0, lastColon); port = bare.slice(lastColon + 1) || defaultPort;
return `${host.toLowerCase()}:${port}`;
```
- **问题**：对 `socks5://user:pass@1.1.1.1:1080`：`atIdx` 命中凭据后的 `@`，`bare = "socks5://user:pass"`，`lastIndexOf(':')`（`utils.ts:291`）落在 `user` 与 `pass` 之间 → `host="socks5://user"`、`port="pass"`，最终键 = `socks5://user:pass`。同 scheme、同凭据、**不同主机/端口**的所有代理条目得到完全相同的键，第二条起被静默丢弃。另外该键还经 `host.toLowerCase()`（`:309`）把用户名/口令的大小写抹平。
- **影响**：用户配置的多个 socks/http 代理节点在整份订阅（raw/xray/sing-box/clash）里只剩第一条，无任何日志。同一函数还用于 `proxyIPs`（`ws-runtime.ts:75`），`a.com:443@HK` 与 `a.com:443@US` 也会因键丢掉地区后缀而合并。
- **修复**：代理条目跳过地址去重（它已有 `cleanProxyEntries` 的精确去重），或在 `extractNodeDedupKey` 开头 `if (/^[a-z0-9+.-]+:\/\//i.test(entry)) return entry.toLowerCase();`。

---

### G-01｜构建闸门的 6 条订阅请求全部落到 fallback —— 三端配置生成层一次都没被执行
- **类型**：BUG（闸门失效，比单条功能缺陷更根本）　**置信度**：确认【实测：读 `dist` 同批次 smoke 产物逐条取证】
- **位置**：`scripts/smoke.mjs:378-383`；`src/common/handlers.ts:180-250`
- **证据**：
```js
// smoke.mjs:378-382 —— 订阅 URL 缺 normal|raw|fragment|warp|warp-pro 段
['GET /sub/<subPath> (raw)', `/sub/${SUB_PATH}`, {}],
['GET /sub/<subPath>?app=clash', `/sub/${SUB_PATH}?app=clash`, {}],
['GET /sub/<subPath>?app=sing-box', `/sub/${SUB_PATH}?app=sing-box`, {}],
```
```ts
// handlers.ts:180-250 —— 服务端只认这些形状，其余一律 fallback
switch (pathName) {
    case `/sub/normal/${subPath}`: …
    case `/sub/raw/${subPath}`: …
    case `/sub/fragment/${subPath}`: …
    case `/sub/warp/${subPath}`: …
    case `/sub/warp-pro/${subPath}`: …
    default: return await fallback(request);
```
```text
# .build/smoke/artifact.json（与 dist/worker.js 同批次，2026-11-16 13:06）
["GET /sub/<subPath> (raw)",{"status":200,"type":"text/html",…,"body":"<!DOCTYPE html><html><body>smoke upstream</body></html>"}]
全文统计：'vless://' 0 次　'proxies' 0 次　'inbounds' 0 次　'smoke upstream' 10 次
```
- **问题**：`/sub/<subPath>` 这种形状在服务端没有任何分支，6 条订阅请求全部走 `default → fallback()`，拿到的是 stub 上游的 HTML。
- **影响**：`cores/xray`、`cores/sing-box`、`cores/clash`、`acl-template.ts` 这一整层（约 6.5k 行）从未被任何闸门执行 —— **落在这层里的缺陷共 16 条：P1 5 条（B-04/B-05/B-06/B-07/B-14）+ P2 11 条（B-42…B-52）**。所谓「smoke 比对通过」实际只覆盖：页面能返回、鉴权会拒绝、限流会生效。这也解释了 B-04（悬空 tag）、B-07（空分组）这类「一眼可见」的缺陷为何能长期存活。
- **修复**：注意这 6 条里 **5 条是错形、1 条是刻意的负例**（`smoke.mjs:383` 的 `/sub/${UUID}` 本就该落 fallback，**不要改**）。把 5 条改成真实形状（`/sub/normal/<subPath>?app=clash` 等），断言用「**响应不得等于 fallback 特征**」这个通用判据（例如 `content-type` 不得为 `text/html`、body 不得等于 stub 页），而不是逐条 token 匹配 —— 后者在 raw 订阅体被 B-37 截断时会失效。长期方案见 §6 末的「结构断言测试」。

---

### S-01｜伪装缓存键不含 Host，正文却按 `reqURL.host` 改写；出站又随机化 UA/Accept-Language
- **类型**：BUG / SECURITY　**置信度**：确认机制【静态】
- **位置**：`src/common/camouflage.ts:1328`、`:1378`、`:475-487`、`:290`
- **问题**：同一个 Worker 常绑多个入口（自定义域 + `*.workers.dev` + 多条 route）。缓存键无 `reqURL.host` → A 域写入的正文（内部链接全是 A 域）被 B 域访客命中，等于泄露部署的另一主机名。同时出站每次随机 UA / `Accept-Language`，上游常据此返回 `Vary: Accept-Language` 的不同语言页，而缓存不区分变体 —— 首个访客的语言决定 5 分钟内所有人看到的页面；上游 `Vary` 还会被原样透出。
- **附**：键可由攻击者无限生成（`normalizeCacheQuery` 保留一切非噪声参数）→ 可把热点键持续挤出缓存，造成 CPU 峰值。
- **修复**：键前置 `reqURL.host`；`Vary` 只保留安全子集或删除；若要保留多语言，把归一化的语言主标签纳入键而非每次随机。

### S-02｜噪声参数无条件剔除 + 代理响应无 CSP：上游回显即构成同源投毒链
- **类型**：SECURITY　**置信度**：确认为「投毒原语」；升 XSS 取决于上游是否回显
- **位置**：`src/common/camouflage.ts:1117-1138`、`:1387-1393`、`:515-518`
- **问题**：`utm_*`/`gclid`/`fbclid` 等被**无条件**从缓存键剔除（与「存在语义参数就整条不归一」的保险无关）。若上游把 `utm_source` 回显进 HTML（营销落地页极常见），`GET /?utm_source=<script>…` 得到的响应会以「无 query」的键入缓存 5 分钟，并在面板同源执行 —— 同源脚本可调 `/panel` 接口。
- **修复**：噪声剔除默认改为「保留一个不透明指纹」；对代理响应补 `Content-Security-Policy: sandbox` 或 `script-src 'none'`（对纯伪装页不改变渲染，但掐断升级链）。

### S-03｜`CF-Connecting-IP` 未转义拼进 1101 页，且它同时是限流/黑名单的键
- **类型**：SECURITY　**置信度**：确认「无转义」；可利用性取决于部署形态（前面是否还挂了一层反代）
- **位置**：`src/common/camouflage.ts:383`（`<span id="cf-footer-ip">${accessIP}</span>`）、`:329,368,372`；`src/common/firstCheck.ts:46`；仓库已有 `escapeHtml`（`src/common/common.ts:122`）却未使用
- **影响**：① 该部署形态下 HTML 注入；② 每请求换一个假 IP 即可让 6 次/小时限流、跨边缘判定与永久黑名单全部失效，并反向污染 KV（`ratelimit:<假IP>`、`violation:<假IP>` 各写一条），正好把内存表与 KV 写额度打满。
- **修复**：渲染侧 `escapeHtml`；键侧做 IPv4/IPv6 形态校验，非法即视为 `''`。

### S-04｜每条连接把客户端目标主机与端口无条件写进日志，不受 `logLevel` 门控
- **类型**：SECURITY（隐私）　**置信度**：确认【静态】
- **位置**：`src/protocols/websocket/unified.ts:192-201`（`log` 无门控）、`:354-355`、`:406-407`
- **证据**：
```ts
const log = (info: string, event?: string) => { console.log(`[${address}:${portWithRandomLog}] ${info}`, event || ""); };
const logDebug = (info: string) => { if (globalThis.settings?.logLevel === 'debug') log(info); };
```
- **问题**：`address` 是客户端请求的**目标主机名**（= 用户浏览历史），被前置到本连接所有日志行，并传进 `handleTCPOutBound` 的全部日志。默认 `logLevel: "warning"` 管不住它。同文件为「不回写 UUID」写了 6 行注释、`handlers.ts` 还为错误页做了凭据脱敏 —— 唯独完整访问目标清单明文留在 Workers Logs。
- **修复**：`log` 同样按 `logLevel` 门控（仅 debug 带 `address:port` 前缀），或把目标地址从默认前缀中移除。

### S-05｜`?qj=` 让任意持订阅路径者关闭服务端「仅走代理」（反 IP 泄漏）开关
- **类型**：SECURITY（策略绕过）　**置信度**：确认机制【静态】
- **位置**：`src/common/ws-runtime.ts:61-91`
- **问题**：`qj` 的 URL 覆盖优先级高于 KV，URL 参数本身不校验任何凭据；WS 路径只要落在公共伪装字典内（`worker.ts:86-92`）就能触发。客户端加 `?qj=no` 即可让运维设置的 `proxyOnly`（`common.ts:919-924` 明确标注「防 IP 泄漏」）失效。**但要说清**：`qj` 只影响 `prepareWsRuntimeConfig` 写出的 `wsConfig`，后续首包鉴权仍要正确 UUID —— 所以准确表述是「任何订阅者可单方面关掉运维的反泄漏开关」，而非「任意人能绕过防护」。这三个参数（`wk`/`rm`/`qj`）在本仓订阅生成代码里从不产出，也无文档，属无消费方的外部开关。
- **修复**：若保留，要求与 `subPath` 同时出现或由 settings 显式允许；否则删掉 URL 覆盖，只读 KV。

---

### P-01｜`/secrets`、`/panel` 等页面每次请求都 base64→gunzip 解压整页 HTML（无记忆化）
- **类型**：PERF　**置信度**：确认【静态】　**位置**：`src/common/handlers.ts:567-578`（`decompressHtml` 无缓存）；调用点 `:112,134,522,543,550`
- **问题**：面板 HTML `__PANEL_HTML_CONTENT__` 约 80KB → base64 约 110KB，`atob` + `DecompressionStream` 每请求各一次。流式返回（`asString=false`）虽然不在请求线程内解压，但 `atob` 与 Blob 构造仍在热路径上；`/login` 走 `asString=true` 则**完整解压进内存**。
- **影响**：每个面板/登录请求固定的 CPU 与 GC 峰值 —— 本项目历史上多次「CPU 超限规律性复发」正是这类固定开销叠加所致。
- **修复**：模块级 `Map<string, Uint8Array>` 缓存解压后的字节（HTML 是构建期常量，isolate 生命周期内不会变），首次解压后复用一个 `Response` 模板；`asString` 结果也缓存。

### P-02｜`getDataset` 无条件读 `warpAccounts`（含 1s sleep 的注册流程）而 `setSettings` 只用 settings
- 与 **B-02** 同源，是其性能面：**不单独计数**，修复方案已并入 B-02（§1 的统计口径已扣除）。

---

## 3. P2 缺陷（44 条，按主题归并）

### 3.1 协议/连接层

| ID | 问题 | 位置 | 影响 | 修复 |
|---|---|---|---|---|
| B-15 | WS 连接名额只靠 WS 事件钩子释放，`accept()` 到监听器注册之间的异常无 `try/finally` | `unified.ts:174-213` | 泄漏窗口是 `:185-213` 之间的异常，这几步几乎不抛（概率低）；一旦触发则**本 isolate 内**额度只减不增、直到 isolate 回收，累计 128 次后该 isolate 全部 429 | 该段包 try/catch，catch 里递减并关闭 socket（对齐 `handler.ts:172-177` 的 `terminate/released`） |
| B-16 | VLESS/Trojan UDP-DNS 的上游 TCP socket 被上游关闭后不重建，下一次写入抛错 → 整条隧道被关 | `unified.ts:1257-1259,1320,1180-1186` | 空闲跨过上游 idle 关闭后，一条无关的 DNS 写失败打死整条 WS | 上游 `done` 时置 `dnsSocketDead`，`write()` 入口重建 socket + writer + 响应泵 |
| B-17 | XHTTP 的 UDP 上行把「任意 chunk 边界」当「一帧一数据报」，每 chunk 都砍 2 字节长度前缀 | `xp/handler.ts:486-503` + `unified.ts:1286-1291` | XHTTP + UDP/53 下 DNS 报文间歇性损坏，无日志 | `pumpUdpUplink` 内做与 `pumpTcpDnsMessages` 同型的两字节长度前缀重组 |
| B-18 | `parseVlHeader` 的地址段无边界校验：ATYP=3 截断抛 `RangeError`，ATYP=1/2 截断接受残地址 | `unified.ts:728-757`（端口处已有校验，地址段没有） | **前提：必须先通过 UUID 比对**（`:695-699` 在读地址段前就 return），故只有持凭据的客户端/自身有 bug 的客户端能触发；WS 路径异常外溢为未捕获 `RangeError`（XHTTP 路径在 try 内，被吞成 400） | 按 ATYP 各自校验 `byteLength`，与 `parseTrHeader` 对齐 |
| B-19 | `dialAndWrite` 无 `finally`：超时不关 socket、写失败时 writer 锁不释放，且 `remoteSocket.value` 残留 → 上行泵拿到 `WritableStream is locked` | `common.ts:424-455` | 黑洞 IP 留半开连接；首包写失败表现为「pipeTo error / locked」而非真实原因 | `try/finally` + 异常分支 `close()` + 失败时把 `value` 置空 |
| B-20 | `btoa` 编码非 Latin-1 凭据抛错，且抛错点在清理区之外（SOCKS5 侧已修长度、HTTP 侧未修） | `common.ts:754-778` | 中文/emoji 口令的上游 HTTP 代理 100% 不可用，且每次泄漏 socket | 先 `TextEncoder().encode()` 再 base64；`requestText` 构造移进 try |
| B-21 | WS `message` 事件不过滤 text 帧 → `ByteLengthQueuingStrategy` 对 string 取 `byteLength=undefined` → `RangeError`（抛出发生在入队**之前**，流不会被 error 化） | `common.ts:1821-1843,1880-1882` | 该帧被静默丢弃、泵继续等下一条；异常位于 `message` 监听器内，不会传到上行泵。VLESS 客户端不发 text 帧，实际触发者是扫描器/中间设备 | `if (typeof event.data === 'string') { log(...); return; }` |
| B-22 | `makeReadableWebSocketStream` 的 close/error 监听器不置 `readableStreamCancel`，迟到的 `message` 对已关 controller `enqueue` | `common.ts:1818-1858` | 关闭瞬间未捕获 `TypeError`，污染日志 | close/error 首行置标志，或 `enqueue` 包 try |
| B-23 | 下行泵 `catch` 静默吞掉所有上游读错误（`error` 变量未使用、不记日志） | `common.ts:1667-1673` | 「下行为什么断了」完全无法从日志定位 | catch 里按 `hasIncomingData` 记一行 `safeErrorMessage` |
| B-24 | `wrapLeftoverSocket` 产出非 byte-stream，导致走上游代理的连接**必然**退回非 BYOB 读路径（额外拷贝 + 每块分配） | `common.ts:604-619` + `:1594-1601` | 配了 socks5/http 上游的用户下行吞吐与 GC 劣化，且无降级日志 | 用 `type:'bytes'` 的 ReadableStream；`cancel` 里补 `releaseLock` |
| P-03 | 竞速/超时定时器全部不清除（`Promise.race` 的 `setTimeout` 无 `clearTimeout`） | `common.ts:210-215,365-370,440-445` | 一次连接最多 15 个必空跑的悬空定时器 | 用 `finally { clearTimeout(t) }` 或统一用 `withTimeout()` |

### 3.2 缓存 / 伪装面

| ID | 问题 | 位置 | 影响 | 修复 |
|---|---|---|---|---|
| B-25 | 缓存只存 body/status/content-type：命中时丢 `Location`/`Content-Language`/`Set-Cookie` 等头，且写入不筛状态码 | `camouflage.ts:1330-1337,1386-1393` | 命中/未命中响应头集合系统性不同（可判定缓存）；3xx 命中变成「无 Location 的 3xx」；上游一次 5xx 被固化 5 分钟 | `CacheEntry` 存 `filterResponseHeaders` 快照；只缓存 2xx |
| P-04 | 缓冲分支 `resp.clone()` 后不消费原 body：双份内存，且上限只依赖上游自报 `content-length` | `camouflage.ts:1375-1378`（对照 `:1371-1372` 明确 cancel 了同类 body） | 常驻内存翻倍；上游谎报长度可把 isolate 打到 OOM | 去掉 `clone()` 直接 `text()`；`finally` 里 `resp.body?.cancel()`；加真实字节闸门 |
| B-26 | 时间戳「值形态门」选错了判据对象：`isNearNowEpoch` 要求落在 `now±1h` 才剔除，恰好把「以当前时刻为内容键」的接口折叠进同一缓存键（**注意：代码与注释一致，不是方向写反**） | `camouflage.ts:1062-1067,1086-1092,1133-1136` | 行情/直播抽帧/实时榜单这类接口，首个访客的快照被发给所有人并固化 5 分钟；而「上一年快照」这类真正的缓存破坏参数反而被保留 | 秒级 10 位一律不归一（或仅在 `STATIC_ASSET_PATH_RE` 命中的静态资源路径上归一）；**不要**改成「剔远离 now 的值」——`camouflage-cpu.test.mjs` 明确钉住了「历史时刻不归一」这条防投毒红线 |
| B-27 | `authFailurePool` 无上限、空条目永不回收（另两个池都有封顶 + 空即删） | `ratelimit.ts:263-284`（对照 `:176-180,193`；`blacklist.ts:127`） | 分布式口令爆破（每 IP 试一次）即可让内存条目单调增长、永不过期 | `valid.length===0` 时 `delete`；插入前 `evictOldest(..., MAX-1)` |
| B-28 | 图片子请求两处裸 `503`（无 Content-Type/nosniff/HSTS），与同文件刻意中性的 1×1 PNG 兜底不一致；Range 分支整段复制 ArrayBuffer | `camouflage.ts:998,1303-1305,1019` | 非中性响应 = 部署存在性 oracle 的又一指纹；每个 206 多一次完整拷贝 | 统一走 `placeholderImageResponse`；Range 改用 `Uint8Array` 视图 |
| B-29 | `is1101` 分支在生产不可达（`init()` 恒把 `fallbackDomain` 填成至少 `h5captcha`） | `camouflage.ts:454-469` vs `init.ts:86` | 「未设置就不出站」的运维假设是错的：未配置时整站反代到 `www.hcaptcha.com` | 二选一并写进契约：删掉死分支，或让 `init()` 不在伪装域名维度兜底 |

### 3.3 设置 / KV / 面板接口

| ID | 问题 | 位置 | 影响 | 修复 |
|---|---|---|---|---|
| B-30 | `updateDataset` 里 `request.json()` 在 try 之外；`extractProxyParams` 的 `new URL(outProxy)` 无护栏 | `kv.ts:200`、`:375-380`、`:328-341` | 面板填一个非法 outProxy / 发一个坏 JSON → 拿到 `{"success":false,"status":500}` **JSON**（不是 HTML 错误页，`handlers.ts:257-267` 已接住），但应是 400「字段非法」 | 解析与 `new URL` 包 try，映射成 `InvalidSettingsError` |
| B-31 | `getMyIP` 把请求体原文插进第三方 URL：`fetch(\`http://ip-api.com/json/${ip}?…\`)` | `handlers.ts:349` | 畸形输入变成任意 path/query 注入与 500；明文 http 外发 | 先校验 IPv4/IPv6 形态，非法直接 400 |
| B-32 | `decompressHtml`（见 P-01）；`serveIcon`/WG ZIP 响应缺 `securityHeaders` | `handlers.ts:459-467,495-505` | 响应头策略不一致（ZIP 无 `Cache-Control`，favicon 无 nosniff） | 统一过一遍 `securityHeaders` |
| B-33 | `resolveSubPath` 的 isolate 级缓存与「运维可改 KV `subPath` 轮换」的文档承诺冲突 | `init.ts:125,162,174` | 改 KV 后需等 isolate 回收才生效（可能数小时），轮换语义失真 | 缓存加 TTL，或让轮换走 `SUB_PATH` env |
| B-34 | `initializePassword` 的「读 pwd → 写 pwd」非原子 | `auth.ts:123-136` | 首访瞬间两个并发请求都看到 `null`，后者覆盖前者（低概率） | 写入后再读回校验，或首访要求与部署日志中的 token 对齐 |
| S-06 | `Authenticate` 成功时把 `payload.userID`（= VLESS UUID）明文写进日志：`console.log(\`Successfully authenticated, User ID: ${payload.userID}\`)` | `auth.ts:182` | `Authenticate` 只被 `requireSession`（6 处）与 `handleProxyIPs:70` 调用 —— **`/sub/*` 不鉴权**，故受影响的是 `/panel/*` 与 `/proxy-ip*`：每条已认证请求刷一次**代理凭据**进 Workers Logs，与 `unified.ts:99-102`「不回写 UUID」的既有裁决直接冲突 | 删除该行，或只打 `payload.userID.slice(0,4)+'…'` |
| B-53 | `resolveUrlEntries` 对「列表 URL 抓取失败」静默丢弃该 URL 展开出的**全部**节点（`catch {}` 后 `push(...[])`），零日志；`:471` 的 `if (!res.ok) return;` 是同类丢弃 | `cores/utils.ts:466-486,490-497` | 远端 cleanIPs 列表临时不可达 → 整段节点从订阅消失，用户与运维都看不到原因（比 B-14 的去重丢节点更常见） | `console.warn` \+ **过期也留作 fallback**：`:459-463` 判过期时不要丢掉 `parsed.lines`，抓取失败时用它（注意 `urlCacheMap` 失败路径没有旧值可"不覆盖"，照原样写无法落地） |
| B-56 | **尾斜杠归一化只喂给了凭据校验，没有回流路由**：`initHttp:213` 算出 `normalizedPath` 但只传给 `assertRequiredCredentials`；`globalConfig.pathName`（`init.ts:100`）保留原样，而 `handleLogin:141`/`handlePanel`/`handleSubscriptions`/`handleProxyIPs:79` 全部按 pathName **精确**匹配 | `init.ts:100,213`；`handlers.ts:36-66,141-154,180-250` | `/panel/`、`/panel/settings/`、`/login/`、`/sub/normal/<x>/`、`/proxy-ip/get/` 一律落到 `fallback`（伪装页）。`init.ts:209` 的注释明确承诺「`/secrets/` 与 `/secrets` 等价」—— 该承诺只在**首段级**路由（`worker.ts:131` 的 `switch(path)`）上侥幸成立，二级路由全部不成立 | 把归一化结果写回 `globalConfig.pathName`（`init()` 里算完后统一小写化与去尾斜杠），或让各 handler 用同一个归一化 path |

### 3.4 前端 / 构建

| ID | 问题 | 位置 | 影响 | 修复 |
|---|---|---|---|---|
| B-35 | smoke 闸门的 `PUT /panel/update-settings` 用 urlencoded + 不存在的字段名（`vlessConfigs`/`protocol`） | `scripts/smoke.mjs:357-373` vs `kv.ts:200`、`panel/script.js:478-483` | 该请求恒 500 且两次运行逐字节相同 → 比对恒过；**设置写入链路零覆盖** | 改发与浏览器一致的 JSON（`VLConfigs`/`TRConfigs`/`ports:[…]`）并断言 200，再补一条负例 |
| B-36 | `verify.mjs` 的禁止词用 `\b词\b`，但词表大半是「词内部片段」（`xhtt`/`ncrypt`/`ipv`/`port`…） | `scripts/verify.mjs:287-301` vs `obfuscate.mjs:274-277` 的 `includes` | 这些条目数学上不可能命中 → 假绿 | 片段型条目改子串匹配（或加前缀标记） |
| B-37 | `normalizeBody` 的 `/\s+at\s[^\n]*/g` 对**单行**响应体会从第一个 ` at ` 删到结尾 | `scripts/smoke.mjs:304-310` | 真正受影响的是 minify 后的 HTML 页面与 raw base64 订阅体；`configJsonResponse` 用 `JSON.stringify(data,null,4)` 是**多行**，不受影响。且当前订阅体根本没被 smoke 生成（见 G-01），故属「修好 G-01 后立刻发作」的隐患 | 只抹带文件定位的帧：`/\s+at\s[^\n(]*\([^)\n]*\)/g` |
| B-38 | 面板首屏 `fetch('/panel/settings')` 不判 `response.ok`，失败仍走 `finally` 完成半初始化 | `panel/script.js:27-61` | 会话过期时用户看到「框架正常、全空白、Apply 永远 disabled」，且每 30s 继续打 `/region` | 非 2xx → 跳 `/login`；事件绑定提前到 fetch 之前 |
| B-39 | `validateChainProxy` 里 `atob`/`JSON.parse`/`new URL` 全裸调用，异常冒泡出 submit handler | `panel/script.js:884,890` | 手改坏的 vmess 链式配置 → 点 Apply **毫无反应**（控制台一条未捕获异常），且从此无法保存任何设置 | 包 try/catch + alert；`validateSettings()` 整体再包一层 |
| B-40 | `applyButton.value = '⌛ Loading...'` 不显示（`<button>` 的标签来自子节点） | `panel/script.js:475-476` | 保存期间零反馈，与 B-39 叠加成「点了没反应」 | 改 `textContent` + `disabled` |
| B-41 | `resetSettings`/`updateWarpConfigs` 的 spinner 与 `cursor:wait` 复位写在成功分支，无 `finally` | `panel/script.js:336-355,439-462` | 网络中断后永久转圈，用户重复点击会真的重写 KV 默认值 | 复位移进 `.finally()`（`updateSettings` 已是正确范式） |
| P-05 | 面板/代理 IP 页从 `cdn.skypack.dev`（无版本号的动态解析）、`cdnjs` 拉执行代码，无 SRI、无 CSP | `panel/index.html:9,1410-1414`、`proxy-ip/index.html:41-44` | 第三方 CDN 被投毒 = 面板完全接管（可读订阅密钥、可改口令）；`qrcodejs` 失效时 QR 弹层空白 | 去掉 polyfill（`String.fromCodePoint` 已够用）、qrcode 本地打包、加 SRI 与 CSP |

### 3.5 跨端一致性（详见 §5 冗余地图）

| ID | 问题 | 影响 |
|---|---|---|
| B-42 | `alpn` 的 `h2` 过滤只存在于 sing-box | 同一订阅三端协商不同 ALPN；按某端调好的结论在另一端不成立 |
| B-43 | sing-box 的 ECH 名称缺 `\|\| host` 回退 → 空名单时 sing-box 输出「ECH + alpn」，另两端输出「ECH 无 alpn」 | 三端 TLS 指纹不一致 |
| B-44 | `blockAds`：Xray 多拦 `category-ads-ir`，另两端没有 | 伊朗用户切 sing-box/Clash 后本地广告不再拦截 |
| B-45 | Clash 静默丢弃「非 TLS 端口的 Trojan」，Xray/sing-box 照常下发明文节点 | 同一订阅在 Clash 少节点；明文口令节点在 JSON 侧无告警 |
| B-46 | 「拦截域名」的 DNS 写法三端三种；Xray 用 `hosts[domain]='#3'`（非 IP 非域名），且把 `geosite:` 塞进 `hosts` 键 | 该拦截很可能完全不生效（靠路由层兜底），三端不可预期 |
| B-47 | ACL 内联规则的 `,no-resolve` 修饰符三端处理不一（URL 规则集路径剥了，内联路径没剥） | 一份含 `no-resolve` 的内联规则即可让 Clash/sing-box 整份配置加载失败 |
| B-48 | 「Clean IPs 代理节点名」无唯一化（只按协议+主机+端口+凭据去重，不管备注重名） | 两个 `#家宽` → Clash 重名拒载 / sing-box `duplicate outbound tag` FATAL |
| B-49 | Clash 顶层 `"ipv6": true` 硬编码，与 `dns.ipv6: enableIPv6` 不一致 | 「关掉 IPv6」在 Clash 端只部分生效（连接仍可走 IPv6） |
| B-50 | Xray 链式出站忽略 outProxy 的显式 `ed`，且把 `?ed=` 原样写进 `wsSettings.path` | 三端 ed 语义不同；Xray 端可能出现「路径带 query」的连不上节点 |
| B-51 | Xray `fakedns` 只对**旁路（直连）域名**发假 IP，另两端是「代理域名才 fake」；且旁路列表为空时行为整体翻转 | 开启 fakeDNS + 任一 bypass 时，直连域名拿到 198.18.x.x 不可路由地址；三端 DNS 结果完全不同 |
| B-52 | 分片订阅静默丢弃全部 `customCdnAddrs` 地址（`if (!isFragment)`） | `/sub/fragment/*` 少一整段节点 |

---

## 4. P3 与卫生问题

### 4.1 死代码

| ID | 位置 | 说明 |
|---|---|---|
| D-01 | `common.ts:880`（`hasCustomProxyIPs`）、`xp/handler.ts:163`（`env`） | `tsc --noUnusedLocals/Parameters` 仅报这两处【实测】 |
| D-02 | `cores/utils.ts:35-41` 的 `特征码字典` | 仅 `[0]`/`[3]` 被引用；`[1]`/`[2]`/`[4]` 每次模块加载白算，且是常量表达式（起不到混淆作用） |
| D-03 | `cores/utils.ts:27` 的 `declare const connect` | 全文件未使用（实现走 `(globalThis as any).connect`） |
| D-04 | `xray/inbounds.ts:29-47` 整段注释的 `buildTunInbound` + `configs.ts:103` 注释调用 + `xray.d.ts:62-70` `TunInbound` | 会让维护者误判「三端都支持 TUN」 |
| D-05 | `types/xray.d.ts:270-275` `Fragment` | 零引用，且 `interval` 与真正在用的 `TCPMask.delay` 字段名不一致 —— 照它写会生成 Xray 不认识的字段 |
| D-06 | `types/clash.d.ts:258` `ProxyGroup`、`types/sing-box.d.ts:106-110` `InlineRuleSet` | 零引用；`acl-template.ts:638` 又自己写了一份内联字面量类型 |
| D-07 | `xray/configs.ts:161-183` `addBestPingConfigs(isFragment)` | 参数只在递归里往下传，函数体从未读取 |
| D-08 | `unified.ts:106` 再导出 `getXPaddingIdentifier`、`:802` 的 `offset` 形参、`:705-710` 空 `if (command===1)` 分支、`:85-91` 不可达嵌套守卫 | 阅读噪音；空分支易被误读成「处理被删掉了」 |
| D-09 | `blacklist.ts:202` `clearBlacklistMemoryCache` | 全仓（含测试）零调用点，注释称「供测试用」但测试未用 |

### 4.2 冗余

| ID | 内容 | 位置 |
|---|---|---|
| R-01 | 三套 `getGeoAssets()`（20 个开关 → geosite/geoip/URL），条目数与 id 拼写已漂移 | `xray/geo-assets.ts`、`sing-box/geo-assets.ts`、`clash/geo-assets.ts` |
| R-02 | DNS 服务器条目构造三份（`buildDnsServer` / `addDnsServer` / 内联字面量） | `xray/dns.ts:148-164`、`sing-box/dns.ts:282-314`、`clash/dns.ts:146-160` |
| R-03 | 三处竞速拨号（`connectWithRaceDial` / `connectWithDirectRaceDial` / `dialAndWrite`），约 180 行同构，且已出现 `allSettled` vs `Promise.any` 的真实分叉 | `common.ts:199-263,359-407,424-455` |
| R-04 | 节点 TLS 上下文（SNI/ECH/alpn/allowInsecure）判定三份，sing-box 那份是内联的 | `xray/outbounds.ts:97-141`、`sing-box/outbounds.ts:92-116`、`clash/outbounds.ts:66-98` |
| R-05 | ~~`buildTransport` 三家分支完全相同（只差 path 预处理，而这正是 B-50 的成因）~~ **⚠️ 本条表述有误，已由复查修正**：三份输出的是**三种不同 schema**（xray 嵌套 `wsSettings`/`rawSettings`、sing-box `type` 标签 + 扁平字段、clash `network` + `ws-opts` 等），**不是同构代码、不可合并为一份更小的函数**。真正重复的是它们共用的**判据**：① path 预处理（B-50 的成因，已收敛为 `normalizeTransportPath`）；② `earlyData ? "Sec-WebSocket-Protocol" : undefined` 这条三元式（**6 处**，已收敛为 `earlyDataHeaderName()`）。附带发现：三份的**形参顺序不同**（xray 是 `earlyData, serviceName`，另两端是 `serviceName, earlyData`），统一签名无体积收益却有换位风险，故保持原样 | `xray/outbounds.ts:444-508`、`sing-box/outbounds.ts:377-429`、`clash/outbounds.ts:442-507` |
| R-06 | `getChainExplicitEarlyData` 在 sing-box / clash 逐字重复；`redrawChainEarlyData` 语义相同、形状不同 | `sing-box/outbounds.ts:219-312`、`clash/outbounds.ts:243-374` |
| R-07 | 订阅主循环骨架三份（~70 行/份：`usedPaths`/`usedEds`/`chainProxy`/`prependUpstreamItem`/端口过滤） | `xray/configs.ts:280-355`、`sing-box/configs.ts:95-178`、`clash/configs.ts:83-166` |
| R-08 | XHTTP 节点第二趟遍历三份（近乎逐行相同） | `xray/configs.ts:372-400`、`sing-box/configs.ts:196-223`、`clash/configs.ts:172-194` |
| R-09 | VLESS/Trojan 的 DNS 上游建连+5s 超时+清理钩子逐字重复，且**登记顺序不一致**（Trojan 侧钩子晚于响应泵启动） | `unified.ts:1236-1255` vs `1350-1369` |
| R-10 | 「伪装背景 iframe」的 27 行 CSS 被复制 5 份；`panel/style.css:572-575` 的 `hr` 规则无宿主元素 | 4 个 style.css + `error/index.html` |
| R-11 | 伪装/兜底域名：`'www.hcaptcha.com'` 两处硬编码；env 链（homepage/HOMEPAGE/URL/FALLBACK）抄两遍；域名归一化两套语义 | `init.ts:86`、`handlers.ts:323`、`camouflage.ts:432-452,456-463` |
| R-12 | TLS 端口表三处硬编码（服务端 `init.ts:222-223`、面板 `script.js:16-17`、`isHttps` 消费端） | 新增端口时极易只改一处 |
| R-13 | `Array.prototype.concatIf` / `Object.prototype.omitEmpty` 直接赋值（**可枚举**） | `utils.ts:1133-1142` + `global.d.ts:233-239`。当前全仓无 `for...in`【实测 grep】，故未造成实际污染，但属高风险隐式耦合；`omitEmpty` 对空数组也返回 `undefined` |

### 4.3 环境/分类卫生

| ID | 内容 | 证据 |
|---|---|---|
| H-01 | **无 ESLint 配置也无 lint 脚本**，却装了 4 个 eslint devDependency（`eslint`、`@eslint/css`、`@eslint/js`、`@eslint/markdown`）外加一个只服务 lint 的 `globals`（它在 `dependencies` 里） | 全仓（除 node_modules）无 `eslint.config.*`/`.eslintrc*`【实测 glob】；`ensure-deps.mjs:43` 还专门写着「其余 devDependencies（eslint、@eslint/*）只服务 lint」——但那条流水线不存在 |
| H-02 | **`package-lock.json` 未被跟踪**：`.gitignore` 的 `*` 全量否定白名单里没有它 | 实测 `git ls-files` = 171 项，含 LICENSE 与 package.json，**不含** package-lock.json；`package.json` 的依赖几乎全是 caret 范围（唯一例外 `js-confuser: "2.0.0"` 是精确版）；CI 每小时无锁 `npm install` 并 `overwrite: true` 发 Release |
| H-03 | `.gitignore` 有两条死规则：`!harden.config.example.json`（文件不存在）、`!NAT64Prefixes.md`（根目录无此文件，实际在 `docs/` 下已被 `!docs/**` 覆盖） | 实测工作区根目录清单 |
| H-04 | `harden.config.json` 的 `_note` 写「复制为 harden.config.json 后生效」，但被引用的 example 文件不存在 | `harden.config.json:2` |
| H-05 | `@babel/traverse` 被 `harden-source.mjs:38` 直接 import，却不在 `package.json` 也不在 `ensure-deps` 的 `REQUIRED_DEPS` —— 只因 `js-confuser` 传递依赖被提升到顶层才恰好能解析 | 换 pnpm / 关闭提升即 `ERR_MODULE_NOT_FOUND`，而 `ensure-deps` 会报「依赖齐全」 |
| H-06 | 体积预算余量极窄：raw 582,728 / 580k（余量 ≈1.8%），zip 269,844 / 264k（余量 ≈0.2%）；`build-params.mjs:11,126` 与 `obfuscate.mjs:9` 的注释却写 520k/236k（三处数字漂移） | 与 H-02 叠加 → 上游任意一个次版本发布都可能让构建卡在混淆搜索失败分支 |
| H-07 | 仓库残骸（**均未被 git 跟踪**，属工作区残留）：`_verify.js`（在 `"type":"module"` 包里用 `require`，跑起来必 `ReferenceError`，且会自删）、`test_b64.js`（半成品）、`wrangler.log`/`wrangler.err`（0 字节）、`node_ver.log`、`.build/`（2.0MB，含**未混淆明文** `worker.reference.js` 与 `last-build.json` 里的 `keyBase64`） | `.gitignore` 全量否定使其不会被提交，但 `git add -f` / 打包会一次性把混淆的意义清零 |
| H-08 | 文档缺口：全仓无 `wrangler.toml`/`wrangler.json`，docs 里也搜不到 `compatibility_date` | 本仓依赖 `connect()`/`request.fetcher.connect`，兼容日期决定了这些 API 是否存在；目前只能靠部署文档口头约定 |
| H-09 | `npm run verify`/`smoke` 之外没有 HTML 校验：`secrets/index.html:65` 与 `panel/index.html:1348` 各有一处重复 `class` 属性（第二个被解析器丢弃，将来只改第二个会静默失效）；`panel/index.html:221,227,634,653,706` 的 `<label for>` 指向 `<div>`（非 labelable） | 已逐行核对 |
| H-10 | 43 处 `(globalThis as any)` / `(env as any)` / `(request as any)` 强制转换，而 `global.d.ts` 已声明了 `settings`/`globalConfig`/`httpConfig`/`wsConfig`/`dict` | `env`、`ctx`、`request.cf` 三处未声明 → 4 个文件各写一遍 `as any`。补 3 行声明即可消除大部分强制转换 |

### 4.4 其他 P3

| ID | 内容 | 位置 | 影响 | 修复 |
|---|---|---|---|---|
| S-07 | `/dns-query/<subPath>` 是无鉴权敞开中继：只校验路径含 `subPath`（而该秘密随订阅 URL 分发给所有用户），随后转发**任意 method + 任意 body** 到 `DOH_URL`，不校验 content-type、不限体积、不限频率 | `handlers.ts:580-603`、`init.ts:102` | 任何拿到订阅 URL 的人都能把它当公共 DoH 转发器，消耗该 Worker 的请求配额与 CPU | 仅允许 POST + `application/dns-message`（或 GET + `dns=`），body ≤2KB，并纳入限流 |
| B-54 | `updateDataset` 静默丢弃 body 里的未知字段（`fields` 白名单派生校验集，`updatedSettings` 只由 `entries` 拼出） | `kv.ts:219-326,343-346` | 面板字段一旦改名，写入既不报错也不生效 —— B-35 里 `vlessConfigs`/`protocol` 即使改成 JSON 也会被**静默丢掉**。这是「闸门恒过」的第二个原因 | 对 `Object.keys(bodyObj)` 与 `bodyFields` 求差集，非空即 400。⚠️ **但必须先处理**：面板 PUT 的 body 来自 `Object.fromEntries(new FormData(configForm))`（`panel/script.js:1178`），其中 `#noises` 动态生成的 `udpXrayNoiseMode/Packet/DelayMin/DelayMax/Count` 五个 name（`script.js:1412,1431,1438,1448,1456`）**不在** `fields` 白名单里 —— 照字面实现会让「加过噪声块的用户」保存全线 400，必须先补齐白名单或让前端剔除这五个键 |
| B-55 | `issueSessionToken` 首访并发竞态：两个并发登录都读到 `secretKey === null`，各自生成并 `put`，后写覆盖先写 | `auth.ts:37-43` | 首访瞬间两客户端同时登录时，先签发的那张 Cookie 立即失效（与 B-34 同类） | 写入后读回校验；或用 KV「仅当不存在时写」语义 |

---

## 5. 冗余地图（结构性建议）

三端平行实现是本项目最大的维护成本来源。下面按「值得抽 / 不值得抽」分级，**不建议一次性重构**（会与体积预算冲突，见 H-06）。

### 5.1 高价值（既消除重复又消灭已发现的跨端缺陷）

| 概念 | 现状 | 建议抽象 | 顺带修掉 |
|---|---|---|---|
| 节点 TLS 上下文（host/isTLS/sni/allowInsecure/echName/alpn） | 3 份，sing-box 内联 | `@utils#resolveNodeTls(address, port, opts)` 返回判据对象 | B-43、B-42 的一半、B-50 的 path 归一 |
| Geo 资产目录 | 3 份（条目数与拼写已漂移） | `GEO_CATALOG` 一份 + 三个适配器 | B-44、`nsfw`/`category-porn` 命名漂移 |
| 链式 ed 解析 | 2 份逐字重复 | `chain-ed.ts`（显式 ed 只消费一次 + 无放回重抽） | B-50 |
| 竞速拨号 | 3 份同构、语义已分叉 | `raceDial({pool, concurrency, batches, timeout, onWinner})` | B-11、P-03 |
| 订阅主循环骨架 | 3 份 ~70 行 | `iterateSubscriptionNodes()` 高阶函数 | 让「三端应该等价」从约定变成结构 |

### 5.2 中价值（重复度高但收益仅限可读性）

`buildTLS` / `buildRealitySettings`（3 份，签名已几乎一致）、`buildWarpOutbound`（3 份，`172.16.0.2/32`/`mtu:1280`/`keepalive` 三处硬编码）、「最佳延迟」组（`generate_204` + 区间写 3 遍）、VLESS/Trojan 的 DNS 建连块（R-09）、ACL 两端组装（空组兜底/修饰符剥离三处各写一份）。

### 5.3 已做得很好、可作为模板的部分

`@utils` 层把**判据**而非**输出**抽出来（`isTlsPort`/`selectSniHost`/`pickEarlyData`/`pickRandomEch`/`antiSanctionDohTarget`/`portsForHost`）、`common.ts` 的 `crossRequestSingleFlight`/`evictOldest`/`createSessionWatchdog`/`createSignatureGate`、`configJsonResponse`/`htmlResponse`。**后续重构应沿用这个模式**（抽判据、留渲染），而不是抽「配置模板」。

---

## 6. 系统性根因：为什么全绿还会漏掉 21 条 P1

| 根因 | 具体表现 | 对应缺陷 |
|---|---|---|
| **闸门的请求形状与客户端不一致** | smoke 的 6 条订阅请求用了 `/sub/<subPath>`（缺 `normal\|raw\|fragment\|warp\|warp-pro` 段）→ 全部落到 `fallback`；`PUT /panel/update-settings` 又发 urlencoded + 不存在的字段名 → 恒 500，两次运行逐字节相同 → 比对恒过 | **G-01**（三端配置生成层零覆盖）、**B-35**（设置写入链路零覆盖）、B-54（未知字段被静默丢弃，使 B-35 即便改成 JSON 也无效） |
| **闸门的归一化会截断待比对内容** | `normalizeBody` 的 ` at ` 正则对单行正文删到结尾 | B-37 |
| **禁止词的判据与混淆侧不一致** | verify 用 `\b词\b`，词表大半是内部片段 → 数学上不可能命中 | B-36 |
| **没有 lint** | 装了 4 个 eslint devDependency（外加只服务 lint 的 `globals`）却无配置；`noUnusedLocals` 也只在本次审查临时开启才发现 2 处 | H-01、D-01 |
| **类型系统在核心输出层被 `as T` 绕过** | 三端 `buildOutbound<T>` 的 `T` 无约束 + `as T`；`xray.d.ts` 的 `TlsSettings` 甚至缺 `allowInsecure` | 本次 11 条跨端缺陷中至少 4 条无法被 `tsc` 拦住 |
| **单测只测「函数级不变量」，不测「配置可加载性」** | 14 个套件覆盖首包/批处理/令牌桶/限流数学，但没有任何用例把生成的 Clash/sing-box/xray 配置送进内核或做 schema 校验 | B-04、B-06、B-07、B-46、B-47、B-48 |
| **无锁文件 + 极窄体积预算** | 上游次版本即可让构建失败 | H-02、H-06 |

**一条最重要建议**：给三端配置加一个「结构断言」测试（纯 JSON schema 级，不需要跑内核）：对每种设置组合生成配置后断言 ① 所有 `proxy`/`outboundTag`/`selector` 引用的 tag 都存在于 outbounds 集合；② 所有分组 `proxies` 非空；③ tag 唯一；④ `alpn`/`ech`/`allowInsecure` 三端取值一致（同一组设置跑三端，diff 判据对象）。这一条能把 B-04/B-07/B-42/B-43/B-48 一次性钉死，且成本远低于跑内核。

**另一条容易被忽略的事实**：smoke 用的 `UUID` 是 `11111111-2222-4333-8444-555555555555`（全小写、纯数字），结构上不可能暴露 B-01；同理任何「只测正常路径」的用例集都不会发现「大写 UUID」这类输入域缺陷。建议在 fixtures 里固定加入一个**含大写的 UUID**。

**关于 `§0.1` 全绿的解释力**：`tsc` 只能证明类型自洽（且三端 `buildOutbound<T>` 的 `as T` 关掉了核心字段校验）；14 个测试套件证明的是若干函数级不变量；smoke/verify 证明的是「HTTP 层能跑通」。三者的并集**恰好不包含**「生成出来的配置是否可被内核接受」与「设置是否真的被写入」——这正是 21 条 P1 的分布特征。

---

## 7. 修复路线图

### 第 -1 批｜先做决策：体积预算（否则下面全部装不下）

当前 zip 产物 **269,844 B / 270,336 B（264 KiB）→ 只剩 492 B**，而 zip/raw ≈ 46.3%，意味着**真正的源码余量只有约 1.0 KB**（raw 的 1.9% 是错觉）。第 0+1 批合计 17 项不可能装进这个空间。

先二选一：
- **(a)** 上调 `harden.config.json` 的 `targetZipBytes`（如 280k），把余量恢复到 ~3%；
- **(b)** 维持现预算，则按「**≤300 B zip / 次**」的节奏分批过混淆闸门，每批都必须实测体积。

**前三大涨者**（按 (b) 执行时必须排在最前评估）：① `P-05` 的「qrcode 本地打包」约 **+4 KB zip**（是全部剩余预算的 8 倍，必须另案）；② `B-02 + B-09` 这类「补逻辑」各 +250~500 B zip，单条即吃掉一半余量；③ `R-01/R-04/R-07` 的抽象化短期 +1~2 KB raw（先增后减，须重构后重测）。

### 第 0 批｜一行级（真·风险≈0）

1. **B-01** `init.ts` 里 `userID: String(UUID).toLowerCase()`（附 B-01 里的三条约束注记）
2. **B-04** `xray/configs.ts:320,470` 的 tag 改为 `'proxy'`
3. **D-01** 删两处未使用变量
4. **B-56** 让归一化后的 path 回流 `globalConfig.pathName`（`/login/`、`/panel/settings/` 等二级路由当前全部落到伪装页）

### 第 0.5 批｜小改 + 断言（同样应尽早，因为它们决定后续修复能否被验证）

5. **G-01** 修 smoke 的订阅 URL 形状（5 条错形；**保留** `smoke.mjs:383` 那条负例），断言用「响应不得等于 fallback 特征」
6. **B-35 + B-54** 同时改：smoke 发 JSON 形状的正确字段 + `updateDataset` 对未知字段报错（**先处理 `udpXrayNoise*` 五个前端专用键**，见 B-54 修复栏）
7. **B-37** 修 `normalizeBody` 的 ` at ` 正则 —— **必须与第 5 项同批**，否则 G-01 一修好，raw 订阅体立刻被截断
8. **B-36** 片段型禁止词改子串匹配
9. **B-03** `build.js` 两处 `replaceAll` 改函数式替换 + `finalHtml` 断言 + 「脚本正文不含 `$&`/`$'`/`` $` ``」断言

### 第 1 批｜本迭代

10. **B-10** 字典小写归一 + 违规计数绑定「字典外且被限流」的因（⚠️ 不要按状态码判，见 B-10 修复栏）
11. **B-08 + S-01 + S-02** 缓存键补 `method` + `host`；写入只接受 2xx；噪声参数剔除改为保留不透明指纹
12. **B-12/B-13/B-15** 三条「资源收口」：握手 try/finally（含 inner socket 与释放顺序）、预算提到会话级（`budgetExceeded` 保持局部）、名额 try/finally。**B-13 不依赖 G-01**，不必等闸门
13. **B-02** WARP 失败路径改 stale 标记（含「仅当缺失时写」闸门 + 导出 `defaultWarpAccounts`）
14. **B-05 + B-07** sing-box `new URL` 兜底、ACL select 空组兜底
15. **S-04 + S-06 + B-31 + B-33** 日志降噪与凭据脱敏、`getMyIP` 输入校验、`resolveSubPath` 缓存 TTL
16. **P-01** `decompressHtml` 加模块级缓存（每个面板/登录请求的固定 CPU 开销）

### 第 2 批｜下个迭代（需要设计决策）

17. 三端一致性：先立「结构断言测试」（§6 末），再逐条修 **B-42~B-52**
18. ~~**B-11 + R-03** 竞速拨号统一~~ ✅ 已完成（`dialCandidate` 单一实现，见 §附二）
19. **B-06** sing-box 链式 bootstrap DNS
20. **B-14 + B-53** 去重键对代理条目分流；列表 URL 失败时「过期值也留作 fallback」
21. **B-16~B-24 + P-03** 数据面其余收口（DNS socket 重建、XHTTP UDP 分帧、地址段边界、BYOB 降级、定时器清理）
22. **B-25~B-34 + S-05** 伪装面与设置面其余项

### 第 3 批｜清理（低风险，可穿插）

23. **H-01** 加最小 eslint 配置（或删掉 4 个包 + `globals`）；**H-02** 提交 `package-lock.json` + CI 改 `npm ci`
24. **H-07** 删工作区残骸；`.build/` 加清理；**H-03/H-04** 修 `.gitignore` 死规则与 `_note`
25. **R-10/R-11/R-12** 抽公共 CSS、单一兜底域名常量、单一端口表
26. **D-02~D-09** 死代码清理；**H-10** 补 `env`/`ctx`/`cf` 三行声明消掉大半 `as any`

> **§7 覆盖度**：21 条 P1 全部入表（B-01~B-14 → 第 0/0.5/1 批；S-01~S-05 → 第 1/2 批；P-01 → 第 1 批；G-01 → 第 0.5 批）；P2 中 B-15~B-34 与 B-42~B-56 亦已排期。

---

## 8. 附录：取证与验证清单

### 8.1 本次实际执行的命令（只读，未修改任何源码）
| 动作 | 结果 |
|---|---|
| `tsc --noEmit` | exit 0 |
| `node tools/*.test.mjs` × 14 | 全 PASS |
| `tsc --noEmit --noUnusedLocals --noUnusedParameters` | 2 处（D-01） |
| `git status --short` / `git ls-files` | 工作区干净；跟踪 171 文件 |
| 读取 `dist/worker.js`（582,728B）、`worker.zip`（269,844B）尺寸与时间戳，比对 src 是否更新 | 产物与源码同步 |
| 读取 `.build/smoke/artifact.json` 中 `/secrets` 真实响应体 | **确认 B-03 污染存在** |
| 读取 `.build/smoke/artifact.json` 中 6 条 `/sub/*` 响应体与全文 token 统计 | **确认 G-01**：全部为 stub 页；`vless://`／`proxies`／`inbounds` 命中均为 **0** |
| grep 全仓 `for...in` / `eval` / `innerHTML` / `eslint.config` / `wrangler.toml` / `compatibility_date` | `for...in`／`eslint.config`／`wrangler.toml`／`compatibility_date` 均 0 命中；`innerHTML` 3 处均为注释（对应 R-13、H-01、H-08，前端 XSS 基线干净） |
| 比对 `xray/configs.ts` 的 outbound tag 与 `routing.ts` 的 tag 引用 | **确认 B-04** |
| 比对 `smoke.mjs` 请求体形状与 `kv.ts` 的 body 解析 | **确认 B-35** |
| 比对 `isPathInDictionary` 与 `isBuiltinRouteWord` 的大小写处理；检查字典是否含 `assets` | **确认 B-10 的两个前提** |
| 追踪 `initHttp` 的 `normalizedPath` 流向（是否回流 `globalConfig.pathName`）；比对 `smoke.mjs:346` 的「尾斜杠归一化」用例与服务端路由 | **确认 B-56**：归一结果只喂给凭据校验，未回流路由 → 该用例是假绿 |

### 8.2 明确排除的假阳性（避免下一轮重复排查）
- Xray `routing.ts` 的 `inboundTag: ["remote-dns"]` **不是**悬空 inbound，而是 Xray 用 DNS 服务器 tag 做 DNS 路由的既有机制（与 `dns.ts:144` 的 `tag:"dns"` 配套）。
- `vmess://<base64>` 用 `new URL().host` 取 base64 **不会**被小写化 —— 非特殊 scheme 的 host 解析保留大小写（`cores/utils.ts` 的相关写法安全）。
- XHTTP 只接受 POST **不是**缺陷：`XP_MODE` 固定 `stream-one`（`cores/xp.ts:10`），单 POST 全双工，与 `worker.ts` 的 POST 门禁自洽。
- 三端配置都用 `JSON.stringify` 序列化，**没有**手工拼串 → 不存在 `undefined`/`NaN`/尾逗号破坏 JSON 的问题；ACL 模板内容含换行也无法突破 JSON 结构。
- `Object.prototype.omitEmpty` 虽可枚举，但全仓无 `for...in`，当前无实际污染。
- 伪装页的 `maskPageTitle`/`buildImagePageHtml` 虽未转义，但入参经 WHATWG URL 解析，`<`/`>`/`"` 已被百分号编码，当前不可注入。
- `blacklist.ts` 内无正则、`camouflage.ts` 内正则为线性构造 → 这两个文件**未发现 ReDoS 面**。但 `acl-template.ts:352-355,373-376,386-389` 会对**模板提供的 pattern** 直接 `new RegExp(p).test(nodeName)`，模板 URL 面板可改、抓取侧无长度限制 —— 这是全仓唯一的「服务端编译外部正则」入口，语法错误有 try/catch，**灾难性回溯没有防线**（P3，未单列）。
- `src/common/common.ts` 的 `crossRequestSingleFlight`、`evictOldest`、`createSessionWatchdog`、`securityHeaders`/`copySafeOutboundHeaders`、`parseHostPort`、`ipv6ToBytes`、CF 网段计算、令牌桶数学、BYOB 三槽语义 —— 逐项核对无缺陷。

### 8.3 未能验证的部分（需人工/联网确认）
1. 未运行 Xray/sing-box/mihomo 内核，B-04/B-06/B-07/B-46/B-47/B-48 的**具体报错文案与失效形态**来自代码路径推断（缺陷本身已确认）。
2. 未联网拉取 `DEFAULT_ACL_TEMPLATE_URL`，无法确认该模板是否真含「纯正则 select 组」与 `,no-resolve` 内联行（影响 B-07/B-47 的触发概率）。
3. 未联网核实 `category-ads-ir` 是否在 sing-box/clash 规则集中有等价文件（影响 B-44 的修复选型）。
4. `cdn.skypack.dev` 当前是否仍在服务未核实（P-05 的处置建议不依赖该结论）。

---

> 配套清单：本报告里的 `R-*`/`D-*` 类冗余条目已归纳成可执行的自查清单，见 [refactor-checklist.md](./refactor-checklist.md)（四条判定 + 负向清单 + 本仓落点速查）。

## 9. 修订记录（第 1 轮评审后）

本报告在交付前经过两轮独立子代理评审。第 1 轮（对抗性事实核查，逐条回读源码 + 复算统计）提出 21 项必改，以下是已落实的修正 —— 保留此节是为了让读者知道**哪些结论被修正过、往哪个方向**。

### 9.1 事实性更正

| 原表述 | 更正 |
|---|---|
| 统计表「70 条，P1 16 / P2 25 / P3 29」 | 第 1 轮重算为 **99 条**：P1 21 / P2 43 / P3 35；第 2 轮又补入 B-56，最终 **100 条**（P1 21 / P2 44 / P3 35）。原表每一列都与正文不符（P2 栏还分配了正文里不存在的类别） |
| 「16 个测试套件」 | **14 个**（`tools/` 的 16 个文件里有 2 个是辅助模块） |
| 「前端 `innerHTML` 等 grep 0 命中」 | 3 处**注释**命中，无真实 sink；结论不变，取证陈述已改 |
| B-02「每条连接固定 +1s + 2 次 fetch」 | 被墙场景是「**2 次密钥生成 + 1 次无超时 fetch**」；那 1s sleep 只在「部分成功」时叠加。已按三种失败形态分档重写 |
| B-13「预算默认关闭」 | **默认开启 900MB**（`WS_SESSION_MAX_MB_DEFAULT`）→ 该缺陷对每个部署都成立，原表述把自己的 P1 影响说小了 |
| B-30「500 错误页」 | 是 **JSON 500**（`handlers.ts:257-267` 已接住），非 HTML 错误页 |
| B-14「`lastColon` 命中 scheme 后的冒号」 | 是**最后一处**冒号（落在 `user` 与 `pass` 之间）→ `host="socks5://user"`、`port="pass"`。结论（键坍缩、静默丢条目）不变，推导已改 |
| B-26「归一方向与注释相反」 | 代码与注释一致；真正缺陷是**判据选错了对象**。已补充「不要反向修改」的警告（会撞上测试钉住的防投毒红线） |
| H-01「5 个 eslint devDependency」 | 4 个 devDependency + `globals`（在 `dependencies`） |
| H-02「依赖全是 caret」 | 唯一例外 `js-confuser: "2.0.0"` |
| `common.ts` 一名指两个文件 | 已在 §0.3 定义简写约定（`common.ts` = 数据面那一个） |

### 9.2 结论方向的修正（3 处）

1. **新增 P1 `G-01`**：smoke 的 6 条订阅请求 URL 形状全错 → 三端配置生成层**一次都没被执行**。这比原报告的 B-35 更根本，已升为「只修 5 件事」第 4 项，并在 §6 根因表置顶。
2. **修正 B-02 的修复建议**：原建议「失败时把内置账号写进 KV」会把「每条连接重试」变成「永远不重试」——`normalizeWarpAccounts` 认为内置账号完全合法 → `getDataset` 的 `if (!warpAccounts)` 此后永不成立。已改为「只写 stale 标记」，并在原处加显式警示。
3. **修正 B-01 的修复建议**：原附带建议「比较改常量时间实现」是危险的 —— `parseVlHeader` 与 `tryParseVlHeader` 是同一判据的两份实现，只改一处会让探测路径与解析路径对同一首包给出不同裁决。已删除该建议并说明原因。

### 9.3 新增条目（第 1 轮补入）

> 下表只是**索引**，条目详情与计数均在 §2/§3/§4 中，不在此重复计数。

| ID | 级别 | 内容 |
|---|---|---|
| G-01 | P1 | 闸门订阅请求形状错误 → cores 层零覆盖（§2） |
| S-06 | P2 | `auth.ts:182` 把 `userID`（VLESS UUID）明文写进日志（§3.3） |
| B-53 | P2 | 列表 URL 抓取失败时静默丢弃该 URL 展开的全部节点（§3.3） |
| S-07 | P3 | `/dns-query/<subPath>` 是无鉴权敞开中继（不限 method/body/频率）（§4.4） |
| B-54 | P3 | `updateDataset` 静默丢弃 body 未知字段 —— 闸门恒过的第二个原因（§4.4） |
| B-55 | P3 | `issueSessionToken` 首访并发竞态（§4.4） |

### 9.4 补充限定（级别不变，但收窄了适用范围）

B-08（需 `xpConfigs=false`）、B-18（需先通过 UUID 比对）、B-21（后果是丢帧而非断连）、B-15（「本 isolate 内」而非「永不」）、B-07（mihomo 版本相关）、B-10（补上「一次被拒 ≥22 次」的算术与 7 天 TTL）、B-37（JSON 是多行不受影响；受影响的是 HTML 与 raw base64）、S-05（需有效 UUID 才能生效）。

---

*报告结束。行号基于 2026-11-17 的工作区快照；若源码已变更，请以 ID 检索而非行号定位。*

---

## 附：第 2 轮评审记录（一致性与可执行性）

第 2 轮独立清点了统计口径（结果为 P1 21 / P2 43 / P3 35 = 99，与当时报告一致），并核对了 6 条新增缺陷的机制与行号。它提出的修正已全部落实，并因此新增 1 条缺陷（B-56）：

| 第 2 轮指出的问题 | 处理 |
|---|---|
| §7 第 0 批第 2 项**仍在推荐已被 §9.2 否决的方案**（写内置账号进 KV）—— 照做会精确复现「永不重试」 | 已改为「只写 stale 标记 + 导出 `defaultWarpAccounts` + 仅当缺失时写」 |
| G-01 影响面写成「21 条 P1 里 11 条」，实际是 16 条（P1 5 + P2 11） | 已改；并区分「5 条错形 + 1 条故意负例」 |
| B-54 的差集校验会让面板保存全线 400（`udpXrayNoise*` 五键不在白名单） | 已在修复栏前置声明 |
| B-10 的「按非 2xx 计数」会让 `permanentBlacklist` 成死代码、同时放大误封 | 已改为绑定「字典外 + 被限流」的因，并注明现有测试发现不了 |
| B-53 的「失败时不覆盖」无法落地（失败路径 map 里没有旧值） | 已改为「过期值也留作 fallback」并纳入 `:471` 的同类丢弃 |
| B-13 未说明哪些变量必须保持局部 | 已补 `budgetExceeded` 必须留在 per-mount |
| B-01 修完后 `globalConfig.userID` 与 `env.UUID` 的大小写分叉是雷区 | 已补约束注记（`resolveSubPath` 必须继续读 `env.UUID`） |
| §0.1 把 P2 的 B-35 混进 P1 列表 | 已分开 |
| 严重度存疑（S-04 vs S-06、B-34 vs B-55、P-05 归类、B-02 是否该在 top-5） | 已在 §1 显式记录判断依据；top-5 扩为 6 项并重排（B-10 升入、B-02 降到第 6 位） |
| 体积预算没接进修复计划（zip 仅剩 492 B） | 新增「第 -1 批：先做预算决策」，并列出前三大涨者 |
| 尾斜杠归一化只喂给凭据校验、路由仍看原路径（`smoke.mjs:346` 假绿） | **新增 B-56（P2）** |

**第 2 轮补入条目**：`B-56`（P2，见 §3.3）。最终统计：**P1 21 / P2 44 / P3 35 = 100 条**。

**两轮评审的共同结论**：21 条 P1 的机制全部经独立复核成立，无一条被证伪；分歧集中在**统计口径、适用范围限定与修复建议的副作用**上，这些已在正文逐条标注。

---

## 附二：修复执行记录（2026-11-17，未提交 git）

按 §7 路线图施工的结果。**20/21 条 P1 已修**，P2 修了一半，P3 只做了与本次改动直接相关的两项（其余留待第 3 批）。

### 验证结论（全部在本地实跑）

| 关卡 | 命令 | 结果 |
|---|---|---|
| 类型 | `tsc --noEmit` | ✅ 0 error |
| 单元/行为 | `node tools/*.test.mjs` × 14 | ✅ 14/14（**且是对新构建的 `.build/worker.reference.js` 跑的**） |
| 构建 | `node scripts/build.js` | ✅ `worker.js 593,396 B` / `worker.zip 276,829 B`（目标 593,920 / 286,720）。**读法见下方说明：raw 尺寸是 `minConcealedLength` 的阶梯函数，不是源码体积的度量** |
| 静态闸门 | `scripts/verify.mjs`（构建内） | ✅ OK（1 条平台内置名豁免 WARN） |
| 行为闸门 | `scripts/smoke.mjs`（构建内） | ✅ 27 条请求与参考逐字节一致；**5 条订阅 + 设置写入首次真正被执行** |

> ⚠️ 一个容易踩的坑：`tools/*.test.mjs` 跑的是 `.build/worker.reference.js`（**构建产物**），不是 `src/`。
> 所以「改了源码 → 直接跑测试」得到的是**旧产物上的绿灯**。必须先 `node scripts/build.js` 再跑测试，
> 否则数据面改动的验证是无效的 —— 本次 B-18 就是被构建内闸门抓出来的。

### 已修（按 ID）

| 批次 | 完成项 |
|---|---|
| **-1** 体积预算 | **决策：上调 zip 目标到 280k**（264k 只剩 48 B，任何改动都会让混淆器抬高 `minConcealedLength`，静默降级混淆强度）；raw 维持 580k。当前余量：raw **902 B / 0.15%**、zip **10,014 B / 3.49%** —— 真实约束不是「构建失败」而是「强度被降级」，见下方「遗留风险」第 1 条 |
| **0** 一行级 | `B-01`（`userID` 小写归一）、`B-04`（clean-proxy 出站 tag → `proxy`）、`D-01`（两处未使用变量）、`B-56`（归一化路径回流 `globalConfig.pathName`） |
| **0.5** 闸门 | `G-01`（5 条订阅 URL 改真形状 + 保留负例）、`B-35`（PUT 改 JSON 正确字段 + 断言 200）、`B-54`（未知字段告警；改为告警而非 400，理由见正文）、`B-37`（` at ` 帧正则只认带位置形态）、`B-36`（禁止词双模式 + 平台名豁免）、`B-03`（函数式 `replaceAll` + 产物断言） |
| **1** | `B-02`（WARP 失败只写 stale 标记 + 导出内置账号 + 注册超时 8s + 面板如实报错）、`B-05`（`new URL` 兜底）、`B-07`（ACL 空分组唯一兜底）、`B-08`/`S-01`（缓存键补 method + host）、`S-02`（噪声参数绕过缓存）、`B-09`（POST 不再豁免黑名单/限流）、`B-10`（字典小写归一 + 违规只认「字典外且被限流」）、`B-12`（SOCKS5/CONNECT 握手 `fail()` 收口 + 总 deadline）、`B-13`（下行预算/令牌桶提升到会话级）、`B-15`（名额 try/catch）、`S-04`（日志去目标主机）、`S-06`（日志去 UUID）、`B-31`（`getMyIP` 入参校验）、`B-33`（subPath 缓存 TTL）、`P-01`（页面字节缓存） |
| **2** | `B-06`（链式出站改 `dns-direct`，断环）、`B-11`（竞速改 `Promise.any` + `batchWinnerClaimed`）、`B-14`（代理条目去重键分流）、`B-16`（DNS 上游 socket 可重建）、`B-17`（XHTTP UDP 按长度前缀重组）、`B-18`（VLESS 地址段边界）、`B-19`（`dialAndWrite` 收口）、`B-20`（Basic 凭据 UTF-8）、`B-21`/`B-22`（text 帧与迟到帧）、`B-23`（下行错误留痕）、`B-25`（缓存头快照 + 只缓存 2xx）、`B-26`（秒级时间戳只在静态资源上归一）、`B-28`（图片裸 503 补头 + Range 视图）、`B-29`（删 `is1101` 死分支并写进契约）、`B-30`（坏 JSON/坏 outProxy → 400）、`B-32`（favicon/WG ZIP 补安全头）、`B-34`/`B-55`（读回校验）、`B-53`（列表抓取失败沿用旧值）、`B-42`~`B-51`（三端一致性 10 条）、`S-03`（1101 页转义）、`S-07`（DoH 收口到 POST/GET 合规形态 + 2KB 上限）、`P-03`（`dialAndWrite` 定时器清理）、前端 `B-38`~`B-41` |
| **3** | `D-02`~`D-06`、`D-08`（死代码；`D-02` 改为具名常量，消除下标位移风险）、`H-01`（新增最小 `eslint.config.mjs` + `npm run lint`，覆盖 `scripts/**`）、`H-02`（`!package-lock.json` + CI 改 `npm ci`）、`H-03`/`H-04`（补 `harden.config.example.json`、删死规则）、`H-05`（显式 `@babel/traverse` + 进 `REQUIRED_DEPS`）、`H-06`（只改注释里的过期数字）、`H-07`（删工作区残骸）、`H-08`（新增 `wrangler.toml.example`）、`H-09`（重复 `class`、孤儿 `label for`）、`H-10`（补 `env`/`ctx` 全局声明）、`D-01`（并顺手在 `tsconfig.json` 开 `noUnusedLocals`/`noUnusedParameters`，让这一类永久可发现） |

### 因改动而**有意更新**的三条测试钉（务必审阅）

1. `tools/ws-firstpacket.test.mjs`：`截断 IPv6 首包` 原先钉「不报非法协议 → 走未捕获异常路径（1006 + pipeTo error）」。
   `B-18` 让它与 Trojan 侧对齐为**干净收口（1008）**，断言已改为「1008 一次 + 有 invalid 日志 + 不拨号」，并注明是有意改动。
2. `tools/camouflage-cpu.test.mjs`：`噪声 query：utm_* 不参与缓存键` 原先钉「命中同一份缓存」（0 次出站）。
   `S-02` 改成「**绕过缓存**」（既不读也不写）以消除投毒原语，断言已改为「本次额外出站 1 次 + 随后无 query 仍命中 + 内容未被污染」。
3. `tools/camouflage-cpu.test.mjs`：`当前时刻的 t= 被归一` 原先钉「接口路径上的秒级 t= 也被归一」。
   `B-26` 改成「接口路径保留、静态资源路径归一」，断言已拆成两条（新增一条静态资源路径的正向用例）。

### 第 5 轮补录（对账时发现 4 项曾丢失/漏做，已修复）

| 项 | 情况 | 处理 |
|---|---|---|
| `D-02` | 第 4 轮曾在 utils.ts 修过，但**被「恢复+重做」覆盖丢失**（我重做了行为类修复，漏了死代码类） | 已重做：`特征码字典[0]/[3]` → 具名常量 `特征码域名前缀` / `特征码根域`，删掉未使用的 `[1][2][4]`；`remarkCounter` 改 `Object.create(null)`（防 `#constructor` 备注污染） |
| `D-03` | 同上，丢失 | 已重做：删 `declare const connect` |
| `D-07` | 从未做（当时文件不在执行者可改范围，只报告） | 已做：删 `addBestPingConfigs` 从未读取的 `isFragment` 形参（含 1 处递归、1 处调用） |
| `D-09` | 从未做（只报告） | 已做：删零调用的 `clearBlacklistMemoryCache` |
| `H-10` | 声明做了，`(globalThis as any).env` 只清了 1 处 | 已清 utils.ts 的 `runtimeEnv`；其余 14 处仍在（见下） |

> 教训：任何「从 git HEAD 恢复文件」的操作，都必须把该文件**全部**历史改动列成清单逐条重做 ——
> 只按「行为类」重做会静默丢掉死代码清理类改动，而这类丢失不会被 `tsc` 或测试发现。
### 仍未做（明确记录，含理由）

第 4~6 轮已把上表**除下列 3 项外全部补齐**：`S-05`、`B-24`、`B-27`、`B-52`、`P-04`、`P-05`、`R-04/R-05a/R-06a/R-08/R-09/R-11/R-12/R-13` 均已落地。

| 项 | 状态 | 理由 |
|---|---|---|
| **`R-02`**（DNS 计划抽象） | 不做 | 三端 DNS 的**判据层已共享**（`accDnsRules`），剩下的是三种完全不同的渲染（Clash `hosts/nameserver-policy`、sing-box `servers/rules`、xray `hosts/servers/queryStrategy`）。抽成「计划 + 三适配器」**净增 +1~3 KB**，而 raw 余量只剩 902 B。§7 原文也写了「先增后减」。 |
| **`R-07`**（订阅主循环抽象） | 不做 | 收益最小、风险最大：三份循环的差异不只在 `usedPaths/usedEds`，更在**输出装配模型**（xray 一节点一 Config，clash/sing-box 追加数组）。抽高阶函数后三端仍要各写 ~30 行回调，实际只省十几行。而它踩的正是本轮返工两次的那个坑：`generateRemark` 全局递增 + `usedPaths` 消费顺序。净减仅 −0.2~−1 KB。 |
| **`R-01`**（Geo 目录） | 不做 | 唯一**可能**净减的一项（估 −0.5~−1.2 KB source），但三份清单的**数据本身不可合并**（`geosite:` 前缀 / `.srs` URL / `.txt` URL 三种形态），只能回收共享 URL 前缀。风险回报比差：−1 KB 换「三端订阅同时可能不可用」，而 B-44 刚证明这块很容易踩坏。 |
| **`R-05`**（`buildTransport` ×3） | **已完成（判据全收敛；渲染三份且应当如此）** | 已收敛 3 条判据：`normalizeTransportPath`（path 预处理）、`earlyDataHeaderName`（原 6 处三元式）、`resolveNodeTls`（R-04）。**不做**：把三份 `buildTransport` 合并成一个 —— 它们输出三种不同 schema（xray 嵌套 `wsSettings` / sing-box `type` 标签 / clash `network`+`-opts`），合并只会变成「plan + 三渲染器」，净增代码。剩余可见重复仅 `host?.split(",")` / `path.split(",")` 这类**字符级**变换，抽成 helper 反而更长，故保留。⚠️ 不要用 raw 尺寸衡量收益（它是 `minConcealedLength` 的阶梯函数，见遗留风险第 1 条）。 |
| **`R-06`**（`redrawChainEarlyData` ×2） | **已完成** | `resolveChainEarlyData(usedEds, explicitEd)` 收敛了「显式 ed 优先 + 只消费一次 + 无放回注册」这条判据；两端现在只保留各自 schema 的两行赋值（`max_early_data` / `max-early-data`）。前置判断（xray 的字段名、clash 的 `v2ray-http-upgrade` 判据）本就不同，保留在本地。 |
| **`R-03`**（竞速拨号三处合并） | **已完成** | 抽出 `dialCandidate(target, rawClientData, timeoutMs, fetcher, hooks)`：三条路径（反代池竞速 / 直连池竞速 / 单条拨号）现在共用**同一份**「拨号 → 等建立 → 写首包 → 失败回收」。这一步的价值不在行数，而在三条曾经各自出过真实缺陷的不变式终于只有一处实现：① `onSocket` 必须早于 `await opened`（写卡住时 teardown 才关得到）；② `opened` 超时/reject 必须就地关 socket（竞速败者不携带 socket 引用）；③ 写首包失败必须先 `releaseLock` 再关闭（否则锁死的 writable 会让上行泵再次 getWriter 抛错）；④ 定时器在 `finally` 清理（否则长连接下堆积悬空定时器）。\n⚠️ 合并时发现并补回一处**会静默消失的语义**：反代池原先只对「连上了但首包写不出去」的候选记黑名单，对「连不上」的不记；公共实现若不区分失败阶段，这条反馈回路会丢掉（池再也不会自动跳过写不出去的节点）。故 `dialCandidate` 给写阶段异常打 `dialPhase` 标记，池侧按阶段决定是否 `blacklistRecord`。 |
| **`H-10` 的 `as any` 清理** | 只做了类型声明 | `Env` 已补 6 个运行时可选键 + 索引签名，`globalThis.env` 现在可直读；仍剩 14 处 `(globalThis as any).env` 的替换（机械但面广，无风险也无收益，按需再做）。 |

### 第 6 轮补录（R-06 / R-10 / R-11 / R-12 / S-03 / S-07 收尾）

| 项 | 之前 | 现在 |
|---|---|---|
| `R-06` | `redrawChainEarlyData` 仍两份 | **已完成**：`@utils#resolveChainEarlyData` 收敛判据，两端只留 schema 赋值 |
| `R-10` | 伪装背景 CSS 仍 5 份 + 无宿主的 `hr` 规则 | **已完成**：新建 `src/assets/common/base.css`（唯一一份），`build.js` 在目录页拼在 `style.css` **之前**、error 页走占位符注入；`panel/style.css` 的 `hr` 规则已删（页面无该元素） |
| `R-11` | `handlers.ts` 另有 `'www.hcaptcha.com'` 字面量 | **已完成**：改引 `@init#DEFAULT_FALLBACK_DOMAIN` |
| `R-12` | 面板 `script.js` 自持端口表副本（注释称「注入做不到」） | **已完成（真正单一来源）**：新建 `src/common/ports.json`，`init.ts` import、`build.js` 构建期注入 `__DEFAULT_HTTP_PORTS__` / `__DEFAULT_HTTPS_PORTS__`。保序（端口顺序 = 订阅节点顺序） |
| `S-03` 键侧 | `CF-Connecting-IP` 原样当限流/黑名单键 | **已完成**：新建 `src/common/client-ip.ts`（`clientIp()` 校验 IPv4/IPv6，非法即视为无 IP），接线**全部 5 处**：`firstCheck`×2（黑名单/限流键）、`auth`×2（登录失败池）、`camouflage`（令牌桶每 IP 键）、`handlers`（地理查询）、`worker`（1101 页渲染）。全仓裸读该头只剩 `client-ip.ts` 内部 1 处 |
| `S-07` 频率 | `/dns-query` 无频率限制 | **已完成**：`ratelimit.ts` 增 `checkDohRateLimit` / `recordDohRequest`（60s 窗口、每 IP 120 次、`DOH_RATE_PER_MIN=0` 可关），`worker.ts` 的 `dns-query` 分支接入并回 429 |

> 两条踩坑记录（都属「注释/占位符与构建期守卫互相打架」）：
> ① `base.css` 注释里写了占位符字面量，注入后被「占位符不得残留」断言命中；
> ② 上一轮 `smoke.mjs` 注释里写了含 `*/` 的正则字面量，把块注释提前闭合导致语法错误。

### 遗留风险（下一轮开工前先看）

1. **体积读法（最容易误判的一条）：raw 尺寸不是源码体积，而是 `minConcealedLength` 的阶梯函数。**
   `obfuscate.mjs` 在目标内挑**最小**（即最保密）的 `minConcealedLength`，所以产物总是被顶到贴近上限。本轮实测台阶：`min=18 → 595,905`（超）、`min=19 → 594,734`（超）、**`min=20 → 593,396`（选中）**、`min=24 → 590,448`、`min=32 → 587,322`。
   由此三条推论，务必按此理解：
   - 源码改小 ~1KB 完全可能让产物**变大**（强度从 min=21 升到 min=20，本次就 +1,641 B）；
   - 「raw 余量 524 B」不等于「再写 524 B 就会失败」，而等于「当前强度已达上限，下一档 min=19 超 814 B」；
   - 真正要盯的指标是 **`minConcealedLength` 的取值**（`.build/last-build.json` 的 `config.minConcealedLength`）：它一旦变大，说明短字符串不再密文化 = 抗特征能力下降。
   要腾空间，按性价比依次是：① 清残留（≈ −200 B，零风险）；② `buildTransport` 的**判据**继续收敛（已做两处，见 R-05）；③ 才考虑 `R-01`。**不要再指望「合并三个渲染器」来省空间 —— 那是三种 schema，合并必然净增**。
2. **`tools/` 测试跑的是构建产物**（`.build/worker.reference.js`），不是 `src/`：「改源码 → 直接跑测试」得到的是**旧产物上的绿灯**，必须先 `node scripts/build.js`。本轮 B-18 与 B-26 都是这样被构建内闸门（而非单测）抓出来的。
3. `B-54` 目前只是**告警**（不 400，因为面板 body 里天然带 `outboundMode` / `udpXrayNoise*` / `newPassword` 三类前端专用键）。配套的离线契约测试（HTML 的 `name` 集合 vs `kv.ts` 白名单）尚未落，这是它从「静默丢弃」升级为「可发现」的关键一半。
4. `H-01` 的 eslint 只覆盖 `scripts/**`：核心 ESLint 的 espree 解析不了 TS（会逐文件 fatal），要覆盖 `src/**/*.ts` 得引入 `@typescript-eslint/parser`（新依赖 + 锁变更）。TS 侧的实际保障现在是 `tsc` + 已开启的 `noUnusedLocals`/`noUnusedParameters`。
5. 首次入库还需 `git add -f package-lock.json`（`.gitignore` 已放行但文件仍未被 tracked）；另有 4 个新文件未 tracked：`eslint.config.mjs`、`harden.config.example.json`、`wrangler.toml.example`、`tools/ws-upstream-leftover.test.mjs`。
6. **一次性漂移须知**：本轮把 sing-box 的 ECH 名抽取顺序对齐到「host 先抽」（与 xray/clash 一致）。分布不变，但同一份订阅的 SNI/ECH 配对会与旧版本不同 —— 已在 `utils.ts#resolveNodeTls` 注释里标明**这是有意的，不是 bug，不要改回去**。
