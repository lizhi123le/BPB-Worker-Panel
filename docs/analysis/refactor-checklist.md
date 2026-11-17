# 重构与去重自查清单

> 用途：改完代码（尤其是「修缺陷 + 顺手去重」这类多轮改动）之后，用本清单自查是否**新引入**了冗余。
> 来历：四条条目不是凭空列的，是同一个问题被追问四次、四次都问出真问题的实证归纳（见每条的「本仓实证」）。
> 用法：30 秒版＝直接跑 §1 的四条命令；要改共享层时先读 §3 的负向清单，避免把「看起来重复」当成「该合并」。
> 上下文：本清单来自 [code-review-2026-11-17.md](./code-review-2026-11-17.md) 里 `R-*` / `D-*` 类冗余条目的归纳。

---

## 1. 四条自查（按此顺序，每条都有可执行的检查动作）

### ① 判据是否只有一份？

**症状**：同一条业务判定（何时算加密、取哪个名字、写不写某个头、失败要不要记账）在多处各写一遍。
**判定问句**：改这条规则时，另外几处是否**必须**同时改？是 → 它是判据，必须单源；否 → 它是各端专有的渲染，允许保留。

```powershell
# 找出同名或近义函数的第二份定义（把 <名字> 换成你要查的判据）
Get-ChildItem src -Recurse -Include *.ts | Select-String -Pattern 'function (resolve|select|pick|is|build)Tls|normalizePath'
```

**本仓实证**：`resolveNodeTls` / `normalizeTransportPath` / `earlyDataHeaderName` / `getChainExplicitEarlyData` 四类判据原本各有 2~6 份副本，收敛到 `src/cores/utils.ts` 后，三端配置的 TLS/路径/早期数据判定才真正同源。
**修法**：抽到**判据层**（本仓是 `src/cores/utils.ts`），渲染留在各端。

---

### ② 是否复制了模板而没有复用？

**症状**：新功能照抄了一段既有实现（滑动窗口、令牌桶、重试循环、拨号收口），只改了变量名或常量。
**判定问句**：这段代码里的**不变式**有几条？复制之后是否每一条都还在？

```powershell
# 找结构相同的池/桶/窗口实现（按本仓的命名习惯）
Get-ChildItem src -Recurse -Include *.ts | Select-String -Pattern 'new Map<string, number\[\]>|\.filter\(t => t > windowStart\)'
```

**本仓实证**：加 DoH 限流时照抄了登录失败池的 20 行，于是出现第三个滑动窗口池。那 20 行里有三条彼此独立的不变式——**空即删**（否则空记录永久占一个条目）、**插入前封顶**（`evictOldest(pool, max-1)`）、**空键放行**（无法识别的 IP 不记账）。历史上前两条都各自出过缺陷，复制第三遍必然漏。
**修法**：抽 `windowAllow()` / `windowRecord()`；结构确实不同源的（如带跨边缘协调字段的那个池）保留独立并**写明理由**。

---

### ③ 同一概念是否导出了两个符号？

**症状**：`export const X` 与 `export function getX()` 并存，而常量只有一个消费点。
**判定问句**：两个符号各自的消费点有多少？只有一个消费点时，后来者会以为存在两套判断入口。

```powershell
# 新增导出后的消费点计数（把 <名字> 换成实际符号）
Get-ChildItem src -Recurse -Include *.ts | Select-String -Pattern '\bEARLY_DATA_HEADER_NAME\b'
```

**本仓实证**：早期数据头名一开始同时导出常量与访问函数，常量仅 1 个消费点。收敛为「常量模块私有 + 只导出函数」，并让那唯一一处调用点传「已确定的值」，使「值」与「是否写该头」变成同一个判断。
**修法**：保留单一公开形态；需要原值的极端场景仍走同一个函数。

---

### ④ 改动是否只覆盖了一半消费点？

**症状**：某判据有多个消费点，只改了其中几个。（**这是四条里最危险的一条**：漏掉的部分编译器与测试都发现不了。）
**判定问句**：改的方向要按「**谁读了这个原始值**」查，而不是按「我改了哪里」查。

```powershell
# 以「客户端 IP」为例：查全部直接读取点（应只剩取用模块内部一处）
Get-ChildItem src -Recurse -Include *.ts | Select-String -Pattern "headers\.get\('CF-Connecting-IP'\)"
```

**本仓实证**：客户端地址校验首次只改了鉴权与限流两处，复查发现伪装面令牌桶、地理查询、错误页渲染三处仍读裸头；全仓最终只剩取用模块内部一处。
**修法**：建单一取用点（本仓 `src/common/client-ip.ts`），把所有消费点逐一替换，并用上面的命令确认收敛。

---

## 2. 命令速查（改完必跑）

```powershell
node node_modules/typescript/bin/tsc --noEmit                                   # 类型
node node_modules/typescript/bin/tsc --noEmit --noUnusedLocals --noUnusedParameters  # 死代码（tsconfig 已开，可省）
node scripts/build.js                                                          # 构建 + 静态闸门 + 行为闸门
Get-ChildItem tools\*.test.mjs | ForEach-Object { node $_.FullName }            # 15 个套件
```

**顺序很重要**：`tools/*.test.mjs` 跑的是**构建产物**（`.build/worker.reference.js`），不是 `src/`。
「改完源码 → 直接跑测试就全绿」是**旧产物上的绿灯**，必须先构建再测试。本仓两次数据面缺陷（首包地址段越界、时间戳缓存键）都是靠构建内闸门而不是单测抓出来的。

---

## 3. 负向清单：三件「看着像去重、其实不该做」的事

### ① 不要合并「输出结构不同」的实现

本仓三份 `buildTransport` 输出三种不同 schema（Xray 嵌套 `wsSettings` / sing-box `type` 标签 / Clash `network` + `-opts`）。合并只能得到「描述符对象 + 三个渲染器」——判据没少，还多了构造与遍历，**净增代码**。

判断方法就是 §1① 的问句：改字段名时另外两端要不要改？不要 → 属渲染，保留。

### ② 不要为「没有第二个消费方」的抽象付出成本

抽公共表/计划对象之前，先确认它有 ≥2 个真实使用方。本仓的 DNS 计划抽象（三种渲染 + 一份计划）估算**净增 1~3 KB**，而当时产物余量只有几百字节。

### ③ 不要抽「输出」而要抽「判据」

同一概念有两层：**判定**（算不算 TLS、取哪个名字、失败要不要记账）与**渲染**（字段怎么摆）。抽判定 → 单一来源且更短；抽渲染 → 描述符加遍历，更长更绕。

---

## 4. 施工顺序（要动共享层时）

1. **先立判据**：把逐字相同的表达式抽到判据层，跑一次门禁确认三端输出未变。
2. **再收敛表/常量**：端口表、兜底域名这类「同一事实多处字面量」，抽到唯一来源（本仓做法：服务端直接 `import`，静态页面由构建期注入占位符）。
3. **最后才碰渲染**：且只在「同一端内部」重构，不跨端合并。

每一步都要单独过门禁——三步一起改，出问题时无法判断是哪一步破坏的输出。

---

## 5. 注释与占位符的三条禁忌

这四条在本仓都真实踩过，且都是「构建期守卫与注释互相打架」：

1. **被注入进产物的文本，不得包含构建守卫正在搜索的占位符字面量**（本仓 `base.css` 注释里写了占位符原文 → 注入后残留断言必然命中）。
2. **注释里不要写含块注释终止符的正则字面量**（本仓测试脚本注释里的正则把块注释提前闭合，整文件语法错误）。
3. **同一事实的具体数值不要在多处注释里重复陈述**（本仓曾把限流/突发/并发三个数写在 15 处注释里，改默认值时必然漏改）。
4. **同一不变式的解释只写在该不变式的唯一实现处**，调用点用一行指过去即可（本仓曾把「`onSocket` 必须早于 `await opened`」在 4 处各写一遍）。

---

## 6. 体积读法（本仓特有，容易误判）

`raw` 产物大小是混淆器 `minConcealedLength` 的**阶梯函数**，不是源码体积的度量：

- 构建在目标内挑**最小**的 `minConcealedLength`（＝最保密），所以产物总被顶到贴近上限；
- 因此「源码改小 1 KB」完全可能让产物**变大**（强度升一档，更多短字符串进入密文化）；
- 要判断改动是否真的瘦身，看 `.build/last-build.json` 的 `config.minConcealedLength`：它变大＝强度被降级（＝短字符串不再密文化），这才是要警惕的方向。

实测台阶（本项目）：`min=18 → 595,905`（超）、`19 → 594,734`（超）、`20 → 593,396`、`21 → 592,297`、`24 → 590,448`、`32 → 587,322`。

---

## 7. 本仓落点速查

| 概念 | 唯一实现位置 |
|---|---|
| 节点 TLS 判据（host/sni/isTLS/allowInsecure/ECH名/alpn） | `src/cores/utils.ts#resolveNodeTls` |
| 传输层 path 预处理 | `src/cores/utils.ts#normalizeTransportPath` |
| 早期数据头名判定 | `src/cores/utils.ts#earlyDataHeaderName` |
| 链式出站显式早期数据取值 | `src/cores/utils.ts#resolveChainEarlyData` + `#getChainExplicitEarlyData` |
| 代理条目节点追加与节点名唯一化 | `src/cores/utils.ts#appendCleanProxyNodes` / `#uniqueNodeName` |
| XHTTP 节点枚举（三端第二趟遍历） | `src/cores/utils.ts#enumerateXpNodes` |
| 单候选「拨号+等建立+写首包+失败回收」 | `src/protocols/websocket/common.ts#dialCandidate` |
| 「每键时间戳窗口」限流（登录失败 / DoH） | `src/common/ratelimit.ts#windowAllow` / `#windowRecord` |
| 客户端地址取用（含形态校验） | `src/common/client-ip.ts#clientIp` |
| 端口表 | `src/common/ports.json`（服务端 import，面板构建期注入） |
| 兜底/伪装域名默认值 | `src/common/init.ts#DEFAULT_FALLBACK_DOMAIN` |
| 伪装背景样式 | `src/assets/common/base.css`（构建期注入各页） |

**允许的「看起来重复」**（不要合并）：

- 三份 `buildTransport` 渲染（三种 schema）；
- 三份 `configs.ts` 的订阅装配骨架（输出模型不同：Xray 一节点一 Config，另两端追加数组）；
- `rateLimitPool` 与另两个窗口池（它带跨边缘协调字段）；
- 各页 `style.css` 里页面专有的样式的覆盖规则。

---

## 附：这份清单自身的来历

同一次工作里被追问四次「有没有产生冗余」，四次都有实证：

| 追问 | 查出的问题 | 对应条目 |
|---|---|---|
| 第 1 次 | 注释里把新默认值重复写在 15 处 | §5-3 |
| 第 2 次 | 同一概念导出常量 + 函数，常量只 1 个消费点 | §1③ |
| 第 3 次 | 客户端地址校验只改了 1/4 消费点；首次引入第三个滑动窗口池 | §1④、§1② |
| 第 4 次 | 为区分失败阶段加了 3 个符号（过度设计）；同一不变式注释重复 4 处 | §1②（反向）、§5-4 |

**共同点**：每次都是**新代码复制了既有形态而没有复用判据**——而这类问题编译器、测试、构建闸门都发现不了，只能靠按清单主动查。
