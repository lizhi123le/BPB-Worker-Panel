# 混淆流水线（BPB-Worker-Panel）

参考实现：`C:\Users\lizhi\Desktop\MOD-Worker-Panel` 的 `obfuscate.mjs` + `tools/cipher.mjs`。
本文记录移植后的形态、每个开关的取舍，以及移植过程中实测到的坑。

## 1. 流水线

```
src/*.ts
  └─ esbuild 打包（ESM，单文件）          scripts/build.js
  └─ terser 压缩（**mangle: false**）     scripts/build.js
  └─ JSZip 运行时前缀
  ├─ .build/worker.reference.js           ← 混淆前基准（verify/smoke 都拿它当对照）
  └─ js-confuser + ChaCha20 字符串密文    scripts/obfuscate.mjs
       └─ 追加"只解密"的运行时（不参与混淆）
  ├─ verify.mjs   静态闸门
  ├─ smoke.mjs    行为闸门（本产物 vs 参考，逐字节比对）
  └─ dist/worker.js + dist/worker.zip
```

中间产物刻意放在 `dist/` **之外**（`.build/`）：`dist/` 是会被整体部署/上传的目录，
把未混淆的 `worker.reference.js` 留在里面等于把明文包一起发出去。

`npm run build` 会跑完整条链；每个产物用**全新的随机 ChaCha20 密钥**，任一闸门不过就换密钥重试
（`HARDEN_ATTEMPTS`，默认 3 次），连续失败则整体退出 1 并且不产出可部署的 zip。

单独跑：

```bash
npm run test:cipher   # ChaCha20 已知答案向量 + 编解码往返 + 发布解码器纯度
npm run obfuscate     # 只重跑混淆（读 .build/worker.reference.js）
npm run verify        # 静态闸门
npm run smoke         # 行为闸门
npm run smoke:bench   # 行为闸门 + 冷启动/热请求耗时对照
```

## 2. 字符串密文为什么这么写

* js-confuser 的 `stringConcealing` 解码器必须**同步**（它被放在表达式位置调用）→ 用不了
  WebCrypto 的 AES-GCM，改用 ChaCha20（RFC 8439，`tools/cipher.mjs`）。
* 每条字符串独立 8 字节随机 nonce，前缀在密文之前 → 无密钥流复用，同一明文两次密文不同。
* 密文以 base64 承载 → 生成的 JS 字面量保持可打印（裸字节会被转义成 `\xNN`，体积翻倍）。
* 解码器**追加在 js-confuser 之后**，不参与混淆：js-confuser 连属性名一起隐藏，
  解码器若活在被混淆的 AST 里，就得先解码自己才能解码任何东西（自举死锁）。
  追加的函数声明会被提升，混淆后的代码以"未绑定的标识符"引用它，因此不会被改名。
* 解码器源码**不含非空字符串字面量**（`tools/cipher.test.mjs` 会守着这条）。

## 3. 闸门

| 闸门 | 抓什么 |
| --- | --- |
| `tools/cipher.test.mjs` | 密码内核是否被改坏（RFC 8439 向量）、发布解码器是否与构建期编码器漂移 |
| `scripts/verify.mjs` | 产物解析/`export default`、每条载荷能否解出、与参考的字符串覆盖（不丢数据）、禁止词是否落明文、`\xNN` 伪装是否还原后仍泄露、产物内解码器独立求值、自遮蔽初始化器 |
| `scripts/smoke.mjs` | 27 条真实请求在两份 bundle 上的响应是否逐字节一致（登录/面板/订阅/DoH/伪装反代/畸形路径/WS 升级），外加关键页面内容断言 |

`smoke.mjs` 把两份 bundle 放在**独立进程**里跑（workerd 里每个 isolate 都是干净的；
同一个进程里跑会共享 `globalThis.settings` 等全局，制造大量假差异），并冻结
`Math.random` / `Date`（整个构造器，不只是 `Date.now`）/ `crypto.getRandomValues` / 出站网络。

响应体比对时只归一化两类"只反映构建差异"的噪音：堆栈帧，以及 V8 报错文本里内嵌的**标识符名**
（`data is not iterable` → `Dz11iE is not iterable`）。消息语义本身原样比较。

## 4. 实测数据（本仓库 5.1.1，GET /login）

| | 旧流水线（javascript-obfuscator） | 新流水线（js-confuser + ChaCha20） |
| --- | --- | --- |
| `worker.js` | 1,235,257 B | 791,613 B（−36%） |
| `worker.zip` | 186,572 B | 430,394 B（+130%） |
| 字符串 | **可 10 行脚本还原**（见下） | 约 13,500 条 ChaCha20 密文 |
| 冷启动（GET /login） | — | 约 1 ms，与参考同量级（多次采样 0.8–1.3 ms） |
| 热请求（GET /login） | — | 0.53 ms（参考 0.72 ms，300 次均值；两者差在采样噪声内） |

zip 变大是正常的：密文不可压缩，而旧产物里的字符串基本是明文、可压。两者都远低于 Workers 的体积上限。

### 旧流水线为什么不算混淆

`javascript-obfuscator` 在本仓库的配置（`splitStrings:1` + `unicodeEscapeSequence` + `stringArray:base64`）
只是把字符串拆成单字符 `\xNN` 再拼回去，**没有密钥**。实测：

```js
// 从 dist/worker.js 里按 '\xNN' 分片重组，直接拿到 gzip+base64 的页面 blob
zlib.gunzipSync(Buffer.from(joined, 'base64'))   // -> 完整 error / panel 页面 HTML
```

`grep vless` 之所以为 0，只是因为 `vless` 被写成了 `\x76\x6c\x65\x73\x73`。
`verify.mjs` 现在会先把 `\xNN` 还原再查禁止词，所以这类"伪隐藏"会被当场拒绝。

## 5. 开关取舍

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `HARDEN_STRINGS` | `true` | `false` → 只藏 `sensitive_words_auto.txt` 命中的字符串 |
| `HARDEN_MAX_STRING` | `0` | 超过该长度不藏（本仓库最大字面量 26KB，是 gzip+base64 页面块） |
| `HARDEN_MIN_STRING` | `0` | 短于该长度不藏。谓词对属性名同样生效，调大能明显压缩载荷表 |
| `HARDEN_OPAQUE` | `0.1` | 不透明谓词概率 |
| `HARDEN_CFF` | `0` | **必须为 0**：控制流平坦化会生成 `with`，ES 模块里是语法错误 |
| `HARDEN_INTEGRITY` | `false` | js-confuser 2.0 的 Lock 会随机生成自遮蔽包装器（`verify` 会拒），且 `tamperProtection` 需要非严格模式 |
| `HARDEN_ANTIDEBUG` / `HARDEN_SELFDEFENDING` | `false` | 对 Workers 无意义，只增加 CPU |
| `HARDEN_MINIFY` | `false` | terser 已压缩；js-confuser 的 minify 与页面字符串里的 CSS 冲突 |
| `HARDEN_IDENTIFIER_GENERATOR` | `mangled` | 紧凑；`randomized` 约 +19% 体积 |
| `HARDEN_RENAME_*` / `HARDEN_MOVED_DECLARATIONS` / `HARDEN_OBJECT_EXTRACTION` / `HARDEN_AST_SCRAMBLER` | `true` | 逐个可关，用于定位问题 |
| `HARDEN_ATTEMPTS` | `3` | 闸门失败后换密钥重试的次数 |
| `SMOKE_EVERY` | `1` | 设 `0` → 只跑静态闸门，不跑行为闸门（调参时用） |

## 6. 坑：terser 的短名复用会让 js-confuser 改名错位

js-confuser 2.0 的 `renameVariables` 按**名字**解析作用域绑定。terser 恰恰最喜欢在嵌套作用域
复用短名：

```js
// terser 之后（worker.reference.js）—— 形参和 catch 参数都叫 e
async function Kt(e){ ... (async()=>{ await e.kv.get("proxySettings_ver") })() ...
                      catch(e){ if(!t.settings) throw e } }

// js-confuser 之后 —— 形参变 a，闭包里的 e.kv 被改到了 catch 参数的绑定上
function eI(a){ ... h["kv"].get(...) ... catch(h){...} }
```

后果：`env.kv` 变成别的对象的属性，所有 KV 读取 500（`/panel/settings`、`/panel/region` 全挂）。
这是 `smoke.mjs` 第一次跑就抓到的真实缺陷。

**解法**：`scripts/build.js` 在混淆阶段给 terser 传 `mangle: false`，让 js-confuser 面对
未短名化的标识符。换 `identifierGenerator` 并不解决问题（`randomized` 一样命中）。

## 7. 已知的 harness 局限

* `/proxy-ip/get` 在 smoke 里两边都会走错误页（stub 的 ip-api 批量响应形状导致的
  `data is not iterable`）——这属于桩的限制，不是产物差异；两边一致即通过。
* WebSocket 升级只走到"解析 early-data → 拨号"这一层：Node 里没有 `connect()`，
  桩会同步抛错，深层的代理转发逻辑没有被行为闸门覆盖（仍受静态覆盖检查保护）。
