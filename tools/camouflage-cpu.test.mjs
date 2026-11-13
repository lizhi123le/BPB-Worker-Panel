/**
 * tools/camouflage-cpu.test.mjs
 *
 * `GET /` 伪装反代的 CPU 防护行为测试。运行：node tools/camouflage-cpu.test.mjs
 * （package.json 里是 `npm run test:camouflage`）
 *
 * 被测规则（src/common/camouflage.ts）：
 *   1. 小页面（content-length 已知且 <1MB）→ 缓冲改写，上游 host 被换成面板 host，且结果进缓存；
 *   2. 上游**不报长度**（chunked）→ 不再把「未知大小」当成「小」，改走流式改写，
 *      但内容量在预算内时同样把 host 换掉（伪装效果不退化）；
 *   3. 体积超过改写预算 → 立即停止改写，余下原样流出，且**不缓存**这份半改写的产物；
 *   4. 根路径突发超过额度 → 熔断为内建页（0 次出站 fetch）；
 *   5. 缓存键剥离 utm_* 等噪声参数 → 两个只有噪声参数不同的请求命中同一份缓存。
 *
 * 为什么需要它：这四条都靠「体积」和「次数」这类边界触发，手测很难稳定复现；
 * 而回归的方向又极其具体 —— 退化成「全部缓冲」就是 CPU 超限复发，
 * 退化成「全部不缓存」就是伪装效果悄悄消失。期望值在这里显式写死，不照抄实现常量。
 *
 * 打桩：globalThis.fetch 只服务伪装上游，记录每次出站 URL 与调用次数。
 *
 * 前提：先构建过（`npm run build`，或快速版 `NODE_ENV=mangle node scripts/build.js`），
 * 本测试加载 .build/worker.reference.js（混淆前产物，行为等价且可读）。
 */
import { existsSync } from 'fs';
import { pathToFileURL } from 'url';

const BUNDLE = '.build/worker.reference.js';
const UUID = '11111111-2222-4333-8444-555555555555';
const TR_PASS = 'trojan-secret';
const PWD = 'Admin-pass-1';
const ORIGIN = 'https://panel.example.com';
const UPSTREAM_HOST = 'upstream.example.net';

let failures = 0;
const out = (...args) => process.stdout.write(args.join(' ') + '\n');
const check = (name, ok, detail = '') => {
    out(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
    if (!ok) failures++;
};

if (!existsSync(BUNDLE)) {
    console.error(`找不到 ${BUNDLE} —— 请先构建：npm run build`);
    process.exit(1);
}

/**
 * 上游桩。`plan` 由各用例设置：
 *   mode: 'known'（带 content-length）| 'chunked'（不报长度）
 *   body: 要返回的字符串
 *   extra: 额外响应头（用于验证「正文被改写后 framing 头必须被剥掉」）
 */
let plan = { mode: 'known', body: 'hello', extra: {} };
let fetchCount = 0;

globalThis.fetch = async (url) => {
    const u = String(url);
    fetchCount++;
    if (!u.includes(UPSTREAM_HOST)) {
        return new Response('{}', { headers: { 'content-type': 'application/json' } });
    }
    const headers = { 'content-type': 'text/html; charset=utf-8', ...plan.extra };
    if (plan.mode === 'known') headers['content-length'] = String(Buffer.byteLength(plan.body));
    // 分块吐字，确保 TransformStream 会看到多个 chunk（更接近真实的 chunked 上游）
    const stream = new ReadableStream({
        start(controller) {
            const enc = new TextEncoder();
            const bytes = enc.encode(plan.body);
            const step = 4096;
            for (let i = 0; i < bytes.length; i += step) {
                controller.enqueue(bytes.subarray(i, i + step));
            }
            controller.close();
        }
    });
    return new Response(stream, { headers });
};

const store = new Map([['pwd', PWD]]);
/** 记录每一次 kv.get 的键：用来守护「根路径不得产生 KV 读取」这条性能不变量 */
const kvReads = [];
const kv = {
    async get(key, opts) {
        kvReads.push(key);
        const value = store.has(key) ? store.get(key) : null;
        if (value === null) return null;
        if (opts && opts.type === 'json') return typeof value === 'string' ? JSON.parse(value) : value;
        return value;
    },
    async put(key, value) { store.set(key, value); },
    async delete(key) { store.delete(key); },
    async list() { return { keys: [], list_complete: true, cursor: '' }; }
};
const env = { UUID, TR_PASS, SUB_PATH: 'p', FALLBACK: UPSTREAM_HOST, kv };
const ctx = { waitUntil() {}, passThroughOnException() {} };

const handler = (await import(pathToFileURL(BUNDLE).href)).default;
if (!handler || typeof handler.fetch !== 'function') throw new Error(`${BUNDLE} 没有 default.fetch()`);

const get = (path, ip = '203.0.113.9') => handler.fetch(new Request(ORIGIN + path, {
    headers: { Host: 'panel.example.com', 'CF-Connecting-IP': ip }
}), env, ctx);

// ---------- 0. 黑名单只覆盖非内置路径；根路径不得承担黑名单刷新成本 ----------
// 回归点（两次都是它）：
//  1) worker.ts 对 `/` 直接进 camouflageProxy，被拉黑的 IP 仍能拿到首页 —— 曾补上检查；
//  2) 但该检查的刷新成本是 O(黑名单规模)：loadPermanentBlacklist 每 60s 过期，过期后由
//     「第一个到达的请求」承担 KV 读 + JSON.parse(整个名单) + new Set(全部条目)。
//     `/` 承担几乎所有流量，于是每个 isolate 每 60s 就有一次请求额外烧 4~25ms
//     （实测 2 万条 ≈4.3ms、5 万条 ≈13.7ms、10 万条 ≈25ms），在 10ms 预算下
//     表现为「CPU 超限规律性复发」。现已撤回根路径的检查，并用下面的不变量守住。
const BANNED_IP = '198.51.100.7';
// 必须在任何请求之前播种：黑名单有 60s 内存缓存，首次请求会把空集合缓存住
store.set('permanentBlacklist', JSON.stringify([BANNED_IP]));

const bannedDict = await get('/about?banned=1', BANNED_IP);
await bannedDict.text();
check('黑名单：被拉黑 IP 访问非内置路径被拦截（429）', bannedDict.status === 429, `status=${bannedDict.status}`);

// 根路径：必须 0 次 KV 读取，且不因黑名单而阻塞
const kvBeforeRoot = kvReads.length;
const rootBannedResp = await get('/?blacklist-probe=1', BANNED_IP);
await rootBannedResp.text();
const rootKvReads = kvReads.length - kvBeforeRoot;
check('根路径：不产生任何 KV 读取（不承担黑名单刷新成本）', rootKvReads === 0,
    `新增 KV 读取 ${rootKvReads} 次：${kvReads.slice(kvBeforeRoot).join(', ') || '无'}`);
check('根路径：不因黑名单而阻塞（保持 15:04 已知良好行为）', rootBannedResp.status === 200, `status=${rootBannedResp.status}`);

// ---------- 1. 小页面：缓冲改写 + 缓存 ----------
plan = { mode: 'known', body: '<html><a href="https://upstream.example.net/x">link</a></html>' };
const beforeSmall = fetchCount;
let resp = await get('/');
let text = await resp.text();
check('小页面：上游 host 被改写为面板 host', text.includes('panel.example.com') && !text.includes('upstream.example.net'), text.slice(0, 120));
check('小页面：确实发起了 1 次出站 fetch', fetchCount === beforeSmall + 1, `before=${beforeSmall} now=${fetchCount}`);
check('小页面：响应保持 200', resp.status === 200, `status=${resp.status}`);

// ---------- 2. 缓存命中：第二次不再出站 ----------
const before = fetchCount;
resp = await get('/');
text = await resp.text();
check('缓存命中：第二次请求 0 次出站 fetch', fetchCount === before, `before=${before} now=${fetchCount}`);
check('缓存命中：返回的仍是改写后的内容', text.includes('panel.example.com'));

// ---------- 3. 噪声 query 归一化：只有 utm_* 不同 → 命中同一份缓存 ----------
const beforeUtm = fetchCount;
resp = await get('/?utm_source=newsletter&utm_medium=email');
text = await resp.text();
check('噪声 query：utm_* 不参与缓存键，未额外出站', fetchCount === beforeUtm, `before=${beforeUtm} now=${fetchCount}`);
check('噪声 query：仍返回改写后的缓存内容', text.includes('panel.example.com'));

// 反过来验证「非噪声参数确实区分缓存」
const beforeReal = fetchCount;
await (await get('/?page=2')).text();
check('非噪声 query：产生独立缓存条目（额外出站 1 次）', fetchCount === beforeReal + 1, `before=${beforeReal} now=${fetchCount}`);

// ---------- 4. chunked（不报长度）、体积在预算内：流式改写仍然替换 host ----------
plan = { mode: 'chunked', body: '<html><link href="https://upstream.example.net/a.css"></html>' };
resp = await get('/chunked-small');
text = await resp.text();
check('chunked 小页面：流式改写后 host 已替换', text.includes('panel.example.com') && !text.includes('upstream.example.net'), text.slice(0, 120));

// ---------- 5. chunked（不报长度）、体积巨大：停止改写，且不缓存半成品 ----------
// 远大于 1MB 预算：旧实现会把整份 body 缓冲后 replaceAll，这正是 CPU 超时路径。
const unit = '<div>upstream.example.net</div>';
const REPEAT = 80000;
const huge = unit.repeat(REPEAT); // ≈ 2.4MB
plan = { mode: 'chunked', body: huge };
resp = await get('/huge-chunked');
text = await resp.text();

// 预算内的前半段被改写（每个 host 变短 UPSTREAM_HOST.length - 9 = 1 字节），
// 预算外的后半段原样流出，所以总长**应当**缩短，缩掉的正是「已改写次数 × 1」。
// 期望值用独立算式重算（不复用实现里的常量与分块大小）：按 4096 切块累计，
// 直到累计字节越过 1MB 预算为止，此前每个 chunk 都改写、此后原样。
const hostDrop = UPSTREAM_HOST.length - 'panel.example.com'.length;
const BUDGET = 1 << 20;
const CHUNK = 4096;
const rawBytes = Buffer.byteLength(huge);
// 精确统计「预算内被改写的 host 实例数」：按 4096 切块，逐块统计该块内 host 的出现次数
const countIn = (str, sub) => str.split(sub).length - 1;
let consumed = 0;
let rewrittenHosts = 0;
for (let i = 0; i < rawBytes; i += CHUNK) {
    const size = Math.min(CHUNK, rawBytes - i);
    if (consumed + size > BUDGET) break;
    consumed += size;
    const slice = huge.slice(i, i + size);
    rewrittenHosts += countIn(slice, UPSTREAM_HOST);
}
const expectedLen = rawBytes - rewrittenHosts * hostDrop;
check('超大 chunked：body 未被结构性截断（长度与独立算式一致）',
    text.length === expectedLen,
    `raw=${rawBytes} got=${text.length} expected=${expectedLen} rewrittenHosts=${rewrittenHosts}`);
check('超大 chunked：预算外部分原样保留（末尾仍是未改写形态）', text.trimEnd().endsWith(unit));

// 再请求一次同一个 URL：若缓存了半成品，这次会 0 次出站 —— 说明错误产物被固化了
const beforeHuge = fetchCount;
await (await get('/huge-chunked')).text();
check('超大 chunked：未缓存（第二次仍出站）', fetchCount === beforeHuge + 1, `before=${beforeHuge} now=${fetchCount}`);

// ---------- 6. 正文被改写后，上游的 framing 头必须被剥掉 ----------
// 回归点：改写会改变长度、且 body 已被 fetch 解压。若继续沿用上游的 content-length /
// content-encoding，客户端会按旧长度读取或二次解压，表现为页面坏掉 + 不断重试，
// 每次重试都是缓存未命中的昂贵反代 —— 曾表现为「CPU 超限规律性复发」。
plan = {
    mode: 'known',
    body: '<html><a href="https://upstream.example.net/y">y</a></html>',
    extra: { 'content-encoding': 'gzip' }
};
const framingResp = await get('/about?framing=1');
await framingResp.text();
check('改写后：content-length 已被移除', !framingResp.headers.has('content-length'),
    `content-length=${framingResp.headers.get('content-length')}`);
check('改写后：content-encoding 已被移除', !framingResp.headers.has('content-encoding'),
    `content-encoding=${framingResp.headers.get('content-encoding')}`);
check('改写后：transfer-encoding 已被移除', !framingResp.headers.has('transfer-encoding'));

// ---------- 7. 一致性：根路径与「内置随机路径」的处理必须同构 ----------
// 随机路径由 generateWsPath 生成：1~3 段、每段取自 PUBLIC_PATH_POOL（= 字典剔除内置路由词），
// 因此按构造必然落在路径字典内 → guardNonBuiltinPath 会跳过限流并直接进 camouflageProxy。
// 它与根路径进入的是**同一个函数**，所以「体积预算改写 / 剥帧头 / 缓存」必须逐项一致。
const consistencyBody = '<html><a href="https://upstream.example.net/z">z</a></html>';
plan = { mode: 'known', body: consistencyBody, extra: { 'content-encoding': 'gzip' } };

const rootResp = await get('/');
const rootText = await rootResp.text();
const RANDOM_PATH = '/blog/news?rid=1';   // 两段，均取自字典池，形态同随机路径
const randResp = await get(RANDOM_PATH);
const randText = await randResp.text();

check('一致性：根路径与随机路径都改写了上游 host',
    rootText.includes('panel.example.com') && randText.includes('panel.example.com'),
    `root=${rootText.slice(0, 60)} rand=${randText.slice(0, 60)}`);
check('一致性：两者都剥掉了 content-length',
    !rootResp.headers.has('content-length') && !randResp.headers.has('content-length'));
check('一致性：两者都剥掉了 content-encoding',
    !rootResp.headers.has('content-encoding') && !randResp.headers.has('content-encoding'));

// 缓存：两者各自命中自己的键；命中是廉价路径，不应再出站
const beforeConsistency = fetchCount;
await (await get('/')).text();
await (await get(RANDOM_PATH)).text();
check('一致性：根路径与随机路径均命中缓存（0 次出站）', fetchCount === beforeConsistency,
    `before=${beforeConsistency} now=${fetchCount}`);

// ---------- 8. 首页缓存必须按字节有界，而不是只按条目数 ----------
// 回归点：条目上限 × 单条正文上限（100 × 1MB）曾逼近甚至超过 isolate 的 128MB 内存，
// 持续 GC 烧掉 CPU，表现为「CPU 超限规律性复发」。这里用行为验证：灌入远超字节预算的
// 大页面后，最早的键必须被淘汰（否则说明预算没生效）。
plan = { mode: 'known', body: 'p'.repeat(300 * 1024), extra: {} };  // 每条约 300KB
const BYTE_BUDGET = 4 * 1024 * 1024;
const distinct = Math.ceil(BYTE_BUDGET / (300 * 1024)) + 12;        // 明显超出预算的条目数

// /about 在路径字典内 → 不触发限流；用 query 区分缓存键
for (let i = 0; i < distinct; i++) {
    await (await get(`/about?bulk=${i}`)).text();
}

// 最早的键应已被字节预算淘汰：再次请求它必然重新出站
const beforeRevisit = fetchCount;
await (await get('/about?bulk=0')).text();
check('缓存字节有界：最早的条目已被淘汰（重新出站）', fetchCount === beforeRevisit + 1,
    `flush 了 ${distinct} 条 300KB 页面，字节预算 ${BYTE_BUDGET}，期望 bulk=0 已淘汰；before=${beforeRevisit} now=${fetchCount}`);

// 最近的键仍在缓存里：不应出站
const beforeHot = fetchCount;
await (await get(`/about?bulk=${distinct - 1}`)).text();
check('缓存字节有界：最近的条目仍在缓存（0 次出站）', fetchCount === beforeHot,
    `before=${beforeHot} now=${fetchCount}`);

// ---------- 9. 熔断必须覆盖「内置随机路径」，而不只是根路径 ----------
// 回归点：熔断判据曾写成 `pathname === '/'`，而随机路径按构造落在路径字典内、
// 被 firstCheck 的限流豁免，于是随机路径成了唯一没有 CPU 保护的入口。
// 这里用字典内路径 + 每次不同的 query（必然未命中缓存）持续打，必须出现「0 次出站」。
let trippedRandom = false;
for (let i = 0; i < 400; i++) {
    const c = fetchCount;
    const r = await get(`/blog/news?flare=${i}`);
    await r.text();
    if (fetchCount === c) { trippedRandom = true; break; }
}
check('熔断：字典内的随机路径同样会被熔断（不再只保护根路径）', trippedRandom, `fetchCount=${fetchCount}`);

// 额度是 isolate 级共享的：随机路径打爆后，根路径应立刻也降级
const beforeShared = fetchCount;
await (await get('/')).text();
check('熔断：根路径与随机路径共享同一份额度', fetchCount === beforeShared,
    `before=${beforeShared} now=${fetchCount}`);

out(failures === 0 ? '\n全部通过' : `\n${failures} 项失败`);
process.exit(failures === 0 ? 0 : 1);
