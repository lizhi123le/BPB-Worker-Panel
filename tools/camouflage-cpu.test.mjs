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

// ---------- 0. 黑名单只作用于探测面；随机路径与根路径豁免且零 KV 成本 ----------
// 回归点（两次踩坑都在这条路径上）：
//  1) 曾把黑名单检查加到 `/` —— 刷新成本 O(名单规模)，`/` 流量最大，于是「CPU 超限规律性复发」；
//  2) 该成本同样存在于任何会查黑名单的路径，包括 WS 升级与节点随机路径。
// 现在的契约：只有「含字典外段」的探测请求才查黑名单；根路径与「每段都在字典内」的
// 随机路径组合（1~N 段）一律豁免，连一次 kv.get 都不产生。
const BANNED_IP = '198.51.100.7';
// 必须在任何请求之前播种：黑名单有 60s 内存缓存，首次请求会把空集合缓存住。
// 这里顺带验证「条数封顶」：名单无上限时，刷新成本 O(条数) 会随运行时间无界增长
// （实测 5 万条 ≈13.7ms，而单请求预算只有 10ms）。封顶后恒 ≈0.7ms，超限丢最旧。
// 构造 5001 条：最前面的 FIRST_IP 是最旧的 → 载入时应被丢弃；最后的 BANNED_IP 应保留。
const FIRST_IP = '198.51.100.1';
const filler = Array.from({ length: 4999 }, (_, i) => `10.${(i >> 8) & 255}.${i & 255}.9`);
store.set('permanentBlacklist', JSON.stringify([FIRST_IP, ...filler, BANNED_IP]));

// 探测面：被拉黑 IP 必须被拦
const bannedProbe = await get('/zz-probe-not-in-dictionary', BANNED_IP);
await bannedProbe.text();
check('黑名单：被拉黑 IP 探测非字典路径被拦截（429）', bannedProbe.status === 429, `status=${bannedProbe.status}`);
// 429 不应带整小时的固定 Retry-After：真实 CF 的 429 不会给这个值，而"429 + 3600"是 cfnew 血统的稳定特征
check('黑名单：429 不带 Retry-After: 3600', bannedProbe.headers.get('retry-after') !== '3600',
    `retry-after=${bannedProbe.headers.get('retry-after')}`);

// 条数封顶：最旧的那条（FIRST_IP）应在载入时被丢弃，因此不再被拦
const trimmedProbe = await get('/zz-probe-not-in-dictionary', FIRST_IP);
await trimmedProbe.text();
check('黑名单：超过 5000 条时丢弃最旧的封禁（最旧 IP 不再被拦）', trimmedProbe.status !== 429,
    `status=${trimmedProbe.status}（期望非 429，说明 FIRST_IP 已被 trim 掉）`);

// 豁免面：根路径 + 随机路径的单段/多段组合，且不得产生任何 KV 读取
// （首条探测请求已顺带预热 initHttp 里一次性的 subPath 缓存）
const EXEMPT_PATHS = [
    '/?bl-probe=1',                 // 根路径
    '/about?bl-probe=1',            // 单段
    '/blog/news?bl-probe=1',        // 两段
    '/api/video/music?bl-probe=1'   // 三段
];
const exemptStatus = [];
for (const p of EXEMPT_PATHS) {
    const kvBefore = kvReads.length;
    const r = await get(p, BANNED_IP);
    await r.text();
    const reads = kvReads.length - kvBefore;
    check(`豁免：${p} 不产生 KV 读取`, reads === 0,
        `新增 ${reads} 次：${kvReads.slice(kvBefore).join(', ') || '无'}`);
    exemptStatus.push(r.status);
}
check('豁免：被拉黑 IP 仍可访问根路径与随机路径（未被黑名单阻塞）',
    exemptStatus.every((s) => s === 200), `statuses=${exemptStatus.join(', ')}`);

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

/**
 * 把两个令牌桶都放到"实际无限"，并睡一小会儿让惰性补充把令牌补满。
 *
 * 为什么必须这样做：桶是 isolate 级单例（生产语义如此），上一段把 requests 打到 0 之后，
 * 下一段即使改了 cap/rate，令牌也要等"下一次判定时按流逝时间补充"才会回来 —— 不补满的话
 * 后续请求全部被判 1101，断言会**假通过**（"0 次出站"其实是根本没发请求）。
 */
const widenBudget = async (overrides = {}) => {
    Object.assign(env, {
        MASK_REQ_CAP: '100000',
        MASK_REQ_BPS: '1000000',
        MASK_TEXT_CAP: String(64 * 1024 * 1024),
        MASK_TEXT_BPS: String(64 * 1024 * 1024),
        MASK_TEXT_IP_CAP: String(64 * 1024 * 1024),
        ...overrides
    });
    await new Promise((r) => setTimeout(r, 40));
};

// ---------- 7.5 预算放宽：下面要灌 ~8MB 文本，先把文本桶调大，避免降级污染 #8 的断言 ----------
await widenBudget();

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

// ---------- 9. 图片伪装：壳页 + 同源图片子请求 ----------
// 形态：页面 ~300B（`<img src="/?<param>=<hash>">`），图片字节由子请求返回，浏览器缓存后不再回源。
// 改成这样是为了把「每请求 ~2.7MB 内联 data URI」的带宽降下来（CPU 已在上一轮修好）。
const IMAGE_TARGET = 'https://upstream.example.net/photo.jpg';
const IMAGE_BODY = 'JPEGDATA'.repeat(100);
const imgEnv = () => ({ ...env, FALLBACK: IMAGE_TARGET });
const imageReq = (path, extraHeaders = {}) => new Request(ORIGIN + path, {
    headers: { Host: 'panel.example.com', 'CF-Connecting-IP': '203.0.113.9', ...extraHeaders }
});
const getImagePage = () => handler.fetch(imageReq('/'), imgEnv(), ctx);
const fetchImagePath = (path, extraHeaders = {}) => handler.fetch(imageReq(path, extraHeaders), imgEnv(), ctx);

plan = { mode: 'known', body: IMAGE_BODY, extra: { 'content-type': 'image/jpeg' } };

const beforeImage = fetchCount;
const firstImage = await getImagePage();
const firstImageText = await firstImage.text();
check('图片伪装：首请求确实出站取图（1 次 fetch）', fetchCount === beforeImage + 1, `before=${beforeImage} now=${fetchCount}`);
check('图片伪装：返回壳页而非 data URI',
    firstImageText.includes('<img src="/?') && !firstImageText.includes('data:image'),
    firstImageText.slice(0, 140));
check('图片伪装：壳页不泄露上游域名', !firstImageText.includes(UPSTREAM_HOST), firstImageText.slice(0, 200));

const imgSrcMatch = firstImageText.match(/<img src="([^"]+)"/);
const imgPath = imgSrcMatch ? imgSrcMatch[1] : '';
check('图片伪装：壳页带同源图片子请求', imgPath.startsWith('/?'), `src=${imgPath}`);

// 壳页必须带部署盐（类名/写法随 UUID 变），否则整页字节是一个可被哈希命中的固定常量
const shellSalt = (firstImageText.match(/class="[wp]([0-9a-f]{5})"/) || [])[1];
check('图片伪装：壳页类名带部署盐（整页哈希不是固定常量）', !!shellSalt, firstImageText.slice(0, 200));
check('图片伪装：壳页不再是 cfnew 的固定字节形态',
    !firstImageText.includes('height:100vh}img{width:100vw'), firstImageText.slice(0, 240));

// 子请求：命中缓存字节 → image/*，逐字节与上游一致，且 0 次出站
const beforeSub = fetchCount;
const subResp = await fetchImagePath(imgPath);
const subBuf = Buffer.from(await subResp.arrayBuffer());
check('图片子请求：命中缓存 0 次出站', fetchCount === beforeSub, `before=${beforeSub} now=${fetchCount}`);
check('图片子请求：Content-Type 为 image/*', (subResp.headers.get('content-type') || '').startsWith('image/'),
    `content-type=${subResp.headers.get('content-type')}`);
check('图片子请求：字节与上游图逐字节一致', subBuf.equals(Buffer.from(IMAGE_BODY)),
    `got=${subBuf.length}B expect=${Buffer.byteLength(IMAGE_BODY)}B`);
check('图片子请求：带 ETag 与长缓存头',
    !!subResp.headers.get('etag') && (subResp.headers.get('cache-control') || '').includes('max-age'),
    `etag=${subResp.headers.get('etag')} cc=${subResp.headers.get('cache-control')}`);

// 与真实静态站对齐的三项头（否则"这张图不支持 Range"就是可判定特征）
check('图片子请求：声明 Accept-Ranges: bytes',
    subResp.headers.get('accept-ranges') === 'bytes',
    `accept-ranges=${subResp.headers.get('accept-ranges')}`);
check('图片子请求：带 Last-Modified',
    !!subResp.headers.get('last-modified'),
    `last-modified=${subResp.headers.get('last-modified')}`);
check('图片子请求：ETag 是内容哈希（不是 URL 哈希）',
    (subResp.headers.get('etag') || '') !== `"${imgPath.split('=').pop()}"`,
    `etag=${subResp.headers.get('etag')}`);

// 单段 Range → 206 + Content-Range，且切片字节正确
const rangeResp = await fetchImagePath(imgPath, { Range: 'bytes=0-9' });
const rangeBytes = Buffer.from(await rangeResp.arrayBuffer());
check('图片子请求：Range 请求返回 206 + Content-Range',
    rangeResp.status === 206
    && (rangeResp.headers.get('content-range') || '') === `bytes 0-9/${Buffer.byteLength(IMAGE_BODY)}`
    && rangeBytes.length === 10
    && rangeBytes.equals(Buffer.from(IMAGE_BODY).subarray(0, 10)),
    `status=${rangeResp.status} cr=${rangeResp.headers.get('content-range')} len=${rangeBytes.length}`);

// 后缀 Range（bytes=-5）取末 5 字节
const suffixResp = await fetchImagePath(imgPath, { Range: 'bytes=-5' });
const suffixBytes = Buffer.from(await suffixResp.arrayBuffer());
check('图片子请求：后缀 Range（bytes=-5）返回末 5 字节',
    suffixResp.status === 206 && suffixBytes.equals(Buffer.from(IMAGE_BODY).subarray(-5)),
    `status=${suffixResp.status} len=${suffixBytes.length}`);

// 越界 Range 不返回 206（回 200 全长，不假装支持）
const overResp = await fetchImagePath(imgPath, { Range: 'bytes=999999-1000000' });
check('图片子请求：越界 Range 不返回 206', overResp.status !== 206, `status=${overResp.status}`);

// 壳页也要有统一的安全头与 no-store（与图片字节分支同一套策略）
check('图片伪装：壳页带 nosniff 且不缓存',
    firstImage.headers.get('x-content-type-options') === 'nosniff'
    && (firstImage.headers.get('cache-control') || '').includes('no-store'),
    `nosniff=${firstImage.headers.get('x-content-type-options')} cc=${firstImage.headers.get('cache-control')}`);

// 条件请求 → 304（浏览器 24h 后重验证不会重下整张图）
const condResp = await fetchImagePath(imgPath, { 'If-None-Match': subResp.headers.get('etag') || '' });
check('图片子请求：If-None-Match 命中 304', condResp.status === 304, `status=${condResp.status}`);

// 未命中（伪造哈希）必须回**中性图片**且绝不回 HTML：
// 回 503 会形成「部署存在性 oracle」，回 HTML 会让 <img> 破图并暴露指纹
const bogusPath = imgPath.replace(/=([0-9a-f]+)$/, '=deadbeef');
const bogusResp = await fetchImagePath(bogusPath);
const bogusText = await bogusResp.text();
check('图片子请求：未知哈希回中性图片（200 + image/*，非 HTML）',
    bogusResp.status === 200
    && (bogusResp.headers.get('content-type') || '').startsWith('image/')
    && !bogusText.includes('<html'),
    `status=${bogusResp.status} ct=${bogusResp.headers.get('content-type')}`);

// 页面第二次：字节命中缓存 → 0 次出站，壳页仍一致
const beforeImageCached = fetchCount;
const secondImageText = await (await getImagePage()).text();
check('图片伪装：第二次请求 0 次出站（字节命中缓存）', fetchCount === beforeImageCached,
    `before=${beforeImageCached} now=${fetchCount}`);
check('图片伪装：壳页与首响应逐字一致', secondImageText === firstImageText,
    `first=${firstImageText.length}B second=${secondImageText.length}B`);

// 回滚开关：MASK_IMG_MODE=data → 退回"内联 data URI 单请求页"（已知可用但费带宽的旧形态）
const IMAGE_TARGET_LEGACY = 'https://upstream.example.net/photo-legacy.jpg';
const legacyEnv = { ...env, FALLBACK: IMAGE_TARGET_LEGACY, MASK_IMG_MODE: 'data' };
const legacyResp = await handler.fetch(imageReq('/'), legacyEnv, ctx);
const legacyText = await legacyResp.text();
check('图片伪装：MASK_IMG_MODE=data 可退回内联 data URI 页（回滚开关）',
    legacyText.includes('data:image/jpeg;base64,') && !legacyText.includes('<img src="/?'),
    legacyText.slice(0, 110));

/** 从 data URI 页里解出 base64 并逐字节比对（钉住回滚模式的编码正确性） */
const decodeDataUri = (html) => {
    const start = html.indexOf('base64,') + 7;
    const end = html.indexOf('" alt=');
    return Buffer.from(html.slice(start, end), 'base64');
};
const expectImageBytes = Buffer.from(IMAGE_BODY);

// (1) 原生 toBase64 路径要字节一致
check('data 回滚模式：base64 与上游字节逐字节一致（原生 toBase64）',
    decodeDataUri(legacyText).equals(expectImageBytes),
    `got=${decodeDataUri(legacyText).length}B expect=${expectImageBytes.length}B`);

// (2) 强制走纯 JS 回退：删掉原型方法后再请求（bytesToBase64 是调用时查属性，故此招有效）
const savedToBase64 = Uint8Array.prototype.toBase64;
let fallbackText = '';
try {
    delete Uint8Array.prototype.toBase64;
    const fallbackResp = await handler.fetch(imageReq('/?_fb=1'), legacyEnv, ctx);
    fallbackText = await fallbackResp.text();
} finally {
    if (savedToBase64) Uint8Array.prototype.toBase64 = savedToBase64;
}
check('data 回滚模式：无原生 toBase64 时回退实现同样字节一致',
    fallbackText.includes('data:image/jpeg;base64,') && decodeDataUri(fallbackText).equals(expectImageBytes),
    `len=${fallbackText.length}`);

// (3) 无 content-length / ≥2MB → 流式直传（这一支由 streamImageResponse 统一处理，必须覆盖）
const STREAM_BODY = 'S'.repeat(64 * 1024);
plan = { mode: 'chunked', body: STREAM_BODY, extra: { 'content-type': 'image/jpeg' } };
const streamEnv = { ...env, FALLBACK: 'https://upstream.example.net/photo-stream.jpg' };
const streamResp = await handler.fetch(imageReq('/'), streamEnv, ctx);
const streamBytes = Buffer.from(await streamResp.arrayBuffer());
check('图片流式分支：无 content-length 时直传图片字节（不缓存、不包装 HTML）',
    (streamResp.headers.get('content-type') || '').startsWith('image/')
    && streamBytes.length === Buffer.byteLength(STREAM_BODY)
    && streamBytes[0] === 0x53
    && !streamBytes.toString('latin1').includes('<html'),
    `status=${streamResp.status} ct=${streamResp.headers.get('content-type')} len=${streamBytes.length}`);

// ---------- 10. 熔断必须覆盖「内置随机路径」，而不只是根路径 ----------
// 回归点：熔断判据曾写成 `pathname === '/'`，而随机路径按构造落在路径字典内、
// 被 firstCheck 的限流豁免，于是随机路径成了唯一没有 CPU 保护的入口。
// 新模型是令牌桶：把 requests 桶调小（容量 8、补充 1/s），连打必在 8 次内降级。
Object.assign(env, { MASK_REQ_CAP: '8', MASK_REQ_BPS: '1' });
let trippedRandom = false;
for (let i = 0; i < 60; i++) {
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

// ---------- 11. 分通道额度：文本桶与 requests 桶互不干扰 ----------
// (a) 只卡文本桶：requests 桶放到实际无限，文本容量 64KB、每次 20KB → 数次内必降级
await widenBudget({ MASK_TEXT_CAP: '65536', MASK_TEXT_BPS: '1024', MASK_TEXT_IP_CAP: '65536' });
plan = { mode: 'known', body: 'r'.repeat(20 * 1024), extra: {} };
let trippedTextAt = -1;
for (let i = 0; i < 12; i++) {
    // 注意：文本桶是**出站后**判定的（要先拿到 content-length 才知道成本），
    // 所以这里用"响应变成 1101 页"作为降级信号，而不是"0 次出站"。
    const t = await (await get(`/about?tx=${i}`)).text();
    if (t.includes('1101')) { trippedTextAt = i; break; }
}
check('分通道：文本桶耗尽后文本请求降级（改写被跳过）', trippedTextAt >= 0, `trippedAt=${trippedTextAt}`);

// (a2) per-IP 绑定：per-IP 额度小、全局额度大 → 只有该 IP 被降级，别的 IP 照常
// 注意 65536 是 MASK_TEXT_IP_CAP 的配置下限（低于它会被回退成默认值）
await widenBudget({ MASK_TEXT_IP_CAP: '65536', MASK_TEXT_CAP: String(64 * 1024 * 1024) });
plan = { mode: 'known', body: 'z'.repeat(20 * 1024), extra: {} };
const HOT_IP = '198.51.100.99';
const OTHER_IP = '198.51.100.42';
let ipTrippedAt = -1;
for (let i = 0; i < 10; i++) {
    const t = await (await get(`/about?ip=${i}`, HOT_IP)).text();
    if (t.includes('1101')) { ipTrippedAt = i; break; }
}
check('熔断：per-IP 文本额度生效（同一 IP 连续大页被降级）', ipTrippedAt >= 0, `trippedAt=${ipTrippedAt}`);
const beforeOtherIp = fetchCount;
const otherIpBody = await (await get(`/about?ip=other&x=${Date.now()}`, OTHER_IP)).text();
check('熔断：per-IP 相互隔离（另一个 IP 不受影响，仍在出站）',
    fetchCount === beforeOtherIp + 1 && !otherIpBody.includes('1101'),
    `before=${beforeOtherIp} now=${fetchCount}`);

// (b) 文本桶耗尽时图片页仍应可用 —— 这正是分通道的目的：文本额度不拖垮图片伪装面
const pageWhileTextDown = await getImagePage();
const pageWhileTextDownText = await pageWhileTextDown.text();
check('分通道：文本桶耗尽时图片页仍可用',
    pageWhileTextDown.status === 200 && pageWhileTextDownText.includes('<img'),
    `status=${pageWhileTextDown.status} body=${pageWhileTextDownText.slice(0, 60)}`);

// (c) 再卡死 requests 桶：图片页也必须降级（熔断覆盖图片分支，不再有"免额度"的旁路）
Object.assign(env, { MASK_REQ_CAP: '3', MASK_REQ_BPS: '1' });
let brokeImage = false;
let brokeImageStatus = 0;
for (let i = 0; i < 12; i++) {
    const c = fetchCount;
    const r = await getImagePage();
    const t = await r.text();
    if (t.includes('1101') && fetchCount === c) { brokeImage = true; brokeImageStatus = r.status; break; }
}
check('requests 桶耗尽：图片目标降级为内建 1101 页（熔断覆盖图片分支）', brokeImage, `fetchCount=${fetchCount}`);

// 指纹一致性：真实 CF 的 1101「Worker threw exception」是 5xx；"错误页配 200" 本身就是可判定特征
check('熔断：1101 降级页状态码为 5xx（不是 200）', brokeImageStatus >= 500 && brokeImageStatus < 600,
    `status=${brokeImageStatus}`);

// (d) requests 桶耗尽时，`<img>` 子请求必须回 503 空体 —— 回 HTML 会让 <img> 破图并暴露指纹
const beforeImgGate = fetchCount;
const gatedImg = await fetchImagePath(imgPath);
const gatedImgText = await gatedImg.text();
check('requests 桶耗尽：<img> 子请求回 503 且不是 HTML',
    gatedImg.status === 503 && !gatedImgText.includes('<html'),
    `status=${gatedImg.status} body=${gatedImgText.slice(0, 30)}`);
check('requests 桶耗尽：<img> 子请求不再出站', fetchCount === beforeImgGate,
    `before=${beforeImgGate} now=${fetchCount}`);

// ---------- 12. 缓存键：时间戳参数按「值形态」归一，语义参数一律不归一 ----------
await widenBudget();
plan = { mode: 'known', body: '<html><a href="https://upstream.example.net/cache">c</a></html>', extra: {} };
const nowSec = Math.floor(Date.now() / 1000);
const nowMs = Date.now();

// 基线守卫：先确认"请求真的出站了"，否则后面的"0 次额外出站"可能只是额度耗尽造成的假通过
const beforeBaseline = fetchCount;
await (await get(`/about?k=ts1&t=${nowSec}`)).text();
check('缓存键：基线请求确实出站（防止额度耗尽导致假通过）', fetchCount === beforeBaseline + 1,
    `before=${beforeBaseline} now=${fetchCount}`);

// 同组参数、只差一个"当前时刻"的秒级时间戳 → 必须命中同一份缓存
let beforeTs = fetchCount;
await (await get(`/about?k=ts1&t=${nowSec + 1}`)).text();
check('缓存键：当前时刻的 t= 被归一（0 次额外出站）', fetchCount === beforeTs,
    `before=${beforeTs} now=${fetchCount}`);

// 13 位毫秒时间戳只在**静态资源路径**上归一（对象 ID / 日志时间戳也常是 13 位，API 路径上归一会投毒）
const beforeMs = fetchCount;
await (await get(`/about/app.js?k=ts2&timestamp=${nowMs}`)).text();
check('缓存键：毫秒 timestamp 基线出站', fetchCount === beforeMs + 1, `before=${beforeMs} now=${fetchCount}`);
beforeTs = fetchCount;
await (await get(`/about/app.js?k=ts2&timestamp=${nowMs + 1}`)).text();
check('缓存键：静态资源路径上的毫秒 timestamp 被归一', fetchCount === beforeTs,
    `before=${beforeTs} now=${fetchCount}`);

// 同一条毫秒时间戳出现在**接口路径**上时必须保留（否则不同对象会折叠成同一缓存键）
const beforeApiMs = fetchCount;
await (await get(`/about/log?k=ts3&timestamp=${nowMs}`)).text();
await (await get(`/about/log?k=ts3&timestamp=${nowMs + 1000}`)).text();
check('缓存键：接口路径上的毫秒 timestamp 不被归一（防跨对象折叠）', fetchCount === beforeApiMs + 2,
    `before=${beforeApiMs} now=${fetchCount}`);

// 出现语义参数（id/page/token…）时整条查询串都不做时间戳归一
const beforeSemantic = fetchCount;
await (await get(`/about?k=ts4&id=5&t=${nowSec}`)).text();
await (await get(`/about?k=ts4&id=5&t=${nowSec + 1}`)).text();
check('缓存键：带语义参数时不做时间戳归一', fetchCount === beforeSemantic + 2,
    `before=${beforeSemantic} now=${fetchCount}`);

// 历史时刻（不在 now±1h）的 t= 是**语义参数**（as-of 快照）→ 必须各自出站，不能被缓存投毒
const oldSec = 1700000000;
const beforeOld = fetchCount;
await (await get(`/about?k=old&t=${oldSec}`)).text();
await (await get(`/about?k=old&t=${oldSec + 1}`)).text();
check('缓存键：历史时刻的 t= 不被归一（防缓存投毒）', fetchCount === beforeOld + 2,
    `before=${beforeOld} now=${fetchCount}`);

// 语义参数一律不归一
const beforeId = fetchCount;
await (await get('/about?k=id&id=5')).text();
await (await get('/about?k=id&id=6')).text();
check('缓存键：id= 等语义参数不被归一', fetchCount === beforeId + 2,
    `before=${beforeId} now=${fetchCount}`);

// 回滚开关：MASK_CACHE_TS_NORM=0 时时间戳不再归一
await widenBudget({ MASK_CACHE_TS_NORM: '0' });
const beforeOff = fetchCount;
await (await get(`/about?k=off&t=${nowSec}`)).text();
await (await get(`/about?k=off&t=${nowSec + 1}`)).text();
check('缓存键：MASK_CACHE_TS_NORM=0 可关闭归一（回滚开关）', fetchCount === beforeOff + 2,
    `before=${beforeOff} now=${fetchCount}`);

out(failures === 0 ? '\n全部通过' : `\n${failures} 项失败`);
process.exit(failures === 0 ? 0 : 1);
