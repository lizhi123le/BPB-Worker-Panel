/**
 * tools/proxy-pool-cache.test.mjs
 *
 * 反代池「三级缓存 + 单飞」的行为测试。
 * 运行：node tools/proxy-pool-cache.test.mjs
 *
 * 为什么需要它：这套逻辑只在 WS 拨号内部跑，smoke 用例连不了真 TCP、也拿不到并发时序，
 * 而 `resolveProxyIPPool` 又不在 worker bundle 的导出里 —— 所以这里直接用 esbuild 把
 * `src/cores/utils.ts` 打成单文件，再用「同一个假 Cache + 每次带不同查询串 import」模拟多个
 * isolate（每个 import 都是全新模块实例、一级 Map 为空，但共享同一份 Cache API）。
 *
 * 覆盖：
 *   1. 一级（isolate 内 Map）命中不再打 DoH；不同目标不同键，互不串味
 *   2. 二级（Cache API）跨 isolate 复用：换一个 isolate 仍命中，且不再产生 DoH 请求
 *   3. 二级条目按体内时间戳判新鲜度：过期当未命中；结构不合法当未命中；空池不入缓存
 *   4. 单飞：同一秒 N 条同键并发只解析一次（N=6 时 DoH 仍是 4 次，而不是 24 次），
 *      不同键各自解析；解析结束后单飞表不残留
 *   5. 降级安全：没有 caches、没有 httpConfig.hostName、cache.match/put 抛错，都只是退化成
 *      一级缓存，不影响本次解析结果（smoke 的 Node 环境就是这种情况）
 *   6. 调试日志：Log Level=debug 时每次解析只落一行 `[proxy-pool] L1 hit|L1 stale|inflight|
 *      L2 hit|L2 miss|L2 skip|DoH`（按 layer 计数即可算命中率），且不打印反代池条目；
 *      非 debug 级别一行都不输出
 *
 * 前提：`npm install`（需要 esbuild、html-minifier 之外的依赖不变）。不依赖 dist/ 与 .build/。
 */
import { build } from 'esbuild';
import { mkdirSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import assert from 'node:assert';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_DIR = join(ROOT, '.build/pool-cache-test');
const BUNDLE_PATH = join(OUT_DIR, 'utils-bundle.mjs');

const PROXY = 'ProxyIP.KR.CMLiussss.net:443';
const TARGET = 'x.com';
const TTL = 10 * 60 * 1000;
const IPV4 = ['1.2.3.4', '1.2.3.5', '1.2.3.6'];

let failures = 0;
const out = (...args) => process.stdout.write(args.join(' ') + '\n');
const check = (name, fn) => {
    try { fn(); out(`PASS  ${name}`); }
    catch (err) { out(`FAIL  ${name}\n      ${err.message}`); failures++; }
};

/** [ [host, port], ... ] 按集合比较：池本身是「排序 + 确定性洗牌」后的顺序，不能按字面顺序断言 */
const asSet = (pool) => [...pool].map(([host, port]) => `${host}:${port}`).sort();
const EXPECT_IPS = asSet(IPV4.map((ip) => [ip, 443]));

// ── 假 Cache API：只做「按 URL 存取」，读时返回全新的 Response（Response body 只能读一次）──
class FakeCache {
    constructor() { this.store = new Map(); this.puts = 0; }
    async match(req) {
        const entry = this.store.get(req.url);
        return entry ? new Response(entry.body, { headers: entry.headers }) : undefined;
    }
    async put(req, res) {
        this.puts++;
        this.store.set(req.url, { body: await res.text(), headers: Object.fromEntries(res.headers) });
    }
}

// ── 假 DoH：只认 A 记录，AAAA 恒空；可按场景切「空结果」与延迟 ──
let dohMode = 'ok';
let dohDelay = 0;
let fetchCount = 0;
const realFetch = globalThis.fetch;
const dohStub = async (url) => {
    fetchCount++;
    if (dohDelay) await new Promise((r) => setTimeout(r, dohDelay));
    const type = new URL(url).searchParams.get('type');
    const answer = dohMode === 'empty' || type !== 'A' ? [] : IPV4.map((data) => ({ type: 1, data }));
    return new Response(JSON.stringify({ Answer: answer }), { headers: { 'content-type': 'application/json' } });
};
globalThis.fetch = dohStub;

// ── 假环境 ──
const cache = new FakeCache();
globalThis.httpConfig = { hostName: 'panel.example.com' };
globalThis.caches = { default: cache };

let seq = 0;
/** 每次调用都拿到一个全新的模块实例 = 模拟「连接落到了另一个 isolate」 */
async function newIsolate() {
    seq++;
    const mod = await import(`${pathToFileURL(BUNDLE_PATH).href}?iso=${seq}`);
    return mod.resolveProxyIPPool;
}

async function main() {
    // 0) 把 utils.ts 打成单文件（走 tsconfig 的 paths 别名，与构建链路一致）
    mkdirSync(OUT_DIR, { recursive: true });
    await build({
        stdin: {
            contents: "export { resolveProxyIPPool } from './src/cores/utils';",
            resolveDir: ROOT,
            sourcefile: 'pool-cache-entry.ts',
            loader: 'ts'
        },
        outfile: BUNDLE_PATH,
        bundle: true,
        format: 'esm',
        platform: 'node',
        target: 'esnext',
        external: ['cloudflare:sockets'],
        legalComments: 'none'
    });

    // 1) 首次解析：L1/L2 都没有 → 走 DoH，并写入二级缓存
    const a = await newIsolate();
    const poolA = await a(PROXY, TARGET, '');
    check('首次解析返回完整池', () => assert.deepStrictEqual(asSet(poolA), EXPECT_IPS));
    check('首次解析确实打了 DoH', () => assert.ok(fetchCount > 0));
    check('首次解析写入了二级缓存', () => assert.strictEqual(cache.puts, 1));
    const fetchAfterFirst = fetchCount;

    // 2) 换一个 isolate（新模块、空 L1）→ 应该命中二级缓存，不再打 DoH
    const b = await newIsolate();
    const poolB = await b(PROXY, TARGET, '');
    check('第二个 isolate 命中二级缓存（结果一致）', () => assert.deepStrictEqual(asSet(poolB), asSet(poolA)));
    check('第二个 isolate 没有新增 DoH 请求', () => assert.strictEqual(fetchCount, fetchAfterFirst));

    // 3) 同一 isolate 内再调 → 命中一级缓存
    const poolB2 = await b(PROXY, TARGET, '');
    check('同 isolate 再调命中一级缓存', () => assert.deepStrictEqual(asSet(poolB2), asSet(poolA)));
    check('一级命中也不打 DoH', () => assert.strictEqual(fetchCount, fetchAfterFirst));

    // 4) 不同目标域名 = 不同键 → 不能串味（会重新解析）
    const c = await newIsolate();
    await c(PROXY, 'other.example.net', '');
    check('不同目标各自解析（键含 targetDomain）', () => assert.ok(fetchCount > fetchAfterFirst));

    // 5) DoH 空结果：既有行为是回退成域名本身（不是空池），这条结果同样可以跨 isolate 复用
    dohMode = 'empty';
    const d1 = await newIsolate();
    const empty1 = await d1('empty.domain.test:443', 'y.com', '');
    check('DoH 空结果回退成域名本身（既有行为不变）', () => assert.deepStrictEqual(asSet(empty1), ['empty.domain.test:443']));
    const fetchBeforeEmpty2 = fetchCount;
    const d2 = await newIsolate();
    const empty2 = await d2('empty.domain.test:443', 'y.com', '');
    check('域名回退结果同样被二级缓存复用', () => {
        assert.deepStrictEqual(asSet(empty2), ['empty.domain.test:443']);
        assert.strictEqual(fetchCount, fetchBeforeEmpty2);
    });
    dohMode = 'ok';

    // 6) DoH 抛错（fetch reject）→ 吞错回退成域名本身，不影响主流程
    globalThis.fetch = async () => { throw new Error('doh boom'); };
    const d3 = await newIsolate();
    const errPool = await d3('dohfail.domain.test:443', 'z.com', '');
    check('DoH 抛错时回退成域名本身且不崩', () => assert.deepStrictEqual(asSet(errPool), ['dohfail.domain.test:443']));
    globalThis.fetch = dohStub;

    // 7) 过期条目当未命中：把已存条目的时间戳往前挪 TTL+1s
    for (const [url, entry] of cache.store) {
        try {
            const parsed = JSON.parse(entry.body);
            if (parsed && typeof parsed.time === 'number') {
                parsed.time -= TTL + 1000;
                cache.store.set(url, { body: JSON.stringify(parsed), headers: entry.headers });
            }
        } catch { /* 跳过非 JSON 条目 */ }
    }
    const fetchBeforeStale = fetchCount;
    const e = await newIsolate();
    await e(PROXY, TARGET, '');
    check('过期条目按未命中处理（重新 DoH）', () => assert.ok(fetchCount > fetchBeforeStale));

    // 8) 脏数据当未命中：体内容结构不合法
    for (const [url, entry] of cache.store) {
        cache.store.set(url, { body: '{"time":' + Date.now() + ',"pool":"oops"}', headers: entry.headers });
    }
    const fetchBeforeDirty = fetchCount;
    const f = await newIsolate();
    const poolF = await f(PROXY, TARGET, '');
    check('非法结构按未命中处理且不崩', () => {
        assert.deepStrictEqual(asSet(poolF), EXPECT_IPS);
        assert.ok(fetchCount > fetchBeforeDirty);
    });

    // 9) 没有 Cache API（Node / smoke 环境）→ 不崩，照常解析
    globalThis.caches = undefined;
    const fetchBeforeNoCache = fetchCount;
    const g = await newIsolate();
    const poolG = await g(PROXY, 'nocache.example.com', '');
    check('无 caches 时照常解析且不崩', () => {
        assert.strictEqual(poolG.length, 3);
        assert.ok(fetchCount > fetchBeforeNoCache);
    });

    // 10) 没有 httpConfig.hostName → 跳过二级缓存，不崩
    globalThis.caches = { default: cache };
    globalThis.httpConfig = {};
    const fetchBeforeNoHost = fetchCount;
    const h = await newIsolate();
    const poolH = await h(PROXY, 'nohost.example.com', '');
    check('无 host 时跳过二级缓存且不崩', () => {
        assert.strictEqual(poolH.length, 3);
        assert.ok(fetchCount > fetchBeforeNoHost);
    });

    // 11) cache.put 抛错（例如被拒绝缓存）→ 不影响本次返回
    globalThis.httpConfig = { hostName: 'panel.example.com' };
    globalThis.caches = { default: { match: async () => undefined, put: async () => { throw new Error('cache refused'); } } };
    const fetchBeforeThrow = fetchCount;
    const i = await newIsolate();
    const poolI = await i(PROXY, 'putthrow.example.com', '');
    check('put 抛错不影响本次返回', () => {
        assert.strictEqual(poolI.length, 3);
        assert.ok(fetchCount > fetchBeforeThrow);
    });

    // 12) cache.match 抛错 → 退化成未命中
    globalThis.caches = { default: { match: async () => { throw new Error('match boom'); }, put: async () => {} } };
    const j = await newIsolate();
    const poolJ = await j(PROXY, 'matchthrow.example.com', '');
    check('match 抛错退化为未命中且不崩', () => assert.strictEqual(poolJ.length, 3));

    // 13) 单飞：同键 N 条并发只解析一次（慢 DoH 保证并发窗口真实存在）
    dohDelay = 60;
    const sfCache = new FakeCache();
    globalThis.caches = { default: sfCache };
    const k = await newIsolate();
    const beforeSf = fetchCount;
    const CONCURRENT = 6;
    const sfResults = await Promise.all(
        Array.from({ length: CONCURRENT }, () => k('sf.example.net:443', 'concurrent.example.com', ''))
    );
    // 一次解析 = A 双源(2) + AAAA 双源(2) = 4 次 DoH；6 条并发应当只有 4 次
    check('单飞：6 条并发只解析一次（4 次 DoH，而不是 24 次）', () => assert.strictEqual(fetchCount - beforeSf, 4));
    check('单飞：6 条并发结果完全一致', () => {
        for (const r of sfResults) assert.deepStrictEqual(asSet(r), EXPECT_IPS);
    });
    check('单飞：只写了一次二级缓存', () => assert.strictEqual(sfCache.puts, 1));

    // 14) 单飞不串键：同时刻两个不同键各自解析（2 次解析 = 8 次 DoH）
    globalThis.caches = { default: new FakeCache() };
    const m = await newIsolate();
    const beforeTwo = fetchCount;
    await Promise.all([
        m('sf.example.net:443', 'a.example.com', ''),
        m('sf.example.net:443', 'b.example.com', '')
    ]);
    check('单飞按 key 隔离：两个不同目标各自解析', () => assert.strictEqual(fetchCount - beforeTwo, 8));

    // 15) 单飞表不残留：解析结束后再调（L1 已写入 → 命中，不再打 DoH）
    const beforeAfter = fetchCount;
    await m('sf.example.net:443', 'a.example.com', '');
    check('解析结束后不再重复解析', () => assert.strictEqual(fetchCount, beforeAfter));
    dohDelay = 0;

    // 16) 调试日志分层：logLevel=debug 时一次解析只落一行，按 layer 计数即可算命中率
    globalThis.caches = { default: new FakeCache() };
    const debugLines = [];
    const realConsoleLog = console.log;
    globalThis.settings = { logLevel: 'debug' };
    console.log = (...args) => { debugLines.push(args.join(' ')); };
    try {
        const n = await newIsolate();
        // 首次：L2 miss → DoH；同 isolate 第二次：L1 hit
        await n('log.example.net:443', 'loglayer.example.com', '');
        await n('log.example.net:443', 'loglayer.example.com', '');
    } finally {
        console.log = realConsoleLog;
    }
    check('debug 日志分层：L2 miss / DoH / L1 hit 各一条', () => {
        const lines = debugLines.filter((l) => l.includes('[proxy-pool]'));
        const need = ['L2 miss', 'DoH', 'L1 hit'];
        for (const key of need) {
            assert.ok(lines.some((l) => l.includes(key)), `缺 ${key}，实际：${lines.join(' | ')}`);
        }
    });
    check('debug 日志不泄露反代池条目（只记目标与条数）', () => {
        // 反代池条目是 log.example.net 这类域名，日志里只应出现目标域名与 n=
        const lines = debugLines.filter((l) => l.includes('[proxy-pool]'));
        assert.ok(lines.every((l) => !l.includes('log.example.net')), lines.join(' | '));
    });

    // 17) 非 debug 级别不输出：默认日志里不能凭空多出噪声
    const quietLines = [];
    globalThis.settings = { logLevel: 'info' };
    console.log = (...args) => { quietLines.push(args.join(' ')); };
    try {
        const q = await newIsolate();
        await q('quiet.example.net:443', 'quiet.example.com', '');
    } finally {
        console.log = realConsoleLog;
        globalThis.settings = undefined;
    }
    check('非 debug 级别不输出 [proxy-pool] 日志', () => {
        assert.ok(!quietLines.some((l) => l.includes('[proxy-pool]')), quietLines.join(' | '));
    });

    globalThis.fetch = realFetch;

    out('');
    if (failures) {
        out(`proxy-pool-cache: FAILED（${failures} 项）`);
        process.exit(1);
    }
    out('proxy-pool-cache: OK');
}

await main();
