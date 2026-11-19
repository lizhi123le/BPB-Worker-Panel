/**
 * tools/doh-source.test.mjs
 *
 * DoH 出站层的三个「时间 / 顺序」旋钮的行为测试（都不需要真实网络）：
 *   A. `dohAnswersDual` 先到先用 + CF 宽限期
 *        A1 CF 快 / Google 慢   → 用 CF，且不等 Google（耗时 ≈ CF）
 *        A2 CF 空 / Google 快   → 用 Google（CF 的优先权只对非空成立）
 *        A3 Google 先答、CF 在宽限期内到 → 仍用 CF（保住既有的「CF 优先」）
 *        A4 Google 先答、CF 在宽限期后才到 → 用 Google（不被卡死的 CF 拖住）
 *        A5 宽限期显式 0 → 谁先到用谁（关掉 CF 优先）
 *   B. 三个 env 旋钮的钳制 / 回退 / 派生关系，以及「超时真的接到 AbortSignal.timeout 上」
 *        `DOH_TIMEOUT_MS`（默认 500，区间 50~6000）
 *        `DOH_SOURCE_GRACE_MS`（默认 260，区间 0~2000；显式 0 = 关掉 CF 优先）
 *        `DOH_WAIT_STALL_MS`（默认 260，区间 50 ~ min(3000, 超时 − 50)）
 *        `DOH_WAIT_BUDGET_MS`（默认 1000，区间 50~10000；单飞等待的总上界）
 *   C. 单飞等待方的进展感知
 *        C1 无进展（所有 DoH 都挂住）→ 260ms 就自己上（4+4=8 次，而不是干等满总上界）
 *        C2 有进展（同一轮解析里陆续有 DoH 完成）→ 继续等，仍只解析一次（4 次）
 *        C3 阈值调大后，慢但会完成的解析不再被重复（4 次）
 *        C4 总上界（env `DOH_WAIT_BUDGET_MS`）比 stall 更紧时，由预算先到
 *
 * 为什么需要它：这三处都是「用时间换请求数」的取舍，断言无法在 smoke 里稳定复现
 * （要控制两个源的相对时延与 settle 顺序）。所以用 esbuild 把 src/cores/utils.ts 打成单文件，
 * 再用可编程的 fetch 桩（按 host + type 给出 delay / records）驱动真实解析路径。
 *
 * 运行：node tools/doh-source.test.mjs
 * 前提：`npm install`（esbuild 已是依赖）。不依赖 dist/ 与 .build/worker.reference.js。
 */
import assert from 'node:assert';
import { join } from 'path';
import { ROOT, asSet, bundleUtils, createReporter, isolateLoader } from './lib/utils-bundle.mjs';

const OUT_DIR = join(ROOT, '.build/doh-source-test');
const BUNDLE_PATH = join(OUT_DIR, 'utils-bundle.mjs');

const CF_HOST = 'cloudflare-dns.com';
const GOOGLE_HOST = 'dns.google';
const TYPE_CODE = { A: 1, AAAA: 28, TXT: 16 };

const CF_A = ['203.0.113.11'];
const CF_AAAA = ['2001:db8::11'];
const GOOGLE_A = ['198.51.100.21'];
const GOOGLE_AAAA = ['2001:db8::21'];

const { check, finish } = createReporter('doh-source');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── 可编程 fetch 桩：按 host + type 控制「延迟」与「返回哪些记录」 ──
let plan = {};
let callCount = 0;
const EMPTY = { delay: 0, records: [] };

globalThis.fetch = async (url) => {
    const u = new URL(url);
    const host = u.hostname;
    const type = u.searchParams.get('type');
    callCount++;
    const spec = (plan[host] && plan[host][type]) || EMPTY;
    if (spec.delay) await sleep(spec.delay);
    const answers = (spec.records || []).map((data) => ({ type: TYPE_CODE[type] ?? 1, data }));
    return new Response(JSON.stringify({ Answer: answers }), { headers: { 'content-type': 'application/json' } });
};

// ── 假环境：不提供 caches（只走一级 Map，避免 Cache API 干扰时延断言）──
globalThis.caches = undefined;
globalThis.settings = undefined;

/** 每次都拿一个全新的模块实例（= 新的 isolate，一级缓存与进度时间戳都是空的） */
const loadModule = isolateLoader(BUNDLE_PATH);

/** 一个场景：给定两源在 A / AAAA 上的表现，解析一次池，返回 { pool, ms } */
async function resolveOnce(proxyName, hostPlan, target = 'target.example.com') {
    plan = hostPlan;
    const mod = await loadModule();
    const startedAt = Date.now();
    const pool = await mod.resolveProxyIPPool(`${proxyName}:443`, target, '');
    return { pool, ms: Date.now() - startedAt, mod };
}

const BOTH_SOURCES = (a, aaaa) => ({
    [CF_HOST]: { A: a, AAAA: aaaa },
    [GOOGLE_HOST]: { A: a, AAAA: aaaa },
});

async function main() {
    await bundleUtils({
        outFile: BUNDLE_PATH,
        names: ['resolveProxyIPPool', 'dohTimeoutMs', 'dohSourceGraceMs', 'dohWaitStallMs', 'dohWaitBudgetMs'],
    });

    // ── A1：CF 快 / Google 慢 → 用 CF，且不等 Google ──
    {
        const t = await resolveOnce('a1-pool.example.net', {
            [CF_HOST]: { A: { delay: 20, records: CF_A }, AAAA: { delay: 20, records: CF_AAAA } },
            [GOOGLE_HOST]: { A: { delay: 700, records: GOOGLE_A }, AAAA: { delay: 700, records: GOOGLE_AAAA } },
        });
        check('A1 CF 快 / Google 慢：用 CF 的答案', () => {
            assert.deepStrictEqual(asSet(t.pool), asSet([[CF_A[0], 443], [`[${CF_AAAA[0]}]`, 443]]));
        });
        check('A1 不等慢源：耗时不随 Google 的 700ms 增长', () => assert.ok(t.ms < 500, `耗时 ${t.ms}ms`));
        await sleep(750); // 让挂住的 Google 桩收尾，避免污染下一场景的计时
    }

    // ── A2：CF 空 / Google 快 → 用 Google（CF 优先只对非空成立）──
    {
        const t = await resolveOnce('a2-pool.example.net', BOTH_SOURCES(
            { delay: 20, records: [] }, { delay: 20, records: [] },
        ));
        check('A2 CF 空：退到 Google（两源都空时回退成域名本身）', () => {
            assert.deepStrictEqual(asSet(t.pool), ['a2-pool.example.net:443']);
        });

        const t2 = await resolveOnce('a2b-pool.example.net', {
            [CF_HOST]: { A: { delay: 20, records: [] }, AAAA: { delay: 20, records: [] } },
            [GOOGLE_HOST]: { A: { delay: 60, records: GOOGLE_A }, AAAA: { delay: 60, records: GOOGLE_AAAA } },
        });
        check('A2 CF 空 / Google 有记录：用 Google 的答案', () => {
            assert.deepStrictEqual(asSet(t2.pool), asSet([[GOOGLE_A[0], 443], [`[${GOOGLE_AAAA[0]}]`, 443]]));
        });
        check('A2 耗时不随 CF 的计时增长（≈ Google 的 60ms）', () => assert.ok(t2.ms < 400, `耗时 ${t2.ms}ms`));
    }

    // ── A3：Google 先答非空、CF 在宽限期（260ms）内到 → 仍用 CF ──
    {
        const t = await resolveOnce('a3-pool.example.net', {
            [CF_HOST]: { A: { delay: 140, records: CF_A }, AAAA: { delay: 140, records: CF_AAAA } },
            [GOOGLE_HOST]: { A: { delay: 20, records: GOOGLE_A }, AAAA: { delay: 20, records: GOOGLE_AAAA } },
        });
        check('A3 宽限期内 CF 到：仍用 CF（保住「CF 优先」）', () => {
            assert.deepStrictEqual(asSet(t.pool), asSet([[CF_A[0], 443], [`[${CF_AAAA[0]}]`, 443]]));
        });
    }

    // ── A4：Google 先答非空、CF 在宽限期之后才到 → 用 Google ──
    {
        const t = await resolveOnce('a4-pool.example.net', {
            [CF_HOST]: { A: { delay: 900, records: CF_A }, AAAA: { delay: 900, records: CF_AAAA } },
            [GOOGLE_HOST]: { A: { delay: 20, records: GOOGLE_A }, AAAA: { delay: 20, records: GOOGLE_AAAA } },
        });
        check('A4 宽限期外 CF 才到：用 Google（不被卡死的源拖住）', () => {
            assert.deepStrictEqual(asSet(t.pool), asSet([[GOOGLE_A[0], 443], [`[${GOOGLE_AAAA[0]}]`, 443]]));
        });
        check('A4 耗时有界（≈ 20ms + 宽限期，而不是 900ms）', () => assert.ok(t.ms < 700, `耗时 ${t.ms}ms`));
        await sleep(950);
    }

    // ── A5：DOH_SOURCE_GRACE_MS=0 → 谁先到用谁（关掉 CF 优先）──
    {
        plan = {
            [CF_HOST]: { A: { delay: 140, records: CF_A }, AAAA: { delay: 140, records: CF_AAAA } },
            [GOOGLE_HOST]: { A: { delay: 20, records: GOOGLE_A }, AAAA: { delay: 20, records: GOOGLE_AAAA } },
        };
        globalThis.env = { DOH_SOURCE_GRACE_MS: '0' };
        const mod = await loadModule();
        const startedAt = Date.now();
        const pool = await mod.resolveProxyIPPool('a5-pool.example.net:443', 'a5.example.com', '');
        const ms = Date.now() - startedAt;
        globalThis.env = undefined;
        check('A5 宽限期 0：直接用先到的 Google（不再等 CF）', () => {
            assert.deepStrictEqual(asSet(pool), asSet([[GOOGLE_A[0], 443], [`[${GOOGLE_AAAA[0]}]`, 443]]));
        });
        check('A5 耗时 ≈ 20ms（不是 CF 的 140ms）', () => assert.ok(ms < 120, `耗时 ${ms}ms`));
        await sleep(200);
    }

    // ── B：三个 env 旋钮的钳制 / 回退 / 派生关系 ──
    {
        plan = BOTH_SOURCES({ delay: 0, records: CF_A }, { delay: 0, records: [] });
        const mod = await loadModule();
        const warns = [];
        const realWarn = console.warn;
        console.warn = (...args) => { warns.push(args.join(' ')); };
        try {
            globalThis.env = undefined;
            check('B 未设 DOH_TIMEOUT_MS → 默认 500ms', () => assert.strictEqual(mod.dohTimeoutMs(), 500));
            globalThis.env = { DOH_TIMEOUT_MS: '1800' };
            check('B 区间内的值原样生效', () => assert.strictEqual(mod.dohTimeoutMs(), 1800));
            globalThis.env = { DOH_TIMEOUT_MS: 'abc' };
            check('B 非数字 → 回退默认值', () => assert.strictEqual(mod.dohTimeoutMs(), 500));
            globalThis.env = { DOH_TIMEOUT_MS: '0' };
            check('B 显式 0 → 回退默认值（不做「无超时」这种危险语义）', () => assert.strictEqual(mod.dohTimeoutMs(), 500));
            globalThis.env = { DOH_TIMEOUT_MS: '30' };
            check('B 低于下限 → 钳到 50ms', () => assert.strictEqual(mod.dohTimeoutMs(), 50));
            globalThis.env = { DOH_TIMEOUT_MS: '99999' };
            check('B 高于上限 → 钳到 6000ms', () => assert.strictEqual(mod.dohTimeoutMs(), 6000));

            globalThis.env = undefined;
            check('B 未设 DOH_SOURCE_GRACE_MS → 默认 260ms', () => assert.strictEqual(mod.dohSourceGraceMs(), 260));
            globalThis.env = { DOH_SOURCE_GRACE_MS: '100' };
            check('B DOH_SOURCE_GRACE_MS 区间内原样生效', () => assert.strictEqual(mod.dohSourceGraceMs(), 100));
            globalThis.env = { DOH_SOURCE_GRACE_MS: '0' };
            check('B DOH_SOURCE_GRACE_MS=0 → 0（谁先到用谁，关掉 CF 优先）', () => assert.strictEqual(mod.dohSourceGraceMs(), 0));
            globalThis.env = { DOH_SOURCE_GRACE_MS: '99999' };
            check('B DOH_SOURCE_GRACE_MS 高于上限 → 钳到 2000ms', () => assert.strictEqual(mod.dohSourceGraceMs(), 2000));

            globalThis.env = undefined;
            check('B 未设 DOH_WAIT_STALL_MS → 默认 260ms', () => assert.strictEqual(mod.dohWaitStallMs(), 260));
            globalThis.env = { DOH_WAIT_STALL_MS: '150' };
            check('B DOH_WAIT_STALL_MS 区间内原样生效', () => assert.strictEqual(mod.dohWaitStallMs(), 150));
            globalThis.env = { DOH_WAIT_STALL_MS: '30' };
            check('B DOH_WAIT_STALL_MS 低于下限 → 钳到 50ms', () => assert.strictEqual(mod.dohWaitStallMs(), 50));
            globalThis.env = { DOH_WAIT_STALL_MS: '99999' };
            check('B DOH_WAIT_STALL_MS 高于派生上限 → 钳到 min(3000, 500−50) = 450ms', () => assert.strictEqual(mod.dohWaitStallMs(), 450));
            globalThis.env = { DOH_TIMEOUT_MS: '100', DOH_WAIT_STALL_MS: '99999' };
            check('B 派生上限跟随 DOH_TIMEOUT_MS（超时 100 → 上限 50）', () => assert.strictEqual(mod.dohWaitStallMs(), 50));

            globalThis.env = undefined;
            check('B 未设 DOH_WAIT_BUDGET_MS → 默认 1000ms', () => assert.strictEqual(mod.dohWaitBudgetMs(), 1000));
            globalThis.env = { DOH_WAIT_BUDGET_MS: '2500' };
            check('B DOH_WAIT_BUDGET_MS 区间内原样生效', () => assert.strictEqual(mod.dohWaitBudgetMs(), 2500));
            globalThis.env = { DOH_WAIT_BUDGET_MS: '10' };
            check('B DOH_WAIT_BUDGET_MS 低于下限 → 钳到 50ms', () => assert.strictEqual(mod.dohWaitBudgetMs(), 50));
            globalThis.env = { DOH_WAIT_BUDGET_MS: '99999' };
            check('B DOH_WAIT_BUDGET_MS 高于上限 → 钳到 10000ms', () => assert.strictEqual(mod.dohWaitBudgetMs(), 10000));

            check('B 越界各打一条 warn（按 name=原始值 去重）', () => {
                assert.ok(warns.some((l) => l.includes('DOH_TIMEOUT_MS=30')), warns.join(' | '));
                assert.ok(warns.some((l) => l.includes('DOH_TIMEOUT_MS=99999')), warns.join(' | '));
                assert.ok(warns.some((l) => l.includes('DOH_SOURCE_GRACE_MS=99999')), warns.join(' | '));
                assert.ok(warns.some((l) => l.includes('DOH_WAIT_STALL_MS=30')), warns.join(' | '));
                assert.ok(warns.some((l) => l.includes('DOH_WAIT_BUDGET_MS=10')), warns.join(' | '));
                assert.ok(warns.some((l) => l.includes('DOH_WAIT_BUDGET_MS=99999')), warns.join(' | '));
            });
        } finally {
            console.warn = realWarn;
            globalThis.env = undefined;
        }

        // 接线：生效值必须真的落到 AbortSignal.timeout 上
        const captured = [];
        const realTimeout = AbortSignal.timeout;
        globalThis.env = { DOH_TIMEOUT_MS: '1200' };
        AbortSignal.timeout = (ms) => { captured.push(ms); return new AbortController().signal; };
        try {
            await resolveOnce('b-wire-pool.example.net', BOTH_SOURCES({ delay: 0, records: CF_A }, { delay: 0, records: [] }));
        } finally {
            AbortSignal.timeout = realTimeout;
            globalThis.env = undefined;
        }
        check('B 生效值真的接到 AbortSignal.timeout（每源一次）', () => {
            assert.ok(captured.length >= 2, `捕获 ${captured.length} 次`);
            assert.ok(captured.every((ms) => ms === 1200), captured.join(','));
        });
    }

    // ── C1：无进展 → 等待方 260ms 就自己上 ──
    {
        const SLOW = 700;
        plan = BOTH_SOURCES({ delay: SLOW, records: CF_A }, { delay: SLOW, records: [] });
        const mod = await loadModule();
        const before = callCount;
        const startedAt = Date.now();
        const first = mod.resolveProxyIPPool('c1-pool.example.net:443', 'c1.example.com', '');
        await sleep(30);            // 让生产者先进到 DoH（此时四条都挂住 = 没有任何进展）
        const second = mod.resolveProxyIPPool('c1-pool.example.net:443', 'c1.example.com', '');
        const [r1, r2] = await Promise.all([first, second]);
        const ms = Date.now() - startedAt;
        check('C1 无进展 260ms：等待方自己上（4 + 4 = 8 次 DoH，而不是干等满总上界）', () => {
            assert.strictEqual(callCount - before, 8, `实际 ${callCount - before} 次`);
        });
        check('C1 两条连接拿到同一份池，且总耗时不接近总上界（1000ms）', () => {
            assert.deepStrictEqual(asSet(r2), asSet(r1));
            // 区分度：stall(260) 生效 → ≈700ms（两条管线并行跑完）；若 stall 失效、由总上界兜底
            // → 1000 + 700 = 1700ms。取 1200 作为分界，留 500ms 的 CI 抖动余量。
            assert.ok(ms < 1200, `耗时 ${ms}ms`);
        });
    }

    // ── C2：有进展 → 继续等，仍只解析一次 ──
    {
        // A 在 100ms 完成（两条源都算进展），AAAA 在 260ms 完成 —— 中间间隔 160ms < 260ms，
        // 所以等待方应当继续等，最终命中生产者写入的一级缓存，而不是自己再解析一轮。
        plan = BOTH_SOURCES({ delay: 100, records: CF_A }, { delay: 260, records: [] });
        const mod = await loadModule();
        const before = callCount;
        const first = mod.resolveProxyIPPool('c2-pool.example.net:443', 'c2.example.com', '');
        await sleep(10);
        const second = mod.resolveProxyIPPool('c2-pool.example.net:443', 'c2.example.com', '');
        const [r1, r2] = await Promise.all([first, second]);
        check('C2 有进展就继续等：只解析一次（4 次 DoH）', () => {
            assert.strictEqual(callCount - before, 4, `实际 ${callCount - before} 次`);
            assert.deepStrictEqual(asSet(r2), asSet(r1));
        });
    }

    // ── C3：把阈值调大（env）后，慢但会完成的解析不再被重复 ──
    {
        // 阈值 900ms（派生上限 3000ms 内，允许）：生产者 700ms 完成，等待方应当等到它，而不是
        // 在 260ms 处自己上。顺带钉住「阈值确实来自 env，而不是写死的 260」。
        plan = BOTH_SOURCES({ delay: 700, records: CF_A }, { delay: 700, records: [] });
        globalThis.env = { DOH_TIMEOUT_MS: '6000', DOH_WAIT_STALL_MS: '900' };
        const mod = await loadModule();
        const before = callCount;
        const first = mod.resolveProxyIPPool('c3-pool.example.net:443', 'c3.example.com', '');
        await sleep(30);
        const second = mod.resolveProxyIPPool('c3-pool.example.net:443', 'c3.example.com', '');
        const [r1, r2] = await Promise.all([first, second]);
        globalThis.env = undefined;
        check('C3 阈值调大（900ms）：慢解析只做一次（4 次 DoH）', () => {
            assert.strictEqual(callCount - before, 4, `实际 ${callCount - before} 次`);
            assert.deepStrictEqual(asSet(r2), asSet(r1));
        });
    }

    // ── C4：总上界 env 生效——预算小于 stall 时，由预算先到（谁更紧谁说话）──
    {
        // DoH 700ms 挂住（无进展），stall 默认 260、预算压到 100 → 预算先到（100 < 260）：
        // 等待方在 ~100ms 就自己上 → 4 + 4 = 8 次。若预算被忽略（仍是 1000），则 stall 在 260
        // 才触发，两者都会给 8 次 —— 所以再加一条耗时断言来区分：总耗时应接近 700ms（两条管线
        // 并行跑完），而不是 260 + 700 = 960ms。
        plan = BOTH_SOURCES({ delay: 700, records: CF_A }, { delay: 700, records: [] });
        globalThis.env = { DOH_WAIT_BUDGET_MS: '100' };
        const mod = await loadModule();
        const before = callCount;
        const startedAt = Date.now();
        const first = mod.resolveProxyIPPool('c4-pool.example.net:443', 'c4.example.com', '');
        await sleep(10);
        const second = mod.resolveProxyIPPool('c4-pool.example.net:443', 'c4.example.com', '');
        const [r1, r2] = await Promise.all([first, second]);
        const ms = Date.now() - startedAt;
        globalThis.env = undefined;
        check('C4 预算 100ms 生效：等待方在预算处自己上（4 + 4 = 8 次）', () => {
            assert.strictEqual(callCount - before, 8, `实际 ${callCount - before} 次`);
            assert.deepStrictEqual(asSet(r2), asSet(r1));
        });
        check('C4 比 stall(260) 更早放手：总耗时接近 700ms 而不是 960ms', () => assert.ok(ms < 860, `耗时 ${ms}ms`));
    }

    finish();
}

await main();
