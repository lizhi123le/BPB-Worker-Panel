/**
 * tools/proxy-ip-limit.test.mjs
 *
 * /proxy-ip（面板「Proxy IPs」信息页）取数规则的行为测试。运行：node tools/proxy-ip-limit.test.mjs
 * （package.json 里是 `npm run test:proxyip`）
 *
 * 规则（handlers.ts getProxyIPsInfo）：
 *   1. 域名解析 A + AAAA（纯 v6 的中继也要能在表里出现，不能只查 A）；
 *   2. 两类合计 ≤ 100 条 → 全部显示；
 *   3. 超过 100 条 → 按 1:1 各加入一半（各 50），某一类不够就从**还有剩余**的那一类补齐到 100 条；
 *   4. 送进 geoLookupBatch 的条数因此恒 ≤ 100（ip-api /batch 的单次上限），永远只发一个批次。
 *
 * 为什么需要它：这条规则有一堆边界形态（不足 100 / 恰好 100 / 单类超 100 / 两类悬殊 / 纯 v6 …），
 * 而它决定的是页面上用户能复制到哪些中继地址；期望值在测试里用**独立公式**重算一遍，
 * 不照着实现抄，避免"实现怎么写都判绿"。
 *
 * 打桩：出站 fetch 只服务两件事 —— DoH（按 type 返回本次形状的 A / AAAA）与 ip-api /batch（回显）。
 * 走真实链路：/login/authenticate 拿会话 → GET /proxy-ip/get（该接口需要登录态）。
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
const LIMIT = 100;

let failures = 0;
// 接管 console：Worker 日志收进 workerLogs（构建闸门输出只剩 PASS/FAIL，失败时回放）
const out = (...args) => process.stdout.write(args.join(' ') + '\n');
const workerLogs = [];
for (const level of ['log', 'info', 'warn', 'error', 'debug']) {
    console[level] = (...args) => { workerLogs.push(args.map((a) => (a && a.message) ? a.message : String(a)).join(' ')); };
}
process.on('exit', () => {
    if (failures > 0) process.stdout.write('\n--- 捕获到的 Worker 日志 ---\n' + workerLogs.join('\n') + '\n');
});
const check = (name, ok, detail = '') => {
    out(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
    if (!ok) failures++;
};

if (!existsSync(BUNDLE)) {
    console.error(`找不到 ${BUNDLE} —— 请先构建：npm run build`);
    process.exit(1);
}

/** 本次形状（由各用例设置）与最近一次 ip-api 批次 */
let shape = { v4: 0, v6: 0 };
let lastBatch = [];

globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    if (u.includes('cloudflare-dns.com') || u.includes('dns.google')) {
        // 注意交替顺序：写成 (A|AAAA) 时 `type=AAAA` 会先匹配到 A，AAAA 查询会被当成 A 查询返回
        const type = /[?&]type=(AAAA|A)/.exec(u)?.[1] ?? 'A';
        const isV6 = type === 'AAAA';
        const count = isV6 ? shape.v6 : shape.v4;
        const ips = Array.from({ length: count }, (_, i) => isV6 ? `2001:db8:${i + 1}::1` : `10.70.${Math.floor(i / 250)}.${(i % 250) + 1}`);
        const answer = ips.map((data) => ({ name: 'x.', type: isV6 ? 28 : 1, TTL: 300, data }));
        return new Response(JSON.stringify({ Status: 0, Answer: answer }), { headers: { 'content-type': 'application/dns-json' } });
    }
    if (u.includes('ip-api.com')) {
        lastBatch = JSON.parse(String(init.body || '[]'));
        return new Response(JSON.stringify(lastBatch.map((ip) => ({
            query: ip, city: 'City', country: 'Country', countryCode: 'ZZ', isp: 'ISP', status: 'success'
        }))), { headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({}), { headers: { 'content-type': 'application/json' } });
};

const store = new Map([['pwd', PWD]]);
const kv = {
    async get(key, opts) {
        const value = store.has(key) ? store.get(key) : null;
        if (value === null) return null;
        if (opts && opts.type === 'json') return typeof value === 'string' ? JSON.parse(value) : value;
        return value;
    },
    async put(key, value) { store.set(key, value); },
    async delete(key) { store.delete(key); },
    async list() { return { keys: [], list_complete: true, cursor: '' }; }
};
const env = { UUID, TR_PASS, SUB_PATH: 'p', FALLBACK: 'www.hcaptcha.com', PUBLIC_PROXY_IP: 'shape.example.net', kv };
const ctx = { waitUntil() {}, passThroughOnException() {} };

const handler = (await import(pathToFileURL(BUNDLE).href)).default;
if (!handler || typeof handler.fetch !== 'function') throw new Error(`${BUNDLE} 没有 default.fetch()`);

const call = (path, init = {}) => handler.fetch(new Request(ORIGIN + path, {
    ...init, headers: { Host: 'panel.example.com', ...(init.headers || {}) }
}), env, ctx);

const login = await call('/login/authenticate', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: PWD });
const cookie = (login.headers.get('set-cookie') || '').match(/jwtToken=([^;]+)/)?.[1] || '';
check('拿到会话（/proxy-ip/get 需要登录态）', cookie.length > 10, `set-cookie=${(login.headers.get('set-cookie') || '').slice(0, 60)}`);

/**
 * 期望条数：与实现**同规格、独立重算**（不 import 生产代码，也不用实现里的变量名）；
 * 这样实现若被改成别的规则，这里会立刻不符。
 */
function expected(v4, v6) {
    const half = LIMIT / 2;
    const base4 = Math.min(v4, half);
    const base6 = Math.min(v6, half);
    const gap = LIMIT - base4 - base6;
    const fill4 = Math.min(v4 - base4, gap);
    const fill6 = Math.min(v6 - base6, gap - fill4);
    return { v4: base4 + fill4, v6: base6 + fill6 };
}

async function measure(v4, v6) {
    shape = { v4, v6 };
    env.PUBLIC_PROXY_IP = `shape-${v4}-${v6}.example.net`;
    lastBatch = [];
    const res = await call('/proxy-ip/get', { headers: { cookie: `jwtToken=${cookie}` } });
    const json = await res.json();
    const ips = (json.body || []).map((item) => item.ip);
    return {
        status: res.status,
        total: ips.length,
        v4: ips.filter((ip) => !ip.includes(':')).length,
        v6: ips.filter((ip) => ip.includes(':')).length,
        batch: lastBatch.length
    };
}

// ── 形状表：[A 条数, AAAA 条数] → 期望（由 expected() 现算）
// 覆盖：不足 100、恰好 100、单类超 100、两类悬殊（含"大 v4 + 小 v6"这种真实形态）、纯 v4、纯 v6
const SHAPES = [
    [6, 4], [68, 0], [99, 1], [100, 0], [101, 0], [500, 0],
    [500, 4], [4, 500], [30, 500], [500, 30], [50, 50], [0, 500], [3, 2], [1, 1],
    [106, 8], [120, 1], [200, 20]
];

out(`— /proxy-ip 取数规则：合计 ≤ ${LIMIT} 全列；超出则 1:1 各半，不足从多的那类补齐到 ${LIMIT} —`);
for (const [v4, v6] of SHAPES) {
    const got = await measure(v4, v6);
    const exp = expected(v4, v6);
    check(`A=${v4} / AAAA=${v6} → ${exp.v4} v4 + ${exp.v6} v6（合计 ${exp.v4 + exp.v6}）`,
        got.status === 200 && got.v4 === exp.v4 && got.v6 === exp.v6,
        `实际 v4=${got.v4} v6=${got.v6} status=${got.status}`);
    check(`A=${v4} / AAAA=${v6} → ip-api 只收展示的这些（恒 ≤ ${LIMIT}，单批次）`,
        got.batch === got.total && got.total <= LIMIT,
        `批次=${got.batch} 展示=${got.total}`);
}

// 收口：说明这两条是整个规则的核心不变量
const big = await measure(500, 500);
check('双类都远超上限时正好各 50 条（1:1）', big.v4 === 50 && big.v6 === 50, `v4=${big.v4} v6=${big.v6}`);
const pureV6 = await measure(0, 500);
check('纯 v6 中继也能把表填满（此前只查 A，这类域名在页面上永远是空的）',
    pureV6.v4 === 0 && pureV6.v6 === LIMIT, `v4=${pureV6.v4} v6=${pureV6.v6}`);

out(failures === 0 ? '\nproxy-ip-limit: OK' : `\nproxy-ip-limit: ${failures} 项失败`);
process.exit(failures === 0 ? 0 : 1);
