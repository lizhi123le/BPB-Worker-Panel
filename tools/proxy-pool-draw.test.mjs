/**
 * tools/proxy-pool-draw.test.mjs
 *
 * 反代池「全量入池 + 抽取时按临时黑名单过滤 + 随机抽 8 条 → 2 秒探测 → 分批竞速」的行为测试。
 * 运行：node tools/proxy-pool-draw.test.mjs
 *
 * 为什么需要它：这套逻辑全在 WS 内部（resolveProxyIPPool + connectWithRaceDial），smoke 用例
 * 连不了真 TCP，所以这里用「早期数据」把合法 VLESS 首包喂进 write()，并用
 *   globalThis.connect  → 可编程的 TCP 桩（按 IP 决定 connect 立即失败还是 3ms 成功）
 *   globalThis.fetch    → DoH 桩（按查询域名返回对应的 A 记录集合；AAAA 为空）
 * 把真实连接路径跑起来；env.PROXY_IP（或 KV proxyIPs）+ `?qj=only`（仅走代理）让首跳必然是反代池竞速。
 *
 * 覆盖：
 *   1. 解析出的候选**全部**入池：日志 `got 14 IPs`（改动前解析期 slice(0,8) 只留 8 条、
 *      其余 6 条连探测机会都没有，且这份残缺池被冻结 10 分钟）
 *   2. 每连接最多抽 8 条参与可达性探测
 *   3. 探测不通的候选进临时黑名单（30s 起指数退避）并从抽取集合隐退（日志 in backoff 计数到 6）
 *   4. 退避到期后重新回到池中参与抽取（等 31s 后再次被抽中）
 *   5. 大池不截断：实测地区池 SG/JP/通用有 50 条 A 记录，必须**全部**在对应地区池里
 *      （曾经按 32 条截断，被砍掉的 18 条连 2 秒探测机会都没有）
 *   6. 地区隔离：面板按 `@地区` 锚定的条目，wk=KR/SG 时各自只解析并抽取本地区的池，
 *      不混入其它地区的 IP
 *
 * 前提：先构建过（`NODE_ENV=mangle node scripts/build.js`），本测试加载
 * .build/worker.reference.js（混淆前产物，行为等价且可读）。
 */
import { existsSync } from 'fs';
import { pathToFileURL } from 'url';

const BUNDLE = '.build/worker.reference.js';
const UUID = '11111111-2222-4333-8444-555555555555';
const TR_PASS = 'trojan-secret';
const ORIGIN = 'https://panel.example.com';
const PROXY_DOMAIN = 'pool.example.net';
const BIG_DOMAIN = 'big-pool.example.net';
const KR_DOMAIN = 'kr-pool.example.net';
const SG_DOMAIN = 'sg-pool.example.net';
const TARGET = 'ipv4.icanhazip.com';

// 14 条候选：前 6 条「不通」（connect 立即失败），后 8 条「通」（3ms 建连）
const POOL = Array.from({ length: 14 }, (_, i) => `10.20.0.${i + 1}`);
const FAILING = new Set(POOL.slice(0, 6));
const HEALTHY = new Set(POOL.slice(6));
// 大池：对齐实测地区池规模（SG/JP/通用 = 50 条 A 记录），验证「解析出多少就全量入池」
const BIG_POOL = Array.from({ length: 50 }, (_, i) => `10.30.0.${i + 1}`);
// 两个不同地区的池（真实地区池互不重叠），用于验证 @地区 锚定的池隔离
const KR_POOL = Array.from({ length: 12 }, (_, i) => `10.40.0.${i + 1}`);
const SG_POOL = Array.from({ length: 12 }, (_, i) => `10.50.0.${i + 1}`);
const BLACKLIST_BASE_TTL_MS = 30 * 1000; // IP_BLACKLIST_TTL：等过它才能验证「回池」
const CONN_WAIT_MS = 300;                // 每次连接后等它的探测/拨号跑完

let failures = 0;
const out = (...args) => process.stdout.write(args.join(' ') + '\n');
const check = (name, ok, detail = '') => {
    out(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
    if (!ok) failures++;
};

// ── VLESS 首包：ver(1) + uuid(16) + optLen(1) + cmd(1) + port(2) + atyp(1) + 域名字节
function vlessDomainPacket(domain, port = 443) {
    const head = [0, ...UUID.split('-').join('').match(/../g).map((h) => parseInt(h, 16)), 0, 1, port >> 8, port & 0xff, 2];
    const d = [...Buffer.from(domain, 'utf8')];
    return Uint8Array.from([...head, d.length, ...d]);
}

function makeKv(seed = {}) {
    const store = new Map(Object.entries(seed));
    return {
        // KV 的 get 必须支持 { type: 'json' }：proxySettings 以 JSON 字符串存放，
        // 读的时候要解成对象（少了这一步，阶段 D 的 KV 配置会被当成字符串，Object.assign 展开成字符下标）
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
}

if (!existsSync(BUNDLE)) {
    console.error(`找不到 ${BUNDLE} —— 请先构建：NODE_ENV=mangle node scripts/build.js`);
    process.exit(1);
}

// ── 桩：Response 101 / WebSocketPair / connect / fetch / console
const RealResponse = globalThis.Response;
globalThis.Response = class extends RealResponse {
    constructor(body, init = {}) {
        if (init && init.status === 101) {
            super(null);
            Object.defineProperty(this, 'status', { value: 101, configurable: true });
            Object.defineProperty(this, 'webSocket', { value: init.webSocket, configurable: true });
        } else {
            super(body, init);
        }
    }
};

globalThis.WebSocketPair = class {
    constructor() {
        const make = () => ({
            readyState: 1,
            listeners: {},
            sent: [],
            closed: new Promise(() => {}),
            accept() {},
            addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); },
            removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn); },
            send(payload) { this.sent.push(payload); },
            close() {}
        });
        this[0] = make();
        this[1] = make();
    }
};

/** 本次连接内所有 TCP 建连尝试（探测 + 竞速拨号都会打到这里） */
let dialedThisConnection = [];
globalThis.connect = ({ hostname, port }) => {
    dialedThisConnection.push(`${hostname}:${port}`);
    let resolveOpened;
    let rejectOpened;
    const opened = new Promise((res, rej) => { resolveOpened = res; rejectOpened = rej; });
    opened.catch(() => {}); // 未被 await 的分支也别变成 unhandled rejection
    const socket = {
        opened,
        closed: new Promise(() => {}),
        readable: new ReadableStream({ start() {} }), // 永不产出：避免 remoteSocketToWS 早退
        writable: new WritableStream({ write() {} }),
        close() {}
    };
    if (FAILING.has(hostname)) rejectOpened(new Error('ECONNREFUSED'));
    else setTimeout(resolveOpened, 3);
    return socket;
};

/** DoH 桩当前返回的 A 记录集合（阶段 C 换成 50 条的大池以验证不截断） */
let dohIps = POOL;
/** 按查询域名返回对应的 A 记录集合：不同地区域名 = 各自独立的池 */
function dohRecordsFor(name) {
    const n = name.toLowerCase();
    if (n.includes('kr-pool')) return KR_POOL;
    if (n.includes('sg-pool')) return SG_POOL;
    return dohIps;
}
globalThis.fetch = async (url) => {
    const u = String(url);
    const isDoh = u.includes('cloudflare-dns.com') || u.includes('dns.google');
    if (isDoh) {
        const name = decodeURIComponent(/[?&]name=([^&]+)/.exec(u)?.[1] ?? '');
        const type = /[?&]type=(A|AAAA)/.exec(u)?.[1] ?? 'A';
        const ips = type === 'AAAA' ? [] : dohRecordsFor(name);
        const answer = ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip }));
        return new RealResponse(JSON.stringify({ Status: 0, Answer: answer }), {
            headers: { 'content-type': 'application/dns-json' }
        });
    }
    // warp 账号等旁路请求：给个必然走内置回退的空体
    return new RealResponse(JSON.stringify({}), { headers: { 'content-type': 'application/json' } });
};

const logs = [];
const originalConsole = {};
for (const level of ['log', 'info', 'warn', 'error', 'debug']) {
    originalConsole[level] = console[level];
    console[level] = (...args) => { logs.push(args.map((a) => (a && a.message) ? a.message : String(a)).join(' ')); };
}

const handler = (await import(pathToFileURL(BUNDLE).href)).default;
const ctx = { waitUntil() {}, passThroughOnException() {} };
const env = {
    UUID,
    TR_PASS,
    SUB_PATH: 'ws-test-sub-path',
    PROXY_IP: PROXY_DOMAIN, // 反代池实体：hasCustomProxyIPs=true
    FALLBACK: 'www.hcaptcha.com',
    kv: makeKv()
};

const PACKET = vlessDomainPacket(TARGET);

/** 发一次 WS 升级（仅走代理模式），等首包处理跑完，返回本次观测 */
async function runConnection(query = '?qj=only') {
    dialedThisConnection = [];
    logs.length = 0;
    const earlyData = Buffer.from(PACKET).toString('base64url');
    const request = new Request(`${ORIGIN}/${query}`, {
        headers: {
            Host: 'panel.example.com',
            Upgrade: 'websocket',
            'sec-websocket-protocol': earlyData
        }
    });
    const response = await handler.fetch(request, env, ctx);
    await new Promise((r) => setTimeout(r, CONN_WAIT_MS));
    const probed = new Set(dialedThisConnection.map((k) => k.split(':')[0]));
    const drawLog = logs.find((l) => /got \d+ IPs for proxy .* drawing \d+/.test(l)) || '';
    const m = /got (\d+) IPs for proxy .* drawing (\d+) \((\d+) in backoff\)/.exec(drawLog);
    return {
        status: response.status,
        dialed: [...dialedThisConnection],
        probed,
        poolSize: m ? Number(m[1]) : null,
        drawn: m ? Number(m[2]) : null,
        inBackoff: m ? Number(m[3]) : null,
        drawLog
    };
}

// ── 阶段 A：全量入池 + 抽取上限 + 探测失败退避
out(`— 阶段 A：解析池 ${POOL.length} 条（${FAILING.size} 条不通）→ 全量入池、抽 8 条、坏候选退避 —`);

const seenProbed = new Set();
const retiredFailures = new Set();
let firstConnection = null;
let maxDrawn = 0;
let maxPool = 0;
let maxBackoff = 0;
let lastFailObservedAt = 0;
let cleanStreak = 0;
let maxCleanStreak = 0;

for (let i = 0; i < 22; i++) {
    const r = await runConnection();
    if (i === 0) firstConnection = r;
    if (r.status !== 101) check(`第 ${i + 1} 次连接：升级返回 101`, false, `status=${r.status}`);

    if (r.poolSize !== null) maxPool = Math.max(maxPool, r.poolSize);
    if (r.drawn !== null) maxDrawn = Math.max(maxDrawn, r.drawn);
    if (r.inBackoff !== null) maxBackoff = Math.max(maxBackoff, r.inBackoff);

    const drewFailing = [...r.probed].filter((ip) => FAILING.has(ip));
    if (drewFailing.length === 0) {
        cleanStreak++;
        maxCleanStreak = Math.max(maxCleanStreak, cleanStreak);
    } else {
        cleanStreak = 0;
        for (const ip of drewFailing) retiredFailures.add(ip);
        lastFailObservedAt = Date.now();
    }
    for (const ip of r.probed) seenProbed.add(ip);

    // 6 条坏候选全部退避过、且已经连续 4 次连接不再抽到它们 → 阶段 A 达标，提前收尾
    if (retiredFailures.size === FAILING.size && cleanStreak >= 4) break;
}

check('解析出的候选全部入池（日志 got 14，而不是被 slice(0,8) 砍成 8）',
    firstConnection?.poolSize === POOL.length,
    `poolSize=${firstConnection?.poolSize} log=${firstConnection?.drawLog}`);
check('每连接抽取条数 ≤ 8',
    maxDrawn > 0 && maxDrawn <= 8,
    `maxDrawn=${maxDrawn}`);
check('每连接抽取条数 = 8（可用候选充足时填满槽位）',
    firstConnection?.drawn === 8,
    `firstConnection.drawn=${firstConnection?.drawn}`);
check('抽取覆盖池内全部 14 条候选（改动前只有固定 8 条有机会被用到）',
    seenProbed.size === POOL.length,
    `probed=${[...seenProbed].sort().join(',')}`);
check('6 条不通的候选都被探测到并退避',
    retiredFailures.size === FAILING.size,
    `retired=${[...retiredFailures].sort().join(',')}`);
check('退避计数达到 6（日志 in backoff：坏候选已从抽取集合隐退）',
    maxBackoff === FAILING.size,
    `maxBackoff=${maxBackoff}`);
check('退避生效后连续 ≥4 次连接不再抽到不通的候选',
    maxCleanStreak >= 4,
    `maxCleanStreak=${maxCleanStreak}`);
check('通的候选仍一直在被抽取（池未被打空）',
    [...HEALTHY].every((ip) => seenProbed.has(ip)),
    `probed=${[...seenProbed].sort().join(',')}`);

// ── 阶段 B：退避到期 → 重新回池参与抽取
const waitMs = Math.max(0, lastFailObservedAt + BLACKLIST_BASE_TTL_MS + 1000 - Date.now());
out(`— 阶段 B：等待退避到期 ${Math.ceil(waitMs / 1000)}s 后，坏候选应重新回池参与抽取 —`);
await new Promise((r) => setTimeout(r, waitMs));

let reEntered = null;
for (let i = 0; i < 12; i++) {
    const r = await runConnection();
    const again = [...r.probed].filter((ip) => FAILING.has(ip));
    if (again.length > 0) {
        reEntered = { attempt: i + 1, ips: again, log: r.drawLog };
        break;
    }
}
check('退避到期后坏候选重新进入抽取集合（临时黑名单不是永久封禁）',
    reEntered !== null,
    reEntered ? `第 ${reEntered.attempt} 次连接抽到 ${reEntered.ips.join(',')}` : '等待 12 次连接仍未回池');

// ── 阶段 C：大池全量入池（真实地区池 SG/JP/通用 实测 50 条 A）
out(`— 阶段 C：换成 ${BIG_POOL.length} 条的池（对齐实测地区池规模），解析出多少就应入池多少 —`);
dohIps = BIG_POOL;
env.PROXY_IP = BIG_DOMAIN;
const big = await runConnection();
check(`${BIG_POOL.length} 条全部入池（不再被任何条数上限截断）`,
    big.poolSize === BIG_POOL.length,
    `poolSize=${big.poolSize} log=${big.drawLog}`);
check('大池仍只抽 8 条参与 2 秒探测',
    big.drawn === 8,
    `drawn=${big.drawn}`);
check('大池抽出的候选都来自该池',
    big.probed.size > 0 && [...big.probed].every((ip) => BIG_POOL.includes(ip)),
    `probed=${[...big.probed].join(',')}`);

// ── 阶段 D：地区隔离（面板按 @地区 锚定的两条域名 + wk 指定地区）
//    KV 里放两个带 @地区标签的条目；wk=KR 时必须只解析/抽取 KR 域名解析出的池，绝不混入 SG；
//    wk=SG 同理。这条钉住「不同地区 = 不同池」不被后续改动破坏。
out('— 阶段 D：KV 配 KR/SG 两个 @地区 条目，wk=KR / wk=SG 应各自只用本地区的池 —');
env.kv = makeKv({
    proxySettings: JSON.stringify({
        proxyIPs: [`${KR_DOMAIN}:443@KR`, `${SG_DOMAIN}:443@SG`],
        regionMatch: true
    }),
    proxySettings_ver: 'v-region-test'
});
// 强制 KV 缓存失效（等价于 clearKvCache）：否则 5 分钟 TTL 内不会重读 KV，新配置不生效
if (globalThis.__kvCache) globalThis.__kvCache.timestamp = 0;

const krRun = await runConnection('?qj=only&wk=KR');
check('wk=KR 时选中的是本地区（KR）域名',
    krRun.drawLog.includes(KR_DOMAIN),
    `log=${krRun.drawLog}`);
check('wk=KR 时抽取的候选全部来自 KR 池',
    krRun.probed.size > 0 && [...krRun.probed].every((ip) => KR_POOL.includes(ip)),
    `probed=${[...krRun.probed].sort().join(',')}`);
check('wk=KR 时绝不混入 SG 池的 IP',
    ![...krRun.probed].some((ip) => SG_POOL.includes(ip)),
    `probed=${[...krRun.probed].sort().join(',')}`);

const sgRun = await runConnection('?qj=only&wk=SG');
check('wk=SG 时选中的是本地区（SG）域名',
    sgRun.drawLog.includes(SG_DOMAIN),
    `log=${sgRun.drawLog}`);
check('wk=SG 时抽取的候选全部来自 SG 池（不同地区 = 不同池）',
    sgRun.probed.size > 0 && [...sgRun.probed].every((ip) => SG_POOL.includes(ip)),
    `probed=${[...sgRun.probed].sort().join(',')}`);
check('wk=SG 时绝不混入 KR 池的 IP',
    ![...sgRun.probed].some((ip) => KR_POOL.includes(ip)),
    `probed=${[...sgRun.probed].sort().join(',')}`);

for (const level of ['log', 'info', 'warn', 'error', 'debug']) console[level] = originalConsole[level];

out(failures === 0 ? '\nproxy-pool-draw: OK' : `\nproxy-pool-draw: ${failures} 项失败`);
process.exit(failures === 0 ? 0 : 1);
