/**
 * tools/proxy-pool-draw.test.mjs
 *
 * 反代池「全量入池 + 抽取时按临时黑名单过滤 + 随机抽 6 条 → 可达性探测 → 分批竞速」的行为测试。
 * 运行：node tools/proxy-pool-draw.test.mjs
 *
 * 为什么需要它：这套逻辑全在 WS 内部（resolveProxyIPPool + connectWithRaceDial），smoke 用例
 * 连不了真 TCP，所以这里用「早期数据」把合法 VLESS 首包喂进 write()，并用
 *   globalThis.connect  → 可编程的 TCP 桩（按 IP 决定 connect 立即失败 / 3ms 成功 / 首次建连慢 SLOW_MS）
 *   globalThis.fetch    → DoH 桩（按查询域名 + 查询类型返回对应的 A / AAAA 记录集合）
 * 把真实连接路径跑起来；env.PROXY_IP（或 KV proxyIPs）+ `?qj=only`（仅走代理）让首跳必然是反代池竞速。
 *
 * 覆盖：
 *   1. 解析出的候选**全部**入池：日志 `got 14 IPs`（改动前解析期 slice(0,8) 只留 8 条、
 *      其余 6 条连探测机会都没有，且这份残缺池被冻结 10 分钟）
 *   2. 每连接最多抽 RACE_PROBE_COUNT=6 条参与可达性探测
 *   3. 探测按 **3 条滚动窗口**限流：事件序列里开头连续 start 的次数必须是 3
 *      （不是 6 —— 一次性全发会把峰值顶到运行时「单请求并发出站连接」配额的边界上，
 *      改动前 8 条时超出的候选是被直接拒绝的：那种假失败会被当成「候选不通」记进黑名单，
 *      连锁误杀好候选）
 *   4. 探测不通的候选进临时黑名单（30s 起指数退避）并从抽取集合隐退（日志 in backoff 计数到 6）
 *   5. 退避到期后重新回到池中参与抽取（等 31s 后再次被抽中）
 *   6. 大池不截断：实测地区池 SG/JP/通用有 50 条 A 记录，必须**全部**在对应地区池里
 *      （曾经按 32 条截断，被砍掉的 18 条连一次探测机会都没有）
 *   7. 地区隔离：面板按 `@地区` 锚定的条目，wk=KR/SG 时各自只解析并抽取本地区的池，
 *      不混入其它地区的 IP
 *   8. 不砍 IPv6：解析 A + AAAA 时，AAAA 以 `[v6]` 入池并**同等参与**抽取与探测
 *      （回归钉：防止以后有人把 v6 候选过滤掉，或用 `split(':')` 之类把 v6 键解析坏）
 *   9. 指定地区 + 默认模式 + CF 目标：反代池（含内置兜底）应该是池首跳的**第一优先**，
 *      成功即不再拨官方直连池（官方池只留在回退阶梯的下一级）
 *  10. 探测即预连接：第一条候选一被测通，它那条**已建好的 socket** 直接接管成数据连接，首包在
 *      「等整批探测收口」之前就发出去 —— 日志是 `race dial winner (probe socket` 且没有
 *      `race dialing batch`；接管**不新开连接**（connect 次数 = 探测条数，峰值仍 ≤ 3）
 *  11. 探测总预算的 env 覆盖与钳制（`PROBE_PHASE_BUDGET_MS`）：默认 300ms、可调区间 50~3000ms。
 *      过小值（10）钳到下限 50ms 并告警 —— 此时慢候选（首连 1.4s）第一波全部探测超时判死、
 *      没有可接管对象，必须退回批次循环仍能连通（预算用尽/跳过的候选按 unknown 处理：不记退避、
 *      仍照常拨号）；过大值（99999）反向钳到上限 3000ms 并告警，预算足时恢复「探测即预连接」。
 *      区间内的边界值（3000）不钳制、不告警（阶段 H 就用它给慢候选留足预算）。
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
const V6_DOMAIN = 'v6-pool.example.net';
const TARGET = 'ipv4.icanhazip.com';
// 命中 Cloudflare 网段的目标域名（DoH 桩解析到 104.16.0.0/13），用于验证池首跳的目标识别路径
const CF_TARGET = 'cf-target.example.com';

// 14 条候选：前 6 条「不通」（connect 立即失败），后 8 条「通」（3ms 建连）
const POOL = Array.from({ length: 14 }, (_, i) => `10.20.0.${i + 1}`);
const FAILING = new Set(POOL.slice(0, 6));
const HEALTHY = new Set(POOL.slice(6));
// 大池：对齐实测地区池规模（SG/JP/通用 = 50 条 A 记录），验证「解析出多少就全量入池」
const BIG_POOL = Array.from({ length: 50 }, (_, i) => `10.30.0.${i + 1}`);
// 两个不同地区的池（真实地区池互不重叠），用于验证 @地区 锚定的池隔离
const KR_POOL = Array.from({ length: 12 }, (_, i) => `10.40.0.${i + 1}`);
const SG_POOL = Array.from({ length: 12 }, (_, i) => `10.50.0.${i + 1}`);
// 双栈池：同一域名同时发布 A 与 AAAA，用来钉「AAAA 以 [v6] 入池并同等参与抽取/探测」
const V6_A = ['10.60.0.1', '10.60.0.2', '10.60.0.3'];
const V6_AAAA = ['2001:db8::1', '2001:db8::2', '2001:db8::3'];
// 慢候选池（阶段 H）：**首次**建连要 SLOW_MS 才成功（＝可达性探测那一次），之后的建连立即成功。
// 这样「等探测」与「真拨」两段耗时可以分开断言，不会被单一时延混在一起。
const SLOW_DOMAIN = 'slow-pool.example.net';
const SLOW_MS = 1400;
const SLOW_POOL = Array.from({ length: 6 }, (_, i) => `10.70.0.${i + 1}`);
const SLOW = new Set(SLOW_POOL);
const BLACKLIST_BASE_TTL_MS = 30 * 1000; // IP_BLACKLIST_TTL：等过它才能验证「回池」
const CONN_WAIT_MS = 300;                // 每次连接后等它的探测/拨号跑完

let failures = 0;
const out = (...args) => process.stdout.write(args.join(' ') + '\n');
const check = (name, ok, detail = '') => {
    out(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
    if (!ok) failures++;
};

// ── VLESS 首包：ver(1) + uuid(16) + optLen(1) + cmd(1) + port(2) + atyp(1) + 域名字节
function vlessDomainPacket(domain, port = 443, payload = []) {
    const head = [0, ...UUID.split('-').join('').match(/../g).map((h) => parseInt(h, 16)), 0, 1, port >> 8, port & 0xff, 2];
    const d = [...Buffer.from(domain, 'utf8')];
    // payload 是「VLESS 头之后的剩余载荷」—— 服务端会把它当首包数据写进后端 socket。
    // 必须带载荷：否则 rawClientData 为空、写首包被跳过，「首包只写一次」的断言会变成空转。
    return Uint8Array.from([...head, d.length, ...d, ...payload]);
}

/** 首包载荷（长度固定、内容可辨识），用于断言「胜者收到的字节 = 这份载荷」 */
const PACKET_PAYLOAD = Array.from({ length: 16 }, (_, i) => 0xa0 + i);

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

/** 本次连接内所有 TCP 建连尝试（探测 + 竞速拨号都会打到这里）。
 *  分两份记：拼好的 `host:port` 字符串只用于日志，**裸 hostname** 才是断言用的集合 ——
 *  IPv6 地址本身含冒号，用 `split(':')[0]` 解析会把 `2001:db8::1` 截成 `2001`，v6 断言必然假绿。 */
let dialedThisConnection = [];
let dialedHostsThisConnection = [];
/** 每个 dialed socket 收到的首包写入记录：`{ host, writes: number, bytes: number[] }`。
 *  为什么要记：竞速拨号的首包是**同一个 ArrayBuffer**，而 write() 会 detach 它 ——
 *  一旦「每个候选都写一次」，第一个写成功的候选吃掉缓冲区、真正的胜者只能写出 0 字节，
 *  表现是「反代（CF 目标）首跳连上但整条不通」。桩若不记录写入内容，这类回归会全绿通过
 *  （曾经真实发生过：R-03 合并把写入挪进候选内部，15/15 全绿但线上反代失效）。 */
let firstPacketWritesThisConnection = [];
/** 本次连接的事件序列，元素只有 `'start'` / `'settle'` 两种（`settle` = 该 socket 的 opened
 *  有了结论，成功或失败都算）。用它量**探测窗口**：滚动窗口实现下序列开头必然是连续 3 个
 *  `'start'`（第 4 个要等某一条 settle 才会发出）；一次性全发的旧实现开头会是连续 6 个。
 *  只靠数组顺序判定 —— 不用时间戳（3ms 成功与同步失败都在同一毫秒内，分不开），
 *  也不用额外序号或 host 字段（序号与下标同构、host 与 dialed 重复，都是纯冗余）。 */
let eventsThisConnection = [];
/** 当前在飞的 socket 数与其峰值。运行时对单请求的并发连接有配额（约 6 条），
 *  这条峰值就是「会不会撞配额」的直接度量：探测 3 + 竞速 3 各自独立成峰，永远不该超过 3。
 *  ⚠️ 名额在 `opened` **有结论**时归还，而「有结论」包含 `close()`：探测超时后探针会主动关掉
 *  那条半开连接（真实运行时 `opened` 随之 reject），桩必须一样处理，否则已关掉的 socket 会被
 *  继续算在飞 —— 阶段 I（预算收紧 → 探测全部超时 → 立刻改走批次）就会假性冲到 6。 */
let inFlight = 0;
let maxInFlight = 0;
/** 本次连接内每个 host 被建连的次数（阶段 H 用：第 1 次＝探测，之后＝真拨） */
let attemptsThisConnection = new Map();
/** 本次连接开始的时刻（`firstPacketAt` 的零点） */
let connectionStartedAt = 0;
globalThis.connect = ({ hostname, port }) => {
    dialedThisConnection.push(`${hostname}:${port}`);
    dialedHostsThisConnection.push(hostname);
    eventsThisConnection.push('start');
    const attempt = (attemptsThisConnection.get(hostname) || 0) + 1;
    attemptsThisConnection.set(hostname, attempt);
    inFlight++;
    if (inFlight > maxInFlight) maxInFlight = inFlight;
    let resolveOpened;
    let rejectOpened;
    const opened = new Promise((res, rej) => { resolveOpened = res; rejectOpened = rej; });
    /** `opened` 只允许出结论一次：连上 / 失败 / 被 close() 打断，三者取先到者 */
    let openedSettled = false;
    const settleOpened = (error) => {
        if (openedSettled) return;
        openedSettled = true;
        if (error) rejectOpened(error); else resolveOpened();
    };
    // 这一个 then 同时承担「记 settle 事件 + 归还在飞名额 + 处理 rejection」三件事，
    // 所以不再需要额外的 opened.catch(() => {})（它原先只用来防未处理的 rejection）。
    const onSettled = () => {
        eventsThisConnection.push('settle');
        inFlight--;
    };
    opened.then(onSettled, onSettled);
    const writeRecord = { host: hostname, writes: 0, bytes: [], at: null };
    firstPacketWritesThisConnection.push(writeRecord);
    const socket = {
        opened,
        closed: new Promise(() => {}),
        readable: new ReadableStream({ start() {} }), // 永不产出：避免 remoteSocketToWS 早退
        writable: new WritableStream({
            write(chunk) {
                // 记录每次写入的字节量（断言「胜者恰好写一次且字节完整」用）
                writeRecord.writes++;
                writeRecord.bytes.push(chunk?.byteLength ?? 0);
                // 首包落地时刻（相对本次连接开始）：阶段 H 用它量「探测即预连接」的真实延迟
                if (writeRecord.at === null) writeRecord.at = Date.now() - connectionStartedAt;
            }
        }),
        // 关闭 = 这条连接不再在飞（真实运行时 `opened` 会 reject）
        close() { settleOpened(new Error('closed before open')); }
    };
    if (FAILING.has(hostname)) settleOpened(new Error('ECONNREFUSED'));
    // 慢候选：**首次**建连（探测）慢，之后的建连（预热/批次真拨）立即成功
    else if (SLOW.has(hostname) && attempt === 1) setTimeout(() => settleOpened(), SLOW_MS);
    else setTimeout(() => settleOpened(), 3);
    return socket;
};

/** DoH 桩当前对「未知域名」返回的 A 记录集合（阶段 C 换成 50 条的大池以验证不截断） */
let dohIps = POOL;
/** 按查询域名返回该域名发布的记录集合：`{ a, aaaa }`。
 *  不同地区域名 = 各自独立的池；v6-pool 同时发布 A 与 AAAA（双栈）。 */
function dohRecordsFor(name) {
    const n = name.toLowerCase();
    if (n.includes('kr-pool')) return { a: KR_POOL, aaaa: [] };
    if (n.includes('sg-pool')) return { a: SG_POOL, aaaa: [] };
    if (n.includes('v6-pool')) return { a: V6_A, aaaa: V6_AAAA };
    // 阶段 H：6 条慢候选（首次建连 SLOW_MS）
    if (n.includes('slow-pool')) return { a: SLOW_POOL, aaaa: [] };
    // 目标识别测试：解析到 Cloudflare 网段（104.16.0.0/13），首跳应走池
    if (n.includes('cf-target')) return { a: ['104.16.0.1'], aaaa: [] };
    return { a: dohIps, aaaa: [] };
}
globalThis.fetch = async (url) => {
    const u = String(url);
    const isDoh = u.includes('cloudflare-dns.com') || u.includes('dns.google');
    if (isDoh) {
        const name = decodeURIComponent(/[?&]name=([^&]+)/.exec(u)?.[1] ?? '');
        // 注意交替顺序：写成 (A|AAAA) 时 `type=AAAA` 会先匹配到 A，AAAA 查询就被当成 A 查询返回，
        // v6 候选永远进不了池（阶段 E 的回归钉就是这么把这个桩的 bug 抓出来的）。
        const type = /[?&]type=(AAAA|A)/.exec(u)?.[1] ?? 'A';
        const records = dohRecordsFor(name);
        const isAaaa = type === 'AAAA';
        const answer = (isAaaa ? records.aaaa : records.a)
            .map((data) => ({ name, type: isAaaa ? 28 : 1, TTL: 300, data }));
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

const PACKET = vlessDomainPacket(TARGET, 443, PACKET_PAYLOAD);

/** 发一次 WS 升级，等首包处理跑完，返回本次观测。
 *  target 默认是 TARGET；验证目标识别（CF 网段）时传 CF_TARGET。
 *  waitMs：等待后台探测/拨号的时长（默认为「快候选」够用的 300ms；慢候选阶段要传更长的值）。 */
async function runConnection(query = '?qj=only', target = TARGET, waitMs = CONN_WAIT_MS) {
    dialedThisConnection = [];
    dialedHostsThisConnection = [];
    firstPacketWritesThisConnection = [];
    eventsThisConnection = [];
    attemptsThisConnection = new Map();
    connectionStartedAt = Date.now();
    logs.length = 0;
    const packet = target === TARGET ? PACKET : vlessDomainPacket(target, 443, PACKET_PAYLOAD);
    const earlyData = Buffer.from(packet).toString('base64url');
    const request = new Request(`${ORIGIN}/${query}`, {
        headers: {
            Host: 'panel.example.com',
            Upgrade: 'websocket',
            'sec-websocket-protocol': earlyData
        }
    });
    const response = await handler.fetch(request, env, ctx);
    await new Promise((r) => setTimeout(r, waitMs));
    // 断言集合用裸 hostname：IPv6 地址自带冒号，不能再按 ':' 切分
    const probed = new Set(dialedHostsThisConnection);
    const drawLog = logs.find((l) => /got \d+ IPs for proxy .* drawing \d+/.test(l)) || '';
    const m = /got (\d+) IPs for proxy .* drawing (\d+) \((\d+) in backoff\)/.exec(drawLog);
    // 首包写入总账：竞速时同一 ArrayBuffer 只能被写一次（write 会 detach 它）
    const wroteOnce = firstPacketWritesThisConnection.filter((w) => w.writes > 0);
    // 事件序列开头连续 'start' 的个数 = 第一个窗口的宽度（滚动窗口 = 3；一次性全发 = 抽取条数）
    let leadingStarts = 0;
    for (const e of eventsThisConnection) {
        if (e !== 'start') break;
        leadingStarts++;
    }
    return {
        status: response.status,
        dialed: [...dialedThisConnection],
        probed,
        poolSize: m ? Number(m[1]) : null,
        drawn: m ? Number(m[2]) : null,
        inBackoff: m ? Number(m[3]) : null,
        drawLog,
        leadingStarts,
        /** 首包字节数（应等于剥离 VLESS 头后的载荷长度，绝不是 0） */
        firstPacketBytes: wroteOnce.length ? wroteOnce[0].bytes[0] : null,
        /** 首包落地时刻（ms，相对本次连接开始）；没有写入时为 null */
        firstPacketAt: wroteOnce.length ? wroteOnce[0].at : null,
        /** 本次连接产生的日志快照（下一个 runConnection 会清空全局 logs） */
        logs: [...logs],
    };
}

// ── 阶段 A：全量入池 + 抽取上限 + 探测窗口 + 探测失败退避
out(`— 阶段 A：解析池 ${POOL.length} 条（${FAILING.size} 条不通）→ 全量入池、抽 6 条、探测窗口 3、坏候选退避 —`);

const seenProbed = new Set();
const retiredFailures = new Set();
let firstConnection = null;
let maxDrawn = 0;
let maxBackoff = 0;
let lastFailObservedAt = 0;
let cleanStreak = 0;
let maxCleanStreak = 0;

// 30 次上限是「抽满覆盖」的余量：每连接随机抽 6/14，收到全部 14 条约需十几次连接
// （每次漏掉某个候选的概率 0.571，30 次后 <1e-6）。
for (let i = 0; i < 30; i++) {
    const r = await runConnection();
    if (i === 0) firstConnection = r;
    if (r.status !== 101) check(`第 ${i + 1} 次连接：升级返回 101`, false, `status=${r.status}`);

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

    // 收尾条件必须**含覆盖**：只按「坏候选都退避过 + 连续 4 次干净」判断，会在第 5~6 次连接
    // 就退出，而那时「14 条全部被抽到过」还有约 3.5% 的概率不成立 —— 这就是下面两条覆盖断言
    // 曾经偶发 FAIL 的原因（每连接只抽 6/14，coupon collector 还没收集完）。
    if (retiredFailures.size === FAILING.size && cleanStreak >= 4 && seenProbed.size === POOL.length) break;
}

check('解析出的候选全部入池（日志 got 14，而不是被 slice(0,8) 砍成 8）',
    firstConnection?.poolSize === POOL.length,
    `poolSize=${firstConnection?.poolSize} log=${firstConnection?.drawLog}`);
check('每连接抽取条数 ≤ 6（= RACE_PROBE_COUNT）',
    maxDrawn > 0 && maxDrawn <= 6,
    `maxDrawn=${maxDrawn}`);
check('每连接抽取条数 = 6（可用候选充足时填满槽位）',
    firstConnection?.drawn === 6,
    `firstConnection.drawn=${firstConnection?.drawn}`);
check('探测按 3 条滚动窗口限流：事件序列开头是连续 3 个 start（一次性全发会是 6 个）',
    firstConnection?.leadingStarts === 3,
    `leadingStarts=${firstConnection?.leadingStarts} dialed=${firstConnection?.dialed.join(' | ')}`);
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
check('大池仍只抽 6 条参与可达性探测（抽取上限与池大小无关）',
    big.drawn === 6,
    `drawn=${big.drawn}`);
check('大池抽出的候选都来自该池',
    big.probed.size > 0 && [...big.probed].every((ip) => BIG_POOL.includes(ip)),
    `probed=${[...big.probed].join(',')}`);

// ── 阶段 E：不砍 IPv6（A + AAAA 都要入池、都要参与抽取与探测）
//    回归钉：曾经有人把 AAAA 丢掉（直连池只取 ipv4），或把 v6 键用 split(':') 解析坏 —— 这里全钉住。
//    ⚠️ 「探测即预连接」后单次连接**只会碰 1~3 个候选**（接管成功即停止发起新探测，这是省 socket 的
//    关键），所以这里按多轮累积覆盖，而不是要求一次连接碰满 6 条。
out(`— 阶段 E：${V6_DOMAIN} 同时发布 ${V6_A.length} 条 A + ${V6_AAAA.length} 条 AAAA，两类都要在池里并被抽到 —`);
env.PROXY_IP = V6_DOMAIN;
const v6runs = [];
const v6Probed = new Set();
for (let i = 0; i < 20; i++) {
    const r = await runConnection();
    v6runs.push(r);
    for (const h of r.probed) v6Probed.add(h);
    // 6 条全部被碰过就收工；每轮 1~3 条，20 轮仍未覆盖的概率 < 1e-6
    if (V6_A.every((ip) => v6Probed.has(ip)) && V6_AAAA.every((ip) => v6Probed.has(ip))) break;
}
const v6First = v6runs[0];
const v6ProbedV6 = [...v6Probed].filter((h) => h.includes(':'));
const v6ProbedV4 = [...v6Probed].filter((h) => !h.includes(':'));

check(`双栈池全量入池（A ${V6_A.length} + AAAA ${V6_AAAA.length} = ${V6_A.length + V6_AAAA.length} 条）`,
    v6First.poolSize === V6_A.length + V6_AAAA.length,
    `poolSize=${v6First.poolSize} log=${v6First.drawLog}`);
check('AAAA 候选确实进入抽取/探测（3 条 v6 都被抽到过）',
    V6_AAAA.every((ip) => v6Probed.has(ip)),
    `v6probed=${v6ProbedV6.sort().join(',')} 期望=${V6_AAAA.join(',')} runs=${v6runs.length}`);
check('A 候选同样被抽到（v6 不是靠挤掉 v4 才进池的）',
    V6_A.every((ip) => v6Probed.has(ip)),
    `v4probed=${v6ProbedV4.sort().join(',')} runs=${v6runs.length}`);
check('抽取键未被 v6 的冒号解析坏（抽到的 host 都是完整地址，无 2001 之类的截断）',
    v6ProbedV6.every((h) => /^[0-9a-fA-F:]+$/.test(h) && h.split(':').length >= 3),
    `v6probed=${v6ProbedV6.sort().join(',')}`);
check('v6 候选完成 TCP 探测后连接仍成功（每轮 101）',
    v6runs.every((r) => r.status === 101),
    v6runs.map((r) => `status=${r.status} probed=${[...r.probed].join('|')}`).join(' ;; '));

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

// ── 阶段 F：留空 + 指定地区 → 内置 DEFAULT_PROXY_IPS 必须真正参与拨号
//    回归钉：hasProxyPool 曾要求 hasCustomProxyIPs（用户显式配置），而 connectWithRaceDial 的
//    panelIPs → DEFAULT_PROXY_IPS 兜底只在 hasProxyPool 为真后才可达 —— 结果「留空 + wk=SG」
//    收敛出的内置池永远拨不到，地区锚定形同虚设。这里清空 KV / env PROXY_IP 后验证内置池确实被拨号。
out('— 阶段 F：清空反代池配置，?qj=only&wk=SG 应仍用内置池拨号（地区锚定生效） —');
env.PROXY_IP = undefined;
env.kv = makeKv();
// setSettings 用 Object.assign 合并，清空 KV 不会抹掉已合并进 globalThis.settings 的 proxyIPs，这里显式复位
if (globalThis.settings) globalThis.settings.proxyIPs = [];
if (globalThis.__kvCache) globalThis.__kvCache.timestamp = 0;

const builtinRun = await runConnection('?qj=only&wk=SG');
check('留空 + wk=SG：反代池拨号路径被触发（不再退化为直连首跳）',
    logs.some((l) => l.includes('proxy-first: attempting race dial through reverse-proxy pool')),
    `logs=${logs.join(' | ')}`);
check('留空 + wk=SG：内置池完成解析并进入竞速（drawLog 非空）',
    builtinRun.poolSize !== null && builtinRun.probed.size > 0,
    `poolSize=${builtinRun.poolSize} probed=${[...builtinRun.probed].join(',')}`);
check('留空 + wk=SG：抽到的候选来自内置池解析结果',
    builtinRun.probed.size > 0 && [...builtinRun.probed].every((ip) => BIG_POOL.includes(ip)),
    `probed=${[...builtinRun.probed].join(',')}`);

// ── 阶段 G：指定地区 + 默认模式 + CF 目标 → 反代池优先于官方直连池
//    hasProxyPool 修好后，wk 非空时内置池也进入 needsTargetProbe 的池首跳候选：
//    CF 目标必须先拨反代池，成功即不再拨官方池（官方池只作为回退阶梯的下一级）。
out('— 阶段 G：清空配置 + ?wk=SG（默认模式）+ CF 目标，应由反代池首跳且官方池不抢跑 —');
const cfRun = await runConnection('?wk=SG', CF_TARGET);
check('默认模式 + CF 目标：目标识别命中 Cloudflare 网段，走池首跳',
    logs.some((l) => l.includes('target-check:') && l.includes('Cloudflare range, pool-first')),
    `logs=${logs.join(' | ')}`);
check('默认模式 + CF 目标：首跳先拨反代池（内置池兜底）',
    logs.some((l) => l.includes('pool-first: reverse-proxy pool race dial')),
    `logs=${logs.join(' | ')}`);
check('默认模式 + CF 目标：反代池成功后不再拨官方直连池',
    !logs.some((l) => l.includes('CF official IP pool race dial')),
    `logs=${logs.join(' | ')}`);
check('默认模式 + CF 目标：拨号候选来自反代池解析结果（不是官方直连 IP）',
    cfRun.probed.size > 0 && [...cfRun.probed].every((ip) => BIG_POOL.includes(ip)),
    `probed=${[...cfRun.probed].join(',')}`);

// ── 首包写入总账（R-03 回归的守卫）──
// 竞速时同一批候选共享**同一个** ArrayBuffer：只要「每个候选各写一次」，就会有多个 socket
// 收到同一份首包（write 语义上是 transfer，真正该拿到的胜者可能反而写出 0 字节）→
// 表现为「反代（CF 目标）首跳连上但整条不通」。桩此前是空 `write() {}`，这类回归全绿也发现不了。
// 这里钉两条**确定成立**的不变量：
//  ① 至少有 socket 收到首包（否则断言空转，等于没测）；
//  ② 每次写入的字节数都等于载荷长度 —— write 是 transfer 语义，同一缓冲区被第二个写者
//     拿到时会变成 0 字节，这条正是「共享缓冲区被多写」的探针。
// 注：不钉「每个 socket 只能写一次」——实测存在同一 socket 被写两次的情形（疑为回退/上行泵
// 复用同一 socket），在未查明前不把它写成断言，避免把未知行为固化成契约。
const wroteAny = firstPacketWritesThisConnection.filter((w) => w.writes > 0);
const zeroByteWrites = firstPacketWritesThisConnection.filter((w) => w.writes > 0 && w.bytes.some((n) => n === 0));
check('CF 目标：确有 socket 收到首包（守卫非空转）',
    wroteAny.length > 0 && cfRun.firstPacketBytes === PACKET_PAYLOAD.length,
    `writers=${wroteAny.length} bytes=${cfRun.firstPacketBytes} expect=${PACKET_PAYLOAD.length}`);
check('CF 目标：没有 0 字节的首包写入（共享缓冲区未被多写吃掉）',
    zeroByteWrites.length === 0,
    `zero=${JSON.stringify(zeroByteWrites)} all=${JSON.stringify(firstPacketWritesThisConnection)}`);
check('默认模式 + CF 目标：连接成功返回 101',
    cfRun.status === 101,
    `status=${cfRun.status}`);

// ── 阶段 H：探测即预连接（约 +1.6s）──
//    6 条候选**首次**建连都要 SLOW_MS 才成功，于是：
//      · 窗口 3：第一波 3 条在 1.4s 出结论；**第一条成功的瞬间被接管** → 剩余候选不再发起探测
//        （`shouldStop` 记 unknown），所以整场只碰过 3 个 IP；
//      · 接管：那条已建好的 socket 直接变成数据连接，首包立刻写出去 —— 日志是
//        `race dial winner (probe socket` 且**没有** `race dialing batch`；
//      · 关键的一条（CPU 侧的回归钉）：接管路径**不再另开连接**。整场 connect() 次数必须正好是 3
//        （第一波探测 3 条，其中 1 条成为数据连接），而不是「3 探测 + 1 抢跑拨号」的 4。
//    ⚠️ 这一阶段不再依赖预算：拦住第二波的是「已接管」，不是剩余预算（旧注释写错过一次）。
//       预算本身由阶段 I 用 env 单独钉。
//    ⚠️ 但预算要先给足：默认 300ms **短于**这里的 SLOW_MS（1.4s），慢候选会在默认档被判死。
//       本阶段考的是「接管」路径，所以显式用上限边界值 3000ms（顺带钉「区间内的边界值不钳制、
//       不打告警」）。
out(`— 阶段 H：${SLOW_POOL.length} 条慢候选（首连 ${SLOW_MS}ms）→ 探测即预连接（约 +1.6s）—`);
env.PROXY_IP = SLOW_DOMAIN;
env.PROBE_PHASE_BUDGET_MS = '3000';
dohIps = SLOW_POOL;
const slow = await runConnection('?qj=only', TARGET, SLOW_MS + 400);
delete env.PROBE_PHASE_BUDGET_MS;
check('慢候选：预算取上限边界值 3000ms 时不被钳制、不打告警',
    !slow.logs.some((l) => l.includes('[探针预算]')),
    `logs=${slow.logs.filter((l) => l.includes('探针预算')).join(' | ')}`);
check('慢候选：接管后不再碰剩余候选（整场只碰过第一波的 3 条）',
    slow.probed.size > 0 && slow.probed.size <= 3,
    `probed=${[...slow.probed].join(',')} dialed=${slow.dialed.join(' | ')}`);
check('慢候选：接管探测 socket 摘下首包，且没有进批次循环',
    slow.logs.some((l) => l.includes('race dial winner (probe socket'))
    && !slow.logs.some((l) => l.includes('race dialing batch')),
    `logs=${slow.logs.filter((l) => l.includes('race dial') || l.includes('reachable')).join(' | ')}`);
check('慢候选：接管后不再多建连（connect 次数 = 3，没有额外的并行拨号）',
    slow.dialed.length === 3,
    `dialed=${slow.dialed.join(' | ')}`);
check('慢候选：首包在「一次慢建连」之内到达（接管没有白等探测预算）',
    slow.firstPacketAt !== null && slow.firstPacketAt < SLOW_MS + 300,
    `firstPacketAt=${slow.firstPacketAt}ms expect<${SLOW_MS + 300}`);
check('慢候选：连接成功返回 101',
    slow.status === 101,
    `status=${slow.status}`);

// ── 阶段 I：探测总预算的 env 钳制（约 +4s）──
//    I-1 同一批慢候选（首连 1.4s），把 `PROBE_PHASE_BUDGET_MS` 设成 10（低于下限 50）：
//      · env 真的被读到 → 打一条「低于下限 → 按 50ms 生效」的告警；
//      · 生效预算 50ms ≪ 慢候选的 1.4s → 第一波探测**全部超时判死**，没有候选可接管
//        （日志里不该出现 `race dial winner (probe socket`）；
//      · 于是必须走批次循环，由第二次建连（立即成功）连上 → 101 + `race dialing batch`。
//    I-2 换成快候选池，把同一个 env 设成 99999（高于上限 3000）：反向钳到 3000ms 并告警，
//        预算重新充足 → 回到「探测即预连接」（证明上限钳制不是把探测关掉）。
//    这一对（阶段 H 边界内 → 接管 / 阶段 I 双向越界 → 钳制生效）就是预算开关的回归钉。
out('— 阶段 I-1：PROBE_PHASE_BUDGET_MS=10（钳到 50ms）→ 探测判死、改走批次（约 +2.8s）—');
env.PROBE_PHASE_BUDGET_MS = '10';
// 等待 = 探测超时(50ms) + 批次里那几条候选的**首次**建连（桩里同样是 SLOW_MS）
const tight = await runConnection('?qj=only', TARGET, SLOW_MS * 2);
delete env.PROBE_PHASE_BUDGET_MS;
check('预算 env：过小值被钳到下限 50ms 并打一条告警',
    tight.logs.some((l) => l.includes('[探针预算]') && l.includes('按 50ms 生效')),
    `logs=${tight.logs.filter((l) => l.includes('探针预算')).join(' | ')}`);
check('预算 env：收紧后没有候选被接管（探测全部判死）',
    !tight.logs.some((l) => l.includes('race dial winner (probe socket')),
    `logs=${tight.logs.filter((l) => l.includes('race dial')).join(' | ')}`);
check('预算 env：收紧后改走批次循环并连通',
    tight.logs.some((l) => l.includes('race dialing batch')) && tight.status === 101,
    `status=${tight.status} logs=${tight.logs.filter((l) => l.includes('race dial')).join(' | ')}`);

out('— 阶段 I-2：PROBE_PHASE_BUDGET_MS=99999（钳到 3000ms）→ 告警 + 恢复探测即预连接 —');
env.PROXY_IP = PROXY_DOMAIN;
dohIps = POOL;
env.PROBE_PHASE_BUDGET_MS = '99999';
const oversized = await runConnection('?qj=only', TARGET, CONN_WAIT_MS);
delete env.PROBE_PHASE_BUDGET_MS;
check('预算 env：过大值被钳到上限 3000ms 并打一条告警',
    oversized.logs.some((l) => l.includes('[探针预算]') && l.includes('按 3000ms 生效')),
    `logs=${oversized.logs.filter((l) => l.includes('探针预算')).join(' | ')}`);
check('预算 env：钳回上限后仍在探测并连通（上限钳制没把探测关掉）',
    oversized.probed.size > 0 && oversized.status === 101,
    `probed=${[...oversized.probed].join(',')} status=${oversized.status}`);

// ── 并发总账（整场，含慢候选阶段）──
//    这条是「探测窗口限流」的兜底：任何一条路径退回到「一次性全发」（大池 6 条、v6 池 6 条），
//    峰值都会立刻超过 3 —— 运行时对单请求的并发连接有配额，撞上就是假失败 + 误判退避。
//    「探测即预连接」把峰值从「窗口 3 + 抢跑 1 = 4」压回 **3**：接管的是探测自己那条，不新开连接。
//    放在最后统一判：maxInFlight 是全程累加的峰值，分散在多处断言只会重复同一条上界。
check('全流程（含慢候选阶段）同时在飞的 socket 峰值 ≤ 3（窗口 3；接管不新开连接）',
    maxInFlight <= 3 && maxInFlight > 0,
    `maxInFlight=${maxInFlight}`);

for (const level of ['log', 'info', 'warn', 'error', 'debug']) console[level] = originalConsole[level];

out(failures === 0 ? '\nproxy-pool-draw: OK' : `\nproxy-pool-draw: ${failures} 项失败`);
process.exit(failures === 0 ? 0 : 1);
