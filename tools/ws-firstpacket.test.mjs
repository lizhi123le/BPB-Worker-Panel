/**
 * tools/ws-firstpacket.test.mjs
 *
 * WS 首包判定路径的行为测试。运行：node tools/ws-firstpacket.test.mjs
 * （package.json 里是 `npm run test:ws`）
 *
 * 为什么需要它：首包处理（协议探测 → 解析 → 分流）原本在「协议已锁定」与「首包探测」两条路径上
 * 各写了一份（四段重复），现已合并为一个 handleFirstPacket；而 tryParse* 也改为"判据成立就返回
 * 完整解析结果"。这些都在 WS 内部，smoke 的 WS 用例**不发首包**，本地也连不了真 TCP，
 * 所以这里用「早期数据」把首包喂进 write()：
 *   sec-websocket-protocol: <首包字节的 base64url>  → makeReadableWebSocketStream 解码后 enqueue，
 *   成为第一个 write(chunk) 的入参 —— 正好走上面的合并路径。
 *
 * 打桩：globalThis.connect 一调用即抛错（连接必定失败），因此"是否发生拨号"就是
 * "首包是否被成功识别"的确定信号；close(1008) 与服务端日志则是"判定为非法"的信号。
 *
 * 覆盖：
 *   1. 合法 VLESS 首包       → 进入拨号（connect 被调用）、不判非法
 *   2. 乱码首包              → close(1008) + 日志 `invalid first packet: neither VLESS nor Trojan`
 *   3. UUID 对但域名长度为 0 → close(1008) + 日志 `invalid first packet: vless header: ...`
 *                              （刻意保留"探测判据比 parse 成功条件宽"的老行为）
 *   4. 合法 Trojan 首包      → 进入拨号（口令 SHA-224 只算一次）、不判非法
 *   5. Trojan 口令错误       → close(1008) + `neither VLESS nor Trojan`
 *
 * 前提：先构建过（`npm run build`，或快速版 `NODE_ENV=mangle node scripts/build.js`），
 * 本测试直接加载 .build/worker.reference.js（混淆前产物，行为等价且可读）。
 */
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'fs';
import { pathToFileURL } from 'url';

const BUNDLE = '.build/worker.reference.js';
const UUID = '11111111-2222-4333-8444-555555555555';
const TR_PASS = 'trojan-secret';
const ORIGIN = 'https://panel.example.com';

let failures = 0;
// 注意：下面会把 console.* 换成"只记录不打印"的桩，所以测试自己的结论必须走这个通道打印
const out = (...args) => process.stdout.write(args.join(' ') + '\n');
const check = (name, ok, detail = '') => {
    out(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
    if (!ok) failures++;
};

// ── 首包构造
/** VLESS: ver(1) + uuid(16) + optLen(1) + cmd(1) + port(2) + atyp(1) + addr + payload
 *  地址类型编号：1=IPv4、2=域名（1 字节长度 + 域名）、3=IPv6（16 字节）。addrBytes 可显式覆盖（用于构造畸形/截断包）。 */
function vlessPacket({ uuid = UUID, cmd = 1, port = 443, atyp = 1, addr = [203, 0, 113, 7], domlen = null, addrBytes = null, payload = [] } = {}) {
    const head = [0, ...uuid.split('-').join('').match(/../g).map((h) => parseInt(h, 16)), 0, cmd, port >> 8, port & 0xff, atyp];
    const body = addrBytes ?? (atyp === 1 ? addr : atyp === 2 ? [domlen ?? 0] : atyp === 3 ? new Array(16).fill(0) : []);
    return Uint8Array.from([...head, ...body, ...payload]);
}

/** Trojan: 口令 sha224 的 56 个 ASCII 十六进制字符 + CRLF + cmd(1) + atyp(1) + addr + port(2) */
function trojanPacket({ password = TR_PASS, cmd = 1, atyp = 1, addr = [203, 0, 113, 7], port = 443 } = {}) {
    const hashChars = [...createHash('sha224').update(password, 'utf8').digest('hex')].map((c) => c.charCodeAt(0));
    return Uint8Array.from([...hashChars, 0x0d, 0x0a, cmd, atyp, ...addr, port >> 8, port & 0xff]);
}

function makeKv(seed = {}) {
    const store = new Map(Object.entries(seed));
    return {
        store,
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
    console.error(`找不到 ${BUNDLE} —— 请先构建：npm run build`);
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
    static redirect(url, status) { return RealResponse.redirect(url, status); }
};

let connectCalls = 0;
globalThis.connect = () => {
    connectCalls++;
    throw new Error('connect() is not available in the test harness');
};
globalThis.fetch = async () => new RealResponse('<!DOCTYPE html><html><body>stub</body></html>', { headers: { 'content-type': 'text/html' } });

const logs = [];
const originalConsole = {};
for (const level of ['log', 'info', 'warn', 'error', 'debug']) {
    originalConsole[level] = console[level];
    console[level] = (...args) => { logs.push(args.map((a) => (a && a.message) ? a.message : String(a)).join(' ')); };
}

let closeCalls = [];
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
            close(code, reason) { closeCalls.push({ code, reason }); }
        });
        this[0] = make();
        this[1] = make();
    }
};

const handler = (await import(pathToFileURL(BUNDLE).href)).default;
const ctx = { waitUntil() {}, passThroughOnException() {} };
const env = {
    UUID,
    TR_PASS,
    SUB_PATH: 'ws-test-sub-path',
    DOH_URL: 'https://cloudflare-dns.com/dns-query',
    FALLBACK: 'www.hcaptcha.com',
    kv: makeKv()
};

/** 把首包作为早期数据发一次 WS 升级，返回该次运行的观测结果 */
async function runFirstPacket(packet) {
    connectCalls = 0;
    closeCalls = [];
    logs.length = 0;

    const earlyData = Buffer.from(packet).toString('base64url');
    const request = new Request(ORIGIN + '/', {
        headers: {
            Host: 'panel.example.com',
            Upgrade: 'websocket',
            'sec-websocket-protocol': earlyData
        }
    });
    const response = await handler.fetch(request, env, ctx);
    // 首包处理在 pipeTo 的异步链里，等它跑完（连接桩同步抛错，通常几十毫秒内结束）
    await new Promise((r) => setTimeout(r, 250));

    return {
        status: response.status,
        connectCalls,
        close1008: closeCalls.filter((c) => c.code === 1008),
        invalidLog: logs.find((l) => l.includes('invalid first packet')) || null,
        closeAll: [...closeCalls]
    };
}

// ── 1) 合法 VLESS 首包 → 识别成功 → 进入拨号
let r = await runFirstPacket(vlessPacket());
check('合法 VLESS 首包：升级返回 101', r.status === 101, `status=${r.status}`);
check('合法 VLESS 首包：确实进入拨号（connect 被调用）', r.connectCalls > 0, `connectCalls=${r.connectCalls} logs=${r.invalidLog}`);
check('合法 VLESS 首包：未被判为非法首包', r.invalidLog === null && r.close1008.length === 0, `log=${r.invalidLog} closes=${JSON.stringify(r.closeAll)}`);

// ── 2) 乱码首包 → 收口
r = await runFirstPacket(new Uint8Array(64).fill(0x41));
check('乱码首包：close(1008)', r.close1008.length === 1, JSON.stringify(r.closeAll));
check('乱码首包：日志为 neither VLESS nor Trojan', r.invalidLog?.includes('neither VLESS nor Trojan') === true, String(r.invalidLog));
check('乱码首包：不应发生拨号', r.connectCalls === 0, `connectCalls=${r.connectCalls}`);

// ── 3) UUID 对、但域名长度为 0（探测判据成立 / parse 报头畸形）→ 必须仍是"认出 VLESS 再报畸形"
// VLESS 地址类型编号：1=IPv4、2=域名、3=IPv6。用 atyp=2 + domlen=0。
// 注意要凑够 24 字节（tryParseVlHeader 的硬下限），否则会先被长度判据挡掉、变成 neither。
r = await runFirstPacket(vlessPacket({ atyp: 2, domlen: 0, payload: [0x00] }));
check('零长度域名 VLESS：close(1008)', r.close1008.length === 1, JSON.stringify(r.closeAll));
check('零长度域名 VLESS：日志是 vless header 畸形（证明判据仍比 parse 宽、老行为未变）',
    r.invalidLog?.includes('vless header: addressValue is empty, addressType is 2') === true, String(r.invalidLog));
check('零长度域名 VLESS：不应发生拨号', r.connectCalls === 0, `connectCalls=${r.connectCalls}`);

// ── 4) 合法 Trojan 首包 → 识别成功 → 进入拨号（口令 SHA-224 复用，不再算第二遍）
r = await runFirstPacket(trojanPacket());
check('合法 Trojan 首包：升级返回 101', r.status === 101, `status=${r.status}`);
check('合法 Trojan 首包：确实进入拨号（口令哈希比对通过）', r.connectCalls > 0, `connectCalls=${r.connectCalls} log=${r.invalidLog}`);
check('合法 Trojan 首包：未被判为非法首包', r.invalidLog === null && r.close1008.length === 0, `log=${r.invalidLog}`);

// ── 5) Trojan 口令错误 → 收口
r = await runFirstPacket(trojanPacket({ password: 'wrong-password' }));
check('Trojan 口令错误：close(1008)', r.close1008.length === 1, JSON.stringify(r.closeAll));
check('Trojan 口令错误：日志为 neither VLESS nor Trojan', r.invalidLog?.includes('neither VLESS nor Trojan') === true, String(r.invalidLog));
check('Trojan 口令错误：不应发生拨号', r.connectCalls === 0, `connectCalls=${r.connectCalls}`);

// ── 6) VLESS 的 UDP/53 分支也应被识别（走 DNS 泵，连接失败即可）
r = await runFirstPacket(vlessPacket({ cmd: 2, port: 53, addr: [8, 8, 4, 4] }));
check('VLESS UDP/53 首包：被识别（进入拨号）且不判非法', r.connectCalls > 0 && r.invalidLog === null, `connectCalls=${r.connectCalls} log=${r.invalidLog}`);

// ── 7) 既有行为登记：VLESS 声明了 IPv6 但地址被截断 → parseVlHeader 抛 RangeError，
//     连接由 pipeTo 的取消路径关掉（无 1008、无 invalid first packet 日志）。
//     本次合并**没有**改变这条路径（parse 调用刻意留在 try 之外，异常照旧冒泡），这里只做回归钉。
r = await runFirstPacket(vlessPacket({ atyp: 3, addrBytes: [0x00], payload: [0x00, 0x00] }));
check('截断 IPv6 首包：不误报为"非法协议"（走既有抛错取消路径）',
    r.close1008.length === 0 && r.invalidLog === null && r.connectCalls === 0,
    `closes=${JSON.stringify(r.closeAll)} log=${r.invalidLog} connectCalls=${r.connectCalls}`);

for (const level of ['log', 'info', 'warn', 'error', 'debug']) console[level] = originalConsole[level];

out(failures === 0 ? '\nws-firstpacket: OK' : `\nws-firstpacket: ${failures} 项失败`);
process.exit(failures === 0 ? 0 : 1);
