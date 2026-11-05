/**
 * tools/xhttp-inbound.test.mjs
 *
 * XHTTP 入站（HTTP POST / stream-one）的行为测试。运行：node tools/xhttp-inbound.test.mjs
 *
 * 为什么需要它：XHTTP 入站是「把 WS 的双向连接换成一次 HTTP POST」，它复用 WS 的出站/下行管道，
 * 但入口判定是全新的：POST 方法 + settings.xhttpConfigs 开关 + 路径白名单，三者同时成立才接管。
 * 这条判定最容易出的两类事故在 smoke 里都看不见：
 *   · 吞掉既有 POST 路由（/login/authenticate、/panel/...）——面板直接不可用；
 *   · 首包处理细节丢失（UUID 校验、0xED7F 填充剥离、跨 chunk 累积、UDP DNS 分支）——客户端连不上。
 * 所以这里把 worker.fetch 直接当入口驱动，逐条钉住这些分支。
 *
 * 打桩（与 ws-firstpacket.test.mjs 同范式）：
 *   · globalThis.connect 一调用即抛错 —— 「是否发生拨号」就是「首包是否被成功识别」的确定信号；
 *   · globalThis.fetch 返回一段固定 HTML —— 关闭开关时 POST / 会落到伪装反代，据此区分「伪装页」与「被接管」。
 *
 * 覆盖：
 *   1. xhttpConfigs=false：同样的 POST 不进入 XHTTP（伪装页 + 未拨号）；
 *   2. xhttpConfigs=true + 合法 VLESS 首包：接管并拨号，响应不是伪装页；
 *   3. 非法 UUID：400 且未拨号；
 *   4. 0xED7F 隐私填充首包：剥离后仍被识别；
 *   5. 首包拆成两个 chunk：跨 chunk 累积后仍被识别；
 *   6. POST /login/authenticate：开关打开也不被 XHTTP 吞掉（面板路由不变）；
 *   7. cmd=2/port=53（UDP DNS）：被识别并拨号。
 *
 * 前提：先构建过（npm run build，或快速版 NODE_ENV=mangle node scripts/build.js），
 * 本测试直接加载 .build/worker.reference.js（混淆前产物，行为等价且可读）。
 */
import { existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const BUNDLE = '.build/worker.reference.js';
const UUID = '11111111-2222-4333-8444-555555555555';
const TR_PASS = 'trojan-secret';
const SUB_PATH = 'xhttp-inbound-sub';
const ORIGIN = 'https://panel.example.com';

let failures = 0;
// 注意：下面会把 console.* 换成"只记录不打印"的桩，所以测试自己的结论必须走这个通道打印
const out = (...args) => process.stdout.write(args.join(' ') + '\n');
const check = (name, ok, detail = '') => {
    out(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
    if (!ok) failures++;
};

/** VLESS 首包：ver(1) + uuid(16) + optLen(1) + cmd(1) + port(2) + atyp(1) + addr + payload */
function vlessPacket({ uuid = UUID, cmd = 1, port = 443, atyp = 1, addr = [203, 0, 113, 7], payload = [] } = {}) {
    const head = [0, ...uuid.split('-').join('').match(/../g).map((h) => parseInt(h, 16)), 0, cmd, port >> 8, port & 0xff, atyp];
    const body = atyp === 1 ? addr : atyp === 2 ? [0] : atyp === 3 ? new Array(16).fill(0) : [];
    return Uint8Array.from([...head, ...body, ...payload]);
}

/** 给首包加 0xED7F 隐私填充：[0xED,0x7F][padLen 2B 大端][padLen 字节填充][VLESS…] */
function withPrivacyPadding(packet, padLen = 64) {
    return Uint8Array.from([0xED, 0x7F, (padLen >> 8) & 0xff, padLen & 0xff, ...new Array(padLen).fill(0x41), ...packet]);
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

// ── 桩：出站网络；必须早于 bundle 导入
globalThis.fetch = async () =>
    new Response('<!DOCTYPE html><html><body>stub camouflage page</body></html>', {
        headers: { 'content-type': 'text/html; charset=utf-8' }
    });

let connectCalls = 0;
globalThis.connect = () => {
    connectCalls++;
    throw new Error('connect() is not available in the test harness');
};

const logs = [];
const originalConsole = {};
for (const level of ['log', 'info', 'warn', 'error', 'debug']) {
    originalConsole[level] = console[level];
    console[level] = (...args) => { logs.push(args.map((a) => (a && a.message) ? a.message : String(a)).join(' ')); };
}

const handler = (await import(pathToFileURL(BUNDLE).href)).default;
const ctx = { waitUntil() {}, passThroughOnException() {} };

/** seed 一次：让 worker 把完整出厂设置写进 KV，后续每个用例只覆盖 xhttpConfigs。 */
const seedKv = makeKv();
const seedEnv = { UUID, TR_PASS, SUB_PATH, DOH_URL: 'https://cloudflare-dns.com/dns-query', FALLBACK: 'www.hcaptcha.com', kv: seedKv };
await handler.fetch(
    new Request(`${ORIGIN}/sub/raw/${SUB_PATH}?app=xray`, { headers: { Host: 'panel.example.com' } }),
    seedEnv,
    ctx
);
const baseSettings = JSON.parse(seedKv.store.get('proxySettings'));
check('出厂默认 xhttpConfigs=false（入站开关的默认态）', baseSettings.xhttpConfigs === false, `xhttpConfigs=${baseSettings.xhttpConfigs}`);

function makeEnv(settings) {
    return {
        UUID,
        TR_PASS,
        SUB_PATH,
        DOH_URL: 'https://cloudflare-dns.com/dns-query',
        FALLBACK: 'www.hcaptcha.com',
        kv: makeKv({ proxySettings: JSON.stringify(settings), proxySettings_ver: '1' })
    };
}

/**
 * 发一次 POST 并收集观测值。
 * body 可以是 Uint8Array（单块）或 Uint8Array[]（多 chunk 的 ReadableStream）。
 */
async function runXhttp({ packet, chunks = null, path = '/', xhttpConfigs, method = 'POST' }) {
    connectCalls = 0;
    logs.length = 0;

    // worker 的 kv-cache 是 isolate 级 5 分钟 TTL（globalThis.__kvCache）：本测试在同一进程里
    // 反复换 KV 内容，不清理就会一直命中第一次 seed 时的缓存，后续用例永远读不到
    // xhttpConfigs=true，全部静默落回伪装页。删掉它等价于「换一个新 isolate」——
    // 也正是 random-path.test.mjs 用「父进程 spawn 子进程」绕开的那个缓存。
    delete globalThis.__kvCache;

    const env = makeEnv({ ...baseSettings, xhttpConfigs });
    const init = { method, headers: { Host: 'panel.example.com' } };
    if (chunks) {
        init.body = new ReadableStream({
            start(controller) {
                for (const chunk of chunks) controller.enqueue(chunk);
                controller.close();
            }
        });
        init.duplex = 'half';
    } else if (method === 'POST') {
        init.body = packet;
    }

    const response = await handler.fetch(new Request(`${ORIGIN}${path}`, init), env, ctx);

    // 下行可能是永不结束的流（真实隧道）：读失败/超时都不影响断言，只留证据
    let text = '';
    let readError = null;
    try {
        text = await Promise.race([
            response.text(),
            new Promise((_, reject) => setTimeout(() => reject(new Error('response body timeout')), 2000))
        ]);
    } catch (error) {
        readError = error.message;
    }
    // 首包处理在其余异步链里，等它跑完（connect 桩同步抛错，通常几十毫秒内结束）
    await new Promise((resolve) => setTimeout(resolve, 120));

    return {
        status: response.status,
        contentType: response.headers.get('content-type') || '',
        text,
        readError,
        connectCalls,
        logs: [...logs]
    };
}

// ── 1) xhttpConfigs=false：同样的 POST 不进入 XHTTP 处理，落到伪装反代
let r = await runXhttp({ packet: vlessPacket(), xhttpConfigs: false });
check('xhttpConfigs=false：POST / 落到伪装页（未被 XHTTP 接管）',
    r.status === 200 && /text\/html/.test(r.contentType) && r.text.includes('stub camouflage page'),
    `status=${r.status} ct=${r.contentType} text=${String(r.text).slice(0, 80)} readError=${r.readError}`);
check('xhttpConfigs=false：未发生任何拨号', r.connectCalls === 0, `connectCalls=${r.connectCalls}`);
check('xhttpConfigs=false：响应不是 XHTTP 的 400 Bad Request',
    !(r.status === 400 && r.text.includes('Bad Request')),
    `status=${r.status} text=${String(r.text).slice(0, 80)}`);

// ── 2) xhttpConfigs=true + 合法 VLESS 首包：接管并拨号，响应不是伪装页
r = await runXhttp({ packet: vlessPacket(), xhttpConfigs: true });
check('xhttpConfigs=true：合法 VLESS 首包被识别（发生拨号）', r.connectCalls > 0,
    `connectCalls=${r.connectCalls} status=${r.status} logs=${r.logs.join(' | ')}`);
check('xhttpConfigs=true：处理被接管，出站全失败按网关错误收口（502 Bad Gateway）',
    r.status === 502, `status=${r.status} ct=${r.contentType} text=${String(r.text).slice(0, 80)} readError=${r.readError}`);

// ── 3) 非法 UUID：400 且未拨号
r = await runXhttp({ packet: vlessPacket({ uuid: '99999999-2222-4333-8444-555555555555' }), xhttpConfigs: true });
check('非法 UUID：400 Bad Request', r.status === 400, `status=${r.status} text=${String(r.text).slice(0, 80)}`);
check('非法 UUID：未发生拨号', r.connectCalls === 0, `connectCalls=${r.connectCalls}`);

// ── 4) 0xED7F 隐私填充首包：剥离后仍被识别
r = await runXhttp({ packet: withPrivacyPadding(vlessPacket()), xhttpConfigs: true });
check('0xED7F 填充首包：剥离后仍被识别（发生拨号）', r.connectCalls > 0,
    `connectCalls=${r.connectCalls} status=${r.status} logs=${r.logs.join(' | ')}`);
check('0xED7F 填充首包：按已识别处理（502，而非 400）', r.status === 502,
    `status=${r.status} text=${String(r.text).slice(0, 80)}`);

// ── 5) 首包被拆成两个 chunk：跨 chunk 累积后仍被识别
const splitPacket = vlessPacket();
r = await runXhttp({ chunks: [splitPacket.slice(0, 10), splitPacket.slice(10)], xhttpConfigs: true });
check('首包拆成两个 chunk：跨 chunk 累积后仍被识别（发生拨号）', r.connectCalls > 0,
    `connectCalls=${r.connectCalls} status=${r.status} logs=${r.logs.join(' | ')}`);
check('首包拆成两个 chunk：按已识别处理（502，而非 400）', r.status === 502,
    `status=${r.status} text=${String(r.text).slice(0, 80)}`);

// ── 6) 既有 POST 路由不被吞：/login/authenticate 即使在开关打开时也走登录处理器
r = await runXhttp({ packet: vlessPacket(), path: '/login/authenticate', xhttpConfigs: true });
check('POST /login/authenticate：未被 XHTTP 吞掉（未发生拨号）', r.connectCalls === 0,
    `connectCalls=${r.connectCalls} status=${r.status}`);
check('POST /login/authenticate：仍走登录路由（401 Wrong password，而非 XHTTP 的 400）',
    r.status === 401 && r.text.includes('Wrong password'),
    `status=${r.status} text=${String(r.text).slice(0, 120)}`);

// ── 7) cmd=2 / port=53（UDP DNS）：被识别并拨号（DNS 走 8.8.4.4:53 的 TCP socket）
r = await runXhttp({ packet: vlessPacket({ cmd: 2, port: 53, addr: [8, 8, 4, 4] }), xhttpConfigs: true });
check('UDP/53 首包：被识别（发生拨号）', r.connectCalls > 0,
    `connectCalls=${r.connectCalls} status=${r.status} logs=${r.logs.join(' | ')}`);
check('UDP/53 首包：DNS socket 建连失败按 500 收口（已进入 UDP 分支）', r.status === 500,
    `status=${r.status} text=${String(r.text).slice(0, 80)}`);

for (const level of ['log', 'info', 'warn', 'error', 'debug']) console[level] = originalConsole[level];

out('');
out(failures === 0 ? 'xhttp-inbound: OK' : `xhttp-inbound: ${failures} 项失败`);
process.exit(failures === 0 ? 0 : 1);
