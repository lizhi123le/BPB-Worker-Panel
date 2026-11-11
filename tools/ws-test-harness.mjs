/**
 * tools/ws-test-harness.mjs
 *
 * ws-firstpacket / ws-uplink-batch 共用的测试脚手架。
 *
 * 为什么单独成文件：两个测试需要同一套 Workers 运行时桩 —— Response 101、WebSocketPair、
 * fetch、KV、console 捕获、首包构造。此前各复制一份（约 110 行），改桩要改两处、也容易漂移。
 * 这里只放**共用**部分；每个测试自己的假 socket / 断言仍留在测试文件里。
 *
 * 使用顺序（与 Workers 运行时一致，顺序不能颠倒）：
 *   installWebStubs() → captureConsole() → await importBundle() → handler.fetch(...)
 * 桩必须在 import 被测 bundle 之前装好，否则模块加载期就取不到 globalThis.connect 等。
 */
import { createHash } from 'node:crypto';
import { existsSync } from 'fs';
import { pathToFileURL } from 'url';

export const BUNDLE = '.build/worker.reference.js';
export const UUID = '11111111-2222-4333-8444-555555555555';
export const TR_PASS = 'trojan-secret';
export const ORIGIN = 'https://panel.example.com';
/** 生产代码（unified.ts 的 failUplink）里的日志文案。测试断言复用它，避免两处硬编码。 */
export const PIPE_ERROR_LOG = 'readableWebSocketStream pipeTo error';

export function makeReporter() {
    let failures = 0;
    // 注意：测试会把 console.* 换成"只记录不打印"的桩，所以测试自己的结论必须走这个通道打印
    const out = (...args) => process.stdout.write(args.join(' ') + '\n');
    const check = (name, ok, detail = '') => {
        out(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
        if (!ok) failures++;
    };
    return { out, check, failures: () => failures };
}

export function makeKv(seed = {}) {
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

/** VLESS: ver(1) + uuid(16) + optLen(1) + cmd(1) + port(2) + atyp(1) + addr + payload
 *  地址类型编号：1=IPv4、2=域名（1 字节长度 + 域名）、3=IPv6（16 字节）。addrBytes 可显式覆盖（用于构造畸形/截断包）。 */
export function vlessPacket({ uuid = UUID, cmd = 1, port = 443, atyp = 1, addr = [203, 0, 113, 7], domlen = null, addrBytes = null, payload = [] } = {}) {
    const head = [0, ...uuid.split('-').join('').match(/../g).map((h) => parseInt(h, 16)), 0, cmd, port >> 8, port & 0xff, atyp];
    const body = addrBytes ?? (atyp === 1 ? addr : atyp === 2 ? [domlen ?? 0] : atyp === 3 ? new Array(16).fill(0) : []);
    return Uint8Array.from([...head, ...body, ...payload]);
}

/** Trojan: 口令 sha224 的 56 个 ASCII 十六进制字符 + CRLF + cmd(1) + atyp(1) + addr + port(2) */
export function trojanPacket({ password = TR_PASS, cmd = 1, atyp = 1, addr = [203, 0, 113, 7], port = 443 } = {}) {
    const hashChars = [...createHash('sha224').update(password, 'utf8').digest('hex')].map((c) => c.charCodeAt(0));
    return Uint8Array.from([...hashChars, 0x0d, 0x0a, cmd, atyp, ...addr, port >> 8, port & 0xff]);
}

/** 把首包（或任意字节）作为早期数据 base64url 放进 sec-websocket-protocol。 */
export function earlyDataRequest(bytes) {
    const earlyData = Buffer.from(bytes).toString('base64url');
    return new Request(ORIGIN + '/', {
        headers: {
            Host: 'panel.example.com',
            Upgrade: 'websocket',
            'sec-websocket-protocol': earlyData
        }
    });
}

/**
 * Response 101 / fetch / WebSocketPair 桩。
 * onClose(code, reason) 记录 WS close（不需要记录时传空默认）。
 * 返回 { lastPair }：最近一次 WebSocketPair 实例，测试可从中取服务端那一端。
 */
export function installWebStubs({ onClose = () => {} } = {}) {
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

    globalThis.fetch = async () => new RealResponse('<!DOCTYPE html><html><body>stub</body></html>', { headers: { 'content-type': 'text/html' } });

    const state = { lastPair: null };
    globalThis.WebSocketPair = class {
        constructor() {
            state.lastPair = this;
            const make = () => ({
                readyState: 1,
                listeners: {},
                sent: [],
                closed: new Promise(() => {}),
                accept() {},
                addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); },
                removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn); },
                send(payload) { this.sent.push(payload); },
                close(code, reason) { onClose(code, reason); }
            });
            this[0] = make();
            this[1] = make();
        }
    };
    return state;
}

/** 替换 console.* 为只记录不打印；返回 { logs, restore }。 */
export function captureConsole() {
    const logs = [];
    const original = {};
    for (const level of ['log', 'info', 'warn', 'error', 'debug']) {
        original[level] = console[level];
        console[level] = (...args) => { logs.push(args.map((a) => (a && a.message) ? a.message : String(a)).join(' ')); };
    }
    return {
        logs,
        restore() {
            for (const level of ['log', 'info', 'warn', 'error', 'debug']) console[level] = original[level];
        }
    };
}

/** 每个测试的 env 基底；SUB_PATH 等按需覆盖。 */
export function makeEnv(overrides = {}) {
    return {
        UUID,
        TR_PASS,
        SUB_PATH: 'ws-test-sub-path',
        DOH_URL: 'https://cloudflare-dns.com/dns-query',
        FALLBACK: 'www.hcaptcha.com',
        kv: makeKv(),
        ...overrides
    };
}

/** 检查构建产物并动态 import 默认导出（handler）。必须在 installWebStubs 之后调用。 */
export async function importBundle() {
    if (!existsSync(BUNDLE)) {
        // 走 stderr：此时 console.* 可能已被 captureConsole 替换，输出不能被吞掉
        process.stderr.write(`找不到 ${BUNDLE} —— 请先构建：npm run build\n`);
        process.exit(1);
    }
    return (await import(pathToFileURL(BUNDLE).href)).default;
}
