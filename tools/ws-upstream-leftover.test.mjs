/**
 * tools/ws-upstream-leftover.test.mjs
 *
 * 上游 SOCKS5 代理「残留字节」路径的下行字节序测试。运行：node tools/ws-upstream-leftover.test.mjs
 *
 * 为什么需要它（B-24）：SOCKS5 / HTTP CONNECT 握手成功后，上游代理**往往已经把目标的首段数据
 * 一并送来了**（代理是先连上目标、收到目标的 ServerHello 才回 CONNECT 成功应答的），
 * 这段「残留字节」在手握里被读进缓冲，必须重新排回读流的最前面 —— 就是 wrapLeftoverSocket。
 * 此前那个包装流是普通 ReadableStream，于是 remoteSocketToWS 的
 * `getReader({ mode: 'byob' })` 直接抛错 → 整条连接静默退回非 BYOB 读路径（每块多一次分配 + 拷贝），
 * 而且只在配置了 settings.upstreamProxy 时才走到 —— 这条路径此前**零测试覆盖**。
 *
 * 这条用例钉住的不是「流是不是 byte stream」（那是实现细节），而是 B-24 改动**最容易搞坏**的东西：
 *   1) 残留字节必须是下行第一块，且**排在**后续 chunk 之前（不丢、不重、不乱序）；
 *   2) 残留 + 后续 chunk 的总账与输入逐字节一致。
 * 换句话说：把包装流换成 `type:'bytes'` 允许改「分配与拷贝的次数」，不允许改**字节流本身**。
 *
 * 打桩：globalThis.connect 返回一个「假 SOCKS5 代理」——
 *   · 第 1 次写（问候）→ 回 `[5,0]`（选中无认证）；
 *   · 第 2 次写（CONNECT）→ 回 10 字节成功应答 **+ 目标侧残留字节**（同一段到达，模拟最坏情形）；
 *   · 之后由测试主动投喂后续 chunk。
 *
 * 前提：先构建过（`npm run build`，或快速版 `NODE_ENV=mangle node scripts/build.js`），
 * 本测试加载 .build/worker.reference.js。
 */
import {
    makeReporter, makeEnv, makeKv, vlessPacket,
    installWebStubs, captureConsole, importBundle, earlyDataRequest
} from './ws-test-harness.mjs';

const { out, check, failures } = makeReporter();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const sameBytes = (a, b) => {
    if (!a || !b || a.byteLength !== b.byteLength) return false;
    for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
    return true;
};
const concatBytes = (chunks) => {
    const total = chunks.reduce((n, c) => n + c.byteLength, 0);
    const res = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { res.set(c, off); off += c.byteLength; }
    return res;
};

// ── 假 SOCKS5 代理 ────────────────────────────────────────────────
const LEFTOVER = new Uint8Array(1000).fill(0xe1);   // 代理握手时一并送来的目标首段数据
const NEXT_BIG = new Uint8Array(40000).fill(0x5a);  // 残留之后的下一块（≥24KiB → 直发）
const NEXT_SMALL = new Uint8Array(5000).fill(0x6b); // 再下一块（<24KiB → 走合帧）

let proxyReader = null;      // 代理 socket 的 readable 控制器（byte stream）
let proxyWrites = 0;         // 代理侧收到的写次数：1=问候 2=CONNECT 3=首包
let proxyClosed = 0;

function makeSocks5Socket() {
    return {
        opened: Promise.resolve(),
        closed: new Promise(() => {}),
        readable: new ReadableStream({
            type: 'bytes',
            start(c) { proxyReader = c; },
            pull() { /* 由测试/握手桩主动 enqueue */ }
        }),
        writable: new WritableStream({
            write(chunk) {
                proxyWrites++;
                if (proxyWrites === 1) {
                    // 方法协商：`[5,0]` = 版本 5 +「无需认证」
                    proxyReader.enqueue(Uint8Array.from([5, 0]));
                    return undefined;
                }
                if (proxyWrites === 2) {
                    // CONNECT 成功应答（10B，ATYP=1 回绑地址）与目标侧残留字节在**同一段**到达：
                    // 握手代码读走前 10B 后剩下的这些，正是 wrapLeftoverSocket 要重新排回读流头部的部分。
                    proxyReader.enqueue(concatBytes([
                        Uint8Array.from([5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90]),
                        new Uint8Array(LEFTOVER)
                    ]));
                }
                return undefined;
            }
        }),
        close() { proxyClosed++; }
    };
}

globalThis.connect = () => makeSocks5Socket();

const stubs = installWebStubs({});
const { logs, restore } = captureConsole();
const handler = await importBundle();
const ctx = { waitUntil() {}, passThroughOnException() {} };
// settings.upstreamProxy 是这条路径唯一的开关；KV 里播一份即可（首次 setSettings 就会读到）
const env = makeEnv({
    SUB_PATH: 'ws-upstream-leftover',
    kv: makeKv({ proxySettings: JSON.stringify({ upstreamProxy: 'socks5://9.9.9.9:1080' }) })
});

// 前置：运行时必须支持 byte stream + BYOB（否则本用例覆盖不到新路径）
check('运行时支持 BYOB（否则该用例覆盖不到 byte stream 包装流）', (() => {
    try {
        new ReadableStream({ type: 'bytes', pull() {} }).getReader({ mode: 'byob' }).releaseLock();
        return true;
    } catch { return false; }
})());

const resp = await handler.fetch(earlyDataRequest(vlessPacket({ payload: [1, 2, 3, 4] })), env, ctx);
check('升级返回 101', resp.status === 101, `status=${resp.status}`);
const serverWs = stubs.lastPair[1];

const frames = [];
serverWs.send = (payload) => {
    const view = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
    frames.push(view.slice());
};

await sleep(80);   // 等握手（问候 → CONNECT → 首包）走完
check('确实经过上游代理（问候 + CONNECT + 首包 共 3 次写）', proxyWrites >= 3, `proxyWrites=${proxyWrites} logs=${logs.slice(-2).join(' | ')}`);
check('握手成功（未被关闭、无代理错误日志）',
    proxyClosed === 0 && !logs.some((l) => l.includes('fail to open')),
    `proxyClosed=${proxyClosed} logs=${logs.slice(-3).join(' | ')}`);

// 残留之后的后续 chunk：分两次投喂，检查「残留不会插到它们后面，也不会重复」
proxyReader.enqueue(new Uint8Array(NEXT_BIG));
await sleep(60);
proxyReader.enqueue(new Uint8Array(NEXT_SMALL));
await sleep(120);

// 首帧 = VLESS 响应头（[version, 0]）+ 残留字节（顺序：残留必须在最前）
check('残留字节是下行第一块（紧随 2 字节 VLESS 响应头）',
    frames.length >= 1
    && frames[0].byteLength === 2 + LEFTOVER.byteLength
    && frames[0][0] === 0 && frames[0][1] === 0
    && sameBytes(frames[0].subarray(2), LEFTOVER),
    `frames=${frames.length} firstLen=${frames[0]?.byteLength} expect=${2 + LEFTOVER.byteLength}`);

// 总账：残留 + 后续两块，逐字节一致（不丢、不重、不乱序）
const expected = concatBytes([Uint8Array.from([0, 0]), LEFTOVER, NEXT_BIG, NEXT_SMALL]);
check('残留 + 后续 chunk 总账逐字节一致（不丢/不重/不乱序）',
    sameBytes(concatBytes(frames), expected),
    `got=${concatBytes(frames).byteLength}B expect=${expected.byteLength}B frames=${frames.length}`);

// 残留之后的字节必须来自后续 chunk，而不是残留的重复
check('后续 chunk 确实到达（残留之后仍有数据）',
    concatBytes(frames).byteLength > 2 + LEFTOVER.byteLength,
    `total=${concatBytes(frames).byteLength}B leftoverOnly=${2 + LEFTOVER.byteLength}B`);

restore();
out(failures() === 0 ? '\nws-upstream-leftover: OK' : `\nws-upstream-leftover: ${failures()} 项失败`);
process.exit(failures() === 0 ? 0 : 1);
