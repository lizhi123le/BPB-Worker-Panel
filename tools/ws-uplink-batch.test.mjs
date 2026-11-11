/**
 * tools/ws-uplink-batch.test.mjs
 *
 * 上行两阶段（首包后合批）的行为测试。运行：node tools/ws-uplink-batch.test.mjs
 * （package.json 里是 `npm run test:wsbatch`）
 *
 * 为什么要它：上行泵从「逐帧穿过 sink」改成两阶段——
 *   阶段 1：sink 逐帧做填充剥离/协议识别/拨号；
 *   阶段 2：sink 置 byteStreamMode 后，泵攒批（32KiB / 2ms）直写后端 TCP，不再经过 sink。
 * 切换到阶段 2 之后，帧边界就消失了，最容易出的两个事故是：
 *   1) 首包被并进后续帧（首包必须自成一次 TCP 写）；
 *   2) 合批后字节序/字节数错位。
 * 这两条都是"数据相关、低概率、难以在线上复现"的错误，必须在这里钉死。
 *
 * 打桩：globalThis.connect 返回一个「可写但永不回数据」的假 socket，
 * 记录每一次 TCP write；这样能直接观察到「写了几次、每次写了什么字节」。
 * 共用桩（Response/WebSocketPair/KV/首包构造）在 ws-test-harness.mjs。
 *
 * 覆盖（每条断言互不蕴含，避免重复计数）：
 *   1. 首包自成一次写：第一次 TCP 写 == 首包载荷
 *   2. 阶段 2 合批生效：24 个 1.2KiB 帧被合成远少于帧数的写
 *   3. 2ms 定时器：停手后单独发一帧，无需后续帧/关闭也会在限时内落地
 *   4. ≥32KiB 大帧直写：恰好一次写、字节完全一致（不拆分、不与相邻小帧混合）
 *   5. 总账：后端收到的字节 == 首包载荷 + 全部帧（不丢、不重、不乱序）
 *
 * 前提：先构建过（`npm run build`，或快速版 `NODE_ENV=mangle node scripts/build.js`），
 * 本测试直接加载 .build/worker.reference.js（混淆前产物，行为等价且可读）。
 */
import {
    makeReporter, makeEnv, vlessPacket,
    installWebStubs, captureConsole, importBundle, earlyDataRequest
} from './ws-test-harness.mjs';

const { out, check, failures } = makeReporter();

// ── 桩：connect 返回可记录写入的假 socket
const tcpWrites = [];
function makeFakeSocket() {
    return {
        opened: Promise.resolve(),
        closed: new Promise(() => {}),   // 永不关闭：下行没有数据，也不需要触发 client-closed
        readable: new ReadableStream({ start() { /* 保持打开 */ } }),
        writable: new WritableStream({
            write(chunk) {
                const view = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
                tcpWrites.push(view.slice());
            }
        }),
        close() { /* no-op：测试不关心关闭 */ }
    };
}
let connectCalls = 0;
globalThis.connect = () => {
    connectCalls++;
    return makeFakeSocket();
};

const stubs = installWebStubs();
const { logs, restore } = captureConsole();
const handler = await importBundle();
const ctx = { waitUntil() {}, passThroughOnException() {} };
const env = makeEnv({ SUB_PATH: 'ws-uplink-batch-sub-path' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const sameBytes = (a, b) => {
    if (!a || !b || a.byteLength !== b.byteLength) return false;
    for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
    return true;
};

const concatBytes = (chunks) => {
    const total = chunks.reduce((n, c) => n + c.byteLength, 0);
    const outBytes = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { outBytes.set(c, off); off += c.byteLength; }
    return outBytes;
};

/** 通过假 WS 派发一条 message（event.data 为 ArrayBuffer） */
function sendFrame(ws, bytes) {
    const data = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    for (const fn of (ws.listeners.message || [])) fn({ data });
}

// ── 建立连接：首包（含载荷）作为 early data，路由到假 socket
const firstPayload = Uint8Array.from([0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4]);
const response = await handler.fetch(earlyDataRequest(vlessPacket({ payload: firstPayload })), env, ctx);
check('升级返回 101', response.status === 101, `status=${response.status}`);
check('首包触发了一次后端拨号', connectCalls === 1, `connectCalls=${connectCalls} logs=${logs.slice(-3).join(' | ')}`);

const serverWs = stubs.lastPair[1];
await sleep(150);   // 等首包处理（拨号 + 写载荷）完成

// ── 阶段 2：连发 24 个 1.2KiB 帧（总量 28.8KiB < 32KiB，应被合成很少的几次写）
const FRAME_SIZE = 1200;
const FRAME_COUNT = 24;
const frames = [];
for (let i = 0; i < FRAME_COUNT; i++) {
    const f = new Uint8Array(FRAME_SIZE);
    f.fill((i * 37 + 11) & 0xff);
    f[0] = i;             // 帧序号，便于定位错位
    f[1] = (i >> 8) & 0xff;
    frames.push(f);
}
for (const f of frames) sendFrame(serverWs, f);
await sleep(150);

// ── 断言 1：首包仍自成一次写
check('首包保持单帧：第一次 TCP 写 == 首包载荷',
    tcpWrites.length >= 1 && sameBytes(tcpWrites[0], firstPayload),
    `writes=${tcpWrites.length} first=${tcpWrites[0] && tcpWrites[0].byteLength}B`);

// ── 断言 2：阶段 2 生效（合批）
check('阶段 2 已切到合批：写次数远少于帧数',
    tcpWrites.length >= 2 && tcpWrites.length <= 6,
    `frameCount=${FRAME_COUNT} tcpWrites=${tcpWrites.length} sizes=[${tcpWrites.map((w) => w.byteLength).join(',')}]`);

// ── 断言 3：2ms 定时器刷批（停手后单独再发一帧；只有定时器能把它送出去）
const lateFrame = new Uint8Array(700).fill(0xAB);
lateFrame[0] = 0xFF;
const beforeLate = tcpWrites.length;
const t0 = Date.now();
sendFrame(serverWs, lateFrame);
// 没有任何后续帧、也不关闭连接：等待定时器路径自己把这一帧写出去
while (tcpWrites.length === beforeLate && Date.now() - t0 < 500) await sleep(2);
const lateElapsed = Date.now() - t0;
const lateWrites = tcpWrites.slice(beforeLate);
check('2ms 定时器刷批：停手后单独发的一帧在限时内落地',
    lateWrites.length > 0 && sameBytes(concatBytes(lateWrites), lateFrame) && lateElapsed <= 100,
    `elapsed=${lateElapsed}ms lateWrites=${lateWrites.length} sizes=[${lateWrites.map((w) => w.byteLength).join(',')}]`);

// ── 断言 4：≥32KiB 大帧走直写分支（不拆分、不与缓冲里的小帧混合）
const bigFrame = new Uint8Array(40 * 1024);
for (let i = 0; i < bigFrame.length; i++) bigFrame[i] = (i * 31 + 7) & 0xff;
const beforeBig = tcpWrites.length;
sendFrame(serverWs, bigFrame);
await sleep(100);
const bigWrites = tcpWrites.slice(beforeBig);
check('≥32KiB 大帧直写：恰好一次写且字节一致',
    bigWrites.length === 1 && sameBytes(bigWrites[0], bigFrame),
    `writes=${bigWrites.length} sizes=[${bigWrites.map((w) => w.byteLength).join(',')}]`);

// ── 断言 5：总账：TCP 侧收到的字节 = 首包载荷 + 全部帧，顺序一致
const expectedAll = concatBytes([firstPayload, ...frames, lateFrame, bigFrame]);
check('总账：后端收到的字节 == 首包载荷 + 所有帧（不丢不重不乱序）',
    sameBytes(concatBytes(tcpWrites), expectedAll),
    `got=${concatBytes(tcpWrites).byteLength}B expect=${expectedAll.byteLength}B`);

restore();
out(failures() === 0 ? '\nws-uplink-batch: OK' : `\nws-uplink-batch: ${failures()} 项失败`);
process.exit(failures() === 0 ? 0 : 1);
