/**
 * tools/ws-downlink-frame.test.mjs
 *
 * 下行（后端 socket → WS）成帧与缓冲复用的行为测试。运行：node tools/ws-downlink-frame.test.mjs
 * （package.json 里是 `npm run test:downlink`）
 *
 * 为什么要它：下行链路做过两项「零拷贝」改造，都是**不改变可见输出、只改变缓冲生命周期**的改动，
 * 一旦复用距离算错，故障形态是「画面花掉 / 数据错位」这类低概率、难复现的错误：
 *   1) BYOB 缓冲改为三槽轮换（不再每块 new ArrayBuffer(64KiB)）；
 *   2) batcher 的 flush 直接把缓冲视图交给 send()（不再 subarray().slice() + 重新分配）。
 * 这两项的安全前提都是「交出去的缓冲至少隔两代才复用」。这里把它钉成可执行的不变式：
 *
 *   - 大块（≥24KiB）各自成帧、字节完全一致（不拆分、不与相邻数据混合）；
 *   - 小块经 batcher 合帧后字节不丢不重不乱序；
 *   - **相邻两帧永不复用同一块底层 ArrayBuffer**（复用距离 ≥ 1 代）；
 *   - 上行积压超过上限时收口（关 WS），而不是让 isolate 内存无界增长。
 *
 * 打桩说明：WS 的 send() 在真实运行时是同步复制（view 不被保留），所以桩在 send 调用那一刻
 * 就快照字节 —— 这既符合生产语义，也让「缓冲被提前复用」这类错误在断言里暴露成字节不一致。
 *
 * 前提：先构建过（`npm run build` 或 `NODE_ENV=mangle node scripts/build.js`），
 * 本测试加载 .build/worker.reference.js。
 */
import {
    makeReporter, makeEnv, vlessPacket,
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
    const outBytes = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { outBytes.set(c, off); off += c.byteLength; }
    return outBytes;
};

// ── 假后端 socket：下行由 byte stream 提供（支持 BYOB），上行按 plan 决定是否卡住
let plan = { mode: 'stream', queue: [] };
let streamCtrl = null;
/** mode='plain' 时的控制器：readable 不是 byte stream，用于覆盖非 BYOB 回退分支 */
let plainCtrl = null;
let writes = 0;
/** 后端 socket 被 close() 的次数：用来验证「收口时一并关 socket」这条退出路径 */
let socketClosed = 0;
/** connect() 被调用次数：用来确认拨号已发生（socket 已登记）再灌水 */
let socketCreated = 0;

function makeFakeSocket() {
    socketCreated++;
    // mode='plain'：普通 ReadableStream（没有 type:'bytes'）→ 上游 getReader({mode:'byob'}) 会抛错，
    // 代码因此走普通 reader 回退。这是"上游不支持 BYOB"的真实形态。
    const stream = plan.mode === 'plain'
        ? new ReadableStream({
            start(c) { plainCtrl = c; },
            pull() { /* 由测试主动 enqueue */ }
        })
        : new ReadableStream({
            type: 'bytes',
            start(c) { streamCtrl = c; },
            pull() { /* 由测试主动 enqueue，这里不自动吐数据 */ }
        });
    return {
        opened: Promise.resolve(),
        closed: new Promise(() => {}),
        readable: stream,
        writable: new WritableStream({
            write() {
                writes++;
                // mode='block'：永远不 resolve —— 模拟后端堵死，用于验证上行背压收口
                if (plan.mode === 'block') return new Promise(() => {});
                return undefined;
            }
        }),
        close() { socketClosed++; }
    };
}

const closed = [];
globalThis.connect = () => makeFakeSocket();

const stubs = installWebStubs({ onClose: (code, reason) => closed.push({ code, reason }) });
const { logs, restore } = captureConsole();
const handler = await importBundle();
const ctx = { waitUntil() {}, passThroughOnException() {} };
const env = makeEnv({ SUB_PATH: 'ws-downlink-sub-path' });

/** 建立一条 WS，并接管服务端 WS 的 send：发送那一刻快照字节 + 记录底层缓冲标识 */
async function openConnection(tag, envOverride = null) {
    const before = stubs.lastPair;
    const resp = await handler.fetch(earlyDataRequest(vlessPacket({ payload: [1, 2, 3, 4] })), envOverride ?? env, ctx);
    if (resp.status !== 101) throw new Error(`${tag}: 升级失败 status=${resp.status}`);
    const serverWs = stubs.lastPair[1];
    if (stubs.lastPair === before) throw new Error(`${tag}: WebSocketPair 未重建`);
    const frames = [];
    serverWs.send = (payload) => {
        const view = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
        frames.push({ bytes: view.slice(), bufferId: view.buffer });
    };
    await sleep(60); // 等首包处理完成（拨号 + 首包写）
    return { serverWs, frames };
}

// =========================================================== 用例 1：成帧 + 缓冲轮换
check('BYOB 可用（否则本用例覆盖不到轮换路径）', (() => {
    try {
        const s = new ReadableStream({ type: 'bytes', pull() {} });
        s.getReader({ mode: 'byob' }).releaseLock();
        return true;
    } catch { return false; }
})());

const { frames } = await openConnection('case1');

const BIG = 64 * 1024;
// 注意：byte stream 的 enqueue() 会 **transfer（detach）** 传入的缓冲区，
// 因此所有用于断言的期望值必须在 enqueue 之前快照出来。
const blockA = new Uint8Array(BIG).fill(0xA1);
const blockB = new Uint8Array(BIG).fill(0xB2);
const blockC = new Uint8Array(BIG).fill(0xC3);
const expectA = blockA.slice();
const expectB = blockB.slice();
const expectC = blockC.slice();
const smalls = [];
for (let i = 0; i < 8; i++) {
    const f = new Uint8Array(8 * 1024);
    f.fill((i * 17 + 3) & 0xff);
    f[0] = i;           // 帧序号，便于定位错位
    smalls.push(f.slice());      // 期望值快照
}
const sendSmall = [];
for (let i = 0; i < 8; i++) {
    const f = new Uint8Array(8 * 1024);
    f.fill((i * 17 + 3) & 0xff);
    f[0] = i;
    sendSmall.push(f);           // 真正投喂的副本（会被 detach）
}

// 逐块投喂：给读循环留出「读一块 → 发一帧 → 读下一块」的间隔
for (const block of [blockA, blockB, blockC]) {
    streamCtrl.enqueue(block);
    await sleep(40);
}
for (const f of sendSmall) streamCtrl.enqueue(f);
await sleep(150);
try { streamCtrl.close(); } catch { /* 已关闭 */ }
await sleep(150);

// 首帧带 VLESS 响应头（2 字节：[version, 0]），其余大块各自成帧
check('大块各自成帧：帧数符合预期（3 个大块 + batcher 合帧）',
    frames.length >= 4 && frames.length <= 6,
    `frames=${frames.length} sizes=[${frames.map((f) => f.bytes.byteLength).join(',')}]`);

check('首帧 = 2 字节响应头 + 第一块（未拆分）',
    frames[0].bytes.byteLength === 2 + BIG
    && frames[0].bytes[0] === 0 && frames[0].bytes[1] === 0
    && sameBytes(frames[0].bytes.subarray(2), expectA),
    `len=${frames[0] && frames[0].bytes.byteLength} head=[${frames[0] && [...frames[0].bytes.subarray(0, 4)]}]`);

check('第二帧 == 第二块（字节完全一致）', sameBytes(frames[1].bytes, expectB),
    `len=${frames[1] && frames[1].bytes.byteLength}`);
check('第三帧 == 第三块（字节完全一致）', sameBytes(frames[2].bytes, expectC),
    `len=${frames[2] && frames[2].bytes.byteLength}`);

// 缓冲轮换不变式：相邻两帧的底层 ArrayBuffer 必须是不同的两块
let sharedBuffer = -1;
for (let i = 0; i + 1 < frames.length; i++) {
    if (frames[i].bufferId === frames[i + 1].bufferId) { sharedBuffer = i; break; }
}
check('相邻帧不复用同一底层缓冲（交出后至少隔一代再复用）', sharedBuffer === -1,
    `第 ${sharedBuffer} 与 ${sharedBuffer + 1} 帧共用同一 ArrayBuffer`);

const smallFrames = frames.slice(3);
const smallTotal = smallFrames.reduce((n, f) => n + f.bytes.byteLength, 0);
check('小块经 batcher 合批：总字节不变、帧数远少于 8 帧',
    smallTotal === smalls.length * 8 * 1024 && smallFrames.length <= 4,
    `smallFrames=${smallFrames.length} total=${smallTotal}B expect=${smalls.length * 8 * 1024}B`);
check('小块合批后字节序正确（不丢不重不乱序）',
    sameBytes(concatBytes(smallFrames.map((f) => f.bytes)), concatBytes(smalls)),
    `got=${smallTotal}B`);

check('总账：WS 侧收到的字节 == 响应头 + 全部下行数据',
    sameBytes(concatBytes(frames.map((f) => f.bytes)), concatBytes([Uint8Array.from([0, 0]), expectA, expectB, expectC, ...smalls])),
    `frames=${frames.length}`);

// =========================================================== 用例 2：上行积压超限收口
// 积压上限是「isolate 预算 ÷ 连接数」折算出来的，默认 32MiB 很难在测试里打满，
// 所以用 env 把它压到 512KiB（每连接 256KiB 下限）—— 这也顺带验证了 env 旋钮生效。
plan = { mode: 'block', queue: [] };
const closedBefore = closed.length;
const logsBefore = logs.length;
const second = await openConnection('case2', makeEnv({
    SUB_PATH: 'ws-downlink-backlog',
    WS_UPLINK_ISOLATE_MB: '0.5'
}));
// 等拨号真正发生（socket 已建立并登记）再灌水：积压只可能在"写不出去"时累积。
// 不能用 writes 判断：block 模式下首包写永不 resolve，writes 不会再增长。
// socketCreated 在 openConnection 的等待窗口内已增加，这里只做一次"至少拨过两次"的健全性检查
// （用例 1 的竞速可能创建多个候选 socket）。
await sleep(120);
check('上行积压用例：拨号已发生（socket 已建立并登记）', socketCreated >= 2,
    `socketCreated=${socketCreated}`);

// 后端永不完成写 → 上行泵卡住 → 队列增长；超过 256KiB 上限时必须收口
const FLOOD_FRAME = 8 * 1024;
const flood = new Uint8Array(FLOOD_FRAME).fill(0x5A);
const listener = second.serverWs.listeners.message[0];
for (let i = 0; i < 1200 && closed.length === closedBefore; i++) {
    listener({ data: flood.buffer.slice(0) });
}
await sleep(150);

const backlogLog = logs.slice(logsBefore).find((l) => l.includes('uplink backlog'));
check('上行积压超限：打出 uplink backlog 日志并关闭 WS', !!backlogLog && closed.length > closedBefore,
    `closed=${closed.length - closedBefore} logs=${logs.slice(logsBefore).slice(-2).join(' | ')}`);
check('上行积压超限：收口前没有吞掉数据写（后端只收到已交出批次）', writes >= 1, `writes=${writes}`);

// 收口必须**释放后端 socket**：否则上行泵可能正卡在写不出去的 await 上永远不退出，
// 积压的字节与 socket 一起挂到调用结束（评审 MAJOR）。清理钩子里注册了 safeCloseTcpSocket。
check('上行积压超限：后端 socket 被一并关闭（泵有退出路径）', socketClosed >= 1, `socketClosed=${socketClosed}`);

// =========================================================== 用例 3：下行会话字节预算（env 开启时才生效）
// 默认关闭属于策略选择；一旦开启，超限必须在**发送之前**收口，而不是把超出的块也吐出去。
plan = { mode: 'stream', queue: [] };
const closedBeforeBudget = closed.length;
const logsBeforeBudget = logs.length;
const budgetEnv = makeEnv({ SUB_PATH: 'ws-downlink-budget', WS_SESSION_MAX_MB: '0.001' }); // ≈1048B
const third = await openConnection('case3', budgetEnv);
streamCtrl.enqueue(new Uint8Array(64 * 1024).fill(0x77));  // 单块即超预算
await sleep(150);
const budgetLog = logs.slice(logsBeforeBudget).find((l) => l.includes('session downlink budget'));
check('会话字节预算：超限即收口（打日志 + 关 WS）', !!budgetLog && closed.length > closedBeforeBudget,
    `closed=${closed.length - closedBeforeBudget} logs=${logs.slice(logsBeforeBudget).slice(-2).join(' | ')}`);
check('会话字节预算：超限的块不会被发送（预算判定在 send 之前）', third.frames.length === 0,
    `frames=${third.frames.length}`);

// =========================================================== 用例 4：三槽轮换不变式（缓冲区身份序列）
// 原本想用「延迟复制桩」钉住"提前复用"，但 BYOB 的 `read(view)` 会 **transfer（detach）** 缓冲区，
// 保留的 view 在下一轮就失效（实测抛 "detached ArrayBuffer"）——延后快照在这个模型下不可行。
// 等价且更直接的判据是**缓冲区身份序列**：交给 send 的每块底层 ArrayBuffer 必须与前面 2 帧都不同，
// 即复用距离 ≥3 代。1 槽（立即复用）或 2 槽都会在这里露馅。
plan = { mode: 'stream', queue: [] };
const fourth = await openConnection('case4');
const identity = [];
fourth.serverWs.send = (payload) => {
    const view = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
    identity.push({ buffer: view.buffer, length: view.byteLength, head: view[0] });
};
const identityBlocks = [0x11, 0x22, 0x33, 0x44, 0x55].map((v) => new Uint8Array(64 * 1024).fill(v));
const identityExpect = identityBlocks.map((b) => b.slice());
for (const b of identityBlocks) {
    streamCtrl.enqueue(b);
    await sleep(35);
}
await sleep(60);
const bigIdentities = identity.filter((f) => f.length >= 64 * 1024);
let recentOverlap = -1;
for (let i = 3; i < bigIdentities.length; i++) {
    for (let back = 1; back <= 2; back++) {
        if (bigIdentities[i].buffer === bigIdentities[i - back].buffer) { recentOverlap = i; break; }
    }
    if (recentOverlap !== -1) break;
}
check('三槽轮换：任意帧都不与前 2 帧共用底层缓冲（复用距离 ≥3 代）',
    bigIdentities.length >= 4 && recentOverlap === -1,
    `bigFrames=${bigIdentities.length} overlapAt=${recentOverlap}`);
check('三槽轮换：每帧首字节仍对应正确的块（数据未被覆盖）',
    bigIdentities.length >= 4
    && bigIdentities.every((f, i) => (i === 0
        ? f.head === 0                                   // 首帧开头是 2 字节 VL 响应头
        : f.head === identityExpect[i]?.[0])),           // 第 i 帧装的就是第 i 块
    `heads=[${bigIdentities.map((f) => f.head).join(',')}] expect=[0,${identityExpect.map((b) => b[0]).join(',')}]`);

// =========================================================== 用例 5：阈值边界（24576 / 24577）
// 24KiB 是「直发 vs 合帧」的分界。差一个字节就必须**不丢不重**，这是 off-by-one 的经典位置。
plan = { mode: 'stream', queue: [] };
const fifth = await openConnection('case5');
const atBoundary = new Uint8Array(24576).fill(0x5C);     // == DOWNLOAD_PACKET_MIN → 合帧
const overBoundary = new Uint8Array(24577).fill(0x6D);   // +1 → 直发
const boundaryExpect = [atBoundary.slice(), overBoundary.slice()];
streamCtrl.enqueue(atBoundary);
await sleep(40);
streamCtrl.enqueue(overBoundary);
await sleep(80);
try { streamCtrl.close(); } catch { /* 已关闭 */ }
await sleep(80);
check('阈值边界：24576 / 24577 字节均完整送达（不丢不重）',
    sameBytes(concatBytes(fifth.frames.map((f) => f.bytes)),
        concatBytes([Uint8Array.from([0, 0]), boundaryExpect[0], boundaryExpect[1]])),
    `frames=${fifth.frames.length} sizes=[${fifth.frames.map((f) => f.bytes.byteLength).join(',')}]`);

// =========================================================== 用例 6：非 BYOB 回退
// 上游 socket 的 readable 不是 byte stream 时，getReader({mode:'byob'}) 会抛错 → 走普通 reader。
// 这条回退分支此前零覆盖，而它决定了"上游不支持 BYOB 时是否还能正确成帧"。
plan = { mode: 'plain', queue: [] };
const sixth = await openConnection('case6');
const plainChunk = new Uint8Array(40 * 1024).fill(0x7E);
const plainExpect = plainChunk.slice();
plainCtrl.enqueue(plainChunk);
await sleep(120);
check('非 BYOB 回退：普通 reader 下仍能正确成帧',
    sameBytes(concatBytes(sixth.frames.map((f) => f.bytes)), concatBytes([Uint8Array.from([0, 0]), plainExpect])),
    `frames=${sixth.frames.length} sizes=[${sixth.frames.map((f) => f.bytes.byteLength).join(',')}]`);

restore();
out(failures() === 0 ? '\nws-downlink-frame: OK' : `\nws-downlink-frame: ${failures()} 项失败`);
process.exit(failures() === 0 ? 0 : 1);
