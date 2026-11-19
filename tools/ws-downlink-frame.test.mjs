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

// =========================================================== 用例 7：下行速率上限（env 开启才生效）
// 为什么必须钉这条：workers-types 的 WebSocket **没有 bufferedAmount**、send() 返回 void，
// 平台没有任何发送侧背压。客户端慢于上游时未发完的帧只能在运行时里无界堆积，表现为
// 「越播越卡 → 最后断」（延迟线性增长 + 堆顶到内存上限）。节流是唯一能形成端到端背压的点：
// await 令牌 → 不 read() → socket 接收缓冲满 → TCP 窗口关闭 → 上游停顿。
// 容量 = clamp(min(速率, WS_DOWNLINK_BURST_KB), 下限 256KiB)：本用例 128KiB/s → 容量 256KiB
//（突发额度默认 3MB 不构成限制，限制来自速率；256KiB 是「必须大于单块」的下界）。
// 结果：先放 256KiB，其余按 128KiB/s 排队。
plan = { mode: 'stream', queue: [] };
const seventh = await openConnection('case7', makeEnv({
    SUB_PATH: 'ws-downlink-throttle',
    WS_DOWNLINK_BPS: '131072'
}));
const throttleTotal = () => seventh.frames.reduce((n, f) => n + f.bytes.byteLength, 0);
const throttleBlocks = [];
for (let i = 0; i < 8; i++) {
    const b = new Uint8Array(64 * 1024);
    b.fill(i + 1);
    throttleBlocks.push(b.slice());   // enqueue 会 detach，期望值必须先快照
    streamCtrl.enqueue(b);
}
await sleep(150);
const earlyBytes = throttleTotal();
check('下行节流：容量内先放行（≤ 256KiB 容量 + 一个块）', earlyBytes <= 256 * 1024 + 64 * 1024,
    `early=${earlyBytes}B`);
await sleep(2200);
// +2 是首帧前面的 VLESS 响应头（[version, 0]）
check('下行节流：其余字节按上限排队后到齐（不丢）', throttleTotal() === 8 * 64 * 1024 + 2,
    `later=${throttleTotal()}B expect=${8 * 64 * 1024 + 2}B`);
check('下行节流：全量字节序正确（节流不改内容）',
    sameBytes(concatBytes(seventh.frames.map((f) => f.bytes)),
        concatBytes([Uint8Array.from([0, 0]), ...throttleBlocks])),
    `frames=${seventh.frames.length}`);

// =========================================================== 用例 8：send() 返回 thenable 时串行化
// workers-types 声明 send(): void，但运行时若返回 Promise，await 它就是**真背压**。
// 判据：任何时刻只有一笔 send 在飞（不允许「上一笔还没被收下就发下一块」）。
plan = { mode: 'stream', queue: [] };
const eighth = await openConnection('case8');
let inFlight = 0;
let maxInFlight = 0;
eighth.serverWs.send = (payload) => {
    const view = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
    inFlight++;
    if (inFlight > maxInFlight) maxInFlight = inFlight;
    eighth.frames.push({ bytes: view.slice(), bufferId: view.buffer });
    return new Promise((resolve) => setTimeout(() => { inFlight--; resolve(); }, 30));
};
const backBlocks = [0x21, 0x22, 0x23, 0x24].map((v) => new Uint8Array(64 * 1024).fill(v));
const backExpect = backBlocks.map((b) => b.slice());
for (const b of backBlocks) {
    streamCtrl.enqueue(b);
    await sleep(5);
}
await sleep(300);
check('send() 返回 thenable：任何时刻只有一笔在飞（真背压）', maxInFlight === 1, `maxInFlight=${maxInFlight}`);
check('send() 返回 thenable：字节仍完整有序',
    sameBytes(concatBytes(eighth.frames.map((f) => f.bytes)),
        concatBytes([Uint8Array.from([0, 0]), ...backExpect])),
    `frames=${eighth.frames.length}`);

// 注：曾有过「读块/帧长可调」（WS_DL_BLOCK_KIB / WS_DL_FRAME_KIB）的用例，实测 4K 反而更卡
// 已连同实现一起回滚 —— 帧长基准调大会把分流阈值抬高，原本直发的中等块被推回 batcher 的
// 1~3ms 定时器里排队，延迟变差；读块放大的收益则被「窗口/RTT 是平台属性」这条否掉。
// 因此尺寸是常量，这里不再保留开关用例。

// =========================================================== 用例 9：默认值钉死 + 显式 0 可关闭
// 这两个默认值现在是**默认开启**的（速率上限、会话字节预算），所以它们
// 必须像 WS_MAX_CONNECTIONS 一样在测试里钉住：改默认值 = 改所有部署的行为，不能悄悄漂。
// 判据用 debug 仪表那一行（它把生效值原样打出来），不靠读实现常量。
// 用 WS_DOWNLINK_STATS=1 开仪表，而不是改 globalThis.settings —— 后者会被 KV 里的
// settings 快照（getKvCache，5 分钟 TTL）覆盖回去，测试会变成偶发失败。
const STATS_ENV = { WS_DOWNLINK_STATS: '1' };
plan = { mode: 'stream', queue: [] };
const logsBeforeDefaults = logs.length;
await openConnection('case9', makeEnv({ SUB_PATH: 'ws-downlink-defaults', ...STATS_ENV }));
// 仪表在每次 read 之前判定，所以要跨过 1 秒且持续有数据，才会打印
for (let i = 0; i < 15; i++) {
    streamCtrl.enqueue(new Uint8Array(8 * 1024).fill(0x51));
    await sleep(100);
}
const defaultLines = logs.slice(logsBeforeDefaults).filter((l) => l.includes('downlink '));
// 默认值已按业主指定调整为 20MiB/s（20971520 B/s）/ 900MiB（突发 3MiB：见下一段的显式 env 用例，
// 这里只钉「未设 env 时生效的是哪个数」，所以断言的是 B/s 与预算的绝对值）。
check('默认值：下行速率上限默认 20MiB/s', defaultLines.some((l) => l.includes('cap=20971520B/s')),
    `lines=${defaultLines.slice(-2).join(' | ')}`);
check('默认值：会话字节预算默认 900MB', defaultLines.some((l) => l.includes('budget=943718400B')),
    `lines=${defaultLines.slice(-2).join(' | ')}`);

// 显式 0 = 关闭（默认值不再是 0 之后，这是唯一的回滚开关）
plan = { mode: 'stream', queue: [] };
const logsBeforeOff = logs.length;
const tenth = await openConnection('case10', makeEnv({
    SUB_PATH: 'ws-downlink-off',
    ...STATS_ENV,
    WS_DOWNLINK_BPS: '0',
    WS_SESSION_MAX_MB: '0'
}));
for (let i = 0; i < 15; i++) {
    streamCtrl.enqueue(new Uint8Array(8 * 1024).fill(0x52));
    await sleep(100);
}
const offLines = logs.slice(logsBeforeOff).filter((l) => l.includes('downlink '));
check('默认值：显式 0 可同时关闭速率上限与字节预算（回滚开关）',
    offLines.some((l) => l.includes('cap=off') && l.includes('budget=off')),
    `lines=${offLines.slice(-2).join(' | ')}`);
await sleep(200);
check('默认值用例：关闭后仍逐字节送达', sameBytes(concatBytes(tenth.frames.map((f) => f.bytes)),
    concatBytes([Uint8Array.from([0, 0]), ...Array.from({ length: 15 }, () => new Uint8Array(8 * 1024).fill(0x52))])),
    `frames=${tenth.frames.length}`);

// =========================================================== 用例 10：小块持续喂入的吞吐与合批质量
// 4K 的实际读侧形态可能不是 64KiB 整块，而是持续的小块（3~16KiB）。这条用例钉两件事：
//   1) 饱和喂入下管线的吞吐不会被 batcher 的定时器拖住（≥6MB/s，约为 4K 码率的 2 倍）；
//   2) 合批没有退化成"一块一帧"（平均帧 ≥4KiB），否则帧数暴涨会直接吃掉 CPU 预算。
// 关掉限速（WS_DOWNLINK_BPS=0），否则测的是令牌桶而不是 batcher。
// 注意测法：**先把总量同步塞进流里**，再量"多长时间全部送达"——
// 若改成"喂一轮 await 一次 setTimeout"，测到的是 Node 定时器粒度（实测 ~14ms/轮），
// 不是管线（第一版就这么写的，结果 1.6MB/s 全是假信号）。
plan = { mode: 'stream', queue: [] };
const chunkCase = await openConnection('case11', makeEnv({
    SUB_PATH: 'ws-downlink-smallchunk',
    WS_DOWNLINK_BPS: '0'
}));
const SMALL = 3 * 1024;
const TOTAL_CHUNKS = 8 * 1024;                 // 8192 × 3KiB = 24MiB
const offered = SMALL * TOTAL_CHUNKS;
const startedAt = Date.now();
for (let i = 0; i < TOTAL_CHUNKS; i++) streamCtrl.enqueue(new Uint8Array(SMALL).fill(0x61));
// 等送达（首帧含 2 字节 VLESS 响应头）；上限 5s 防挂死
let delivered = 0;
while (Date.now() - startedAt < 5000) {
    delivered = chunkCase.frames.reduce((n, f) => n + f.bytes.byteLength, 0) - 2;
    if (delivered >= offered) break;
    await sleep(20);
}
const elapsedMs = Date.now() - startedAt;
const frameCount = chunkCase.frames.length;
const mbPerSec = (delivered / 1048576) / (elapsedMs / 1000);
check('小块饱和喂入：吞吐 ≥ 6MB/s（batcher 定时器没有成为瓶颈）', mbPerSec >= 6,
    `${mbPerSec.toFixed(1)}MB/s delivered=${delivered}B in ${elapsedMs}ms frames=${frameCount}`);
check('小块饱和喂入：平均帧 ≥ 4KiB（仍在合批，没有退化成一帧一块）',
    frameCount > 0 && delivered / frameCount >= 4096,
    `avgFrame=${frameCount ? Math.round(delivered / frameCount) : 0}B frames=${frameCount}`);
check('小块饱和喂入：字节总量与喂入量一致（不丢不重）', delivered === offered,
    `delivered=${delivered}B offered=${offered}B`);

// =========================================================== 用例 12：会话生命周期上限（先于平台的 loadShed 主动换连接）
// 现场依据（2026-11-16）：平台在 ~20 分钟窗口把长连接 load-shed 掉（`$workers.outcome = "loadShed"`，
// wallTimeMs ≈ 1.17e6、cpuTimeMs ≈ 20），客户端拿到 1101 `internal error; reference = …`。
// 这条用例钉住「服务端比平台先动手」：上限设 1s，看门狗粒度自动从 5s 降到 250ms。
check('默认值：会话看门狗默认 idle=599s / max=899s',
    logs.some((l) => l.includes('session guard: idle=599s max=899s')),
    `guardLines=${logs.filter((l) => l.includes('session guard')).slice(-2).join(' | ')}`);

plan = { mode: 'stream', queue: [] };
const closedBeforeMax = closed.length;
await openConnection('case13', makeEnv({
    SUB_PATH: 'ws-session-max',
    WS_MAX_SESSION_S: '1',
    WS_IDLE_TIMEOUT_S: '0'
}));
await sleep(1800);
check('会话上限：到点主动关 WS（不等平台 shed）', closed.length > closedBeforeMax,
    `closed=${closed.length - closedBeforeMax}`);
check('会话上限：日志点明原因', logs.some((l) => l.includes('session reached max 1s')),
    `tail=${logs.slice(-3).join(' | ')}`);
const closedAfterMax = closed.length;
await sleep(800);
check('会话上限：到期只收口一次（看门狗不重复 close / 不刷日志）', closed.length === closedAfterMax,
    `again=${closed.length - closedAfterMax}`);

plan = { mode: 'stream', queue: [] };
const closedBeforeIdle = closed.length;
await openConnection('case14', makeEnv({
    SUB_PATH: 'ws-session-idle',
    WS_IDLE_TIMEOUT_S: '1',
    WS_MAX_SESSION_S: '0'
}));
await sleep(1800);
check('空闲超时：双向都无流量时主动关 WS', closed.length > closedBeforeIdle,
    `closed=${closed.length - closedBeforeIdle}`);
check('空闲超时：日志点明原因', logs.some((l) => l.includes('session idle')),
    `tail=${logs.slice(-3).join(' | ')}`);

// 回滚开关：显式 0 同时关闭两项 → 看门狗不登记，连接不会被本机制打断
plan = { mode: 'stream', queue: [] };
const closedBeforeOffGuard = closed.length;
const noGuard = await openConnection('case15', makeEnv({
    SUB_PATH: 'ws-session-off',
    WS_IDLE_TIMEOUT_S: '0',
    WS_MAX_SESSION_S: '0'
}));
streamCtrl.enqueue(new Uint8Array(4096).fill(0x71));
await sleep(1500);
check('回滚开关：显式 0 关闭两项后连接不会被打断', closed.length === closedBeforeOffGuard,
    `closed=${closed.length - closedBeforeOffGuard}`);
check('回滚开关：关闭后仍能正常下行',
    noGuard.frames.reduce((n, f) => n + f.bytes.byteLength, 0) >= 2 + 4096,
    `bytes=${noGuard.frames.reduce((n, f) => n + f.bytes.byteLength, 0)}`);

// =========================================================== 用例 13：突发额度与速率解耦（WS_DOWNLINK_BURST_KB）
// 现场依据（2026-11-16）：测速场景同时开 8 条连接，旧实现「容量 = 速率」= 每条可瞬时灌 10MB，
// 8 条 = 80MB，直接把 128MB 的 isolate 顶到平台回收（报 internal error 而非 1102）。
// 这条用例钉住两件事：突发额度按 KB 生效；显式 0 回到旧行为（容量 = 速率）。
const burstTotal = (conn) => conn.frames.reduce((n, f) => n + f.bytes.byteLength, 0);

plan = { mode: 'stream', queue: [] };
const burstConn = await openConnection('case16', makeEnv({
    SUB_PATH: 'ws-downlink-burst',
    WS_DOWNLINK_BPS: '1048576',      // 1MB/s：速率不是这一段的限制，限制来自容量
    WS_DOWNLINK_BURST_KB: '256'      // 容量 = 256KiB
}));
for (let i = 0; i < 32; i++) streamCtrl.enqueue(new Uint8Array(64 * 1024));  // 共 2MiB
await sleep(500);
const burstEarly = burstTotal(burstConn);
// 期望 ≈ 256KiB 容量 + 500ms × 1MB/s ≈ 756KiB；旧行为（容量=1MB）会是 ≈1.5MB
check('突发额度：容量按 WS_DOWNLINK_BURST_KB 咬住（500ms 内 < 1MiB）', burstEarly < 1024 * 1024,
    `early=${burstEarly}B`);
await sleep(2200);   // 余量 ≈ (2MiB-256KiB)/1MiB/s ≈ 1.75s
check('突发额度：限速后余下字节仍全部到齐（不丢）', burstTotal(burstConn) === 32 * 64 * 1024 + 2,
    `total=${burstTotal(burstConn)}B expect=${32 * 64 * 1024 + 2}B`);

plan = { mode: 'stream', queue: [] };
const legacyConn = await openConnection('case17', makeEnv({
    SUB_PATH: 'ws-downlink-burst-off',
    WS_DOWNLINK_BPS: '1048576',
    WS_DOWNLINK_BURST_KB: '0'        // 显式 0 = 回滚：容量重新等于速率（1MiB）
}));
for (let i = 0; i < 32; i++) streamCtrl.enqueue(new Uint8Array(64 * 1024));
await sleep(500);
const legacyEarly = burstTotal(legacyConn);
check('突发额度：显式 0 回到「容量 = 速率」的旧行为（500ms 内 ≥ 1MiB）', legacyEarly >= 1024 * 1024,
    `early=${legacyEarly}B`);

restore();
out(failures() === 0 ? '\nws-downlink-frame: OK' : `\nws-downlink-frame: ${failures()} 项失败`);
process.exit(failures() === 0 ? 0 : 1);
