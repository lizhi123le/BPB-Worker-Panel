/**
 * tools/ws-connection-limit.test.mjs
 *
 * WS「每 isolate 连接数上限」的行为测试。运行：node tools/ws-connection-limit.test.mjs
 * （package.json 里是 `npm run test:wslimit`）
 *
 * 被测规则（unified.ts）：每条 WS 连接占一个名额，上限 WS_MAX_CONNECTIONS；
 * 超限直接返回 429（不 accept 服务端 socket、不分配任何缓冲）；
 * 连接关闭时名额必须归还（登记在 registerWsCleanup 的清理钩子上）。
 *
 * 为什么要它：这个上限的错误方向是**静默把用户挡在门外**。
 *  - 计数泄漏（只加不减）→ 跑一阵子之后所有客户端都连不上，日志里只有「已达上限」；
 *  - 上限判据写错（>= 写成 >）→ 边界多放一条或少放一条。
 * 这两种都不会让任何既有用例变红，所以单独测。
 *
 * 打桩：复用 ws-test-harness。connect 一调用即抛错，所以每条连接都会走「拨号失败」，
 * 但 101 已返回、名额已占用 —— 正是我们要压测的状态。
 * 桩的 socket.close() 不会触发监听器，因此释放路径由测试显式触发 close 监听器来验证。
 */
import {
    installWebStubs,
    captureConsole,
    makeEnv,
    makeReporter,
    importBundle,
    earlyDataRequest,
    vlessPacket
} from './ws-test-harness.mjs';

const { out, check, failures } = makeReporter();

globalThis.connect = () => {
    throw new Error('connect() is not available in the test harness');
};

const state = installWebStubs();
const { logs } = captureConsole();
const handler = await importBundle();
const ctx = { waitUntil() {}, passThroughOnException() {} };
const env = makeEnv({ SUB_PATH: 'ws-limit-sub-path' });

/** 建一条连接，返回响应状态；成功后把服务端 socket 记下来 */
const openedSockets = [];
async function openConnection() {
    const response = await handler.fetch(earlyDataRequest(vlessPacket()), env, ctx);
    if (response.status === 101) {
        // WebSocketPair 的 [0] 是客户端端、[1] 是服务端端（unified.ts 用 Object.values 解构）
        openedSockets.push(state.lastPair[1]);
    }
    return response.status;
}

// ---------- 1. 一直连到被拒，确认上限数值与拒绝方式 ----------
const EXPECTED_LIMIT = 128;   // 与 unified.ts 的 WS_MAX_CONNECTIONS 对齐
let opened = 0;
let rejectedAt = null;
for (let i = 0; i < EXPECTED_LIMIT + 5; i++) {
    const status = await openConnection();
    if (status === 101) {
        opened++;
    } else {
        rejectedAt = { attempt: i + 1, status };
        break;
    }
}

check(`上限内全部建立成功（${EXPECTED_LIMIT} 条）`, opened === EXPECTED_LIMIT, `opened=${opened}`);
check('超限请求被拒，且状态码为 429', rejectedAt !== null && rejectedAt.status === 429,
    `rejectedAt=${JSON.stringify(rejectedAt)}`);
check('拒绝发生在第 129 次尝试（边界不多不少）', rejectedAt !== null && rejectedAt.attempt === EXPECTED_LIMIT + 1,
    `attempt=${rejectedAt?.attempt}`);
check('拒绝时打出了「已达上限」日志', logs.some((l) => l.includes('[WS 连接上限]')));

// ---------- 2. 关闭一条连接后，名额必须归还 ----------
// 桩的 close() 不触发监听器，这里显式驱动服务端的 close 监听器（真实运行时由 socket.close() 触发）
const victim = openedSockets[0];
victim.listeners.close?.forEach((fn) => fn());

const afterClose = await openConnection();
check('关闭一条后名额归还，新连接可以建立（计数没有泄漏）', afterClose === 101, `status=${afterClose}`);

// ---------- 3. 归还后立刻又满：仍然只放行一条 ----------
const secondReject = await openConnection();
check('名额只有一个：再连一次仍然 429', secondReject === 429, `status=${secondReject}`);

out(failures() === 0 ? '\n全部通过' : `\n${failures()} 项失败`);
process.exit(failures() === 0 ? 0 : 1);
