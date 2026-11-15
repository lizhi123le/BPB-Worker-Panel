/**
 * tools/ws-connection-limit.test.mjs
 *
 * WS「每 isolate 连接数上限」的行为测试。运行：node tools/ws-connection-limit.test.mjs
 * （package.json 里是 `npm run test:wslimit`）
 *
 * 被测规则（unified.ts）：每条 WS 连接占一个名额，上限由 env `WS_MAX_CONNECTIONS` 决定
 * （默认 128，钳制 1~1024，非法值回退默认，高于默认值会 warn 一次）；
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
    vlessPacket,
    ORIGIN
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

/** 建一条连接，返回响应状态；成功后把服务端 socket 记下来（env 可覆盖，供 env 用例复用同一条路径） */
const openedSockets = [];
async function openConnection(envOverride = null) {
    const response = await handler.fetch(earlyDataRequest(vlessPacket()), envOverride ?? env, ctx);
    if (response.status === 101) {
        // WebSocketPair 的 [0] 是客户端端、[1] 是服务端端（unified.ts 用 Object.values 解构）
        openedSockets.push(state.lastPair[1]);
    }
    return response.status;
}

/** 归还当前所有名额（桩的 close() 不触发监听器，必须显式驱动服务端的 close 监听器） */
function releaseAll() {
    for (const socket of openedSockets) socket.listeners.close?.forEach((fn) => fn());
    openedSockets.length = 0;
}

// ---------- 0. 路径门禁：移除 WS 黑名单检查后，保护没有减少 ----------
// WS 分支不再调 guardPermanentBlacklist（与 cfnew 一致），但「含字典外段」的 WS 路径
// 仍被下一步的字典校验拦成 429 —— 能通过字典校验的请求，按黑名单的豁免判据本来就必然放行。
// 注意：这一段必须跑在上限测试**之前**，否则名额已满，429 会来自连接上限而不是路径门禁。
const badPath = await handler.fetch(new Request(ORIGIN + '/zzz-not-in-dictionary', {
    headers: { Host: 'panel.example.com', Upgrade: 'websocket', 'CF-Connecting-IP': '203.0.113.9' }
}), env, ctx);
await badPath.text();
check('WS：非字典路径被字典校验拦成 429（移除黑名单检查后保护不减）', badPath.status === 429, `status=${badPath.status}`);

// 字典内路径（= 随机路径形态）仍可正常升级
const okPath = await handler.fetch(new Request(ORIGIN + '/blog/news', {
    headers: { Host: 'panel.example.com', Upgrade: 'websocket', 'CF-Connecting-IP': '203.0.113.9' }
}), env, ctx);
check('WS：字典内随机路径仍可正常升级（未被误伤）', okPath.status === 101, `status=${okPath.status}`);

// 释放这条连接占用的名额，避免影响下面的上限测试（桩的 close() 不触发监听器，显式驱动）
if (okPath.status === 101) state.lastPair[1].listeners.close?.forEach((fn) => fn());

// ---------- 1. 一直连到被拒，确认上限数值与拒绝方式 ----------
const EXPECTED_LIMIT = 128;   // 默认值（unified.ts 的 WS_MAX_CONNECTIONS_DEFAULT / env WS_MAX_CONNECTIONS）
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
check(`拒绝发生在第 ${EXPECTED_LIMIT + 1} 次尝试（边界不多不少）`,
    rejectedAt !== null && rejectedAt.attempt === EXPECTED_LIMIT + 1,
    `attempt=${rejectedAt?.attempt}`);
check('拒绝时打出了「已达上限」日志', logs.some((l) => l.includes('[WS 连接上限]')));

// ---------- 2. 关闭一条连接后，名额必须归还 ----------
// 桩的 close() 不触发监听器，这里显式驱动服务端的 close 监听器（真实运行时由 socket.close() 触发）
const victim = openedSockets[0];
victim.listeners.close?.forEach((fn) => fn());

const afterClose = await openConnection();
check('关闭一条后名额归还，新连接可以建立（计数没有泄漏）', afterClose === 101, `status=${afterClose}`);

// ---------- 3. 归还后立刻又满：仍然只放行一条 ----------
// 这里已经同时证明了「上限仍然生效」——被拒的请求不占名额，所以下一次仍是同一状态，
// 不需要再补一条等价的 429 断言。
const secondReject = await openConnection();
check('名额只有一个：归还后只能补一条，再连仍然 429', secondReject === 429, `status=${secondReject}`);

// ---------- 4. env WS_MAX_CONNECTIONS 可调：调低后确切的边界 ----------
// 先把这一轮占用的名额全部归还（计数是模块级的，不清零后面测小上限会一直被 429 挡住）
releaseAll();

const smallEnv = makeEnv({ SUB_PATH: 'ws-limit-small', WS_MAX_CONNECTIONS: '4' });
let smallOpened = 0;
let smallRejectedAt = null;
for (let i = 0; i < 6; i++) {
    const status = await openConnection(smallEnv);
    if (status === 101) {
        smallOpened++;
    } else {
        smallRejectedAt = { attempt: i + 1, status };
        break;
    }
}
check('env 调低上限：4 条建立成功', smallOpened === 4, `opened=${smallOpened}`);
check('env 调低上限：第 5 条被拒（429）',
    smallRejectedAt !== null && smallRejectedAt.attempt === 5 && smallRejectedAt.status === 429,
    `rejectedAt=${JSON.stringify(smallRejectedAt)}`);
check('env 调低上限：拒绝日志里带的是生效值（4）而不是默认值',
    logs.some((l) => l.includes('[WS 连接上限] 已达 4 条')),
    `logs=${logs.slice(-2).join(' | ')}`);

// ---------- 5. 钳制：越界值按边界处理并 warn 一次（笔误不能打死 isolate） ----------
releaseAll();
const logsBeforeClamp = logs.length;
const hugeResp = await openConnection(makeEnv({ SUB_PATH: 'ws-limit-huge', WS_MAX_CONNECTIONS: '100000' }));
check('越界值：仍按钳制后的上限放行（不静默接受 100000）', hugeResp === 101, `status=${hugeResp}`);
check('越界值：打出一条「超出 1~1024 安全范围，按 1024 处理」警告',
    logs.slice(logsBeforeClamp).some((l) => l.includes('超出 1~1024 安全范围，按 1024 处理')),
    `logs=${logs.slice(logsBeforeClamp).slice(-2).join(' | ')}`);
releaseAll();

// ---------- 6. 非法值回退默认：不 warn、不限成 0 ----------
const logsBeforeBad = logs.length;
const badResp = await openConnection(makeEnv({ SUB_PATH: 'ws-limit-bad', WS_MAX_CONNECTIONS: 'abc' }));
check('非法值：回退默认上限而不是把所有人挡在门外', badResp === 101, `status=${badResp}`);
check('非法值：不产生「超出安全范围」警告（静默回退到默认）',
    !logs.slice(logsBeforeBad).some((l) => l.includes('超出 1~1024 安全范围')),
    `logs=${logs.slice(logsBeforeBad).slice(-2).join(' | ')}`);

out(failures() === 0 ? '\n全部通过' : `\n${failures()} 项失败`);
process.exit(failures() === 0 ? 0 : 1);
