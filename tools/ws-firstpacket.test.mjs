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
 * 共用桩（Response/WebSocketPair/KV/首包构造）在 ws-test-harness.mjs，避免与
 * ws-uplink-batch.test.mjs 各复制一份。
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
import {
    makeReporter, makeEnv, vlessPacket, trojanPacket,
    installWebStubs, captureConsole, importBundle, earlyDataRequest, PIPE_ERROR_LOG
} from './ws-test-harness.mjs';

const { out, check, failures } = makeReporter();

let connectCalls = 0;
globalThis.connect = () => {
    connectCalls++;
    throw new Error('connect() is not available in the test harness');
};

let closeCalls = [];
installWebStubs({ onClose: (code, reason) => { closeCalls.push({ code, reason }); } });
const { logs, restore } = captureConsole();
const handler = await importBundle();
const ctx = { waitUntil() {}, passThroughOnException() {} };
const env = makeEnv({ SUB_PATH: 'ws-test-sub-path' });

/** 把首包作为早期数据发一次 WS 升级，返回该次运行的观测结果 */
async function runFirstPacket(packet) {
    connectCalls = 0;
    closeCalls = [];
    logs.length = 0;

    const response = await handler.fetch(earlyDataRequest(packet), env, ctx);
    // 首包处理在上行泵的异步链里，等它跑完（连接桩同步抛错，通常几十毫秒内结束）
    await new Promise((r) => setTimeout(r, 250));

    return {
        status: response.status,
        connectCalls,
        close1008: closeCalls.filter((c) => c.code === 1008),
        invalidLog: logs.find((l) => l.includes('invalid first packet')) || null,
        // 上行泵（替代 pipeTo）的错误路径日志：write 抛错后必须能走到这条 catch
        pipeErrorLog: logs.find((l) => l.includes(PIPE_ERROR_LOG)) || null,
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
check('乱码首包：write 抛错后走上行泵的错误路径', r.pipeErrorLog !== null, String(r.pipeErrorLog));

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
//     连接由上行泵的取消路径关掉（无 1008、无 invalid first packet 日志）。
//     本次合并**没有**改变这条路径（parse 调用刻意留在 try 之外，异常照旧冒泡），这里只做回归钉。
r = await runFirstPacket(vlessPacket({ atyp: 3, addrBytes: [0x00], payload: [0x00, 0x00] }));
check('截断 IPv6 首包：不误报为"非法协议"（走既有抛错取消路径）',
    r.close1008.length === 0 && r.invalidLog === null && r.connectCalls === 0,
    `closes=${JSON.stringify(r.closeAll)} log=${r.invalidLog} connectCalls=${r.connectCalls}`);
check('截断 IPv6 首包：异常由上行泵接管（pipeTo error 日志）', r.pipeErrorLog !== null, String(r.pipeErrorLog));

restore();
out(failures() === 0 ? '\nws-firstpacket: OK' : `\nws-firstpacket: ${failures()} 项失败`);
process.exit(failures() === 0 ? 0 : 1);
