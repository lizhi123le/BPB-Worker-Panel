import { safeErrorMessage, createSessionWatchdog, WATCHDOG_INTERVAL_MS, type SessionWatchdog } from '@common';
import {
    envConnectionLimit,
    envNumber,
    handleTCPOutBound,
    runWsCleanupHooks,
    safeCloseTcpSocket,
    WS_READY_STATE_OPEN
} from '@protocols/websocket/common';
import {
    buildWsLocal204Response,
    handleUDPOutBound,
    isSpeedTestSite,
    parseVlHeader,
    probePrivacyPadding,
    type PrivacyProbe
} from '@protocols/websocket/unified';

/**
 * XHTTP 入站（HTTP POST / stream-one）。
 *
 * 语义上它是「把 WS 那条双向连接换成一次 HTTP POST 的双向流」：request body 是上行、
 * response body 是下行，首包仍是 VLESS 头（cmd=1 TCP / cmd=2 UDP-DNS）。
 * 出站策略（反代池 / 官方直连池 / 上游代理 / NAT64 / 回退阶梯）**完全复用** WS 的实现
 * （handleTCPOutBound + remoteSocketToWS），而不是另写一套：两条入站若各有一份决策逻辑，
 * 用户改一次面板设置就会得到两种不同的出口行为，且回退阶梯的细节差异极难被发现。
 *
 * 实现手法：造一个「假 WebSocket」（只实现 send / close / readyState），交给
 * handleTCPOutBound；它内部所有 `webSocket.send()` 都变成往 response 的 ReadableStream
 * 里 enqueue，`webSocket.close()` 变成关闭 response body。于是下行管道（含 VL 响应头前置、
 * 批量发送、socket.closed 时关连接）与 WS 逐字同源。
 *
 * 与 cfnew 的差异（刻意为之，见 unified.ts:85-95 的既有裁决）：
 *  - 不校验、也不回写 UUID 派生的填充头：回写会把 UUID 的 12 个 hex 泄露给未认证调用方，
 *    长度校验则会变成 UUID 校验 oracle；本实现只做 0xED7F 填充剥离（复用 WS 的跨帧状态机）。
 *  - Content-Type 用 application/octet-stream，不用参考压缩版里的 application/grpc（历史值）。
 */

/** 并发上限默认值：与参考实现一致。超出直接 429，避免单个 isolate 被大量长连接抽干 */
const XP_MAX_CONNECTIONS_DEFAULT = 32;
/** 首包（VLESS 头）安全上限：合法头最长约 1+16+1+255+1+2+1+255 ≈ 532 字节，8KB 只用来兜畸形/恶意包 */
const XP_HEADER_LIMIT = 8 * 1024;
/** 首包到达超时：客户端只建连接不发头时，不能让配额被无限占用（DoSing 本 isolate 的并发槽位，默认 32） */
const XP_HEADER_TIMEOUT_MS = 30_000;
/**
 * 空闲超时默认值（秒）：两个方向都无数据即主动断开（对齐参考实现 30s）。
 * env `XP_IDLE_TIMEOUT_S` 可覆盖，**显式 0 = 关闭空闲断流**（长暂停/长缓冲的播放器需要）。
 */
const XP_IDLE_TIMEOUT_S_DEFAULT = 30;
/**
 * 下行排队上限默认值（MB）：send() 是同步的，没法把背压反传给 remoteSocketToWS；
 * 超过这个积压量就收口，宁可断一个慢客户端也不让 isolate 内存被拖爆。
 * env `XP_MAX_QUEUED_MB` 可覆盖，**显式 0 = 关闭该保护**。
 */
const XP_MAX_QUEUED_MB_DEFAULT = 8;
/**
 * 积压容忍窗口默认值（秒）：**先限速、后断流**。
 * 下行已经过 WS 侧同一个令牌桶（WS_DOWNLINK_BPS）限速，所以"客户端比上限慢"时队列仍会涨。
 * 旧行为是一越过上限立刻 terminate（短时抖动也断）；现在要求**持续超限**超过这个窗口才断，
 * 短暂尖峰（seek、切集、GC 抖动）能被吸收。env `XP_QUEUE_GRACE_S` 覆盖，0 = 立即断（旧行为）。
 */
const XP_QUEUE_GRACE_S_DEFAULT = 15;
/** 下行流的排队策略上限：desiredSize 按字节计，send() 用它判断积压 */
const XP_STREAM_HIGH_WATER = 64 * 1024;

const XP_RESPONSE_HEADERS = {
    'X-Accel-Buffering': 'no',
    'Cache-Control': 'no-store',
    'Content-Type': 'application/octet-stream'
};

/** 模块级并发计数：与参考实现一样按 isolate 统计（不是全局配额，跨 isolate 无法共享） */
let activeXpConnections = 0;

/** VLESS 头解析成功后需要的字段（用于跨 chunk 累积判据，不重复实现一份协议解析） */
interface ParsedVlessHeader {
    addressRemote: string;
    portRemote: number;
    rawDataIndex: number;
    isUDP: boolean;
}

/**
 * 计算「要完整解析这个 VLESS 头，当前还至少需要多少字节」。
 * 返回 -1 表示已能确定是非法头（地址类型不在 1/2/3 内），不必再等更多字节。
 *
 * 为什么需要它：request body 的 chunk 边界与 VLESS 头边界无关，头可能被拆到多个 chunk；
 * 直接调 parseVlHeader 会把「还没收全」误判成「非法头 → 400」。
 * 这里只做「长度拼图」，协议字段的合法性仍完全交给 parseVlHeader 判定。
 */
function requiredVlHeaderLength(bytes: Uint8Array): number {
    // version(1) + uuid(16) + addonLen(1) 都不够时，只能先按协议最小头长度等
    if (bytes.byteLength < 18) return 24;

    const optLength = bytes[17];
    const commandIndex = 18 + optLength;
    const portIndex = commandIndex + 1;
    const addressIndex = portIndex + 2;
    if (bytes.byteLength < addressIndex + 1) return Math.max(24, addressIndex + 1);

    const addressType = bytes[addressIndex];
    if (addressType === 1) return Math.max(24, addressIndex + 5);
    if (addressType === 3) return Math.max(24, addressIndex + 17);
    if (addressType === 2) {
        if (bytes.byteLength < addressIndex + 2) return Math.max(24, addressIndex + 2);
        return Math.max(24, addressIndex + 2 + bytes[addressIndex + 1]);
    }
    return -1;
}

/** 把流读到的 chunk 规整成「byteOffset=0 且 buffer 长度精确」的 ArrayBuffer，
 *  这样后续累积/解析拿到的偏移语义就是数组下标，不会踩到宿主给的分片视图 */
function toExactArrayBuffer(value: Uint8Array): ArrayBuffer {
    if (value.byteOffset === 0 && value.byteLength === value.buffer.byteLength) {
        return value.buffer as ArrayBuffer;
    }
    return value.slice().buffer;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(a.byteLength + b.byteLength);
    out.set(a, 0);
    out.set(b, a.byteLength);
    return out;
}

/**
 * B-17：从缓冲里切出所有**完整**的 `[2B len][payload]` 帧逐一交给 emit，返回没凑够的残片
 * （半帧、或只有一个字节的长度前缀）。返回的残片可能是原缓冲的引用（未切出任何帧时零拷贝）。
 *
 * 为什么帧长含前缀本身：VLESS UDP 的长度字段只计 payload，帧的物理长度是 len + 2；
 * 这样 `[lenHi][lenLo]` 与后续 payload 一起被写进 DNS 上游，不用再做一次拼装。
 */
async function drainUdpFrames(
    buffer: Uint8Array,
    emit: (frame: ArrayBuffer) => Promise<void>
): Promise<Uint8Array> {
    let offset = 0;
    while (offset + 2 <= buffer.byteLength) {
        const frameLength = ((buffer[offset] << 8) | buffer[offset + 1]) + 2;
        if (offset + frameLength > buffer.byteLength) break;   // 半帧：等下一块
        // slice 得到独立副本：emit 会持有它到写完，不能引用下一次拼接会替换掉的缓冲
        await emit(buffer.slice(offset, offset + frameLength).buffer as ArrayBuffer);
        offset += frameLength;
    }
    return offset ? buffer.slice(offset) : buffer;
}

function badRequest(): Response {
    return new Response('Bad Request', { status: 400 });
}

/**
 * 每请求解析一次的生效阈值（env 可调；非法值回退默认，显式 0 按各自语义处理）。
 *
 * 注意 env **前缀是 `XP_`** 而不是 `XP_`：环境变量名会原样出现在面板/部署文档上，
 * 不该把传输名写进部署面。内部常量仍叫 `XP_*_DEFAULT`（代码标识符会被混淆器改名，
 * 不需要跟着改）。**不要"顺手改回" XP_ 前缀 —— 对外约定的名字一旦发布就不能再变。**
 */
function xpLimits(): {
    maxConnections: number;
    idleTimeoutMs: number;
    maxQueuedBytes: number;
    graceMs: number;
} {
    const { value: maxConnections } = envConnectionLimit('XP_MAX_CONNECTIONS', XP_MAX_CONNECTIONS_DEFAULT);
    const idleTimeoutSec = envNumber('XP_IDLE_TIMEOUT_S', XP_IDLE_TIMEOUT_S_DEFAULT, true);
    const queuedMb = envNumber('XP_MAX_QUEUED_MB', XP_MAX_QUEUED_MB_DEFAULT, true);
    const graceSec = envNumber('XP_QUEUE_GRACE_S', XP_QUEUE_GRACE_S_DEFAULT, true);
    return {
        maxConnections,
        idleTimeoutMs: idleTimeoutSec > 0 ? Math.floor(idleTimeoutSec * 1000) : 0,
        maxQueuedBytes: queuedMb > 0 ? Math.floor(queuedMb * 1024 * 1024) : 0,
        graceMs: Math.floor(graceSec * 1000)
    };
}

/**
 * XHTTP 入站唯一入口。
 *
 * 前置条件（由 worker.ts 保证，勿在此重复推导）：
 *   init() → initHttp() → 路径白名单 → initWs(env) → setSettings() → prepareWsRuntimeConfig()
 * 已执行，因此 globalThis.globalConfig / settings / wsConfig 都是本次请求的最新值。
 */
export async function handleXp(request: Request, _env: Env): Promise<Response> {
    const limits = xpLimits();
    if (activeXpConnections >= limits.maxConnections) {
        console.log(`[xp] 已达并发上限 ${limits.maxConnections} 条，拒绝新连接`);
        return new Response('Too many connections', { status: 429 });
    }

    activeXpConnections++;
    // 配额释放必须幂等：成功/失败/客户端断开/空闲超时都可能触发，重复释放会把别人的额度扣掉
    let released = false;
    const release = () => {
        if (released) return;
        released = true;
        activeXpConnections = Math.max(0, activeXpConnections - 1);
    };

    const log = (info: string, event?: string) => {
        console.log(`[xp] ${info}`, event || '');
    };

    let terminated = false;
    let watchdog: SessionWatchdog | null = null;
    let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;
    let uplinkReader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    let uplinkWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
    let uplinkWriterSocket: Socket | null = null;
    const remoteSocketRef: { value: Socket | null } = { value: null };
    let readyState: number = WS_READY_STATE_OPEN;
    /** 下行积压首次越过上限的时刻（0 = 当前未超限）；配合 graceMs 实现"持续超限才断" */
    let overflowSince = 0;

    /** 记活动：看门狗未装（XP_IDLE_TIMEOUT_S=0）时是 no-op */
    const touch = () => { watchdog?.touch(); };

    /** 统一的收口：关 socket、关下行流、跑连接级清理钩子（UDP 的 DNS socket）、释放配额。
     *  所有退出路径都必须走到这里 —— 参考实现曾因建连失败漏释放配额，32 次失败后该路径恒 429。 */
    function terminate(): void {
        if (terminated) return;
        terminated = true;
        if (watchdog) {
            watchdog.stop();
            watchdog = null;
        }
        if (uplinkReader) {
            // 客户端断开/超时后让挂在 read() 上的上行泵立即退出（cancel 会让 read 返回 done）
            try { void uplinkReader.cancel().catch(() => { /* 流可能已关闭 */ }); } catch { /* ignore */ }
        }
        if (uplinkWriter) {
            try { uplinkWriter.releaseLock(); } catch { /* 有未决写时释放会抛，socket 即将关闭 */ }
            uplinkWriter = null;
            uplinkWriterSocket = null;
        }
        safeCloseTcpSocket(remoteSocketRef.value);
        remoteSocketRef.value = null;
        try { controllerRef?.close(); } catch { /* 已经 close/errored */ }
        controllerRef = null;
        // 3 = WebSocket.CLOSED：safeCloseWebSocket 只在 OPEN/CLOSING 时才再调 close()，这里先落终态防递归
        readyState = 3;
        // handleUDPOutBound 把 DNS socket 的清理登记进了 WS teardown 钩子表；
        // XHTTP 没有真正的 WS 事件，必须手动排空，否则 UDP-DNS 复用连接会半开残留。
        runWsCleanupHooks(fakeWebSocket as unknown as WebSocket);
        release();
    }

    // 假 WebSocket：handleTCPOutBound / handleUDPOutBound 只用到这三个成员。
    // 用 unknown 双重断言交给 WS 类型，是为了**零改动**复用那两条已审计的出站/下行管道；
    // 与其复制一份决策逻辑，让类型在这里退一步是更小的风险。
    const fakeWebSocket: { readyState: number; send(payload: ArrayBuffer | Uint8Array): void; close(code?: number, reason?: string): void } = {
        get readyState() {
            return readyState;
        },
        send(payload: ArrayBuffer | Uint8Array) {
            if (terminated || readyState !== WS_READY_STATE_OPEN || !controllerRef) return;
            const data = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
            if (!data.byteLength) return;
            // 积压过深说明客户端读得太慢。send 是同步的，没法在此 await 背压 ——
            // 所以策略是「先限速（WS 侧令牌桶已在压）+ 容忍短暂尖峰，持续超限才断」：
            // 只要队列在 graceMs 内回到水位以下就继续跑，避免 seek / 切集 / GC 抖动直接断流。
            const desired = controllerRef.desiredSize;
            if (limits.maxQueuedBytes > 0 && desired !== null && desired < -limits.maxQueuedBytes) {
                if (!overflowSince) overflowSince = Date.now();
                if (Date.now() - overflowSince >= limits.graceMs) {
                    log(`downlink backlog exceeded ${limits.maxQueuedBytes} bytes for ${limits.graceMs}ms, closing`);
                    terminate();
                    return;
                }
            } else if (overflowSince) {
                overflowSince = 0;   // 已回到水位以下：重新计时
            }
            touch();
            try {
                // 这里必须拷贝：WS 入站的下行缓冲是「交出后隔一代复用」的池缓冲，
                // 而 enqueue 进响应流的数据要等到 HTTP body 真正被消费者读走才失效 ——
                // 等待时间不受控（可能几十帧之后），一代的复用间隔不足以保证安全。
                controllerRef.enqueue(data.slice());
            } catch {
                terminate();
            }
        },
        close(_code?: number, _reason?: string) {
            if (terminated) return;
            terminate();
        }
    };

    const readable = new ReadableStream<Uint8Array>({
        start(controller) {
            controllerRef = controller;
        },
        cancel() {
            // 客户端中途取消（断流/关页面）：下行流 cancel 是唯一能观测到的信号
            terminate();
        }
    }, new ByteLengthQueuingStrategy({ highWaterMark: XP_STREAM_HIGH_WATER }));

    const fetcher = (request as any).fetcher;
    const userID = globalThis.globalConfig?.userID || '';

    if (!request.body) {
        terminate();
        return badRequest();
    }
    uplinkReader = request.body.getReader();
    const reader = uplinkReader;

    // 首包阶段单独设一次性超时：连接建立后客户端迟迟不发 VLESS 头时，配额不能被空占
    const headerTimer = setTimeout(() => {
        log(`no VLESS header within ${XP_HEADER_TIMEOUT_MS}ms, aborting`);
        try { void reader.cancel().catch(() => { /* ignore */ }); } catch { /* ignore */ }
    }, XP_HEADER_TIMEOUT_MS);

    let headerBytes = new Uint8Array(0);
    let vlHeader: ParsedVlessHeader | null = null;
    let paddingResolved = false;
    const paddingProbe: PrivacyProbe = { pending: null };

    try {
        while (!vlHeader) {
            const { done, value } = await reader.read();
            if (done) break;
            touch();

            let chunk = toExactArrayBuffer(value);
            // 与 WS 同一条裁决：0xED7F 填充只在首包上判定/剥离一次。probePrivacyPadding 是
            // 跨帧累积状态机，正好覆盖「request body 把填充头也切开」的情形，故复用而非复制。
            if (!paddingResolved) {
                const resolved = probePrivacyPadding(chunk, paddingProbe);
                if (resolved === null) continue; // 头部不足，等下一个 chunk
                paddingResolved = true;
                chunk = resolved;
            }
            if (!chunk.byteLength) continue;

            headerBytes = concatBytes(headerBytes, new Uint8Array(chunk));
            if (headerBytes.byteLength > XP_HEADER_LIMIT) {
                log(`VLESS header exceeds ${XP_HEADER_LIMIT} bytes`);
                clearTimeout(headerTimer);
                terminate();
                return badRequest();
            }

            const required = requiredVlHeaderLength(headerBytes);
            if (required < 0) {
                clearTimeout(headerTimer);
                terminate();
                return badRequest();
            }
            if (headerBytes.byteLength < required) continue;

            const candidate = parseVlHeader(headerBytes.buffer as ArrayBuffer, userID);
            if (candidate.hasError) {
                // 拒绝原因只进服务端日志：回给未认证调用方会重新引入 UUID / 口令 oracle
                log(`invalid VLESS header: ${String(candidate.message)}`);
                clearTimeout(headerTimer);
                terminate();
                return badRequest();
            }
            vlHeader = candidate as unknown as ParsedVlessHeader;
        }
    } catch (error) {
        clearTimeout(headerTimer);
        log(`reading VLESS header failed: ${safeErrorMessage(error)}`);
        terminate();
        return badRequest();
    }
    clearTimeout(headerTimer);

    if (!vlHeader) {
        log('request body ended before VLESS header completed');
        terminate();
        return badRequest();
    }

    const { addressRemote, portRemote, rawDataIndex, isUDP } = vlHeader;
    // 首包剩余载荷（VLESS 头之后的字节）：TCP 要写进 socket，UDP 是第一条 DNS 帧
    const rawClientData = headerBytes.slice(rawDataIndex).buffer as ArrayBuffer;
    // F-18：响应版本字节归一为 0，不回显客户端版本（与 parseVlHeader 的既有裁决一致）
    const vlResponseHeader = new Uint8Array([0, 0]);

    // ===== cmd=2：UDP 只支持 DNS（port 53）=====
    if (isUDP) {
        if (portRemote !== 53) {
            log(`UDP is only supported for DNS (53), got ${portRemote}`);
            terminate();
            return badRequest();
        }
        try {
            // 假 WebSocket 的 send 直接写 response body，于是 UDP 帧格式/缓存完全由 WS 侧实现决定
            const { write } = await handleUDPOutBound(
                fakeWebSocket as unknown as WebSocket,
                vlResponseHeader,
                log,
                'vless',
                fetcher
            );
            // B-17：首包残余（VLESS 头之后的字节）是第一条 UDP 帧的开头，可能只有半帧。
            // 先切出其中**完整**的帧立即写（失败仍走本 try 的 500），残余交给上行泵与新字节一起重组。
            const leftover = await drainUdpFrames(new Uint8Array(rawClientData), write);
            void pumpUdpUplink(reader, write, leftover);
            startWatchdog();
            return new Response(readable, { headers: XP_RESPONSE_HEADERS });
        } catch (error) {
            log(`UDP DNS setup failed: ${safeErrorMessage(error)}`);
            terminate();
            return new Response('Internal Server Error', { status: 500 });
        }
    }

    // ===== 测速拦截：无上游代理时本地 204（与 WS 分支同判据）=====
    // 注意响应体仍是「VL 头 + 原始 HTTP 响应字节」：XHTTP 客户端在隧道内跑的是完整 HTTP 请求，
    // 直接回一个外层 204 会被当成隧道结束而不是测速响应。
    if (isSpeedTestSite(addressRemote) && !globalThis.settings?.upstreamProxy) {
        log(`local speed-test 204 for ${addressRemote}`);
        terminate();
        // buildWsLocal204Response 的返回类型是泛型 Uint8Array（ArrayBufferLike），
        // 这里作为 BodyInit 使用需要明确是 ArrayBuffer 支撑的视图
        const body = buildWsLocal204Response(vlResponseHeader) as Uint8Array<ArrayBuffer>;
        return new Response(body, {
            status: 200,
            headers: XP_RESPONSE_HEADERS
        });
    }

    // ===== cmd=1：TCP，出站完全交给 WS 的出站实现 =====
    try {
        await handleTCPOutBound(
            remoteSocketRef,
            addressRemote,
            portRemote,
            rawClientData,
            fakeWebSocket as unknown as WebSocket,
            vlResponseHeader,
            log,
            fetcher
        );
    } catch (error) {
        // 走到这里说明出站实现自己抛了（建连/回退阶梯异常），按网关失败收口
        log(`TCP dial failed: ${safeErrorMessage(error)}`);
        terminate();
        return new Response('Bad Gateway', { status: 502 });
    }

    // handleTCPOutBound 内部吞掉大部分失败（它按 WS 语义 close() 假 WS），
    // 所以「没有拿到任何 socket」就等价于全部出站策略失败。
    // terminated 也要检查：首包超时可能已经先一步收口，避免这里再启动一条无人管的管道。
    if (terminated || !remoteSocketRef.value) {
        safeCloseTcpSocket(remoteSocketRef.value);
        terminate();
        return new Response('Bad Gateway', { status: 502 });
    }

    void pumpTcpUplink(reader, remoteSocketRef);
    startWatchdog();
    return new Response(readable, { headers: XP_RESPONSE_HEADERS });

    /** 空闲看门狗：两个方向（上行 chunk / 下行 send）都算活动，静默超时才断开。
     *  `XP_IDLE_TIMEOUT_S=0` 时 createSessionWatchdog 返回空实现（不装定时器）——
     *  长暂停/长缓冲的播放器需要这个回滚开关。 */
    function startWatchdog(): void {
        // 轮询间隔跟随超时自适应：设 2s 却 5s 才检测是没意义的
        watchdog = createSessionWatchdog({
            idleMs: limits.idleTimeoutMs,
            // 短超时按 timeout/2 自适应，避免"设 2s 却 5s 才检测"；上限与 WS 侧共用同一常量
            intervalMs: Math.max(200, Math.min(WATCHDOG_INTERVAL_MS, Math.floor(limits.idleTimeoutMs / 2))),
            onExpire: () => {
                log(`idle for ${limits.idleTimeoutMs}ms, closing`);
                terminate();
            }
        });
    }

    /** 上行泵（TCP）：把 request body 的后续 chunk 写进当前出站 socket。
     *  不能在 await handleTCPOutBound 之前启动：它会在拨号期写掉 rawClientData，
     *  早启动会让同一批字节写两遍。 */
    async function pumpTcpUplink(
        source: ReadableStreamDefaultReader<Uint8Array>,
        socketRef: { value: Socket | null }
    ): Promise<void> {
        try {
            for (;;) {
                const { done, value } = await source.read();
                if (done) break;
                if (!value?.byteLength) continue;
                touch();

                const socket = socketRef.value;
                if (!socket) throw new Error('remote socket is not available');
                // 回退阶梯会在首字节超时后换 socket；旧 writer 绑着已关闭的 socket，
                // 写前校验并重建，否则回退后的数据永远写不出去（WS 侧同一约束）。
                if (!uplinkWriter || uplinkWriterSocket !== socket) {
                    try { uplinkWriter?.releaseLock(); } catch { /* already released */ }
                    uplinkWriter = socket.writable.getWriter();
                    uplinkWriterSocket = socket;
                }
                await uplinkWriter.write(new Uint8Array(toExactArrayBuffer(value)));
            }
        } catch (error) {
            log(`uplink pipe error: ${safeErrorMessage(error)}`);
        } finally {
            // request body 结束 = 客户端不再发数据；与参考实现一致，任一方向结束就收口整条连接
            terminate();
        }
    }

    /** 上行泵（UDP）：按 [2B len][payload] 重组后逐帧交给 WS 的 UDP 写入器。
     *
     *  B-17：request body 是**字节流**，chunk 边界与 UDP 帧边界无关。原实现把每个 chunk 都当成
     *  一整帧交给 write()（它会砍掉前 2 字节当长度前缀），于是「一帧被切开」时后半个 chunk 的
     *  头两字节被当成新帧的长度前缀吃掉 → DNS 报文间歇性损坏且无日志。
     *  这里做与 unified.ts 的 pumpTcpDnsMessages 同型的两字节长度前缀重组：不够一帧就缓存残余。
     *  `initial` 是首包（VLESS 头之后）切完完整帧剩下的残余，可能非空。 */
    async function pumpUdpUplink(
        source: ReadableStreamDefaultReader<Uint8Array>,
        write: (chunk: ArrayBuffer) => Promise<void>,
        initial: Uint8Array
    ): Promise<void> {
        let pending = initial;
        try {
            for (;;) {
                const { done, value } = await source.read();
                if (done) break;
                if (!value?.byteLength) continue;
                touch();
                // 无残余时不拼接（零拷贝直通），有残余才 concat —— 稳态下两条分支都不会反复复制
                pending = pending.byteLength
                    ? concatBytes(pending, new Uint8Array(toExactArrayBuffer(value)))
                    : new Uint8Array(toExactArrayBuffer(value));
                pending = await drainUdpFrames(pending, write);
            }
            if (pending.byteLength) {
                // 客户端结束时留下残帧：只可能是被截断的查询，丢弃并留一条可检索的日志
                log(`UDP uplink: ${pending.byteLength}B trailing bytes dropped`);
            }
        } catch (error) {
            log(`UDP uplink pipe error: ${safeErrorMessage(error)}`);
        } finally {
            terminate();
        }
    }
}
