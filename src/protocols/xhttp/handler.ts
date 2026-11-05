import { safeErrorMessage } from '@common';
import {
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

/** 并发上限：与参考实现一致。超出直接 429，避免单个 isolate 被大量长连接抽干 */
const XHTTP_MAX_CONNECTIONS = 32;
/** 首包（VLESS 头）安全上限：合法头最长约 1+16+1+255+1+2+1+255 ≈ 532 字节，8KB 只用来兜畸形/恶意包 */
const XHTTP_HEADER_LIMIT = 8 * 1024;
/** 首包到达超时：客户端只建连接不发头时，不能让配额被无限占用（DoSing 本 isolate 的 32 个槽位） */
const XHTTP_HEADER_TIMEOUT_MS = 30_000;
/** 空闲超时：两个方向都无数据即主动断开（对齐参考实现 30s） */
const XHTTP_IDLE_TIMEOUT_MS = 30_000;
const XHTTP_IDLE_CHECK_INTERVAL_MS = 5_000;
/** 下行排队上限：send() 是同步的，没法把背压反传给 remoteSocketToWS；
 *  超过这个积压量就主动断开，宁可断一个慢客户端也不让 isolate 内存被拖爆 */
const XHTTP_MAX_QUEUED_BYTES = 8 * 1024 * 1024;
/** 下行流的排队策略上限：desiredSize 按字节计，send() 用它判断积压 */
const XHTTP_STREAM_HIGH_WATER = 64 * 1024;

const XHTTP_RESPONSE_HEADERS = {
    'X-Accel-Buffering': 'no',
    'Cache-Control': 'no-store',
    'Content-Type': 'application/octet-stream'
};

/** 模块级并发计数：与参考实现一样按 isolate 统计（不是全局配额，跨 isolate 无法共享） */
let activeXhttpConnections = 0;

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

function badRequest(): Response {
    return new Response('Bad Request', { status: 400 });
}

/**
 * XHTTP 入站唯一入口。
 *
 * 前置条件（由 worker.ts 保证，勿在此重复推导）：
 *   init() → initHttp() → 路径白名单 → initWs(env) → setSettings() → prepareWsRuntimeConfig()
 * 已执行，因此 globalThis.globalConfig / settings / wsConfig 都是本次请求的最新值。
 */
export async function handleXhttp(request: Request, env: Env): Promise<Response> {
    if (activeXhttpConnections >= XHTTP_MAX_CONNECTIONS) {
        return new Response('Too many connections', { status: 429 });
    }

    activeXhttpConnections++;
    // 配额释放必须幂等：成功/失败/客户端断开/空闲超时都可能触发，重复释放会把别人的额度扣掉
    let released = false;
    const release = () => {
        if (released) return;
        released = true;
        activeXhttpConnections = Math.max(0, activeXhttpConnections - 1);
    };

    const log = (info: string, event?: string) => {
        console.log(`[xhttp] ${info}`, event || '');
    };

    let terminated = false;
    let watchdog: ReturnType<typeof setInterval> | null = null;
    let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;
    let uplinkReader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    let uplinkWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
    let uplinkWriterSocket: Socket | null = null;
    const remoteSocketRef: { value: Socket | null } = { value: null };
    let lastActivityAt = Date.now();
    let readyState: number = WS_READY_STATE_OPEN;

    const touch = () => { lastActivityAt = Date.now(); };

    /** 统一的收口：关 socket、关下行流、跑连接级清理钩子（UDP 的 DNS socket）、释放配额。
     *  所有退出路径都必须走到这里 —— 参考实现曾因建连失败漏释放配额，32 次失败后该路径恒 429。 */
    function terminate(): void {
        if (terminated) return;
        terminated = true;
        if (watchdog) {
            clearInterval(watchdog);
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
            // 积压过深说明客户端读得太慢；这里只能主动断开（send 同步，无法在此 await 背压）
            const desired = controllerRef.desiredSize;
            if (desired !== null && desired < -XHTTP_MAX_QUEUED_BYTES) {
                log(`downlink backlog exceeded ${XHTTP_MAX_QUEUED_BYTES} bytes, closing`);
                terminate();
                return;
            }
            touch();
            try {
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
    }, new ByteLengthQueuingStrategy({ highWaterMark: XHTTP_STREAM_HIGH_WATER }));

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
        log(`no VLESS header within ${XHTTP_HEADER_TIMEOUT_MS}ms, aborting`);
        try { void reader.cancel().catch(() => { /* ignore */ }); } catch { /* ignore */ }
    }, XHTTP_HEADER_TIMEOUT_MS);

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
            if (headerBytes.byteLength > XHTTP_HEADER_LIMIT) {
                log(`VLESS header exceeds ${XHTTP_HEADER_LIMIT} bytes`);
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
            if (rawClientData.byteLength) await write(rawClientData);
            void pumpUdpUplink(reader, write);
            startWatchdog();
            return new Response(readable, { headers: XHTTP_RESPONSE_HEADERS });
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
            headers: XHTTP_RESPONSE_HEADERS
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
    return new Response(readable, { headers: XHTTP_RESPONSE_HEADERS });

    /** 空闲看门狗：两个方向（上行 chunk / 下行 send）都算活动，30s 全静默才断开 */
    function startWatchdog(): void {
        lastActivityAt = Date.now();
        watchdog = setInterval(() => {
            if (Date.now() - lastActivityAt > XHTTP_IDLE_TIMEOUT_MS) {
                log(`idle for ${XHTTP_IDLE_TIMEOUT_MS}ms, closing`);
                terminate();
            }
        }, XHTTP_IDLE_CHECK_INTERVAL_MS);
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

    /** 上行泵（UDP）：每条后续 body chunk 都是一条 VLESS UDP 帧，交给 WS 的 UDP 写入器 */
    async function pumpUdpUplink(
        source: ReadableStreamDefaultReader<Uint8Array>,
        write: (chunk: ArrayBuffer) => Promise<void>
    ): Promise<void> {
        try {
            for (;;) {
                const { done, value } = await source.read();
                if (done) break;
                if (!value?.byteLength) continue;
                touch();
                await write(toExactArrayBuffer(value));
            }
        } catch (error) {
            log(`UDP uplink pipe error: ${safeErrorMessage(error)}`);
        } finally {
            terminate();
        }
    }
}
