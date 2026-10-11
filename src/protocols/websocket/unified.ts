import {
    safeCloseTcpSocket,
    handleTCPOutBound,
    makeReadableWebSocketStream,
    registerWsCleanup,
    WS_READY_STATE_OPEN,
    connectSocket
} from './common';

// 对齐 cfnew c0eb20c（明文源吗 L33-40）：隐私增强 —— 智能剥离随机填充前缀
// 客户端首包可能携带 [0xED 0x7F][2 字节 padLen][padLen 字节随机填充]，若不剥离直接做
// 协议检测，0xED 0x7F 会被 parseVlHeader 当成版本号、填充被当成 UUID，检测必失败。
// 幂等：无魔数或 padLen 异常时原样返回；仅由 write() 在本次连接的首个数据块起调用
// （见 paddingStripped 标志），一旦判定完成即转直通，已建连后的数据块不再剥离。
// V-02：首包可能被客户端拆成多个 WS 帧 —— 第 1 帧不足 4 字节（判不了魔数），或只含
// [魔数][长度] 而不含全部填充，此时第 2 帧起是纯随机填充，逐帧剥离必然失败。故在
// 「尚未判定是否含填充」的这段头部上做跨帧累积，直到能给出确定结论再一次性交给后续流程。
// H15 — 冻结，不作卖点：魔数 0xED7F 与 padLen ∈ [64,2048] 仍是客户端侧的固定常量，服务端只做剥离、
// 既不校验也不回写，因此这条填充链路只对 cfnew 系客户端生效，且不构成任何抗指纹增益。
// 不要把它当成隐私卖点，也不要据此单方面推进「客户端约定」（需客户端与订阅侧同步改）；
// 本次明确按「不作卖点」冻结，魔数与上界保持现状。
const PRIVACY_MAGIC = 0xED7F;
const PRIVACY_PAD_MIN = 64;
const PRIVACY_PAD_MAX = 2048;
// 等待态允许保留的字节上限：判定所需的头部最长就是 [魔数 2][长度 2][填充 2048] = 2052。
// 超过它只会来自畸形/恶意帧，直接判为无填充交回，放任缓冲增长就是内存放大面。
const PRIVACY_PROBE_LIMIT = 4 + PRIVACY_PAD_MAX;
// 跨帧累积状态：pending === null 表示「未在等待」，此时无缓冲、无额外拷贝（热路径直通）。
type PrivacyProbe = { pending: Uint8Array | null };

/**
 * 判定并剥离首包 0xED7F 填充（跨帧安全，取代 V-02 之前的单块 stripPrivacyPadding）。
 * 返回 null：当前字节不足以判定（头部已累积进 state.pending），调用方应丢弃本帧、等后续帧补齐；
 * 返回 ArrayBuffer：判定完成 —— 有填充则已剥离，无填充则按原字节序交回（未进入等待态时是同一个对象，零拷贝）。
 */
function probePrivacyPadding(chunk: ArrayBuffer, state: PrivacyProbe): ArrayBuffer | null {
    let buf: ArrayBuffer;
    if (state.pending) {
        // 只有等待态才发生拷贝：把上一帧留下的头部与当前帧按序拼成一个块再次判定
        const pending = state.pending;
        const merged = new Uint8Array(pending.byteLength + chunk.byteLength);
        merged.set(pending, 0);
        merged.set(new Uint8Array(chunk), pending.byteLength);
        state.pending = null;
        buf = merged.buffer;
    } else {
        buf = chunk; // 无填充客户端的首帧：零拷贝直通，与改动前逐字节一致
    }

    const bytes = new Uint8Array(buf);

    // ① 连魔数都判不了（<2 字节）→ 继续等：至多 1 字节，不可能触上限
    if (bytes.byteLength < 2) {
        state.pending = bytes;
        return null;
    }

    // ② 前 2 字节不是魔数 → 判定为无填充，原样一次性交回
    if (((bytes[0] << 8) | bytes[1]) !== PRIVACY_MAGIC) return buf;

    // ③ 是魔数但长度字段未收全（2 或 3 字节）→ 继续等：至多 3 字节，不可能触上限
    if (bytes.byteLength < 4) {
        state.pending = bytes;
        return null;
    }

    const padLen = (bytes[2] << 8) | bytes[3];
    // ④ padLen 不在 [64,2048] → 判为无填充，原样交回
    if (padLen < PRIVACY_PAD_MIN || padLen > PRIVACY_PAD_MAX) return buf;

    // ⑤ 填充没收全 → 继续累积到 4 + padLen 再剥离
    if (bytes.byteLength < 4 + padLen) {
        // 结构性防御：本分支内 bytes.byteLength < 4 + padLen ≤ PRIVACY_PROBE_LIMIT，
        // 等待态在现有常量下不可能超限；保留判断以防将来放宽上界后失去内存保护。
        if (bytes.byteLength > PRIVACY_PROBE_LIMIT) return buf;
        state.pending = bytes;
        return null;
    }

    // ⑥ 已收满 [魔数][长度][填充] → 剥离，交回真实协议头
    return buf.slice(4 + padLen);
}

// ===== xPadding 抗指纹（对齐 cfnew 52143dccb，参考 cmliu/edgetunnel）=====
// UUID 派生隐蔽的填充头名/键名，订阅链接据此生成 extra 约定（跨组冻结接口，勿改名/删除）。
// 服务端不再对入站填充做任何校验，也不在 101 响应里回写填充头，理由见下：
//   1. 校验可被零成本绕过（不发送填充即放行），却把“非法填充 → 400”变成一个可区分响应，
//      攻击者用“猜测的 UUID 算出的头名 + 非法长度填充”即可区分 400 与放行 → UUID 校验 oracle；
//   2. 101 响应回写 UUID 派生头会把 UUID 的 12 个 hex 字符泄露给未认证调用方。

// 从 UUID 派生隐蔽的头名/键名，与订阅侧 extra 约定一致
export function getXPaddingIdentifier(uuid: string): { header: string; key: string } {
    return { header: uuid.slice(1, 7), key: '_' + uuid.slice(25, 31) };
}

export async function UnifiedWSHandler(request: Request): Promise<Response> {
    // 对齐 cfnew d4b2b7f：优先用请求绑定的 fetcher 建连（新版 Workers 运行时可能缺全局 connect）
    const fetcher = request.fetcher;
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    webSocket.binaryType = 'arraybuffer';

    let address = "";
    let portWithRandomLog = "";
    let protocolType: 'vless' | 'trojan' | null = null;

    const log = (info: string, event?: string) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWrapper: { value: Socket | null } = { value: null };
    let remoteWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
    let remoteWriterSocket: Socket | null = null; // remoteWriter 绑定的 socket，回退换 socket 后据此重建
    let paddingStripped = false; // 每连接一次：0xED7F 隐私填充只在首包上判定/剥离一次，判定完成即转直通
    const paddingProbe: PrivacyProbe = { pending: null }; // V-02：填充头部被拆帧时的跨帧累积态
    let udpStreamWrite: any = null;
    let isDns = false;

    // ===== WS 本地测速模式（对齐 cfnew L4538-4542）=====
    let wsLocalSpeedTestMode = false;
    let wsLocalSpeedTestSocket: WebSocket | null = null;
    let wsLocalSpeedTestBuffer = new Uint8Array(0);
    let wsLocalSpeedTestFirstHeader: Uint8Array | null = null;
    const WS_LOCAL_SPEED_TEST_MAX = 64 * 1024;

    // ===== WS 本地测速模式（对齐 cfnew L4593-4631）=====
    const findHttpHeaderEnd = (data: Uint8Array): number => {
        for (let i = 0; i <= data.byteLength - 4; i++) {
            if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) return i + 4;
        }
        return -1;
    };

    const sendWsLocalSpeedTestResponse = async () => {
        if (!wsLocalSpeedTestSocket) return;
        const respHeader = wsLocalSpeedTestFirstHeader;
        wsLocalSpeedTestFirstHeader = null;
        await webSocketSendAndWait(wsLocalSpeedTestSocket, buildWsLocal204Response(respHeader));
    };

    const processWsLocalSpeedTestData = async (data: ArrayBuffer): Promise<void> => {
        const chunk = new Uint8Array(data);
        if (!chunk.byteLength) return;
        if (wsLocalSpeedTestBuffer.byteLength + chunk.byteLength > WS_LOCAL_SPEED_TEST_MAX) throw new Error('WS local speed-test request is too large');
        const newBuf = new Uint8Array(wsLocalSpeedTestBuffer.byteLength + chunk.byteLength);
        newBuf.set(wsLocalSpeedTestBuffer);
        newBuf.set(chunk, wsLocalSpeedTestBuffer.byteLength);
        wsLocalSpeedTestBuffer = newBuf;
        while (wsLocalSpeedTestBuffer.byteLength) {
            const headerEnd = findHttpHeaderEnd(wsLocalSpeedTestBuffer);
            if (headerEnd === -1) return;
            const headerText = new TextDecoder().decode(wsLocalSpeedTestBuffer.subarray(0, headerEnd));
            const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
            const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
            const requestLength = headerEnd + contentLength;
            if (!Number.isSafeInteger(contentLength) || requestLength > WS_LOCAL_SPEED_TEST_MAX) throw new Error('WS local speed-test request body is too large');
            if (wsLocalSpeedTestBuffer.byteLength < requestLength) return;
            wsLocalSpeedTestBuffer = wsLocalSpeedTestBuffer.slice(requestLength);
            await sendWsLocalSpeedTestResponse();
        }
    };

    const enableWsLocalSpeedTestMode = async (webSocket: WebSocket, respHeader: Uint8Array | null, firstData?: ArrayBuffer): Promise<void> => {
        wsLocalSpeedTestMode = true;
        wsLocalSpeedTestSocket = webSocket;
        wsLocalSpeedTestBuffer = new Uint8Array(0);
        wsLocalSpeedTestFirstHeader = respHeader;
        if (firstData && firstData.byteLength > 0) await processWsLocalSpeedTestData(firstData);
    };

    // ===== 首包非法的主动收口（H5 残留）=====
    // 首包已到达却无法建连（既非合法 VLESS 也非合法 Trojan，或协议已认出但头畸形）时统一收口。
    // 此前只有 write() 抛错，WS 关闭完全依赖 pipeTo 在目标流 write 失败后隐式触发的 source.cancel()
    // → common.ts 的 safeCloseWebSocket（不带 code → 客户端看到 1005），且日志与「管道异常」混在一起。
    // 现在显式 close(1008)：客户端立刻拿到确定的关闭码，日志也能区分「首包非法」与「管道异常」。
    // 只在「已判定首包非法」时调用（调用点全部在 write() 内、非空帧、协议识别之后）：
    // 首包未到达（write 未被调用 / 空帧）根本走不到这些行，不会误关。
    // close reason 固定用通用文案：invalid user / password 之类的拒绝原因只写服务端日志，
    // 回给未认证调用方会重新引入 UUID / 口令 oracle。
    const closeInvalidFirstPacket = (reason: string) => {
        log(`invalid first packet: ${reason}, closing WS 1008`);
        try {
            webSocket.close(1008, 'Invalid protocol or authentication failed');
        } catch (_) { /* 已关闭或正在关闭，忽略 */ }
    };

    const writableStream = new WritableStream({
        async write(chunk) {
            // 对齐 cfnew c0eb20c：0xED7F 魔数+随机填充只在本次连接的首包上判定/剥离一次。
            // 若对每个数据块都剥离，任一后续块首 2 字节恰为 0xED7F 且 padLen ∈ [64,2048] 时会被静默截断/丢弃。
            // 空帧（客户端可发零长度 WS 消息）不消耗这次机会，否则真首包将不再被剥离。
            // V-02：判定未完成时 probePrivacyPadding 返回 null（填充头被拆帧），本帧不下发、继续等下一帧；
            // 一旦判定完成 paddingStripped=true，后续数据块零缓冲、零拷贝直通（不进这个分支）。
            if (!paddingStripped && chunk.byteLength) {
                const resolved = probePrivacyPadding(chunk, paddingProbe);
                if (resolved === null) return;
                paddingStripped = true;
                chunk = resolved;
            }

            // 测速拦截：WS 本地测速模式下直接处理请求（对齐 cfnew L4641-4644）
            if (wsLocalSpeedTestMode) {
                await processWsLocalSpeedTestData(chunk);
                return;
            }

            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }

            if (remoteSocketWrapper.value) {
                // FIRST_BYTE_TIMEOUT 回退会替换 remoteSocketWrapper.value（common.ts handleRetryConnection），
                // 旧 writer 仍指向已关闭的 socket；写前校验并解绑重建，否则回退路径永远写不出去。
                if (!remoteWriter || remoteWriterSocket !== remoteSocketWrapper.value) {
                    if (remoteWriter) {
                        try { remoteWriter.releaseLock(); } catch (_) { /* already released */ }
                    }
                    remoteWriter = remoteSocketWrapper.value.writable.getWriter();
                    remoteWriterSocket = remoteSocketWrapper.value;
                }
                await remoteWriter.write(chunk);
                return;
            }

            const { userID, TrPass } = globalThis.globalConfig;

            if (protocolType === 'vless') {
                const {
                    hasError,
                    message,
                    portRemote = 443,
                    addressRemote = "",
                    rawDataIndex,
                    VLVersion = new Uint8Array([0, 0]),
                    isUDP,
                } = parseVlHeader(chunk, userID!);

                address = addressRemote;
                portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;

                if (hasError) {
                    throw new Error(message);
                }

                const VLResponseHeader = new Uint8Array([VLVersion[0], 0]);
                const rawClientData = chunk.slice(rawDataIndex);

                if (isUDP) {
                    if (portRemote === 53) {
                        isDns = true;
                        const { write } = await handleUDPOutBound(webSocket, VLResponseHeader, log, 'vless', fetcher);
                        udpStreamWrite = write;
                        await udpStreamWrite(rawClientData);
                        return;
                    } else {
                        throw new Error("UDP proxy only enable for DNS which is port 53");
                    }
                }

                // 测速拦截：无上游代理时本地 204 响应（对齐 cfnew L4679-4681）
                if (isSpeedTestSite(addressRemote) && !globalThis.settings?.upstreamProxy) {
                    await enableWsLocalSpeedTestMode(webSocket, VLResponseHeader, rawClientData);
                    return;
                }

                await handleTCPOutBound(
                    remoteSocketWrapper,
                    addressRemote,
                    portRemote,
                    rawClientData,
                    webSocket,
                    VLResponseHeader,
                    log,
                    fetcher
                );
            } else if (protocolType === 'trojan') {
                const {
                    hasError,
                    message,
                    portRemote = 443,
                    addressRemote = "",
                    rawClientData,
                    trAddrHeader,
                    isUDP,
                } = await parseTrHeader(chunk, TrPass!);

                address = addressRemote;
                portWithRandomLog = `${portRemote}--${Math.random()} tcp`;

                if (hasError) {
                    throw new Error(message);
                }

                if (isUDP) {
                    if (portRemote === 53) {
                        isDns = true;
                        const { write } = await handleUDPOutBound(webSocket, null, log, 'trojan', fetcher, trAddrHeader);
                        udpStreamWrite = write;
                        await udpStreamWrite(rawClientData);
                        return;
                    } else {
                        throw new Error("UDP proxy only enable for DNS which is port 53");
                    }
                }

                // 测速拦截：无上游代理时本地 204 响应（对齐 cfnew L4703-4705）
                if (isSpeedTestSite(addressRemote) && !globalThis.settings?.upstreamProxy) {
                    await enableWsLocalSpeedTestMode(webSocket, null, rawClientData);
                    return;
                }

                await handleTCPOutBound(
                    remoteSocketWrapper,
                    addressRemote,
                    portRemote,
                    rawClientData,
                    webSocket,
                    null,
                    log,
                    fetcher
                );
            } else {
                // 零长度帧不构成首包（客户端可发零长度 WS 消息），更不构成「非法首包」：
                // 忽略并继续等待，避免把「首包尚未到达」误判为非法而主动断开。
                if (!chunk.byteLength) return;

                const firstChunk = chunk;

                const vlResult = tryParseVlHeader(firstChunk, userID!);
                if (vlResult) {
                    protocolType = 'vless';
                    log('protocol detected: VLESS');
                    // 修复：不能在 write() 回调内再次调用 writableStream.getWriter()（流已被 pipeTo 锁定）
                    // 直接内联处理首包，与 protocolType='vless' 分支逻辑相同
                    const {
                        hasError,
                        message,
                        portRemote = 443,
                        addressRemote = "",
                        rawDataIndex,
                        VLVersion = new Uint8Array([0, 0]),
                        isUDP,
                    } = parseVlHeader(firstChunk, userID!);

                    address = addressRemote;
                    portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;

                    if (hasError) {
                        closeInvalidFirstPacket(`vless header: ${String(message)}`);
                        throw new Error(message);
                    }

                    const VLResponseHeader = new Uint8Array([VLVersion[0], 0]);
                    const rawClientData = firstChunk.slice(rawDataIndex);

                    if (isUDP) {
                        if (portRemote === 53) {
                            isDns = true;
                            const { write } = await handleUDPOutBound(webSocket, VLResponseHeader, log, 'vless', fetcher);
                            udpStreamWrite = write;
                            await udpStreamWrite(rawClientData);
                            return;
                        } else {
                            throw new Error("UDP proxy only enable for DNS which is port 53");
                        }
                    }

                    // 测速拦截：无上游代理时本地 204 响应（对齐 cfnew L4679-4681）
                    if (isSpeedTestSite(addressRemote) && !globalThis.settings?.upstreamProxy) {
                        await enableWsLocalSpeedTestMode(webSocket, VLResponseHeader, rawClientData);
                        return;
                    }

                    await handleTCPOutBound(
                        remoteSocketWrapper,
                        addressRemote,
                        portRemote,
                        rawClientData,
                        webSocket,
                        VLResponseHeader,
                        log,
                        fetcher
                    );
                    return;
                }

                const trResult = await tryParseTrHeader(firstChunk, TrPass!);
                if (trResult) {
                    protocolType = 'trojan';
                    log('protocol detected: Trojan');
                    // 修复：直接内联处理首包，不重入已锁定的 writableStream
                    const {
                        hasError,
                        message,
                        portRemote = 443,
                        addressRemote = "",
                        rawClientData,
                        trAddrHeader,
                        isUDP,
                    } = await parseTrHeader(firstChunk, TrPass!);

                    address = addressRemote;
                    portWithRandomLog = `${portRemote}--${Math.random()} tcp`;

                    if (hasError) {
                        closeInvalidFirstPacket(`trojan header: ${String(message)}`);
                        throw new Error(message);
                    }

                    if (isUDP) {
                        if (portRemote === 53) {
                            isDns = true;
                            const { write } = await handleUDPOutBound(webSocket, null, log, 'trojan', fetcher, trAddrHeader);
                            udpStreamWrite = write;
                            await udpStreamWrite(rawClientData);
                            return;
                        } else {
                            throw new Error("UDP proxy only enable for DNS which is port 53");
                        }
                    }

                    // 测速拦截：无上游代理时本地 204 响应（对齐 cfnew L4703-4705）
                    if (isSpeedTestSite(addressRemote) && !globalThis.settings?.upstreamProxy) {
                        await enableWsLocalSpeedTestMode(webSocket, null, rawClientData);
                        return;
                    }

                    await handleTCPOutBound(
                        remoteSocketWrapper,
                        addressRemote,
                        portRemote,
                        rawClientData,
                        webSocket,
                        null,
                        log,
                        fetcher
                    );
                    return;
                }

                // H5 残留：首包既不是合法 VLESS 也不是合法 Trojan —— 已判定非法，主动收口。
                closeInvalidFirstPacket('neither VLESS nor Trojan');
                throw new Error('Invalid protocol or authentication failed');
            }
        },
        close() {
            if (remoteWriter) {
                try { remoteWriter.releaseLock(); } catch (_) { /* already released */ }
                remoteWriter = null;
                remoteWriterSocket = null;
            }
            safeCloseTcpSocket(remoteSocketWrapper.value);
        },
        abort(reason) {
            log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
    });

    readableWebSocketStream
        .pipeTo(writableStream)
        .catch(error => {
            log("readableWebSocketStream pipeTo error", error);
            safeCloseTcpSocket(remoteSocketWrapper.value);
        });

    // 自定义头泄露修复：不再回写 UUID 派生的填充头。
    // 旧实现用 getXPaddingIdentifier(uuid) 的头名/键名回写随机填充，等于把 UUID 的 12 个 hex 字符
    // 送给未认证调用方（48 bit 可枚举），故 101 响应不设任何头。
    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

function parseVlHeader(VLBuffer: ArrayBuffer, userID: string) {
    if (VLBuffer.byteLength < 24) {
        return { hasError: true, message: "invalid data" };
    }

    // F-18：VLESS 响应版本字节按规范固定回 0，不再原样回显客户端输入（原实现把入站字节回写进响应头）。
    // 入站版本不做拒绝：拒绝只会在握手主路径上新增一个可区分的失败面，而鉴权完全由 UUID 保证，
    // 非 0 版本不放大攻击面（审计结论），故取「归一为 0 再回显」而非「拒绝」。
    const version = new Uint8Array([0]);
    const slicedBuffer = new Uint8Array(VLBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);
    const isValidUser = slicedBufferString === userID;

    if (!isValidUser) {
        return { hasError: true, message: "invalid user" };
    }

    const optLength = new Uint8Array(VLBuffer.slice(17, 18))[0];
    const command = new Uint8Array(VLBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
    let isUDP = false;

    if (command === 1) {
    } else if (command === 2) {
        isUDP = true;
    } else {
        return { hasError: true, message: `command ${command} is not supported, command 01-tcp,02-udp,03-mux` };
    }

    const portIndex = 18 + optLength + 1;
    // F-17：optLength 可达 255，读端口前必须校验边界，否则 DataView.getUint16 抛 RangeError
    // （同文件 tryParseVlHeader 已有同型校验）
    if (VLBuffer.byteLength < portIndex + 2) {
        return { hasError: true, message: "invalid data" };
    }
    const portBuffer = VLBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(VLBuffer.slice(addressIndex, addressIndex + 1));
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;

        case 2:
            addressLength = new Uint8Array(VLBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;

        case 3: {
            addressLength = 16;
            const dataView = new DataView(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        }
        default:
            return { hasError: true, message: `invalid addressType is ${addressType}` };
    }

    if (!addressValue) {
        return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        VLVersion: version,
        isUDP,
    };
}

function tryParseVlHeader(VLBuffer: ArrayBuffer, userID: string) {
    if (VLBuffer.byteLength < 24) return null;

    try {
        const version = new Uint8Array(VLBuffer.slice(0, 1));
        const slicedBuffer = new Uint8Array(VLBuffer.slice(1, 17));
        const slicedBufferString = stringify(slicedBuffer);
        if (slicedBufferString !== userID) return null;

        const optLength = new Uint8Array(VLBuffer.slice(17, 18))[0];
        const command = new Uint8Array(VLBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
        if (command !== 1 && command !== 2) return null;

        const portIndex = 18 + optLength + 1;
        if (VLBuffer.byteLength < portIndex + 2) return null;
        const portBuffer = VLBuffer.slice(portIndex, portIndex + 2);
        new DataView(portBuffer).getUint16(0);

        let addressIndex = portIndex + 2;
        if (VLBuffer.byteLength < addressIndex + 1) return null;
        const addressType = new Uint8Array(VLBuffer.slice(addressIndex, addressIndex + 1))[0];
        if (addressType < 1 || addressType > 3) return null;

        return { hasError: false };
    } catch {
        return null;
    }
}

function stringify(arr: Uint8Array, offset = 0) {
    const byteToHex: string[] = [];
    for (let i = 0; i < 256; ++i) {
        byteToHex.push((i + 256).toString(16).slice(1));
    }
    return (
        byteToHex[arr[offset + 0]] +
        byteToHex[arr[offset + 1]] +
        byteToHex[arr[offset + 2]] +
        byteToHex[arr[offset + 3]] +
        "-" +
        byteToHex[arr[offset + 4]] +
        byteToHex[arr[offset + 5]] +
        "-" +
        byteToHex[arr[offset + 6]] +
        byteToHex[arr[offset + 7]] +
        "-" +
        byteToHex[arr[offset + 8]] +
        byteToHex[arr[offset + 9]] +
        "-" +
        byteToHex[arr[offset + 10]] +
        byteToHex[arr[offset + 11]] +
        byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] +
        byteToHex[arr[offset + 14]] +
        byteToHex[arr[offset + 15]]
    ).toLowerCase();
}

async function parseTrHeader(chunk: ArrayBuffer, password: string) {
    if (chunk.byteLength < 56) {
        return { hasError: true, message: "invalid trojan data - too short" };
    }

    const bytes = new Uint8Array(chunk);
    if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) {
        return { hasError: true, message: "invalid trojan header format (missing CR LF)" };
    }

    const passwordHash = await hashPassword(password);
    const receivedPassword = new TextDecoder().decode(bytes.subarray(0, 56));
    if (receivedPassword !== passwordHash) {
        return { hasError: true, message: "invalid trojan password" };
    }

    const data = bytes.subarray(58);
    // F-16：协议最小请求体 = CMD(1) + ATYP(1) + IPv4(4) + PORT(2) = 8 字节（原写 6，6 字节体读端口会抛 RangeError）
    if (data.byteLength < 8) {
        return { hasError: true, message: "invalid trojan request data" };
    }

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const cmd = view.getUint8(0);
    const isUDP = cmd === 3;
    if (cmd !== 1 && cmd !== 3) {
        return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
    }

    const addrType = view.getUint8(1);
    let addressIndex = 2;
    let address = "";

    switch (addrType) {
        case 1:
            if (data.byteLength < addressIndex + 4) return { hasError: true, message: "invalid data" };
            address = new Uint8Array(data.subarray(addressIndex, addressIndex + 4)).join(".");
            addressIndex += 4;
            break;
        case 3:
            if (data.byteLength < addressIndex + 1) return { hasError: true, message: "invalid data" };
            const addrLen = data[addressIndex++];
            if (data.byteLength < addressIndex + addrLen) return { hasError: true, message: "invalid data" };
            address = new TextDecoder().decode(data.subarray(addressIndex, addressIndex + addrLen));
            addressIndex += addrLen;
            break;
        case 4:
            if (data.byteLength < addressIndex + 16) return { hasError: true, message: "invalid data" };
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(view.getUint16(addressIndex + i * 2).toString(16));
            }
            address = ipv6.join(":");
            addressIndex += 16;
            break;
        default:
            return { hasError: true, message: `invalid addressType is ${addrType}` };
    }

    if (!address) {
        return { hasError: true, message: `address is empty, addressType is ${addrType}` };
    }

    // F-16：读端口前校验 addressIndex + 2 <= len
    if (data.byteLength < addressIndex + 2) return { hasError: true, message: "invalid data" };
    const port = view.getUint16(addressIndex);

    return {
        hasError: false,
        addressRemote: address,
        portRemote: port,
        // F-12：请求头里的地址头（ATYP + ADDR + PORT），供 Trojan UDP 首包缺地址头时补齐响应帧
        trAddrHeader: data.slice(1, addressIndex + 2),
        rawClientData: data.slice(addressIndex + 2).buffer,
        isUDP,
    };
}

async function tryParseTrHeader(chunk: ArrayBuffer, password: string) {
    if (chunk.byteLength < 56) return null;

    const passwordHash = await hashPassword(password);
    
    try {
        const bytes = new Uint8Array(chunk);
        if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) return null;

        const receivedPassword = new TextDecoder().decode(bytes.subarray(0, 56));
        if (receivedPassword !== passwordHash) return null;

        const data = bytes.subarray(58);
        // F-16：与 parseTrHeader 保持一致的下限（协议最小 8 字节），避免「检出 trojan 却解析失败」
        if (data.byteLength < 8) return null;

        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const cmd = view.getUint8(0);
        if (cmd !== 1 && cmd !== 3) return null;

        const addrType = view.getUint8(1);
        if (addrType < 1 || addrType > 4) return null;

        return { hasError: false };
    } catch {
        return null;
    }
}

// Pure JS SHA-224 (SHA-256 core + SHA-224 IVs, output truncated to first 7 state words).
// WebCrypto's crypto.subtle.digest does NOT support SHA-224 in Cloudflare Workers (workerd),
// so implement it manually to stay compatible with real Trojan clients (56-char hex).
const SHA224_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const SHA224_H = new Uint32Array([
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
]);

function sha224(data: Uint8Array): string {
    // Message padding: append 0x80, then zeros until total length ≡ 0 (mod 64)
    // with room for the final 8 bytes of big-endian bit length (two 32-bit words).
    const bitLen = data.byteLength * 8;
    const total = (data.byteLength + 1 + 8 + 63) & ~63;

    const msg = new Uint8Array(total);
    msg.set(data);
    msg[data.byteLength] = 0x80;

    const view = new DataView(msg.buffer);
    const bitLenHigh = Math.floor(bitLen / 0x100000000);
    const bitLenLow = bitLen >>> 0;
    view.setUint32(total - 8, bitLenHigh, false);
    view.setUint32(total - 4, bitLenLow, false);

    const h = SHA224_H.slice();
    const w = new Uint32Array(64);

    function rotr(x: number, n: number): number {
        return (x >>> n) | (x << (32 - n));
    }

    for (let i = 0; i < total; i += 64) {
        for (let t = 0; t < 16; t++) {
            w[t] = view.getUint32(i + t * 4, false);
        }
        for (let t = 16; t < 64; t++) {
            const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
            const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
            w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
        }

        let a = h[0], b = h[1], c = h[2], d = h[3];
        let e = h[4], f = h[5], g = h[6], hh = h[7];

        for (let t = 0; t < 64; t++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (hh + S1 + ch + SHA224_K[t] + w[t]) >>> 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + maj) >>> 0;

            hh = g;
            g = f;
            f = e;
            e = (d + t1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (t1 + t2) >>> 0;
        }

        h[0] = (h[0] + a) >>> 0;
        h[1] = (h[1] + b) >>> 0;
        h[2] = (h[2] + c) >>> 0;
        h[3] = (h[3] + d) >>> 0;
        h[4] = (h[4] + e) >>> 0;
        h[5] = (h[5] + f) >>> 0;
        h[6] = (h[6] + g) >>> 0;
        h[7] = (h[7] + hh) >>> 0;
    }

    // SHA-224 output: first 7 state words (28 bytes) as 56 lowercase hex chars.
    let hex = '';
    for (let i = 0; i < 7; i++) {
        hex += h[i].toString(16).padStart(8, '0');
    }
    return hex;
}

async function hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    return sha224(data);
}

// ===== 测速站点检测 + 本地 204 响应（对齐 cfnew L4974-5008）=====

function isSpeedTestSite(hostname: string): boolean {
    const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
    hostname = hostname.toLowerCase();
    return speedTestDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

function buildWsLocal204Response(respHeader: Uint8Array | null): Uint8Array {
    const wsLocal204 = new TextEncoder().encode(
        'HTTP/1.1 204 No Content\r\n' +
        'Content-Length: 0\r\n' +
        'Connection: keep-alive\r\n' +
        '\r\n'
    );
    if (!respHeader || respHeader.byteLength === 0) return wsLocal204;
    const response = new Uint8Array(respHeader.byteLength + wsLocal204.byteLength);
    response.set(respHeader, 0);
    response.set(wsLocal204, respHeader.byteLength);
    return response;
}

async function webSocketSendAndWait(webSocket: WebSocket, payload: Uint8Array) {
    const sendResult: unknown = webSocket.send(payload);
    if (sendResult && typeof (sendResult as { then?: unknown }).then === 'function') await sendResult;
}

function parseDNSQueryInfo(packet: Uint8Array): { domain: string; qtype: number; qclass: number } | null {
    if (packet.length < 12) return null;
    let offset = 12; // skip DNS header
    let domain = '';
    while (offset < packet.length) {
        const labelLen = packet[offset];
        if (labelLen === 0) { offset++; break; }
        if ((labelLen & 0xC0) === 0xC0) { offset += 2; break; } // compression pointer
        offset++;
        if (offset + labelLen > packet.length) return null;
        if (domain) domain += '.';
        domain += String.fromCharCode(...packet.slice(offset, offset + labelLen));
        offset += labelLen;
    }
    if (offset + 4 > packet.length) return null;
    const qtype = (packet[offset] << 8) | packet[offset + 1];
    const qclass = (packet[offset + 2] << 8) | packet[offset + 3];
    return { domain, qtype, qclass };
}

function parseDNSResponseTTL(packet: Uint8Array): number {
    if (packet.length < 12) return 300;
    let offset = 12;
    const qdcount = (packet[4] << 8) | packet[5];
    const ancount = (packet[6] << 8) | packet[7];
    // Skip question section
    for (let i = 0; i < qdcount; i++) {
        while (offset < packet.length && packet[offset] !== 0) {
            if ((packet[offset] & 0xC0) === 0xC0) { offset += 2; break; }
            offset += packet[offset] + 1;
        }
        if (offset < packet.length && packet[offset] === 0) offset++;
        offset += 4; // qtype + qclass
    }
    // Parse answer section — find min TTL
    let minTTL = 86400;
    for (let i = 0; i < ancount; i++) {
        if (offset >= packet.length) break;
        if ((packet[offset] & 0xC0) === 0xC0) offset += 2;
        else { while (offset < packet.length && packet[offset] !== 0) offset += packet[offset] + 1; offset++; }
        if (offset + 10 > packet.length) break;
        offset += 2; // type
        offset += 2; // class
        const ttl = (packet[offset] << 24) | (packet[offset + 1] << 16) | (packet[offset + 2] << 8) | packet[offset + 3];
        if (ttl > 0) minTTL = Math.min(minTTL, ttl);
        offset += 4; // ttl
        const rdlength = (packet[offset] << 8) | packet[offset + 1];
        offset += 2 + rdlength;
    }
    return minTTL;
}

// ===== 模块级 DNS 响应缓存（对齐 cfnew 域名系统缓存映射）=====
interface DNSCacheEntry {
    response: Uint8Array;
    expiresAt: number;
}
const globalDNSCache = new Map<string, DNSCacheEntry>();
const DNS_CACHE_MAX = 1024;

function setDNSCache(dnsPayload: Uint8Array) {
    const ancount = (dnsPayload[6] << 8) | dnsPayload[7];
    if (ancount === 0) return; // NXDOMAIN or empty — don't cache
    const cacheInfo = parseDNSQueryInfo(dnsPayload);
    if (cacheInfo && dnsPayload.length >= 2) {
        const key = `${cacheInfo.domain}|${cacheInfo.qtype}|${cacheInfo.qclass}`;
        if (globalDNSCache.size >= DNS_CACHE_MAX) {
            const firstKey = globalDNSCache.keys().next().value;
            if (firstKey) globalDNSCache.delete(firstKey);
        }
        const ttl = parseDNSResponseTTL(dnsPayload);
        const expiresAt = Date.now() + Math.min(86400, Math.max(60, ttl)) * 1000;
        globalDNSCache.set(key, { response: dnsPayload, expiresAt });
    }
}

function getDNSCache(dnsQueryPacket: Uint8Array): Uint8Array | null {
    const info = parseDNSQueryInfo(dnsQueryPacket);
    if (!info) return null;
    const key = `${info.domain}|${info.qtype}|${info.qclass}`;
    const cached = globalDNSCache.get(key);
    if (cached && Date.now() < cached.expiresAt) {
        // 对齐 cfnew L5425：复制缓存响应并将事务 ID 替换为当前查询的 ID
        const resp = new Uint8Array(cached.response.length);
        resp.set(cached.response);
        if (dnsQueryPacket.length >= 2) {
            resp[0] = dnsQueryPacket[0];
            resp[1] = dnsQueryPacket[1];
        }
        return resp;
    }
    if (cached) {
        globalDNSCache.delete(key);
    }
    return null;
}

async function handleUDPOutBound(webSocket: WebSocket, VLResponseHeader: Uint8Array<ArrayBuffer> | null, log: Function, protocol: 'vless' | 'trojan', fetcher?: any, trAddrHeader?: Uint8Array) {
    if (protocol === 'vless') {
        // VLESS UDP DNS: TCP socket to 8.8.4.4:53 with caching (cfnew style)
        let isVLHeaderSent = false;

        const socket = connectSocket({ hostname: '8.8.4.4', port: 53 }, fetcher);
        try {
            await Promise.race([
                socket.opened,
                new Promise((_, reject) => setTimeout(() => reject(new Error('DNS connect timeout')), 5000))
            ]);
        } catch (connectError) {
            // F-11：建连超时/失败时这条 socket 还没登记清理钩子（WS 也没关），必须就地关闭，否则残留半开连接
            safeCloseTcpSocket(socket);
            throw connectError;
        }
        log('VLESS DNS TCP connected to 8.8.4.4:53');

        const writer = socket.writable.getWriter();
        // F-11：UDP DNS 复用的 TCP socket 不在 remoteSocketWrapper 纳管范围内（WS 关闭时无人关它），
        // 在此登记到 WS teardown 钩子：关闭后读循环因 done/error 退出并释放 reader 锁。
        registerWsCleanup(webSocket, () => {
            try { writer.releaseLock(); } catch { /* 有未决写时释放会抛，忽略（socket 即将关闭） */ }
            safeCloseTcpSocket(socket);
        });
        
        // Response handling with caching
        let dnsBuffer = new Uint8Array(0);
        const DNS_MAX_BUF = 65536;
        const responseReader = socket.readable.getReader();
        
        const handleVLESSDNSResponse = async () => {
            try {
                while (true) {
                    const { done, value } = await responseReader.read();
                    if (done) break;

                    const chunk = value as Uint8Array;
                    if (dnsBuffer.length + chunk.length > DNS_MAX_BUF) {
                        log('VLESS DNS buffer overflow');
                        break;
                    }

                    // Reassemble
                    const newBuffer = new Uint8Array(dnsBuffer.length + chunk.length);
                    newBuffer.set(dnsBuffer);
                    newBuffer.set(chunk, dnsBuffer.length);
                    dnsBuffer = newBuffer;

                    // Parse TCP DNS messages (2-byte length prefix)
                    let offset = 0;
                    while (offset + 2 <= dnsBuffer.length) {
                        const dnsLength = (dnsBuffer[offset] << 8) | dnsBuffer[offset + 1];
                        const dnsStart = offset + 2;
                        const dnsEnd = dnsStart + dnsLength;

                        if (dnsEnd > dnsBuffer.length) break; // incomplete message

                        const dnsPayload = dnsBuffer.slice(dnsStart, dnsEnd);

                        // Build VLESS UDP frame: VLResponseHeader (first only) + [2B length BE] + raw DNS payload
                        const lenHi = (dnsPayload.length >> 8) & 0xff;
                        const lenLo = dnsPayload.length & 0xff;
                        if (isVLHeaderSent) {
                            const frame = new Uint8Array(2 + dnsPayload.length);
                            frame[0] = lenHi;
                            frame[1] = lenLo;
                            frame.set(dnsPayload, 2);
                            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                                webSocket.send(frame.buffer);
                            }
                        } else {
                            // First response includes VL header
                            const frame = new Uint8Array(VLResponseHeader!.length + 2 + dnsPayload.length);
                            frame.set(VLResponseHeader!, 0);
                            frame[VLResponseHeader!.length] = lenHi;
                            frame[VLResponseHeader!.length + 1] = lenLo;
                            frame.set(dnsPayload, VLResponseHeader!.length + 2);
                            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                                webSocket.send(frame.buffer);
                            }
                            isVLHeaderSent = true;
                        }

                        // Save to global DNS cache
                        setDNSCache(dnsPayload);

                        offset = dnsEnd;
                    }

                    // Keep remaining buffer
                    if (offset < dnsBuffer.length) {
                        dnsBuffer = dnsBuffer.slice(offset);
                    } else {
                        dnsBuffer = new Uint8Array(0);
                    }
                }
            } catch (e) {
                log("VLESS DNS response error: " + e);
            } finally {
                // F-11：teardown 由外部 close 驱动，此时 reader 已无未决读；仍包 try/catch 以防重复释放
                try { responseReader.releaseLock(); } catch { /* already released */ }
            }
        };
        handleVLESSDNSResponse();

        return {
            async write(chunk: ArrayBuffer) {
                const data = new Uint8Array(chunk);
                // data = [2B length BE][DNS message] (VLESS UDP payload). Strip the 2-byte
                // length prefix so parseDNSQueryInfo parses the DNS header at offset 0.
                const dnsPacket = data.length >= 2 ? data.subarray(2) : data;
                // Cache lookup: parse DNS query to get domain|qtype|qclass
                const cachedResp = getDNSCache(dnsPacket);
                if (cachedResp) {
                    // Cache hit: send cached response directly to client (align cfnew L5495)
                    const lenHi = (cachedResp.length >> 8) & 0xff;
                    const lenLo = cachedResp.length & 0xff;
                    if (isVLHeaderSent) {
                        const frame = new Uint8Array(2 + cachedResp.length);
                        frame[0] = lenHi;
                        frame[1] = lenLo;
                        frame.set(cachedResp, 2);
                        if (webSocket.readyState === WS_READY_STATE_OPEN) {
                            webSocket.send(frame.buffer);
                        }
                    } else {
                        const frame = new Uint8Array(VLResponseHeader!.length + 2 + cachedResp.length);
                        frame.set(VLResponseHeader!, 0);
                        frame[VLResponseHeader!.length] = lenHi;
                        frame[VLResponseHeader!.length + 1] = lenLo;
                        frame.set(cachedResp, VLResponseHeader!.length + 2);
                        if (webSocket.readyState === WS_READY_STATE_OPEN) {
                            webSocket.send(frame.buffer);
                        }
                        isVLHeaderSent = true;
                    }
                    return; // cache hit — do NOT forward to DNS socket
                }
                // Cache miss: forward to DNS socket. data already carries the 2-byte
                // TCP DNS length prefix (VLESS UDP payload), so write it directly (align cfnew L5506).
                await writer.write(data);
            },
        };
    } else {
        // Trojan UDP DNS: Parse Trojan UDP packets, forward to 8.8.4.4:53 via TCP, reconstruct responses
        let dnsBuffer = new Uint8Array(0);
        const DNS_MAX_BUF = 65536;
        let currentRequestHeader: Uint8Array | null = null; // Stores addrType + addr + port from request

        async function handleTrojanUDPResponse(socket: Socket) {
            const reader = socket.readable.getReader();
            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    const chunk = value as Uint8Array;
                    if (dnsBuffer.length + chunk.length > DNS_MAX_BUF) {
                        log('Trojan DNS buffer overflow');
                        break;
                    }

                    // Reassemble
                    const newBuffer = new Uint8Array(dnsBuffer.length + chunk.length);
                    newBuffer.set(dnsBuffer);
                    newBuffer.set(chunk, dnsBuffer.length);
                    dnsBuffer = newBuffer;

                    // Parse TCP DNS messages (2-byte length prefix)
                    let offset = 0;
                    while (offset + 2 <= dnsBuffer.length) {
                        const dnsLength = (dnsBuffer[offset] << 8) | dnsBuffer[offset + 1];
                        const dnsStart = offset + 2;
                        const dnsEnd = dnsStart + dnsLength;

                        if (dnsEnd > dnsBuffer.length) break; // incomplete message

                        const dnsPayload = dnsBuffer.slice(dnsStart, dnsEnd);

                        // Build Trojan UDP response frame:
                        // [addrType + addr + port] + [2B length BE] + [0x0d, 0x0a] + [payload]
                        if (currentRequestHeader) {
                            const frame = new Uint8Array(
                                currentRequestHeader.length + 4 + dnsPayload.length
                            );
                            frame.set(currentRequestHeader, 0);
                            frame[currentRequestHeader.length] = (dnsPayload.length >> 8) & 0xff;
                            frame[currentRequestHeader.length + 1] = dnsPayload.length & 0xff;
                            frame[currentRequestHeader.length + 2] = 0x0d;
                            frame[currentRequestHeader.length + 3] = 0x0a;
                            frame.set(dnsPayload, currentRequestHeader.length + 4);
                            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                                webSocket.send(frame.buffer);
                            }
                        }

                        // Save to global DNS cache
                        setDNSCache(dnsPayload);

                        offset = dnsEnd;
                    }

                    // Keep remaining buffer
                    if (offset < dnsBuffer.length) {
                        dnsBuffer = dnsBuffer.slice(offset);
                    } else {
                        dnsBuffer = new Uint8Array(0);
                    }
                }
            } catch (e) {
                log("Trojan DNS response error: " + e);
            } finally {
                // F-11：teardown 由外部 close 驱动，此时 reader 已无未决读；仍包 try/catch 以防重复释放
                try { reader.releaseLock(); } catch { /* already released */ }
            }
        }

        // Connect to DNS server via TCP
        const socket = connectSocket({ hostname: '8.8.4.4', port: 53 }, fetcher);
        try {
            await Promise.race([
                socket.opened,
                new Promise((_, reject) => setTimeout(() => reject(new Error('DNS connect timeout')), 5000))
            ]);
        } catch (connectError) {
            // F-11：建连超时/失败时这条 socket 还没登记清理钩子（WS 也没关），必须就地关闭，否则残留半开连接
            safeCloseTcpSocket(socket);
            throw connectError;
        }
        log('Trojan DNS TCP connected to 8.8.4.4:53');
        handleTrojanUDPResponse(socket);

        const writer = socket.writable.getWriter();
        // F-11：UDP DNS 复用的 TCP socket 不在 remoteSocketWrapper 纳管范围内（WS 关闭时无人关它），
        // 在此登记到 WS teardown 钩子：关闭后读循环因 done/error 退出并释放 reader 锁。
        registerWsCleanup(webSocket, () => {
            try { writer.releaseLock(); } catch { /* 有未决写时释放会抛，忽略（socket 即将关闭） */ }
            safeCloseTcpSocket(socket);
        });

        // F-12：请求头已给出目标地址（ATYP+ADDR+PORT），首个 UDP 包可能省略地址头，用它预置响应帧头；
        // 否则响应帧无从构建（原实现 currentRequestHeader 只在收到带地址头的包后才置位）
        if (trAddrHeader) currentRequestHeader = trAddrHeader;

        return {
            async write(chunk: ArrayBuffer) {
                const data = new Uint8Array(chunk);
                
                // Parse incoming Trojan UDP packet:
                // 规范形态：addrType (1B) + addr + port (2B) + payloadLen (2B) + CRLF (2B) + payload
                // F-12 兼容形态：首个 UDP 包可能省略地址头（目标地址已在请求头里给出），
                //   即 payloadLen (2B) + CRLF (2B) + payload。原实现 data[0] 非 1/3/4 即静默 return，
                //   首个 DNS 查询因此被丢弃；此处用请求头地址头补齐，响应帧仍能正确回填。
                // 另：rawClientData 取自请求头端口字段之后，部分客户端会把请求收尾的 CRLF 一并计入，
                // 故先跳过可选的前置 CRLF（ATYP 取值 1/3/4，不可能与 0x0d 冲突），再判定形态。
                let base = 0;
                if (data.length >= 2 && data[0] === 0x0d && data[1] === 0x0a) base = 2;

                let addrLen = 0;
                if (data[base] === 1) addrLen = 4;
                else if (data[base] === 4) addrLen = 16;
                else if (data[base] === 3) {
                    if (data.length < base + 2) return;
                    addrLen = 1 + data[base + 1];
                }

                let addrHeader: Uint8Array;
                let lenIndex: number;
                if (addrLen) {
                    const portIdx = base + 1 + addrLen;
                    if (data.length < portIdx + 6) return;

                    addrHeader = data.slice(base, portIdx + 2); // addrType + addr + port
                    lenIndex = portIdx + 2;
                } else {
                    // 无地址头形态：[payloadLen][CRLF][payload]
                    if (!currentRequestHeader || data.length < base + 4
                        || data[base + 2] !== 0x0d || data[base + 3] !== 0x0a) {
                        log('Trojan UDP: packet without address header and no valid request header, dropped');
                        return;
                    }
                    addrHeader = currentRequestHeader;
                    lenIndex = base;
                }

                currentRequestHeader = addrHeader;

                const payloadLen = (data[lenIndex] << 8) | data[lenIndex + 1];
                const payloadStart = lenIndex + 4; // skips length(2B) + CRLF(2B)
                const payloadEnd = payloadStart + payloadLen;
                if (data.length < payloadEnd) return;

                const dnsQuery = data.slice(payloadStart, payloadEnd);

                // Check global DNS cache
                const cachedResp = getDNSCache(dnsQuery);
                if (cachedResp) {
                    // Cache hit: send Trojan UDP response frame directly
                    const frame = new Uint8Array(addrHeader.length + 4 + cachedResp.length);
                    frame.set(addrHeader, 0);
                    frame[addrHeader.length] = (cachedResp.length >> 8) & 0xff;
                    frame[addrHeader.length + 1] = cachedResp.length & 0xff;
                    frame[addrHeader.length + 2] = 0x0d;
                    frame[addrHeader.length + 3] = 0x0a;
                    frame.set(cachedResp, addrHeader.length + 4);
                    if (webSocket.readyState === WS_READY_STATE_OPEN) {
                        webSocket.send(frame.buffer);
                    }
                    return;
                }

                // Cache miss: add 2-byte TCP DNS length prefix and forward to 8.8.4.4:53
                const prefixed = new Uint8Array(dnsQuery.length + 2);
                prefixed[0] = (dnsQuery.length >> 8) & 0xff;
                prefixed[1] = dnsQuery.length & 0xff;
                prefixed.set(dnsQuery, 2);
                await writer.write(prefixed);
            },
        };
    }
}
