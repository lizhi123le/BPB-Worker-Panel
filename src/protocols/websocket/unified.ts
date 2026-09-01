import {
    safeCloseTcpSocket,
    handleTCPOutBound,
    makeReadableWebSocketStream,
    WS_READY_STATE_OPEN,
    connectSocket
} from './common';

// 对齐 cfnew c0eb20c（明文源吗 L33-40）：隐私增强 —— 智能剥离随机填充前缀
// 客户端首包可能携带 [0xED 0x7F][2 字节 padLen][padLen 字节随机填充]，若不剥离直接做
// 协议检测，0xED 0x7F 会被 parseVlHeader 当成版本号、填充被当成 UUID，检测必失败。
// 幂等：无魔数或 padLen 异常时原样返回，非首包（已建连后的数据块）不受影响。
const PRIVACY_MAGIC = 0xED7F;

function stripPrivacyPadding(data: ArrayBuffer): ArrayBuffer {
    if (data.byteLength < 4) return data;
    const bytes = new Uint8Array(data);
    const magic = (bytes[0] << 8) | bytes[1];
    if (magic !== PRIVACY_MAGIC) return data; // 旧客户端，无魔数
    const padLen = (bytes[2] << 8) | bytes[3];
    if (padLen < 64 || padLen > 2048) return data; // 异常值，视为旧客户端
    return data.slice(4 + padLen); // 跳过 [魔数][长度][填充]
}

// ===== xPadding 抗指纹（对齐 cfnew 52143dccb，参考 cmliu/edgetunnel）=====
// UUID 派生隐蔽的填充头名/键名，服务端宽松校验、响应回写随机填充，订阅链接带 extra 约定。
// 与上方 0xED7F 隐私填充（数据层）不同，xPadding 是 HTTP 层抗指纹机制，两者互不冲突。
// 霍夫曼码长表（RFC 7541，257 项，索引 0-256，256 为 EOS）
const XPADDING_HUFFMAN_CODE_LENGTHS = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30
];

// 从 UUID 派生隐蔽的头名/键名，与订阅侧 extra 约定一致
export function getXPaddingIdentifier(uuid: string): { header: string; key: string } {
    return { header: uuid.slice(1, 7), key: '_' + uuid.slice(25, 31) };
}

// 计算字符串按霍夫曼编码后的字节长度（用于填充长度校验）
function calcXPaddingHuffmanByteLength(str: string): number {
    const bytes = new TextEncoder().encode(str);
    let totalBits = 0;
    for (let i = 0; i < bytes.length; i++) totalBits += XPADDING_HUFFMAN_CODE_LENGTHS[bytes[i]];
    return Math.ceil(totalBits / 8);
}

// 提取填充值：优先头（URL 编码形式），回退请求 URL 查询参数
function extractXPaddingValue(request: Request, header: string, key: string): string {
    const headerValue = request.headers.get(header);
    if (headerValue) {
        try {
            const parsed = new URL(headerValue, 'https://x.invalid');
            const queryValue = parsed.searchParams.get(key);
            if (queryValue) return queryValue;
        } catch (_) { /* ignore */ }
        return headerValue;
    }
    try {
        return new URL(request.url).searchParams.get(key) || '';
    } catch (_) {
        return '';
    }
}

// 宽松校验：空填充放行（老客户端兼容），非空时霍夫曼字节长度须在 98..1002
function validateXPadding(request: Request, header: string, key: string): boolean {
    const padding = extractXPaddingValue(request, header, key);
    if (!padding) return true;
    const length = calcXPaddingHuffmanByteLength(padding);
    return length >= 98 && length <= 1002;
}

const XPADDING_CHARSET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

// 生成随机填充串（纯噪声，服务端不回读校验）
function generateXPaddingString(length: number): string {
    const charsetLength = XPADDING_CHARSET.length;
    let result = '';
    for (let i = 0; i < length; i++) result += XPADDING_CHARSET[Math.floor(Math.random() * charsetLength)];
    return result;
}

export async function UnifiedWSHandler(request: Request): Promise<Response> {
    // 对齐 cfnew 52143dccb：xPadding 抗指纹 —— 入站宽松校验（空填充放行，非法返回 400）
    const { userID: xPaddingUserID } = globalThis.globalConfig;
    if (xPaddingUserID) {
        const { header: xPaddingHeader, key: xPaddingKey } = getXPaddingIdentifier(xPaddingUserID);
        if (!validateXPadding(request, xPaddingHeader, xPaddingKey)) {
            return new Response('Bad Request', { status: 400 });
        }
    }

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

    const writableStream = new WritableStream({
        async write(chunk) {
            // 对齐 cfnew c0eb20c：write 入口无条件剥离 0xED7F 魔数+随机填充（明文源吗 L4638）
            // 幂等：无魔数/异常 padLen 原样返回；剥离后数据供后续所有协议检测与解析使用
            chunk = stripPrivacyPadding(chunk);

            // 测速拦截：WS 本地测速模式下直接处理请求（对齐 cfnew L4641-4644）
            if (wsLocalSpeedTestMode) {
                await processWsLocalSpeedTestData(chunk);
                return;
            }

            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }

            if (remoteSocketWrapper.value) {
                if (!remoteWriter) {
                    remoteWriter = remoteSocketWrapper.value.writable.getWriter();
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

                // 测速拦截：无代理时本地 204 响应（对齐 cfnew L4679-4681）
                if (isSpeedTestSite(addressRemote) && !globalThis.wsConfig.hasCustomProxyIPs) {
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
                        const { write } = await handleUDPOutBound(webSocket, null, log, 'trojan', fetcher);
                        udpStreamWrite = write;
                        await udpStreamWrite(rawClientData);
                        return;
                    } else {
                        throw new Error("UDP proxy only enable for DNS which is port 53");
                    }
                }

                // 测速拦截：无代理时本地 204 响应（对齐 cfnew L4703-4705）
                if (isSpeedTestSite(addressRemote) && !globalThis.wsConfig.hasCustomProxyIPs) {
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

                    // 测速拦截：无代理时本地 204 响应（对齐 cfnew L4679-4681）
                    if (isSpeedTestSite(addressRemote) && !globalThis.wsConfig.hasCustomProxyIPs) {
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
                        isUDP,
                    } = await parseTrHeader(firstChunk, TrPass!);

                    address = addressRemote;
                    portWithRandomLog = `${portRemote}--${Math.random()} tcp`;

                    if (hasError) {
                        throw new Error(message);
                    }

                    if (isUDP) {
                        if (portRemote === 53) {
                            isDns = true;
                            const { write } = await handleUDPOutBound(webSocket, null, log, 'trojan', fetcher);
                            udpStreamWrite = write;
                            await udpStreamWrite(rawClientData);
                            return;
                        } else {
                            throw new Error("UDP proxy only enable for DNS which is port 53");
                        }
                    }

                    // 测速拦截：无代理时本地 204 响应（对齐 cfnew L4703-4705）
                    if (isSpeedTestSite(addressRemote) && !globalThis.wsConfig.hasCustomProxyIPs) {
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

                throw new Error('Invalid protocol or authentication failed');
            }
        },
        close() {
            if (remoteWriter) {
                try { remoteWriter.releaseLock(); } catch (_) { /* already released */ }
                remoteWriter = null;
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

    // 对齐 cfnew 52143dccb：xPadding 抗指纹 —— 101 响应回写随机填充头（100-1000 字符纯噪声）
    const responseHeaders = new Headers();
    try {
        const { userID: respUserID } = globalThis.globalConfig;
        if (respUserID) {
            const { header: respPaddingHeader, key: respPaddingKey } = getXPaddingIdentifier(respUserID);
            const paddingUrl = new URL('https://x.invalid/');
            paddingUrl.searchParams.set(respPaddingKey, generateXPaddingString(100 + Math.floor(Math.random() * 901)));
            responseHeaders.set(respPaddingHeader, paddingUrl.toString());
        }
    } catch (_) { /* ignore */ }

    return new Response(null, {
        status: 101,
        webSocket: client,
        headers: responseHeaders,
    });
}

function parseVlHeader(VLBuffer: ArrayBuffer, userID: string) {
    if (VLBuffer.byteLength < 24) {
        return { hasError: true, message: "invalid data" };
    }

    const version = new Uint8Array(VLBuffer.slice(0, 1));
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
    if (data.byteLength < 6) {
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

    const port = view.getUint16(addressIndex);

    return {
        hasError: false,
        addressRemote: address,
        portRemote: port,
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
        if (data.byteLength < 6) return null;

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

async function handleUDPOutBound(webSocket: WebSocket, VLResponseHeader: Uint8Array<ArrayBuffer> | null, log: Function, protocol: 'vless' | 'trojan', fetcher?: any) {
    if (protocol === 'vless') {
        // VLESS UDP DNS: TCP socket to 8.8.4.4:53 with caching (cfnew style)
        let isVLHeaderSent = false;

        const cache = new Map<string, { response: Uint8Array; expiresAt: number }>();
        const CACHE_MAX = 1024;

        const transformStream = new TransformStream({
            start(_controller) { },
            transform(chunk, controller) {
                // Parse UDP packets: 2-byte length + payload
                for (let index = 0; index < chunk.byteLength;) {
                    const lengthBuffer = chunk.slice(index, index + 2);
                    const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                    const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
                    index = index + 2 + udpPacketLength;
                    
                    // Cache by domain|qtype|qclass
                    const info = parseDNSQueryInfo(udpData);
                    const key = info ? `${info.domain}|${info.qtype}|${info.qclass}` : null;
                    if (key) {
                        const cached = cache.get(key);
                        if (cached && Date.now() < cached.expiresAt) {
                            controller.enqueue(cached.response);
                            continue;
                        } else if (cached) {
                            cache.delete(key); // expired
                        }
                    }
                    controller.enqueue(udpData);
                }
            },
            flush(_controller) { },
        });

        const socket = connectSocket({ hostname: '8.8.4.4', port: 53 }, fetcher);
        await Promise.race([
            socket.opened,
            new Promise((_, reject) => setTimeout(() => reject(new Error('DNS connect timeout')), 5000))
        ]);
        log('VLESS DNS TCP connected to 8.8.4.4:53');

        const writer = socket.writable.getWriter();
        
        // Send initial data from transform
        const pumpReader = transformStream.readable.getReader();
        const pumpToSocket = async () => {
            try {
                while (true) {
                    const { done, value } = await pumpReader.read();
                    if (done) break;
                    // Add 2-byte TCP DNS length prefix
                    const data = value as Uint8Array;
                    const prefixed = new Uint8Array(data.length + 2);
                    prefixed[0] = (data.length >> 8) & 0xff;
                    prefixed[1] = data.length & 0xff;
                    prefixed.set(data, 2);
                    await writer.write(prefixed);
                }
            } catch (e) {
                log('VLESS DNS pump error: ' + e);
            }
        };
        pumpToSocket();

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

                        // Build VLESS UDP frame: VLResponseHeader (first only) + raw DNS payload
                        if (isVLHeaderSent) {
                            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                                webSocket.send(dnsPayload.buffer);
                            }
                        } else {
                            // First response includes VL header
                            const frame = new Uint8Array(VLResponseHeader!.length + dnsPayload.length);
                            frame.set(VLResponseHeader!, 0);
                            frame.set(dnsPayload, VLResponseHeader!.length);
                            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                                webSocket.send(frame.buffer);
                            }
                            isVLHeaderSent = true;
                        }

                        // Cache by domain|qtype|qclass with TTL expiry
                        const ancount = (dnsPayload[6] << 8) | dnsPayload[7];
                        if (ancount === 0) {
                            // NXDOMAIN or empty — don't cache
                            offset = dnsEnd;
                            continue;
                        }
                        const cacheInfo = parseDNSQueryInfo(dnsPayload);
                        if (cacheInfo && dnsPayload.length >= 2) {
                            const key = `${cacheInfo.domain}|${cacheInfo.qtype}|${cacheInfo.qclass}`;
                            if (cache.size >= CACHE_MAX) {
                                const firstKey = cache.keys().next().value;
                                if (firstKey) cache.delete(firstKey);
                            }
                            const ttl = parseDNSResponseTTL(dnsPayload);
                            const expiresAt = Date.now() + Math.min(86400, Math.max(60, ttl)) * 1000;
                            cache.set(key, { response: dnsPayload, expiresAt });
                        }

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
                responseReader.releaseLock();
            }
        };
        handleVLESSDNSResponse();

        log('VLESS DNS TCP connected to 8.8.4.4:53');

        return {
            async write(chunk: ArrayBuffer) {
                const data = new Uint8Array(chunk);
                // Add 2-byte TCP DNS length prefix
                const prefixed = new Uint8Array(data.length + 2);
                prefixed[0] = (data.length >> 8) & 0xff;
                prefixed[1] = data.length & 0xff;
                prefixed.set(data, 2);
                await writer.write(prefixed);
            },
        };
    } else {
        // Trojan UDP DNS: Parse Trojan UDP packets, forward to 8.8.4.4:53 via TCP, reconstruct responses
        // 对齐 cfnew：共享 DNS 缓存（VLESS + Trojan 复用），键 = DNS查询ID(前2字节) + 长度
        const dnsCache = new Map<string, Uint8Array>();
        const DNS_CACHE_MAX = 1024;

        let dnsBuffer = new Uint8Array(0);
        const DNS_MAX_BUF = 65536;
        let currentRequestHeader: Uint8Array | null = null; // Stores addrType + addr + port + CR LF from request

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

                        // 对齐 cfnew：DNS 缓存查询/存储（键 = DNS查询ID + 长度）
                        let cacheKey = '';
                        if (dnsPayload.length >= 2) {
                            cacheKey = `${dnsPayload[0]}${dnsPayload[1]}:${dnsPayload.length}`;
                            const cached = dnsCache.get(cacheKey);
                            if (cached) {
                                // 缓存命中：直接发送缓存的响应
                                const frame = new Uint8Array(
                                    currentRequestHeader!.length + 2 + cached.length + 2
                                );
                                frame.set(currentRequestHeader!, 0);
                                frame[currentRequestHeader!.length] = (cached.length >> 8) & 0xff;
                                frame[currentRequestHeader!.length + 1] = cached.length & 0xff;
                                frame.set(cached, currentRequestHeader!.length + 2);
                                frame[frame.length - 2] = 0x0d;
                                frame[frame.length - 1] = 0x0a;
                                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                                    webSocket.send(frame.buffer);
                                }
                                offset = dnsEnd;
                                continue;
                            }
                        }

                        // Build Trojan UDP response frame:
                        // addrType + addr + port + CR LF + 2-byte length + payload + CR LF
                        if (currentRequestHeader) {
                            const frame = new Uint8Array(
                                currentRequestHeader.length + 2 + dnsPayload.length + 2
                            );
                            frame.set(currentRequestHeader, 0);
                            frame[currentRequestHeader.length] = (dnsPayload.length >> 8) & 0xff;
                            frame[currentRequestHeader.length + 1] = dnsPayload.length & 0xff;
                            frame.set(dnsPayload, currentRequestHeader.length + 2);
                            frame[frame.length - 2] = 0x0d; // CR
                            frame[frame.length - 1] = 0x0a; // LF
                            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                                webSocket.send(frame.buffer);
                            }
                        }

                        // 存入缓存
                        if (cacheKey && dnsCache.size < DNS_CACHE_MAX) {
                            dnsCache.set(cacheKey, dnsPayload);
                        }

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
                reader.releaseLock();
            }
        }

        // Connect to DNS server via TCP
        const socket = connectSocket({ hostname: '8.8.4.4', port: 53 }, fetcher);
        await Promise.race([
            socket.opened,
            new Promise((_, reject) => setTimeout(() => reject(new Error('DNS connect timeout')), 5000))
        ]);
        log('Trojan DNS TCP connected to 8.8.4.4:53');
        handleTrojanUDPResponse(socket);

        const writer = socket.writable.getWriter();

        return {
            async write(chunk: ArrayBuffer) {
                const data = new Uint8Array(chunk);
                
                // Parse incoming Trojan UDP packet to extract address/port header
                // Format: addrType + addr + port + CR LF + 2-byte length + payload + CR LF
                if (data.length >= 3) {
                    const addrType = data[0];
                    let addrLen = 0;
                    let headerEnd = 1;
                    
                    if (addrType === 1) { // IPv4
                        addrLen = 4;
                        headerEnd = 1 + 4;
                    } else if (addrType === 4) { // IPv6
                        addrLen = 16;
                        headerEnd = 1 + 16;
                    } else if (addrType === 3) { // Domain
                        if (data.length >= 2) {
                            addrLen = data[1];
                            headerEnd = 2 + addrLen;
                        }
                    }
                    
                    if (data.length >= headerEnd + 2) {
                        // Check for CR LF after address+port
                        if (data[headerEnd] === 0x0d && data[headerEnd + 1] === 0x0a) {
                            // Found complete header: addrType + addr + port + CR LF
                            // Save for response framing
                            currentRequestHeader = data.slice(0, headerEnd + 2);
                        }
                    }
                }
                
                // Add 2-byte TCP DNS length prefix and forward
                const prefixed = new Uint8Array(data.length + 2);
                prefixed[0] = (data.length >> 8) & 0xff;
                prefixed[1] = data.length & 0xff;
                prefixed.set(data, 2);
                await writer.write(prefixed);
            },
        };
    }
}
