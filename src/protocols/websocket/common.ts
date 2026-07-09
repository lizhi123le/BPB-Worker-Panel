import { connect } from 'cloudflare:sockets';
import { isIPv4, parseHostPort, resolveDNS, selectProxyIPByRegion, stripRegionTag } from '@utils';
import { safeErrorMessage } from '@common';

export const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CONNECT_TIMEOUT = 5000; // 连接超时 5 秒

export async function handleTCPOutBound(
    remoteSocket: { value: Socket | null },
    addressRemote: string,
    portRemote: number,
    rawClientData: ArrayBuffer | undefined,
    webSocket: WebSocket,
    VLResponseHeader: Uint8Array<ArrayBuffer> | null,
    log: Function
) {
    // 保存原始目标地址，兜底直连时使用
    const originalAddress = addressRemote;
    const originalPort = portRemote;

    async function connectAndWrite(address: string, port: number): Promise<Socket> {
        // if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LnNzbGlwLmlv')}`;
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });

        remoteSocket.value = tcpSocket;

        // 连接超时保护：防止连到不通的 IP 时卡死
        await Promise.race([
            tcpSocket.opened,
            new Promise<void>((_, reject) =>
                setTimeout(() => reject(new Error(`连接超时 (${address}:${port})`)), CONNECT_TIMEOUT)
            )
        ]);

        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    const getRandomValue = (arr: string[]) => arr[Math.floor(Math.random() * arr.length)];
    const parseIPs = (value: string) => value ? value.split(',').map(val => val.trim()).filter(Boolean) : undefined;

    // 兜底：直连原始目标地址
    async function fallbackDirect() {
        log(`proxy IP failed, falling back to direct connection for ${originalAddress}`);
        try {
            const tcpSocket = await connectAndWrite(originalAddress, originalPort);
            tcpSocket.closed
                .catch(error => console.log('direct TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
        } catch (error) {
            console.error('Direct connection failed:', error);
            webSocket.close(1011, `Direct connection failed: ${safeErrorMessage(error)}`);
        }
    }

    // prefix 兜底：直连无数据返回时，用 prefix 生成动态 IP
    async function fallbackPrefix() {
        log(`direct connection idle, trying prefix-generated IP for ${originalAddress}`);
        const { panelIPs, envPrefixes, defaultPrefixes } = globalThis.wsConfig;
        const prefixes = panelIPs?.length ? panelIPs : parseIPs(envPrefixes) ?? defaultPrefixes;
        const prefix = getRandomValue(prefixes);

        try {
            const dynamicProxyIP = await getDynamicProxyIP(originalAddress, prefix);
            if (!dynamicProxyIP) {
                webSocket.close(1011, 'Retry connection failed: Invalid Prefix');
                return;
            }
            log(`trying prefix IP ${dynamicProxyIP}:${originalPort}`);
            const tcpSocket = await connectAndWrite(dynamicProxyIP, originalPort);
            tcpSocket.closed
                .catch(error => console.log('prefix TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
        } catch (error) {
            console.error('Prefix retry failed:', error);
            webSocket.close(1011, `Prefix retry failed: ${safeErrorMessage(error)}`);
        }
    }

    // 首次连接：优先使用代理 IP（区域匹配），直连作为兜底
    const { proxyMode, panelIPs, envProxyIPs, envPrefixes, defaultProxyIPs, defaultPrefixes } = globalThis.wsConfig;

    if (proxyMode === 'proxyip') {
        const proxyIPs = panelIPs?.length ? panelIPs : parseIPs(envProxyIPs) ?? defaultProxyIPs;
        const { regionMatch, workerRegion } = globalThis.wsConfig;
        const proxyIP = (regionMatch && workerRegion)
            ? (selectProxyIPByRegion(proxyIPs, workerRegion) ?? getRandomValue(proxyIPs))
            : getRandomValue(proxyIPs);
        const cleanIP = stripRegionTag(proxyIP);
        const { host, port } = parseHostPort(cleanIP, true);
        const proxyAddr = host || originalAddress;
        const proxyPort = port || originalPort;

        try {
            log(`trying Proxy IP ${proxyAddr}:${proxyPort} for ${originalAddress}`);
            const tcpSocket = await connectAndWrite(proxyAddr, proxyPort);
            // proxy IP 连接成功但无数据返回时，降级直连
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, fallbackDirect, log);
            return;
        } catch (error) {
            console.error(`Proxy IP connection failed: ${error}`);
            log(`proxy IP failed, falling back to direct connection`);
            // 代理 IP 连接失败，直接降级直连
        }
    }

    // 降级或非 proxyip 模式：直接连接目标地址
    try {
        const tcpSocket = await connectAndWrite(originalAddress, originalPort);
        // prefix 模式：直连无数据时用 prefix 生成动态 IP 重试
        const retryFn = proxyMode === 'prefix' ? fallbackPrefix : null;
        remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, retryFn, log);
    } catch (error) {
        console.error(`Connection failed: ${error}`);
        webSocket.close(1011, `Connection failed: ${safeErrorMessage(error)}`);
    }
}

async function remoteSocketToWS(
    remoteSocket: Socket,
    webSocket: WebSocket,
    VLResponseHeader: Uint8Array<ArrayBuffer> | null,
    retry: Function | null,
    log: Function
) {
    let vlHeader = VLResponseHeader;
    let hasIncomingData = false;

    const writableStream = new WritableStream({
        start() { },
        async write(chunk, controller) {
            hasIncomingData = true;
            if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                controller.error("webSocket.readyState is not open, maybe close");
            }

            if (vlHeader) {
                webSocket.send(await new Blob([vlHeader, chunk]).arrayBuffer());
                vlHeader = null;
            } else {
                webSocket.send(chunk);
            }
        },
        close() {
            log(`remoteConnection.readable is close with hasIncomingData is ${hasIncomingData}`);
        },
        abort(reason) {
            console.error(`remoteConnection.readable abort`, reason);
            safeCloseTcpSocket(remoteSocket);
        }
    });

    try {
        await remoteSocket.readable.pipeTo(writableStream);
    } catch (error) {
        console.error('VLRemoteSocketToWS has exception.', error);
        safeCloseTcpSocket(remoteSocket);
        safeCloseWebSocket(webSocket);
    }

    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

export function makeReadableWebSocketStream(webSocketServer: WebSocket, earlyDataHeader: string, log: Function) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) return;
                // WebSocket binaryType='arraybuffer' ensures event.data is always ArrayBuffer
                controller.enqueue(event.data);
            });

            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) return;
                controller.close();
            });

            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer has error");
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);

            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(_controller) { },
        cancel(reason) {
            if (readableStreamCancel) return;
            log(`ReadableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

function base64ToArrayBuffer(base64Str: string) {
    if (!base64Str) {
        return { earlyData: null, error: null };
    }

    try {
        // go use modified Base64 for URL rfc4648 which js atob not support
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

export function safeCloseTcpSocket(socket: Socket | null) {
    if (socket) {
        try {
            socket.close();
        } catch (error) {
            console.error("Failed to close TCP socket:", error);
        }
    }
}

export function safeCloseWebSocket(socket: WebSocket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error('safeCloseWebSocket error', error);
    }
}

async function getDynamicProxyIP(address: string, prefix: string) {
    let finalAddress = address;

    if (!isIPv4(address)) {
        const { ipv4 } = await resolveDNS(address, true);

        if (ipv4.length) {
            finalAddress = ipv4[0];
        } else {
            throw new Error('Unable to find IPv4 in DNS records');
        }
    }

    return convertToNAT64IPv6(finalAddress, prefix);
}

function convertToNAT64IPv6(ipv4Address: string, prefix: string) {
    const parts = ipv4Address.split('.');

    if (parts.length !== 4) {
        throw new Error('Invalid IPv4 address');
    }

    const hex = parts.map(part => {
        const num = parseInt(part, 10);

        if (num < 0 || num > 255) {
            throw new Error('Invalid IPv4 address');
        }

        return num.toString(16).padStart(2, '0');
    });

    const match = prefix.match(/^\[([0-9A-Fa-f:]+)\]$/);

    if (match) {
        return `[${match[1]}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
    }
}

