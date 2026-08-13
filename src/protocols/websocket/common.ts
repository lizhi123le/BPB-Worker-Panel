import { resolveDNS, filterReachableIPs, selectProxyIPByRegion, parseHostPort, stripRegionTag, DEFAULT_PROXY_IPS, countryToRegion } from '@utils';
import { safeErrorMessage } from '@common';

// cfnew 风格：每次调用时才从运行时全局查找 connect，避免模块加载时固化为 undefined
// 核心修复：原写法 `export const connectSocket = getConnect()` 在模块加载期立即执行，
// 此时 CF Workers 的 globalThis.connect 尚未挂载，导致 connectSocket === undefined。
// 对齐 cfnew: const 连接 = (选项) => (typeof TCP拨号 !== 'undefined' ? TCP拨号 : connect)(选项)
export const connectSocket = (options: { hostname: string; port: number }, fetcher?: any): Socket => {
    // 对齐 cfnew d4b2b7f：优先 request.fetcher.connect，回退全局 connect()
    // （新版 Workers 运行时可能没有全局 connect，必须用请求绑定的 fetcher 建连）
    return fetcher && typeof fetcher.connect === 'function'
        ? fetcher.connect(options)
        : (globalThis as any).connect(options);
};

export const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CONNECT_TIMEOUT = 5000; // 连接超时 5 秒
const RACE_DIAL_CONCURRENCY = 3; // 并发拨号数量，参考 cfnew
const RACE_DIAL_MAX_BATCHES = 5; // 最大重试批次

// IP:port 黑名单：连续失败计数 + 冷却，避免反复拨号已知不通的 IP
const IP_BLACKLIST_TTL = 5 * 60 * 1000;   // 基础冷却 5 分钟
const IP_BLACKLIST_MAX_FAIL = 3;          // 连续失败达到该次数后，冷却期延长 3 倍
const ipBlacklist = new Map<string, { failCount: number; lastFailAt: number }>();
function blacklistCheck(key: string): boolean {
    const e = ipBlacklist.get(key);
    if (!e) return false;
    // 连续失败越多，冷却越久：达到 IP_BLACKLIST_MAX_FAIL 后延长 3 倍，
    // 避免对反复拨号已知不通的 IP 造成无谓的建连开销（对齐 cfnew 节点黑名单语义）
    const ttl = e.failCount >= IP_BLACKLIST_MAX_FAIL ? IP_BLACKLIST_TTL * 3 : IP_BLACKLIST_TTL;
    if (Date.now() - e.lastFailAt > ttl) {
        ipBlacklist.delete(key);
        return false;
    }
    return true;
}
function blacklistRecord(key: string) {
    const e = ipBlacklist.get(key);
    // failCount 封顶到 IP_BLACKLIST_MAX_FAIL，防止长生命周期 isolate 中无界增长
    const failCount = Math.min((e ? e.failCount : 0) + 1, IP_BLACKLIST_MAX_FAIL);
    ipBlacklist.set(key, { failCount, lastFailAt: Date.now() });
}
function blacklistClear(key: string) { ipBlacklist.delete(key); }

/** cfnew 风格：竞速拨号多个代理 IP，取最快成功的 */
async function connectWithRaceDial(
    targetAddress: string,
    targetPort: number,
    rawClientData: ArrayBuffer | undefined,
    log: Function,
    fetcher?: any
): Promise<{ socket: Socket; usedIp: string }> {
    // 1. 获取配置
    const { panelIPs, envProxyIPs, proxyMode, regionMatch, workerRegion } = globalThis.wsConfig;
    const proxyIPs = panelIPs?.length ? panelIPs : (envProxyIPs ? [envProxyIPs] : DEFAULT_PROXY_IPS);
    
    if (!proxyIPs.length) {
        throw new Error('No proxy IPs available');
    }

    // 如果是 prefix 模式，直接走 NAT64 prefix 路径
    if (proxyMode === 'prefix') {
        return await connectWithPrefixFallback(targetAddress, targetPort, rawClientData, log, fetcher);
    }

    // 2. 根据 workerRegion 选择最优代理 IP（cfnew 逻辑）
    let selectedProxyIP = proxyIPs[0];
    if (regionMatch && workerRegion) {
        const region = countryToRegion(workerRegion);
        const regionSelected = selectProxyIPByRegion(proxyIPs, region);
        if (regionSelected) selectedProxyIP = regionSelected;
    }
    
    log(`selected proxy IP: ${selectedProxyIP} for ${targetAddress}:${targetPort}`);

    // 3. 解析选中的代理域名（去除地区标签）
    const cleanProxyIP = stripRegionTag(selectedProxyIP);
    const { host: proxyHost, port: proxyPort } = parseHostPort(cleanProxyIP, true);
    const proxyAddr = proxyHost || targetAddress;
    const proxyPortNum = proxyPort || targetPort;

    // 4. DoH 解析代理域名获取 IP 池
    log(`resolving proxy ${proxyAddr} via DoH...`);
    const { ipv4, ipv6 } = await resolveDNS(proxyAddr, true);
    const allIps = [...ipv4, ...ipv6.map(ip => `[${ip}]`)];
    
    if (allIps.length === 0) {
        throw new Error(`DNS resolution failed for proxy ${proxyAddr}`);
    }
    
    log(`got ${allIps.length} IPs for proxy ${proxyAddr}, probing reachability...`);
    
    // 5. 并发探测前 8 个 IP 的可达性
    const probeIps = allIps.slice(0, 8);
    const reachableIps = await filterReachableIPs(probeIps, proxyPortNum);
    
    log(`reachable proxy IPs: ${reachableIps.join(', ')}`);
    
    // 6. 分批竞速拨号
    const dialConcurrency = RACE_DIAL_CONCURRENCY;
    let offset = 0;
    
    for (let batch = 0; batch < RACE_DIAL_MAX_BATCHES && offset < reachableIps.length; batch++) {
        const batchIps = reachableIps.slice(offset, offset + dialConcurrency);
        offset += dialConcurrency;
        
        if (batchIps.length === 0) continue;
        
        log(`race dialing batch ${batch + 1}: ${batchIps.join(', ')}`);
        
        // 并发拨号，取最快成功的
        const dialPromises = batchIps.map(async (ip) => {
            const cleanIp = ip.replace(/^\[|\]$/g, '');
            const socket = connectSocket({ hostname: cleanIp, port: proxyPortNum }, fetcher);
            // 等待连接建立
            await Promise.race([
                socket.opened,
                new Promise<never>((_, reject) => 
                    setTimeout(() => reject(new Error('timeout')), CONNECT_TIMEOUT)
                )
            ]);
            return { socket, ip: cleanIp };
        });
        
        const results = await Promise.allSettled(dialPromises);
        
        // 找第一个竞速成功的 socket，直接写载荷（对齐 cfnew 连接值发送直连路径 L4732-4768）：
        // 备用地址（CMLosss 等）是直连中继，竞速拨号建立 TCP 后无需 SOCKS5 握手，
        // 直接通过写入器把剥离 VLESS 头后的载荷写入即可。写入失败视同该候选不通，
        // 继续尝试本批下一个候选。
        for (const result of results) {
            if (result.status !== 'fulfilled' || !result.value || !result.value.socket) continue;
            const { socket, ip } = result.value;
            try {
                // 先写首包再关闭其余候选，避免连接被重置（对齐 cfnew 连接值发送 L4766-4768：
                // if (值数据378.byteLength) await 写入器.write(值数据378)）
                const writer = socket.writable.getWriter();
                if (rawClientData && rawClientData.byteLength) {
                    await writer.write(rawClientData);
                }
                writer.releaseLock();
                // 关闭其余已建立的候选 socket，避免泄漏（对齐 cfnew 连接值套接字 Promise.any 关闭败者）
                for (const other of results) {
                    if (other.status === 'fulfilled' && other.value && other.value.socket && other.value.socket !== socket) {
                        try { other.value.socket.close(); } catch {}
                    }
                }
                log(`race dial winner: ${ip}:${proxyPortNum} (proxy: ${proxyAddr})`);
                return { socket, usedIp: ip };
            } catch (writeError) {
                log(`race dial write failed for ${ip}:${proxyPortNum}: ${safeErrorMessage(writeError)}`);
                try { socket.close(); } catch {}
            }
        }
        
        // 本批次全部失败，关闭已建立的连接（如果有）
        for (const result of results) {
            if (result.status === 'fulfilled' && result.value && result.value.socket) {
                try { result.value.socket.close(); } catch {}
            }
        }
    }
    
    // 所有批次都失败，抛出错误让上层处理兜底
    throw new Error(`All race dial attempts failed for proxy ${proxyAddr}:${proxyPortNum}`);
}

/** 判断地址是否为 IP 字面量（IPv4 或含冒号的 IPv6），而非域名（对齐 cfnew 是IP地址） */
const isIPLiteral = (address: string): boolean =>
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)
    || (address.includes(':') && !address.includes('/'));

// 直连 IP 池轮询偏移（模块级，避免总是从第一个 IP 开始，对齐 cfnew IP池轮询索引）
let directPoolRoundRobin = 0;
// 直连竞速每批并发拨号数：对齐 cfnew 传输连接竞速数=2
const DIRECT_RACE_CONCURRENCY = 2;

/**
 * cfnew 风格：直连竞速拨号（目标域名/IP 池 + 黑名单跳过 + failover）
 * 对齐 cfnew 连接值发送直连路径 L4730-4783：DNS 解析目标 → IP 池轮询 → 分批竞速拨号
 * → 黑名单记录失败候选 → 全部失败则抛出，由上层走代理/兜底。
 */
async function connectWithDirectRaceDial(
    targetAddress: string,
    targetPort: number,
    rawClientData: ArrayBuffer | undefined,
    log: Function,
    fetcher?: any
): Promise<{ socket: Socket; usedIp: string }> {
    // 1. 构建 IP 池：IP 字面量直接用；域名则 DoH 解析（A + AAAA）
    let pool: string[];
    if (isIPLiteral(targetAddress)) {
        pool = [targetAddress];
    } else {
        log(`resolving ${targetAddress} via DoH for direct dial...`);
        const { ipv4, ipv6 } = await resolveDNS(targetAddress, true);
        pool = [...ipv4, ...ipv6.map(v6 => `[${v6}]`)];
    }

    if (pool.length === 0) {
        throw new Error(`DNS resolution failed for direct target ${targetAddress}`);
    }

    log(`direct dial IP pool: ${pool.join(', ')}`);

    // 2. 轮询偏移：大素数取模防溢出，避免每次总是从第一个 IP 开始
    const startOffset = directPoolRoundRobin % pool.length;
    let attemptedBatches = 0;

    // 3. 分批竞速拨号：每批并发 DIRECT_RACE_CONCURRENCY 个，黑名单内的候选直接跳过
    for (let k = 0; k < pool.length && attemptedBatches < RACE_DIAL_MAX_BATCHES; k += DIRECT_RACE_CONCURRENCY) {
        const batchCandidates: { hostname: string; port: number; key: string; index: number }[] = [];
        for (let j = 0; j < DIRECT_RACE_CONCURRENCY && k + j < pool.length; j++) {
            const realIndex = (startOffset + k + j) % pool.length;
            const ip = pool[realIndex];
            const key = `${ip}:${targetPort}`;
            if (blacklistCheck(key)) continue; // 黑名单预检，不计 failCount
            batchCandidates.push({ hostname: ip.replace(/^\[|\]$/g, ''), port: targetPort, key, index: realIndex });
        }
        if (batchCandidates.length === 0) continue;
        attemptedBatches++;

        log(`direct race dialing batch ${attemptedBatches}: ${batchCandidates.map(c => c.key).join(', ')}`);

        // 并发拨号，每个候选独立超时保护
        const dialPromises = batchCandidates.map(async (candidate) => {
            const socket = connectSocket({ hostname: candidate.hostname, port: candidate.port }, fetcher);
            await Promise.race([
                socket.opened,
                new Promise<never>((_, reject) =>
                    setTimeout(() => reject(new Error('timeout')), CONNECT_TIMEOUT)
                )
            ]);
            return { socket, candidate };
        });

        const results = await Promise.allSettled(dialPromises);

        // 4. 取首个竞速成功的 socket，写首包后关闭其余候选，避免连接被重置
        for (const result of results) {
            if (result.status !== 'fulfilled' || !result.value || !result.value.socket) continue;
            const { socket, candidate } = result.value;
            try {
                const writer = socket.writable.getWriter();
                if (rawClientData && rawClientData.byteLength) {
                    await writer.write(rawClientData);
                }
                writer.releaseLock();
                // 关闭其余已建立的候选 socket，避免泄漏
                for (const other of results) {
                    if (other.status === 'fulfilled' && other.value && other.value.socket && other.value.socket !== socket) {
                        try { other.value.socket.close(); } catch {}
                    }
                }
                blacklistClear(candidate.key); // 胜出候选清除黑名单
                directPoolRoundRobin = candidate.index; // 轮询偏移指向胜出候选，下一轮优先尝试
                log(`direct race dial winner: ${candidate.key}`);
                return { socket, usedIp: candidate.hostname };
            } catch (writeError) {
                log(`direct race dial write failed for ${candidate.key}: ${safeErrorMessage(writeError)}`);
                try { socket.close(); } catch {}
            }
        }

        // 5. 整批失败：关闭已建立的连接并记录黑名单（自动递增 failCount）
        for (const result of results) {
            if (result.status === 'fulfilled' && result.value && result.value.socket) {
                try { result.value.socket.close(); } catch {}
            }
        }
        for (const candidate of batchCandidates) {
            blacklistRecord(candidate.key);
        }
    }

    // 6. 全部失败：抛出错误，由上层走代理路径/兜底直连
    throw new Error(`All direct race dial attempts failed for ${targetAddress}:${targetPort}`);
}

/** 工具函数：模块级，供 connectWithPrefixFallback 等使用 */
const getRandomValue = (arr: string[]) => arr[Math.floor(Math.random() * arr.length)];
const parseIPs = (value: string) => value ? value.split(',').map(val => val.trim()).filter(Boolean) : undefined;

/** 连接并写入初始数据的工具函数，供模块内各连接策略使用 */
async function connectAndWrite(address: string, port: number, rawClientData: ArrayBuffer | undefined, fetcher?: any): Promise<Socket> {
    // if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LnNzbGlwLmlv')}`;
    const tcpSocket = connectSocket({
        hostname: address,
        port: port,
    }, fetcher);

    // 连接超时保护：防止连到不通的 IP 时卡死
    await Promise.race([
        tcpSocket.opened,
        new Promise<void>((_, reject) =>
            setTimeout(() => reject(new Error(`连接超时 (${address}:${port})`)), CONNECT_TIMEOUT)
        )
    ]);

    // log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
}

/** NAT64 prefix 模式：将目标域名解析为 IPv4，转换为 IPv6 NAT64 地址连接 */
async function connectWithPrefixFallback(
    targetAddress: string,
    targetPort: number,
    rawClientData: ArrayBuffer | undefined,
    log: Function,
    fetcher?: any
): Promise<{ socket: Socket; usedIp: string }> {
    log(`using NAT64 prefix mode for ${targetAddress}:${targetPort}`);
    
    const { panelIPs, envPrefixes, defaultPrefixes } = globalThis.wsConfig;
    const settingsPrefixes = globalThis.settings?.prefixes?.length ? globalThis.settings.prefixes : [];
    const prefixes = settingsPrefixes.length
        ? settingsPrefixes
        : (panelIPs?.length ? panelIPs : parseIPs(envPrefixes) ?? defaultPrefixes);
    
    if (!prefixes.length) {
        throw new Error('No NAT64 prefixes available');
    }

    const prefix = getRandomValue(prefixes);
    
    // 解析目标域名获取 IPv4
    const { ipv4 } = await resolveDNS(targetAddress, true);
    if (!ipv4.length) {
        throw new Error('Unable to find IPv4 in DNS records for prefix fallback');
    }
    const targetIPv4 = ipv4[0];
    
    // 转换为 NAT64 IPv6 地址
    const match = prefix.match(/^\[([0-9A-Fa-f:]+)\]$/);
    if (!match) {
        throw new Error('Invalid prefix format');
    }
    const parts = targetIPv4.split('.');
    const hex = parts.map(part => parseInt(part, 10).toString(16).padStart(2, '0'));
    const nat64IP = `[${match[1]}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
    
    log(`trying NAT64 prefix IP ${nat64IP}:${targetPort}`);
    
    const tcpSocket = await connectAndWrite(nat64IP, targetPort, rawClientData, fetcher);
    
    return { socket: tcpSocket, usedIp: nat64IP };
}

export async function handleTCPOutBound(
    remoteSocket: { value: Socket | null },
    addressRemote: string,
    portRemote: number,
    rawClientData: ArrayBuffer | undefined,
    webSocket: WebSocket,
    VLResponseHeader: Uint8Array<ArrayBuffer> | null,
    log: Function,
    fetcher?: any
) {
    // 保存原始目标地址，兜底直连时使用
    const originalAddress = addressRemote;
    const originalPort = portRemote;

    async function connectAndWriteLocal(address: string, port: number, fetcher?: any): Promise<Socket> {
        // if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LnNzbGlwLmlv')}`;
        const tcpSocket = connectSocket({
            hostname: address,
            port: port,
        }, fetcher);

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

    // 获取 proxyMode 与自定义代理标记（hasCustomProxyIPs 由 handlers.ts 写入 wsConfig）
    const { proxyMode, hasCustomProxyIPs } = globalThis.wsConfig as WsConfig & { hasCustomProxyIPs?: boolean };

    // 模式 1: prefix (NAT64) - 仅前端显式选择时使用（原逻辑不变，失败不回退）
    if (proxyMode === 'prefix') {
        try {
            log(`using NAT64 prefix mode for ${originalAddress}:${originalPort}`);
            const { socket: tcpSocket, usedIp } = await connectWithPrefixFallback(originalAddress, originalPort, rawClientData, log, fetcher);
            
            tcpSocket.closed
                .catch(error => console.log('prefix fallback TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));
            
            log(`prefix fallback connected via ${usedIp}:${originalPort}`);
            // 修复：与竞速拨号分支一致，登记 remoteSocket 以便后续数据转发
            remoteSocket.value = tcpSocket;
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
            return;
        } catch (error) {
            log(`prefix fallback failed: ${safeErrorMessage(error)}`);
            console.warn(`Prefix fallback failed: ${error}`);
            // prefix 模式失败直接报错，不回退到其他策略
            webSocket.close(1011, `Prefix fallback failed: ${safeErrorMessage(error)}`);
            return;
        }
    }

    // 直连优先（对齐 cfnew 默认策略）：未配置自定义代理 IP 时，先直连目标
    if (!hasCustomProxyIPs) {
        try {
            log(`attempting direct race dial for ${originalAddress}:${originalPort}`);
            const { socket: tcpSocket, usedIp } = await connectWithDirectRaceDial(originalAddress, originalPort, rawClientData, log, fetcher);
            
            tcpSocket.closed
                .catch(error => console.log('direct race dial TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));
            
            log(`direct race dial connected via ${usedIp}:${originalPort}`);
            // 首包写入已在 connectWithDirectRaceDial 内完成（对齐 cfnew 直连路径：竞速胜出后直接写载荷），
            // 此处只需登记 remoteSocket 供后续数据转发。
            remoteSocket.value = tcpSocket;
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
            return;
        } catch (directError) {
            log(`direct race dial failed: ${safeErrorMessage(directError)}`);
            console.warn(`Direct race dial failed: ${directError}`);
            // 直连失败后继续走代理竞速与直连兜底，不能直接 close
        }
    }

    // 模式 2: proxyip - cfnew 风格竞速拨号（用户显式配置自定义代理 IP 时优先，或直连失败后的回退）
    try {
        log(`attempting race dial for ${originalAddress}:${originalPort}`);
        const { socket: tcpSocket, usedIp } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher);
        
        tcpSocket.closed
            .catch(error => console.log('race dial TCP socket closed error', error))
            .finally(() => safeCloseWebSocket(webSocket));
        
        log(`race dial connected via ${usedIp}:${originalPort}`);
        // 首包写入已在 connectWithRaceDial 内完成（对齐 cfnew 连接值发送直连路径：竞速胜出后直接写载荷），
        // 此处只需登记 remoteSocket 供后续数据转发。
        remoteSocket.value = tcpSocket;
        remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
        return;
    } catch (error) {
        log(`race dial failed: ${safeErrorMessage(error)}`);
        console.warn(`Race dial failed: ${error}`);
        
        // 直连兜底（最后策略）
        try {
            log(`falling back to direct connection for ${originalAddress}:${originalPort}`);
            const tcpSocket = await connectAndWriteLocal(originalAddress, originalPort, fetcher);
            tcpSocket.closed
                .catch(error => console.log('direct TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
        } catch (directError) {
            console.error('Direct connection failed:', directError);
            webSocket.close(1011, `All connection strategies failed: ${safeErrorMessage(directError)}`);
        }
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
