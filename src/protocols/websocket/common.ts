import { resolveDNS, resolveProxyIPPool, filterReachableEntries, parseHostPort, stripRegionTag, DEFAULT_PROXY_IPS } from '@utils';
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
const DIRECT_DIAL_TIMEOUT = 1000; // 直连竞速与兜底直连连接超时（对齐 edgetunnel 连接超时毫秒 = 1000）
const PROXY_DIAL_TIMEOUT = 1000; // 代理竞速连接超时（对齐 edgetunnel 连接超时毫秒 = 1000）
const RACE_DIAL_CONCURRENCY = 3; // 并发拨号数量，参考 cfnew
const RACE_DIAL_MAX_BATCHES = 5; // 最大重试批次

// IP:port 黑名单：连续失败计数 + 指数退避冷却（对齐 edgetunnel 节点黑名单 250-253）
const IP_BLACKLIST_TTL = 30 * 1000;          // 基础冷却 30 秒
const IP_BLACKLIST_BACKOFF = 2;              // 指数退避系数
const IP_BLACKLIST_MAX_TTL = 30 * 60 * 1000; // 最大冷却 30 分钟
const IP_BLACKLIST_MAX_FAIL = 3;             // failCount 封顶，防止长生命周期 isolate 中无界增长
const ipBlacklist = new Map<string, { failCount: number; lastFailAt: number }>();
function blacklistCheck(key: string): boolean {
    const e = ipBlacklist.get(key);
    if (!e) return false;
    // 指数退避：基础 30s × 2^(failCount-1)，上限 30min（对齐 edgetunnel 节点黑名单计算过期时间）
    const ttl = Math.min(IP_BLACKLIST_TTL * Math.pow(IP_BLACKLIST_BACKOFF, e.failCount - 1), IP_BLACKLIST_MAX_TTL);
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

// 代理竞速 IP 级轮询游标：成功候选推进游标（对齐 edgetunnel 缓存反代数组索引 5779/5800）
let proxyIpPoolCursor = 0;

/** cfnew 风格：竞速拨号多个代理 IP，取最快成功的 */
async function connectWithRaceDial(
    targetAddress: string,
    targetPort: number,
    rawClientData: ArrayBuffer | undefined,
    log: Function,
    fetcher?: any
): Promise<{ socket: Socket; usedIp: string }> {
    // 1. 获取配置
    const { panelIPs, envProxyIPs, proxyMode } = globalThis.wsConfig;
    const proxyIPs = panelIPs?.length ? panelIPs : (envProxyIPs ? [envProxyIPs] : DEFAULT_PROXY_IPS);
    
    if (!proxyIPs.length) {
        throw new Error('No proxy IPs available');
    }

    // 如果是 prefix 模式，直接走 NAT64 prefix 路径
    if (proxyMode === 'prefix') {
        return await connectWithPrefixFallback(targetAddress, targetPort, rawClientData, log, fetcher);
    }

    // 2. 构建 IP 池输入：纯 IP/IP:port 直接入池轮询，域名（自动地区/指定地区）解析其 IP 入池
    //    地区匹配已在 handlers.ts 收敛为匹配的 @ 后缀码域名（panelIPs=[selected]），
    //    此处直接全列表作为池输入（对齐 edgetunnel 解析地址端口语义）
    //    每项先 stripRegionTag 去 @REGION 标签（parseHostPort 不识别 @ 后缀）
    const poolInput: string[] = proxyIPs.map(e => stripRegionTag(e));

    const firstClean = stripRegionTag(poolInput[0]);
    const { host: proxyHost } = parseHostPort(firstClean, true);
    const proxyAddr = proxyHost || targetAddress;

    log(`selected proxy IP: ${poolInput[0]} for ${targetAddress}:${targetPort}`);

    // 3. 解析 IP 池（对齐 edgetunnel 解析地址端口 9895-10016）：
    //    逐项分流——IP 字面量直接入池（不 DoH），域名走 DoH 双源解析；
    //    整体排序 + LCG 确定性洗牌 + 取前 8；带缓存
    //    每项携带自身端口（显式端口 / .tpN 端口），无端口条目回退 targetPort（保持既有语义）
    log(`resolving proxy pool via DoH...`);
    const pool = await resolveProxyIPPool(poolInput.join(','), targetAddress, '');
    const poolEntries: [string, number][] = pool.map(([host, port]) => [host, port || targetPort]);

    if (poolEntries.length === 0) {
        throw new Error(`DNS resolution failed for proxy ${proxyAddr}`);
    }

    log(`got ${poolEntries.length} IPs for proxy ${proxyAddr}, probing reachability...`);

    // 4. 并发探测前 8 个条目的可达性（每项用自身端口，BPB 独有，兼容保留）
    const probeEntries = poolEntries.slice(0, 8);
    const reachableEntries = await filterReachableEntries(probeEntries);

    log(`reachable proxy IPs: ${reachableEntries.map(([h, p]) => `${h}:${p}`).join(', ')}`);

    // 对齐 cfnew 取官方直连地址（每次连接随机取一个官方 IP）：
    // 每次连接随机起点，让不同连接从池中不同位置开始竞速拨号，
    // 分散负载到全部候选 IP，避免所有连接从同一游标位置起步；
    // 可达性探测/黑名单/分批兜底逻辑不变
    const raceStartOffset = Math.floor(Math.random() * reachableEntries.length);

    // 6. 分批竞速拨号（IP 级游标轮询，对齐 edgetunnel 5779/5800）
    const dialConcurrency = RACE_DIAL_CONCURRENCY;
    let offset = 0;

    for (let batch = 0; batch < RACE_DIAL_MAX_BATCHES && offset < reachableEntries.length; batch++) {
        // 游标轮询取候选：索引 = (游标 + 随机起点 + 偏移) % 池长度（对齐 edgetunnel 5779 + cfnew 随机起点）
        const poolLen = reachableEntries.length;
        const batchEntries: [string, number][] = [];
        const batchIndexes: number[] = [];
        for (let j = 0; j < dialConcurrency && offset + j < poolLen; j++) {
            const idx = (proxyIpPoolCursor + raceStartOffset + offset + j) % poolLen;
            batchEntries.push(reachableEntries[idx]);
            batchIndexes.push(idx);
        }
        offset += dialConcurrency;

        if (batchEntries.length === 0) continue;

        log(`race dialing batch ${batch + 1}: ${batchEntries.map(([h, p]) => `${h}:${p}`).join(', ')}`);

        // 并发拨号，取最快成功的（黑名单预检跳过已知不通的 IP:port，对齐 edgetunnel 5782-5786）
        const dialPromises = batchEntries.map(async ([ip, entryPort], j) => {
            const cleanIp = ip.replace(/^\[|\]$/g, '');
            const key = `${cleanIp}:${entryPort}`;
            if (blacklistCheck(key)) return { socket: null, ip: cleanIp, port: entryPort, index: batchIndexes[j] };
            const socket = connectSocket({ hostname: cleanIp, port: entryPort }, fetcher);
            // 等待连接建立
            await Promise.race([
                socket.opened,
                new Promise<never>((_, reject) =>
                    setTimeout(() => reject(new Error('timeout')), PROXY_DIAL_TIMEOUT)
                )
            ]);
            return { socket, ip: cleanIp, port: entryPort, index: batchIndexes[j] };
        });

        const results = await Promise.allSettled(dialPromises);

        // 找第一个竞速成功的 socket，直接写载荷（对齐 cfnew 连接值发送直连路径 L4732-4768）：
        // 备用地址（CMLosss 等）是直连中继，竞速拨号建立 TCP 后无需 SOCKS5 握手，
        // 直接通过写入器把剥离 VLESS 头后的载荷写入即可。写入失败视同该候选不通，
        // 继续尝试本批下一个候选。
        for (const result of results) {
            if (result.status !== 'fulfilled' || !result.value || !result.value.socket) continue;
            const { socket, ip, port: entryPort, index } = result.value;
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
                // 成功：清除黑名单 + 游标推进到成功候选（对齐 edgetunnel 5799-5800）
                blacklistClear(`${ip}:${entryPort}`);
                proxyIpPoolCursor = index;
                log(`race dial winner: ${ip}:${entryPort} (proxy: ${proxyAddr})`);
                return { socket, usedIp: ip };
            } catch (writeError) {
                log(`race dial write failed for ${ip}:${entryPort}: ${safeErrorMessage(writeError)}`);
                blacklistRecord(`${ip}:${entryPort}`);
                try { socket.close(); } catch {}
            }
        }

        // 本批次全部失败，记录黑名单并关闭已建立的连接（如果有）
        for (const result of results) {
            if (result.status === 'fulfilled' && result.value && result.value.socket) {
                blacklistRecord(`${result.value.ip}:${result.value.port}`);
                try { result.value.socket.close(); } catch {}
            }
        }
    }

    // 所有批次都失败，抛出错误让上层处理兜底
    throw new Error(`All race dial attempts failed for proxy ${proxyAddr}`);
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
                    setTimeout(() => reject(new Error('timeout')), DIRECT_DIAL_TIMEOUT)
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
            setTimeout(() => reject(new Error(`连接超时 (${address}:${port})`)), DIRECT_DIAL_TIMEOUT)
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

// --- Upstream Proxy (SOCKS5 / HTTP CONNECT) ---
// Aligned with cfnew: 处理值代理连接, 处理值隧道连接, 解析代理配置, 包装残留套接字

interface UpstreamProxyConfig {
    kind: 'socks5' | 'tunnel' | 'secure-tunnel';
    hostname: string;
    port: number;
    username?: string;
    password?: string;
}

/** Parse upstream proxy URL — aligned with cfnew 解析代理配置 (L5686-5731) */
function parseUpstreamProxyConfig(upstreamProxy: string): UpstreamProxyConfig | null {
    if (!upstreamProxy || !upstreamProxy.trim()) return null;
    let addr = upstreamProxy.trim();
    let kind: UpstreamProxyConfig['kind'] = 'socks5';
    const lower = addr.toLowerCase();
    if (lower.startsWith('https://')) {
        kind = 'secure-tunnel';
        addr = addr.slice('https://'.length);
    } else if (lower.startsWith('http://')) {
        kind = 'tunnel';
        addr = addr.slice('http://'.length);
    } else if (lower.startsWith('socks5://')) {
        addr = addr.slice('socks5://'.length);
    } else if (lower.startsWith('socks://')) {
        addr = addr.slice('socks://'.length);
    }
    // Strip trailing path — aligned with cfnew L5703-5704
    const pathIdx = addr.indexOf('/');
    if (pathIdx >= 0) addr = addr.slice(0, pathIdx);
    if (!addr) throw new Error('Invalid SOCKS address format');

    // Parse user:pass@host:port — aligned with cfnew L5706-5711
    let authPart: string | undefined;
    let hostPort: string;
    const atIdx = addr.lastIndexOf('@');
    if (atIdx >= 0) {
        authPart = addr.slice(0, atIdx);
        hostPort = addr.slice(atIdx + 1);
    } else {
        hostPort = addr;
    }

    let username: string | undefined;
    let password: string | undefined;
    if (authPart) {
        const colonIdx = authPart.indexOf(':');
        if (colonIdx < 0) throw new Error('Invalid SOCKS address format');
        username = authPart.slice(0, colonIdx);
        password = authPart.slice(colonIdx + 1);
    }

    // Parse host:port — aligned with cfnew L5713-5724
    const parts = hostPort.split(':');
    const lastPart = parts.pop()!;
    let port = Number(lastPart);
    if (isNaN(port)) {
        // Tunnel allows omitted port — cfnew: secure→443, http→80
        if (kind === 'socks5') throw new Error('Invalid SOCKS address format');
        parts.push(lastPart);
        port = kind === 'secure-tunnel' ? 443 : 80;
    }
    const hostname = parts.join(':');
    if (!hostname) throw new Error('Invalid SOCKS address format');
    // IPv6 without brackets is invalid — cfnew L5724
    if (hostname.includes(':') && !/^\[.*\]$/.test(hostname)) throw new Error('Invalid SOCKS address format');

    return { kind, hostname, port, username, password };
}

/** Strip brackets from IPv6 address for SOCKS5 domain addressing — cfnew 规范化目标地址 L5591-5593 */
function normalizeTargetAddress(addr: string): string {
    const s = String(addr || '');
    return /^\[.*\]$/.test(s) ? s.slice(1, -1) : s;
}

/** Wrap leftover bytes from handshake response back into readable stream head — cfnew 包装残留套接字 L5662-5684 */
function wrapLeftoverSocket(socket: Socket, leftover: Uint8Array): Socket {
    let upstreamReader: ReadableStreamDefaultReader<any> | null = null;
    const newReadable = new ReadableStream({
        start(controller) {
            controller.enqueue(leftover);
            upstreamReader = socket.readable.getReader();
        },
        async pull(controller) {
            const { value, done } = await upstreamReader!.read();
            if (done) { controller.close(); return; }
            controller.enqueue(value);
        },
        cancel(reason) {
            try { upstreamReader?.cancel(reason); } catch {}
        }
    });
    return {
        readable: newReadable,
        writable: socket.writable,
        closed: socket.closed,
        opened: socket.opened,
        close: () => socket.close()
    } as Socket;
}

/** SOCKS5 handshake + CONNECT — aligned with cfnew 处理值代理连接 L5516-5588 */
async function socks5Connect(
    targetAddress: string,
    targetPort: number,
    proxyConfig: UpstreamProxyConfig,
    rawClientData: ArrayBuffer | undefined,
    fetcher?: any
): Promise<Socket> {
    const { username, password, hostname: proxyHost, port: proxyPort } = proxyConfig;

    // Connect to SOCKS5 proxy — aligned with cfnew 处理打开值套接字 L5528
    const socket = connectSocket({ hostname: proxyHost, port: proxyPort }, fetcher);

    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    // Accumulated leftover bytes across reads — aligned with cfnew 残留字节 L5533
    let leftover: Uint8Array<ArrayBuffer> = new Uint8Array(0);

    async function readAtLeast(need: number): Promise<Uint8Array<ArrayBuffer>> {
        while (leftover.length < need) {
            const { value, done } = await reader.read();
            if (done || !value) throw new Error('fail to open socks connection');
            leftover = concatUint8Arrays(leftover, toUint8Array(value)) as Uint8Array<ArrayBuffer>;
        }
        return leftover;
    }

    function take(len: number): Uint8Array<ArrayBuffer> {
        const result = leftover.subarray(0, len);
        leftover = leftover.subarray(len);
        return result;
    }

    // Step 1: Greeting — cfnew L5530
    await writer.write(new Uint8Array(username ? [5, 2, 0, 2] : [5, 1, 0]));

    // Step 2: Method selection response — cfnew L5547-5550
    let response = await readAtLeast(2);
    if (response[0] !== 5 || response[1] === 255) throw new Error('no acceptable methods');
    const selectedMethod = response[1];
    take(2);

    // Step 3: Username/password auth (method 2) — cfnew L5551-5558
    if (selectedMethod === 2) {
        if (!username || !password) throw new Error('socks server needs auth');
        const encoder = new TextEncoder();
        const authRequest = new Uint8Array([
            1, username.length, ...encoder.encode(username),
            password.length, ...encoder.encode(password)
        ]);
        await writer.write(authRequest);
        response = await readAtLeast(2);
        if (response[0] !== 1 || response[1] !== 0) throw new Error('fail to auth socks server');
        take(2);
    }

    // Step 4: CONNECT request — always domain-type (ATYP=3) — cfnew L5560-5565
    // Comment from cfnew: 统一用域名型寻址：交给代理自己解析更稳妥
    const encoder = new TextEncoder();
    const targetBytes = encoder.encode(normalizeTargetAddress(targetAddress));
    await writer.write(new Uint8Array([
        5, 1, 0, 3, targetBytes.length, ...targetBytes,
        targetPort >> 8, targetPort & 255
    ]));

    // Step 5: Read CONNECT response — cfnew L5567-5581
    response = await readAtLeast(4);
    if (response[1] !== 0) throw new Error('fail to open socks connection');
    const bindAddrType = response[3];
    let replyLen: number;
    if (bindAddrType === 1) {
        replyLen = 10; // IPv4: 4 header + 4 addr + 2 port
    } else if (bindAddrType === 4) {
        replyLen = 22; // IPv6: 4 header + 16 addr + 2 port
    } else if (bindAddrType === 3) {
        replyLen = 7 + (await readAtLeast(5))[4]; // Domain: 4 header + 1 len + domain + 2 port
    } else {
        throw new Error('invalid proxy response');
    }
    await readAtLeast(replyLen);
    take(replyLen);

    // Step 6: Write first packet before releasing writer — cfnew L5582-5584
    if (rawClientData && rawClientData.byteLength) await writer.write(rawClientData);
    writer.releaseLock();
    reader.releaseLock();

    // Step 7: Wrap leftover if proxy already sent target data — cfnew L5587
    if (leftover.length) return wrapLeftoverSocket(socket, leftover);
    return socket;
}

/** HTTP/HTTPS CONNECT tunnel — aligned with cfnew 处理值隧道连接 L5595-5659 */
async function httpConnectTunnel(
    targetAddress: string,
    targetPort: number,
    proxyConfig: UpstreamProxyConfig,
    rawClientData: ArrayBuffer | undefined,
    fetcher?: any
): Promise<Socket> {
    const { kind, username, password, hostname: proxyHost, port: proxyPort } = proxyConfig;

    // For HTTPS tunnels, use secureTransport — cfnew L5603-5606
    const connectOpts = kind === 'secure-tunnel' ? { secureTransport: 'on', allowHalfOpen: false } : undefined;
    const target = { hostname: proxyHost, port: proxyPort };

    // Connect to proxy — cfnew L5612
    const socket = (fetcher && typeof fetcher.connect === 'function')
        ? (connectOpts ? fetcher.connect(target, connectOpts) : fetcher.connect(target))
        : (connectOpts ? (globalThis as any).connect(target, connectOpts) : (globalThis as any).connect(target));

    if (socket.opened) await socket.opened;

    // IPv6 targets need brackets in request line — cfnew L5615
    const targetHost = targetAddress.includes(':') && !/^\[.*\]$/.test(targetAddress) ? `[${targetAddress}]` : targetAddress;
    const targetAddr = `${targetHost}:${targetPort}`;

    // Build CONNECT request — cfnew L5617-5621
    let requestText = `CONNECT ${targetAddr} HTTP/1.1\r\n`
        + `Host: ${targetAddr}\r\n`
        + `User-Agent: Mozilla/5.0\r\n`
        + `Proxy-Connection: Keep-Alive\r\n`;
    if (username) {
        requestText += `Proxy-Authorization: Basic ${btoa(`${username}:${password || ''}`)}\r\n`;
    }
    requestText += '\r\n';

    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    try {
        await writer.write(new TextEncoder().encode(requestText));

        // Read until \r\n\r\n — cfnew L5627-5640
        const separator = [13, 10, 13, 10];
        let buffer: Uint8Array<ArrayBuffer> = new Uint8Array(0);
        let headerEnd = -1;
        while (headerEnd < 0) {
            const { value, done } = await reader.read();
            if (done || !value) throw new Error('fail to open proxy tunnel');
            buffer = concatUint8Arrays(buffer, toUint8Array(value)) as Uint8Array<ArrayBuffer>;
            for (let pos = 0; pos + 3 < buffer.length; pos++) {
                if (buffer[pos] === separator[0] && buffer[pos + 1] === separator[1]
                    && buffer[pos + 2] === separator[2] && buffer[pos + 3] === separator[3]) {
                    headerEnd = pos + 4;
                    break;
                }
            }
            if (headerEnd < 0 && buffer.length > 8192) throw new Error('invalid proxy response');
        }

        // Validate status line — cfnew L5642-5645
        const statusLine = new TextDecoder().decode(buffer.subarray(0, Math.min(headerEnd, 128)));
        if (!statusLine.startsWith('HTTP/')) throw new Error('invalid proxy response');
        const statusCode = Number(statusLine.split(' ')[1]);
        if (!(statusCode >= 200 && statusCode < 300)) throw new Error('fail to open proxy tunnel');

        // Leftover data after headers — cfnew L5647
        const leftoverData = buffer.subarray(headerEnd);

        // Write first packet before releasing writer — cfnew L5648-5649
        if (rawClientData && rawClientData.byteLength) await writer.write(rawClientData);
        writer.releaseLock();
        reader.releaseLock();

        // Wrap leftover — cfnew L5652
        if (leftoverData.byteLength) return wrapLeftoverSocket(socket, leftoverData);
        return socket;
    } catch (err) {
        // Clean up on error — cfnew L5654-5658
        try { writer.releaseLock(); } catch {}
        try { reader.releaseLock(); } catch {}
        try { socket.close(); } catch {}
        throw err;
    }
}

/** Connect through upstream SOCKS5/HTTP CONNECT proxy — returns socket or null if no proxy configured */
async function connectThroughUpstreamProxy(
    targetAddress: string,
    targetPort: number,
    rawClientData: ArrayBuffer | undefined,
    fetcher?: any
): Promise<Socket | null> {
    const upstreamProxy = globalThis.settings?.upstreamProxy;
    if (!upstreamProxy) return null;

    let proxyConfig: UpstreamProxyConfig;
    try {
        const parsed = parseUpstreamProxyConfig(upstreamProxy);
        if (!parsed) return null;
        proxyConfig = parsed;
    } catch {
        return null;
    }

    if (proxyConfig.kind === 'socks5') {
        return socks5Connect(targetAddress, targetPort, proxyConfig, rawClientData, fetcher);
    } else {
        return httpConnectTunnel(targetAddress, targetPort, proxyConfig, rawClientData, fetcher);
    }
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
                setTimeout(() => reject(new Error(`连接超时 (${address}:${port})`)), DIRECT_DIAL_TIMEOUT)
            )
        ]);

        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    // Helper: attempt direct race dial → fallback to local direct connect → stream to WS.
    // Used by firstHopProxy retry (broken-proxy failover) and reusable for future paths.
    async function connectDirectAndStream(): Promise<void> {
        // Try direct race dial first
        try {
            log(`retry-direct: attempting direct race dial for ${originalAddress}:${originalPort}`);
            const { socket: tcpSocket, usedIp } = await connectWithDirectRaceDial(originalAddress, originalPort, rawClientData, log, fetcher);

            tcpSocket.closed
                .catch(error => console.log('retry-direct race dial TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));

            log(`retry-direct race dial connected via ${usedIp}:${originalPort}`);
            remoteSocket.value = tcpSocket;
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
            return;
        } catch (directError) {
            log(`retry-direct race dial failed: ${safeErrorMessage(directError)}`);
        }

        // Final fallback: local direct connect
        try {
            log(`retry-direct: falling back to direct connection for ${originalAddress}:${originalPort}`);
            const tcpSocket = await connectAndWriteLocal(originalAddress, originalPort, fetcher);
            tcpSocket.closed
                .catch(error => console.log('retry-direct TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
        } catch (directError) {
            console.error('retry-direct: All direct connection strategies failed:', directError);
            webSocket.close(1011, `Retry direct connection failed: ${safeErrorMessage(directError)}`);
        }
    }

    // 获取 proxyMode 与首跳决策配置（对齐 cfnew 处理值值384 首跳决策）
    const { proxyMode, proxyOnly, proxyDegrade, hasCustomProxyIPs } = globalThis.wsConfig as WsConfig;

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

    // Upstream proxy (SOCKS5/HTTP CONNECT) — primary strategy when configured
    // Falls through to existing fallback chain (firstHopProxy → direct → proxy race → direct fallback) on failure
    if (globalThis.settings?.upstreamProxy) {
        try {
            log(`upstream-proxy: attempting SOCKS5/HTTP CONNECT for ${originalAddress}:${originalPort}`);
            const upstreamSocket = await connectThroughUpstreamProxy(originalAddress, originalPort, rawClientData, fetcher);
            if (upstreamSocket) {
                upstreamSocket.closed
                    .catch(error => console.log('upstream-proxy TCP socket closed error', error))
                    .finally(() => safeCloseWebSocket(webSocket));

                log(`upstream-proxy connected to ${originalAddress}:${originalPort}`);
                remoteSocket.value = upstreamSocket;
                remoteSocketToWS(upstreamSocket, webSocket, VLResponseHeader, null, log);
                return;
            }
        } catch (upstreamError) {
            log(`upstream-proxy failed: ${safeErrorMessage(upstreamError)}`);
            console.warn(`Upstream proxy failed: ${upstreamError}`);
            // Fall through to existing fallback chain
        }
    }

    // 对齐 cfnew 首跳决策（处理值值384 L4873）：
    //   首跳走代理 = 仅走代理 && 代理已启用 ? true : 代理降级 ? false : 代理已启用
    // 对齐 cfnew 的"直连"语义（处理值套接字 调用 配置.connect(目标)）：
    //   首跳连接的目标 = 代理 IP（p，指定地区解析出的代理 IP 池），通过 Worker 地区 IP 连接 p，p 再转发到真正目标。
    //   对应 BPB 的 connectWithRaceDial（连接 panelIPs 代理 IP 池）。
    //   因此 firstHopProxy 由 p（hasCustomProxyIPs）决定：配置 p → 首跳走 connectWithRaceDial（通过代理 IP）。
    // 仅走代理（proxyOnly）→ 必走代理，失败即关闭（防 IP 泄漏，不回退直连）
    // 代理降级（proxyDegrade）→ 直连优先，代理作为回退
    // 默认 → 有自定义代理 IP（前端指定地区）时代理优先，直连回退；无代理则直连优先
    const hasProxyIPs = hasCustomProxyIPs === true;
    const firstHopProxy = proxyOnly && hasProxyIPs ? true : proxyDegrade ? false : hasProxyIPs;

    // 首跳走代理：代理竞速拨号优先（对齐 cfnew 连接值发送 值代理=true 路径）
    if (firstHopProxy) {
        try {
            log(`proxy-first: attempting proxy race dial for ${originalAddress}:${originalPort}`);
            const { socket: tcpSocket, usedIp } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher);
            
            tcpSocket.closed
                .catch(error => console.log('proxy race dial TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));
            
            log(`proxy race dial connected via ${usedIp}:${originalPort}`);
            // 首包写入已在 connectWithRaceDial 内完成（对齐 cfnew 连接值发送直连路径：竞速胜出后直接写载荷），
            // 此处只需登记 remoteSocket 供后续数据转发。
            remoteSocket.value = tcpSocket;
            // Pass retry to enable FIRST_BYTE_TIMEOUT: if proxy is reachable but broken
            // (TCP connects but no data forwarded), retry fires and falls back to direct connection.
            // Guarded by local flag + remoteSocketToWS's hasRetryFired to prevent double-fire.
            let proxyRetryFired = false;
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, () => {
                if (proxyRetryFired) return;
                proxyRetryFired = true;
                log(`proxy-first: no data within FIRST_BYTE_TIMEOUT, closing broken proxy socket and falling back to direct`);
                try { tcpSocket.close?.(); } catch {}
                connectDirectAndStream();
            }, log);
            return;
        } catch (proxyError) {
            log(`proxy race dial failed: ${safeErrorMessage(proxyError)}`);
            console.warn(`Proxy race dial failed: ${proxyError}`);
            // 仅走代理模式：失败即关闭，不回退直连（防 IP 泄漏，对齐 cfnew 处理重试连接 L4816-4819）
            if (proxyOnly) {
                webSocket.close(1011, `Proxy-only mode failed: ${safeErrorMessage(proxyError)}`);
                return;
            }
            // 默认模式（有代理）：代理失败后回退直连竞速与兜底直连
        }
    }

    // 直连优先（对齐 edgetunnel 默认策略 / cfnew 代理降级首跳）：直连竞速拨号
    try {
        log(`attempting direct race dial for ${originalAddress}:${originalPort}`);
        const { socket: tcpSocket, usedIp } = await connectWithDirectRaceDial(originalAddress, originalPort, rawClientData, log, fetcher);
        
        tcpSocket.closed
            .catch(error => console.log('direct race dial TCP socket closed error', error))
            .finally(() => safeCloseWebSocket(webSocket));
        
        log(`direct race dial connected via ${usedIp}:${originalPort}`);
        // 首包写入已在 connectWithDirectRaceDial 内完成（对齐 edgetunnel 直连路径：竞速胜出后直接写载荷），
        // 此处只需登记 remoteSocket 供后续数据转发。
        remoteSocket.value = tcpSocket;
        remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
        return;
    } catch (directError) {
        log(`direct race dial failed: ${safeErrorMessage(directError)}`);
        console.warn(`Direct race dial failed: ${directError}`);
        // 直连失败后继续走代理竞速与直连兜底，不能直接 close
    }

    // 代理竞速回退（cfnew 风格竞速拨号）：直连失败后，或默认模式代理首跳失败后的回退
    try {
        log(`attempting proxy race dial fallback for ${originalAddress}:${originalPort}`);
        const { socket: tcpSocket, usedIp } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher);
        
        tcpSocket.closed
            .catch(error => console.log('proxy race dial fallback TCP socket closed error', error))
            .finally(() => safeCloseWebSocket(webSocket));
        
        log(`proxy race dial fallback connected via ${usedIp}:${originalPort}`);
        // 首包写入已在 connectWithRaceDial 内完成（对齐 cfnew 连接值发送直连路径：竞速胜出后直接写载荷），
        // 此处只需登记 remoteSocket 供后续数据转发。
        remoteSocket.value = tcpSocket;
        remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
        return;
    } catch (error) {
        log(`proxy race dial fallback failed: ${safeErrorMessage(error)}`);
        console.warn(`Proxy race dial fallback failed: ${error}`);
        
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

// --- Download batcher constants (aligned with cfnew 传输下载包大小/尾部/延迟/块大小) ---
const DOWNLOAD_PACKET_SIZE = 32 * 1024;  // 传输下载包大小：批量缓冲满阈值
const DOWNLOAD_TAIL = 512;                // 传输下载尾部：剩余空间阈值触发刷新
const DOWNLOAD_DELAY = 0;                 // 传输下载延迟：0ms（用 queueMicrotask 刷新）
const DOWNLOAD_BLOCK_SIZE = 64 * 1024;    // 传输块大小：BYOB reader 复用缓冲
const FIRST_BYTE_TIMEOUT = 2000;          // 首字节超时 ms（触发 retry 降级）

// --- Uint8Array helpers (aligned with cfnew 处理值值8数组 / 拼接值8数组) ---
function toUint8Array(data: ArrayBufferView | ArrayBuffer | Uint8Array): Uint8Array {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(data);
}

function concatUint8Arrays(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.byteLength + b.byteLength);
    out.set(a);
    out.set(b, a.byteLength);
    return out;
}

// --- cfnew-style download batcher (aligned with cfnew 创建值值 L5013-5078) ---
// Batches small TCP chunks into larger WebSocket frames for better throughput.
function createDownloadBatcher(webSocket: WebSocket) {
    const PACKET_SIZE = DOWNLOAD_PACKET_SIZE;   // 32KB
    const TAIL = DOWNLOAD_TAIL;                 // 512
    const LOW_WATER = Math.max(4096, TAIL << 3); // 4096
    let buffer = new Uint8Array(PACKET_SIZE);
    let buffered = 0;
    let timer: ReturnType<typeof setTimeout> | 0 = 0;
    let scheduled = false;
    let writeCount = 0;
    let lastWriteCount = 0;
    let retryCount = 0;

    function flush() {
        if (timer) { clearTimeout(timer); timer = 0; }
        scheduled = false;
        if (!buffered) return;
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
            webSocket.send(buffer.subarray(0, buffered).slice());
        }
        buffer = new Uint8Array(PACKET_SIZE);
        buffered = 0;
        retryCount = 0;
    }

    function schedule() {
        if (timer || scheduled) return;
        scheduled = true;
        lastWriteCount = writeCount;
        queueMicrotask(() => {
            scheduled = false;
            if (!buffered || timer) return;
            if (PACKET_SIZE - buffered < TAIL) return flush();
            timer = setTimeout(() => {
                timer = 0;
                if (!buffered) return;
                if (PACKET_SIZE - buffered < TAIL) return flush();
                // Adaptive: allow up to 2 retries if data is still trickling in
                if (retryCount < 2 && (writeCount !== lastWriteCount || buffered < LOW_WATER)) {
                    retryCount++;
                    lastWriteCount = writeCount;
                    return schedule();
                }
                flush();
            }, Math.max(DOWNLOAD_DELAY, 1));
        });
    }

    return {
        send(chunk: Uint8Array) {
            const data = toUint8Array(chunk);
            let offset = 0;
            const total = data.byteLength;
            if (!total) return;
            while (offset < total) {
                // If buffer is empty and remaining data >= PACKET_SIZE, send directly (no copy)
                if (!buffered && total - offset >= PACKET_SIZE) {
                    const size = Math.min(PACKET_SIZE, total - offset);
                    if (webSocket.readyState === WS_READY_STATE_OPEN) {
                        webSocket.send(offset || size !== total ? data.subarray(offset, offset + size) : data);
                    }
                    offset += size;
                    continue;
                }
                // Copy into buffer
                const size = Math.min(PACKET_SIZE - buffered, total - offset);
                buffer.set(data.subarray(offset, offset + size), buffered);
                buffered += size;
                offset += size;
                writeCount++;
                if (buffered === PACKET_SIZE || PACKET_SIZE - buffered < TAIL) {
                    flush();
                } else {
                    schedule();
                }
            }
        },
        flush,
    };
}

// --- Rewritten remoteSocketToWS with BYOB reader + download batching ---
// (aligned with cfnew 连接值279 L5256-5331)
async function remoteSocketToWS(
    remoteSocket: Socket,
    webSocket: WebSocket,
    VLResponseHeader: Uint8Array<ArrayBuffer> | null,
    retry: Function | null,
    log: Function
) {
    let vlHeader = VLResponseHeader;
    let hasIncomingData = false;
    let hasRetryFired = false;

    // First-byte timeout: if no data arrives, fire retry (SOCKS5 fallback)
    let firstByteTimer: ReturnType<typeof setTimeout> | null = null;
    if (retry) {
        firstByteTimer = setTimeout(() => {
            if (!hasIncomingData && !hasRetryFired) {
                hasRetryFired = true;
                try { remoteSocket.close?.(); } catch {}
                retry();
            }
        }, FIRST_BYTE_TIMEOUT);
    }

    const batcher = createDownloadBatcher(webSocket);
    let reader: ReadableStreamDefaultReader<any> | null = null;
    let isByob = true;
    let byobBuffer = new ArrayBuffer(DOWNLOAD_BLOCK_SIZE);

    try {
        // Try BYOB reader first (zero-copy, reusable buffer)
        try {
            reader = (remoteSocket.readable as any).getReader({ mode: 'byob' });
        } catch {
            isByob = false;
            reader = remoteSocket.readable.getReader();
        }

        for (;;) {
            const result = isByob
                ? await (reader as any).read(new Uint8Array(byobBuffer, 0, DOWNLOAD_BLOCK_SIZE))
                : await reader!.read();
            if (result.done) break;
            const readValue = result.value;
            let chunk = toUint8Array(readValue);
            if (!chunk.byteLength) continue;

            // Cancel first-byte retry timer on first real data
            if (!hasIncomingData) {
                hasIncomingData = true;
                if (firstByteTimer) { clearTimeout(firstByteTimer); firstByteTimer = null; }
            }

            if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                throw new Error('webSocket.readyState is not open, maybe close');
            }

            // Prepend VLResponseHeader on first chunk (Uint8Array concat, NOT slow Blob)
            if (vlHeader) {
                chunk = concatUint8Arrays(vlHeader, chunk);
                vlHeader = null;
            }

            // Large chunk (>= 32KB): flush batcher + send directly
            if (chunk.byteLength >= DOWNLOAD_BLOCK_SIZE >> 1) {
                batcher.flush();
                webSocket.send(chunk);
                if (isByob) byobBuffer = new ArrayBuffer(DOWNLOAD_BLOCK_SIZE);
            } else {
                // Small chunk: go through batcher for frame coalescing
                batcher.send(chunk.slice());
                if (isByob) {
                    // Track BYOB buffer reuse: if read filled the full block, buffer is safe to reuse
                    byobBuffer = readValue?.buffer instanceof ArrayBuffer && readValue.buffer.byteLength >= DOWNLOAD_BLOCK_SIZE
                        ? readValue.buffer
                        : new ArrayBuffer(DOWNLOAD_BLOCK_SIZE);
                }
            }
        }

        batcher.flush();
    } catch (error) {
        // Don't close WS if retry is about to re-mount a new socket
        if (!hasRetryFired) safeCloseWebSocket(webSocket);
    } finally {
        try { batcher.flush(); } catch {}
        try { reader?.releaseLock(); } catch {}
    }

    if (firstByteTimer) { clearTimeout(firstByteTimer); firstByteTimer = null; }
    if (!hasIncomingData && !hasRetryFired && retry) {
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
