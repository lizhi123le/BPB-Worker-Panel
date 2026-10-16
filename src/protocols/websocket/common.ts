import { resolveDNS, resolveProxyIPPool, filterReachableEntries, parseHostPort, stripRegionTag, DEFAULT_PROXY_IPS, resolveTargetDNS, isCloudflareTarget, ipv6ToBytes } from '@utils';
import { evictOldest, safeErrorMessage, randomUserAgent } from '@common';

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
const DIRECT_DIAL_TIMEOUT = 5000; // 直连竞速与兜底直连连接超时（对齐 cfnew 连接超时值 = 5000）
const PROXY_DIAL_TIMEOUT = 5000; // 代理竞速连接超时（对齐 cfnew 连接超时值 = 5000）
const RACE_DIAL_CONCURRENCY = 3; // 并发拨号数量，参考 cfnew
const RACE_DIAL_MAX_BATCHES = 5; // 最大重试批次
const RACE_PROBE_COUNT = 8; // 每连接从缓存池抽取参与 2 秒可达性探测的候选数（抽取在探测前、按黑名单过滤后进行）

// IP:port 黑名单：连续失败计数 + 指数退避冷却（对齐 edgetunnel 节点黑名单 250-253）
const IP_BLACKLIST_TTL = 30 * 1000;          // 基础冷却 30 秒
const IP_BLACKLIST_BACKOFF = 2;              // 指数退避系数
const IP_BLACKLIST_MAX_TTL = 30 * 60 * 1000; // 最大冷却 30 分钟
const IP_BLACKLIST_MAX_FAIL = 3;             // failCount 封顶，防止长生命周期 isolate 中无界增长
const IP_BLACKLIST_MAX_ENTRIES = 512;        // 键数量上限：只封顶单条大小不封顶键数，长期 isolate 内 Map 仍会无界增长
const ipBlacklist = new Map<string, { failCount: number; lastFailAt: number }>();

/** 条目冷却时长：指数退避 基础 30s × 2^(failCount-1)，上限 30min（对齐 edgetunnel 节点黑名单计算过期时间） */
function blacklistTtl(e: { failCount: number }): number {
    return Math.min(IP_BLACKLIST_TTL * Math.pow(IP_BLACKLIST_BACKOFF, e.failCount - 1), IP_BLACKLIST_MAX_TTL);
}

/** 清扫已过期条目（F-10）：未被再次查询的键也必须回收，原实现只在同键再次查询且已过期时删除 */
function blacklistSweep(): void {
    const now = Date.now();
    for (const [key, e] of ipBlacklist) {
        if (now - e.lastFailAt > blacklistTtl(e)) ipBlacklist.delete(key);
    }
}

function blacklistCheck(key: string): boolean {
    const e = ipBlacklist.get(key);
    if (!e) return false;
    if (Date.now() - e.lastFailAt > blacklistTtl(e)) {
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
    // F-10 容量兜底：超上限时先清扫过期条目，仍超上限则按 Map 插入序淘汰最旧键
    if (ipBlacklist.size > IP_BLACKLIST_MAX_ENTRIES) {
        blacklistSweep();
        evictOldest(ipBlacklist, IP_BLACKLIST_MAX_ENTRIES);
    }
}
function blacklistClear(key: string) { ipBlacklist.delete(key); }

/** 黑名单键的唯一口径：IPv6 去方括号 + `:port`。
 *  抽取过滤、拨号前预检、成功清除、失败记账四处必须同键，否则退避形同虚设。 */
function blacklistKey(host: string, port: number): string {
    return `${host.replace(/^\[|\]$/g, '')}:${port}`;
}

/** Fisher-Yates 洗牌后取前 n 条（不改动入参）。
 *  反代池每连接随机抽取候选，让池里**全部**解析结果都有机会被用到；
 *  被临时拉黑的候选已在抽取前过滤，退避到期后自然回到抽取集合。 */
function shuffleTake<T>(items: T[], n: number): T[] {
    const copy = [...items];
    for (let i = copy.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        const tmp = copy[i];
        copy[i] = copy[j];
        copy[j] = tmp;
    }
    return copy.slice(0, n);
}

// 代理竞速 IP 级轮询游标：成功候选推进游标（对齐 edgetunnel 缓存反代数组索引 5779/5800）
let proxyIpPoolCursor = 0;

/** cfnew 风格：竞速拨号多个代理 IP，取最快成功的 */
async function connectWithRaceDial(
    targetAddress: string,
    targetPort: number,
    rawClientData: ArrayBuffer | undefined,
    log: Function,
    fetcher?: any,
    poolOverride?: string[]
): Promise<{ socket: Socket; usedIp: string }> {
    // 1. 获取配置
    //    poolOverride 供「CF 内置 IP 池」层使用：显式指定官方直连池，
    //    不读 panelIPs —— 指定地区模式下 panelIPs 是反代池，不是官方池。
    const { panelIPs, envProxyIPs, proxyMode } = globalThis.wsConfig;
    const proxyIPs = poolOverride?.length
        ? poolOverride
        : (panelIPs?.length ? panelIPs : (envProxyIPs ? [envProxyIPs] : DEFAULT_PROXY_IPS));
    
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
    //    整体排序 + LCG 确定性洗牌 + 带缓存的**全量**入池（解析出多少就存多少，不截断）；
    //    「按黑名单过滤后随机抽 8 条去探测/竞速」在下方第 4/5 步做
    //    每项携带自身端口（显式端口 / .tpN 端口），无端口条目回退 targetPort（保持既有语义）
    log(`resolving proxy pool via DoH...`);
    const pool = await resolveProxyIPPool(poolInput.join(','), targetAddress, '');
    const poolEntries: [string, number][] = pool.map(([host, port]) => [host, port || targetPort]);

    if (poolEntries.length === 0) {
        throw new Error(`DNS resolution failed for proxy ${proxyAddr}`);
    }

    // 4. 抽取阶段先按临时黑名单过滤：退避中的候选（指数退避 30/60/120s）暂时从缓存池隐退，
    //    把本连接的槽位让给可用候选；退避到期由 blacklistCheck 自动删除条目、重新参与抽取。
    const usableEntries = poolEntries.filter(([host, port]) => !blacklistCheck(blacklistKey(host, port)));
    // 全池都在退避中（例如整池刚集体抖动）：此刻不再相信黑名单，本次照拨 ——
    // 与 filterReachableEntries「全部不通则回退原始列表」同一取向，连通性优先，避免一次集体误判把池锁死。
    const blacklistBypass = usableEntries.length === 0;
    const drawSource = blacklistBypass ? poolEntries : usableEntries;

    // 洗牌抽 8 条参与探测：池内（本次可用的）全部候选都有机会被用到，
    // 不再由解析期的 slice(0,8) 把其余候选结构性丢弃、锁死 10 分钟。
    const probeEntries = shuffleTake(drawSource, RACE_PROBE_COUNT);

    log(`got ${poolEntries.length} IPs for proxy ${proxyAddr}, drawing ${probeEntries.length} (${poolEntries.length - drawSource.length} in backoff), probing reachability...`);

    // 5. 并发探测（每项用自身端口）—— 探测不通的记一次失败进临时黑名单，不再每连接为死候选白等 2 秒
    const probeFailed: [string, number][] = [];
    const reachableEntries = await filterReachableEntries(probeEntries, (entry, ok) => {
        if (!ok) probeFailed.push(entry);
    });

    // 例外：本批抽取的候选**全部**探测不通 —— 这正是「2 秒探测超时、5 秒拨号仍可能连上」的边界情形，
    // filterReachableEntries 会把它们原样返回继续拨号，所以此时不记退避，免得一次集体抖动就把整池锁进黑名单
    //（真不通的候选会在拨号超时/写首包失败时按既有逻辑记账）。
    const allProbeFailed = probeEntries.length > 0 && probeFailed.length === probeEntries.length;
    if (!blacklistBypass && !allProbeFailed) {
        for (const [host, port] of probeFailed) blacklistRecord(blacklistKey(host, port));
    }

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
            const key = blacklistKey(cleanIp, entryPort);
            // 抽取阶段已按黑名单过滤过；这里只兜住「抽取 → 拨号」之间被并发连接新拉黑的键。
            // blacklistBypass（全池退避中）时不跳过，保证最后兜底仍真的会拨号。
            if (!blacklistBypass && blacklistCheck(key)) return { socket: null, ip: cleanIp, port: entryPort, index: batchIndexes[j] };
            const socket = connectSocket({ hostname: cleanIp, port: entryPort }, fetcher);
            // 等待连接建立
            try {
                await Promise.race([
                    socket.opened,
                    new Promise<never>((_, reject) =>
                        setTimeout(() => reject(new Error('timeout')), PROXY_DIAL_TIMEOUT)
                    )
                ]);
            } catch (dialError) {
                // F-09：超时/reject 分支创建的 socket 同样要回收。allSettled 的 rejected 分支不再携带
                // socket，若不在此关闭，每次竞速失败都会残留 2-3 条半开连接。
                try { socket.close(); } catch {}
                throw dialError;
            }
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
                blacklistClear(blacklistKey(ip, entryPort));
                proxyIpPoolCursor = index;
                log(`race dial winner: ${ip}:${entryPort} (proxy: ${proxyAddr})`);
                return { socket, usedIp: ip };
            } catch (writeError) {
                log(`race dial write failed for ${ip}:${entryPort}: ${safeErrorMessage(writeError)}`);
                blacklistRecord(blacklistKey(ip, entryPort));
                try { socket.close(); } catch {}
            }
        }

        // 走到这里说明本批没有一个候选写成功：每个 fulfilled 的候选都已在上面那个 write 失败的 catch 分支里
        // 记过黑名单并关过 socket。原先这里再来一遍"本批次全部失败"循环，会把同一键的失败数**再加一次**
        // （IP_BLACKLIST_MAX_FAIL=3 时两批就拉黑），属重复记账，已删除 —— 封禁节奏回到阈值本身。
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
        // 与出站模式的目标分类共用同一份解析缓存（A + AAAA），同一域名不再重复 DoH。
        // ★ IPv6 修复一（对齐 cfnew「解析域名获取IP池」L167-220 / L184 `[${data}]`）：原实现只取
        //   ipv4 而**丢掉 AAAA**，于是「只发布 AAAA 记录」的目标解析出的池恒为空，本函数在
        //   **一个候选都没拨号**的情况下就抛 'DNS resolution failed for direct target'
        //   （已由 tmp/verify-ipv6-dial/run.ts 固定在改前源码上：拨号记录为空 + 抛错）。
        //   而 test-ipv6.com 判「有没有 IPv6」只认这类域名 —— 其官方 FAQ：测试是客户端 JS 向
        //   「force the use of IPv6 only」的 DNS 名字发 ajax，且**耗时也参与判定**；实测
        //   ipv6. / v6. / mtu1280. / aaaa.test-ipv6.com 均只有 AAAA、无 A
        //   （test-ipv6.com 主站则是 A=4、无 AAAA，官方说明是刻意的）。
        //   顺序：IPv4 在前（保持既有「v4 优先」语义与故障域，双栈目标行为不变），IPv6 追加在后，
        //   以方括号形式承载 —— 与 resolveProxyIPPool 的 `[${data}]` 口径一致：黑名单键
        //   `${ip}:${port}` 不会与 IPv4 混淆，拨号前统一由 `ip.replace(/^\[|\]$/g, '')` 去括号。
        //
        // ★ IPv6 修复二（对齐 edgetunnel 直连路径的关键做法）：候选里**始终附上未解析的原始目标
        //   域名**，由 Workers 运行时自己去做 A + AAAA 解析与连接。edgetunnel 就是这么干的 ——
        //   它的候选列表放的是原始地址而非 IP 字面量（`构建预加载竞速候选列表` L5752-5754 与
        //   `connectDirect` L5769 都返回 `{ hostname: address, port }`），所以它从来不存在
        //   「预先解析漏掉 AAAA」这个问题。只把 AAAA 放进 IP 池仍不够稳：
        //     ① 我们自己那一路 DoH（cloudflare-dns.com / dns.google）抖动或被墙时，池里就没有 AAAA；
        //     ② 万一「按 IP 字面量拨号」这条路存在运行时限制，纯 v6 目标依旧连不上，
        //        于是又掉进回退阶梯，被只承载 Cloudflare 目标的反代池 / 官方池把首包（**不含目标
        //        地址**）投给不匹配的对端 —— 那种错投在浏览器侧正表现为 TLS 握手失败
        //        （如 ERR_SSL_VERSION_OR_CIPHER_MISMATCH）。域名候选让直连恒有第三条腿，不必再兜底。
        //   窗口保证：候选窗口只有 RACE_DIAL_MAX_BATCHES × DIRECT_RACE_CONCURRENCY 个，故把 IP 部分
        //   截到「窗口 - 1」，域名恒定占据窗口内最后一个位置，任何情况下都一定会被尝试到。
        const { ipv4, ipv6 } = await resolveTargetDNS(targetAddress);
        const window = RACE_DIAL_MAX_BATCHES * DIRECT_RACE_CONCURRENCY;
        const ipCandidates = [...ipv4, ...ipv6.map(ip => `[${ip}]`)].slice(0, Math.max(1, window - 1));
        // cfnew 同款兜底（cfnew L213 `if (已去重.length === 0) return [域名]`）：A / AAAA 一条都没
        // 解析出来时也要有一个可拨候选。非空地址才附域名，空地址维持下面原有的抛错。
        pool = targetAddress ? [...ipCandidates, targetAddress] : ipCandidates;
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
            const key = blacklistKey(ip, targetPort);
            if (blacklistCheck(key)) continue; // 黑名单预检，不计 failCount
            batchCandidates.push({ hostname: ip.replace(/^\[|\]$/g, ''), port: targetPort, key, index: realIndex });
        }
        if (batchCandidates.length === 0) continue;
        attemptedBatches++;

        log(`direct race dialing batch ${attemptedBatches}: ${batchCandidates.map(c => c.key).join(', ')}`);

        // 并发拨号，取最快成功的（对齐 cfnew 并发连接候选 Promise.any）
        const dialPromises = batchCandidates.map(async (candidate) => {
            const socket = connectSocket({ hostname: candidate.hostname, port: candidate.port }, fetcher);
            try {
                await Promise.race([
                    socket.opened,
                    new Promise<never>((_, reject) =>
                        setTimeout(() => reject(new Error('timeout')), DIRECT_DIAL_TIMEOUT)
                    )
                ]);
            } catch (dialError) {
                // F-09：Promise.any 只处理 fulfilled 的败者，reject 分支的 socket 必须在这里就地回收
                try { socket.close(); } catch {}
                throw dialError;
            }
            return { socket, candidate };
        });

        try {
            const { socket, candidate } = await Promise.any(dialPromises);
            // 写入首包载荷（对齐 cfnew L4759: if (值数据.byteLength) await 写入器.write(值数据)）
            const writer = socket.writable.getWriter();
            if (rawClientData && rawClientData.byteLength) {
                await writer.write(rawClientData);
            }
            writer.releaseLock();

            // 关闭其余候选 socket（对齐 cfnew 并发连接候选关闭败者）
            for (const p of dialPromises) {
                p.then(({ socket: otherSocket }) => {
                    if (otherSocket !== socket) {
                        try { otherSocket.close(); } catch {}
                    }
                }).catch(() => {});
            }

            blacklistClear(candidate.key);
            directPoolRoundRobin = candidate.index;
            log(`direct race dial winner: ${candidate.key}`);
            return { socket, usedIp: candidate.hostname };
        } catch (batchError) {
            // 本批全部失败 → 记录黑名单（对齐 cfnew L4763）
            for (const candidate of batchCandidates) {
                blacklistRecord(candidate.key);
            }
        }
    }

    // 6. 全部失败：抛出错误，由上层走代理路径/兜底直连
    throw new Error(`All direct race dial attempts failed for ${targetAddress}:${targetPort}`);
}

/** 工具函数：模块级，供 connectWithPrefixFallback 等使用 */
const getRandomValue = (arr: string[]) => arr[Math.floor(Math.random() * arr.length)];
const parseIPs = (value: string) => value ? value.split(',').map(val => val.trim()).filter(Boolean) : undefined;

/**
 * 拨号 + 写首包的共用实现：模块级调用方与 handleWebsocket 内的 connectAndWriteLocal 共用这一份。
 * hooks 的回调时机是语义的一部分，不能挪：
 *  - onSocket：connectSocket 之后、`await opened` **之前**。本地版靠它把 socket 登记进 remoteSocket.value，
 *    必须早于等待 —— 否则超时/失败时 teardown 关不到这条半开连接（F-09 同一约束）。
 *  - onOpened：连接建立之后、取 writer **之前**。本地版在这里打「connected to」日志，保持既有日志顺序。
 */
async function dialAndWrite(
    address: string,
    port: number,
    rawClientData: ArrayBuffer | undefined,
    fetcher?: any,
    hooks?: { onSocket?: (socket: Socket) => void; onOpened?: () => void }
): Promise<Socket> {
    // if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LnNzbGlwLmlv')}`;
    const tcpSocket = connectSocket({
        hostname: address,
        port: port,
    }, fetcher);

    hooks?.onSocket?.(tcpSocket);

    // 连接超时保护：防止连到不通的 IP 时卡死
    await Promise.race([
        tcpSocket.opened,
        new Promise<void>((_, reject) =>
            setTimeout(() => reject(new Error(`连接超时 (${address}:${port})`)), DIRECT_DIAL_TIMEOUT)
        )
    ]);

    hooks?.onOpened?.();

    // log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    // F-19：rawClientData 可能为 undefined（首包剥离后无残余载荷），直接 write(undefined) 会抛 TypeError
    if (rawClientData && rawClientData.byteLength) await writer.write(rawClientData);
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
    
    // 解析目标 IPv4。正常路径**逐字沿用** resolveDNS(targetAddress, true)：只查 A、不碰 AAAA、
    // 不吃 resolveTargetDNS 的 10 分钟缓存 —— 即「有 A 记录的目标」在 prefix 模式下与改动前完全一致
    // （含 IP 轮换的时效性，不会被缓存拖成 10 分钟前的地址）。NAT64 本身也只对 IPv4 目标成立。
    const { ipv4 } = await resolveDNS(targetAddress, true);
    if (!ipv4.length) {
        // ★ IPv6 修复（与 connectWithDirectRaceDial 同一类缺陷）：NAT64 只能把 **IPv4** 映射进前缀，
        //   对「只发布 AAAA 记录」的目标（test-ipv6.com 的 ipv6. / v6. / mtu1280. / aaaa.test-ipv6.com
        //   —— 该站判「有没有 IPv6」正是靠这些纯 v6 域名）以及 IPv6 字面量目标，压根没有可映射的 IPv4。
        //   原实现一律抛 'Unable to find IPv4 in DNS records for prefix fallback'，而 prefix 模式
        //   「失败不回退」（调用点直接 close 1011），于是这类目标在 prefix 模式下 100% 不可达 ——
        //   尽管它本来就是 IPv6 可达的。此时本就不需要 NAT64：把原始目标交给运行时解析器直连即可。
        //
        //   但必须区分两种「没有 IPv4」：resolveDNS 在任何 DoH 故障下都返回空数组
        //   （dualSourceResolve 用 allSettled 把所有拒绝吞成 []），那是「解析不出来」而不是
        //   「目标没有 IPv4」。若无条件改走直连，一次 DNS 抖动就会让**双栈目标**静默绕过用户
        //   显式选择的 NAT64 出口（本模式的契约恰恰是失败不回退，防的就是这种绕过）。故只有在
        //   没有 A 记录时**额外**查一次 A + AAAA 取证，拿到「目标确实是 IPv6 目标」的证据
        //   （IPv6 字面量，或确实解析出了 AAAA）才直连；证据不足时保持原有 fail-closed 抛错，
        //   行为与改动前一致。取证只在「本来就要失败」的这条分支上发生，不影响任何正常路径。
        const isV6Literal = isIPLiteral(targetAddress) && targetAddress.includes(':');
        const hasV6Record = isV6Literal ? true : (await resolveTargetDNS(targetAddress)).ipv6.length > 0;
        if (hasV6Record) {
            log(`no IPv4 record for ${targetAddress}; dialing target directly (NAT64 mapping not applicable)`);
            const directSocket = await dialAndWrite(targetAddress, targetPort, rawClientData, fetcher);
            return { socket: directSocket, usedIp: targetAddress };
        }
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
    
    const tcpSocket = await dialAndWrite(nat64IP, targetPort, rawClientData, fetcher);
    
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
        // F-20：SOCKS5 认证长度字段是 UTF-8 字节数，非 ASCII 账号/口令用 .length（字符数）会少算 → 认证报文非法
        const usernameBytes = encoder.encode(username);
        const passwordBytes = encoder.encode(password);
        const authRequest = new Uint8Array([
            1, usernameBytes.length, ...usernameBytes,
            passwordBytes.length, ...passwordBytes
        ]);
        await writer.write(authRequest);
        response = await readAtLeast(2);
        if (response[0] !== 1 || response[1] !== 0) throw new Error('fail to auth socks server');
        take(2);
    }

    // Step 4: CONNECT request — 按目标类型选 ATYP。
    // cfnew 原先是**恒用域名型寻址**（ATYP=3：长度前缀 + 把地址当域名发出去），口径是
    // 「交给代理自己解析更稳妥」：对真正的域名成立，但对 **IPv6 字面量不成立** ——
    // `2001:db8::1` 不是合法 DNS 名，上游拿它去解析必然失败（normalizeTargetAddress 只去掉方括号，
    // 并不改变这一点），于是「客户端自己解析后按 IPv6 字面量连」的场景一走上游代理就整条断。
    // 现按 RFC 1928 选类型：4 = IPv6（紧跟 16 字节原始地址，上游无需解析）。
    //
    // 只对 IPv6 特判，IPv4 字面量与域名**一律维持 ATYP=3 的既有行为**，理由：
    //   `1.2.3.4` 这种数字串几乎所有解析器都直接认（getaddrinfo 与常见 DNS 都会原样返回该地址），
    //   而改成 ATYP=1 会让「只实现域名型寻址」的少数上游从可用变不可用 —— 对本次要修的问题零收益。
    // ipv6ToBytes 解不出字节时（畸形/带 zone 后缀等）退回 ATYP=3 原样发送，保持改动前行为，
    // 不新增任何失败面。
    const encoder = new TextEncoder();
    const v6Bytes = targetAddress.includes(':') ? ipv6ToBytes(targetAddress) : null;
    const atyp = v6Bytes ? 4 : 3;
    const addrBytes = v6Bytes ?? encoder.encode(normalizeTargetAddress(targetAddress));
    await writer.write(new Uint8Array([
        5, 1, 0, atyp,
        ...(atyp === 3 ? [addrBytes.length] : []),
        ...addrBytes,
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
    // H13：固定 `User-Agent: Mozilla/5.0` 是 cfnew 系的恒定特征，改用随机真实浏览器 UA
    let requestText = `CONNECT ${targetAddr} HTTP/1.1\r\n`
        + `Host: ${targetAddr}\r\n`
        + `User-Agent: ${randomUserAgent()}\r\n`
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

    // —— 出站模式与首跳决策 ——
    //   hasUpstreamProxy —— 上游 SOCKS5 / HTTP CONNECT 出口代理（settings.upstreamProxy）
    //   hasProxyPool     —— 用户显式配置的反代池（settings.proxyIPs 或 env PROXY_IP）
    //                       不含内置 DEFAULT_PROXY_IPS 公共备用中继，也不含 CF 模式下被 handlers
    //                       替换成的官方直连 IP 池；CF 模式下仅「仅走代理」仍可用它（见下方判定）
    //   hasOfficialPool  —— CF 内置 / 面板配置的官方直连 IP 池（handlers.ts 归一化后写入 officialPool）
    //   默认（两者皆 false）→ 配了上游代理则上游代理首跳；否则按目标分类：
    //                        目标命中 Cloudflare 网段 → 池首跳（反代池 → 官方池），否则直连目标首跳
    //   仅走代理（proxyOnly）→ 有代理则代理首跳（上游优先 → 反代池），失败不回退、直接断；
    //                          一个代理都没配则退化为直连目标首跳
    //   直连目标（proxyDegrade，面板显示名 Direct Target）→ 恒直连目标首跳，失败按同一阶梯回退
    // 注：反代池 / 官方池只承载 Cloudflare CDN 目标，所以只有「目标命中 CF 网段、未配上游代理、
    //     且非仅走代理/直连目标」时才拿它们做首跳；其余情况池一律留在回退阶梯里兜底。
    //     首跳失败后统一按 上游代理 → 反代池 → 官方池 → 直连 回退（跳过已试级别）。
    // 注：proxyIPMode === 'prefix'（NAT64）在上方分支已提前返回，不参与本决策。
    const { proxyMode, proxyOnly, proxyDegrade, hasCustomProxyIPs, workerRegion } = globalThis.wsConfig as WsConfig;
    const hasUpstreamProxy = Boolean(globalThis.settings?.upstreamProxy);
    // 用户显式配置的反代池实体（handlers.ts 已剔除内置 DEFAULT_PROXY_IPS 与 CF 模式的官方直连池）
    const customProxyPool = globalThis.wsConfig?.customProxyPool?.length ? globalThis.wsConfig.customProxyPool : [];
    // workerRegion === 'CF'（wk 留空 = 官方直连）时 handlers.ts 会把 panelIPs 换成官方直连 IP 池。
    // 反代池是否作为代理参与本连接：
    //   仅走代理（proxyOnly）→ 与指定地区保持同一套逻辑，不受地区设置影响：配了反代池就能用
    //   默认 / 直连目标       → 只在指定地区生效；CF 模式下反代池不参与，改走官方直连池
    const hasProxyPool = Boolean(hasCustomProxyIPs) && (proxyOnly || workerRegion !== 'CF');
    // 「反代池」这一级实际拨的池：指定地区用 panelIPs（handlers 已按 wk 地区收敛候选）；
    // CF 模式下 panelIPs 已被官方直连池覆盖，仅走代理必须改用用户配置的反代池。
    const proxyPoolForDial = workerRegion === 'CF' ? customProxyPool : undefined;
    const hasAnyProxy = hasUpstreamProxy || hasProxyPool;
    const officialPool = globalThis.wsConfig?.officialPool?.length ? globalThis.wsConfig.officialPool : [];
    const hasOfficialPool = officialPool.length > 0;

    // 已尝试过的出口级别：回退时跳过，避免对同一级重复拨号（直连兜底不在此列，允许最后重试一次）
    const triedHops = new Set<'upstream' | 'pool' | 'official'>();

    async function connectAndWriteLocal(address: string, port: number, fetcher?: any): Promise<Socket> {
        return await dialAndWrite(address, port, rawClientData, fetcher, {
            // 登记时机不能挪到 await 之后：超时/失败时 teardown 要靠它关掉这条半开连接
            onSocket: (socket) => { remoteSocket.value = socket; },
            onOpened: () => log(`connected to ${address}:${port}`),
        });
    }

    let retryInFlight = false;

    async function handleRetryConnection(): Promise<void> {
        // 重入保护：回退阶梯本身是异步的，避免并发触发多条回退连接
        if (retryInFlight) return;
        retryInFlight = true;
        try {
            // 1. 仅走代理（proxyOnly）：任何失败都不回退直连，直接断（防 IP 泄漏，对齐 cfnew 处理重试连接 L4816-4819）
            if (proxyOnly) {
                log(`retry: proxy-only mode, closing without fallback for ${originalAddress}:${originalPort}`);
                safeCloseWebSocket(webSocket);
                return;
            }

            // 2. 上游代理：直连目标模式（proxyDegrade）的第一级回退 / 默认模式的第二级（对齐 cfnew L4820-4827）
            //    回退顺序同样是 上游代理 > 反代池，与首跳优先级一致
            if (hasUpstreamProxy && !triedHops.has('upstream')) {
                triedHops.add('upstream');
                try {
                    log(`retry: attempting upstream proxy for ${originalAddress}:${originalPort}`);
                    const upstreamSocket = await connectThroughUpstreamProxy(originalAddress, originalPort, rawClientData, fetcher);
                    if (upstreamSocket) {
                        upstreamSocket.closed
                            .catch(error => console.log('retry upstream-proxy TCP socket closed error', error))
                            .finally(() => safeCloseWebSocket(webSocket));

                        log(`retry upstream-proxy connected to ${originalAddress}:${originalPort}`);
                        remoteSocket.value = upstreamSocket;
                        remoteSocketToWS(upstreamSocket, webSocket, VLResponseHeader, null, log);
                        return;
                    }
                    log('retry: upstream proxy unavailable (empty or invalid config)');
                } catch (upstreamErr) {
                    log(`retry upstream proxy failed: ${safeErrorMessage(upstreamErr)}`);
                }
            }

            // 3. 反代池竞速回退（仅用户显式配置且当前模式生效的反代池）
            if (hasProxyPool && !triedHops.has('pool')) {
                triedHops.add('pool');
                try {
                    log(`retry: attempting reverse-proxy pool race dial for ${originalAddress}:${originalPort}`);
                    const { socket: tcpSocket, usedIp } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, proxyPoolForDial);

                    tcpSocket.closed
                        .catch(error => console.log('reverse-proxy pool TCP socket closed error', error))
                        .finally(() => safeCloseWebSocket(webSocket));

                    log(`reverse-proxy pool connected via ${usedIp}:${originalPort}`);
                    remoteSocket.value = tcpSocket;
                    remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
                    return;
                } catch (poolErr) {
                    log(`retry: reverse-proxy pool failed: ${safeErrorMessage(poolErr)}`);
                    console.warn(`Reverse-proxy pool failed: ${poolErr}`);
                }
            }

            // 4. CF 内置 IP 池竞速回退（官方直连池：面板 officialIPs，未配置则内置 10 个）
            if (hasOfficialPool && !triedHops.has('official')) {
                triedHops.add('official');
                try {
                    log(`retry: attempting CF official IP pool race dial for ${originalAddress}:${originalPort}`);
                    const { socket: tcpSocket, usedIp } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, officialPool);

                    tcpSocket.closed
                        .catch(error => console.log('CF official pool TCP socket closed error', error))
                        .finally(() => safeCloseWebSocket(webSocket));

                    log(`CF official pool connected via ${usedIp}:${originalPort}`);
                    remoteSocket.value = tcpSocket;
                    remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
                    return;
                } catch (officialErr) {
                    log(`retry: CF official pool failed: ${safeErrorMessage(officialErr)}`);
                    console.warn(`CF official pool failed: ${officialErr}`);
                }
            }

            // 5. 直连兜底（最后策略）
            try {
                log(`retry: falling back to direct connection for ${originalAddress}:${originalPort}`);
                const tcpSocket = await connectAndWriteLocal(originalAddress, originalPort, fetcher);
                tcpSocket.closed
                    .catch(error => console.log('direct TCP socket closed error', error))
                    .finally(() => safeCloseWebSocket(webSocket));
                remoteSocket.value = tcpSocket;
                remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
                return;
            } catch (finalDirectError) {
                console.error('retry: All connection strategies failed:', finalDirectError);
                webSocket.close(1011, `All connection strategies failed: ${safeErrorMessage(finalDirectError)}`);
            }
        } finally {
            retryInFlight = false;
        }
    }

    // 模式 1: prefix (NAT64) - 仅前端显式选择时使用（原逻辑不变，失败不回退）
    if (proxyMode === 'prefix') {
        try {
            log(`using NAT64 prefix mode for ${originalAddress}:${originalPort}`);
            const { socket: tcpSocket, usedIp } = await connectWithPrefixFallback(originalAddress, originalPort, rawClientData, log, fetcher);
            
            tcpSocket.closed
                .catch(error => console.log('prefix fallback TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));
            
            log(`prefix fallback connected via ${usedIp}:${originalPort}`);
            remoteSocket.value = tcpSocket;
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
            return;
        } catch (error) {
            log(`prefix fallback failed: ${safeErrorMessage(error)}`);
            console.warn(`Prefix fallback failed: ${error}`);
            webSocket.close(1011, `Prefix fallback failed: ${safeErrorMessage(error)}`);
            return;
        }
    }

    // 首跳决策（池只在「目标确实由 Cloudflare 承载」时才做首跳）：
    //   默认     → 配了上游代理则上游代理首跳；否则先解析目标：
    //              命中 Cloudflare 网段 → 池首跳（反代池优先 → 官方池）；否则直连目标首跳
    //   直连目标 → 恒直连目标首跳
    //   仅走代理 → 有代理（上游或反代池）则代理首跳；一个代理都没配则退化为直连目标首跳
    //
    // 为什么必须做目标识别：反代池与官方池都只承载 Cloudflare CDN 目标
    // （docs/configuration/vless-trojan「Proxy IP」节：for connecting to Cloudflare CDN addresses），
    // 拨号时写进池 socket 的载荷是 VLESS 头之后的字节、不含目标地址
    // （resolveProxyIPPool 只把 targetDomain 当缓存键与洗牌种子，不参与路由）。
    // 对非 CF 目标，池 socket 的 TCP 可能是通的、还会有数据回来，6s 首字节兜底不触发、回退不发生，
    // 表现为节点整体不通 —— 所以非 CF 目标必须直连优先，CF 目标才先走池。
    const firstHopProxy = !proxyDegrade && (proxyOnly ? hasAnyProxy : hasUpstreamProxy);
    const hasAnyPool = hasProxyPool || hasOfficialPool;
    const needsTargetProbe = !proxyDegrade && !proxyOnly && !hasUpstreamProxy && hasAnyPool;
    const targetIsCF = needsTargetProbe ? await isCloudflareTarget(originalAddress) : false;
    if (needsTargetProbe) {
        log(`target-check: ${originalAddress} → ${targetIsCF ? 'Cloudflare range, pool-first' : 'non-Cloudflare, direct-first'}`);
    }

    // 仅走代理但一个代理都没配：退化为直连目标首跳（不再硬断，避免配置缺失直接不可用）
    if (proxyOnly && !hasAnyProxy) {
        log(`proxy-only: no usable proxy (upstream=${hasUpstreamProxy}, pool=${hasProxyPool}, workerRegion=${workerRegion}), falling back to direct first hop for ${originalAddress}:${originalPort}`);
    }

    // 首跳走代理
    if (firstHopProxy) {
        let proxySocket: Socket | null = null;

        // 优先级：上游代理 > 反代池 —— 上一级可用就不再尝试下一级；两级都失败才进入回退/断连
        // 第一优先：上游代理
        if (hasUpstreamProxy) {
            triedHops.add('upstream');
            try {
                log(`proxy-first: attempting upstream proxy for ${originalAddress}:${originalPort}`);
                proxySocket = await connectThroughUpstreamProxy(originalAddress, originalPort, rawClientData, fetcher);
                if (!proxySocket) log('proxy-first: upstream proxy unavailable (empty or invalid config)');
            } catch (upstreamError) {
                log(`upstream-proxy failed: ${safeErrorMessage(upstreamError)}`);
                console.warn(`Upstream proxy failed: ${upstreamError}`);
            }
        }

        // 第二优先：用户配置的反代池
        if (!proxySocket && hasProxyPool) {
            triedHops.add('pool');
            try {
                log(`proxy-first: attempting race dial through reverse-proxy pool for ${originalAddress}:${originalPort}`);
                const { socket } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, proxyPoolForDial);
                proxySocket = socket;
            } catch (poolError) {
                log(`reverse-proxy pool failed: ${safeErrorMessage(poolError)}`);
                console.warn(`Reverse-proxy pool failed: ${poolError}`);
            }
        }

        if (proxySocket) {
            const activeSocket = proxySocket;
            activeSocket.closed
                .catch(error => console.log('proxy-first TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));

            log(`proxy-first connected to ${originalAddress}:${originalPort}`);
            remoteSocket.value = activeSocket;
            // 传 retry 回调以便 FIRST_BYTE_TIMEOUT 超时触发回退（仅走代理时回调内直接断连）
            remoteSocketToWS(activeSocket, webSocket, VLResponseHeader, () => {
                log(`proxy-first: no data within FIRST_BYTE_TIMEOUT, retrying fallback`);
                try { activeSocket.close?.(); } catch {}
                handleRetryConnection();
            }, log);
            return;
        }

        // 首跳代理不可用
        if (proxyOnly) {
            log(`proxy-only: first hop proxy failed for ${originalAddress}:${originalPort}, closing`);
            webSocket.close(1011, 'Proxy-only mode: proxy connection failed');
            return;
        }

        // 首跳代理全失败（默认模式配了上游代理）→ 回退阶梯（反代池 → 官方池 → 直连兜底）
        await handleRetryConnection();
        return;
    }

    // 首跳走池：目标命中 Cloudflare 网段（池才是这类目标的正确通道）
    if (needsTargetProbe && targetIsCF) {
        let poolSocket: Socket | null = null;

        // 优先级：反代池 > 官方池
        if (hasProxyPool) {
            triedHops.add('pool');
            try {
                log(`pool-first: reverse-proxy pool race dial for ${originalAddress}:${originalPort}`);
                const { socket } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, proxyPoolForDial);
                poolSocket = socket;
            } catch (poolError) {
                log(`pool-first reverse-proxy pool failed: ${safeErrorMessage(poolError)}`);
            }
        }
        if (!poolSocket && hasOfficialPool) {
            triedHops.add('official');
            try {
                log(`pool-first: CF official IP pool race dial for ${originalAddress}:${originalPort}`);
                const { socket } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, officialPool);
                poolSocket = socket;
            } catch (officialError) {
                log(`pool-first CF official pool failed: ${safeErrorMessage(officialError)}`);
            }
        }

        if (poolSocket) {
            const activeSocket = poolSocket;
            activeSocket.closed
                .catch(error => console.log('pool-first TCP socket closed error', error))
                .finally(() => safeCloseWebSocket(webSocket));

            log(`pool-first connected to ${originalAddress}:${originalPort}`);
            remoteSocket.value = activeSocket;
            remoteSocketToWS(activeSocket, webSocket, VLResponseHeader, () => {
                log('pool-first: no data within FIRST_BYTE_TIMEOUT, retrying fallback');
                try { activeSocket.close?.(); } catch {}
                handleRetryConnection();
            }, log);
            return;
        }

        // 池全失败 → 回退阶梯（此处未配上游代理，阶梯里只剩直连兜底）
        log(`pool-first: all pools failed for ${originalAddress}:${originalPort}, falling back`);
        await handleRetryConnection();
        return;
    }

    // 首跳打目标直连（默认模式未配上游代理且目标非 CF / 直连目标模式 / 仅走代理但无代理可退）：
    // 直连竞速拨号；失败或 6s 无首字节 → 回退阶梯（上游代理 → 反代池 → 官方池 → 直连兜底）
    try {
        log(`attempting direct race dial for ${originalAddress}:${originalPort}`);
        const { socket: tcpSocket, usedIp } = await connectWithDirectRaceDial(originalAddress, originalPort, rawClientData, log, fetcher);

        tcpSocket.closed
            .catch(error => console.log('direct race dial TCP socket closed error', error))
            .finally(() => safeCloseWebSocket(webSocket));

        log(`direct race dial connected via ${usedIp}:${originalPort}`);
        remoteSocket.value = tcpSocket;
        // 关键对齐 cfnew：传 retry 回调，直连握手成功但 6s 首字节超时无数据时触发回退重试！
        remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, () => {
            log(`direct race dial: no data within FIRST_BYTE_TIMEOUT, retrying fallback`);
            try { tcpSocket.close?.(); } catch {}
            handleRetryConnection();
        }, log);
        return;
    } catch (directError) {
        log(`direct race dial failed: ${safeErrorMessage(directError)}`);
        console.warn(`Direct race dial failed: ${directError}`);
        await handleRetryConnection();
        return;
    }
}

// --- Download batcher constants (aligned with cfnew 传输下载包大小/尾部/延迟/块大小) ---
const DOWNLOAD_PACKET_SIZE = 32 * 1024;  // 传输下载包大小：批量缓冲满阈值
const DOWNLOAD_TAIL = 512;                // 传输下载尾部：剩余空间阈值触发刷新
const DOWNLOAD_DELAY = 0;                 // 传输下载延迟：0ms（用 queueMicrotask 刷新）
const DOWNLOAD_BLOCK_SIZE = 64 * 1024;    // 传输块大小：BYOB reader 复用缓冲
const FIRST_BYTE_TIMEOUT = 6000;          // 首字节超时 ms（触发 retry 降级）

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
    // 出口帧长抖动：每连接在 24KiB..40KiB 闭区间随机取包长，消除固定 32KiB 帧长的可统计长度指纹
    // （DOWNLOAD_PACKET_SIZE 保留为模块级基准值，抖动后仍恒 ≤ DOWNLOAD_BLOCK_SIZE）
    const PACKET_SIZE = DOWNLOAD_PACKET_SIZE / 4 * 3 + Math.floor(Math.random() * (DOWNLOAD_PACKET_SIZE / 2 + 1));
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

// ===== 每连接清理钩子：WS teardown 统一收口（F-11 DNS socket 释放 + F-21 close 语义）=====
// makeReadableWebSocketStream 的 close / cancel / error 是 WS 关闭仅有的三条路径，
// 与 remoteSocketWrapper（由 unified.ts 的 writableStream 收口）无关的自建资源在此登记，
// 避免「UDP DNS 复用的 TCP socket 无人关闭」这类半开残留。
// 键表用 WeakMap：WS 对象被回收时登记项随之消失，不假设 close 一定触发。
const wsCleanupHooks = new WeakMap<WebSocket, Set<() => void>>();

/** 注册连接级清理钩子（同一 ws + 同一函数引用去重） */
export function registerWsCleanup(webSocket: WebSocket, hook: () => void): void {
    let hooks = wsCleanupHooks.get(webSocket);
    if (!hooks) {
        hooks = new Set();
        wsCleanupHooks.set(webSocket, hooks);
    }
    hooks.add(hook);
}

/**
 * 排空并执行该连接的全部清理钩子。
 * 先 delete 再执行：close / cancel / error 中先到者执行，后到者成为 no-op —— 每个钩子至多跑一次，
 * 因此内部即便不做幂等也不会重复关闭。
 */
function runWsCleanupHooks(webSocket: WebSocket): void {
    const hooks = wsCleanupHooks.get(webSocket);
    if (!hooks) return;
    wsCleanupHooks.delete(webSocket);
    for (const hook of hooks) {
        try { hook(); } catch (error) { console.error('ws cleanup hook failed', error); }
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
                runWsCleanupHooks(webSocketServer);
                if (readableStreamCancel) return;
                // F-21：early data 解码失败或 error 事件已先把流 error 化，此处再 close() 会在监听器内抛 TypeError
                try { controller.close(); } catch (_) { /* 流已 error/关闭，忽略 */ }
            });

            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer has error");
                runWsCleanupHooks(webSocketServer);
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);

            if (error) {
                // early-data 解析失败：**默认可见**地记一笔（不走 logLevel 门控），
                // 然后**忽略这段坏数据、继续等真正的首包**。
                // 改前是 controller.error() 直接断连 —— 客户端随后本可正常发首包，却整条连接被拒，属误伤；
                // early data 只是可选的加速路径（sec-websocket-protocol），坏掉不该导致连接失败。
                log(`early data parse failed: ${safeErrorMessage(error)}`);
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
            runWsCleanupHooks(webSocketServer);
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
