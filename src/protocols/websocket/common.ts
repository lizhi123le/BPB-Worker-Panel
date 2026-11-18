import { resolveDNS, resolveProxyIPPool, filterReachableEntries, parseHostPort, stripRegionTag, DEFAULT_PROXY_IPS, resolveTargetDNS, isCloudflareTarget, ipv6ToBytes, isBareIPv4 } from '@utils';
import { evictOldest, safeErrorMessage, randomUserAgent, base64EncodeUtf8, createSessionWatchdog, createSignatureGate, WATCHDOG_INTERVAL_MS, type SessionWatchdog } from '@common';

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
/**
 * B-12：上游代理**握手**总超时（建连之后、首包之前）。
 * 竞速拨号的 5s 只覆盖 `socket.opened`，覆盖不到「accept 了但永不复 SOCKS5 应答 /
 * 永不回 `\r\n\r\n`」这类黑洞上游 —— 那种情况下 read() 会永久挂起。
 */
const UPSTREAM_HANDSHAKE_TIMEOUT = 8000;
const RACE_DIAL_CONCURRENCY = 3; // 并发拨号数量，参考 cfnew
const RACE_DIAL_MAX_BATCHES = 5; // 最大重试批次
/**
 * 每连接从缓存池抽取参与可达性探测的候选数（抽取在探测前、按黑名单过滤后进行）。
 * 探测本身由 filterReachableEntries 按 3 条**滚动窗口**限流（见 utils 的 PROBE_CONCURRENCY），
 * 而**整批耗时由 PROBE_PHASE_BUDGET_MS 封顶在 2s**（预算内没轮到的候选按 unknown 处理：
 * 不记退避、照常拨号）—— 所以这个数不是并发连接数，也不是延迟上界，只是「一次能考几个候选」。
 * 同时必须满足 RACE_PROBE_COUNT ≤ RACE_DIAL_MAX_BATCHES × RACE_DIAL_CONCURRENCY
 * （6 ≤ 15）：一旦抽取数超过批次窗口，尾部候选永远排不进批次（结构性饥饿，白抽 + 白探测）。
 */
const RACE_PROBE_COUNT = 6;

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

/**
 * 接管来的那条连接（= 本次连接的胜者）：`filterReachableEntries` 把第一条被测通的 socket
 * 直接交出来，调用方写首包后就用它 —— 不再另拨一次。
 */
type ClaimedSocket = { socket: Socket; ip: string; port: number };

/** cfnew 风格：竞速拨号多个代理 IP，取最快成功的。
 *
 *  **一条路径服务两种池**：反代池（`poolOverride` 省略 → 读 panelIPs）与官方 CF 池
 *  （`poolOverride` = officialPool）。两者都走「按黑名单过滤 → 抽 6 → 探测 + 接管 → 批次兜底」。
 *  曾经给官方池开了 `skipProbe`（整池直接分批）——理由是「anycast 没有信息量、别垫 2s 探测」；
 *  但「探测即预连接」实现之后，探测不再额外建连、也不再额外等待（首条连通就是首包时刻），
 *  于是那条理由失效，反而丢了「死候选进黑名单」这条学习通道（官方 IP 也会挂）→ 已统一。
 */
async function connectWithRaceDial(
    targetAddress: string,
    targetPort: number,
    rawClientData: ArrayBuffer | undefined,
    log: Function,
    fetcher?: any,
    poolOverride?: string[],
    onSocket?: (socket: Socket) => void
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
        return await connectWithPrefixFallback(targetAddress, targetPort, rawClientData, log, fetcher, onSocket);
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
    //    「按黑名单过滤后随机抽 RACE_PROBE_COUNT 条去探测/竞速」在下方第 4/5 步做
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

    // 抽取：池内（本次可用的）全部候选都有机会被用到，不再由解析期的 slice(0,8) 把其余候选
    // 结构性丢弃、锁死 10 分钟。反代池与官方池同一套（理由见函数头对 skipProbe 的说明）。
    const probeEntries = shuffleTake(drawSource, RACE_PROBE_COUNT);

    log(`got ${poolEntries.length} IPs for proxy ${proxyAddr}, drawing ${probeEntries.length} (${poolEntries.length - drawSource.length} in backoff), probing reachability...`);

    // 5. 探测（总预算 2s）+ **探测即预连接**：第一条被测通的候选，它那条**已经建立的 socket**
    //    直接接管成数据连接，立刻写首包返回。
    //    为什么不「等整批探测跑完再拨」：那段等待整段落在首包之前，而探测只是筛选、不是裁决 ——
    //    只要有一条候选已被证明可达，就没有理由为「等最慢那条的结论」按住首包。
    //    为什么不是「另起一次拨号」（更早的实现）：那要给每条连接多开一个 socket + 一个超时定时器，
    //    探测相位先收口时还要再等它 —— 净增一份建连成本。接管现成 socket 的成本是 0：
    //    并发峰值仍是探测窗口 3，不会出现「第 4 条连接」。
    const probeFailed: [string, number][] = [];
    // 只以「接管成功」落地：接管没发生就压根不 resolve（那就等 probeDone 那条）——
    // 所以不需要 null 变体，少一个永远不会出现的状态。
    let resolveClaim: (winner: ClaimedSocket) => void = () => {};
    const claimOutcome = new Promise<ClaimedSocket>((resolve) => { resolveClaim = resolve; });

    /** 接管探测连上的那条 socket（只会被调用一次：filterReachableEntries 内部只交第一条）。
     *  这里只做三件事：登记到连接级清理钩子（teardown 才关得掉）、交付接管结果、返回 true 表示
     *  「所有权归我，别关」。写首包/记账留给主流程 —— 一个 ArrayBuffer 只能交给 write 一次，
     *  必须等主流程确认这条真的赢了再写。 */
    const claimProbeSocket = (entry: [string, number], socket: Socket): boolean => {
        const cleanIp = entry[0].replace(/^\[|\]$/g, '');
        onSocket?.(socket);
        resolveClaim({ socket, ip: cleanIp, port: entry[1] });
        return true;
    };

    // 探测照常跑完（≤2s 预算），结论用于批次与黑名单，与是否已接管无关。
    // 探针在 filterReachableEntries 内部按 3 条滚动窗口限流，所以这里的「不通」是候选自身的结论，
    // 不是被自己的探测并发撞配额打出来的假失败；预算内没轮到的候选是 'unknown'（不上报、不判死）。
    const probePromise = filterReachableEntries(probeEntries, (entry, ok) => {
        if (!ok) probeFailed.push(entry);
    }, claimProbeSocket);

    // 记账挂在探测**完成**的回调里，不挂在主流程的 await 之后：接管成功会提前 return，
    // 但「哪些候选是真的不通」仍必须落进黑名单（否则死候选每连接都要白探一次）。
    probePromise.then((entries) => {
        // 例外：本批抽取的候选**全部**探测不通 —— 这是「整池集体抖动」的信号，而不是 6 个候选各自死了。
        // 探测超时(2s)比拨号超时(5s)更严，「探测判死」本来就不等于「拨号连不上」：
        // filterReachableEntries 会把它们原样返回继续拨号，所以此时不记退避，
        // 免得一次集体抖动就把整池锁进黑名单（真不通的候选会在拨号超时/写首包失败时按既有逻辑记账）。
        const allProbeFailed = probeEntries.length > 0 && probeFailed.length === probeEntries.length;
        if (!blacklistBypass && !allProbeFailed) {
            for (const [host, port] of probeFailed) blacklistRecord(blacklistKey(host, port));
        }
        log(`reachable proxy IPs: ${entries.map(([h, p]) => `${h}:${p}`).join(', ')}`);
    }).catch(() => { /* 探测本身不抛；兜一层，别让未处理的 rejection 逃出去 */ });

    // 接管窗口：接管到连接（已建立）/ 探测收口。接管一定早于收口发生（在探测 worker 内），
    // 所以这里不需要「收口后再等它一会儿」—— 那一步只在更早的「另起一次拨号」实现里才需要。
    const probeDone = probePromise.then<null, null>(() => null, () => null);
    const claimed = await Promise.race([claimOutcome, probeDone]);

    if (claimed) {
        // 写首包/清黑名单/打点统一由 commitWinner 负责（一个 ArrayBuffer 只写一次，见该函数）
        if (await commitWinner(claimed, rawClientData, log, proxyAddr, 'race dial winner (probe socket, no extra dial)')) {
            return { socket: claimed.socket, usedIp: claimed.ip };
        }
        // 写首包失败：该候选已记账并关过 socket，落回批次循环（批次里的预检会跳过它）
    }

    const reachableEntries = await probePromise;

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

        // 并发拨号，取**最快**成功的（黑名单预检跳过已知不通的 IP:port，对齐 edgetunnel 5782-5786）
        // B-11：batchWinnerClaimed 是本批的「先到先得」闸门 —— 只有第一条成功连上的候选会认领，
        // 之后连上的候选立即关闭并抛 'lost race'，因此不会有无人认领的 socket 残留。
        // R-03：单候选的「拨号 + 等建立 + 写首包 + 失败回收」由 dialCandidate 统一提供。
        let batchWinnerClaimed = false;
        const dialPromises = batchEntries.map(async ([ip, entryPort], j) => {
            const cleanIp = ip.replace(/^\[|\]$/g, '');
            const key = blacklistKey(cleanIp, entryPort);
            // 抽取阶段已按黑名单过滤过；这里只兜住「抽取 → 拨号」之间被并发连接新拉黑的键。
            // blacklistBypass（全池退避中）时不跳过，保证最后兜底仍真的会拨号。
            // 用 throw 而不是返回 socket:null —— Promise.any 只该在「真的拿到了 socket」时才 settle。
            if (!blacklistBypass && blacklistCheck(key)) throw new Error('candidate blacklisted');

            // 先到先得闸门与黑名单记账留在本路径；建连与写首包的收口见 openCandidate / writeFirstPacket
            let socket: Socket;
            try {
                socket = await openCandidate(
                    { hostname: cleanIp, port: entryPort },
                    PROXY_DIAL_TIMEOUT,
                    fetcher,
                    { onSocket }
                );
            } catch (dialError) {
                // 连不上/建连超时是这个候选自己的问题 → 记一次退避（「输掉竞速」不记：它是通了的，
                // 见下面的 batchWinnerClaimed 分支）。openCandidate 只关闭 socket、不记账，
                // 所以这条路径必须自己记 —— 否则死候选会被每次连接反复拨。
                if (!blacklistBypass) blacklistRecord(key);
                throw dialError;
            }

            // B-11：晚到的候选（本批已经有人连上）自行关闭并出局
            if (batchWinnerClaimed) {
                try { socket.close(); } catch {}
                throw new Error('lost race');
            }
            batchWinnerClaimed = true;
            return { socket, ip: cleanIp, port: entryPort, index: batchIndexes[j] };
        });

        // B-11：取**最快成功**的候选（Promise.any），不再 `await Promise.allSettled`。
        // 原实现有两个问题：① 单条候选最多等 PROXY_DIAL_TIMEOUT(5s)，于是「1 条 10ms 连上 +
        // 2 条黑洞」也要白等 5s 才写首包（批次上限 5 → 单跳最坏 25s，再叠加回退阶梯最坏 75s）；
        // ② allSettled 的结果数组按**入参顺序**排列，for 取到的是「池序第一个成功者」而不是最快者 ——
        // 与注释「取最快成功的」以及同文件 connectWithDirectRaceDial 的 Promise.any 语义都不一致。
        // 败者由 dial 内的 batchWinnerClaimed 分支自行关闭，不会留下无人认领的 socket。
        let winner: { socket: Socket; ip: string; port: number; index: number } | null = null;
        try {
            winner = await Promise.any(dialPromises);
        } catch {
            // AggregateError：本批所有候选都失败（各自已在 dial 内关 socket 并记黑名单）
            winner = null;
        }

        if (winner) {
            const { socket, ip: winnerIp, port: winnerPort, index } = winner;
            // 必须在关闭其余候选之前写首包，避免连接被重置；
            // 成功时游标推进到该候选（对齐 edgetunnel 5799-5800），其余记账见 commitWinner
            if (await commitWinner({ socket, ip: winnerIp, port: winnerPort }, rawClientData, log, proxyAddr, 'race dial winner', index)) {
                return { socket, usedIp: winnerIp };
            }
        }

        // 走到这里说明本批没有一个候选写成功：每个 fulfilled 的候选都已在上面那个 write 失败的 catch 分支里
        // 记过黑名单并关过 socket。原先这里再来一遍"本批次全部失败"循环，会把同一键的失败数**再加一次**
        // （IP_BLACKLIST_MAX_FAIL=3 时两批就拉黑），属重复记账，已删除 —— 封禁节奏回到阈值本身。
    }

    // 所有批次都失败，抛出错误让上层处理兜底
    throw new Error(`All race dial attempts failed for proxy ${proxyAddr}`);
}

/** 判断地址是否为 IP 字面量（IPv4 或含冒号的 IPv6），而非域名（对齐 cfnew 是IP地址）。
 *  IPv4 判定复用 @utils 的 isBareIPv4（与订阅侧同一份正则，避免两处口径漂移）；
 *  IPv6 沿用「含冒号且非 CIDR」的宽松判据 —— 这里只用于决定是否跳过 DoH，不需要地址合法性。 */
const isIPLiteral = (address: string): boolean =>
    isBareIPv4(address)
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
    fetcher?: any,
    onSocket?: (socket: Socket) => void
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
        // 并发拨号，取最快成功的（对齐 cfnew 并发连接候选 Promise.any）
        // R-03：建连归 openCandidate（统一 onSocket 时机 / 超时关连接 / 定时器清理），
        // 首包由**胜者单独写**（共享 ArrayBuffer 不可写多次）。
        const dialPromises = batchCandidates.map(async (candidate) => {
            const socket = await openCandidate(
                { hostname: candidate.hostname, port: candidate.port },
                DIRECT_DIAL_TIMEOUT,
                fetcher,
                { onSocket }
            );
            return { socket, candidate };
        });

        try {
            const { socket, candidate } = await Promise.any(dialPromises);

            // 先写首包（只有胜者写），再关闭败者 —— 顺序反了会因连接被重置而丢首包
            await writeFirstPacket(socket, rawClientData);

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
            // 本批全部失败（或胜者首包写失败）→ 记录黑名单（对齐 cfnew L4763），并回收可能已建立的败者
            for (const candidate of batchCandidates) {
                blacklistRecord(candidate.key);
            }
            for (const p of dialPromises) {
                p.then(({ socket: otherSocket }) => {
                    try { otherSocket.close(); } catch {}
                }).catch(() => {});
            }
        }
    }

    // 6. 全部失败：抛出错误，由上层走代理路径/兜底直连
    throw new Error(`All direct race dial attempts failed for ${targetAddress}:${targetPort}`);
}

/**
 * 工具函数：模块级，供 connectWithPrefixFallback 等使用 */
const getRandomValue = (arr: string[]) => arr[Math.floor(Math.random() * arr.length)];
const parseIPs = (value: string) => value ? value.split(',').map(val => val.trim()).filter(Boolean) : undefined;

/**
 * R-03：**单个候选的「拨号 + 等建立 + 写首包」**，三条拨号路径（反代池竞速 / 直连池竞速 /
 * 单条拨号）共用的唯一实现。
 *
 * 之所以必须只有一份：这一段里藏着三条彼此独立、且每条都曾经是真实缺陷的不变式，
 * 复制三遍时必然漏掉其中一条（历史证据：P-03 定时器不清理只修了一处、B-19 超时不关连接
 * 只修了一处、F-09 失败分支 socket 泄漏只在两处修过）。
 *  1. `onSocket` 必须在 `await opened` **之前**回调 —— 竞速路径「先写首包再返回」，
 *     写卡住时上层拿不到 socket，teardown 只能靠这个登记把它关掉；
 *  2. `opened` 超时或 reject 时**就地关闭** socket（竞速的败者分支不携带 socket 引用）；
 *  3. 写首包失败时先 `releaseLock` 再关闭 —— 否则锁死的 writable 会让上层再次 getWriter 抛错，
 *     把整条上行泵打死（现象是「管道错误」而非真实原因）。
 * 定时器在 `finally` 里清掉：`Promise.race` 的 setTimeout 不会自动取消，长连接下会堆积成
 * 「每连接数个必然空跑的悬空定时器」。
 *
 * 出错时本函数**已经**完成回收并抛出，调用方只需决定「要不要记黑名单」，不需要再关 socket。
 */
/**
 * R-03 / 回归修复：**建连 + 等建立**（不含写首包）。
 *
 * 为什么必须与「写首包」分开：竞速会对同一批候选并发建连，而首包 `rawClientData` 是**同一个**
 * ArrayBuffer —— `write(arrayBuffer)` 在把它交给 socket sink 时会 detach 该缓冲区，
 * 于是「每个候选都写一次」会让第一个写成功的候选吃掉缓冲区、真正的胜者只能写出 0 字节。
 * 表现就是：反代（CF 目标）首跳拿不到 VLESS 头与目标信息 → 连接建立但整条不通，
 * 而单条拨号（只写一次）与非池路径都正常。
 * 所以顺序必须是「先决出胜者 → 只有胜者写 → 再关闭其余」。
 *
 * 本函数保证的三条不变式（原先三处各写一遍，且各漏过其中一条）：
 *  1. `onSocket` 早于 `await opened`（写卡住时上层拿不到 socket，teardown 只能靠这个登记）；
 *  2. `opened` 超时或 reject 时**就地关闭** socket（竞速败者分支不携带 socket 引用）；
 *  3. 定时器在 `finally` 清理（`Promise.race` 的 setTimeout 不会自动取消）。
 */
async function openCandidate(
    target: { hostname: string; port: number },
    timeoutMs: number,
    fetcher?: any,
    hooks?: { onSocket?: (socket: Socket) => void }
): Promise<Socket> {
    const socket = connectSocket(target, fetcher);

    hooks?.onSocket?.(socket);

    let timer: ReturnType<typeof setTimeout> | null = null;
    try {
        await Promise.race([
            socket.opened,
            new Promise<never>((_, reject) => {
                timer = setTimeout(() => reject(new Error(`连接超时 (${target.hostname}:${target.port})`)), timeoutMs);
            })
        ]);
    } catch (dialError) {
        try { socket.close(); } catch { /* 已关闭 */ }
        throw dialError;
    } finally {
        if (timer) clearTimeout(timer);
    }

    return socket;
}

/**
 * 写首包。**每个 ArrayBuffer 只能交给它一次**（见 openCandidate 的说明）——
 * 调用方必须保证「一个连接只调用一次」。
 * 失败时先解锁再关闭：锁死的 writable 会让上层再次 getWriter 抛错，把整条上行泵打死。
 */
async function writeFirstPacket(socket: Socket, rawClientData: ArrayBuffer | undefined): Promise<void> {
    // F-19：rawClientData 可能为 undefined（首包剥离后无残余载荷），直接 write(undefined) 会抛 TypeError
    const writer = socket.writable.getWriter();
    try {
        if (rawClientData && rawClientData.byteLength) await writer.write(rawClientData);
    } catch (writeError) {
        try { writer.releaseLock(); } catch { /* 有未决写时释放会抛 */ }
        try { socket.close(); } catch { /* 已关闭 */ }
        throw writeError;
    }
    writer.releaseLock();
}

/**
 * 「胜者落地」的唯一实现：写首包 → 清黑名单 →（可选）推进池游标 → 打点；
 * 失败则记一次黑名单并返回 false（socket 已由 writeFirstPacket 解锁并关闭，调用方只需决定后续）。
 *
 * 为什么必须收在一处：`rawClientData` 是**同一个** ArrayBuffer，write 会 detach 它 ——
 * 「一个连接只写一次」这条铁律每多一份实现，就多一次被写错的机会（R-03 的成因正是写入被挪进候选内部）。
 * 为什么只有失败才记账：「连上了但首包写不出去」才算这个候选的问题；连不上的由探测/批次失败负责。
 * `cursorIndex` 省略 = 接管路径（探测即预连接）：它的下标属于「探测完成后的可达集合」，此刻还没成型，
 * 跳过它只影响下一次连接的起点偏移（每次连接另有随机起点兜着）。
 */
async function commitWinner(
    winner: { socket: Socket; ip: string; port: number },
    rawClientData: ArrayBuffer | undefined,
    log: Function,
    proxyAddr: string,
    label: string,
    cursorIndex?: number
): Promise<boolean> {
    try {
        await writeFirstPacket(winner.socket, rawClientData);
        blacklistClear(blacklistKey(winner.ip, winner.port));
        if (cursorIndex !== undefined) proxyIpPoolCursor = cursorIndex;
        log(`${label}: ${winner.ip}:${winner.port} (proxy: ${proxyAddr})`);
        return true;
    } catch (writeError) {
        log(`first packet write failed for ${winner.ip}:${winner.port}: ${safeErrorMessage(writeError)}`);
        blacklistRecord(blacklistKey(winner.ip, winner.port));
        return false;
    }
}

/**
 * 拨号 + 写首包的对外形态（单条拨号路径用；只有一个连接，不存在共享缓冲区问题）。
 * = openCandidate + writeFirstPacket —— 不再多套一层同名函数（此前 dialCandidate 只服务本函数）。
 * hooks 的回调时机是语义的一部分，不能挪：onSocket 早于 await opened、onOpened 在建连之后取 writer 之前。
 */
async function dialAndWrite(
    address: string,
    port: number,
    rawClientData: ArrayBuffer | undefined,
    fetcher?: any,
    hooks?: {
        onSocket?: (socket: Socket) => void;
        onOpened?: () => void;
        /** 首包写失败时的回调（socket 已解锁并关闭） */
        onWriteFailure?: (error: unknown) => void;
    }
): Promise<Socket> {
    const socket = await openCandidate({ hostname: address, port }, DIRECT_DIAL_TIMEOUT, fetcher, hooks);

    hooks?.onOpened?.();

    try {
        await writeFirstPacket(socket, rawClientData);
    } catch (writeError) {
        hooks?.onWriteFailure?.(writeError);
        throw writeError;
    }

    return socket;
}

/** NAT64 prefix 模式：将目标域名解析为 IPv4，转换为 IPv6 NAT64 地址连接 */
async function connectWithPrefixFallback(
    targetAddress: string,
    targetPort: number,
    rawClientData: ArrayBuffer | undefined,
    log: Function,
    fetcher?: any,
    onSocket?: (socket: Socket) => void
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
    
    // 解析目标 IPv4：只查 A、不碰 AAAA（NAT64 本身只对 IPv4 目标成立）。
    // 注意「缓存」口径：resolveDNS 现在自带结果缓存（有结果 10 分钟 / 空结果 30 秒），
    // prefix 模式因此不再享受「每次都拿最新 A 记录」的时效性 —— 换来的是同一请求里
    // 目标分类、直连竞速、本路径共享一次 DoH 结果（此前是各打一轮，DNS 阶段上界成倍放大）。
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
            const directSocket = await dialAndWrite(targetAddress, targetPort, rawClientData, fetcher, { onSocket });
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
    
        const tcpSocket = await dialAndWrite(nat64IP, targetPort, rawClientData, fetcher, { onSocket });
    
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

/**
 * Wrap leftover bytes from handshake response back into readable stream head — cfnew 包装残留套接字 L5662-5684
 *
 * B-24：必须是 **byte stream**（`type:'bytes'`）。旧实现产出的普通 ReadableStream 让下游
 * `remoteSocketToWS` 的 `getReader({ mode: 'byob' })` 直接抛错 → 静默退回非 BYOB 路径：
 * 每块都新分配一枚 ArrayBuffer（真正零化）再打包一次，而这条包装流**只在「配了上游 SOCKS5 /
 * HTTP CONNECT」时**才出现 —— 也就是配了上游代理的用户全程乘着最贵的读路径，且没有任何降级日志。
 * byte stream 的 `enqueue` 同样接受 Uint8Array，残留字节仍排在后续 chunk 之前（见下方 pull）。
 */
function wrapLeftoverSocket(socket: Socket, leftover: Uint8Array): Socket {
    let upstreamReader: ReadableStreamDefaultReader<any> | null = null;
    const newReadable = new ReadableStream({
        type: 'bytes',
        start(controller: ReadableByteStreamController) {
            // 先塞残留：byte stream 的 enqueue 会把这段字节排在队列头，BYOB 读到的第一块必然是它
            controller.enqueue(leftover);
            upstreamReader = socket.readable.getReader();
        },
        async pull(controller: ReadableByteStreamController) {
            const { value, done } = await upstreamReader!.read();
            if (done) { controller.close(); return; }
            controller.enqueue(toUint8Array(value));
        },
        cancel(reason: any) {
            try { upstreamReader?.cancel(reason); } catch {}
            // B-24：cancel 不会释放 reader 的锁，而这里持有的是**上游 socket 的** readable ——
            // 不释放的话，teardown 路径再去 getReader() 会抛「stream is locked」（旧实现同样漏了这步）。
            // 有未决读时 releaseLock 会抛，故与同文件其它位置一样包 try。
            try { upstreamReader?.releaseLock(); } catch { /* 有未决读时释放会抛 */ }
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

    /**
     * B-12：握手失败必须回收 socket。
     *
     * 原实现从建连到握手结束**没有 try/catch**，也没有 deadline：上游代理若「TCP accept 但
     * 永不复 SOCKS5 应答」，`readAtLeast` 会永久挂起（`PROXY_DIAL_TIMEOUT` 只用于竞速拨号，
     * 覆盖不到这里）；而 `no acceptable methods` / `fail to auth` / `invalid proxy response`
     * 这些分支直接 `throw`，既没 close 也没走 `remoteSocket.track` —— 每次失败泄漏一条半开 TCP
     * 与一对锁死的 reader/writer，长 isolate 中累积到句柄耗尽。
     *
     * 这里用 `fail()` 把「收口 + 抛错」绑在一起，避免再出现「新增了一个 throw 但忘了关 socket」。
     */
    function fail(message: string): never {
        // P-03/B-12：失败路径也要清掉握手 deadline，否则每次握手失败都会留下一个
        // 8 秒后必定空跑、且会去 close 一个已关闭 socket 的定时器。
        clearTimeout(handshakeDeadline);
        try { writer.releaseLock(); } catch { /* 有未决写时释放会抛 */ }
        try { reader.releaseLock(); } catch { /* 同上 */ }
        try { socket.close(); } catch { /* 已关闭 */ }
        throw new Error(message);
    }
    // 握手总 deadline：超时直接关 socket → 挂起的 read() 随即失败 → 由上方 fail 的 catch 收口
    const handshakeDeadline = setTimeout(() => {
        try { socket.close(); } catch { /* 已关闭 */ }
    }, UPSTREAM_HANDSHAKE_TIMEOUT);

    // Accumulated leftover bytes across reads — aligned with cfnew 残留字节 L5533
    let leftover: Uint8Array<ArrayBuffer> = new Uint8Array(0);

    async function readAtLeast(need: number): Promise<Uint8Array<ArrayBuffer>> {
        while (leftover.length < need) {
            const { value, done } = await reader.read();
            if (done || !value) fail('fail to open socks connection');
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
    if (response[0] !== 5 || response[1] === 255) fail('no acceptable methods');
    const selectedMethod = response[1];
    take(2);

    // Step 3: Username/password auth (method 2) — cfnew L5551-5558
    if (selectedMethod === 2) {
        if (!username || !password) fail('socks server needs auth');
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
        if (response[0] !== 1 || response[1] !== 0) fail('fail to auth socks server');
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
    if (response[1] !== 0) fail('fail to open socks connection');
    const bindAddrType = response[3];
    let replyLen: number;
    if (bindAddrType === 1) {
        replyLen = 10; // IPv4: 4 header + 4 addr + 2 port
    } else if (bindAddrType === 4) {
        replyLen = 22; // IPv6: 4 header + 16 addr + 2 port
    } else if (bindAddrType === 3) {
        replyLen = 7 + (await readAtLeast(5))[4]; // Domain: 4 header + 1 len + domain + 2 port
    } else {
        fail('invalid proxy response');
    }
    await readAtLeast(replyLen);
    take(replyLen);

    // Step 6: Write first packet before releasing writer — cfnew L5582-5584
    if (rawClientData && rawClientData.byteLength) await writer.write(rawClientData);
    clearTimeout(handshakeDeadline);
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

    if (socket.opened) {
        // B-12：这条 await 原先在 try 之外 —— opened 被拒时 socket 无人关闭（清理只覆盖 try 之后）
        try {
            await socket.opened;
        } catch (error) {
            try { socket.close(); } catch { /* 已关闭 */ }
            throw error;
        }
    }

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
        // B-20：Basic 凭据必须是 **UTF-8 字节** 再 base64（RFC 7617）。
        // 原实现用 btoa(`${user}:${pass}`)：① 只接受 ≤0xFF 的码点，中文/emoji 口令直接抛
        // InvalidCharacterError（且抛点在 try 之外 → socket 泄漏）；② 即使不抛也只是 Latin-1。
        requestText += `Proxy-Authorization: Basic ${base64EncodeUtf8(`${username}:${password || ''}`)}\r\n`;
    }
    requestText += '\r\n';

    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    // B-12：tunnel 握手总 deadline（黑洞上游会让下面的 while 永久挂起）
    const tunnelDeadline = setTimeout(() => {
        try { socket.close(); } catch { /* 已关闭 */ }
    }, UPSTREAM_HANDSHAKE_TIMEOUT);

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
        clearTimeout(tunnelDeadline);
        writer.releaseLock();
        reader.releaseLock();

        // Wrap leftover — cfnew L5652
        if (leftoverData.byteLength) return wrapLeftoverSocket(socket, leftoverData);
        return socket;
    } catch (err) {
        // Clean up on error — cfnew L5654-5658
        clearTimeout(tunnelDeadline);
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
    remoteSocket: { value: Socket | null; track?: (socket: Socket | null) => void },
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
    //   hasProxyPool     —— 本连接可拨的反代池（含内置 DEFAULT_PROXY_IPS 兜底）
    //                       指定地区取 panelIPs（已按 wk 收敛）；CF 模式下仅「仅走代理」取
    //                       用户显式配置的 customProxyPool（见下方判定）
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
    const { proxyMode, proxyOnly, proxyDegrade, workerRegion } = globalThis.wsConfig as WsConfig;
    const hasUpstreamProxy = Boolean(globalThis.settings?.upstreamProxy);
    // 用户显式配置的反代池实体（handlers.ts 已剔除内置 DEFAULT_PROXY_IPS 与 CF 模式的官方直连池）
    const customProxyPool = globalThis.wsConfig?.customProxyPool?.length ? globalThis.wsConfig.customProxyPool : [];
    // workerRegion === 'CF'（wk 留空 = 官方直连）时 handlers.ts 会把 panelIPs 换成官方直连 IP 池。
    // 反代池是否作为代理参与本连接：
    //   指定地区（wk 非空）→ panelIPs 恒有可拨条目（最次也是内置 DEFAULT_PROXY_IPS 兜底），
    //                        因此「留空 + 指定地区」同样能用内置池并做地区锚定
    //   仅走代理（proxyOnly）→ 与指定地区同一套逻辑；CF 模式下用 customProxyPool（配了才能用）
    //   默认 / 直连目标       → CF 模式下反代池不参与，改走官方直连池
    // 这里只判断「本模式下有没有可拨的池条目」，不再要求用户显式配置：
    // panelIPs 已按 proxyIPs > env PROXY_IP > DEFAULT_PROXY_IPS 兜底，内置公共备用中继同样参与拨号。
    const poolEntriesForDial = workerRegion === 'CF' ? customProxyPool : (globalThis.wsConfig?.panelIPs ?? []);
    const hasProxyPool = poolEntriesForDial.length > 0 && (proxyOnly || workerRegion !== 'CF');
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
            onSocket: (socket) => { remoteSocket.value = socket; },  // 单条拨号路径：它就是要被认领的 socket
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

            // 3. 反代池竞速回退（本模式下可拨的反代池：指定地区用 panelIPs，含内置 DEFAULT_PROXY_IPS
            //    兜底；CF 模式仅「仅走代理」用用户显式配置的 customProxyPool）
            if (hasProxyPool && !triedHops.has('pool')) {
                triedHops.add('pool');
                try {
                    log(`retry: attempting reverse-proxy pool race dial for ${originalAddress}:${originalPort}`);
                    const { socket: tcpSocket, usedIp } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, proxyPoolForDial, (s) => remoteSocket.track?.(s));

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
                    // 官方池不特殊化：与反代池同一条路（探测 + 接管 → 批次兜底），理由见 connectWithRaceDial 的函数头
                    const { socket: tcpSocket, usedIp } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, officialPool, (s) => remoteSocket.track?.(s));

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
            const { socket: tcpSocket, usedIp } = await connectWithPrefixFallback(originalAddress, originalPort, rawClientData, log, fetcher, (s) => remoteSocket.track?.(s));
            
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

        // 第二优先：反代池（指定地区用 panelIPs，含内置 DEFAULT_PROXY_IPS 兜底；CF 模式用 customProxyPool）
        if (!proxySocket && hasProxyPool) {
            triedHops.add('pool');
            try {
                log(`proxy-first: attempting race dial through reverse-proxy pool for ${originalAddress}:${originalPort}`);
                const { socket } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, proxyPoolForDial, (s) => remoteSocket.track?.(s));
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
                const { socket } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, proxyPoolForDial, (s) => remoteSocket.track?.(s));
                poolSocket = socket;
            } catch (poolError) {
                log(`pool-first reverse-proxy pool failed: ${safeErrorMessage(poolError)}`);
            }
        }
        if (!poolSocket && hasOfficialPool) {
            triedHops.add('official');
            try {
                log(`pool-first: CF official IP pool race dial for ${originalAddress}:${originalPort}`);
                // 与 retry 路径同口径：官方池不特殊化，走「探测 + 接管 → 批次兜底」
                const { socket } = await connectWithRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, officialPool, (s) => remoteSocket.track?.(s));
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
        const { socket: tcpSocket, usedIp } = await connectWithDirectRaceDial(originalAddress, originalPort, rawClientData, log, fetcher, (s) => remoteSocket.track?.(s));

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
/**
 * 帧长抖动的**下限**（24KiB）。下行分流的阈值必须用它，而不是 `DOWNLOAD_BLOCK_SIZE >> 1`：
 * 只有「块 < 下限 ≤ PACKET_SIZE」才能保证 batcher 里那条「缓冲为空且剩余 ≥ PACKET_SIZE
 * 就直接按引用 send」的分支永不触发 —— 那条分支会把调用方即将复用的缓冲按引用交出去。
 */
const DOWNLOAD_PACKET_MIN = DOWNLOAD_PACKET_SIZE / 4 * 3;
const FIRST_BYTE_TIMEOUT = 6000;          // 首字节超时 ms（触发 retry 降级）

/**
 * ⚠️ `DOWNLOAD_BLOCK_SIZE` / `DOWNLOAD_PACKET_SIZE` 是**实测选定的常量，刻意不做成 env 可调**
 * （曾尝试过 `WS_DL_BLOCK_KIB` / `WS_DL_FRAME_KIB`，实测 4K 反而更卡，已回滚）。原因：
 *   - 吞吐上限通常是「窗口/RTT」，那是平台侧属性，**放大读块不改变在途字节上限**；
 *   - 帧长基准调大会把分流阈值一起抬高（阈值 = 3/4 基准），原本直发的中等块（24~48KiB）
 *     被推回 batcher 的 1~3ms 定时器里排队，**延迟反而变差**；
 *   - 三槽池 = 3 × 读块，128KiB 读块即 384KiB/连接，内存与 GC 压力一起上升。
 * 换言之：卡顿的杠杆不在这里，在下行流控（`WS_DOWNLINK_BPS`）与线路本身。
 * 若要重试，先看 debug 仪表里的 `maxBlock` 是否长期远小于 64KiB —— 那是唯一值得改的前提。
 */

/**
 * 下行「会话字节预算」的默认值（MB）：**默认开启**，用完即主动关连接让客户端重连。
 *
 * 为什么默认开启：Workers 的 CPU/内存额度是**按调用累计**的，而一条 WebSocket 会话就是
 * 一次调用 —— 长会话迟早把额度耗光，超限时平台返回 1102 并**连带打死整个 isolate**
 * （同 isolate 上的其它连接一起断）。按字节主动收口，把「不可控的 isolate 崩溃」换成
 * 「单条连接可控断开 + 客户端自动重连」。
 * 900MB 的量级：按默认速率上限约 45 秒（客户端真能跑满时）；按 4K 真实码率（≈3.1MB/s）
 * 约 5 分钟；1080p（≈0.8MB/s）约 19 分钟。断一次只是一次干净重连，不丢会话状态。
 *
 * env `WS_SESSION_MAX_MB` 可覆盖；**显式设为 0 表示关闭该保护**（回滚开关），
 * 未设或非法值仍取本默认值。
 */
const WS_SESSION_MAX_MB_DEFAULT = 900;

/**
 * 下行速率上限的默认值（字节/秒）：**默认开启**，具体取值见下方 WS_DOWNLINK_BPS_DEFAULT。
 * 依据见 downlinkByteRate 的注释（平台没有发送侧背压）。
 *
 * 默认值对 4K（25~50Mbps）有数倍余量，正常播放不会咬到它；它的作用是**兜底**：
 * 一旦客户端链路远低于这个值，无界排队就会被压成稳定速率，而不是一直涨到 isolate 被打死。
 * 链路更快（>80Mbps）的部署在跑大文件下载时会被这个上限压住，需要时上调或设 `0` 关闭。
 *
 * ⚠️ 现默认 20MB/s（按业主指定）。**这是本仓有过实机结论的一个值，务必读懂再改**：
 * `docs/analysis/worker-internal-error-1101-2026-11-15.md` §9/§9.3 记录，20MB/s 曾经让
 * 「令牌永远够用 → 节流从不等待 → isolate 发送队列无界堆积」，被平台以
 * `internal error; reference = …` 收口；降到 10MB/s 后同类报错在 10 分钟内明显减少。
 * 与当时不同的是，突发额度现在是**独立的**（见 `WS_DOWNLINK_BURST_KB`），不再等于速率 ——
 * 单次尖峰被封在下面那个常量里，但**长期平均速率仍高于常见客户端（3~6MB/s）**，
 * 所以「节流咬不住」这一条依然成立。若线上复现上述报错，把 env 调回 `10000000` 即可，无需改代码。
 * 校准时看 debug 日志的 `capWait`：≈0 说明上限没咬住（应调低），接近窗口长度说明它是瓶颈（可调高）。
 *
 * ⚠️ 它是**全量下行**的上限，不分协议。
 */
const WS_DOWNLINK_BPS_DEFAULT = 20 * 1000 * 1000;

function sessionByteBudget(): number {
    return Math.floor(envNumber('WS_SESSION_MAX_MB', WS_SESSION_MAX_MB_DEFAULT, true) * 1024 * 1024);
}

/**
 * 下行速率上限（字节/秒）。**这是本项目下行唯一的流控点**。
 *
 * 为什么必须有它（不是调参，是接口缺陷）：`@cloudflare/workers-types` 的 `WebSocket`
 * 接口**没有 `bufferedAmount`**，`send()` 返回 `void`（见 index.d.ts 的 WebSocket 接口）。
 * 平台因此不提供任何「客户端还收得动吗」的信号，而 `remoteSocketToWS` 是
 * 「read 一块 → send 一块 → 再 read」的紧循环：只要上游比客户端快，发不出去的帧就在
 * 运行时里**无界堆积**。故障形态正是「越播越卡 → 最后断」：
 *   - 堆积 = 排队延迟线性增长 → 播放器缓冲被排空 → 画面卡顿越来越重；
 *   - 堆积 = isolate 堆持续增长 → GC 压力上升（GC 时间算 CPU）→ 最终 exceededMemory/1102 硬断。
 * 这三个症状与「拷贝次数多」毫无关系，所以零拷贝/memcpy 优化对它们完全无效。
 *
 * 为什么在这个位置能形成**端到端**背压：await 令牌 → 本循环不再调用 `read()` →
 * socket 接收缓冲填满 → TCP 窗口关闭 → 上游源站自然停顿。平台没有给我们发送侧信号，
 * 但接收侧（不读就不收）是真实的。
 *
 * env `WS_DOWNLINK_BPS`（字节/秒）：未设取 `WS_DOWNLINK_BPS_DEFAULT`（见该常量），
 * **显式设 0 = 关闭**。取值建议略高于客户端实际下行能力，再用 debug 日志里的 `capWait`
 * 校准：`capWait≈0` 说明上限没咬住（客户端比你设的更慢，应调低）；`capWait` 接近
 * 窗口长度说明上限才是瓶颈（可调高）。
 */
function downlinkByteRate(): number {
    return Math.floor(envNumber('WS_DOWNLINK_BPS', WS_DOWNLINK_BPS_DEFAULT, true));
}

/**
 * 下行「突发额度」（字节）：令牌桶**容量**，与速率解耦。
 *
 * 为什么必须解耦：桶容量决定了「一条连接在开始被限速之前能灌多少字节进运行时队列」。
 * 旧实现容量 = 速率，于是速率设多大就意味着**每条连接可瞬时灌多少**；
 * 现场测速场景同时开 8 条 → 瞬时额度 80MB，128MB 的 isolate 直接被顶到平台回收
 * （表现仍是 `internal error; reference = …`，而不是 1102）。速率与突发是两件事：
 * 前者是长期平均，后者是单次尖峰的内存风险，必须分开设。
 *
 * env `WS_DOWNLINK_BURST_KB`（KB）：未设取 `WS_DOWNLINK_BURST_KB_DEFAULT`（3MiB）；**显式 0 = 沿用旧行为（容量 = 速率）**，
 * 作为回滚开关。本函数只算「策略」，`4 × 读块` 这个下界由 createByteGovernor 单独兜（唯一一处），
 * 避免两处各写一遍同一条不变式。
 *
 * ⚠️ 容量 × 连接上限就是**单次尖峰的上界**：3MiB × `WS_MAX_CONNECTIONS`(256) = 768MiB，
 * 是 isolate 128MB 上限的 6 倍。这个乘积只会在「所有连接同时被灌满且都发不出去」时成立，
 * 但它正是本保护要防的那种场景 —— 调大这三者中任意一个都要重新算这个乘积。
 */
const WS_DOWNLINK_BURST_KB_DEFAULT = 3072;

function downlinkBurstBytes(bytesPerSec: number): number {
    const kb = envNumber('WS_DOWNLINK_BURST_KB', WS_DOWNLINK_BURST_KB_DEFAULT, true);
    // 显式 0：容量退回「速率」，即改动前的行为
    if (!kb) return bytesPerSec;
    return Math.min(bytesPerSec, Math.floor(kb * 1024));
}

/**
 * 字节令牌桶。容量由调用方给定（见 {@link downlinkBurstBytes}），但恒 ≥ `4 × 读块`：
 * 必须**大于单块上限**，否则「块大于桶」会让 take() 永远等不满而死锁。
 * 等待一律让出事件循环（1~50ms 分片），不做忙等。
 */
function createByteGovernor(bytesPerSec: number, capacityBytes: number) {
    const capacity = Math.max(4 * DOWNLOAD_BLOCK_SIZE, capacityBytes);
    let credit = capacity;
    let last = Date.now();
    let waitedMs = 0;
    return {
        async take(bytes: number): Promise<void> {
            for (;;) {
                const now = Date.now();
                credit = Math.min(capacity, credit + ((now - last) / 1000) * bytesPerSec);
                last = now;
                if (bytes <= credit) {
                    credit -= bytes;
                    return;
                }
                const need = Math.ceil(((bytes - credit) / bytesPerSec) * 1000);
                const wait = Math.max(1, Math.min(need, 50));
                waitedMs += wait;
                await new Promise<void>((resolve) => setTimeout(resolve, wait));
            }
        },
        /**
         * 取走「自上次调用以来」的累计节流等待毫秒，**读取即清零**。
         * 必须清零：仪表的分母是「本报告窗口」的毫秒数，若这里返回累计值，
         * 从第二个窗口起 capWait 会恒大于窗口长度（看起来像 100%+ 一直在咬），
         * 校准方向就被带反了。
         */
        takeWaited(): number {
            const value = waitedMs;
            waitedMs = 0;
            return value;
        },
    };
}

/**
 * `send()` 若返回 thenable 就 await（＝真背压），返回 void 时等价于直接调用。
 *
 * workers-types 声明 `send(): void`，但运行时可能返回 Promise；这里统一探测一次，
 * **有就等、没有就照旧**，因此对当前运行时的行为零变化，而在会返回 Promise 的运行时上
 * 直接获得背压。**唯一实现**：unified.ts 的测速 204 响应路径也用它（此前那里有一份
 * 逐字相同的副本，已合并）。
 * 只用于直发路径：batcher 的 flush() 是同步函数，塞不进 await（见 flush 处注释）。
 */
export async function sendAndWaitIfPossible(webSocket: WebSocket, payload: Uint8Array): Promise<void> {
    const result: unknown = (webSocket as any).send(payload);
    if (result && typeof (result as { then?: unknown }).then === 'function') await result;
}

/**
 * 连接数类 env 的统一钳制：**WS 与 XHTTP 共用这一份**（两边都曾有各自的 1 / 1024 常量）。
 * 下界 1（0 会被错解成"全拒"，所以 0 走 fallback）；上界 1024（只作笔误护栏，不代表内存可行）。
 */
const CONNECTION_LIMIT_FLOOR = 1;
const CONNECTION_LIMIT_CEILING = 1024;
/** 钳制区间对外暴露（警告文案要打印它，测试也钉这句文案） */
export const CONNECTION_LIMIT_RANGE = `${CONNECTION_LIMIT_FLOOR}~${CONNECTION_LIMIT_CEILING}`;

/** 解析连接数 env：返回原始值（用于日志对比）与钳制后的生效值 */
export function envConnectionLimit(name: string, fallback: number): { raw: number; value: number } {
    const raw = envNumber(name, fallback);
    const value = Math.min(CONNECTION_LIMIT_CEILING, Math.max(CONNECTION_LIMIT_FLOOR, Math.floor(raw)));
    return { raw, value };
}

/**
 * 从 env 读数值。语义（顺序即判据）：
 *   - **未设 / 空串** → `fallback`；
 *   - 非数字、负数 → `fallback`（fail-closed：设错了不能静默变成"无上限"或"全关"）；
 *   - **显式 0** → `zeroMeansOff` 时返回 0（关闭），否则仍是 `fallback`；
 *   - 正数 → 原值。
 *
 * 为什么必须区分「未设」与「显式 0」：默认值一旦不是 0（如下行速率、会话预算），
 * `?? 0` 的写法会把"没设"也当成 0 —— 默认值就永远不生效（本仓库踩过这个坑）。
 * 同时保留显式 0 = 关闭，否则"改默认值"等于"永久失去回滚开关"。
 * 三处（会话字节预算、下行速率、上行 isolate 预算）共用这一份实现。
 */
export function envNumber(name: string, fallback: number, zeroMeansOff = false): number {
    const value = (globalThis as any).env?.[name];
    if (value === undefined || value === null || value === '') return fallback;
    const raw = Number(value);
    if (!Number.isFinite(raw) || raw < 0) return fallback;
    if (raw === 0) return zeroMeansOff ? 0 : fallback;
    return raw;
}

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
    // 出口帧长抖动：每连接在「3/4 基准 .. 5/4 基准」随机取（基准 32KiB → 24~40KiB），
    // 消除固定帧长的长度指纹。抖动**下限**同时是 remoteSocketToWS 的分流阈值：
    // 不变式 = **进入 batcher 的块一定 < 下限 ≤ PACKET_SIZE**（见 flush 里的说明）。
    const PACKET_SIZE = DOWNLOAD_PACKET_MIN + Math.floor(Math.random() * (DOWNLOAD_PACKET_SIZE / 2 + 1));
    const TAIL = DOWNLOAD_TAIL;                 // 512
    const LOW_WATER = Math.max(4096, TAIL << 3); // 4096
    // 攒批缓冲**懒分配**：只在第一次收到小块时才占这 24~40KiB。
    // 只跑大块直发的连接（4K 下行几乎全是 ≥24KiB 的块）、以及只做 DNS/测速/握手失败就结束的连接，
    // 按旧实现各自白占一块；256 连接上限下这部分最多是 ~10MB 的恒定开销。
    let buffer: Uint8Array<ArrayBuffer> | null = null;
    // 交出后待复用的那块：flush 把当前块的**视图**交给 send()，随后改用另一块，
    // 交出去的那块要等下一轮 flush 才会被复用（依据：webSocket.send() 是同步 API，
    // 载荷在调用时即被复制进待发队列、view 不被保留；即便运行时延迟复制，也有一整代缓冲间隔）。
    let spareBuffer: Uint8Array<ArrayBuffer> | null = null;
    let buffered = 0;
    let timer: ReturnType<typeof setTimeout> | 0 = 0;
    let scheduled = false;
    let writeCount = 0;
    let lastWriteCount = 0;
    let retryCount = 0;

    function flush() {
        if (timer) { clearTimeout(timer); timer = 0; }
        scheduled = false;
        const used = buffer;
        if (!buffered || !used) { buffered = 0; return; }
        const length = buffered;
        buffered = 0;
        retryCount = 0;
        // 交换而非重分配：交出 used，下一帧写进另一块。
        // 旧实现每次 flush 都在 queueMicrotask 之后做 subarray().slice() 再 new Uint8Array(PACKET_SIZE)，
        // 一次 flush 一次拷贝 + 一次分配（实测 16KiB 读路径 0.57ms/MB → 单拷贝实现 0.079ms/MB）。
        // 没有 spare 时把 buffer 置 null 而不是立刻分配第二块：只 flush 一次的连接（短连接、
        // 只跑小块的连接）永远不会为「下一块」付内存。
        if (spareBuffer) {
            buffer = spareBuffer;
            spareBuffer = used;
        } else {
            spareBuffer = used;
            buffer = null;
        }
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
            webSocket.send(used.subarray(0, length));
        }
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
            // 契约：只有小于 DOWNLOAD_PACKET_MIN 的块会进到这里（见 remoteSocketToWS 的分流），
            // 因此这里**一律拷贝**进合帧缓冲，绝不把调用方的缓冲按引用交给 send()。
            // 旧实现有一条「缓冲为空且剩余 ≥ PACKET_SIZE 就按引用直发」的捷径：在调用方改用
            // 可复用缓冲池之后，它会把手头即将被复用的内存交出去，故已删除（现在也进不来）。
            while (offset < total) {
                // 缓冲懒分配：没小块流量的连接不为它付内存
                const dst = buffer ?? (buffer = new Uint8Array(PACKET_SIZE));
                const size = Math.min(PACKET_SIZE - buffered, total - offset);
                dst.set(data.subarray(offset, offset + size), buffered);
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

/**
 * B-13：WS **会话级**下行记账。
 *
 * 回退阶梯（上游代理 → 反代池 → 官方池 → 直连）每换一条 socket 都会重新调用
 * `remoteSocketToWS`。预算 / 令牌桶 / 累计字节原本是函数局部变量 —— **每换一次就重置一次**，
 * 于是客户端只要让首字节超时发生一次，就能在同一条 WS 上把 900MiB 预算与
 * `WS_DOWNLINK_BURST_KB` 的突发额度重复兑现，恰好绕过这条保护要防的「isolate 被打死」场景。
 *
 * 以 WebSocket 为键：一条会话只有一个 WS，连接结束后随 WS 一起被 GC，无需手工清理。
 * `budgetExceeded` 刻意**不**放进来 —— 它表示「本次挂载已收口」，必须保持 per-mount，
 * 否则第二次重挂会立刻把刚建立的会话关掉（客户端表现为抖动重连）。
 */
interface DownlinkSessionState {
    budget: number;
    sent: number;
    governor: ReturnType<typeof createByteGovernor> | null;
}

const downlinkSessionStates = new WeakMap<WebSocket, DownlinkSessionState>();

function getDownlinkSessionState(webSocket: WebSocket, rate: number): DownlinkSessionState {
    let state = downlinkSessionStates.get(webSocket);
    if (!state) {
        state = {
            budget: sessionByteBudget(),
            sent: 0,
            governor: rate ? createByteGovernor(rate, downlinkBurstBytes(rate)) : null
        };
        downlinkSessionStates.set(webSocket, state);
    }
    return state;
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
    /**
     * BYOB 读缓冲的「三槽」管理。
     *
     * 关键事实（Streams 规范，实测已确认）：`read(view)` 会 **transfer（detach）传入的 view 缓冲区**，
     * 并把数据搬到它解析出来的 `value.buffer` 上（同一块内存的新身份）。因此：
     *   - 同一块 ArrayBuffer **不能**跨两次 read 复用（第二次会在构造 view 时抛 TypeError）；
     *   - 但每轮把槽刷新成 `value.buffer` 就可以继续用，且**不产生新的内存分配**（transfer 是移动不是拷贝）。
     * 旧实现每读一块就 `new ArrayBuffer(64KiB)`（真正的零化 + 分配），正是下行最贵的单项。
     *
     * 为什么是**三**槽（而不是两槽）：交出去给 `send()` 的那块，必须隔足够远才被再次用作读目标。
     * 两槽时复用距离只有 1 次 read+send，安全性完全押在"send() 在调用时同步复制"这个运行时语义上
     * （Workers 文档没写死，XHTTP 侧我们也判定过"一代不够"）。三槽把距离拉到 2 代，
     * 即便某个运行时把复制推迟一整轮，也不会读到被覆盖的数据。槽位按需分配：只做小块的连接
     * （不 rotate）永远只用 1 块。
     */
    const byobPool: (ArrayBuffer | null)[] = [null, null, null];
    let byobIndex = 0;
    const takeBlock = (): ArrayBuffer =>
        byobPool[byobIndex] ?? (byobPool[byobIndex] = new ArrayBuffer(DOWNLOAD_BLOCK_SIZE));
    /** 本轮 read 已把传入缓冲 transfer 走，槽位改记「解析出来的那块」；尺寸异常时退回新分配 */
    const refreshBlock = (readValue: any): void => {
        const next = readValue?.buffer;
        byobPool[byobIndex] = next instanceof ArrayBuffer && next.byteLength >= DOWNLOAD_BLOCK_SIZE
            ? next
            : new ArrayBuffer(DOWNLOAD_BLOCK_SIZE);
    };
    const rotateBlock = (): void => { byobIndex = (byobIndex + 1) % 3; };
    // 会话级下行字节预算 / 速率上限（均可在 env 里关闭或调参）。
    // B-13：三者都取会话级实例（见 getDownlinkSessionState），回退重挂时复用同一份。
    const downlinkRate = downlinkByteRate();
    const session = getDownlinkSessionState(webSocket, downlinkRate);
    const byteBudget = session.budget;
    const governor = session.governor;
    let budgetExceeded = false;
    // 1 秒粒度仪表：默认跟随面板 Log Level=debug；`WS_DOWNLINK_STATS=1` 可单独打开
    // （运维只想快照一行吞吐、不想为此改面板设置；测试也用它，避免依赖 KV 里的 settings）
    const statsOn = (globalThis as any).settings?.logLevel === 'debug'
        || envNumber('WS_DOWNLINK_STATS', 0) > 0;
    let statAt = Date.now();
    let statBytes = 0;
    let statFrames = 0;
    let statMaxBlock = 0;
    const reportStats = (): void => {
        if (!statsOn) return;
        const now = Date.now();
        const elapsed = now - statAt;
        if (elapsed < 1000) return;
        const secs = elapsed / 1000;
        log(`downlink ${(statBytes / secs / 1024).toFixed(0)}KiB/s frames=${statFrames}`
            + ` maxBlock=${statMaxBlock}B total=${(session.sent / 1048576).toFixed(1)}MiB`
            + (governor ? ` cap=${downlinkRate}B/s capWait=${governor.takeWaited()}ms/${elapsed}ms` : ' cap=off')
            + (byteBudget ? ` budget=${byteBudget}B` : ' budget=off'));
        statAt = now;
        statBytes = 0;
        statFrames = 0;
        statMaxBlock = 0;
    };

    try {
        // Try BYOB reader first (zero-copy, reusable buffer)
        try {
            reader = (remoteSocket.readable as any).getReader({ mode: 'byob' });
        } catch {
            isByob = false;
            reader = remoteSocket.readable.getReader();
        }

        for (;;) {
            // 节流必须在 read 之前：不读，socket 就不再收，TCP 窗口才会退给上游 —— 这才是端到端背压
            reportStats();
            const result = isByob
                ? await (reader as any).read(new Uint8Array(takeBlock(), 0, DOWNLOAD_BLOCK_SIZE))
                : await reader!.read();
            if (result.done) break;
            const readValue = result.value;
            // 本轮的缓冲已被 transfer 走，槽位立刻改记新身份（小块的下一轮读也靠它复用）
            if (isByob) refreshBlock(readValue);
            let chunk = toUint8Array(readValue);
            if (!chunk.byteLength) continue;
            // 下行有真实流量 → 刷新会话空闲计时（与上行同一个看门狗；见 startWsSessionGuard）
            touchWsSession(webSocket);

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

            // 会话字节预算：超限即主动收口。计数是**会话级**的（B-13），回退重挂不清零。
            session.sent += chunk.byteLength;
            if (byteBudget && session.sent > byteBudget) {
                log(`session downlink budget ${(byteBudget / 1048576).toFixed(0)}MiB reached, closing (client reconnects)`);
                budgetExceeded = true;
                break;
            }

            // 速率上限：令牌不足就让出事件循环。**默认开启**（见 downlinkByteRate），
            // 只有 env `WS_DOWNLINK_BPS=0` 时 governor 才为 null —— 那时这里是一条空判，零开销
            if (governor) await governor.take(chunk.byteLength);

            if (statsOn) {
                statBytes += chunk.byteLength;
                statFrames++;
                if (chunk.byteLength > statMaxBlock) statMaxBlock = chunk.byteLength;
            }

            // 分流阈值取帧长抖动的下限（24KiB），保证走 batcher 的块**一定**小于 PACKET_SIZE，
            // 从而 batcher 里「按引用直接 send」的分支永不触发（它会把即将复用的池缓冲交出去）。
            if (chunk.byteLength >= DOWNLOAD_PACKET_MIN) {
                batcher.flush();
                // 量的主体在这条路径（4K 下行几乎全是大块），所以背压也只做在这里
                await sendAndWaitIfPossible(webSocket, chunk);
                // 交出的是池里整块的视图（send 同步复制）；改用另一块，隔一代再复用
                if (isByob) rotateBlock();
            } else {
                // 小块：交给 batcher 合帧。batcher 内部必然 buffer.set 拷贝一次，因此无需先 slice()
                //（旧实现这里还有一次 chunk.slice()，同一段数据被拷了两遍）
                batcher.send(chunk);
            }
        }

        batcher.flush();
    } catch (error) {
        // B-23：这里原先是 `catch (error)` 但 error 从未被使用 —— 下行泵把**所有**上游读错误
        // 静默压成「关 WS」，客户端看到 1005 正常关闭、日志里一片空白。
        // 「播放中途断流」这类问题因此完全无法从服务端定位。已有流量之后才报的错才值得记一行。
        if (hasIncomingData && !budgetExceeded) {
            log(`downlink error after ${(session.sent / 1024).toFixed(0)}KiB: ${safeErrorMessage(error)}`);
        }
        // Don't close WS if retry is about to re-mount a new socket
        if (!hasRetryFired) safeCloseWebSocket(webSocket);
    } finally {
        try { batcher.flush(); } catch {}
        try { reader?.releaseLock(); } catch {}
    }

    // 预算耗尽的收口：主动关 WS（其 close 事件会让上行泵结束并关掉后端 socket），
    // 而不是等平台用 1102 把整个 isolate 一起打死。
    if (budgetExceeded) safeCloseWebSocket(webSocket);

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
 *
 * 导出给 XHTTP 入站：XHTTP 没有真正的 WebSocket，handleUDPOutBound 登记的 DNS socket 清理钩子
 * 不会由 WS 事件触发，必须由 XHTTP 在流结束时手动排空（复用同一份钩子表，不另建一套）。
 */
export function runWsCleanupHooks(webSocket: WebSocket): void {
    const hooks = wsCleanupHooks.get(webSocket);
    if (!hooks) return;
    wsCleanupHooks.delete(webSocket);
    for (const hook of hooks) {
        try { hook(); } catch (error) { console.error('ws cleanup hook failed', error); }
    }
}

// ===== 会话生命周期上限：空闲超时 / 最长存活 =====
/**
 * 为什么需要它（2026-11 线上现场数据）：
 * 平台会在「运行时更新宽限 ≈ 20 分钟」这类周期性动作里把长连接 **load-shed** 掉
 * （Workers Logs: `$workers.outcome = "loadShed"`，wallTimeMs ≈ 1.17e6，cpuTimeMs ≈ 20），
 * 客户端看到的是 1101 `internal error; reference = …`。
 *
 * 关键在于：`WS_SESSION_MAX_MB` 是**按已发送字节**算的，一条低速/空闲会话永远触发不了它
 * （现场那条 19 分钟只花了 20ms CPU），于是只能等平台动手。这里改成我们**先**干净 close()：
 * 客户端立刻自动重连（无错误页、无 1101），平台也就没机会 shed 它。
 *
 * 默认值都刻意小于平台的 ~20 分钟窗口：
 *   - `WS_IDLE_TIMEOUT_S` 600s：双向都无流量 10 分钟 → 判为死连接，关掉；
 *   - `WS_MAX_SESSION_S`  900s：单连接最长存活 15 分钟 → 强制换一条新连接。
 * 两者都可 env 覆盖，**显式 0 = 关闭该保护**（与其它 WS_* 旋钮同一套 envNumber 语义）。
 */
const WS_IDLE_TIMEOUT_S_DEFAULT = 600;
const WS_MAX_SESSION_S_DEFAULT = 900;

/** 按连接登记看门狗。用 WeakMap：连接被回收时登记项自动消失，不需要显式遍历清理 */
const wsSessionGuards = new WeakMap<WebSocket, SessionWatchdog>();
/** 「生效值只在 env 变化时打一行」的闸门（与伪装熔断、连接上限共用同一实现） */
const sessionLimitsGate = createSignatureGate();

function wsSessionLimits(): { idleMs: number; maxMs: number } {
    return {
        idleMs: Math.floor(envNumber('WS_IDLE_TIMEOUT_S', WS_IDLE_TIMEOUT_S_DEFAULT, true) * 1000),
        maxMs: Math.floor(envNumber('WS_MAX_SESSION_S', WS_MAX_SESSION_S_DEFAULT, true) * 1000)
    };
}

/** WS 侧的粒度策略 = 「较小上限的 1/10」，夹在 [250ms, 5s]：默认 600s/900s → 5s；测试 1s → 250ms */
function sessionWatchdogMs(idleMs: number, maxMs: number): number {
    const smallest = Math.min(idleMs || Infinity, maxMs || Infinity);
    if (!Number.isFinite(smallest)) return WATCHDOG_INTERVAL_MS;
    return Math.max(250, Math.min(WATCHDOG_INTERVAL_MS, Math.floor(smallest / 10)));
}

/** 生效值只在 env 变化时打一行（对齐 camouflage 的预算日志），便于灰度期核对 */
function logSessionLimitsOnce(idleMs: number, maxMs: number, log: Function): void {
    if (!sessionLimitsGate.isNew(`${idleMs}/${maxMs}`)) return;
    log(`session guard: idle=${idleMs ? `${idleMs / 1000}s` : 'off'} max=${maxMs ? `${maxMs / 1000}s` : 'off'}`);
}

/**
 * 为一条 WS 会话启动看门狗。必须在 `webSocket.accept()` 之后调用。
 * 到期收口走 onExpire（一次性，由 createSessionWatchdog 保证），外部收口走清理钩子。
 */
export function startWsSessionGuard(webSocket: WebSocket, log: Function): void {
    const { idleMs, maxMs } = wsSessionLimits();
    logSessionLimitsOnce(idleMs, maxMs, log);
    // 两项都关（显式 0）：不登记、不挂清理钩子 —— 关掉的保护不该在每条连接上留一份残留
    if (!idleMs && !maxMs) return;

    const guard = createSessionWatchdog({
        idleMs,
        maxMs,
        intervalMs: sessionWatchdogMs(idleMs, maxMs),
        // 别处已关掉它（客户端断开 / 上行积压收口 / 字节预算耗尽）：停表，不留空转定时器
        isAlive: () => webSocket.readyState === WS_READY_STATE_OPEN,
        onExpire: (reason: string): void => {
            wsSessionGuards.delete(webSocket);
            log(`session ${reason}，主动关闭（客户端会立即重连）`);
            safeCloseWebSocket(webSocket);
        }
    });

    wsSessionGuards.set(webSocket, guard);

    // 任何收口路径都会跑清理钩子 → 统一在这里停表并注销
    registerWsCleanup(webSocket, () => {
        guard.stop();
        wsSessionGuards.delete(webSocket);
    });
}

/** 记一次双向流量。未登记（如 XHTTP 入站）时是无副作用的 no-op。 */
export function touchWsSession(webSocket: WebSocket): void {
    wsSessionGuards.get(webSocket)?.touch();
}

/**
 * 上行背压阈值：WS 没有 pause/暂停 API（客户端发多少，message 事件就触发多少次），
 * 「消费者落后」只能靠**主动收口**处理 —— 丢帧会破坏被代理的 TCP 字节流，所以唯一正确的
 * 做法是关连接。
 *
 * `maxQueuedBytes` 由调用方按当前活动连接数折算后传入（isolate 级预算 ÷ 连接数）。
 * 它是**必填参数**而不是带默认值的可选参数：唯一的调用方恒会传值，留一个 8MiB 的默认值
 * 只会让人误以为"每连接默认 8MiB 有保护"，而 N 条连接各 8MiB 正是要消除的"整体无界"。
 */
const WS_UPLINK_HIGH_WATER = 64 * 1024;

export function makeReadableWebSocketStream(
    webSocketServer: WebSocket,
    earlyDataHeader: string,
    log: Function,
    maxQueuedBytes: number
): ReadableStream<ArrayBuffer> {
    let readableStreamCancel = false;
    const stream = new ReadableStream<ArrayBuffer>({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) return;
                // 背压：desiredSize = 高水位 − 已入队未读字节；为负说明消费者（上行泵）落后。
                // 落后超过上限说明后端已堵死或客户端在猛灌，此时继续 enqueue 只会让 isolate
                // 内存无界增长 → 持续 GC（GC 时间全额计入 CPU）→ 1102。
                const desired = controller.desiredSize;
                if (desired !== null && -desired > maxQueuedBytes) {
                    log(`uplink backlog ${-desired}B exceeds ${maxQueuedBytes}B, closing WS`);
                    readableStreamCancel = true;
                    safeCloseWebSocket(webSocketServer);
                    // 用 error() 而不是 close()：close 会让泵把队列里剩余的最多 maxQueuedBytes
                    // 逐个读出来再写进一个已经堵死的后端（既慢又不释放内存）；error() 让泵的
                    // read 直接抛错 → failUplink → 关后端 socket 的**唯一**收口。
                    try { controller.error(new Error('uplink backlog exceeded')); } catch (_) { /* 已 error/关闭，忽略 */ }
                    // 清理钩子里会强制关闭后端 socket（unified.ts 注册），
                    // 否则泵可能正卡在"写不出去"的 await 上永远不退出。
                    runWsCleanupHooks(webSocketServer);
                    return;
                }
                // 上行有真实流量 → 刷新会话空闲计时（空闲超时按"双向"判，纯上传的连接不该被误杀）
                touchWsSession(webSocketServer);
                // WebSocket binaryType='arraybuffer' ensures event.data is always ArrayBuffer
                //
                // B-21：这句注释只对**二进制帧**成立。text 帧仍以 string 投递，而
                // ByteLengthQueuingStrategy 对 string 取 `byteLength → undefined` → enqueue 抛 RangeError
                // （异常在事件监听器里，属未捕获，表现为「莫名管道异常」）。
                // B-22：close/error 之后迟到的 message 同样会对已关闭/已 error 的 controller 抛 TypeError。
                // 两处都在这里收口：过滤 text 帧，enqueue 失败即丢帧（不需要为此关掉整条会话）。
                if (typeof event.data === 'string') {
                    log('ignoring text frame on uplink');
                    return;
                }
                try {
                    controller.enqueue(event.data);
                } catch { /* 流已关闭/已 error：丢弃该帧 */ }
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
    // 字节口径的高水位：desiredSize 才是「已入队未读字节」的真实水位，默认计数策略拿不到它。
    // 策略只用于计算水位，chunk 类型仍是 ArrayBuffer（因此这里显式收窄一次）。
    }, new ByteLengthQueuingStrategy({ highWaterMark: WS_UPLINK_HIGH_WATER }) as unknown as QueuingStrategy<ArrayBuffer>);

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