import { getGeoAssets } from './geo-assets';
import { DNS, DnsRule, DnsServer } from '#types/sing-box';
import { accDnsRules, pickRandomEch, resolveDNS, isDomain, antiSanctionDohTarget } from '@utils';

/**
 * H7：解析节点自身域名的 hosts 静态 IP 服务器 tag。
 * 与 outbounds.ts 共用（非链式出站的 domain_resolver 指向它），两侧必须保持一致。
 */
export const NODE_DNS_TAG = "dns-node";

/**
 * 残留#6：制裁域名的明文兜底 DNS 服务器 tag（冻结口径里的 plainFallback）。
 * 只在用户输入未带 https:// 时生成，且只被 dns-anti-sanction 引用：DoH 端点是域名时作它的
 * domain_resolver（先用明文解析出 DoH 端点地址）；端点是裸 IP（如默认 178.22.122.100）时无需解析，
 * 该服务器因此不被引用——原因见 dns-anti-sanction 处的 failover 说明。
 */
const PLAIN_SANCTION_TAG = "dns-anti-sanction-plain";

/**
 * C3：ACL 模板接管后，内置分组出站（✅ Selector / 各类「最佳延迟」）会被从 config.outbounds 中移除，
 * 但 dns-remote 的 detour 仍指向它们 → sing-box 启动期解析出站失败，整份配置加载失败。
 * 该函数把仍指向「已被移除分组」的 detour 改写为确实存在的出站。
 *
 * 语义变化（必读）：detour 决定该 DNS 服务器由哪个出站解析。指向模板分组时与旧语义等价
 * （仍由代理组解析 DoH）；退回内置 `direct` 时 DoH 改为本地直连解析——不经代理，查询目标
 * 对该 DNS 服务器（默认 remoteDNS=8.8.8.8）可见，属隐私上的退让。之所以接受：另一种结局是
 * 指向不存在的出站导致整份配置无法加载，DNS 完全不可用，故「可加载」优先。
 * 只改写 removedGroups 内的 tag，指向 direct / 节点出站等其他有效 tag 时保持原样。
 */
export function retargetDnsDetour(dns: DNS, removedGroups: ReadonlySet<string>, target: string): void {
    for (const server of dns.servers) {
        if (server.detour && removedGroups.has(server.detour)) server.detour = target;
    }
}

export async function buildDNS(isWarp: boolean, isChain: boolean): Promise<DNS> {
    const {
        localDNS,
        remoteDNS,
        warpRemoteDNS,
        antiSanctionDNS,
        remoteDnsHost,
        enableIPv6,
        fakeDNS,
        enableECH,
        echServerName
    } = globalThis.settings;

    const url = new URL(remoteDNS);
    const protocol = url.protocol.replace(':', '');
    // 命名引用：下面「域名型 DoH 服务器需要 domain_resolver」处直接改这个对象
    const remoteServer: DnsServer = {
        type: isWarp ? "udp" : protocol,
        server: isWarp ? warpRemoteDNS : remoteDnsHost.host,
        detour: isWarp ? "Warp - 最佳延迟 🚀" : isChain ? "🔗 最佳延迟 🚀" : "✅ Selector",
        tag: "dns-remote"
    };
    const servers: DnsServer[] = [remoteServer];

    // 明文 DNS（localDNS）：dns-direct 与节点域名解析器的回退副本共用同一份定义
    const addLocalDnsServer = (tag: string) => {
        if (localDNS === 'localhost') {
            addDnsServer(servers, "local", tag, undefined, undefined, undefined);
        } else {
            addDnsServer(servers, "udp", tag, localDNS, undefined, undefined);
        }
    };

    addLocalDnsServer("dns-direct");

    // H7：节点自身域名（httpConfig.hostName）不再交给明文 localDNS 解析。
    // 用 hosts 静态 IP 服务器（独立 tag）把它钉在面板侧 DoH 解析出的 IP 上：既不走上游代理
    // （dns-remote 的 detour 是代理选择器/链式组，解析节点域名要先建隧道 → 成环），也不走明文 DNS。
    // 解析失败或拿不到 IP 时回退为 dns-direct 的副本（仅 tag 不同、行为与改动前一致），
    // 保证 outbounds.ts 对 NODE_DNS_TAG 的引用永不悬空、配置不会因解析失败而加载失败。
    // 非 warp 配置恒生成该 tag；warp 配置的出站走 buildWarpOutbound（configs.ts），不使用它。
    const nodeHostName = globalThis.httpConfig?.hostName;
    const nodeIPs = !isWarp && !!nodeHostName && isDomain(nodeHostName)
        ? await resolveNodeIPs(nodeHostName, enableIPv6)
        : [];

    if (nodeIPs.length) {
        addDnsServer(servers, "hosts", NODE_DNS_TAG, undefined, undefined, undefined, nodeHostName, nodeIPs);
    } else if (!isWarp) {
        addLocalDnsServer(NODE_DNS_TAG);
    }

    const rules: DnsRule[] = [
        {
            clash_mode: "Direct",
            server: "dns-direct"
        },
        {
            clash_mode: "Global",
            server: "dns-remote"
        }
    ];

    if (enableECH) {
        const { hostName } = globalThis.httpConfig;
        // H3：ECH 配置查询（HTTPS RR）改走 DoH（dns-remote），不再用明文 dns-direct。
        // 残留#2：echServerName 未配置时查询对象就是节点自身域名（hostName）。旧写法在这种最常见的
        // 空名单形态下仍退回 dns-direct（明文），把「开了 ECH 又用明文把要查的域名交出去」的自我抵消留着。
        // 现在空名单也走 dns-remote，判据是**解析环已断**（下述三条均按本文件/outbounds.ts 实际代码核过）：
        //   1) 非链式 + nodeIPs 非空：节点域名由 hosts 静态 IP 服务器 NODE_DNS_TAG 解析（见上方 nodeIPs 分支），
        //      解析它不需要任何 DNS 查询；而 dns-remote 的 detour 是出站分组 "✅ Selector"（见 servers[0]），
        //      「查 HTTPS RR → 经代理隧道 → 建隧道要节点 IP」，节点 IP 已静态钉死、不回头查 DNS → 无环。
        //   2) 链式：dns-remote 的 detour 是链式分组 "🔗 最佳延迟 🚀"，而链式出站自身的服务器域名解析
        //      （outbounds.ts:54，isChain=true）也指向 dns-remote → 查域名要先建隧道、建隧道又要查域名 → 成环，
        //      故链式保持 dns-direct（本改动只对非链式放开）。
        //   3) warp / hostName 非域名 / 面板侧解析失败（nodeIPs 为空；其中 !isWarp 时 NODE_DNS_TAG 退化为
        //      dns-direct 的副本）：不满足第 1 条的静态前提，同样保持 dns-direct，不扩大改动面。
        // 条件表达式（与派发口径逐字一致）：echName || (!isChain && nodeIPs.length) ? 'dns-remote' : 'dns-direct'
        const echName = pickRandomEch(echServerName);
        // G13-C10：空名单时回退到该节点自身域名（`pickRandomEch(echServerName) || hostName`），
        // 与 handlers.ts:876 的 URI 侧（`pickRandomEch(echServerName) || host`）取同一口径；
        // 且与出站侧一致：出站 ech.query_server_name 同样因空名单而为 undefined → sing-box 改用
        // server_name（= 节点 SNI）查 HTTPS RR，也是该域名。
        addDnsRule(rules, echName || (!isChain && nodeIPs.length) ? 'dns-remote' : 'dns-direct', undefined, undefined, undefined, [echName || hostName], ["HTTPS"]);
    }

    if (remoteDnsHost.isDomain && !isWarp) {
        const { ipv4, ipv6, host } = remoteDnsHost;
        const predefined = ipv4.concatIf(enableIPv6, ipv6);
        addDnsServer(servers, "hosts", "hosts", undefined, undefined, undefined, host, predefined);
        // 域名型 DoH 服务器（server 是域名）必须能解析自身地址 → 指向上面的静态 hosts 服务器
        //（面板侧已解析出 IP，无需真实 DNS 查询，无环）。这正是 sing-box 1.12+ 对「域名型 DNS 服务器」
        // 的正规机制 domain_resolver。
        // 旧写法 `rules.unshift({ ip_accept_any: true, server: "hosts" })` 必须移除：`ip_accept_any` 属
        // Response Match Fields（sing-box 1.14 起要求 match_response），较新内核启动期直接拒载整份配置：
        // `validate dns rule[0]: Response Match Fields (...) require match_response to be enabled`。
        remoteServer.domain_resolver = { server: "hosts", strategy: "ipv4_only" };
    }

    const assets = getGeoAssets();
    const dnsRules = accDnsRules(assets);

    const blockDomains = [
        ...dnsRules.block.geosites,
        ...dnsRules.block.domains
    ];

    if (blockDomains.length) {
        addDnsRule(
            rules,
            'reject',
            undefined,
            dnsRules.block.geosites,
            undefined, 
            dnsRules.block.domains
        );
    }

    dnsRules.bypass.localDNS.geositeGeoips.forEach(({ geosite, geoip }) => {
        addDnsRule(
            rules,
            'dns-direct',
            undefined,
            [geosite], 
            geoip,
            undefined
        );
    });

    const bypassDomains = [
        ...dnsRules.bypass.localDNS.geosites,
        ...dnsRules.bypass.localDNS.domains
    ];

    if (bypassDomains.length) {
        addDnsRule(
            rules,
            'dns-direct',
            undefined,
            dnsRules.bypass.localDNS.geosites,
            undefined,
            dnsRules.bypass.localDNS.domains
        );
    }

    const sanctionDomains = [
        ...dnsRules.bypass.antiSanctionDNS.geosites,
        ...dnsRules.bypass.antiSanctionDNS.domains
    ];

    if (sanctionDomains.length) {
        // 残留#6（H7）：制裁域名不再用明文 DNS 解析。面板输入框（settings.antiSanctionDNS）仍是唯一权威
        // 来源——不新增设置项，只按冻结口径（三端一致）派生：
        //   输入已带 https:// → dohUrl = 原样（用户显式给了完整 DoH 端点），无明文兜底；
        //   否则              → dohUrl = https://<输入>/dns-query，明文 <输入> 作兜底。
        // 裸 IPv6 必须加方括号，否则 `https://2001:db8::1/dns-query` 不是合法 URL（与 xray 端同一判据）。
        // 端点派生（含方括号归一与明文兜底）由 @utils 的 antiSanctionDohTarget 统一维护。
        const { dohUrl, plainFallback } = antiSanctionDohTarget(antiSanctionDNS);
        const doh = parseDohUrl(dohUrl);

        addDnsRule(
            rules,
            'dns-anti-sanction',
            undefined,
            dnsRules.bypass.antiSanctionDNS.geosites,
            undefined,
            dnsRules.bypass.antiSanctionDNS.domains
        );

        // 明文兜底先入栈：DoH 端点若是域名，它就是 dns-anti-sanction 的 domain_resolver（tag 必须先存在）。
        // 关于「兜底」：sing-box 的 DNS 没有 failover——规则首条匹配即定，服务器只有 server/detour/
        // domain_resolver 三个相关字段（SagerNet/sing-box#1154「DNS fallback」至今未实现）。
        // 故本端能表达的兜底只有「用明文先解析出 DoH 端点自身的地址」；端点是裸 IP 时无需解析，
        // 该服务器不被任何规则引用（保留它是为与另两端口径一致：用户把输入改成域名即自动生效）。
        // domain_resolver 指向 dns-direct（明文 localDNS，裸 IP）→ 不再引入第二层解析，无环。
        if (plainFallback) {
            addDnsServer(servers, "udp", PLAIN_SANCTION_TAG, plainFallback, undefined,
                isDomain(plainFallback) ? "dns-direct" : undefined);
        }

        // DoH 主服务器：server 只填 host；path/端口只在用户显式写出时随附（见 parseDohUrl）。
        // detour 保持 undefined（直连）：制裁 DNS 必须由客户端本地直连发问，若走出站代理，
        // 返回的会是「境外视角」的解析结果，与 anti-sanction 语义相反；
        // 端点本身是裸 IP/域名，也没有 domain_resolver 指向会被它自己解析的东西（无环）。
        addDnsServer(servers, "https", "dns-anti-sanction", doh.host, undefined,
            isDomain(doh.host) ? (plainFallback ? PLAIN_SANCTION_TAG : "dns-direct") : undefined,
            undefined, undefined, undefined, undefined, doh.path, doh.port);
    }

    if (fakeDNS) {
        addDnsServer(
            servers,
            "fakeip",
            "dns-fake",
            undefined,
            undefined,
            undefined,
            undefined,
            undefined,
            "198.18.0.0/15",
            enableIPv6 ? "fc00::/18" : undefined
        );

        addDnsRule(rules, "dns-fake", "tun-in", undefined, undefined, undefined, ["A", "AAAA"]);
    }

    return {
        servers,
        rules,
        strategy: enableIPv6 ? "prefer_ipv4" : "ipv4_only"
        // independent_cache 自 sing-box 1.14 弃用、1.16 将删除，且 1.14 源码里它已是**空操作**
        // （dns/router.go 仅在为 true 时调用 deprecated.Report，无任何行为）→ 删除：避免 1.14+ 打 WARN、
        // 1.16+ 因未知/已删字段直接拒配置。官方迁移口径即「remove the field」。
    }
}

/**
 * 残留#6：把冻结口径派生出的 DoH 端点 URL 拆成 sing-box https 服务器需要的字段。
 * - host：去掉 IPv6 字面量的方括号（sing-box 的 server 是「地址」不是 URL）；
 * - path：只在用户显式写了非默认路径时下发（sing-box https 默认 path 即 /dns-query）；
 * - port：只在 URL 里显式带端口时下发（sing-box 的 server_port 默认 443）。
 * 解析失败（畸形输入）退化为「整串当 host」，绝不抛错：宁可得到一个查不通的服务器，
 * 也不让订阅接口因 DNS 段构造异常而 500。
 */
function parseDohUrl(url: string): { host: string; port?: number; path?: string } {
    try {
        const parsed = new URL(url);
        return {
            host: parsed.hostname.replace(/^\[|\]$/g, ''),
            port: parsed.port ? +parsed.port : undefined,
            path: parsed.pathname && parsed.pathname !== '/dns-query' ? parsed.pathname : undefined
        };
    } catch {
        return { host: url };
    }
}

/**
 * 残留#6：sing-box 的 https 型 DNS 服务器另有 path / server_port 两个官方字段
 * （https://sing-box.sagernet.org/configuration/dns/server/https：path 默认 /dns-query、
 * server_port 默认 443），但 #types/sing-box.d.ts 的 DnsServer 未声明它们，本任务不允许改类型
 * 文件（只改 dns.ts / outbounds.ts），故用局部扩展类型承载：只有调用点显式传入时才写进输出，
 * 其余调用点的输出逐字不变（不传 → 两个 if 都不成立 → 对象与改动前完全一致）。
 */
type DnsServerWithHttpPath = DnsServer & { path?: string; server_port?: number };

function addDnsServer(
    servers: DnsServer[],
    type: string,
    tag: string,
    server?: string,
    detour?: string,
    domain_resolver?: string,
    host?: string,
    predefined?: string[],
    inet4_range?: string,
    inet6_range?: string,
    path?: string,
    server_port?: number
) {
    const entry: DnsServerWithHttpPath = {
        type,
        server,
        detour,
        domain_resolver: domain_resolver ? {
            server: domain_resolver,
            strategy: "ipv4_only"
        } : undefined,
        predefined: host ? { [host]: predefined } : undefined,
        inet4_range,
        inet6_range,
        tag
    };

    if (path) entry.path = path;
    if (server_port) entry.server_port = server_port;

    servers.push(entry);
}

function addDnsRule(
    rules: DnsRule[],
    dns: string,
    inbound?: string,
    geosite?: string[],
    geoip?: string,
    domain?: string[],
    query_type?: Array<"A" | "AAAA" | "HTTPS">
) {
    const isPair = geosite && geoip;
    rules.push({
        inbound,
        type: isPair ? 'logical' : undefined,
        mode: isPair ? 'and' : undefined,
        rules: isPair ? [
            { rule_set: geosite }, 
            { rule_set: geoip }
        ] : undefined,
        rule_set: geosite?.length && !geoip ? geosite : undefined,
        domain_suffix: domain?.omitEmpty(),
        query_type,
        action: dns === 'reject' ? 'reject' : 'route',
        server: dns === 'reject' ? undefined : dns
    });
}

/**
 * H7：用面板侧 DoH 双源（@utils resolveDNS）把节点自身域名解析成 IP。
 * 失败或无结果一律返回空数组、绝不抛错——调用点据此回退到 dns-direct 副本，
 * 避免解析失败导致用户拿到一份不可用的 sing-box 配置。
 */
async function resolveNodeIPs(host: string, enableIPv6: boolean): Promise<string[]> {
    try {
        const { ipv4, ipv6 } = await resolveDNS(host, !enableIPv6);
        return ipv4.concatIf(enableIPv6, ipv6);
    } catch {
        return [];
    }
}