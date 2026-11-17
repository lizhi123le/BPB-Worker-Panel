import { getGeoAssets } from './geo-assets';
import type { DNS, DnsServer, DnsHosts } from '#types/xray';
import { resolveDNS, isDomain, getDomain, accDnsRules, antiSanctionDohTarget, concatIf, omitEmpty } from '@utils';

export async function buildDNS(
    outboundAddrs: string[],
    isWorkerLess: boolean,
    isWarp: boolean,
    domainToStaticIPs?: string,
    customDns?: string,
    customDnsHosts?: string[]
): Promise<DNS> {
    const {
        localDNS,
        remoteDNS,
        warpRemoteDNS,
        antiSanctionDNS,
        remoteDnsHost,
        enableIPv6,
        fakeDNS
    } = globalThis.settings;

    const hosts: DnsHosts = {};
    const servers: DnsServer[] = [];

    if (remoteDnsHost.isDomain && !isWorkerLess && !isWarp) {
        const { ipv4, ipv6, host } = remoteDnsHost;
        hosts[host] = concatIf(ipv4, enableIPv6, ipv6);
    }

    if (domainToStaticIPs) {
        const { ipv4, ipv6 } = await resolveDNS(domainToStaticIPs, !enableIPv6);
        hosts[domainToStaticIPs] = [...ipv4, ...ipv6];
    }

    let skipFallback = true;
    let finalRemoteDNS = isWarp ? warpRemoteDNS : remoteDNS;

    if (isWorkerLess) {
        finalRemoteDNS = `https://${customDns}/dns-query`;
        if (customDns && customDnsHosts) hosts[customDns] = customDnsHosts;
        skipFallback = false;
    }

    const remoteDnsServer = buildDnsServer(finalRemoteDNS, undefined, undefined, undefined, undefined, "remote-dns");
    servers.push(remoteDnsServer);

    // H7：节点自身域名（outboundAddrs）改走 DoH，不再交给明文 localDNS。
    // 仅在 finalRemoteDNS 确为 DoH（https://）时启用；否则保持原有明文 localDNS 行为
    // （warp 配置下 warpRemoteDNS 默认是裸 IP 1.1.1.1，不应把明文查询换成另一个明文解析器）。
    // 单列一条带 domains 的服务器，而不依赖「默认服务器」回退：fakeDNS 开启时 fakedns 会被
    // unshift 到首位，仅靠默认回退会被解析成 fake IP。
    // 防环：DoH 端点自身若为域名，已由上方 hosts[remoteDnsHost.host] 或 hosts[customDns] 静态预置。
    const outboundDomains = outboundAddrs.filter(isDomain).map(domain => `full:${domain}`);
    const outboundDomainsOnDoH = /^https:\/\//i.test(finalRemoteDNS);
    if (outboundDomainsOnDoH && outboundDomains.length) {
        servers.push(buildDnsServer(finalRemoteDNS, outboundDomains));
    }

    const geoAssets = getGeoAssets();
    const dnsRules = accDnsRules(geoAssets);

    // B-46：这里原先还给每个 block 域名写 `hosts[domain] = '#3'`。两处都不对：
    //  1) Xray 的 `dns.hosts` 值语义是「IP 或可解析域名」，`#3` 两者都不是，等于一条垃圾记录；
    //  2) 它把 `geosite:…` 也塞进 hosts 的键（键只能是域名模式，Clash 端早已因同一原因移除）。
    // 拦截语义由**路由层**唯一承担（routing.ts 从同一份 geo 资产建 domain/geosite → block 规则），
    // 与 sing-box 的 route 规则、Clash 的 `RULE-SET…,REJECT` 对称，故整段删除。

    dnsRules.bypass.localDNS.geositeGeoips.forEach(({ geosite, geoip }) => {
        const localDnsServer = buildDnsServer(localDNS, [geosite], [geoip!], skipFallback);
        servers.push(localDnsServer);
    });

    const sanctionDomains = [
        ...dnsRules.bypass.antiSanctionDNS.geosites,
        ...dnsRules.bypass.antiSanctionDNS.domains.map(domain => `domain:${domain}`)
    ];

    const bypassDomains = [
        ...dnsRules.bypass.localDNS.geosites,
        ...dnsRules.bypass.localDNS.domains.map(domain => `domain:${domain}`),
        ...(outboundDomainsOnDoH ? [] : outboundDomains)
    ];

    // 残留 #6：制裁域名「优先 DoH，明文 IP 兜底」（clash/sing-box 同一口径）。
    // 面板输入 antiSanctionDNS 仍是唯一权威来源，不新增设置项：
    //   - 已带 https:// → 直接当 DoH 端点，无明文兜底；
    //   - 裸 IP/域名   → 拼 `https://<输入>/dns-query` 作 DoH，原地址留作明文兜底
    //     （伊朗对加密 DNS 有封锁，兜底不可省）。
    // 表达「优先 + 兜底」无需 Xray 新字段：sortClients 按 servers 出现顺序收集全部 domains 命中的
    // 条目，serialQuery 依次查询、前面取不到结果才用后面的，故「DoH 条目在前 + 明文条目在后」即原生语义
    // （app/dns/dns.go: sortClients/serialQuery）。finalQuery 只标在链尾（有明文兜底时标明文，否则标
    // DoH 那条）：命中后不再回落到默认 remoteDNS，与改动前单条 finalQuery:true 的语义保持一致。
    if (sanctionDomains.length) {
        // 裸 IPv6 必须加方括号，否则 `https://2001:db8::1/dns-query` 不是合法地址，xray 会启动失败。
        // 端点派生（含方括号归一与明文兜底）由 @utils 的 antiSanctionDohTarget 统一维护。
        const {
            dohUrl: antiSanctionDohUrl,
            plainFallback: antiSanctionPlainFallback
        } = antiSanctionDohTarget(antiSanctionDNS);

        servers.push(buildDnsServer(
            antiSanctionDohUrl,
            sanctionDomains,
            undefined,
            skipFallback,
            antiSanctionPlainFallback ? undefined : true
        ));

        if (antiSanctionPlainFallback) {
            servers.push(buildDnsServer(antiSanctionPlainFallback, sanctionDomains, undefined, skipFallback, true));
        }

        // 防环：DoH 端点若为域名，其自身域名必须先由明文 localDNS 解析（加入 bypass 列表），
        // 否则它会被这条 DoH 服务器反向依赖。裸 IP 端点无需处理。
        // 取 host 用 DoH URL 而非原始输入：new URL() 只接受带协议的字符串。
        const { host, isHostDomain } = getDomain(antiSanctionDohUrl);
        if (isHostDomain) bypassDomains.push(`full:${host}`);
    }

    customDnsHosts?.filter(isDomain).forEach(host => bypassDomains.push(`full:${host}`));

    if (bypassDomains.length) {
        const localDnsServer = buildDnsServer(localDNS, bypassDomains, undefined, skipFallback);
        servers.push(localDnsServer);
    }

    // B-51：fakeDNS 此前只对 **bypass（直连）域名**发假 IP —— 因为上面两处把 bypass 域名塞进
    // `fakeDnsDomains` 当成了 fakedns 服务器的 domains。而 sing-box（tun-in 全量 A/AAAA 发 fakeip）
    // 与 Clash（全域 fake-ip）都是「走代理的域名才发假 IP」，语义正好相反；更糟的是旁路列表为空时
    // `fakeDnsDomains.length === 0` 会退化成裸 "fakedns"（对**所有**域名发假 IP），行为整体翻转。
    // 现退化为裸 "fakedns"（无条件），与另两端同口径，并删掉那条反向依赖。
    if (fakeDNS || isWorkerLess) {
        servers.unshift("fakedns");
    }

    return {
        hosts: omitEmpty(hosts),
        servers,
        queryStrategy: isWarp && !enableIPv6 ? "UseIPv4" : "UseIP",
        tag: "dns"
    };
}

function buildDnsServer(
    address: string,
    domains?: string[],
    expectIPs?: string[],
    skipFallback?: boolean,
    finalQuery?: boolean,
    tag?: string
): DnsServer {
    return {
        address,
        domains,
        expectIPs,
        skipFallback,
        finalQuery,
        tag
    };
}