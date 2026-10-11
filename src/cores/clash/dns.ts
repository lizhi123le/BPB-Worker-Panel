import { getGeoAssets } from './geo-assets';
import { DNS, DnsHosts, FakeDNS } from '#types/clash';
import { isDomain, getDomain, accDnsRules, isIPv6 } from '@utils';

/**
 * C3：ACL 模板接管后，内置策略组（✅ Selector / 各类「最佳延迟」）被整体替换为模板分组，
 * 而 nameserver / nameserver-policy 里仍写着 `#<内置组>` 形式的 detour → mihomo 解析到
 * 不存在的策略组，该 DNS 条目失效。该函数把仍指向已移除组的 detour 改写为确实存在的组。
 *
 * 语义变化（必读）：detour 决定该 DNS 服务器由哪个策略组解析。指向模板分组时与旧语义等价
 * （仍由代理组解析 DoH）；退回内置 DIRECT 时 DoH 改为直连解析——不经代理，属隐私上的退让。
 * 之所以接受：另一种结局是引用不存在的策略组导致 DNS 策略整体不可用，故「有效引用」优先。
 * 仅改写 `#<removedGroups 中的组名>` 后缀：DIRECT（mihomo 内置代理）、DoH 主机名等一律保持原样。
 */
export function retargetDnsDetour(dns: DNS, removedGroups: ReadonlySet<string>, target: string): void {
    const rewrite = (value: string): string => {
        const sharp = value.lastIndexOf('#');
        if (sharp === -1) return value;
        const group = value.substring(sharp + 1).trim();
        return removedGroups.has(group) ? `${value.substring(0, sharp)}#${target}` : value;
    };
    dns.nameserver = dns.nameserver.map(rewrite);
    dns["proxy-server-nameserver"] = dns["proxy-server-nameserver"].map(rewrite);
    dns["direct-nameserver"] = dns["direct-nameserver"].map(rewrite);
    const policy = dns["nameserver-policy"];
    if (policy) {
        for (const key of Object.keys(policy)) policy[key] = rewrite(policy[key]);
    }
}

export async function buildDNS(isChain: boolean, isWarp: boolean, isPro: boolean): Promise<DNS> {
    // G13-C10：名称回退（空 echServerName → 该节点 host）已在 outbounds.ts#buildWebsocketOutbound 完成，
    // 即 Clash 的 `ech-opts.query-server-name` 不再落成 undefined；ECH 配置查询（HTTPS RR）的解析目标
    // 则由下方 nameserver-policy 指向远程 DoH（与 H3 的 Xray/sing-box 口径一致，见本函数末尾）。
    const {
        localDNS,
        remoteDNS,
        warpRemoteDNS,
        antiSanctionDNS,
        outProxyParams,
        remoteDnsHost,
        enableIPv6,
        fakeDNS,
        allowLANConnection,
        enableECH,
        echServerName
    } = globalThis.settings;

    const finalLocalDNS = localDNS === 'localhost' ? 'system' : `${localDNS}#DIRECT`;
    const proSign = isPro ? "Pro " : "";
    const remoteDnsDetour = isWarp
        ? `Warp ${proSign}- 最佳延迟 🚀`
        : isChain ? "🔗 最佳延迟 🚀" : "✅ Selector";

    const finalRemoteDNS = `${isWarp ? warpRemoteDNS : remoteDNS}#${remoteDnsDetour}`;
    // H7：代理节点自身域名的解析改走 DoH（remoteDNS），不再交给明文 localDNS。
    // 不带 #<策略组> detour：proxy-server-nameserver 必须能在隧道建立前完成解析，带代理会形成解析环。
    // 远程 DNS（warp 下取 warpRemoteDNS）非 https（如用户填了裸 IP）时保持原有 finalLocalDNS 行为。
    const proxyServerRemoteDNS = isWarp ? warpRemoteDNS : remoteDNS;
    const proxyServerDNS = /^https:\/\//i.test(proxyServerRemoteDNS) ? proxyServerRemoteDNS : finalLocalDNS;
    const hosts: DnsHosts = {};
    const nameserverPolicy: Record<string, string> = {};

    if (isChain && !isWarp) {
        const { server } = outProxyParams;
        if (isDomain(server)) nameserverPolicy[server] = finalRemoteDNS;
    }

    if (remoteDnsHost.isDomain && !isWarp) {
        const { ipv4, ipv6, host } = remoteDnsHost;
        hosts[host] = ipv4.concatIf(enableIPv6, ipv6);
    }

    const geoAssets = getGeoAssets();
    const dnsRules = accDnsRules(geoAssets);

    // C12：`hosts` 是域名表，键只能是域名模式；`rule-set:<geosite>` 前缀只在 nameserver-policy 里有意义。
    // 原先把 geosite 也塞进 hosts，那条 DNS 层拦截永不匹配（无效配置项）。拦截语义仍由路由层
    // `RULE-SET,<geosite>,REJECT`（routing.ts#buildBlockRules）承担——它在两条路径上都已经前置。
    // 故这里只保留真正的域名模式；把 geosite 转成 nameserver-policy 的 DoH 目标并与 bypass 混在同一次
    // `nameserverPolicy[value] = finalLocalDNS` 赋值里，反而会让最后写入者的组语义污染对方，收益为负。
    const blockDomains = dnsRules.block.domains.map(domain => `+.${domain}`);

    blockDomains.forEach(value => hosts[value] = "rcode://refused");

    const sanctionDomains = [
        ...dnsRules.bypass.antiSanctionDNS.geosites.map(geosite => `rule-set:${geosite}`),
        ...dnsRules.bypass.antiSanctionDNS.domains.map(domain => `+.${domain}`)
    ];

    const bypassDomains = [
        ...dnsRules.bypass.localDNS.geositeGeoips.map(({ geosite }) => `rule-set:${geosite}`),
        ...dnsRules.bypass.localDNS.geosites.map(geosite => `rule-set:${geosite}`),
        ...dnsRules.bypass.localDNS.domains.map(domain => `+.${domain}`)
    ];

    if (sanctionDomains.length) {
        // 残留 #6（H7 续）：制裁域名改为**优先 DoH**解析，不再把查询明文交给 antiSanctionDNS
        // （本地 ISP 直接可见，正是 H7 指出的问题）。冻结口径（三端一致，只从既有 settings.antiSanctionDNS
        // 派生、不新增设置项）：以 https:// 开头 → 原样作为 DoH；否则由它派生 `https://<值>/dns-query`；
        // 明文兜底 = 非 https 输入时的 antiSanctionDNS 本身。
        // 裸 IPv6 必须加方括号：`https://2001:db8::1/dns-query#DIRECT` 会被 mihomo 判为
        // `too many colons in address`，**整份配置被拒**（实测 mihomo v1.19.30：裸形态 test failed、
        // 方括号形态 test successful）——与 xray 端同一判据（isIPv6 且未自带方括号）。
        const antiSanctionDohHost = isIPv6(antiSanctionDNS) && !antiSanctionDNS.startsWith('[')
            ? `[${antiSanctionDNS}]`
            : antiSanctionDNS;
        const dohUrl = /^https:\/\//i.test(antiSanctionDNS) ? antiSanctionDNS : `https://${antiSanctionDohHost}/dns-query`;
        // 「Doh 优先 + 明文兜底」里的**兜底**在 Clash 侧无处安放，只落地可安全表达的一半，原因：
        //  1) nameserver-policy 是单值映射（clash.d.ts:42 `Record<string, string>`），同一个键塞两个服务器
        //     在 mihomo 里是**并发查询、最快者胜**，不是「先主后备」——明文查询仍会照旧发出，且通常被
        //     本地明文解析器抢答，等于没改；
        //  2) 顶层 `fallback`/`fallback-filter` 是全域生效（会给所有域名追加明文查询，比现状更差），
        //     且命中 nameserver-policy 的域名根本不走 fallback 分支。
        // 若实测 Shecan DoH 被墙，需要恢复明文兜底只能改口径（见交付说明），不能在此表达。
        sanctionDomains.forEach(value => nameserverPolicy[value] = `${dohUrl}#DIRECT`);
        const { host, isHostDomain } = getDomain(antiSanctionDNS);
        if (isHostDomain) bypassDomains.push(host);
    }

    bypassDomains.forEach(value => nameserverPolicy[value] = finalLocalDNS);

    // G13-C10：把 ECH 查询名（HTTPS RR 的解析对象）钉到远程 DoH 上。mihomo 的 ech-opts 只有
    // {enable, query-server-name}（clash.d.ts:123-126），没有 DNS 目标字段，但 ECH 查询名同样由 DNS 模块解析、
    // nameserver-policy 对其生效，故在此补策略项，避免它落进 sanctions/bypass 的明文解析路径。
    // 空名单时 outbounds 会回退到该节点自身域名，而节点域名恒由 proxy-server-nameserver（H7：DoH 且无 detour）
    // 优先解析（其优先级高于 nameserver-policy），故无需也无法在此再列。
    // 安全性：键必须是域名模式 → 非域名（IP/畸形串）由 isDomain 过滤掉，不生成无法匹配的策略项；
    // 已被 sanctions/bypass 定过的键不覆盖，避免改掉该域名既有的解析策略。
    if (enableECH) {
        for (const name of echServerName.filter(isDomain)) {
            if (!(name in nameserverPolicy)) nameserverPolicy[name] = finalRemoteDNS;
        }
    }
    const listen = `${allowLANConnection ? "0.0.0.0" : "127.0.0.1"}:1053`;
    let enhancedMode: "redir-host" | "fake-ip" = "redir-host";
    let fakeDnsSettings: Partial<FakeDNS> = {};
    
    if (fakeDNS) {
        enhancedMode = "fake-ip";
        fakeDnsSettings = {
            "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter-mode": "blacklist",
            "fake-ip-filter": ["+.lan", "+.local"]
        };
    }

    const dns: DNS = {
        "enable": true,
        "respect-rules": true,
        "use-system-hosts": false,
        "listen": listen,
        "ipv6": enableIPv6,
        "hosts": hosts.omitEmpty(),
        "nameserver": [finalRemoteDNS],
        "proxy-server-nameserver": [proxyServerDNS],
        "direct-nameserver": [finalLocalDNS],
        "direct-nameserver-follow-policy": true,
        "nameserver-policy": nameserverPolicy.omitEmpty(),
        "enhanced-mode": enhancedMode,
        ...fakeDnsSettings
    };

    return dns;
}