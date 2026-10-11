import { getGeoAssets } from './geo-assets';
import { accRoutingRules } from '@utils';
import { Route, RoutingRule, RuleSet } from '#types/sing-box';

/**
 * C6：ACL 模板接管 route.rules 时的「前置基础规则」，即 buildRoutingRules 中最前那段不依赖
 * 出站/分组 tag 的规则：sniff、hijack-dns（内含 172.19.0.2 那台上游 DNS 服务器）、
 * ip_is_private 直连、clash_mode 直连/全局，以及 UDP 兜底 reject。
 * 与 Clash 端 C5 的 buildBaseRoutingRules（clash/routing.ts，GEOIP,lan + NETWORK,udp,REJECT）对称：
 * 模板整表重建 rules 时必须把这段放回最前，否则接管后 DNS 劫持/局域网直连/嗅探/UDP 策略全部静默改变。
 */
export function buildBaseRoutingRules(isWarp: boolean): RoutingRule[] {
    const { blockUDP443 } = globalThis.settings;
    const rules: RoutingRule[] = [
        {
            ip_cidr: "172.19.0.2",
            action: "hijack-dns"
        },
        {
            clash_mode: "Direct",
            outbound: "direct"
        },
        {
            clash_mode: "Global",
            outbound: "✅ Selector"
        },
        {
            action: "sniff"
        },
        {
            protocol: "dns",
            action: "hijack-dns"
        },
        {
            ip_is_private: true,
            outbound: "direct"
        }
    ];

    if (!isWarp) {
        addRoutingRule(rules, 'reject', undefined, undefined, undefined, undefined, "udp");
    } else if (blockUDP443) {
        addRoutingRule(rules, 'reject', undefined, undefined, undefined, undefined, "udp", "quic", 443);
    }

    return rules;
}

export function buildRoutingRules(isWarp: boolean): Route {
    const { rules: blockBypassRules, ruleSets } = buildBlockAndBypassRules();
    const rules = [
        ...buildBaseRoutingRules(isWarp),
        ...blockBypassRules
    ];

    return {
        rules,
        rule_set: ruleSets.omitEmpty(),
        auto_detect_interface: true,
        final: "✅ Selector"
    };
}

/** 生成 Block（reject）+ Bypass（direct）路由规则与 rule_set，供 ACL 模板接管时前置保留。 */
export function buildBlockAndBypassRules(): { rules: RoutingRule[]; ruleSets: RuleSet[] } {
    const geoAssets = getGeoAssets();
    const routingRules = accRoutingRules(geoAssets);
    const rules: RoutingRule[] = [];

    const blockDomains = [
        ...routingRules.block.geosites,
        ...routingRules.block.domains
    ];
    if (blockDomains.length) {
        addRoutingRule(rules, 'reject', routingRules.block.domains, undefined, routingRules.block.geosites);
    }
    const blockIPs = [
        ...routingRules.block.geoips,
        ...routingRules.block.ips
    ];
    if (blockIPs.length) {
        addRoutingRule(rules, 'reject', undefined, routingRules.block.ips, undefined, routingRules.block.geoips);
    }
    const bypassDomains = [
        ...routingRules.bypass.geosites,
        ...routingRules.bypass.domains
    ];
    if (bypassDomains.length) {
        addRoutingRule(rules, 'direct', routingRules.bypass.domains, undefined, routingRules.bypass.geosites);
    }
    const bypassIPs = [
        ...routingRules.bypass.geoips,
        ...routingRules.bypass.ips
    ];
    if (bypassIPs.length) {
        addRoutingRule(rules, 'direct', undefined, routingRules.bypass.ips, undefined, routingRules.bypass.geoips);
    }

    const ruleSets: RuleSet[] = geoAssets.reduce((sets, asset) => {
        addRuleSets(sets, asset);
        return sets;
    }, []);

    return { rules, ruleSets };
}

function addRoutingRule(
    rules: RoutingRule[],
    type: 'direct' | 'reject' | 'route',
    domain?: string[],
    ip?: string[],
    geosite?: string[],
    geoip?: string[],
    network?: "tcp" | "udp",
    protocol?: "http" | "tls" | "quic" | "dns",
    port?: number
) {
    rules.push({
        rule_set: (geosite || geoip) ? [...(geosite || []), ...(geoip || [])] : undefined,
        domain_suffix: domain?.length ? domain : undefined,
        ip_cidr: ip?.length ? ip : undefined,
        network,
        protocol,
        port,
        action: type === 'reject' ? 'reject' : 'route',
        outbound: type === 'direct' ? 'direct' : undefined
    });
}

function addRuleSets(ruleSets: RuleSet[], geoAsset: GeoAsset) {
    const { geosite, geositeURL, geoip, geoipURL } = geoAsset;

    // 不下发 `download_detour`：该选项在 sing-box 1.14.0 已弃用、1.16.0 将移除。
    // 省略后下载出口由内核默认行为决定（不再固定指向 direct）。
    const addRuleSet = (geo: string, url: string) => ruleSets.push({
        type: "remote",
        tag: geo,
        format: "binary",
        url
    });

    if (geosite && geositeURL) addRuleSet(geosite, geositeURL);
    if (geoip && geoipURL) addRuleSet(geoip, geoipURL);
}