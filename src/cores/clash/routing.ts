import { RuleProvider } from '#types/clash';
import { getGeoAssets } from './geo-assets';
import { isIPv6, isIPv4, accRoutingRules } from '@utils';

/**
 * 不含 Block/Bypass 与 MATCH 兜底的基础规则行（局域网直连 + UDP 策略）。
 * C5：ACL 模板接管时 rules 会被整体重建（configs.ts#getClNormalConfig），
 * 若只前置 buildBlockRules/buildBypassRules，就会丢掉这两行 baseline —— 局域网不再强制直连、
 * UDP 也不再被策略性 reject，行为与未接管时不一致。故单独抽出，供默认路径与 ACL 路径共用。
 */
export function buildBaseRoutingRules(isWarp: boolean): string[] {
    const { blockUDP443 } = globalThis.settings;
    const rules = [`GEOIP,lan,DIRECT,no-resolve`];

    if (!isWarp) {
        rules.push("NETWORK,udp,REJECT");
    } else if (blockUDP443) {
        rules.push("AND,((NETWORK,udp),(DST-PORT,443)),REJECT");
    }

    return rules;
}

export function buildRoutingRules(isWarp: boolean) {
    return [
        ...buildBaseRoutingRules(isWarp),
        ...buildBlockRules(),
        ...buildBypassRules(),
        "MATCH,✅ Selector"
    ];
}

/** 仅生成 Block（REJECT）规则行，供 ACL 模板接管时前置保留。 */
export function buildBlockRules(): string[] {
    const geoAssets = getGeoAssets();
    const routingRules = accRoutingRules(geoAssets);
    const blockRules = [
        ...routingRules.block.geosites.map(geosite => `RULE-SET,${geosite},REJECT`),
        ...routingRules.block.domains.map(domain => `DOMAIN-SUFFIX,${domain},REJECT`),
        ...routingRules.block.geoips.map(geoip => `RULE-SET,${geoip},REJECT`),
        ...routingRules.block.ips.map(ip => buildIpCidrRule(ip, 'REJECT'))
    ];
    // 过滤掉 URL-REGEX 之类 Clash 不支持的规则行由 buildAclClash 处理；这里仅原生 REJECT
    return blockRules;
}

/** 仅生成 bypass（DIRECT）规则行，供 ACL 模板前置判定（国内/直连优先）。 */
export function buildBypassRules(): string[] {
    const geoAssets = getGeoAssets();
    const routingRules = accRoutingRules(geoAssets);
    return [
        ...routingRules.bypass.geosites.map(geosite => `RULE-SET,${geosite},DIRECT`),
        ...routingRules.bypass.domains.map(domain => `DOMAIN-SUFFIX,${domain},DIRECT`),
        ...routingRules.bypass.geoips.map(geoip => `RULE-SET,${geoip},DIRECT`),
        ...routingRules.bypass.ips.map(ip => buildIpCidrRule(ip, 'DIRECT'))
    ];
}

export function buildRuleProviders(): Record<string, RuleProvider> | undefined {
    const geoAssets = getGeoAssets();
    return geoAssets.reduce((providers, asset) => {
        addRuleProvider(providers, asset);
        return providers;
    }, {}).omitEmpty();
}

function addRuleProvider(
    ruleProviders: Record<string, RuleProvider>,
    ruleProvider: GeoAsset
) {
    const { geosite, geoip, geositeURL, geoipURL, format } = ruleProvider;
    const fileExtension = format === 'text' ? 'txt' : format;

    const defineProvider = (geo: string, behavior: 'domain' | 'ipcidr', url: string) => {
        ruleProviders[geo] = {
            type: "http",
            format: format!,
            behavior,
            path: `./ruleset/${geo}.${fileExtension}`,
            interval: 86400,
            url
        };
    };

    if (geosite && geositeURL) defineProvider(geosite, 'domain', geositeURL);
    if (geoip && geoipURL) defineProvider(geoip, 'ipcidr', geoipURL);
}

function buildIpCidrRule(ip: string, proxy: string) {
    ip = isIPv6(ip) ? ip.replace(/\[|\]/g, '') : ip;
    const cidr = ip.includes('/') ? '' : isIPv4(ip) ? '/32' : '/128';
    return `IP-CIDR,${ip}${cidr},${proxy}`;
}