import type {
    Selector as ClashSelector,
    URLTest as ClashUrlTest,
    LoadBalance,
    Fallback,
    RuleProvider,
} from '#types/clash';
import type { RoutingRule, RuleSet, Selector as SbSelector, URLTest as SbUrlTest, Outbound } from '#types/sing-box';
import { fetchWithTimeout } from '@common';

/**
 * ACL4SSR 分组配置模板引擎（对齐 cfnew `明文源吗` 实现）。
 * 负责：
 *   1. 解析 INI 模板文本（`ruleset=` / `custom_proxy_group=`）
 *   2. 拉取模板并缓存（fetchWithTimeout + 模块级 Map）
 *   3. 依据节点名单展开正则 / `.*`，生成通用策略组
 *   4. 分别组装为 Clash 结构化分组 / sing-box 结构化分组 + 落地规则
 *
 * 供 `src/cores/clash/configs.ts`（保留 load-balance）与
 * `src/cores/sing-box/configs.ts`（load-balance/fallback → urltest）共用。
 */

interface InlineRuleSetEntry { group: string; type: 'inline'; ruleType: string; ruleVal: string; }
interface UrlRuleSetEntry { group: string; type: 'url'; url: string; }
type RulesetEntry = InlineRuleSetEntry | UrlRuleSetEntry;

export interface ParsedProxyGroup {
    name: string;
    type: string;
    proxies: string[];
    url?: string;
    interval?: number;
    tolerance?: number;
    strategy?: string;
    hasBrackets?: boolean;
}

export interface ParsedTemplate {
    rulesets: RulesetEntry[];
    proxyGroups: ParsedProxyGroup[];
}

const iniTemplateCache = new Map<string, ParsedTemplate | null>();
const PROVIDER_PREFIX = 'provider_';

/* ----------------------------- INI 文本解析 ----------------------------- */

export function parseIniTemplateText(iniText: string): ParsedTemplate | null {
    if (!iniText) return null;
    const lines = iniText.split(/\r?\n/);
    const rulesets: RulesetEntry[] = [];
    const proxyGroups: ParsedProxyGroup[] = [];

    for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith(';') || line.startsWith('#') || line.startsWith('[')) continue;

        if (line.startsWith('ruleset=')) {
            const payload = line.substring(8).trim();
            const firstComma = payload.indexOf(',');
            if (firstComma === -1) continue;
            const group = payload.substring(0, firstComma).trim();
            const rest = payload.substring(firstComma + 1).trim();

            if (rest.startsWith('[]')) {
                const ruleContent = rest.substring(2).trim();
                const ruleComma = ruleContent.indexOf(',');
                if (ruleComma === -1) {
                    rulesets.push({ group, type: 'inline', ruleType: ruleContent, ruleVal: '' });
                } else {
                    rulesets.push({
                        group,
                        type: 'inline',
                        ruleType: ruleContent.substring(0, ruleComma).trim(),
                        ruleVal: ruleContent.substring(ruleComma + 1).trim()
                    });
                }
            } else if (rest.startsWith('http://') || rest.startsWith('https://')) {
                rulesets.push({ group, type: 'url', url: rest });
            } else if (rest) {
                // 裸规则（如 DOMAIN-SUFFIX,google.com）
                const ruleComma = rest.indexOf(',');
                if (ruleComma === -1) {
                    rulesets.push({ group, type: 'inline', ruleType: rest, ruleVal: '' });
                } else {
                    rulesets.push({
                        group,
                        type: 'inline',
                        ruleType: rest.substring(0, ruleComma).trim(),
                        ruleVal: rest.substring(ruleComma + 1).trim()
                    });
                }
            }
        } else if (line.startsWith('custom_proxy_group=')) {
            const payload = line.substring(19).trim();
            const firstBacktick = payload.indexOf('`');
            if (firstBacktick === -1) continue;
            const groupName = payload.substring(0, firstBacktick).trim();
            const rest = payload.substring(firstBacktick + 1);
            const secondBacktick = rest.indexOf('`');
            if (secondBacktick === -1) continue;
            const groupType = rest.substring(0, secondBacktick).trim();
            const afterType = rest.substring(secondBacktick + 1);
            const proxies: string[] = [];
            let url = '';
            let interval = 300;
            let tolerance = 50;
            let strategy = '';
            let current = afterType;
            let hasBracketsConsumed = false;

            while (current.startsWith('[')) {
                hasBracketsConsumed = true;
                current = current.substring(1);
                const bracketEnd = current.indexOf(']');
                if (bracketEnd === -1) break;
                let proxy = current.substring(0, bracketEnd).trim();
                if (proxy.startsWith('"') && proxy.endsWith('"')) proxy = proxy.slice(1, -1);

                if (!proxy) {
                    // `[]代理名` 形式：空括号后接代理名
                    current = current.substring(bracketEnd + 1);
                    const backtickIdx = current.indexOf('`');
                    if (backtickIdx === -1) {
                        proxy = current.trim();
                        current = '';
                    } else {
                        proxy = current.substring(0, backtickIdx).trim();
                        current = current.substring(backtickIdx + 1);
                    }
                } else {
                    current = current.substring(bracketEnd + 2);
                }
                if (proxy) proxies.push(proxy);
            }

            if (current) {
                const parts = current.split('`').map(p => p.trim()).filter(Boolean);
                if (groupType === 'select') {
                    if (parts.length > 0) proxies.push(...parts);
                } else {
                    // url-test / load-balance / fallback
                    if (parts.length >= 1) {
                        if (parts[0].startsWith('http://') || parts[0].startsWith('https://')) {
                            url = parts[0];
                            if (parts.length >= 2) {
                                const params = parts[1].split(',');
                                if (params[0]) interval = parseInt(params[0], 10) || 300;
                                if (params.length >= 3) {
                                    strategy = params[1] || '';
                                    if (params[2]) tolerance = parseInt(params[2], 10) || 50;
                                } else if (params.length === 2) {
                                    if (params[1]) tolerance = parseInt(params[1], 10) || 50;
                                }
                            }
                        } else {
                            proxies.push(parts[0]);
                            if (parts.length >= 2) url = parts[1];
                            if (parts.length >= 3) {
                                const params = parts[2].split(',');
                                if (params[0]) interval = parseInt(params[0], 10) || 300;
                                if (params.length >= 3) {
                                    strategy = params[1] || '';
                                    if (params[2]) tolerance = parseInt(params[2], 10) || 50;
                                } else if (params.length === 2) {
                                    if (params[1]) tolerance = parseInt(params[1], 10) || 50;
                                }
                            }
                        }
                    }
                }
            }
            proxyGroups.push({ name: groupName, type: groupType, proxies, url, interval, tolerance, strategy, hasBrackets: hasBracketsConsumed });
        }
    }
    return { rulesets, proxyGroups };
}

/* ------------------------- 模板拉取与缓存 ------------------------- */

export async function fetchAclTemplate(configUrl: string): Promise<ParsedTemplate | null> {
    if (!configUrl) return null;
    if (iniTemplateCache.has(configUrl)) return iniTemplateCache.get(configUrl)!;

    try {
        const res = await fetchWithTimeout(configUrl, {}, 6000);
        if (!res.ok) return null;
        const text = await res.text();
        const parsed = parseIniTemplateText(text);
        iniTemplateCache.set(configUrl, parsed);
        return parsed;
    } catch (e: any) {
        console.warn('[ACL Config] Fetch ini template error:', e?.message || e);
        return null;
    }
}

/** 检测字符串是否为正则模式（而非字面代理/组名）。 */
export function isRegexPattern(str: string): boolean {
    return /[\(\)\|\*\+\?\[\]\{\}\^\$\\]/.test(str);
}

/* ------------------------- 通用策略组生成 ------------------------- */

export interface AclGroup {
    name: string;
    type: string;
    proxies: string[];
    url?: string;
    interval?: number;
    tolerance?: number;
    strategy?: string;
}

interface AclRuleProvider {
    name: string;
    url: string;
    group: string;
}

interface GeneratedAcl {
    groups: AclGroup[];
    ruleProviders: AclRuleProvider[];
    inlineRules: InlineRuleSetEntry[];
}

interface GenOptions {
    convertLoadBalanceToUrlTest?: boolean;
    targetClient?: 'auto' | 'clash' | 'singbox';
}

/** 依据节点名单展开模板 group（对齐 cfnew `生成代理组配置`）。 */
export function generateAclGroups(
    parsed: ParsedTemplate,
    nodeNames: string[],
    opts: GenOptions = {}
): GeneratedAcl {
    const { convertLoadBalanceToUrlTest = false, targetClient = 'auto' } = opts;
    const rulesets = parsed?.rulesets || [];
    const parsedProxyGroups = parsed?.proxyGroups || [];
    const fallbackNodes = nodeNames.length ? nodeNames : ['DIRECT'];

    const compileAllRegex = (patterns: (string | undefined)[]) =>
        patterns.map(p => {
            try { return p ? new RegExp(p) : null; } catch { return null; }
        }).filter((re): re is RegExp => !!re);

    const groups: AclGroup[] = [];

    for (const pg of parsedProxyGroups) {
        let type = pg.type;
        if (convertLoadBalanceToUrlTest && type === 'load-balance' && targetClient !== 'clash') {
            type = 'url-test';
        }

        let proxyList: string[] = [];
        if (pg.proxies.length > 0) {
            if (type === 'select') {
                proxyList = [];
                for (const p of pg.proxies) {
                    if (p === '.*') {
                        proxyList.push('.*'); // 占位，后处理展开
                    } else if (isRegexPattern(p)) {
                        try {
                            const re = new RegExp(p);
                            proxyList.push(...nodeNames.filter(name => re.test(name)));
                        } catch { /* 无效正则跳过 */ }
                    } else {
                        proxyList.push(p);
                    }
                }
            } else {
                if (pg.hasBrackets) {
                    proxyList = [];
                    for (const p of pg.proxies) {
                        if (isRegexPattern(p)) {
                            try {
                                const re = new RegExp(p);
                                proxyList.push(...nodeNames.filter(name => re.test(name)));
                            } catch { /* 无效正则跳过 */ }
                        } else {
                            proxyList.push(p);
                        }
                    }
                } else {
                    const patterns = compileAllRegex(pg.proxies);
                    proxyList = nodeNames.filter(name => patterns.some(re => re.test(name)));
                }
                if (proxyList.length === 0) proxyList = fallbackNodes;
            }
        } else {
            proxyList = type === 'select' ? ['DIRECT', ...fallbackNodes] : [...fallbackNodes];
        }
        // 过滤自引用，避免环路
        proxyList = proxyList.filter(p => p !== pg.name);

        const group: AclGroup = { name: pg.name, type, proxies: proxyList };
        if ((type === 'url-test' || type === 'load-balance' || type === 'fallback') && pg.url) {
            group.url = pg.url;
            group.interval = pg.interval;
            if (type === 'url-test' || type === 'fallback') group.tolerance = pg.tolerance;
            if (type === 'load-balance' && pg.strategy) group.strategy = pg.strategy;
        }
        groups.push(group);
    }

    // 后处理：展开 select 组中的 `.*` 占位
    for (const g of groups) {
        if (g.type === 'select') {
            const idx = g.proxies.indexOf('.*');
            if (idx !== -1) {
                g.proxies.splice(idx, 1, ...nodeNames, 'DIRECT');
                g.proxies = [...new Set(g.proxies)].filter(p => p !== g.name);
            }
        }
    }

    const ruleProviders: AclRuleProvider[] = [];
    let providerIdx = 0;
    const urlRuleSets = rulesets.filter((r): r is UrlRuleSetEntry => r.type === 'url');
    for (const item of urlRuleSets) {
        ruleProviders.push({ name: `${PROVIDER_PREFIX}${providerIdx++}`, url: item.url, group: item.group });
    }

    const inlineRules = rulesets.filter((r): r is InlineRuleSetEntry => r.type === 'inline');

    return { groups, ruleProviders, inlineRules };
}

/* ------------------------- Clash 组装入口 ------------------------- */

export type ClashGroup = ClashSelector | ClashUrlTest | LoadBalance | Fallback;

export interface AclClashResult {
    groups: ClashGroup[];
    rules: string[];
}

/**
 * 把 URL 规则集映射为 Clash rule-providers 记录。
 * 使用 `behavior: classical`（匹配 ACL4SSR 在线模板的规则集格式）。
 */
export function buildAclProviders(
    providers: AclRuleProvider[]
): Record<string, RuleProvider> {
    const out: Record<string, RuleProvider> = {};
    for (const p of providers) {
        out[p.name] = {
            type: 'http',
            format: 'text',
            behavior: 'classical',
            url: p.url,
            path: `./ruleset/${p.name}.list`,
            interval: 86400,
        };
    }
    return out;
}

/** 生成 Clash 结构化策略组 + 规则（rule-providers 引用式，见用户要求）。load-balance 保留原生。 */
export async function buildAclClash(
    templateUrl: string,
    nodeNames: string[]
): Promise<AclClashResult & { providers: Record<string, RuleProvider> } | null> {
    const parsed = await fetchAclTemplate(templateUrl);
    if (!parsed || (parsed.rulesets.length === 0 && parsed.proxyGroups.length === 0)) return null;

    const { groups, ruleProviders, inlineRules } = generateAclGroups(
        parsed,
        nodeNames,
        { convertLoadBalanceToUrlTest: false, targetClient: 'clash' }
    );

    const clashGroups: ClashGroup[] = groups.map(g => {
        const base: any = { name: g.name, type: g.type, proxies: g.proxies };
        if (g.url) {
            base.url = g.url;
            base.interval = g.interval;
            if (g.type === 'url-test' || g.type === 'fallback') base.tolerance = g.tolerance;
            if (g.type === 'load-balance' && g.strategy) base.strategy = g.strategy;
        }
        return base;
    });

    const rules: string[] = [];
    // 1) 规则集引用：RULE-SET,<providerName>,<策略组>
    for (const rp of ruleProviders) {
        rules.push(`RULE-SET,${rp.name},${rp.group}`);
    }
    const providers = buildAclProviders(ruleProviders);
    // 3) 内联规则（模板中 `ruleset=` 的裸规则）仍作为普通规则带策略组
    for (const rule of inlineRules) {
        if (rule.ruleType.toUpperCase() === 'FINAL') {
            rules.push(`MATCH,${rule.group}`);
        } else {
            rules.push(`${rule.ruleType},${rule.ruleVal},${rule.group}`);
        }
    }

    return { groups: clashGroups, rules, providers };
}

/* ------------------------- sing-box 规则格式转换 ------------------------- */

const SINGBOX_RULE_TYPE_MAP: Record<string, string> = {
    'DOMAIN': 'domain',
    'DOMAIN-SUFFIX': 'domain_suffix',
    'DOMAIN-KEYWORD': 'domain_keyword',
    'DOMAIN-REGEX': 'domain_regex',
    'IP-CIDR': 'ip_cidr',
    'IP-CIDR6': 'ip_cidr',
    'PROCESS-NAME': 'process_name',
    'PROCESS-PATH': 'process_path',
    'PROCESS-PATH-REGEX': 'process_path_regex',
    'PACKAGE-NAME': 'package_name',
    'PORT': 'port'
};

export function convertClashRulesToSingbox(
    text: string
): Array<Record<string, string[]>> {
    const ruleSet: Record<string, Set<string>> = {};
    const lines = text.split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed === '---') continue;
        const cleaned = trimmed.replace(/^\s*-\s*/, '');
        const parts = cleaned.split(',').map(s => s.trim());
        if (parts.length < 2) continue;
        const field = SINGBOX_RULE_TYPE_MAP[parts[0].toUpperCase()];
        if (!field) continue;
        const value = parts[1].replace(/,?\s*no-resolve$/i, '').trim();
        if (!value) continue;
        if (!ruleSet[field]) ruleSet[field] = new Set();
        ruleSet[field].add(value);
    }
    const out: Array<Record<string, string[]>> = [];
    for (const [field, values] of Object.entries(ruleSet)) {
        out.push({ [field]: [...values] });
    }
    return out;
}

/* ------------------------- sing-box 组装 ------------------------- */

export type SnboxGroup = SbSelector | SbUrlTest;

export interface AclSingboxResult {
    outboundGroups: SnboxGroup[];
    rules: RoutingRule[];
    ruleSets: Array<{ type: 'inline'; tag: string; rules: Array<Record<string, string[]>> }>;
    final: string;
}

/**
 * 生成 sing-box 结构化分组与路由规则。
 * load-balance / fallback 一律转 urltest（延迟测试）。URL provider 服务端内联。
 */
export async function buildAclSingbox(
    templateUrl: string,
    nodeNames: string[]
): Promise<AclSingboxResult | null> {
    const parsed = await fetchAclTemplate(templateUrl);
    if (!parsed || (parsed.rulesets.length === 0 && parsed.proxyGroups.length === 0)) return null;

    const { groups, ruleProviders, inlineRules } = generateAclGroups(
        parsed,
        nodeNames,
        { convertLoadBalanceToUrlTest: true, targetClient: 'singbox' }
    );

    const outboundGroups: SnboxGroup[] = groups.map(g => {
        if (g.type === 'select') {
            return {
                type: 'selector',
                tag: g.name,
                outbounds: [...g.proxies, 'direct'],
                interrupt_exist_connections: false,
            } as SbSelector;
        }
        const ut: any = {
            type: 'urltest',
            tag: g.name,
            outbounds: [...g.proxies],
            url: g.url || 'https://www.gstatic.com/generate_204',
            interval: `${g.interval || 300}s`,
            interrupt_exist_connections: false,
        };
        if (g.tolerance) ut.tolerance = g.tolerance;
        return ut as SbUrlTest;
    });

    // URL provider → inline rule_set
    const ruleSets: AclSingboxResult['ruleSets'] = [];
    const urlRules: RoutingRule[] = [];
    if (ruleProviders.length > 0) {
        const settled = await Promise.allSettled(ruleProviders.map(async (rp) => {
            try {
                const resp = await fetchWithTimeout(rp.url, {}, 10000);
                if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                const text = await resp.text();
                return { tag: rp.name, rules: convertClashRulesToSingbox(text), group: rp.group };
            } catch (e: any) {
                console.warn(`[ACL 规则集] 获取转换失败 ${rp.name}: ${e.message || e}`);
                return { tag: rp.name, rules: [] as Array<Record<string, string[]>>, group: rp.group };
            }
        }));
        settled.forEach((res) => {
            const val = res.status === 'fulfilled'
                ? res.value
                : { tag: '', rules: [] as Array<Record<string, string[]>>, group: '' };
            if (!val.tag || val.rules.length === 0) return;
            ruleSets.push({ type: 'inline', tag: val.tag, rules: val.rules });
            urlRules.push({ rule_set: val.tag, outbound: val.group });
        });
    }

    // inline 规则 → route rule
    const inlineRouteRules: RoutingRule[] = [];
    let finalGroup = undefined as string | undefined;
    for (const rule of inlineRules) {
        if (rule.ruleType.toUpperCase() === 'FINAL') {
            finalGroup = rule.group || finalGroup;
            continue;
        }
        const type = rule.ruleType.toLowerCase();
        const ruleObj: RoutingRule = { outbound: rule.group };
        if (type === 'domain') ruleObj.domain = [rule.ruleVal];
        else if (type === 'domain-suffix') ruleObj.domain_suffix = [rule.ruleVal];
        else if (type === 'domain-keyword') ruleObj.domain_keyword = [rule.ruleVal];
        else if (type === 'ipcidr' || type === 'ip-cidr') ruleObj.ip_cidr = [rule.ruleVal];
        else if (type === 'geoip') ruleObj.geoip = { country_code: rule.ruleVal.toUpperCase() };
        else if (type === 'process') ruleObj.process = [rule.ruleVal];
        else ruleObj.rule_set = rule.ruleType;
        inlineRouteRules.push(ruleObj);
    }

    const final = finalGroup || (groups.length > 0 ? groups[0].name : '✅ Selector');

    return {
        outboundGroups,
        rules: [...urlRules, ...inlineRouteRules],
        ruleSets,
        final,
    };
}