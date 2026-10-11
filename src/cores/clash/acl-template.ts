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

/**
 * ACL 模板接管时被移除的内置分组名（sing-box 出站 tag / Clash proxy-groups 共用同一套命名）。
 * 两个用途必须同源，否则会留下「组已删除、引用还在」的悬空引用：
 *   1. `sing-box/configs.ts` 用它把内置分组出站从 outbounds 中过滤掉；
 *   2. 两端 configs 用它判断 DNS 的 detour 是否指向已被移除的组（见各端 dns.ts#retargetDnsDetour）。
 * 过滤集合与改写集合一旦不同源，就会出现「组被删了、DNS 引用还在」→ 客户端加载配置失败。
 */
export const ACL_BUILTIN_GROUP_TAGS: ReadonlySet<string> = new Set([
    "✅ Selector",
    "最佳延迟 🚀",
    "Warp - 最佳延迟 🚀",
    "WoW - 最佳延迟 🚀",
    "🔗 最佳延迟 🚀",
    "Warp Pro - 最佳延迟 🚀",
    "WoW Pro - 最佳延迟 🚀"
]);

/**
 * 语义为「拒绝」的内置策略名（mihomo）。ACL4SSR 默认模板把它们写进分组成员 ——
 * `🛑 广告拦截` / `🛡️ 隐私防护` / `🍃 应用净化` 都是 `select`[]REJECT`[]DIRECT`。
 * sing-box 里没有对应的出站 tag（拒绝是 route 的 action，不是 outbound），因此：
 *   1) 生成出站时要把这些成员名从 sing-box 分组成员里滤掉，否则 `selector -> REJECT` 悬空引用、整份配置加载失败；
 *   2) 还必须把「指向这类分组」的规则改写成 `action: "reject"`（见 buildAclSingbox 的 blockGroupTags）——
 *      否则该组只剩 direct/节点，广告与恶意域名会退化成**直连或走节点**，拦截彻底失效。
 */
const REJECT_POLICY_MEMBERS: ReadonlySet<string> = new Set([
    'REJECT',
    'REJECT-DROP'
]);

/**
 * 只有 Clash/mihomo 才存在的内置策略名：mihomo 把它们当策略常量解析，但 sing-box 里没有对应出站 tag。
 * 注意 DIRECT 不在此列：它有 sing-box 对应出站 direct，由 generateAclGroups 的 mapMember 归一。
 */
const CLASH_ONLY_POLICY_MEMBERS: ReadonlySet<string> = new Set([
    ...REJECT_POLICY_MEMBERS,
    'PASS',
    'COMPATIBLE',
    'GLOBAL'
]);

/** Clash/mihomo 恒存在的内置策略名（含 DIRECT），模板规则可直接引用它们。 */
const CLASH_BUILTIN_POLICIES: ReadonlySet<string> = new Set(['DIRECT', ...CLASH_ONLY_POLICY_MEMBERS]);

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
    /** 成员里含 REJECT/REJECT-DROP → 该组语义是「拒绝」；sing-box 侧据此把指向它的规则改写成 action:"reject" */
    blocking?: boolean;
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
    // C4：内置直连 tag 两端不同名——Clash 是内置代理 `DIRECT`（大写），sing-box 是出站 tag `direct`（小写）。
    // 模板里的 DIRECT 是原样透传的成员名，喂给 sing-box 就变成引用不存在的 tag → 出站解析失败、整份配置不可用。
    // 故按目标核心给出对应字面量；未显式指定目标核心（auto）时保持历史 Clash 语义（大写 DIRECT）不变。
    const directTag = targetClient === 'singbox' ? 'direct' : 'DIRECT';
    // 模板显式书写的内建策略成员（ACL4SSR 常见的 `[]DIRECT`）同样要按核心归一，
    // Clash 目标下 directTag === 'DIRECT'，此映射恒等 → Clash 输出逐字不变。
    const mapMember = (name: string) => name === 'DIRECT' ? directTag : name;
    const rulesets = parsed?.rulesets || [];
    const parsedProxyGroups = parsed?.proxyGroups || [];
    const fallbackNodes = nodeNames.length ? nodeNames : [directTag];

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
            proxyList = type === 'select' ? [directTag, ...fallbackNodes] : [...fallbackNodes];
        }
        // 本次分组是否为「拦截组」：成员里含 REJECT/REJECT-DROP。
        // 判定必须在下面的哨兵过滤**之前**（过滤后 REJECT 就没了）；标记由 buildAclSingbox 消费。
        let blocking = false;
        // 过滤自引用，避免环路；并归一模板里显式书写的大写 DIRECT（仅 sing-box 目标生效）
        proxyList = proxyList.filter(p => p !== pg.name).map(mapMember);
        // 仅 sing-box 目标：滤掉 Clash 专有的内置策略名（如 `[]REJECT`）——它们在 sing-box 里没有出站 tag，
        // 留着就是 `selector/urltest -> REJECT` 悬空引用、整份配置加载失败。
        // Clash 目标保留（REJECT 是 mihomo 合法内置策略），故此处只对 singbox 生效。
        if (targetClient === 'singbox') {
            blocking = proxyList.some(p => REJECT_POLICY_MEMBERS.has(p));
            proxyList = proxyList.filter(p => !CLASH_ONLY_POLICY_MEMBERS.has(p));
            // 成员全是哨兵名时（模板只写了 `[]REJECT`）退回节点清单，避免生成 outbounds 为空的组
            if (proxyList.length === 0) proxyList = fallbackNodes;
        }

        const group: AclGroup = { name: pg.name, type, proxies: proxyList };
        if (blocking) group.blocking = true;
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
                g.proxies.splice(idx, 1, ...nodeNames, directTag);
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

    const inlineRules = rulesets
        .filter((r): r is InlineRuleSetEntry => r.type === 'inline')
        .filter(r => r.ruleType !== undefined && r.ruleType !== null);

    return { groups, ruleProviders, inlineRules };
}

/* ------------------------- Clash 规则类型白名单 ------------------------- */

/**
 * C11：mihomo 支持的规则类型白名单（FINAL 单独处理为 MATCH，不在此列）。
 * ACL4SSR 模板里常见 Clash 不支持的规则行（`SRC-IP-CIDR` / `SRC-PORT` / `IN-PORT` 等），
 * 原样写入 rules 会被 mihomo 当成未知规则类型而整份配置被拒。故只放行确知支持的类型，
 * 其余在 buildAclClash 里跳过并 warn（口径与 keepGroup 一致），而不是猜一个替代规则。
 * 注意：URL-REGEX 是 mihomo 合法类型，模板用它时并不算未知类型。
 */
export const CLASH_SUPPORTED_RULE_TYPES: ReadonlySet<string> = new Set([
    'DOMAIN',
    'DOMAIN-SUFFIX',
    'DOMAIN-KEYWORD',
    'DOMAIN-REGEX',
    'GEOSITE',
    'GEOIP',
    'IP-CIDR',
    'IP-CIDR6',
    'IP-SUFFIX',
    'IP-ASN',
    'RULE-SET',
    'PROCESS-NAME',
    'PROCESS-PATH',
    'PROCESS-PATH-REGEX',
    'PROCESS-NAME-REGEX',
    'UID',
    'DST-PORT',
    'SUB-RULE',
    'MATCH',
    'AND',
    'OR',
    'NOT',
    'URL-REGEX'
]);

/** 规则类型是否受 Clash/mihomo 支持（大小写不敏感；模板里 `[]Final` 之类的大小写差异不影响判定）。 */
export function isSupportedClashRuleType(ruleType: string): boolean {
    return CLASH_SUPPORTED_RULE_TYPES.has(ruleType.trim().toUpperCase());
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
    // 未生成组的规则引用悬空：模板 `ruleset=` 引用的组名必须有对应 `custom_proxy_group`，
    // 否则 RULE-SET / 普通规则 / MATCH 的策略指向不存在的组（mihomo 加载失败）。
    // 口径：丢弃该条规则（连同它专属的 rule-provider）并 warn，不猜替代组；
    // Clash 内置策略（DIRECT/REJECT 等）恒存在，视为已定义。
    const clashKnownGroups = new Set<string>([...groups.map(g => g.name), ...CLASH_BUILTIN_POLICIES]);
    const keepGroup = (group: string, ruleLabel: string): boolean => {
        if (clashKnownGroups.has(group)) return true;
        console.warn(`[ACL 分组] 丢弃引用未生成分组的规则 ${ruleLabel}: ${group}`);
        return false;
    };
    // 1) 规则集引用：RULE-SET,<providerName>,<策略组>
    const keptProviders: AclRuleProvider[] = [];
    for (const rp of ruleProviders) {
        if (!keepGroup(rp.group, `RULE-SET,${rp.name}`)) continue;
        keptProviders.push(rp);
        rules.push(`RULE-SET,${rp.name},${rp.group}`);
    }
    const providers = buildAclProviders(keptProviders);
    // 3) 内联规则（模板中 `ruleset=` 的裸规则）仍作为普通规则带策略组
    for (const rule of inlineRules) {
        const isFinal = rule.ruleType.toUpperCase() === 'FINAL';
        // C11：先按 Clash 支持的规则类型白名单过滤，未知类型原样下发会让 mihomo 拒绝整份配置。
        // 口径与 keepGroup 一致：丢弃该行并 warn，不猜替代规则（FINAL 走 MATCH，单独放行）。
        if (!isFinal && !isSupportedClashRuleType(rule.ruleType)) {
            console.warn(`[ACL 规则] 跳过 Clash 不支持的规则类型 ${rule.ruleType},${rule.ruleVal}: ${rule.group}`);
            continue;
        }
        if (!keepGroup(rule.group, isFinal ? 'MATCH' : `${rule.ruleType},${rule.ruleVal}`)) continue;
        if (isFinal) {
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
    // 内含两类：URL provider 服务端内联（inline），以及 geoip 规则所需的 remote/binary 规则集
    ruleSets: Array<RuleSet | { type: 'inline'; tag: string; rules: Array<Record<string, string[]>> }>;
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
                // C4：g.proxies 的占位展开已注入小写 direct（见 generateAclGroups 的 directTag），
                // 这里再补一个 direct 可能产生重复成员，故去重（Set 保序，不改变既有成员顺序）
                outbounds: [...new Set([...g.proxies, 'direct'])],
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

    // 未生成组的规则引用悬空：模板 `ruleset=` 引用的组名必须有对应 `custom_proxy_group`，
    // 否则 route rule 的 outbound 指向不存在的 tag（sing-box 启动期解析失败、整份配置不可用）。
    // 口径：丢弃该条规则（URL 规则集连同它的内联 rule_set 一起丢）并 warn，不猜替代组；
    // 'direct' 是内置直连出站、恒存在，视为已定义。
    const sbKnownGroups = new Set<string>([...groups.map(g => g.name), 'direct']);
    const keepGroup = (group: string, ruleLabel: string): boolean => {
        if (sbKnownGroups.has(group)) return true;
        console.warn(`[ACL 分组] 丢弃引用未生成分组的规则 ${ruleLabel}: ${group}`);
        return false;
    };

    // 拦截组（模板成员含 REJECT）：其 sing-box 出站成员已被滤掉 REJECT，只剩 direct/节点。
    // 指向它们的规则必须改写成 `action: "reject"`，否则广告/隐私/恶意域名变成直连或走节点（拦截失效）。
    const blockGroupTags = new Set(groups.filter(g => g.blocking).map(g => g.name));
    const isBlockTarget = (group: string): boolean => blockGroupTags.has(group);

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
            if (!keepGroup(val.group, `rule_set=${val.tag}`)) return;
            ruleSets.push({ type: 'inline', tag: val.tag, rules: val.rules });
            urlRules.push(isBlockTarget(val.group)
                ? { rule_set: val.tag, action: 'reject' }
                : { rule_set: val.tag, outbound: val.group });
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
        if (!keepGroup(rule.group, `${rule.ruleType},${rule.ruleVal}`)) continue;
        const type = rule.ruleType.toLowerCase();
        const ruleObj: RoutingRule = isBlockTarget(rule.group) ? { action: 'reject' } : { outbound: rule.group };
        if (type === 'domain') ruleObj.domain = [rule.ruleVal];
        else if (type === 'domain-suffix') ruleObj.domain_suffix = [rule.ruleVal];
        else if (type === 'domain-keyword') ruleObj.domain_keyword = [rule.ruleVal];
        else if (type === 'ipcidr' || type === 'ip-cidr') ruleObj.ip_cidr = [rule.ruleVal];
        else if (type === 'geoip') {
            // sing-box 1.8 弃用、1.12 **删除** legacy `geoip` 字段（1.14 实测：`parse rule[N]: geoip database is
            // deprecated ... removed in sing-box 1.12.0` → 整份配置加载失败）。官方迁移口径：
            // `geoip:"private"/"lan"` → `ip_is_private: true`；`geoip:"xx"` → 引用 rule_set `geoip-xx`。
            const cc = rule.ruleVal.trim().toLowerCase();
            if (cc === 'lan' || cc === 'private') {
                ruleObj.ip_is_private = true;
            } else {
                const tag = `geoip-${cc}`;
                // 与 sing-box/geo-assets.ts 的 geoip 规则集同 tag 同源（SagerNet/sing-geoip），故按 tag 去重
                if (!ruleSets.some(rs => rs.tag === tag)) {
                    ruleSets.push({
                        type: 'remote',
                        tag,
                        format: 'binary',
                        url: `https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/${tag}.srs`,
                        download_detour: 'direct'
                    });
                }
                ruleObj.rule_set = [tag];
            }
        }
        else if (type === 'process') ruleObj.process = [rule.ruleVal];
        else {
            // C14：未命中已知类型时绝不能把规则类型名（如 `URL-REGEX`）当成 rule_set tag 下发 ——
            // configs.ts 只并入 blockBypass/acl 的 ruleSets，该 tag 从不定义，sing-box 启动期校验直接失败。
            // 口径：跳过该条并 warn（与上方 keepGroup / convertClashRulesToSingbox 的未知类型处理一致）。
            console.warn(`[ACL 规则] 跳过 sing-box 不支持的规则类型 ${rule.ruleType},${rule.ruleVal}: ${rule.group}`);
            continue;
        }
        inlineRouteRules.push(ruleObj);
    }

    // FINAL 同理：它指向的组必须有定义，否则 route.final 悬空 → 退回下面的默认分组逻辑
    if (finalGroup && !sbKnownGroups.has(finalGroup)) {
        console.warn(`[ACL 分组] 丢弃引用未生成分组的规则 FINAL: ${finalGroup}`);
        finalGroup = undefined;
    }

    // 拦截组不能作为 route.final：sing-box 的 final 只能是出站 tag，没有 reject 形态。
    // 保持原样（该组退化为直连/节点）并明确告警，避免静默失效。
    if (finalGroup && isBlockTarget(finalGroup)) {
        console.warn(`[ACL 分组] FINAL 指向拦截组 ${finalGroup}：sing-box 无法把 final 表达为 reject，该组按直连/节点处理`);
    }

    // C3 同源兜底：模板只提供规则、一个分组都没生成时，默认 final 不能是「✅ Selector」——
    // 接管后该出站已被 sing-box/configs.ts 移除 → route.final 悬空、整份配置加载失败。
    // 退回 sing-box 一定存在的内置直连出站 direct（它不在 ACL_BUILTIN_GROUP_TAGS 中）。
    const final = finalGroup || (groups.length > 0 ? groups[0].name : 'direct');

    return {
        outboundGroups,
        rules: [...urlRules, ...inlineRouteRules],
        ruleSets,
        final,
    };
}