import { getDataset } from '@kv';
import { buildDNS, retargetDnsDetour } from './dns';
import { buildRoutingRules, buildBlockAndBypassRules, buildBaseRoutingRules } from './routing';
import { buildChainOutbound, buildCleanProxyOutbound, buildUrlTest, buildWarpOutbound, buildWebsocketOutbound, getChainExplicitEarlyData, redrawChainEarlyData } from './outbounds.js';
import { Outbound, WireguardEndpoint, Config } from '#types/sing-box';
import { buildEntryPortMap, getConfigItems, cleanProxyEntries, cleanProxyRemark, generateRemark, generateWsPath, isHttps, getProtocols, pickEarlyData, resetRemarkCounter } from '@utils';
import { buildMixedInbound, tun } from './inbounds';
import { buildAclSingbox, ACL_BUILTIN_GROUP_TAGS } from '../acl-template';
import { DEFAULT_ACL_TEMPLATE_URL } from '../../common/defaults';

async function buildConfig(
    outbounds: Outbound[],
    endpoints: WireguardEndpoint[],
    selectorTags: string[],
    urlTestTags: string[],
    secondUrlTestTags: string[],
    isWarp: boolean,
    isChain: boolean
): Promise<Config> {
    const { logLevel } = globalThis.settings;

    const config: Config = {
        log: {
            disabled: logLevel === "none",
            level: logLevel === "none" ? undefined : logLevel === "warning" ? "warn" : logLevel,
            timestamp: true
        },
        dns: await buildDNS(isWarp, isChain),
        // 1.14.0 起远程规则集必须显式指定 HTTP 客户端，否则报
        // “implicit default HTTP client using default outbound for remote rule-sets is deprecated in
        //  sing-box 1.14.0 and will be removed in sing-box 1.16.0”。
        // 这里声明一个固定走 direct 下载的客户端（等价于旧的 download_detour: "direct"，但用的是新 schema），
        // 并由下方 route.default_http_client 设为全局默认，覆盖 geoip/geosite 与 ACL 模板的全部远程规则集。
        http_clients: [
            { tag: "http-direct", detour: "direct" }
        ],
        inbounds: [
            tun,
            buildMixedInbound()
        ],
        outbounds: [
            ...outbounds,
            {
                type: "selector",
                tag: "✅ Selector",
                outbounds: selectorTags,
                interrupt_exist_connections: false
            },
            {
                type: "direct",
                tag: "direct",
                domain_resolver: "dns-direct"
            }
        ],
        endpoints: endpoints.omitEmpty(),
        route: buildRoutingRules(isWarp),
        ntp: {
            enabled: true,
            server: "time.cloudflare.com",
            server_port: 123,
            domain_resolver: "dns-direct",
            interval: "30m",
            write_to_system: false
        },
        experimental: {
            cache_file: {
                enabled: true,
                store_fakeip: true
            },
            clash_api: {
                external_controller: "127.0.0.1:9090",
                external_ui: "ui",
                default_mode: "Rule",
                external_ui_download_url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
                external_ui_download_detour: "direct"
            }
        }
    };

    // 远程规则集统一用上面声明的 HTTP 客户端下载（显式指定；从 config 自身取值，避免两处字面量漂移）
    config.route.default_http_client = config.http_clients[0].tag;

    const tag = isWarp ? "Warp - 最佳延迟 🚀" : "最佳延迟 🚀";
    const mainUrlTest = buildUrlTest(tag, urlTestTags, isWarp);
    config.outbounds.push(mainUrlTest);
    if (isWarp) config.outbounds.push(buildUrlTest("WoW - 最佳延迟 🚀", secondUrlTestTags, isWarp));
    if (isChain) config.outbounds.push(buildUrlTest("🔗 最佳延迟 🚀", secondUrlTestTags, isWarp));

    return config;
}

export async function getSbCustomConfig(isFragment: boolean): Promise<Response> {
    resetRemarkCounter();
    const { outProxy, ports, upstreamParams: { upstreamServer, upstreamPort } } = globalThis.settings;
    const protocols = getProtocols();
    const items = await getConfigItems(isFragment);
    const entryPortMap = buildEntryPortMap();
    const totalPorts = ports.filter(port => !isFragment || isHttps(port));
    // 已占用路径池词集合：每个 ws 出站各抽一个互不相同的伪装路径
    const usedPaths = new Set<string>();
    // 已占用 early-data 阈值池：作用域与 usedPaths 一致（一次请求一个集合），
    // 同一份订阅内任意两个节点的 ed 两两不同（无放回抽取）
    const usedEds = new Set<number>();
    const chainProxy = outProxy ? buildChainOutbound(usedEds) : undefined;
    const isChain = !!chainProxy;
    // 用户在 outProxy URI 里显式写的 ed：原型只是模板、不出现在输出中，
    // 故把该值待到链式克隆点上消费一次（只给第一个链式节点），其余节点仍从池中无放回抽取
    let pendingChainEd = getChainExplicitEarlyData();

    if (upstreamServer && upstreamPort && !isFragment) {
        totalPorts.unshift(upstreamPort);
        items.unshift({ kind: 'address', value: upstreamServer });
    }

    const proxyTags: string[] = [];
    const chainTags: string[] = [];
    const outbounds: Outbound[] = [];

    const selectorTags = ["最佳延迟 🚀"].concatIf(isChain, "🔗 最佳延迟 🚀");

    // 按 cleanIPs 的输入顺序遍历：普通地址生成 VLESS/Trojan 节点，代理条目生成独立 socks/http(s) 节点
    //（只做节点：不设 detour、不进链式分支）
    for (const item of items) {
        if (item.kind === 'proxy') {
            const tag = cleanProxyRemark(item.value);
            outbounds.push(buildCleanProxyOutbound(item.value, tag));
            proxyTags.push(tag);
            selectorTags.push(tag);
            continue;
        }

        const host = item.value;
        for (const protocol of protocols) {
            const addrPorts = entryPortMap[host]?.length ? entryPortMap[host] : totalPorts;

            for (const port of addrPorts) {
                if ((port === upstreamPort) !== (host === upstreamServer)) continue;

                const tag = generateRemark(port, host, protocol, isFragment, false);
                const outbound = buildWebsocketOutbound(protocol, tag, host, port, generateWsPath(usedPaths), isFragment, pickEarlyData(usedEds));

                outbounds.push(outbound);
                proxyTags.push(tag);
                selectorTags.push(tag);

                if (isChain) {
                    const chainTag = generateRemark(port, host, protocol, isFragment, true);
                    const chain = structuredClone(chainProxy);
                    chain.tag = chainTag;
                    chain.detour = tag;
                    // structuredClone 会连 transport 一起复制：克隆体不得继承源节点的 early-data，
                    // 必须从同一 usedEds 池重新无放回抽取（否则所有链式节点共用同一阈值，形成固定指纹）；
                    // 用户显式写的 ed 则恰好由第一个克隆体使用一次
                    redrawChainEarlyData(chain, usedEds, pendingChainEd);
                    pendingChainEd = undefined;
                    outbounds.push(chain);

                    chainTags.push(chainTag);
                    selectorTags.push(chainTag);
                }
            }
        }
    }

    const config = await buildConfig(
        outbounds,
        [],
        selectorTags,
        proxyTags,
        chainTags,
        false,
        isChain
    );

    // ACL4SSR 分组模板：load-balance/fallback → urltest，模板路由整体接管（失败回退默认）
    const { aclEnabled, aclTemplate } = globalThis.settings;
    // 启用分组模板但 Template URL 未填（空串/纯空白/缺失）→ 用内置远程模板地址兜底，
    // 避免「开关打开却静默不生效」。地址来源唯一：@common/defaults。
    const aclUrl = aclTemplate?.trim() || DEFAULT_ACL_TEMPLATE_URL;
    if (aclEnabled && aclUrl) {
        try {
            // 已配置的地址取不到有效内容（404 / 被墙 / 格式不符）时，旧行为是**静默跳过** ——
            // 用户只看到「开关已启用却仍是内置分组」。故退回内置地址再试一次；两次都取不到才保持内置分组。
            let acl = await buildAclSingbox(aclUrl, proxyTags);
            if ((!acl || (acl.outboundGroups.length === 0 && acl.rules.length === 0)) && aclUrl !== DEFAULT_ACL_TEMPLATE_URL) {
                console.warn('[ACL Config] 模板地址无有效内容，改用内置模板:', aclUrl);
                acl = await buildAclSingbox(DEFAULT_ACL_TEMPLATE_URL, proxyTags);
            }
            if (acl && (acl.outboundGroups.length > 0 || acl.rules.length > 0)) {
                // ACL 模板接管：去掉内置分组出站（✅ Selector 与各类「最佳延迟」），
                // 仅保留真实代理出站与 direct，路由与 final 由模板接管
                const retained = config.outbounds.filter(o => !ACL_BUILTIN_GROUP_TAGS.has(o.tag));
                config.outbounds = [...retained, ...acl.outboundGroups];
                // 拦截组（模板 `[]REJECT`）需要一个 `type:"block"` 出站作为成员载体：
                // 模板里的 REJECT 成员已映射到该 tag，缺了它 selector 就引用不存在的出站 ——
                // sing-box 的 check 不报，但客户端启动期解析出站失败、整份配置不可用。
                if (acl.blockOutbound) config.outbounds.push(acl.blockOutbound as unknown as Outbound);
                // C3：dns-remote 的 detour 原本指向被上面过滤掉的内置分组（✅ Selector / 各类「最佳延迟」），
                // 接管后这些 tag 已不存在 → sing-box 启动期解析出站失败、整份配置加载失败。
                // 改指向模板实际生成的默认分组（与 route.final 同义：由默认策略组解析 DoH）；
                // 模板一个分组都没生成时退回内置直连出站 direct —— 它不在移除集合里，必然存在。
                const aclGroupTags = new Set(acl.outboundGroups.map(g => g.tag));
                const aclDnsDetour = aclGroupTags.has(acl.final)
                    ? acl.final
                    : (acl.outboundGroups[0]?.tag ?? 'direct');
                retargetDnsDetour(config.dns, ACL_BUILTIN_GROUP_TAGS, aclDnsDetour);
                // C6：模板接管的是「分流」，不能连基础规则一起丢。原先只前置 Block/Bypass，
                // sniff、hijack-dns（含 172.19.0.2 上游 DNS 劫持）、ip_is_private 直连、UDP reject
                // 全被整表替换掉 → 接管后 DNS/局域网/嗅探行为静默改变（与 Clash 端 C5 对称）。
                // 顺序与 Clash 端 ACL 分支逐条对齐：基础规则 → Block/Bypass 拦截 → 模板规则。
                const baseRules = buildBaseRoutingRules(false);
                // 基础规则里 clash_mode "Global" 原本指向内置 "✅ Selector"，而该分组正是被上面滤掉的那个；
                // 悬空出站会让 sing-box 启动期解析失败 → 整份配置加载失败。改写为 aclDnsDetour（模板实际存在的
                // 出站，与 C3 的 dns-remote detour 同一目标），使「全局模式」切换在 ACL 下仍然有效。
                for (const rule of baseRules) {
                    if (rule.clash_mode === "Global") rule.outbound = aclDnsDetour;
                }
                const blockBypass = buildBlockAndBypassRules();
                config.route.rules = [
                    ...baseRules,
                    ...blockBypass.rules,
                    ...acl.rules
                ];
                // rule_set 合并：既有地理规则集 + 模板内联 rule_set，保证 block/bypass 引用可用。
                // 必须按 tag 去重：模板里的 `[]GEOIP,CN` 会生成 tag `geoip-cn`，与面板自身 geo 资源
                // （bypassChina → geo-assets `geoip-cn`）撞名；sing-box 对重复 tag 直接 FATAL
                // （1.14 实测：`initialize router: duplicate rule-set tag: geoip-cn`）→ 整份配置加载失败。
                // 保留首次出现者（面板自身资源在前，优先）。
                const mergedRuleSets = [...blockBypass.ruleSets, ...acl.ruleSets];
                const ruleSetTags = new Set<string>();
                config.route.rule_set = mergedRuleSets.filter(rs => {
                    if (ruleSetTags.has(rs.tag)) return false;
                    ruleSetTags.add(rs.tag);
                    return true;
                });
                config.route.final = acl.final;
            }
        } catch (error: any) {
            console.warn('[ACL Config] apply singbox template error:', error?.message || error);
        }
    }

    return new Response(JSON.stringify(config, null, 4), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store',
            'CDN-Cache-Control': 'no-store'
        }
    });
}

export async function getSbWarpConfig(request: Request, env: Env): Promise<Response> {
    const { warpEndpoints } = globalThis.settings;
    const { warpAccounts } = await getDataset(request, env);

    const proxyTags: string[] = [];
    const chainTags: string[] = [];
    const outbounds: WireguardEndpoint[] = [];
    const selectorTags = [
        "Warp - 最佳延迟 🚀",
        "WoW - 最佳延迟 🚀"
    ];

    warpEndpoints.forEach((endpoint, index) => {
        const warpTag = `Warp_${String(index + 1).padStart(2, '0')} 🇮🇷`;
        proxyTags.push(warpTag);

        const wowTag = `WoW_${String(index + 1).padStart(2, '0')} 🌍`;
        chainTags.push(wowTag);

        selectorTags.push(warpTag, wowTag);
        const warpOutbound = buildWarpOutbound(warpAccounts[0], warpTag, endpoint);
        const wowOutbound = buildWarpOutbound(warpAccounts[1], wowTag, endpoint, warpTag);
        outbounds.push(warpOutbound, wowOutbound);
    });

    // Clean IPs / Domains 里的代理条目 → 独立可选节点（只做节点：不设 detour、不进链式分组）
    const extraOutbounds: Outbound[] = [];
    for (const proxy of cleanProxyEntries(globalThis.settings.cleanIPs || [])) {
        const tag = cleanProxyRemark(proxy);
        extraOutbounds.push(buildCleanProxyOutbound(proxy, tag));
        proxyTags.push(tag);
        selectorTags.push(tag);
    }

    const config = await buildConfig(
        extraOutbounds,
        outbounds,
        selectorTags,
        proxyTags,
        chainTags,
        true,
        false
    );

    return new Response(JSON.stringify(config, null, 4), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store',
            'CDN-Cache-Control': 'no-store'
        }
    });
}