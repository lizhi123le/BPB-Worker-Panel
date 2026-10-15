import { getDataset } from '@kv';
import { buildDNS, retargetDnsDetour } from './dns';
import { buildRoutingRules, buildBaseRoutingRules, buildRuleProviders, buildBlockRules, buildBypassRules } from './routing';
import { buildChainOutbound, buildCleanProxyOutbound, buildUrlTest, buildWarpOutbound, buildWebsocketOutbound, getChainExplicitEarlyData, redrawChainEarlyData } from './outbounds';
import type { WireguardOutbound, Config, Outbound } from '#types/clash';
import { buildEntryPortMap, getConfigItems, cleanProxyEntries, cleanProxyRemark, generateRemark, generateWsPath, getProtocols, pickEarlyData, resetRemarkCounter } from '@utils';
import { sniffer, tun } from './inbounds';
import { buildAclClash, ACL_BUILTIN_GROUP_TAGS } from '../acl-template';
import { DEFAULT_ACL_TEMPLATE_URL } from '../../common/defaults';

async function buildConfig(
    outbounds: Outbound[],
    selectorTags: string[],
    proxyTags: string[],
    chainTags: string[],
    isChain: boolean,
    isWarp: boolean,
    isPro: boolean
): Promise<Config> {
    const { logLevel, allowLANConnection } = globalThis.settings;
    const tcpSettings = isWarp ? {} : {
        "disable-keep-alive": false,
        "keep-alive-idle": 10,
        "keep-alive-interval": 15,
        "tcp-concurrent": true
    };

    const config: Config = {
        "mixed-port": 7890,
        "ipv6": true,
        "allow-lan": allowLANConnection,
        "unified-delay": false,
        "log-level": logLevel.replace("none", "silent"),
        "mode": "rule",
        ...tcpSettings,
        "geo-auto-update": true,
        "geo-update-interval": 168,
        "external-controller": "127.0.0.1:9090",
        "external-controller-cors": {
            "allow-origins": ["*"],
            "allow-private-network": true
        },
        "external-ui": "ui",
        "external-ui-url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
        "profile": {
            "store-selected": true,
            "store-fake-ip": true
        },
        "dns": await buildDNS(isChain, isWarp, isPro),
        "tun": tun,
        "sniffer": sniffer,
        "proxies": outbounds,
        "proxy-groups": [
            {
                "name": "✅ Selector",
                "type": "select",
                "proxies": selectorTags
            }
        ],
        "rule-providers": buildRuleProviders(),
        "rules": buildRoutingRules(isWarp),
        "ntp": {
            "enable": true,
            "server": "time.cloudflare.com",
            "port": 123,
            "interval": 30
        }
    };

    const name = isWarp ? `Warp ${isPro ? "Pro " : ""}- 最佳延迟 🚀` : "最佳延迟 🚀";
    const mainUrlTest = buildUrlTest(name, proxyTags, isWarp);
    config["proxy-groups"].push(mainUrlTest);
    if (isWarp) config["proxy-groups"].push(buildUrlTest(`WoW ${isPro ? "Pro " : ""}- 最佳延迟 🚀`, chainTags, isWarp));
    if (isChain) config["proxy-groups"].push(buildUrlTest("🔗 最佳延迟 🚀", chainTags, isWarp));

    return config;
}

export async function getClNormalConfig(): Promise<Response> {
    resetRemarkCounter();
    const { outProxy, ports: cachedPorts, upstreamParams: { upstreamServer, upstreamPort } } = globalThis.settings;
    // C-01 同型缺陷：解构得到的是 globalThis.settings.ports 的引用，而它与 KV 缓存（kv-cache）
    // 是同一数组对象（init.ts 用 Object.assign 浅拷贝、kv-cache 返回内部引用），原地 unshift 会在
    // 同一 isolate 内每生成一次配置就累积一个重复端口（[443] → [1080,443] → [1080,1080,443]），
    // 并可能被后续 PUT 持久化。故只在局部副本上操作，绝不写回 globalThis.settings。
    const ports = [...(cachedPorts || [])];
    // 已占用路径池词集合：每个 ws 出站各抽一个互不相同的伪装路径
    const usedPaths = new Set<string>();
    // 已占用 early-data 阈值集合：每个 ws 出站各抽一个互不相同的 ed（无放回，两两不同）
    const usedEds = new Set<number>();
    // 用户显式给出的 ed：只让第一个链式产出节点使用，其余链式节点仍无放回抽取（保证两两不同）
    let pendingChainEd = getChainExplicitEarlyData();
    const chainProxy = outProxy ? buildChainOutbound(usedEds) : undefined;
    const isChain = !!chainProxy;
    const items = await getConfigItems(false);
    const entryPortMap = buildEntryPortMap();
    const protocols = getProtocols();

    if (upstreamServer && upstreamPort) {
        ports.unshift(upstreamPort);
        items.unshift({ kind: 'address', value: upstreamServer });
    }

    const proxyTags: string[] = [];
    const chainTags: string[] = [];
    const outbounds: Outbound[] = [];
    const selectorTags = ["最佳延迟 🚀"].concatIf(isChain, "🔗 最佳延迟 🚀");

    // 按 cleanIPs 的输入顺序遍历：普通地址生成 VLESS/Trojan 节点，代理条目生成独立 socks/http(s) 节点
    //（只做节点：不设 dialer-proxy、不进链式分支）
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
            const addrPorts = entryPortMap[host]?.length ? entryPortMap[host] : ports;

            for (const port of addrPorts) {
                if ((port === upstreamPort) !== (host === upstreamServer)) continue;

                const tag = generateRemark(port, host, protocol, false, false);
                const outbound = buildWebsocketOutbound(protocol, tag, host, port, generateWsPath(usedPaths), pickEarlyData(usedEds));

                if (outbound) {
                    proxyTags.push(tag);
                    selectorTags.push(tag);
                    outbounds.push(outbound);

                    if (isChain) {
                        const chainTag = generateRemark(port, host, protocol, false, true);
                        let chain = structuredClone(chainProxy);
                        // 克隆体不得继承源节点的 early-data：显式 ed 恰好给第一个克隆体，其余无放回重抽
                        redrawChainEarlyData(chain, usedEds, pendingChainEd);
                        pendingChainEd = undefined; // 只消费一次
                        chain['name'] = chainTag;
                        chain['dialer-proxy'] = tag;
                        outbounds.push(chain);

                        chainTags.push(chainTag);
                        selectorTags.push(chainTag);
                    }
                }
            }
        }
    }

    const config = await buildConfig(
        outbounds,
        selectorTags,
        proxyTags,
        chainTags,
        isChain,
        false,
        false
    );

    // ACL4SSR 分组模板：启用时用模板分组 + 规则整体接管（失败回退默认）
    const { aclEnabled, aclTemplate } = globalThis.settings;
    // 启用分组模板但 Template URL 未填（空串/纯空白/缺失）→ 用内置远程模板地址兜底，
    // 避免「开关打开却静默不生效」。地址来源唯一：@common/defaults。
    const aclUrl = aclTemplate?.trim() || DEFAULT_ACL_TEMPLATE_URL;
    if (aclEnabled && aclUrl) {
        try {
            // 已配置的地址取不到有效内容（404 / 被墙 / 格式不符）时，旧行为是**静默跳过** ——
            // 用户只看到「开关已启用却仍是内置分组」。故退回内置地址再试一次；两次都取不到才保持内置分组。
            let acl = await buildAclClash(aclUrl, proxyTags);
            if ((!acl || (acl.groups.length === 0 && acl.rules.length === 0)) && aclUrl !== DEFAULT_ACL_TEMPLATE_URL) {
                console.warn('[ACL Config] 模板地址无有效内容，改用内置模板:', aclUrl);
                acl = await buildAclClash(DEFAULT_ACL_TEMPLATE_URL, proxyTags);
            }
            if (acl && (acl.groups.length > 0 || acl.rules.length > 0)) {
                // ACL 模板接管：proxy-groups 整体替换为模板组（去掉内置 Selector/最佳延迟）
                config["proxy-groups"] = acl.groups;
                // C3：proxy-groups 被替换后，DNS 里 `#✅ Selector` / `#🔗 最佳延迟 🚀` 之类的 detour 随之悬空
                // （mihomo 解析到不存在的策略组）→ 改指向模板实际生成的第一个分组（等价旧语义：默认组解析 DoH）；
                // 模板一个分组都没生成时退回内置 DIRECT —— mihomo 恒存在，代价是 DoH 改走直连解析。
                const aclDnsDetour = acl.groups.length > 0 ? acl.groups[0].name : 'DIRECT';
                retargetDnsDetour(config.dns, ACL_BUILTIN_GROUP_TAGS, aclDnsDetour);
                // C5：ACL 接管重建 rules 时必须保留基础规则行（GEOIP,lan,DIRECT,no-resolve 与
                // NETWORK,udp,REJECT / AND,((NETWORK,udp),(DST-PORT,443)),REJECT），否则局域网不再直连、
                // UDP 也不再被策略性 reject，行为与未接管时不一致。
                // 顺序：base 基础行 → Block/Bypass 拦截（广告/色情/恶意/挖矿等 REJECT，国内/直连 DIRECT）
                // → 模板规则；Block/Bypass 放在模板规则之前，避免模板规则覆盖掉 Block 拦截。
                // 基础行传 false：本入口（getClNormalConfig）的 buildConfig isWarp 恒为 false，取非 Warp 分支。
                config.rules = [
                    ...buildBaseRoutingRules(false),
                    ...buildBlockRules(),
                    ...buildBypassRules(),
                    ...acl.rules.filter(r => !r.startsWith('MATCH,'))
                ];
                if (!config.rules.some(r => r.startsWith('MATCH,'))) {
                    const fallback = acl.groups.find(g => g.type === 'select') || acl.groups[0];
                    // 零分组兜底：模板只有规则、一个分组都没生成时，历史字面量 '🚀 节点选择' 并不存在
                    // （proxy-groups 为空）→ MATCH 策略悬空、mihomo 加载失败。退回内置 DIRECT（恒存在）。
                    config.rules.push(`MATCH,${fallback ? fallback.name : 'DIRECT'}`);
                }
                // 规则集引用：模板 provider 合并进既有 provider（避免重名），不清空
                const existingProviders = config["rule-providers"] || {};
                config["rule-providers"] = {
                    ...existingProviders,
                    ...(acl.providers || {})
                };
            }
        } catch (error: any) {
            console.warn('[ACL Config] apply clash template error:', error?.message || error);
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

export async function getClWarpConfig(request: Request, env: Env, isPro: boolean): Promise<Response> {
    const { warpEndpoints } = globalThis.settings;
    const { warpAccounts } = await getDataset(request, env);

    const proxyTags: string[] = [];
    const chainTags: string[] = [];
    const outbounds: WireguardOutbound[] = [];
    const proSign = isPro ? "Pro " : "";
    const selectorTags = [
        `Warp ${proSign}- 最佳延迟 🚀`,
        `WoW ${proSign}- 最佳延迟 🚀`
    ];

    warpEndpoints.forEach((endpoint, index) => {
        const warpTag = `Warp_${String(index + 1).padStart(2, '0')} ${proSign}🇮🇷`;
        proxyTags.push(warpTag);

        const wowTag = `WoW_${String(index + 1).padStart(2, '0')} ${proSign}🌍`;
        chainTags.push(wowTag);

        selectorTags.push(warpTag, wowTag);
        const warpOutbound = buildWarpOutbound(warpAccounts[0], warpTag, endpoint, '', isPro);
        const wowOutbound = buildWarpOutbound(warpAccounts[1], wowTag, endpoint, warpTag, false);
        outbounds.push(warpOutbound, wowOutbound);
    });

    // Clean IPs / Domains 里的代理条目 → 独立可选节点（只做节点：不设 dialer-proxy、不进链式分组）
    const cleanProxyOutbounds: Outbound[] = [];
    for (const proxy of cleanProxyEntries(globalThis.settings.cleanIPs || [])) {
        const tag = cleanProxyRemark(proxy);
        cleanProxyOutbounds.push(buildCleanProxyOutbound(proxy, tag));
        proxyTags.push(tag);
        selectorTags.push(tag);
    }

    const config = await buildConfig(
        [...outbounds, ...cleanProxyOutbounds],
        selectorTags,
        proxyTags,
        chainTags,
        false,
        true,
        isPro
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