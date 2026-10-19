import { getDataset } from '@kv';
import { buildDNS } from './dns';
import { buildRoutingRules } from './routing';
import type { Balancer, Config, Observatory, Outbound } from '#types/xray';
import { buildDokodemoInbound, buildMixedInbound } from './inbounds';
import {
    buildChainOutbound,
    buildCleanProxyOutbound,
    buildWebsocketOutbound,
    buildWarpOutbound,
    buildFreedomOutbound
} from './outbounds';

import {
    buildEntryPortMap,
    getConfigItems,
    cleanProxyEntries,
    cleanProxyRemark,
    generateRemark,
    generateWsPath,
    pickEarlyData,
    isDomain,
    isHttps,
    getProtocols,
    parseHostPort,
    resetRemarkCounter
} from '@utils';

function buildBalancer(tag: string, selector: string, fallbackTag?: string): Balancer {
    return {
        tag,
        selector: [selector],
        strategy: {
            type: "leastPing",
        },
        fallbackTag
    };
}

async function buildConfig(
    remark: string,
    outbounds: Outbound[],
    isBalancer: boolean,
    isChain: boolean,
    balancerFallback: boolean,
    isWarp: boolean,
    isWorkerLess: boolean,
    outboundAddrs: string[],
    domainToStaticIPs?: string,
    customDns?: string,
    customDnsHosts?: string[]
): Promise<Config> {
    const {
        fakeDNS,
        bestWarpInterval,
        bestVLTRInterval,
        logLevel,
        allowLANConnection
    } = globalThis.settings;
    let balancers, observatory;

    if (isBalancer) {
        // C15：fallbackTag 必须指向本配置内真实存在的出站。原实现恒写死 "proxy-2"，
        // 但 proxy-N 只在存在第 N 个 proxy 出站时才创建（单节点场景只有 proxy-1）→ 悬空 tag。
        // 优先沿用 "proxy-2"（多节点行为不变），否则退回首个 proxy 出站；两者都无则整体省略。
        const fallbackTag = balancerFallback
            ? outbounds.find(outbound => outbound.tag === "proxy-2")?.tag
                ?? outbounds.find(outbound => outbound.tag === "proxy-1")?.tag
            : undefined;

        balancers = [buildBalancer("all-proxies", "proxy", fallbackTag)]
            .concatIf(isChain, buildBalancer("all-chains", "chain"));

        observatory = {
            subjectSelector: isChain ? ["chain", "proxy"] : ["proxy"],
            probeUrl: "https://www.gstatic.com/generate_204",
            probeInterval: `${isWarp
                ? bestWarpInterval
                : bestVLTRInterval}s`,
            enableConcurrency: true
        } satisfies Observatory;
    }

    const config: Config = {
        remarks: remark,
        version: {
            min: "26.2.6"
        },
        log: {
            loglevel: logLevel,
        },
        dns: await buildDNS(outboundAddrs, isWorkerLess, isWarp, domainToStaticIPs, customDns, customDnsHosts),
        inbounds: [
            buildMixedInbound(allowLANConnection, isWorkerLess, isWorkerLess || fakeDNS),
            buildDokodemoInbound(allowLANConnection),
            // buildTunInbound(isWorkerLess, fakeDNS)
        ],
        outbounds: [
            ...outbounds,
            {
                protocol: "dns",
                settings: {
                    rules: [
                        {
                            action: "hijack"
                        }
                    ]
                },
                tag: "dns-out"
            },
            {
                protocol: "freedom",
                settings: {
                    domainStrategy: "UseIP"
                },
                tag: "direct"
            },
            {
                protocol: "blackhole",
                settings: {
                    response: {
                        type: "http"
                    }
                },
                tag: "block"
            },
        ],
        routing: {
            domainStrategy: "IPIfNonMatch",
            rules: buildRoutingRules(isChain, isBalancer, isWorkerLess, isWarp),
            balancers
        },
        observatory,
        policy: {
            levels: {
                0: {
                    connIdle: 300,
                    handshake: 4,
                    uplinkOnly: 1,
                    downlinkOnly: 1
                }
            },
            system: {
                statsOutboundUplink: true,
                statsOutboundDownlink: true
            }
        },
        stats: {}
    };

    return config;
}

async function addBestPingConfigs(
    configs: Config[],
    totalAddresses: string[],
    proxyOutbounds: Outbound[],
    chainOutbounds: Outbound[],
    isFragment: boolean
) {
    const isChain = !!chainOutbounds.length;
    const chainSign = isChain ? '🔗 ' : '';
    const remark = `${chainSign}最佳延迟 🚀`;
    const outbounds = [
        ...chainOutbounds,
        ...proxyOutbounds
    ];

    const config = await buildConfig(remark, outbounds, true, isChain, true, false, false, totalAddresses);

    if (isChain) {
        await addBestPingConfigs(configs, totalAddresses, proxyOutbounds, [], isFragment);
    }

    configs.push(config);
}

async function addBestFragmentConfigs(
    configs: Config[],
    usedPaths: Set<string>,
    usedEds: Set<number>,
    chainProxy?: Outbound
) {
    const {
        httpConfig: { hostName },
        settings: { fragmentIntervalMin, fragmentIntervalMax },
        dict: { _VL_ }
    } = globalThis;

    const isChain = !!chainProxy;
    const outbounds: Outbound[] = [];
    const bestFragValues = [
        "1-5", "1-10", "10-20", "20-30",
        "30-40", "40-50", "50-60", "60-70",
        "70-80", "80-90", "90-100", "10-30",
        "20-40", "30-50", "40-60", "50-70",
        "60-80", "70-90", "80-100", "100-200"
    ];

    bestFragValues.forEach((fragLength, index) => {
        if (isChain) {
            const chain = modifyOutbound(chainProxy, `chain-${index + 1}`, usedEds, `proxy-${index + 1}`);
            outbounds.push(chain);
        }

        const proxy = buildWebsocketOutbound(`proxy-${index + 1}`, _VL_, hostName, 443, generateWsPath(usedPaths), pickEarlyData(usedEds), true, fragLength, `${fragmentIntervalMin}-${fragmentIntervalMax}`);
        outbounds.push(proxy);
    });

    const chainSign = isChain ? '🔗 ' : '';
    // C16 复核：chainSign 已同时作用于「最佳分片」与「最佳延迟」两处 remark（带链 🔗 / 无链无前缀），
    // 不存在两份 remark 相同的问题；递归先于 push 造成的「无链在前」与最佳延迟、逐节点分组的顺序一致，故不改顺序。
    const config = await buildConfig(
        `${chainSign}最佳分片 😎`,
        outbounds,
        true,
        isChain,
        false,
        false,
        false,
        [],
        hostName
    );

    if (chainProxy) {
        await addBestFragmentConfigs(configs, usedPaths, usedEds);
    }

    configs.push(config);
}

async function addWorkerlessConfigs(configs: Config[]) {
    const tlsFragment = buildFreedomOutbound(true, false, 'proxy');
    const udpNoise = buildFreedomOutbound(false, true, 'udp-noise');
    const httpFragment = buildFreedomOutbound(true, false, 'http-fragment', undefined, undefined, '1-1');
    const outbounds = [
        tlsFragment,
        httpFragment,
        udpNoise
    ];

    const cfDnsConfig = await buildConfig(
        `Workerless-01 ⭐`,
        outbounds,
        false,
        false,
        false,
        false,
        true,
        [],
        undefined,
        "cloudflare-dns.com",
        ["cloudflare.com"]
    );

    const googleDnsConfig = await buildConfig(
        `Workerless-02 ⭐`,
        outbounds,
        false,
        false,
        false,
        false,
        true,
        [],
        undefined,
        "dns.google",
        ["8.8.8.8", "8.8.4.4"]
    );

    configs.push(cfDnsConfig, googleDnsConfig);
}

export async function getXrCustomConfigs(isFragment: boolean): Promise<Response> {
    resetRemarkCounter();
    const { outProxy, ports, upstreamParams: { upstreamServer, upstreamPort } } = globalThis.settings;
    // 已占用路径池词集合（仅「节点随机路径」开启时生效）：每个 ws 出站各抽一个互不相同的伪装路径
    const usedPaths = new Set<string>();
    // 已占用 early-data 阈值集合：与 usedPaths 同粒度、同批次共享，保证任意两个节点的 ed 两两不同
    const usedEds = new Set<number>();
    const chainProxy = outProxy ? buildChainOutbound(pickEarlyData(usedEds)) : undefined;
    const items = await getConfigItems(isFragment);
    const entryPortMap = buildEntryPortMap();
    const totalPorts = ports.filter(port => !isFragment || isHttps(port));
    const protocols = getProtocols();

    if (upstreamServer && upstreamPort && !isFragment) {
        totalPorts.unshift(upstreamPort);
        items.unshift({ kind: 'address', value: upstreamServer });
    }

    const configs: Config[] = [];
    const proxies: Outbound[] = [];
    const chains: Outbound[] = [];
    // 最佳延迟组只由 WS 地址节点组成（代理条目是独立节点，不参与）
    const hosts = items
        .filter((item): item is { kind: 'address'; value: string } => item.kind === 'address')
        .map(item => item.value);
    let index = 1;

    // 按 cleanIPs 的输入顺序遍历：普通地址生成 VLESS/Trojan 节点，代理条目生成该协议自己的独立节点
    for (const item of items) {
        if (item.kind === 'proxy') {
            const remark = cleanProxyRemark(item.value);
            const outbound = buildCleanProxyOutbound(item.value, `cleanproxy-${index}`);
            configs.push(await buildConfig(remark, [outbound], false, false, false, false, false, [item.value.server]));
            index++;
            continue;
        }

        const host = item.value;
        for (const protocol of protocols) {
            const addrPorts = entryPortMap[host]?.length ? entryPortMap[host] : totalPorts;

            for (const port of addrPorts) {
                if ((port === upstreamPort) !== (host === upstreamServer)) continue;

                const outbound = buildWebsocketOutbound("proxy", protocol, host, port, generateWsPath(usedPaths), pickEarlyData(usedEds), isFragment);
                const proxy = modifyOutbound(outbound, `proxy-${index}`, usedEds);
                proxies.push(proxy);

                const remark = generateRemark(port, host, protocol, isFragment, false);
                const config = await buildConfig(remark, [outbound], false, false, false, false, false, [host]);
                configs.push(config);

                if (chainProxy) {
                    const remark = generateRemark(port, host, protocol, isFragment, true);
                    const chainConfig = await buildConfig(remark, [chainProxy, outbound], false, true, false, false, false, [host]);
                    configs.push(chainConfig);

                    const chain = modifyOutbound(chainProxy, `chain-${index}`, usedEds, `proxy-${index}`);
                    chains.push(chain);
                }

                index++;
            }
        }
    }

    await addBestPingConfigs(configs, hosts, proxies, chains, isFragment);

    if (isFragment) {
        await addBestFragmentConfigs(configs, usedPaths, usedEds, chainProxy);
        await addWorkerlessConfigs(configs);
    }

    return new Response(JSON.stringify(configs, null, 4), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store',
            'CDN-Cache-Control': 'no-store'
        }
    });
}

export async function getXrWarpConfigs(
    request: Request,
    env: Env,
    isPro: boolean,
    isKnocker: boolean
): Promise<Response> {
    const { warpEndpoints } = globalThis.settings;
    const { warpAccounts } = await getDataset(request, env);

    const proIndicator = isPro ? ' Pro ' : ' ';
    const configs: Config[] = [];
    const proxies: Outbound[] = [];
    const chains: Outbound[] = [];
    const outboundDomains: string[] = [];

    for (const [index, endpoint] of warpEndpoints.entries()) {
        const { host } = parseHostPort(endpoint);
        if (isDomain(host)) outboundDomains.push(host);

        const warpOutbound = buildWarpOutbound(warpAccounts[0], endpoint, false, isPro, isKnocker);
        const wowOutbound = buildWarpOutbound(warpAccounts[1], endpoint, true, isPro, isKnocker);

        const warpConfig = await buildConfig(
            `Warp_${String(index + 1).padStart(2, '0')}${proIndicator}🇮🇷`,
            [warpOutbound],
            false,
            false,
            false,
            true,
            false,
            [host]
        );

        const wowConfig = await buildConfig(
            `WoW_${String(index + 1).padStart(2, '0')}${proIndicator}🌍`,
            [wowOutbound, warpOutbound],
            false,
            true,
            false,
            true,
            false,
            [host]
        );

        configs.push(warpConfig, wowConfig);

        const proxy = modifyOutbound(warpOutbound, `proxy-${index + 1}`);
        proxies.push(proxy);

        // warp / WoW 出站无 wsSettings，不涉及 early-data，故 usedEds 传 undefined
        const chain = modifyOutbound(wowOutbound, `chain-${index + 1}`, undefined, `proxy-${index + 1}`);
        chains.push(chain);
    }

    // Clean IPs / Domains 里的代理条目 → 独立可选节点
    //（只做节点：不挂 dialerProxy、不进 proxies/chains 数组，因此不参与链式与最佳延迟组）
    let cleanProxyIndex = 1;
    for (const proxy of cleanProxyEntries(globalThis.settings.cleanIPs || [])) {
        const outbound = buildCleanProxyOutbound(proxy, `cleanproxy-${cleanProxyIndex++}`);
        configs.push(await buildConfig(
            cleanProxyRemark(proxy),
            [outbound],
            false,
            false,
            false,
            true,
            false,
            [proxy.server]
        ));
    }

    const warpBestPing = await buildConfig(
        `Warp${proIndicator}- 最佳延迟 🚀`,
        [...proxies],
        true,
        false,
        false,
        true,
        false,
        outboundDomains
    );

    const wowBestPing = await buildConfig(
        `WoW${proIndicator}- 最佳延迟 🚀`,
        [...chains, ...proxies],
        true,
        true,
        false,
        true,
        false,
        outboundDomains
    );

    configs.push(warpBestPing, wowBestPing);

    return new Response(JSON.stringify(configs, null, 4), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store',
            'CDN-Cache-Control': 'no-store'
        }
    });
}

function modifyOutbound(outbound: Outbound, tag: string, usedEds?: Set<number>, dialerProxy?: string): Outbound {
    const newOutbound = structuredClone(outbound);
    newOutbound.tag = tag;

    if (dialerProxy && newOutbound.streamSettings?.sockopt) {
        newOutbound.streamSettings.sockopt.dialerProxy = dialerProxy;
    }

    // 克隆体不得继承源节点的 early-data：在共享去重池中重新无放回抽取，
    // 并保持「有值才写协议头」的自洽（pickEarlyData 必返回 2048..2560 的正整数）。
    const wsSettings = newOutbound.streamSettings?.wsSettings;
    if (wsSettings) {
        wsSettings.maxEarlyData = pickEarlyData(usedEds);
        wsSettings.earlyDataHeaderName = "Sec-WebSocket-Protocol";
    }

    return newOutbound;
}
