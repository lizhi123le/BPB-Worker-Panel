import { getDataset } from '@kv';
import { buildDNS } from './dns';
import { buildRoutingRules } from './routing';
import { buildChainOutbound, buildUrlTest, buildWarpOutbound, buildWebsocketOutbound } from './outbounds.js';
import { Outbound, WireguardEndpoint, Config } from '#types/sing-box';
import { buildEntryPortMap, getConfigAddresses, generateRemark, isHttps, getProtocols, resetRemarkCounter } from '@utils';
import { buildMixedInbound, tun } from './inbounds';

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
    const chainProxy = outProxy ? buildChainOutbound() : undefined;
    const isChain = !!chainProxy;
    const protocols = getProtocols();
    const hosts = await getConfigAddresses(isFragment);
    const entryPortMap = buildEntryPortMap();
    const totalPorts = ports.filter(port => !isFragment || isHttps(port));

    if (upstreamServer && upstreamPort && !isFragment) {
        totalPorts.unshift(upstreamPort);
        hosts.unshift(upstreamServer);
    }

    const proxyTags: string[] = [];
    const chainTags: string[] = [];
    const outbounds: Outbound[] = [];

    const selectorTags = ["最佳延迟 🚀"].concatIf(isChain, "🔗 最佳延迟 🚀");

    for (const protocol of protocols) {
        for (const host of hosts) {
            const addrPorts = entryPortMap[host] ? [entryPortMap[host]] : totalPorts;

            for (const port of addrPorts) {
                if ((port === upstreamPort) !== (host === upstreamServer)) continue;

                const tag = generateRemark(port, host, protocol, isFragment, false);
                const outbound = buildWebsocketOutbound(protocol, tag, host, port, isFragment);

                outbounds.push(outbound);
                proxyTags.push(tag);
                selectorTags.push(tag);

                if (isChain) {
                    const chainTag = generateRemark(port, host, protocol, isFragment, true);
                    const chain = structuredClone(chainProxy);
                    chain.tag = chainTag;
                    chain.detour = tag;
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
        const warpTag = `Warp-${String(index + 1).padStart(2, '0')} 🇮🇷`;
        proxyTags.push(warpTag);

        const wowTag = `WoW-${String(index + 1).padStart(2, '0')} 🌍`;
        chainTags.push(wowTag);

        selectorTags.push(warpTag, wowTag);
        const warpOutbound = buildWarpOutbound(warpAccounts[0], warpTag, endpoint);
        const wowOutbound = buildWarpOutbound(warpAccounts[1], wowTag, endpoint, warpTag);
        outbounds.push(warpOutbound, wowOutbound);
    });

    const config = await buildConfig(
        [],
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