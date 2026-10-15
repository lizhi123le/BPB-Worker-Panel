import {
    base64ToDecimal,
    buildEntryPortMap,
    isHttps,
    toRange,
    selectSniHost,
    pickRandomEch,
    type CleanProxyEntry
} from '@utils';

import {
    Outbound,
    StreamSettings,
    Sockopt,
    VlessSettings,
    TrojanSettings,
    TlsSettings,
    RealitySettings,
    RawSettings,
    WsSettings,
    HttpupgradeSettings,
    GrpcSettings,
    HttpSocksSettings,
    ShadowsocksSettings,
    VmessSettings,
    Noise,
    FreedomSettings,
    WireguardSettings,
    Fingerprint,
    TransportType,
    DomainStrategy,
    Transport,
    FinalMask,
    FragmentPacket
} from '#types/xray';

function buildOutbound<T>(
    protocol: string,
    tag: string,
    enableMux: boolean,
    settings: T,
    streamSettings?: StreamSettings
): Outbound {
    return {
        protocol,
        mux: enableMux ? {
            enabled: true,
            concurrency: 8,
            xudpConcurrency: 16,
            xudpProxyUDP443: "reject"
        } : undefined,
        settings: settings,
        streamSettings,
        tag
    } as Outbound;
}

export function buildFreedomOutbound(
    isFragment: boolean,
    isUdpNoises: boolean,
    tag: string,
    length?: string,
    interval?: string,
    packets?: FragmentPacket
): Outbound {
    const { enableTFO, enableIPv6 } = globalThis.settings;
    const freedomSettings: FreedomSettings = {
        domainStrategy: isFragment ? undefined : enableIPv6 ? "UseIPv4v6" : "UseIPv4"
    };

    const streamSettings: StreamSettings = {
        sockopt: isFragment ? buildSockopt(true, enableTFO, "UseIP") : undefined,
        finalmask: buildFinalMask(isFragment, isUdpNoises, length, interval, packets)
    };

    return {
        protocol: "freedom",
        settings: freedomSettings,
        streamSettings,
        tag
    } satisfies Outbound;
}

export function buildWebsocketOutbound(
    tag: string,
    protocol: string,
    address: string,
    port: number,
    path: string,
    earlyData: number,
    isFragment: boolean,
    fragLength?: string,
    fragInterval?: string
): Outbound {
    const {
        settings: {
            fingerprint,
            alpn,
            enableTFO,
            enableECH,
            echServerName,
            hostSniList,
            upstreamParams: { upstreamServer }
        },
        globalConfig: { userID, TrPass },
        dict: { _VL_ }
    } = globalThis;

    // 与 handlers.ts#buildConfig（URI 侧）的判定逐字一致：显式端口表里出现过该端口即按 TLS 处理，
    // 否则同一节点会出现 URI 写 security=tls、JSON 写 security=none 的自相矛盾配置。
    // entryPortMap 每个出站构造时局部重算（无模块级状态，语义同 xray/configs.ts 的请求内求值）。
    const entryPortMap = buildEntryPortMap();
    const isTLS = isHttps(port) || address === upstreamServer || Object.values(entryPortMap).some(ports => ports.includes(port));
    const { host, sni, allowInsecure } = selectSniHost(address, pickRandomEch(hostSniList));
    // G13-C10：echServerName 名单为空时回退到该节点的 host，与 handlers.ts#buildConfig（URI 侧）的
    // `pickRandomEch(echServerName) || host` 逐字一致，避免同一节点出现「URI 有 ech、JSON 无 ECH」的分歧。
    const pickedEch = enableECH && !isFragment ? (pickRandomEch(echServerName) || host) : undefined;
    const tlsSettings = isTLS ? buildTlsSettings(
        sni,
        fingerprint,
        allowInsecure,
        !!pickedEch,
        pickedEch,
        // G13-C7：仅当本节点真的启用 ECH（pickedEch 有值）时才抑制 alpn；分片节点本就不启用 ECH
        // （pickedEch 为 undefined），必须放行 alpn，否则该节点既无 ECH 也无 alpn。
        pickedEch ? undefined : (alpn || undefined),
    ) : undefined;

    const streamSettings: StreamSettings = {
        network: "ws",
        // early-data：由调用点用 pickEarlyData(usedEds) 无放回抽取（2048..2560）后传入，本函数不产生随机，
        // 以保证同一份订阅内任意两个节点的 ed 两两不同（与 generateWsPath 在调用点求值同一套路）。
        // 下限不再取更低：ed 是「首包长度阈值」，首包超过它会直接不启用 Early Data（丢 0-RTT）。
        ...buildTransport("ws", "none", path, host, earlyData),
        security: isTLS ? "tls" : "none",
        tlsSettings,
        sockopt: buildSockopt(true, enableTFO, "UseIP"),
        finalmask: buildFinalMask(isFragment, false, fragLength, fragInterval)
    };

    if (protocol === _VL_) return buildOutbound<VlessSettings>(protocol, tag, false, {
        vnext: [{
            address,
            port,
            users: [
                {
                    id: userID,
                    encryption: "none"
                }
            ]
        }]
    }, streamSettings);

    return buildOutbound<TrojanSettings>(protocol, tag, false, {
        servers: [{
            address,
            port,
            password: TrPass
        }]
    }, streamSettings);
}

export function buildWarpOutbound(
    warpAccount: WarpAccount,
    endpoint: string,
    isWoW: boolean,
    isPro: boolean,
    isKnocker: boolean
): Outbound {
    const { warpIPv6, reserved, publicKey, privateKey } = warpAccount;
    let wgSettings: WireguardSettings = {
        address: [
            "172.16.0.2/32",
            warpIPv6
        ],
        mtu: 1280,
        peers: [
            {
                endpoint: isWoW ? "162.159.192.1:2408" : endpoint,
                publicKey: publicKey,
                keepAlive: 5
            }
        ],
        // G13-C17：Xray 的 WireguardSettings.reserved 声明为 number[]（xray.d.ts:332），
        // 与 Clash 的 base64 字符串（clash.d.ts:181）属内核 schema 差异，故此处保持十进制字节数组不变。
        reserved: base64ToDecimal(reserved),
        secretKey: privateKey
    };

    const streamSettings: StreamSettings = {};
    if (isWoW) {
        streamSettings.sockopt = buildSockopt(false, false, undefined, "proxy");
    } else if (isPro) {
        if (isKnocker) {
            const {
                knockerNoiseMode,
                noiseCountMin,
                noiseCountMax,
                noiseSizeMin,
                noiseSizeMax,
                noiseDelayMin,
                noiseDelayMax
            } = globalThis.settings;

            wgSettings = {
                ...wgSettings,
                wnoise: knockerNoiseMode,
                wnoisecount: toRange(noiseCountMin, noiseCountMax),
                wpayloadsize: toRange(noiseSizeMin, noiseSizeMax),
                wnoisedelay: toRange(noiseDelayMin, noiseDelayMax)
            };

        } else {
            streamSettings.finalmask = buildFinalMask(false, isPro)
        }
    }

    return {
        protocol: "wireguard",
        settings: wgSettings,
        streamSettings: streamSettings.omitEmpty(),
        tag: isWoW ? "chain" : "proxy"
    } satisfies Outbound;
}

// earlyData：链式出站同样启用 early-data，由调用点用 pickEarlyData(usedEds) 抽取，与主出站共用去重池
/**
 * Clean IPs / Domains 里的 socks / socks5 / http(s) 代理条目 → 独立可选节点出站。
 * 与链式出站的区别：不挂 dialerProxy、不做链式，就是这个节点自己的出站。
 */
export function buildCleanProxyOutbound(proxy: CleanProxyEntry, tag: string): Outbound {
    const isHttpsProxy = proxy.protocol === 'https';
    const streamSettings: StreamSettings = {
        network: 'tcp',
        security: isHttpsProxy ? 'tls' : 'none',
        // HTTPS 代理：对代理本身做 TLS，SNI 取代理主机名，不做 insecure 放行
        tlsSettings: isHttpsProxy ? buildTlsSettings(proxy.server, undefined, false, false) : undefined,
        sockopt: buildSockopt(false, false, 'UseIPv4')
    };

    const hasCredentials = Boolean(proxy.username || proxy.password);

    return buildOutbound<HttpSocksSettings>(
        // xray 的 socks 出站协议名为 socks（socks / socks5 都归它）
        (proxy.protocol === 'http' || isHttpsProxy) ? 'http' : 'socks',
        tag,
        true,
        {
            servers: [{
                address: proxy.server,
                port: proxy.port,
                ...(hasCredentials ? {
                    users: [{ user: proxy.username ?? '', pass: proxy.password ?? '' }]
                } : {})
            }]
        },
        streamSettings
    );
}

export function buildChainOutbound(earlyData: number): Outbound | undefined {
    const {
        dict: { _VL_, _TR_, _SS_, _VM_ },
        settings: {
            outProxyParams: {
                protocol, server: address, port,
                user, pass, password, method, uuid,
                flow, security, type, sni, fp,
                host, path, alpn, pbk, sid, spx,
                headerType, serviceName, mode,
                authority
            }
        }
    } = globalThis;

    const streamSettings: StreamSettings = {
        network: type || "raw",
        ...buildTransport(type, headerType, path, host, earlyData, serviceName, mode, authority),
        security,
        // 链式出站（outProxy）不经 selectSniHost，无 customCdnAddrs 语义 → allowInsecure 恒 false（行为不变）
        tlsSettings: security === 'tls' ? buildTlsSettings(sni || address, fp, false, false, undefined, alpn) : undefined,
        realitySettings: security === "reality" ? buildRealitySettings(sni, fp, pbk, sid, spx) : undefined,
        sockopt: buildSockopt(false, false, "UseIPv4", "proxy")
    };

    const enableMux = !(security === "reality" || type === "grpc");

    switch (protocol) {
        case 'http':
        case 'socks':
            return buildOutbound<HttpSocksSettings>(protocol, "chain", enableMux, {
                servers: [{
                    address,
                    port,
                    users: [{
                        user,
                        pass
                    }]
                }]
            }, streamSettings);

        case _SS_:
            return buildOutbound<ShadowsocksSettings>(protocol, "chain", enableMux, {
                servers: [{
                    address,
                    port,
                    method,
                    password
                }]
            }, streamSettings);

        case _VL_:
            return buildOutbound<VlessSettings>(protocol, "chain", enableMux, {
                vnext: [{
                    address,
                    port,
                    users: [{
                        id: uuid,
                        flow: flow,
                        encryption: "none"
                    }]
                }]
            }, streamSettings);

        case _VM_:
            return buildOutbound<VmessSettings>(protocol, "chain", enableMux, {
                vnext: [{
                    address,
                    port,
                    users: [{
                        id: uuid,
                        security: "auto"
                    }]
                }]
            }, streamSettings);

        case _TR_:
            return buildOutbound<TrojanSettings>(protocol, "chain", enableMux, {
                servers: [{
                    address,
                    port,
                    password
                }]
            }, streamSettings);

        default:
            return undefined;
    }
}

function buildTransport(
    type: TransportType,
    headerType?: "http" | "none",
    path: string = "/",
    host?: string,
    earlyData?: number,
    serviceName?: string,
    mode?: string,
    authority?: string
): Record<string, Transport> {
    switch (type) {
        case 'tcp':
        case 'raw':
            return {
                rawSettings: {
                    header: headerType === 'http'
                        ? {
                            type: "http",
                            request: {
                                headers: {
                                    "Host": host?.split(','),
                                    "Accept-Encoding": ["gzip, deflate"],
                                    "Connection": ["keep-alive"],
                                    "Pragma": "no-cache"
                                },
                                path: path.split(','),
                                method: "GET",
                                version: "1.1"
                            }
                        }
                        : { type: "none" }
                } satisfies RawSettings
            };

        case 'ws':
            return {
                wsSettings: {
                    host: host,
                    path: path,
                    maxEarlyData: earlyData,
                    earlyDataHeaderName: earlyData ? "Sec-WebSocket-Protocol" : undefined
                } satisfies WsSettings
            };

        case 'httpupgrade':
            return {
                httpupgradeSettings: {
                    host: host,
                    path: path
                } satisfies HttpupgradeSettings
            };

        case 'grpc':
            return {
                grpcSettings: {
                    authority: authority,
                    multiMode: mode === 'multi',
                    serviceName: serviceName
                } satisfies GrpcSettings
            };

        default:
            return {};
    };
}

function buildSockopt(
    enableHappyEyeballs: boolean,
    tcpFastOpen: boolean,
    domainStrategy?: DomainStrategy,
    dialerProxy?: string
): Sockopt {
    return {
        domainStrategy,
        dialerProxy,
        tcpFastOpen: tcpFastOpen || undefined,
        happyEyeballs: enableHappyEyeballs ? {
            tryDelayMs: 250,
            prioritizeIPv6: false,
            interleave: 2,
            maxConcurrentTry: 4
        } : undefined
    };
}

function buildTlsSettings(
    serverName: string,
    fingerprint: Fingerprint | undefined,
    allowInsecure: boolean,
    enableECH: boolean,
    echServerName?: string,
    alpn?: string
): TlsSettings & { allowInsecure: boolean } {
    const { localDNS, remoteDNS } = globalThis.settings;
    // H3：ECH 配置查询（HTTPS RR）改走 DoH（remoteDNS），不再用明文 UDP ——
    // 否则刚要用 ECH 藏起来的域名会在同一跳被明文 DNS 交出去。
    // remoteDNS 非 DoH（如被填成裸 IP 或 tls://）时保持原有 udp://localDNS 行为，避免生成非法配置。
    const echQueryDNS = /^https:\/\//i.test(remoteDNS)
        ? remoteDNS
        : `udp://${localDNS === "localhost" ? "8.8.8.8" : localDNS}`;

    return {
        serverName,
        // G13-C9：xray.d.ts 的 Fingerprint 联合类型已含 "randomized"（xray.d.ts:16-26），
        // 本端可直接原样下发；Clash 才需要映射成 "random"（只需一端做映射，此处保持直通）。
        // 无 fingerprint（HTTPS 代理这类只需校验证书的场景）时不写该字段。
        ...(fingerprint ? { fingerprint } : {}),
        // 与 sing-box 的 insecure / Clash 的 skip-cert-verify 同源同值：仅当地址来自 customCdnAddrs 时为 true
        allowInsecure,
        alpn: alpn?.split(','),
        echConfigList: enableECH
            ? echServerName
                ? `${echServerName}+${echQueryDNS}`
                : echQueryDNS
            : undefined
    }
}

function buildRealitySettings(
    serverName: string,
    fingerprint: Fingerprint,
    publicKey: string,
    shortId: string,
    spiderX: string
): RealitySettings {
    return {
        serverName,
        fingerprint: fingerprint,
        publicKey,
        shortId,
        spiderX,
        show: false,
        allowInsecure: false
    }
}

function buildUDPNoises(panelNoises: XrUdpNoise[]): Noise[] {
    return panelNoises.flatMap(({ type, packet, delay, count }) => {
        const noise: Noise = type === "rand"
            ? {
                rand: packet,
                randRange: "0-255",
                delay
            }
            : {
                type,
                packet: type === "array" ? packet.split(",").map(Number) : packet,
                delay
            };

        return Array.from({ length: count }, () => noise);
    });
}

function buildFinalMask(
    isFragment: boolean,
    isUdpNoise: boolean,
    fragLength?: string,
    fragDelay?: string,
    fragPacket?: FragmentPacket
): FinalMask | undefined {
    if (!isFragment && !isUdpNoise) return;
    const {
        settings: {
            fragmentPackets,
            fragmentLengthMin,
            fragmentLengthMax,
            fragmentIntervalMin,
            fragmentIntervalMax,
            fragmentMaxSplitMin,
            fragmentMaxSplitMax,
            xrayUdpNoises
        }
    } = globalThis;

    return {
        tcp: isFragment ? [
            {
                type: "fragment",
                settings: {
                    packets: fragPacket || fragmentPackets,
                    length: fragLength || toRange(fragmentLengthMin, fragmentLengthMax) as string,
                    delay: fragDelay || toRange(fragmentIntervalMin, fragmentIntervalMax) as string,
                    maxSplit: toRange(fragmentMaxSplitMin, fragmentMaxSplitMax)
                }
            }
        ] : undefined,
        udp: isUdpNoise ? [
            {
                type: "noise",
                settings: {
                    reset: "30-60",
                    noise: buildUDPNoises(xrayUdpNoises)
                }
            }
        ] : undefined
    }
}