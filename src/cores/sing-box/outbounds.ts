import {
    base64ToDecimal,
    parseHostPort,
    isDomain,
    isBareIPv4,
    isBareIPv6,
    // R-04 / R-05 / R-06：判据的唯一真源（原先三端各复制一份，见 @utils 内注释）
    resolveNodeTls,
    normalizeTransportPath,
    earlyDataHeaderName,
    resolveChainEarlyData,
    getChainExplicitEarlyData,
    type CleanProxyEntry
} from '@utils';
import { NODE_DNS_TAG } from './dns';

import {
    BaseOutbound,
    HttpOutbound,
    SocksOutbound,
    ShadowsocksOutbound,
    VlessOutbound,
    TrojanOutbound,
    WireguardEndpoint,
    VmessOutbound,
    HttpTransport,
    WsTransport,
    GrpcTransport,
    TLS,
    Transport,
    HttpupgradeTransport,
    TransportType,
    Fingerprint,
    URLTest,
    ChainOutbound
} from '#types/sing-box';

function buildOutbound<T>(
    tag: string,
    type: string,
    server: string,
    server_port: number,
    tcp_fast_open: boolean,
    fields: Omit<T, keyof BaseOutbound>,
    tls?: TLS,
    transport?: Transport,
    isChain?: boolean
): T {
    return {
        tag,
        type,
        server,
        server_port,
        tcp_fast_open,
        ...fields,
        tls,
        transport,
        // B-06：链式出站的**服务器域名解析**必须走 dns-direct，不能走 dns-remote。
        // dns-remote 的 detour 就是链式分组「🔗 最佳延迟 🚀」（dns.ts:55），而该分组本身由这些
        // 链式出站组成 —— 「查域名要先建隧道、建隧道又要查域名」成环，链式节点会全部建不起来。
        // 与 Clash 的 `proxy-server-nameserver`（显式不带 detour）保持同一口径。
        domain_resolver: isDomain(server) ? (isChain ? "dns-direct" : (isNodeHost(server) ? NODE_DNS_TAG : "dns-direct")) : undefined
    } as T;
}

/**
 * H7：server 是否为节点自身域名（httpConfig.hostName）。
 * 该域名由 dns.ts 的 hosts 静态 IP 服务器（NODE_DNS_TAG）解析，不走明文 localDNS；
 * 其余域名不在该 hosts 表的 predefined 内，必须继续用 dns-direct。
 */
function isNodeHost(server: string): boolean {
    const hostName = globalThis.httpConfig?.hostName;
    return !!hostName && server.toLowerCase() === hostName.toLowerCase();
}


export function buildWebsocketOutbound(
    protocol: string,
    remark: string,
    address: string,
    port: number,
    path: string,
    isFragment: boolean,
    earlyData?: number
): VlessOutbound | TrojanOutbound {
    const {
        dict: { _VL_ },
        globalConfig: { userID, TrPass },
        settings: { enableTFO, fingerprint }
    } = globalThis;

    // 判据只求值一次：resolveNodeTls 内含两次随机抽取（hostSniList 与 echServerName），
    // 求值两次会得到两套互不配对的 SNI / ECH 名，必须复用同一个对象。
    const criterion = resolveNodeTls(address, port, isFragment);
    // early-data 由调用点用 pickEarlyData(usedEds) 无放回抽取（2048..2560，513 个取值），构造器只负责装配：
    // 与 generateWsPath(usedPaths) 同一套路，保证同一份订阅内任意两个节点的 ed 两两不同，消除固定长度这一常量特征。
    // 下限不再取更低：ed 是「首包长度阈值」，首包超过它会直接不启用 Early Data（丢 0-RTT）。
    const transport = buildTransport("ws", "none", path, criterion.host, undefined, earlyData);
    // R-04 的 sing-box 侧渲染：判据 → tls 块。record_fragment 只在 TLS 节点上才写（非 TLS 节点无 tls 块）。
    const tls = criterion.isTLS
        ? buildTLS(
            "tls",
            isFragment,
            criterion.allowInsecure,
            criterion.sni,
            // G13-C7/C10：是否启用 ECH 一律以「该节点抽到的 ECH 名称」为准（分片节点不启用；
            // 名单为空时已回退到 host，仍算启用，见上方 B-43），
            // 与判据里抑制 alpn 用同一个字段，避免 ECH 参数与 alpn 参数各按一套条件判断而互相矛盾。
            !!criterion.echName,
            criterion.echName,
            criterion.alpn,
            fingerprint
        ) : undefined;

    if (protocol === _VL_) return buildOutbound<VlessOutbound>(remark, protocol, address, port, enableTFO, {
        uuid: userID,
        packet_encoding: "",
        network: "tcp"
    }, tls, transport);

    return buildOutbound<TrojanOutbound>(remark, protocol, address, port, enableTFO, {
        password: TrPass,
        network: "tcp"
    }, tls, transport);
}

export function buildWarpOutbound(
    warpAccount: WarpAccount,
    remark: string,
    endpoint: string,
    chain?: string
): WireguardEndpoint {
    const { host, port } = parseHostPort(endpoint, false);
    const {
        warpIPv6,
        reserved,
        publicKey,
        privateKey
    } = warpAccount;

    const address = chain ? "162.159.192.1" : host;
    return {
        tag: remark,
        detour: chain || undefined,
        type: "wireguard",
        address: [
            "172.16.0.2/32",
            warpIPv6
        ],
        mtu: 1280,
        peers: [
            {
                address,
                port: chain ? 2408 : port,
                public_key: publicKey,
                // G13-C17：sing-box / Xray 的 wireguard peer 都要求 reserved 为十进制字节数组
                // （#types/sing-box.d.ts:262 `reserved: number[]`；#types/xray.d.ts:332 同），
                // 而 WarpAccount.reserved（global.d.ts:60）与 Clash 的 reserved（clash.d.ts:181）
                // 都是 base64 串。故本端 base64ToDecimal 转换是正确表示，与 Xray 一致；Clash 侧差异由 Clash owner 处理。
                reserved: base64ToDecimal(reserved),
                allowed_ips: [
                    "0.0.0.0/0",
                    "::/0"
                ],
                persistent_keepalive_interval: 5
            }
        ],
        private_key: privateKey,
        domain_resolver: isDomain(address) ? "dns-direct" : undefined
    } satisfies WireguardEndpoint;
}


/** Clean IPs / Domains 里的 socks / socks5 / http(s) 代理条目 → 独立可选节点出站 */
export function buildCleanProxyOutbound(proxy: CleanProxyEntry, tag: string): HttpOutbound | SocksOutbound {
    const isHttpsProxy = proxy.protocol === 'https';
    // IP 主机的 https 代理：证书校验必然失败、SNI 不允许是 IP → 不校验、不下发 server_name；
    // 域名主机保持严格校验 + SNI = 主机名
    const isIPHost = isBareIPv4(proxy.server) || isBareIPv6(proxy.server);
    const tls = isHttpsProxy
        ? buildTLS('tls', false, isIPHost, isIPHost ? '' : proxy.server, false)
        : undefined;

    if (proxy.protocol === 'http' || isHttpsProxy) {
        return buildOutbound<HttpOutbound>(tag, 'http', proxy.server, proxy.port, false, {
            username: proxy.username,
            password: proxy.password
        }, tls, undefined, true);
    }

    return buildOutbound<SocksOutbound>(tag, 'socks', proxy.server, proxy.port, false, {
        username: proxy.username,
        password: proxy.password,
        version: '5',
        network: 'tcp'
    }, undefined, undefined, true);
}

export function buildChainOutbound(usedEds?: Set<number>): ChainOutbound | undefined {
    const {
        dict: { _VL_, _TR_, _SS_, _VM_ },
        settings: {
            outProxyParams: {
                protocol, server, port, user,
                pass, password, method, uuid,
                flow, security, type, sni, fp,
                host, path, alpn, pbk, sid,
                headerType, serviceName, aid
            }
        }
    } = globalThis;

    // R-06：取值判据在 @utils（显式 `ed` 优先、只消费一次、结果登记进 usedEds），
    // 与主出站共用同一个 usedEds 池，避免其它节点抽到同一阈值。
    const earlyData = resolveChainEarlyData(usedEds, getChainExplicitEarlyData());

    const tls = buildTLS(security, false, false, sni || server, false, undefined, alpn, fp, pbk, sid);
    const transport = buildTransport(type, headerType, path, host, serviceName, earlyData);

    switch (protocol) {
        case "http":
            return buildOutbound<HttpOutbound>("", protocol, server, port, false, {
                username: user,
                password: pass
            }, undefined, undefined, true);

        case "socks":
            return buildOutbound<SocksOutbound>("", protocol, server, port, false, {
                username: user,
                password: pass,
                version: "5",
                network: "tcp"
            }, undefined, undefined, true);

        case _SS_:
            return buildOutbound<ShadowsocksOutbound>("", protocol, server, port, false, {
                method,
                password,
                network: "tcp"
            }, undefined, undefined, true);

        case _VL_:
            return buildOutbound<VlessOutbound>("", protocol, server, port, false, {
                uuid,
                flow,
                network: "tcp"
            }, tls, transport, true);

        case _VM_:
            return buildOutbound<VmessOutbound>("", protocol, server, port, false, {
                uuid: uuid,
                security: "auto",
                alter_id: aid,
                network: "tcp"
            }, tls, transport, true);

        case _TR_:
            return buildOutbound<TrojanOutbound>("", protocol, server, port, false, {
                password: password,
                network: "tcp"
            }, tls, transport, true);

        default:
            return undefined;
    };
}

/** 仅 vless/vmess/trojan 出站带 transport 字段，其余（http/socks/ss）没有，用类型谓词取出 */
function hasTransport(outbound: ChainOutbound): outbound is VlessOutbound | VmessOutbound | TrojanOutbound {
    return "transport" in outbound;
}

/**
 * 克隆出的链式出站重新无放回抽取 early-data：structuredClone 会把 transport 一起复制，
 * 不重抽则同一份订阅内所有链式节点会共用源节点那一个阈值（反而形成固定指纹）。
 * 只有 ws 传输带 early-data，其余传输（http/grpc/httpupgrade/undefined）原样不动。
 * explicitEd：用户在 outProxy URI 里显式写的 ed，只由调用点在第一个克隆体上传入一次
 * （原型本身不出现在输出中，若不显式传下来用户的配置就会被静默丢弃）。
 */
export function redrawChainEarlyData(chain: ChainOutbound, usedEds: Set<number>, explicitEd?: number): void {
    const transport = hasTransport(chain) ? chain.transport : undefined;
    if (!transport || transport.type !== "ws") return;

    // R-06：取值判据在 @utils（显式值优先 + 只消费一次 + 无放回注册）
    const earlyData = resolveChainEarlyData(usedEds, explicitEd);
    transport.max_early_data = earlyData;
    transport.early_data_header_name = earlyDataHeaderName(earlyData);
}

export function buildUrlTest(
    tag: string,
    outboundTags: string[],
    isWarp: boolean
): URLTest {
    const { bestWarpInterval, bestVLTRInterval } = globalThis.settings;
    return {
        type: "urltest",
        tag,
        outbounds: outboundTags,
        url: "https://www.gstatic.com/generate_204",
        interrupt_exist_connections: false,
        interval: isWarp ? `${bestWarpInterval}s` : `${bestVLTRInterval}s`
    };
}

function buildTLS(
    security: "tls" | "reality" | "none",
    isFragment: boolean,
    allowInsecure: boolean,
    sni: string,
    enableECH: boolean,
    echServerName?: string,
    alpn?: string,
    fingerprint?: Fingerprint,
    publicKey?: string,
    shortID?: string
): TLS | undefined {
    if (!["tls", "reality"].includes(security)) return undefined;
    // B-42：删除本端独有的 `h2` 过滤（原 G13-C8：`alpn.split(',').filter(v => v !== 'h2')`）。
    // 三端统一**原样下发**用户 alpn —— 这是有意对齐，不是遗漏：旧过滤只存在于 sing-box，
    // 用户勾选含 h2 的档位（面板提供 h3,h2 / h2,http/1.1）时三端协商出的 ALPN 集合不同，
    // 按某端调好的结论在另一端不成立；仓库内没有任何依据说明 h2 必须剥离。
    const tlsAlpns = alpn?.split(',');

    const tls: TLS = {
        enabled: true,
        server_name: sni,
        record_fragment: isFragment,
        insecure: allowInsecure,
        alpn: tlsAlpns,
        utls: {
            enabled: !!fingerprint,
            fingerprint: fingerprint
        },
        ech: enableECH ? {
            enabled: true,
            query_server_name: echServerName
        } : undefined
    };

    if (security === "tls") return tls;
    if (security === 'reality' && publicKey && shortID) return {
        ...tls,
        reality: {
            enabled: true,
            public_key: publicKey,
            short_id: shortID
        }
    };
}



function buildTransport(
    type: TransportType,
    headerType?: "http" | "none",
    path: string = "/",
    host?: string,
    serviceName?: string,
    earlyData?: number
): Transport | undefined {
    path = normalizeTransportPath(path);

    switch (type) {
        case 'tcp':
            if (headerType === 'http') return {
                type: "http",
                host: host?.split(','),
                path: path,
                method: "GET",
                headers: {
                    "Connection": ["keep-alive"],
                    "Content-Type": ["application/octet-stream"]
                },
            } satisfies HttpTransport;

            return undefined;

        case 'ws':
            return {
                type: "ws",
                path: path,
                max_early_data: earlyData,
                early_data_header_name: earlyDataHeaderName(earlyData),
                headers: {
                    Host: host
                }
            } satisfies WsTransport;

        case 'httpupgrade':
            return {
                type: "httpupgrade",
                host: host,
                path: path
            } satisfies HttpupgradeTransport;

        case 'grpc':
            return {
                type: "grpc",
                service_name: serviceName
            } satisfies GrpcTransport;

        default:
            return undefined;
    }
}