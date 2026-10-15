import {
    isHttps,
    buildEntryPortMap,
    base64ToDecimal,
    parseHostPort,
    selectSniHost,
    isDomain,
    pickRandomEch,
    pickEarlyData,
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
        domain_resolver: isDomain(server) ? (isChain ? "dns-remote" : (isNodeHost(server) ? NODE_DNS_TAG : "dns-direct")) : undefined
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
        settings: { 
            fingerprint, 
            alpn, 
            enableTFO, 
            enableECH, 
            echServerName, 
            hostSniList, 
            upstreamParams: { upstreamServer } 
        }
    } = globalThis;

    const pickedEch = enableECH && !isFragment ? pickRandomEch(echServerName) : undefined;
    const { host, sni, allowInsecure } = selectSniHost(address, pickRandomEch(hostSniList));
    // early-data 由调用点用 pickEarlyData(usedEds) 无放回抽取（2048..2560，513 个取值），构造器只负责装配：
    // 与 generateWsPath(usedPaths) 同一套路，保证同一份订阅内任意两个节点的 ed 两两不同，消除固定长度这一常量特征。
    // 下限不再取更低：ed 是「首包长度阈值」，首包超过它会直接不启用 Early Data（丢 0-RTT）。
    const transport = buildTransport("ws", "none", path, host, undefined, earlyData);
    // 与 handlers.ts 的 URI 侧判定对齐：任一地址的显式端口表里出现过该端口也视为 TLS，
    // 否则同一节点会出现 URI 写 security=tls、JSON 写 none 的自相矛盾组合。
    // entryPortMap 只依赖 globalThis.settings，按调用求值为请求内局部量（无模块级可变状态）。
    const tls = isHttps(port) || address === upstreamServer || Object.values(buildEntryPortMap()).some(ports => ports.includes(port))
        ? buildTLS(
            "tls",
            isFragment,
            allowInsecure,
            sni,
            // G13-C7/C10：是否启用 ECH 一律以「该节点抽到的 ECH 名称」为准（分片节点与空名单都不启用），
            // 与下方抑制 alpn 用同一个判据，避免 ECH 参数与 alpn 参数各按一套条件判断而互相矛盾。
            !!pickedEch,
            pickedEch,
            // G13-C7：抑制 alpn 的条件必须是「该节点确实启用了 ECH」（pickedEch 非空），
            // 而不是只看全局 enableECH。分片节点恒 `enableECH && !isFragment` = 未启用 ECH，
            // 旧写法会连 alpn 一起抹掉，得到「既无 ECH 也无 alpn」的节点。
            pickedEch ? undefined : (alpn || undefined),
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

/**
 * 读取 outProxy URI 中显式给出的 ed（early-data 阈值）。
 * 未给出、非数值、outProxy 缺失或 URI 非法时返回 undefined；绝不抛错。
 * 显式值是用户自己的配置，故不做区间钳制（可能超出 2048..2560，保持既有「原样沿用」行为）。
 */
export function getChainExplicitEarlyData(): number | undefined {
    const outProxy = globalThis.settings?.outProxy;
    if (!outProxy) return undefined;

    try {
        const ed = new URL(outProxy).searchParams.get("ed");
        if (ed === null || !Number.isFinite(+ed)) return undefined;
        return +ed;
    } catch {
        return undefined;
    }
}

/** Clean IPs / Domains 里的 socks / socks5 / http(s) 代理条目 → 独立可选节点出站 */
export function buildCleanProxyOutbound(proxy: CleanProxyEntry, tag: string): HttpOutbound | SocksOutbound {
    const isHttpsProxy = proxy.protocol === 'https';
    // HTTPS 代理：对代理本身做 TLS，SNI 取代理主机名
    const tls = isHttpsProxy ? buildTLS('tls', false, false, proxy.server, false) : undefined;

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
            outProxy,
            outProxyParams: {
                protocol, server, port, user,
                pass, password, method, uuid,
                flow, security, type, sni, fp,
                host, path, alpn, pbk, sid,
                headerType, serviceName, aid
            }
        }
    } = globalThis;

    const { searchParams } = new URL(outProxy);
    const ed = searchParams.get("ed");
    // 链式出站同样要开 0-RTT：URI 显式带 ed 时优先沿用该值，并登记进 usedEds（避免与其它节点撞值）；
    // 未显式给出时按主出站同一套路无放回抽取（与主出站共用同一个 usedEds 池）
    const earlyData = ed ? +ed : pickEarlyData(usedEds);
    if (ed && usedEds && !usedEds.has(+ed)) usedEds.add(+ed);

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

    const earlyData = explicitEd ?? pickEarlyData(usedEds);
    if (usedEds && !usedEds.has(earlyData)) usedEds.add(earlyData);
    transport.max_early_data = earlyData;
    transport.early_data_header_name = earlyData ? "Sec-WebSocket-Protocol" : undefined;
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
    // G13-C8：此处对用户 alpn 列表做的 `h2` 过滤是本端独有（Xray/Clash 原样下发），
    // 三端 alpn 集合因此在用户勾选含 h2 的档位时不一致。仓库内未找到任何依据
    // （无注释、无类型约束、无测试）说明 h2 必须剥离，且面板提供 h3,h2 / h2,http/1.1 档位。
    // 依据「证据不足不得贸然放开」保留现状（放开可能让节点连不上），仅标注：未证实，暂不动。
    const tlsAlpns = alpn?.split(',').filter(value => value !== 'h2');

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
    path = path?.split("?")[0];

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
                path: path?.split('?ed=')[0],
                max_early_data: earlyData,
                early_data_header_name: earlyData ? "Sec-WebSocket-Protocol" : undefined,
                headers: {
                    Host: host
                }
            } satisfies WsTransport;

        case 'httpupgrade':
            return {
                type: "httpupgrade",
                host: host,
                path: path?.split('?ed=')[0]
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