import { parseHostPort, isBareIPv4, isBareIPv6, getXPaddingIdentifier, resolveNodeTls, normalizeTransportPath, getChainExplicitEarlyData, earlyDataHeaderName, resolveChainEarlyData, type CleanProxyEntry, type NodeTlsCriterion } from '@utils';

// XHTTP 的路径 / 填充约定与 raw URI、Xray JSON 共用同一份实现（单一来源，避免三端漂移）
import { XP_MODE } from '@cores/xp';

import {
    BaseOutbound,
    HttpOutbound,
    SocksOutbound,
    ShadowsocksOutbound,
    VlessOutbound,
    TrojanOutbound,
    WireguardOutbound,
    WsOpts,
    GrpcOpts,
    HttpOpts,
    XpOpts,
    VmessOutbound,
    TLS,
    Transport,
    AmneziaOpts,
    Network,
    Fingerprint,
    URLTest,
    ChainOutbound
} from '#types/clash';

function buildOutbound<T>(
    name: string,
    type: string,
    server: string,
    port: number,
    isIPv6: boolean,
    tfo: boolean,
    tls: Partial<TLS>,
    transport: Partial<Transport>,
    fields: Omit<T, keyof BaseOutbound | keyof TLS | keyof Transport>,
): T {
    return {
        "name": name,
        "type": type,
        "server": server.replace(/\[|\]/g, ''),
        "port": port,
        "ip-version": isIPv6 ? "ipv4-prefer" : "ipv4",
        "tfo": tfo,
        // C18：ws 出站显式声明 `udp: false`，是**有意取舍**而非遗漏——mihomo 对出站 UDP 能力要求
        // 显式声明（Xray/sing-box 不声明即默认允许，故三端在「UDP 是否经代理」上并不等价）。
        // 保留原因：本项目 Clash 侧的 UDP 策略靠 rules 承担（未接管时 `NETWORK,udp,REJECT`；
        // ACL 接管时该基础行也已保留，见 configs.ts#getClNormalConfig 的 buildBaseRoutingRules 前置），
        // 若此处放开 UDP，反而会让 QUIC/DNS-over-UDP 落到默认组之外、行为不可预期。
        // 若要改为跟随设置放开 UDP，必须同步复核上面两条 UDP 规则行的语义，不要只改这一处。
        "udp": false,
        ...fields,
        ...tls,
        ...transport
    } as T;
}

/**
 * R-04 的 Clash 侧渲染：判据对象 → tls 字段（Partial<TLS>，非 TLS 节点返回空对象）。
 * `protocol` 只影响 servername / sni 的键名选择（Trojan 用 sni），属本端 schema 差异。
 */
function buildNodeTls(protocol: string, criterion: NodeTlsCriterion): Partial<TLS> {
    if (!criterion.isTLS) return {};
    return buildTLS(
        protocol,
        "tls",
        criterion.allowInsecure,
        criterion.sni,
        !!criterion.echName,
        criterion.echName,
        criterion.alpn,
        globalThis.settings.fingerprint
    );
}

export function buildWebsocketOutbound(
    protocol: string,
    remark: string,
    address: string,
    port: number,
    path: string,
    earlyData?: number,
): VlessOutbound | TrojanOutbound {
    const {
        dict: { _VL_ },
        globalConfig: { userID, TrPass },
        settings: { enableTFO, enableIPv6 }
    } = globalThis;

    // 与 handlers.ts 的 URI 侧判定对齐：任一地址的显式端口表里出现过该端口也视为 TLS，
    // 否则同一节点会出现 URI 写 security=tls、JSON 无 tls 字段的自相矛盾组合。
    // 判据（含 entryPortMap 的按调用求值）统一由 @utils 的 isTlsPort 维护。
    // B-45：非 TLS 端口的 Trojan **不再静默丢弃**。原实现 `if (protocol === _TR_ && !isTLS) return null`
    // 让同一份订阅在 Clash 少节点（Xray/sing-box 照常下发明文节点，raw URI 侧也只是在备注上标
    // `⚠️明文(无TLS)`）。取舍（风险更小的一侧）：保留 —— 丢节点会让「服务端本来就是明文」的用户
    // 彻底失去该节点，保留最坏只是一个连不上的节点。Clash 的 trojan 出站无法表达「不带 TLS」，
    // 缺省按 TLS 处理（sni 取 server），这一点无法在本端对齐；备注告警同样只能在 raw URI 侧表达
    // （在本端给节点名加后缀会改变节点名，进而影响分组正则与既有节点匹配）。
    // 判据只求值一次：resolveNodeTls 内含两次随机抽取（hostSniList 与 echServerName），
    // 求值两次会得到两套互不配对的 SNI / ECH 名，必须复用同一个对象。
    // isFragment 恒 false：Clash 无分片订阅（/sub/fragment 对 clash 走 fallback）。
    const criterion = resolveNodeTls(address, port, false);

    // early-data 阈值由调用点从无放回池中抽取（见 pickEarlyData）：2048..2560（513 个取值），
    // 同一份订阅内任意两个节点的 ed 两两不同，消除「固定长度」这一常量特征（不做模块级缓存）。
    // 下限不再取更低：ed 是「首包长度阈值」，首包超过它会直接不启用 Early Data（丢 0-RTT）。
    const transport = buildTransport("ws", undefined, path, criterion.host, undefined, earlyData);
    const tls = buildNodeTls(protocol, criterion);

    if (protocol === _VL_) return buildOutbound<VlessOutbound>(remark, protocol, address, port, enableIPv6, enableTFO, tls, transport, {
        "uuid": userID,
        "packet-encoding": ""
    });

    return buildOutbound<TrojanOutbound>(remark, protocol, address, port, enableIPv6, enableTFO, tls, transport, {
        "password": TrPass
    });
}

/**
 * XHTTP（HTTP POST / stream-one）出站，仅供 VLESS。
 *
 * 与 buildWebsocketOutbound 的差异：
 * - 没有 early-data：`ed` 是 WebSocket 协议头的语义，XHTTP 下无意义，故不抽 usedEds；
 * - transport 用 `network: xhttp` + `xhttp-opts`（mihomo 自 v1.19.22 起支持）：
 *   更老版本的 mihomo 不认识该 network，会整份配置解析失败 —— 面板无法探测内核版本，
 *   因此本节点只在用户显式打开 `xpConfigs` 时才会出现；
 * - 填充参数与 raw URI / Xray JSON 同源（@utils#getXPaddingIdentifier + @cores/xp），
 *   三端填出的头名与键名逐字一致。
 */
export function buildXpOutbound(
    remark: string,
    address: string,
    port: number,
    path: string
): VlessOutbound {
    const {
        dict: { _VL_ },
        globalConfig: { userID },
        settings: { enableTFO, enableIPv6 }
    } = globalThis;

    // isFragment 恒 false：Clash 无分片订阅；与同地址的 WS 节点共用同一套 R-04 判据
    const criterion = resolveNodeTls(address, port, false);
    const { header, key } = getXPaddingIdentifier(userID);

    return buildOutbound<VlessOutbound>(remark, _VL_, address, port, enableIPv6, enableTFO, buildNodeTls(_VL_, criterion), {
        "network": "xhttp",
        "xhttp-opts": {
            "path": path,
            "host": criterion.host,
            "mode": XP_MODE,
            "x-padding-obfs-mode": true,
            "x-padding-method": "tokenish",
            "x-padding-placement": "queryInHeader",
            "x-padding-header": header,
            "x-padding-key": key
        } satisfies XpOpts
    }, {
        "uuid": userID,
        "packet-encoding": ""
    });
}

export function buildWarpOutbound(
    warpAccount: WarpAccount,
    remark: string,
    endpoint: string,
    chain: string,
    isPro: boolean
): WireguardOutbound {
    const {
        amneziaNoiseCount,
        amneziaNoiseSizeMin,
        amneziaNoiseSizeMax,
        enableIPv6
    } = globalThis.settings;

    const { host, port } = parseHostPort(endpoint, false);
    const ipVersion = enableIPv6 ? "ipv4-prefer" : "ipv4";

    const {
        warpIPv6,
        reserved,
        publicKey,
        privateKey
    } = warpAccount;

    return {
        "name": remark,
        "type": "wireguard",
        "ip": "172.16.0.2/32",
        "ipv6": warpIPv6,
        "ip-version": ipVersion,
        "private-key": privateKey,
        "server": chain ? "162.159.192.1" : host,
        "port": chain ? 2408 : port,
        "public-key": publicKey,
        "allowed-ips": ["0.0.0.0/0", "::/0"],
        // G13-C17：WG 出站 `reserved` 的表示三端不一致——Xray/sing-box 用 base64ToDecimal 转十进制数组
        // （xray.d.ts:332 `reserved: number[]`、sing-box.d.ts:262 `reserved: number[]`），
        // Clash 直接下发 base64 串（本仓库 clash.d.ts:181 明确声明 `"reserved": string`，
        // 上游来源是 protocols/warp.ts:36 的 `config.client_id`，即实例级配置里就是 base64 串）。
        // 结论：本例**据类型声明保持现状，不改**。理由：类型证据只能证明「本项目 Clash 面期望字符串」，
        // 无法证明目标 mihomo 内核同时接受 base64 串与十进制数组；两说均有合理依据（三字节 UDP 载荷
        // 既可用 [u8;3] 表示也可用 base64 表示），在无目标内核规范可比对时盲目转换一旦猜错会让
        // 全部 Warp 节点失效。故保留现状并在此留痕：若实测某 mihomo 版本要求十进制数组，
        // 应改为 `base64ToDecimal(reserved)`（utils.ts:588 已有该工具）并同步更新 clash.d.ts 的类型。
        "reserved": reserved,
        "udp": true,
        "mtu": 1280,
        "dialer-proxy": chain || undefined,
        "amnezia-wg-option": isPro ? {
            "jc": amneziaNoiseCount,
            "jmin": amneziaNoiseSizeMin,
            "jmax": amneziaNoiseSizeMax
        } satisfies AmneziaOpts : undefined
    };
}



/** Clean IPs / Domains 里的 socks / socks5 / http(s) 代理条目 → 独立可选节点 */
export function buildCleanProxyOutbound(proxy: CleanProxyEntry, name: string): HttpOutbound | SocksOutbound {
    const isHttpsProxy = proxy.protocol === 'https';
    // IP 主机的 https 代理证书校验必然失败 → skip-cert-verify；域名主机保持严格校验
    const isIPHost = isBareIPv4(proxy.server) || isBareIPv6(proxy.server);

    if (proxy.protocol === 'http' || isHttpsProxy) {
        // HTTPS 代理在 clash 里是 type: http + tls: true
        const tlsOpts: Partial<TLS> = isHttpsProxy
            ? (isIPHost ? { tls: true, 'skip-cert-verify': true } : { tls: true })
            : {};
        return buildOutbound<HttpOutbound>(name, 'http', proxy.server, proxy.port, false, false, tlsOpts, {}, {
            username: proxy.username,
            password: proxy.password
        });
    }

    return buildOutbound<SocksOutbound>(name, 'socks5', proxy.server, proxy.port, false, false, {}, {}, {
        username: proxy.username,
        password: proxy.password
    });
}

export function buildChainOutbound(usedEds?: Set<number>): ChainOutbound | undefined {
    const {
        dict: { _SS_, _VL_, _TR_, _VM_ },
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

    // 链式出站同样启用 early-data：用户显式给出的 ed 优先，未给出时无放回抽取（不再是 undefined）
    // R-06：与 sing-box 同一写法（判据在 @utils）。
    const earlyData = resolveChainEarlyData(usedEds, getChainExplicitEarlyData());

    const tls = buildTLS(protocol, security, false, sni || server, false, undefined, alpn, fp, pbk, sid);
    const transport = buildTransport(type, headerType, path, host, serviceName, earlyData);

    switch (protocol) {
        case "http":
            return buildOutbound<HttpOutbound>("", "http", server, port, false, false, {}, {}, {
                "username": user,
                "password": pass
            });

        case "socks":
            return buildOutbound<SocksOutbound>("", "socks5", server, port, false, false, {}, {}, {
                "username": user,
                "password": pass
            });

        case _SS_:
            return buildOutbound<ShadowsocksOutbound>("", "ss", server, port, false, false, {}, {}, {
                "cipher": method,
                "password": password
            });

        case _VL_:
            return buildOutbound<VlessOutbound>("", _VL_, server, port, false, false, tls, transport, {
                "uuid": uuid,
                "flow": flow
            });

        case _VM_:
            return buildOutbound<VmessOutbound>("", _VM_, server, port, false, false, tls, transport, {
                "uuid": uuid,
                "cipher": "auto",
                "alterId": aid
            });

        case _TR_:
            if (security === "none") return undefined;
            return buildOutbound<TrojanOutbound>("", _TR_, server, port, false, false, tls, transport, {
                "password": password
            });

        default:
            return undefined;
    };
}

/**
 * 链式克隆体重置 early-data：structuredClone 会连 max-early-data 一起继承源节点，
 * 必须重抽，保证克隆节点不与源节点/其它节点同值。
 * explicitEd：用户的显式 `ed`，由调用点只传给第一个链式克隆体（恰好一个产出节点使用），
 * 其余克隆体不传，从池中无放回抽取；这里不再读 outProxy，避免每个克隆体都继承同一显式值。
 */
export function redrawChainEarlyData(
    outbound: { "name": string; "ws-opts"?: WsOpts },
    usedEds?: Set<number>,
    explicitEd?: number
): void {
    const wsOpts = outbound["ws-opts"];
    // 仅纯 ws 传输需要：http-upgrade 走 fast-open，本身不带 early-data 语义
    if (!wsOpts || wsOpts["v2ray-http-upgrade"]) return;

    // R-06：取值判据在 @utils（显式值优先 + 只消费一次 + 无放回注册）
    const earlyData = resolveChainEarlyData(usedEds, explicitEd);
    wsOpts["max-early-data"] = earlyData;
    wsOpts["early-data-header-name"] = earlyDataHeaderName(earlyData);
}

export function buildUrlTest(
    name: string,
    proxies: string[],
    isWarp: boolean
): URLTest {
    const { bestWarpInterval, bestVLTRInterval } = globalThis.settings;
    return {
        "name": name,
        "type": "url-test",
        "proxies": proxies,
        "url": "https://www.gstatic.com/generate_204",
        "interval": isWarp ? bestWarpInterval : bestVLTRInterval,
        "tolerance": 50
    };
}

function buildTLS(
    protocol: string,
    security: "tls" | "reality" | "none",
    allowInsecure: boolean,
    sni: string,
    enableECH: boolean,
    echServerName?: string,
    alpn?: string,
    fingerprint?: Fingerprint,
    publicKey?: string,
    shortID?: string
): Partial<TLS> {
    if (!["tls", "reality"].includes(security)) return {};
    const { _TR_ } = globalThis.dict;

    const common: TLS = {
        "tls": true,
        [protocol === _TR_ ? "sni" : "servername"]: sni,
        // G13-C9：`randomized → random` 的归一化只保留在 Clash 端，依据是 mihomo 的类型面与实际取值：
        // mihomo 的 client-fingerprint 取 `random`（每次握手随机），而 `randomized` 是 Xray 侧 uTLS
        // 的名称。本仓库三端类型声明都并列声明了二者（clash.d.ts:13-23 / xray.d.ts:16-26 /
        // sing-box.d.ts:15-25 的 Fingerprint 联合类型均含 "random" 与 "randomized"），
        // 即「类型层允许原样下发」并不构成 Clash 不该归一化的证据——类型只能排除编译期错误，
        // 不能证明目标内核接受该字面量。故这里保持既有映射不变（Clash 输出字面量不变），
        // 三端取值差异按「各端内核命名不同」处理；若后续实测某端内核同时接受两者，
        // 再统一为同一字面量，不要在此单方面改动。
        "client-fingerprint": fingerprint === "randomized" ? "random" : fingerprint,
        "skip-cert-verify": allowInsecure
    };

    if (security === "tls") {
        return {
            ...common,
            "alpn": alpn?.split(','),
            "ech-opts": enableECH ? {
                "enable": true,
                "query-server-name": echServerName
            } : undefined
        };
    } else if (security === "reality" && publicKey && shortID) {
        return {
            ...common,
            "reality-opts": {
                "public-key": publicKey,
                "short-id": shortID
            }
        };
    } else return {};
}

function buildTransport(
    type: Network,
    headerType?: "http" | "none",
    path: string = "/",
    host?: string,
    serviceName?: string,
    earlyData?: number
): Partial<Transport> {
    path = normalizeTransportPath(path);

    switch (type) {
        case 'tcp':
            return headerType === 'http' ? {
                "network": "http",
                "http-opts": {
                    "method": "GET",
                    "path": path.split(','),
                    "headers": {
                        "Host": host?.split(","),
                        "Connection": ["keep-alive"],
                        "Content-Type": ["application/octet-stream"]
                    }
                } satisfies HttpOpts
            } : {
                "network": "tcp"
            } satisfies Transport;

        case 'ws':
            return {
                "network": "ws",
                "ws-opts": {
                    "path": path,
                    "max-early-data": earlyData,
                    "early-data-header-name": earlyDataHeaderName(earlyData),
                    "headers": {
                        "Host": host
                    }
                } satisfies WsOpts
            };

        case 'httpupgrade':
            const { _V2_ } = globalThis.dict;
            return {
                "network": "ws",
                "ws-opts": {
                    [`${_V2_}-http-upgrade`]: true,
                    [`${_V2_}-http-upgrade-fast-open`]: true,
                    "path": path,
                    "headers": {
                        "Host": host
                    }
                } satisfies WsOpts
            };

        case 'grpc':
            return {
                "network": "grpc",
                "grpc-opts": {
                    "grpc-service-name": serviceName
                } satisfies GrpcOpts
            };

        default:
            return {};
    }
}