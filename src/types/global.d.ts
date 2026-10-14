declare global {
    interface GlobalConfig {
        readonly userID: string;
        readonly TrPass: string;
        readonly pathName: string;
        readonly fallbackDomain: string;
        readonly dohURL: string;
    }

    interface HttpConfig {
        readonly panelVersion: string;
        readonly defaultHttpPorts: number[];
        readonly defaultHttpsPorts: number[];
        readonly hostName: string;
        readonly client: string;
        readonly urlOrigin: string;
        readonly subPath: string;
    }

    interface WsConfig {
        readonly defaultProxyIPs: string[];
        readonly defaultPrefixes: string[];
        readonly envProxyIPs: string;
        readonly envPrefixes: string;
        wsProtocol?: "vl" | "tr";
        proxyMode?: "proxyip" | "prefix";
        panelIPs?: string[];
        workerRegion?: string;
        regionMatch?: boolean;
        wkRegion?: string;
        // 官方直连 IP 池（面板 officialIPs，未配置则为内置 10 个），已在 handlers.ts 归一化。
        // 出站模式的「CF 内置 IP 池」兜底层凭它拨号；CF 模式下它同时也是 panelIPs。
        officialPool?: string[];
        // 用户显式配置的反代池实体（不含内置 DEFAULT_PROXY_IPS，也不含 CF 模式的官方直连池）。
        // CF 模式下 panelIPs 被官方池覆盖后，「仅走代理」靠它走到用户的反代池。
        customProxyPool?: string[];
        // 用户是否显式配置了自定义反代池（settings.proxyIPs 或 env PROXY_IP），
        // 区别于 DEFAULT_PROXY_IPS 公共备用中继。它是「有没有反代池可走」的判据之一
        // （另一个是 settings.upstreamProxy）。注意 workerRegion === 'CF'（wk 留空 = 官方直连）时
        // handlers 会把 panelIPs 换成官方直连 IP 池：默认 / 直连目标模式下反代池不参与，
        // 仅「仅走代理」保持与指定地区同一套逻辑（配了反代池就能用 customProxyPool 拨号）。
        hasCustomProxyIPs?: boolean;
        // 出站模式首跳决策（面板 Outbound Mode / URL query qj）
        // proxyOnly=true    → 有代理（上游代理或自定义反代池）则代理首跳，失败不回退、直接断；
        //                     与地区设置无关（官方直连下同样可用自定义反代池）；
        //                     一个代理都没配则立即断连，禁止直连出网（防 IP 泄漏）
        // proxyDegrade=true（面板显示名 Direct Target / 直连目标）→ 指定地区下恒直连首跳；
        //                     WK = 官方直连（CF）下首跳改用 CF 内置 IP 池竞速。
        //                     两者失败后按 上游代理 → 反代池 → CF 内置 IP 池 → 直连 回退
        // 两者皆 false（默认）→ 有代理则代理首跳（上游优先 → 反代池），否则首跳先打 CF 内置 IP 池；
        //                     失败一律走回退阶梯（跳过已试级别）→ CF 内置 IP 池 → 直连兜底
        proxyOnly?: boolean;
        proxyDegrade?: boolean;
    }

    interface Env {
        readonly UUID: string;
        readonly TR_PASS: string;
        readonly PROXY_IP: string;
        readonly PREFIX: string;
        readonly FALLBACK: string;
        // 伪装页环境变量别名（对齐 cfnew：homepage / HOMEPAGE / URL 优先，FALLBACK 兼容）
        readonly homepage?: string;
        readonly HOMEPAGE?: string;
        readonly URL?: string;
        readonly DOH_URL: string;
        readonly kv: KVNamespace;
    }

    interface WarpAccount {
        privateKey: string;
        publicKey: string;
        warpIPv6: string;
        reserved: string;
    }

    interface DnsHost {
        host: string;
        isDomain: boolean;
        ipv4: string[];
        ipv6: string[];
    }

    interface UpstreamProxy {
        upstreamServer?: string;
        upstreamPort?: number;
    }

    interface DnsResult {
        ipv4: string[];
        ipv6: string[];
    }

    interface XrUdpNoise {
        type: "rand" | "str" | "base64" | "hex" | "array";
        packet: string;
        delay: string;
        count: number;
    }

    interface Settings {
        localDNS: string;
        antiSanctionDNS: string;
        fakeDNS: boolean;
        enableIPv6: boolean;
        allowLANConnection: boolean;
        logLevel: "none" | "warning" | "error" | "info" | "debug";
        remoteDNS: string;
        remoteDnsHost: DnsHost;
        proxyIPMode: "proxyip" | "prefix";
        regionMatch: boolean;
        wkRegion?: string;
        proxyIPs: string[];
        officialIPs?: string[];
        prefixes: string[];
        upstreamProxy: string;
        upstreamParams: UpstreamProxy;
        outProxy: string;
        outProxyParams: any;
        cleanIPs: string[];
        customCdnAddrs: string[];
        bestVLTRInterval: number;
        VLConfigs: boolean;
        TRConfigs: boolean;
        ports: number[];
        fingerprint: Fingerprint;
        alpn: string;
        enableTFO: boolean;
        fragmentMode: "custom" | "low" | "medium" | "high";
        fragmentLengthMin: number;
        fragmentLengthMax: number;
        fragmentIntervalMin: number;
        fragmentIntervalMax: number;
        fragmentPackets: "tlshello" | "1-1" | "1-2" | "1-3" | "1-5";
        fragmentMaxSplitMin?: number;
        fragmentMaxSplitMax?: number;
        enableECH: boolean;
        echServerName: string[];
        hostSniList: string[];
        bypassIran: boolean;
        bypassChina: boolean;
        bypassRussia: boolean;
        bypassOpenAi: boolean;
        bypassGoogleAi: boolean;
        bypassMicrosoft: boolean;
        bypassOracle: boolean;
        bypassDocker: boolean;
        bypassAdobe: boolean;
        bypassEpicGames: boolean;
        bypassIntel: boolean;
        bypassAmd: boolean;
        bypassNvidia: boolean;
        bypassAsus: boolean;
        bypassHp: boolean;
        bypassLenovo: boolean;
        blockAds: boolean;
        blockPorn: boolean;
        blockUDP443: boolean;
        blockMalware: boolean;
        blockPhishing: boolean;
        blockCryptominers: boolean;
        proxyOnly: boolean;
        proxyDegrade: boolean;
        customBypassRules: string[];
        customBlockRules: string[];
        customBypassSanctionRules: string[];
        warpRemoteDNS: string;
        warpEndpoints: string[];
        bestWarpInterval: number;
        xrayUdpNoises: XrUdpNoise[];
        knockerNoiseMode: string;
        noiseCountMin: number;
        noiseCountMax: number;
        noiseSizeMin: number;
        noiseSizeMax: number;
        noiseDelayMin: number;
        noiseDelayMax: number;
        amneziaNoiseCount: number;
        amneziaNoiseSizeMin: number;
        amneziaNoiseSizeMax: number;
        customSubs: string[];
        customConfigs: string[];
        panelVersion: string;
        // 分组配置模板（ACL4SSR）：默认开启，URL 可面板配置
        aclEnabled: boolean;
        aclTemplate: string;
    }

    var settings: Settings;
    var globalConfig: GlobalConfig;
    var httpConfig: HttpConfig;
    var wsConfig: WsConfig;
    var __kvCache: {
        settings: Settings | null;
        timestamp: number;
        version: string;
    } | undefined;
    var workerRegion: string;
    var dict: {
        readonly _VL_: string;
        readonly _VL_CAP_: string;
        readonly _VM_: string;
        readonly _TR_: string;
        readonly _TR_CAP_: string;
        readonly _SS_: string;
        readonly _V2_: string;
        readonly _project_: string;
        readonly _website_: string;
        readonly _public_proxy_ip_: string;
    };

    interface GeoAsset {
        rule: boolean;
        type: string;
        geosite: string;
        geoip?: string;
        geositeURL?: string;
        geoipURL?: string;
        dns?: string;
        format?: string;
    }

    const __VERSION__: string;
    const __ERROR_HTML_CONTENT__: string;
    const __ICON__: string;
    const __PANEL_HTML_CONTENT__: string;
    const __LOGIN_HTML_CONTENT__: string;
    const __SECRETS_HTML_CONTENT__: string;
    const __PROXY_IP_HTML_CONTENT__: string;

    interface Array<T> {
        concatIf<T>(condition: boolean, concat: T | T[]): T[];
    }

    interface Object {
        omitEmpty<T>(): T | undefined;
    }
}

export { };
