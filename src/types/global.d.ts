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
        // 用户是否显式配置了自定义反代池（settings.proxyIPs 或 env PROXY_IP），区别于
        // DEFAULT_PROXY_IPS 公共备用中继；仅用于构造 customProxyPool（CF 模式下「仅走代理」拨它），
        // 不再作为「有没有反代池可走」的拨号判据——内置池经 panelIPs 兜底同样参与拨号。
        hasCustomProxyIPs?: boolean;
        // 出站模式首跳决策（面板 Outbound Mode / URL query qj）
        // 反代池与官方直连池只承载 Cloudflare CDN 目标，故仅在「目标命中 Cloudflare 网段」时才做首跳。
        // proxyOnly=true    → 有代理（上游代理或反代池）则代理首跳，失败不回退、直接断；
        //                     一个代理都没配则退化为直连目标首跳
        // proxyDegrade=true（面板显示名 Direct Target / 直连目标）→ 恒直连目标首跳
        // 两者皆 false（默认）→ 配了上游代理则上游代理首跳；否则解析目标：
        //                     命中 CF 网段 → 池首跳（反代池 → 官方池），非 CF → 直连目标首跳
        // 首跳失败后统一按 上游代理 → 反代池 → CF 内置 IP 池 → 直连 回退
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
        // ── 运行时可选的调参键（全部 ??? 语义：未设置即为默认行为，代码里一律按 `?.` 读）──
        // H-10：这些键原先只能靠 `(globalThis as any).env` 绕过类型，现补声明以便逐处去掉 as any。
        /** 伪装/兜底域（伪装页与兜底反代的目标域） */
        readonly PUBLIC_PROXY_IP?: string;
        /** 伪装反代缓存的时间戳归一总开关（'0' = 关闭，默认开启） */
        readonly MASK_CACHE_TS_NORM?: string;
        /** 运维追加的噪声 query 参数（逗号分隔），按名字从缓存键剔除 */
        readonly MASK_CACHE_NOISE_EXTRA?: string;
        /** 伪装图片形态（'data' = 回滚到 base64 内联） */
        readonly MASK_IMG_MODE?: string;
        /** 单响应文本改写上限（字节，默认 1048576；低于 65536 回退默认） */
        readonly MASK_TEXT_REWRITE_MAX?: string;
        /** 伪装图片缓存张数上限（默认 12；小于 1 或非法回退默认） */
        readonly MASK_IMG_CACHE_MAX?: string;
        /** 伪装图片缓存总字节预算（默认 8388608；低于 65536 回退默认） */
        readonly MASK_IMG_CACHE_BYTES?: string;
        /** HSTS 开关（默认开启；显式 '0' / 'false' 关闭） */
        readonly HSTS_ENABLE?: string;
        /** 反代池缓存的调试日志开关 */
        readonly DEBUG?: string;
        /** 任意其它自定义键（反代池 / 前缀覆盖等），保持宽松以兼容既有部署 */
        readonly [key: string]: unknown;
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
        // XHTTP 传输（HTTP POST / stream-one）：开启后订阅额外生成 VLESS-XHTTP 节点，
        // Worker 侧同时接受 XHTTP 入站（POST + 路径白名单）。默认关闭 —— 客户端需支持 type=xhttp。
        xpConfigs: boolean;
        ports: number[];
        fingerprint: Fingerprint;
        alpn: string;
        // 节点随机路径（面板 Random Path）：true = 每个节点随机抽 1-3 段伪装路径；
        // false = 所有节点共用固定根路径 `/`（旧订阅的 `/?ed=…` 形态）
        randomPath: boolean;
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
    // H-10：请求级运行时全局。worker.ts 在每个请求入口把 env / ctx 挂到 globalThis。
    // 这两个声明让 `globalThis.env` / `globalThis.ctx` 可直读 —— 但**现存调用点仍写
    // `(globalThis as any).env`**（camouflage / common / handlers / utils 共 15 处），
    // 因为 Env 里原先缺一批「运行时可选的调参键」（见下面 Env 的 HSTS_ENABLE 等）。
    // 那些键现已补进 Env：后续可逐处去掉 `as any`，本文件不再有「声明了却没人用」的死面。
    // 注意：模块被非请求路径加载时 env 实际可能缺失，按可选语义使用的调用点仍须自行判空。
    var env: Env;
    var ctx: ExecutionContext;
    var __kvCache: {
        settings: Settings | null;
        timestamp: number;
        version: string;
    } | undefined;
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

    // R-13：原 Array.prototype.concatIf / Object.prototype.omitEmpty 的声明已删除 ——
    // 两个补丁改成 @utils 里的普通函数（concatIf / omitEmpty），不再污染内置原型。
}

export { };
