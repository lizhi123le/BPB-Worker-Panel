/**
 * 出厂默认设置的**唯一来源**：冷启动（@init）、「重置设置」（@handlers）与
 * PUT body 类型校验基准（@kv）共用同一份常量，避免三处默认值漂移。
 *
 * 本模块必须保持**零运行时依赖**（无 import）：否则 `@init`（依赖 `@kv`）
 * 与 `@kv`（反向需要本模块作校验基准）之间会形成循环依赖。
 * `Settings` / `__VERSION__` 都是全局环境声明，无需 import。
 */

/**
 * 内置远程分组模板地址：「Enable Group Template」启用但 Template URL 未填（空串/纯空白/缺失）时的兜底目标。
 * 消费点在 clash / sing-box 的 configs.ts（两端同一口径）；面板 index.html 的占位符同值。
 */
export const DEFAULT_ACL_TEMPLATE_URL = 'https://raw.githubusercontent.com/lizhi123le/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_MultiMode.ini';

/** 面板出厂默认设置。 */
export const DEFAULT_SETTINGS: Settings = {
    localDNS: "8.8.8.8",
    antiSanctionDNS: "178.22.122.100",
    fakeDNS: false,
    enableIPv6: true,
    allowLANConnection: false,
    logLevel: "warning",
    remoteDNS: "https://8.8.8.8/dns-query",
    remoteDnsHost: {
        host: "8.8.8.8",
        isDomain: false,
        ipv4: [],
        ipv6: []
    },
    proxyIPMode: "proxyip",
    regionMatch: true,
    wkRegion: '',
    proxyOnly: false,
    proxyDegrade: false,
    proxyIPs: [],
    officialIPs: [],
    prefixes: [],
    upstreamProxy: "",
    upstreamParams: {
        upstreamServer: undefined,
        upstreamPort: undefined
    },
    outProxy: "",
    outProxyParams: {},
    cleanIPs: [],
    customCdnAddrs: [],
    bestVLTRInterval: 30,
    VLConfigs: true,
    TRConfigs: true,
    ports: [443],
    fingerprint: "chrome",
    alpn: "",
    randomPath: true,
    enableTFO: false,
    fragmentMode: "custom",
    fragmentLengthMin: 100,
    fragmentLengthMax: 200,
    fragmentIntervalMin: 1,
    fragmentIntervalMax: 1,
    fragmentMaxSplitMin: undefined,
    fragmentMaxSplitMax: undefined,
    fragmentPackets: "tlshello",
    enableECH: false,
    echServerName: [],
    hostSniList: [],
    bypassIran: false,
    bypassChina: false,
    bypassRussia: false,
    bypassOpenAi: false,
    bypassGoogleAi: false,
    bypassMicrosoft: false,
    bypassOracle: false,
    bypassDocker: false,
    bypassAdobe: false,
    bypassEpicGames: false,
    bypassIntel: false,
    bypassAmd: false,
    bypassNvidia: false,
    bypassAsus: false,
    bypassHp: false,
    bypassLenovo: false,
    blockAds: false,
    blockPorn: false,
    blockUDP443: false,
    blockMalware: false,
    blockPhishing: false,
    blockCryptominers: false,
    customBypassRules: [],
    customBlockRules: [],
    customBypassSanctionRules: [],
    warpRemoteDNS: "1.1.1.1",
    warpEndpoints: ["engage.cloudflareclient.com:2408"],
    bestWarpInterval: 30,
    xrayUdpNoises: [
        {
            type: "rand",
            packet: "50-100",
            delay: "1-1",
            count: 5
        }
    ],
    knockerNoiseMode: "quic",
    noiseCountMin: 10,
    noiseCountMax: 15,
    noiseSizeMin: 5,
    noiseSizeMax: 10,
    noiseDelayMin: 1,
    noiseDelayMax: 1,
    amneziaNoiseCount: 5,
    amneziaNoiseSizeMin: 50,
    amneziaNoiseSizeMax: 100,
    customSubs: [],
    customConfigs: [],
    aclEnabled: true,
    aclTemplate: DEFAULT_ACL_TEMPLATE_URL,
    panelVersion: __VERSION__
};
