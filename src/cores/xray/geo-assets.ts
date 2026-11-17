export function getGeoAssets(): GeoAsset[] {
    const {
        localDNS,
        antiSanctionDNS,
        blockMalware,
        blockPhishing,
        blockCryptominers,
        blockAds,
        blockPorn,
        bypassIran,
        bypassChina,
        bypassRussia,
        bypassOpenAi,
        bypassGoogleAi,
        bypassMicrosoft,
        bypassOracle,
        bypassDocker,
        bypassAdobe,
        bypassEpicGames,
        bypassIntel,
        bypassAmd,
        bypassNvidia,
        bypassAsus,
        bypassHp,
        bypassLenovo,
    } = globalThis.settings;

    return [
        // B-44：`geosite:category-ads-ir`（伊朗本地广告清单）原只在本端存在，sing-box / Clash 均无对应条目。
        // 取舍（风险更小的一侧）：**删掉本端这条**，三端统一为只拦 `category-ads-all`。
        // 理由：补齐另两端需要一个新的远程规则集 URL，而 sing-box 的远程 rule_set 取不到时是
        // **启动期 FATAL**（不是跳过该条规则），在未联网核实 Chocolate4U 仓库确实提供 ads-ir 文件前，
        // 下发猜测地址会让整个 sing-box 订阅不可用；删掉一条则最多少拦一类本地广告，且三端口径一致。
        { rule: blockAds, type: 'block', geosite: "geosite:category-ads-all" },
        { rule: blockPorn, type: 'block', geosite: "geosite:category-porn" },
        { rule: blockMalware, type: 'block', geosite: "geosite:malware", geoip: "geoip:malware" },
        { rule: blockPhishing, type: 'block', geosite: "geosite:phishing", geoip: "geoip:phishing" },
        { rule: blockCryptominers, type: 'block', geosite: "geosite:cryptominers" },
        { rule: bypassIran, type: 'direct', geosite: "geosite:category-ir", geoip: "geoip:ir", dns: localDNS },
        { rule: bypassChina, type: 'direct', geosite: "geosite:cn", geoip: "geoip:cn", dns: localDNS },
        { rule: bypassRussia, type: 'direct', geosite: "geosite:category-ru", geoip: "geoip:ru", dns: localDNS },
        { rule: bypassOpenAi, type: 'direct', geosite: "geosite:openai", dns: antiSanctionDNS },
        { rule: bypassGoogleAi, type: 'direct', geosite: "geosite:google-deepmind", dns: antiSanctionDNS },
        { rule: bypassMicrosoft, type: 'direct', geosite: "geosite:microsoft", dns: antiSanctionDNS },
        { rule: bypassOracle, type: 'direct', geosite: "geosite:oracle", dns: antiSanctionDNS },
        { rule: bypassDocker, type: 'direct', geosite: "geosite:docker", dns: antiSanctionDNS },
        { rule: bypassAdobe, type: 'direct', geosite: "geosite:adobe", dns: antiSanctionDNS },
        { rule: bypassEpicGames, type: 'direct', geosite: "geosite:epicgames", dns: antiSanctionDNS },
        { rule: bypassIntel, type: 'direct', geosite: "geosite:intel", dns: antiSanctionDNS },
        { rule: bypassAmd, type: 'direct', geosite: "geosite:amd", dns: antiSanctionDNS },
        { rule: bypassNvidia, type: 'direct', geosite: "geosite:nvidia", dns: antiSanctionDNS },
        { rule: bypassAsus, type: 'direct', geosite: "geosite:asus", dns: antiSanctionDNS },
        { rule: bypassHp, type: 'direct', geosite: "geosite:hp", dns: antiSanctionDNS },
        { rule: bypassLenovo, type: 'direct', geosite: "geosite:lenovo", dns: antiSanctionDNS },
    ].filter(({ rule }) => rule);
}