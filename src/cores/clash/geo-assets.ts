/**
 * C13 核验结论（勿改成 behavior:'classical'）：`Chocolate4U/Iran-clash-rules/release/*.txt` 已实测为
 * **纯 payload 列表**，不是 ACL4SSR 的 classical 行式（无 `DOMAIN-SUFFIX,` 前缀）：
 *   - geosite 类（ir/malware/phishing/cryptominers/category-ads-all/nsfw）：逐行 `+.example.com`
 *   - geoip 类（ircidr/malware-ip/phishing-ip）：逐行裸 CIDR（IPv4 与 IPv6 混排）
 * 故 routing.ts#addRuleProvider 固定标 `behavior:'domain'`（geosite）/`'ipcidr'`（geoip）是**正确**的：
 * mihomo 对 domain 规则集按域名模式解析、对 ipcidr 规则集按 CIDR 解析，两者都吃 `+.` 前缀与注释行。
 * 若改成 'classical'，反而会把这些裸行当成含逗号的规则行而全部失效。
 * 这些文件的 `# clash rules in text format` 头注释只是格式说明，不构成 behavior 依据。
 * 本轮离线复核（更可验证的证据）：上游仓库 README 自身的 rule-providers 示例即 `format: text` +
 * `behavior: domain`（ir/ads/malware 等 .txt），与本文件固定标注同源；geoip 类（*cidr.txt / *-ip.txt）
 * 为裸 CIDR，对应 'ipcidr'。故 C13 判为「标注与文件格式一致，无需改动」。
 */
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
        {
            rule: blockMalware,
            type: 'block',
            format: "text",
            geosite: "malware",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.txt",
            geoip: "malware-cidr",
            geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware-ip.txt",
        },
        {
            rule: blockPhishing,
            type: 'block',
            format: "text",
            geosite: "phishing",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.txt",
            geoip: "phishing-cidr",
            geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing-ip.txt",
        },
        {
            rule: blockCryptominers,
            type: 'block',
            format: "text",
            geosite: "cryptominers",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/cryptominers.txt"
        },
        {
            rule: blockAds,
            type: 'block',
            format: "text",
            geosite: "category-ads-all",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.txt"
        },
        {
            rule: blockPorn,
            type: 'block',
            format: "text",
            geosite: "nsfw",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/nsfw.txt",
        },
        {
            rule: bypassIran,
            type: 'direct',
            dns: localDNS,
            format: "text",
            geosite: "ir",
            geoip: "ir-cidr",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt",
            geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt"
        },
        {
            rule: bypassChina,
            type: 'direct',
            dns: localDNS,
            format: "yaml",
            geosite: "cn",
            geoip: "cn-cidr",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.yaml",
            geoipURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.yaml"
        },
        {
            rule: bypassRussia,
            type: 'direct',
            dns: localDNS,
            format: "yaml",
            geosite: "ru",
            geoip: "ru-cidr",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ru.yaml",
            geoipURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/ru.yaml"
        },
        {
            rule: bypassOpenAi,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "openai",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.yaml"
        },
        {
            rule: bypassGoogleAi,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "googleai",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google-deepmind.yaml"
        },
        {
            rule: bypassMicrosoft,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "microsoft",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.yaml"
        },
        {
            rule: bypassOracle,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "oracle",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/oracle.yaml"
        },
        {
            rule: bypassDocker,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "docker",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/docker.yaml"
        },
        {
            rule: bypassAdobe,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "adobe",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/adobe.yaml"
        },
        {
            rule: bypassEpicGames,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "epicgames",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/epicgames.yaml"
        },
        {
            rule: bypassIntel,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "intel",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/intel.yaml"
        },
        {
            rule: bypassAmd,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "amd",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/amd.yaml"
        },
        {
            rule: bypassNvidia,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "nvidia",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/nvidia.yaml"
        },
        {
            rule: bypassAsus,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "asus",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/asus.yaml"
        },
        {
            rule: bypassHp,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "hp",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/hp.yaml"
        },
        {
            rule: bypassLenovo,
            type: 'direct',
            dns: antiSanctionDNS,
            format: "yaml",
            geosite: "lenovo",
            geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/lenovo.yaml"
        }
    ].filter(({ rule }) => rule);
}