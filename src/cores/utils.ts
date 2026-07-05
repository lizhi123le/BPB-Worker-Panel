import { safeErrorMessage } from "@common";

export function isDomain(address: string): boolean {
    if (!address) return false;
    const domainRegex = /^(?!-)(?:[A-Za-z0-9-]{1,63}.)+[A-Za-z]{2,}$/;
    return domainRegex.test(address);
}

/** Extract address part (host only, no port) from "address#name" entry */
export function entryAddress(entry: string): string {
    const addr = entry.split('#')[0].trim();
    return parseHostPort(addr, true).host;
}

/** Extract port from "address:port#name" entry, or 0 if none */
export function entryPort(entry: string): number {
    const addr = entry.split('#')[0].trim();
    return parseHostPort(addr).port;
}

/** Extract name part from "address#name" entry, or undefined */
export function entryName(entry: string): string | undefined {
    const idx = entry.indexOf('#');
    if (idx === -1) return undefined;
    return entry.slice(idx + 1).trim() || undefined;
}

/** Map entries to clean address array */
export function entryAddresses(entries: string[]): string[] {
    return entries.map(entryAddress).filter(Boolean);
}

/** Build port map from entry lists — maps bare address → explicit port */
export function buildEntryPortMap(): Record<string, number> {
    const { settings: { cleanIPs, customCdnAddrs } } = globalThis;
    const map: Record<string, number> = {};
    for (const e of [...cleanIPs, ...customCdnAddrs]) {
        const port = entryPort(e);
        if (port) {
            map[entryAddress(e)] = port;
        }
    }
    return map;
}

/** Find custom name for an address across multiple entry lists */
export function findNameForAddress(entries: string[], address: string): string | undefined {
    for (const e of entries) {
        if (entryAddress(e) === address) {
            const name = entryName(e);
            if (name) return name;
        }
    }
    return undefined;
}

/** Resolve URL entries in an array — fetches http/https URLs and replaces them with their content lines */
export async function resolveUrlEntries(entries: string[]): Promise<string[]> {
    const resolved: string[] = [];
    for (const entry of entries) {
        if (entry.startsWith('http://') || entry.startsWith('https://')) {
            try {
                const res = await fetch(entry);
                if (!res.ok) continue;
                const text = await res.text();
                const lines = text.split('\n')
                    .map(l => l.trim())
                    .filter(l => l && !l.startsWith('#') && !l.startsWith('//'))
                    .map(l => {
                        const hashIdx = l.indexOf('#');
                        const addrPart = (hashIdx >= 0 ? l.slice(0, hashIdx) : l).trim();
                        const namePart = hashIdx >= 0 ? l.slice(hashIdx) : '';
                        if ((addrPart.match(/:/g) || []).length >= 2 && !addrPart.startsWith('[')) {
                            return `[${addrPart}]${namePart}`;
                        }
                        return l;
                    });
                resolved.push(...lines);
            } catch {
                continue;
            }
        } else {
            resolved.push(entry);
        }
    }
    return resolved;
}

export async function resolveDNS(domain: string, onlyIPv4 = false): Promise<DnsResult> {
    const dohBaseURL = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}`;
    const dohURLs = {
        ipv4: `${dohBaseURL}&type=A`,
        ipv6: `${dohBaseURL}&type=AAAA`,
    };

    try {
        const ipv4 = await fetchDNSRecords(dohURLs.ipv4, 1);
        const ipv6 = onlyIPv4 ? [] : await fetchDNSRecords(dohURLs.ipv6, 28);
        return { ipv4, ipv6 };
    } catch (error) {
        throw new Error(`Error resolving DNS for ${domain}: ${safeErrorMessage(error)}`);
    }
}

export async function fetchDNSRecords(url: string, recordType: number): Promise<string[]> {
    try {
        const response = await fetch(url, { headers: { accept: 'application/dns-json' } });
        const data: any = await response.json();

        if (!data.Answer) return [];

        return data.Answer
            .filter((record: any) => record.type === recordType)
            .map((record: any) => record.data);

    } catch (error) {
        throw new Error(`Failed to fetch DNS records from ${url}: ${safeErrorMessage(error)}`);
    }
}

export function getProtocols() {
    const {
        settings: { VLConfigs, TRConfigs },
        dict: { _VL_, _TR_ }
    } = globalThis;

    return [].concatIf(VLConfigs, _VL_).concatIf(TRConfigs, _TR_);
}

export async function getConfigAddresses(isFragment: boolean): Promise<string[]> {
    const {
        httpConfig: { hostName },
        settings: { enableIPv6, customCdnAddrs, cleanIPs }
    } = globalThis;

    const { ipv4, ipv6 } = await resolveDNS(hostName, !enableIPv6);
    const addrs = [
        hostName,
        'www.speedtest.net',
        ...ipv4,
        ...ipv6.map((ip: string) => `[${ip}]`),
        ...entryAddresses(cleanIPs)
    ];

    return addrs.concatIf(!isFragment, entryAddresses(customCdnAddrs));
}

const remarkCounter: Record<string, number> = {};

export function resetRemarkCounter() {
    for (const key of Object.keys(remarkCounter)) {
        delete remarkCounter[key];
    }
}

export function generateRemark(
    port: number,
    address: string,
    _protocol: string,
    _isFragment: boolean,
    isChain: boolean
): string {
    const {
        settings: { cleanIPs, customCdnAddrs, upstreamParams: { upstreamServer } }
    } = globalThis;

    const customName = findNameForAddress([...cleanIPs, ...customCdnAddrs], address);

    let baseName: string;

    if (customName) {
        baseName = customName;
    } else if (address === upstreamServer) {
        baseName = '上游代理';
    } else if (isDomain(address)) {
        baseName = address;
    } else if (isIPv4(address)) {
        baseName = 'IPv4优选';
    } else if (isIPv6(address)) {
        baseName = 'IPv6优选';
    } else {
        baseName = '节点';
    }

    const chainPrefix = isChain ? '🔗 ' : '';

    if (isChain) {
        const currentCount = remarkCounter[baseName] || 0;
        if (currentCount === 0) return `${chainPrefix}${baseName}`;
        return `${chainPrefix}${baseName}-${String(currentCount).padStart(2, '0')}`;
    }

    remarkCounter[baseName] = (remarkCounter[baseName] || 0) + 1;
    const suffix = String(remarkCounter[baseName]).padStart(2, '0');
    return `${chainPrefix}${baseName}-${suffix}`;
}

export function randomUpperCase(str: string): string {
    let result = '';

    for (let i = 0; i < str.length; i++) {
        result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i];
    }

    return result;
}

export function getRandomString(lengthMin: number, lengthMax: number): string {
    let result = '';
    const charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (lengthMax - lengthMin + 1)) + lengthMin;

    for (let i = 0; i < length; i++) {
        result += charSet.charAt(Math.floor(Math.random() * charSet.length));
    }

    return result;
}

export function generateWsPath(protocol: string): string {
    const {
        settings: { proxyIPMode, proxyIPs, prefixes },
        dict: { _VL_ }
    } = globalThis;

    const config = {
        junk: getRandomString(8, 16),
        protocol: protocol === _VL_ ? "vl" : "tr",
        mode: proxyIPMode,
        panelIPs: proxyIPMode === 'proxyip' ? proxyIPs : prefixes
    };

    return `/${btoa(JSON.stringify(config))}`;
}

export function pickRandomEch(echServerNames: string[]): string | undefined {
    if (!echServerNames || echServerNames.length === 0) return undefined;
    return echServerNames[Math.floor(Math.random() * echServerNames.length)];
}

export function base64ToDecimal(base64: string): number[] {
    const binaryString = atob(base64);
    const hexString = Array
        .from(binaryString)
        .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('');

    const decimalArray = hexString
        .match(/.{2}/g)!
        .map(hex => parseInt(hex, 16));

    return decimalArray;
}

export function isIPv4(address: string): boolean {
    const ipv4Pattern = /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/([0-9]|[1-2][0-9]|3[0-2]))?$/;
    return ipv4Pattern.test(address);
}

export function isIPv6(address: string): boolean {
    const ipv6Pattern = /^\[(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|::(?:[a-fA-F0-9]{1,4}:){0,7}|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6})\](?:\/(1[0-1][0-9]|12[0-8]|[0-9]?[0-9]))?$/;
    if (ipv6Pattern.test(address)) return true;
    return (address.match(/:/g) || []).length >= 2;
}

export function getDomain(url: string) {
    try {
        const newUrl = new URL(url);
        const host = newUrl.hostname;
        const isHostDomain = isDomain(host);

        return {
            host,
            isHostDomain
        };
    } catch {
        return {
            host: '',
            isHostDomain: false
        };
    }
}

export function selectSniHost(address: string, sniHostOverride?: string) {
    const {
        httpConfig: { hostName },
        settings: { customCdnAddrs, customCdnHost, customCdnSni }
    } = globalThis;

    if (sniHostOverride) {
        return { host: sniHostOverride, sni: sniHostOverride, allowInsecure: false };
    }

    const isCustomAddr = entryAddresses(customCdnAddrs).includes(address);
    const sni = isCustomAddr ? customCdnSni : randomUpperCase(hostName);
    const host = isCustomAddr ? customCdnHost : hostName;

    return { host, sni, allowInsecure: isCustomAddr };
}

export function parseHostPort(input: string, brackets?: boolean): { host: string, port: number } {
    const bm = input.match(/^\[(?<ipv6>.+?)\](?::(?<port>\d+))?$/);
    if (bm?.groups) {
        const host = brackets ? `[${bm.groups.ipv6}]` : bm.groups.ipv6;
        return { host, port: bm.groups.port ? Number(bm.groups.port) : 0 };
    }

    if (input.includes('::')) {
        const lastColon = input.lastIndexOf(':');
        const afterLastColon = input.slice(lastColon + 1);
        if (/^\d+$/.test(afterLastColon)) {
            const hostPart = input.slice(0, lastColon);
            if (hostPart.includes(':') && !hostPart.endsWith(':')) {
                return { host: brackets ? `[${hostPart}]` : hostPart, port: Number(afterLastColon) };
            }
        }
        return { host: brackets ? `[${input}]` : input, port: 0 };
    }

    const hm = input.match(/^(?<host>[^:]+)(?::(?<port>\d+))?$/);
    if (hm?.groups) {
        return { host: hm.groups.host, port: hm.groups.port ? Number(hm.groups.port) : 0 };
    }

    return { host: "", port: 0 };
}

export function isHttps(port: number): boolean {
    const { defaultHttpsPorts } = globalThis.httpConfig;
    return defaultHttpsPorts.includes(port);
}

const isBypass = (type: string) => type === "direct";
const isBlock = (type: string) => type === "block";

export function accRoutingRules(geoAssets: GeoAsset[]) {
    const {
        customBypassRules,
        customBypassSanctionRules,
        customBlockRules
    } = globalThis.settings;

    return {
        bypass: {
            geosites: geoAssets
                .filter(rule => isBypass(rule.type))
                .map(rule => rule.geosite),
            geoips: geoAssets
                .filter(rule => isBypass(rule.type) && rule.geoip)
                .map(rule => rule.geoip!),
            domains: [
                ...customBypassRules.filter(isDomain),
                ...customBypassSanctionRules.filter(isDomain)
            ],
            ips: customBypassRules.filter(rule => !isDomain(rule))
        },
        block: {
            geosites: geoAssets
                .filter(rule => isBlock(rule.type))
                .map(rule => rule.geosite),
            geoips: geoAssets
                .filter(rule => isBlock(rule.type) && rule.geoip)
                .map(rule => rule.geoip!),
            domains: customBlockRules.filter(isDomain),
            ips: customBlockRules.filter(rule => !isDomain(rule))
        }
    };
}

export function accDnsRules(geoAssets: GeoAsset[]) {
    const {
        localDNS,
        antiSanctionDNS,
        customBypassRules,
        customBypassSanctionRules,
        customBlockRules
    } = globalThis.settings;

    return {
        bypass: {
            localDNS: {
                geositeGeoips: geoAssets
                    .filter(({ type, geoip, dns }) => isBypass(type) && geoip && dns === localDNS)
                    .map(({ geosite, geoip }) => ({ geosite, geoip })),
                geosites: geoAssets
                    .filter(({ type, geoip, dns }) => isBypass(type) && !geoip && dns === localDNS)
                    .map(rule => rule.geosite),
                domains: customBypassRules.filter(isDomain)
            },
            antiSanctionDNS: {
                geosites: geoAssets
                    .filter(rule => isBypass(rule.type) && rule.dns === antiSanctionDNS)
                    .map(rule => rule.geosite),
                domains: customBypassSanctionRules.filter(isDomain)
            }
        },
        block: {
            geosites: geoAssets
                .filter(rule => isBlock(rule.type))
                .map(rule => rule.geosite),
            domains: customBlockRules.filter(isDomain)
        }
    };
}

export function toRange(min?: number, max?: number) {
    if (!min || !max) return undefined;
    if (min === max) return String(min);
    return `${min}-${max}`;
}

Array.prototype.concatIf = function <T>(condition: boolean, concat: T | T[]): T[] {
    if (!condition) return this;
    if (Array.isArray(concat)) return [...this, ...concat];
    return [...this, concat]
}

Object.prototype.omitEmpty = function <T>(): T | undefined {
    if (Object.keys(this).length === 0) return undefined;
    return this as T;
}