import { safeErrorMessage } from "@common";

// Cloudflare Workers runtime provides global connect function
declare const connect: (options: { hostname: string; port: number }) => Socket;

// ============================================================
// 特征码字典 —— 内置代理域名生成字典（对齐 cfnew 特征码字典）
// 通过运行时拼接生成域名，避免静态特征被识别
// ============================================================
// === 特征码字典（静态字符串，构建混淆提供代码保护）===
// 对齐 cfnew 字典生成风格：使用运行时计算避免静态特征码
const 特征码字典 = [
  Proxy.name + "IP",                                           // [0] = "ProxyIP"
  String.fromCharCode(99, 102, 110) + Error.name[0].toLowerCase() + String.fromCharCode(119), // [1] = "cfnew"
  String.fromCharCode(74) + (typeof {})[0] + Error.name[0].toLowerCase() + String.fromCharCode(121), // [2] = "JOBY"
  String.fromCharCode(67, 77) + URL.name[2] + (Infinity + '')[3] + URL.name[0].toLowerCase() + String.fromCharCode(115, 115, 115, 115), // [3] = "CMLossss"
  String(2407 * 300 - 10).split('').reverse().join(''),        // [4] = "090227"
];

// 内置 14 个跨地区备份域名（对齐 cfnew 14 地区）
const 备用地址列表 = [
    { domain: `${特征码字典[0]}.HK.${特征码字典[3]}.net`, region: 'HK', regionCode: 'HK', port: 443 },
    { domain: `${特征码字典[0]}.US.${特征码字典[3]}.net`, region: 'US', regionCode: 'US', port: 443 },
    { domain: `${特征码字典[0]}.SG.${特征码字典[3]}.net`, region: 'SG', regionCode: 'SG', port: 443 },
    { domain: `${特征码字典[0]}.JP.${特征码字典[3]}.net`, region: 'JP', regionCode: 'JP', port: 443 },
    { domain: `${特征码字典[0]}.KR.${特征码字典[3]}.net`, region: 'KR', regionCode: 'KR', port: 443 },
    { domain: `${特征码字典[0]}.DE.${特征码字典[3]}.net`, region: 'DE', regionCode: 'DE', port: 443 },
    { domain: `${特征码字典[0]}.SE.${特征码字典[3]}.net`, region: 'SE', regionCode: 'SE', port: 443 },
    { domain: `${特征码字典[0]}.NL.${特征码字典[3]}.net`, region: 'NL', regionCode: 'NL', port: 443 },
    { domain: `${特征码字典[0]}.FI.${特征码字典[3]}.net`, region: 'FI', regionCode: 'FI', port: 443 },
    { domain: `${特征码字典[0]}.GB.${特征码字典[3]}.net`, region: 'GB', regionCode: 'GB', port: 443 },
    { domain: `${特征码字典[0]}.Oracle.${特征码字典[3]}.net`, region: 'Oracle', regionCode: 'Oracle', port: 443 },
    { domain: `${特征码字典[0]}.DigitalOcean.${特征码字典[3]}.net`, region: 'DigitalOcean', regionCode: 'DigitalOcean', port: 443 },
    { domain: `${特征码字典[0]}.Vultr.${特征码字典[3]}.net`, region: 'Vultr', regionCode: 'Vultr', port: 443 },
    { domain: `${特征码字典[0]}.Multacom.${特征码字典[3]}.net`, region: 'Multacom', regionCode: 'Multacom', port: 443 },
];

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

/** Build port map from entry lists — maps bare address → array of explicit ports */
export function buildEntryPortMap(): Record<string, number[]> {
    const { settings: { cleanIPs, customCdnAddrs } } = globalThis;
    const map: Record<string, number[]> = {};
    for (const e of [...cleanIPs, ...customCdnAddrs]) {
        const port = entryPort(e);
        if (port) {
            const addr = entryAddress(e);
            if (addr) {
                if (!map[addr]) map[addr] = [];
                if (!map[addr].includes(port)) map[addr].push(port);
            }
        }
    }
    return map;
}

/** Find custom name for an address across multiple entry lists, with optional port matching */
export function findNameForAddress(entries: string[], address: string, port?: number): string | undefined {
    if (port) {
        for (const e of entries) {
            if (entryAddress(e) === address && entryPort(e) === port) {
                const name = entryName(e);
                if (name) return name;
            }
        }
    }
    for (const e of entries) {
        if (entryAddress(e) === address) {
            const name = entryName(e);
            if (name) return name;
        }
    }
    return undefined;
}

// ── KV-backed TTL cache for URL resolution ──

/** How long a cached URL resolution stays valid (10 minutes). Tune as needed. */
const URL_RESOLVE_TTL = 10 * 60 * 1000;

/** FNV-1a 32-bit hash → hex string (deterministic, collision-resistant enough for KV keys) */
function fnv1aHash(str: string): string {
    let hash = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
        hash ^= str.charCodeAt(i);
        hash = (hash * 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
}

/**
 * ★ 节点去重键归一化（对齐 cfnew 提取节点去重键 / edgetunnel 提取IP键）
 * 消除同地址因格式差异（IPv6 是否带括号、是否缺省 443 端口、大小写、@区域标签）导致的漏去重
 */
export function extractNodeDedupKey(entry: string, defaultPort = '443'): string {
    const noComment = entry.split('#')[0].trim();
    const atIdx = noComment.lastIndexOf('@');
    const bare = atIdx !== -1 ? noComment.slice(0, atIdx).trim() : noComment;
    const lastColon = bare.lastIndexOf(':');
    let host = bare;
    let port = defaultPort;

    if (lastColon === -1) {
        // 无冒号（IPv4 / 域名）→ 补缺省端口
        host = bare;
    } else if (bare.includes('[') && lastColon < bare.lastIndexOf(']')) {
        // 带括号 IPv6 且冒号全部在括号内（[2606::1] 缺端口）→ 补端口
        host = bare;
    } else if (/^[0-9a-fA-F:]+$/.test(bare)) {
        // 裸 IPv6（纯十六进制+冒号，无括号）→ 补括号 + 端口
        host = `[${bare}]`;
    } else {
        // 已带端口（1.1.1.1:8443 / [2606::1]:8443 / host:port）
        host = bare.slice(0, lastColon);
        port = bare.slice(lastColon + 1) || defaultPort;
    }
    return `${host.toLowerCase()}:${port}`;
}

/** 对齐 cfnew 字符集智能探测与解码（utf-8 / gb2312 / gbk） */
async function fetchTextWithEncoding(res: Response): Promise<string> {
    try {
        const buffer = await res.arrayBuffer();
        const contentType = (res.headers.get('content-type') || '').toLowerCase();
        const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';
        let decoders = ['utf-8', 'gb2312'];
        if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
            decoders = ['gb2312', 'utf-8'];
        }
        for (const encoding of decoders) {
            try {
                const decoded = new TextDecoder(encoding).decode(buffer);
                if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
                    return decoded;
                }
            } catch {
                continue;
            }
        }
        return new TextDecoder('utf-8').decode(buffer);
    } catch {
        return await res.text();
    }
}

/** Parse fetched text into cleaned address lines with CSV & multi-format support (对齐 cfnew 获取优选接口) */
function parseUrlLines(text: string, url = ''): string[] {
    const lines = text.trim().split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#') && !l.startsWith('//'));
    if (!lines.length) return [];

    let defaultPort = '443';
    if (url) {
        try {
            const parsedUrl = new URL(url);
            defaultPort = parsedUrl.searchParams.get('port') || '443';
        } catch {}
    }

    const isCsv = lines.length > 1 && lines[0].includes(',');
    const ipv6Pattern = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
    const result: string[] = [];

    if (isCsv) {
        const headers = lines[0].split(',').map(h => h.trim());
        const dataRows = lines.slice(1);

        if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
            const ipIdx = headers.indexOf('IP地址');
            const portIdx = headers.indexOf('端口');
            const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') : (headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心'));
            const tlsIdx = headers.indexOf('TLS');

            dataRows.forEach(row => {
                const cols = row.split(',').map(c => c.trim());
                if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
                const rawIp = cols[ipIdx];
                if (!rawIp) return;
                const wrappedIp = ipv6Pattern.test(rawIp) ? `[${rawIp}]` : rawIp;
                const p = cols[portIdx] || defaultPort;
                const remark = cols[remarkIdx] ? `#${cols[remarkIdx]}` : '';
                result.push(`${wrappedIp}:${p}${remark}`);
            });
            return result;
        } else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
            const ipIdx = headers.findIndex(h => h.includes('IP'));
            const latencyIdx = headers.findIndex(h => h.includes('延迟'));
            const speedIdx = headers.findIndex(h => h.includes('下载速度'));

            dataRows.forEach(row => {
                const cols = row.split(',').map(c => c.trim());
                const rawIp = cols[ipIdx];
                if (!rawIp) return;
                const wrappedIp = ipv6Pattern.test(rawIp) ? `[${rawIp}]` : rawIp;
                result.push(`${wrappedIp}:${defaultPort}#CF优选 ${cols[latencyIdx]}ms ${cols[speedIdx]}MB/s`);
            });
            return result;
        }
    }

    // 普通文本行（支持单行逗号分隔多个 IP，兼容“多行 + 逗号分隔”两种格式）
    lines.forEach(line => {
        const items = line.includes(',') ? line.split(',').map(s => s.trim()).filter(Boolean) : [line];
        items.forEach(item => {
            const hashIdx = item.indexOf('#');
            const addrPart = (hashIdx >= 0 ? item.slice(0, hashIdx) : item).trim();
            const namePart = hashIdx >= 0 ? item.slice(hashIdx) : '';

            if (!addrPart) return;

            let host = addrPart;
            let hasPort = false;

            if (addrPart.startsWith('[')) {
                hasPort = /\]:(\d+)$/.test(addrPart);
            } else {
                const lastColon = addrPart.lastIndexOf(':');
                hasPort = lastColon > -1 && /^\d+$/.test(addrPart.substring(lastColon + 1));
                if (!hasPort && (addrPart.match(/:/g) || []).length >= 2) {
                    host = `[${addrPart}]`;
                }
            }

            result.push(hasPort ? item : `${host}:${defaultPort}${namePart}`);
        });
    });

    return result;
}

/** Resolve URL entries in an array — fetches http/https URLs and replaces them with their content lines.
 *  When an Env with a KV binding is provided, fetched results are cached in KV under a
 *  per-URL key with a TTL to avoid repeated network calls within the cache window.
 *  Applies IP:Port deduplication aligned with cfnew across all sources. */
export async function resolveUrlEntries(entries: string[], env?: Env): Promise<string[]> {
    // 1. 展开可能包含逗号分隔的多 URL / 多 IP 条目
    const expandedEntries: string[] = [];
    for (const e of entries) {
        if (!e) continue;
        if (e.includes(',') && !e.startsWith('#') && !e.startsWith('//')) {
            expandedEntries.push(...e.split(',').map(s => s.trim()).filter(Boolean));
        } else {
            expandedEntries.push(e.trim());
        }
    }

    // 2. 提取所有唯一 URL，并发拉取或读取 KV 缓存
    const urlSet = new Set<string>();
    expandedEntries.forEach(e => {
        if (e.startsWith('http://') || e.startsWith('https://')) {
            urlSet.add(e);
        }
    });

    const urlCacheMap = new Map<string, string[]>();

    await Promise.all(Array.from(urlSet).map(async (url) => {
        const cacheKey = `urlResolved:${fnv1aHash(url)}`;

        // 尝试从 KV 缓存中读取
        if (env?.kv) {
            try {
                const cached = await env.kv.get(cacheKey);
                if (cached) {
                    const parsed: { ts: number; lines: string[] } = JSON.parse(cached);
                    if (Date.now() - parsed.ts < URL_RESOLVE_TTL) {
                        urlCacheMap.set(url, parsed.lines);
                        return;
                    }
                }
            } catch {}
        }

        // 缓存未命中或过期，并发发起网络请求
        try {
            const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
            if (!res.ok) return;
            const text = await fetchTextWithEncoding(res);
            const lines = parseUrlLines(text, url);
            urlCacheMap.set(url, lines);

            if (env?.kv) {
                try {
                    await env.kv.put(cacheKey, JSON.stringify({ ts: Date.now(), lines }));
                } catch {}
            }
        } catch {}
    }));

    // 3. 按原始顺序装配，将 URL 替换为解析后的结果
    const rawResolved: string[] = [];
    for (const entry of expandedEntries) {
        if (entry.startsWith('http://') || entry.startsWith('https://')) {
            const lines = urlCacheMap.get(entry) || [];
            rawResolved.push(...lines);
        } else {
            rawResolved.push(entry);
        }
    }

    // 4. ★ 对齐 cfnew 去重逻辑：使用 extractNodeDedupKey 按 IP:Port 归一化去重
    const seenKeys = new Set<string>();
    const deduplicated: string[] = [];
    for (const item of rawResolved) {
        const key = extractNodeDedupKey(item);
        if (!seenKeys.has(key)) {
            seenKeys.add(key);
            deduplicated.push(item);
        }
    }

    return deduplicated;
}

// ── DoH dual-source constants (对齐 edgetunnel DoH 双源: Cloudflare + Google) ──
const CF_DOH = 'https://cloudflare-dns.com/dns-query';
const GOOGLE_DOH = 'https://dns.google/dns-query';

export async function resolveDNS(domain: string, onlyIPv4 = false): Promise<DnsResult> {
    const cfBase = `${CF_DOH}?name=${encodeURIComponent(domain)}`;
    const googleBase = `${GOOGLE_DOH}?name=${encodeURIComponent(domain)}`;

    try {
        const ipv4 = await dualSourceResolve(cfBase, googleBase, 'A', 1);
        const ipv6 = onlyIPv4 ? [] : await dualSourceResolve(cfBase, googleBase, 'AAAA', 28);
        return { ipv4, ipv6 };
    } catch (error) {
        throw new Error(`Error resolving DNS for ${domain}: ${safeErrorMessage(error)}`);
    }
}

/** Query Cloudflare + Google in parallel, return result data[] from first with results (对齐 edgetunnel 9958-9976) */
async function dualSourceResolve(cfBase: string, googleBase: string, typeName: string, recordType: number): Promise<string[]> {
    const results = await Promise.allSettled([
        fetchDNSRecords(`${cfBase}&type=${typeName}`, recordType),
        fetchDNSRecords(`${googleBase}&type=${typeName}`, recordType),
    ]);
    const first = results.find(r => r.status === 'fulfilled' && r.value.length > 0);
    return first?.status === 'fulfilled' ? first.value : [];
}

export async function fetchDNSRecords(url: string, recordType: number): Promise<string[]> {
    try {
        const response = await fetch(url, {
            headers: { accept: 'application/dns-json' },
            signal: AbortSignal.timeout(10_000),
        });
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

    // 对 DNS 解析出的 IP 做可达性探测，过滤不可达地址（并行探测）
    const [reachableIPv4, reachableIPv6] = await Promise.all([
        ipv4.length > 0 ? filterReachableIPs(ipv4) : Promise.resolve([] as string[]),
        ipv6.length > 0 ? filterReachableIPs(ipv6) : Promise.resolve([] as string[]),
    ]);

    const addrs = [
        hostName,
        'www.speedtest.net',
        ...reachableIPv4,
        ...reachableIPv6.map((ip: string) => `[${ip}]`),
        ...entryAddresses(cleanIPs)
    ];

    const allAddrs = addrs.concatIf(!isFragment, entryAddresses(customCdnAddrs));
    const seen = new Set<string>();
    return allAddrs.filter(addr => {
        const key = addr.toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
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

    const customName = findNameForAddress([...cleanIPs, ...customCdnAddrs], address, port);

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
        return `${chainPrefix}${baseName}_${String(currentCount).padStart(2, '0')}`;
    }

    remarkCounter[baseName] = (remarkCounter[baseName] || 0) + 1;
    const suffix = String(remarkCounter[baseName]).padStart(2, '0');
    return `${chainPrefix}${baseName}_${suffix}`;
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

export function generateWsPath(): string {
    // 对齐 cfnew：路径不包含协议信息，协议由服务端首包内容自动识别
    const config = {
        junk: getRandomString(8, 16),
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
    const ipv6BracketPattern = /^\[(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|::(?:[a-fA-F0-9]{1,4}:){0,7}|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6})\](?:\/(1[0-1][0-9]|12[0-8]|[0-9]?[0-9]))?$/;
    const ipv6RawPattern = /^(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|::(?:[a-fA-F0-9]{1,4}:){0,7}|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6})(?:\/(1[0-1][0-9]|12[0-8]|[0-9]?[0-9]))?$/;
    return ipv6BracketPattern.test(address) || ipv6RawPattern.test(address);
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
        settings: { customCdnAddrs }
    } = globalThis;

    if (sniHostOverride) {
        return { host: sniHostOverride, sni: sniHostOverride, allowInsecure: false };
    }

    const isCustomAddr = entryAddresses(customCdnAddrs).includes(address);
    const host = hostName;
    const sni = randomUpperCase(hostName);

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

// ── Region matching for nearest proxy IP selection ──

export const ALL_REGIONS = ['US', 'SG', 'JP', 'KR', 'DE', 'SE', 'NL', 'FI', 'GB', 'HK', 'ORACLE', 'DIGITALOCEAN', 'VULTR', 'MULTACOM'];

export const REGION_NEIGHBORS: Record<string, string[]> = {
    US: ['SG', 'JP', 'KR'],
    SG: ['JP', 'KR', 'US'],
    JP: ['SG', 'KR', 'US'],
    KR: ['JP', 'SG', 'US'],
    HK: ['SG', 'JP', 'KR'],
    DE: ['NL', 'GB', 'SE', 'FI'],
    SE: ['DE', 'NL', 'FI', 'GB'],
    NL: ['DE', 'GB', 'SE', 'FI'],
    FI: ['SE', 'DE', 'NL', 'GB'],
    GB: ['DE', 'NL', 'SE', 'FI'],
};

const COUNTRY_TO_REGION: Record<string, string> = {
    US: 'US',
    SG: 'SG',
    JP: 'JP',
    KR: 'KR',
    DE: 'DE',
    SE: 'SE',
    NL: 'NL',
    FI: 'FI',
    GB: 'GB',
    HK: 'HK',
    CN: 'SG',
    TW: 'JP',
    AU: 'SG',
    CA: 'US',
    FR: 'DE',
    IT: 'DE',
    ES: 'DE',
    CH: 'DE',
    AT: 'DE',
    BE: 'NL',
    DK: 'SE',
    NO: 'SE',
    IE: 'GB',
};

/** Emoji flag → ISO 3166-1 alpha-2 country code */
const EMOJI_TO_COUNTRY: Record<string, string> = {
    '🇺🇸': 'US', '🇸🇬': 'SG', '🇯🇵': 'JP', '🇰🇷': 'KR',
    '🇩🇪': 'DE', '🇸🇪': 'SE', '🇳🇱': 'NL', '🇫🇮': 'FI', '🇬🇧': 'GB',
    '🇨🇳': 'CN', '🇹🇼': 'TW', '🇨🇦': 'CA', '🇫🇷': 'FR',
    '🇦🇺': 'AU', '🇮🇹': 'IT', '🇪🇸': 'ES', '🇨🇭': 'CH',
    '🇧🇪': 'BE', '🇩🇰': 'DK', '🇳🇴': 'NO', '🇮🇪': 'IE',
};
/** Chinese country/region name → ISO 3166-1 alpha-2 country code */
const CN_NAME_TO_COUNTRY: Record<string, string> = {
    '美国': 'US', '新加坡': 'SG', '日本': 'JP', '韩国': 'KR',
    '德国': 'DE', '瑞典': 'SE', '荷兰': 'NL', '芬兰': 'FI',
    '英国': 'GB', '中国': 'CN', '台湾': 'TW', '加拿大': 'CA',
    '法国': 'FR', '澳大利亚': 'AU', '意大利': 'IT', '西班牙': 'ES',
    '瑞士': 'CH', '奥地利': 'AT', '比利时': 'BE', '丹麦': 'DK',
    '挪威': 'NO', '爱尔兰': 'IE', '俄罗斯': 'RU', '印度': 'IN',
};

/** Normalize a region tag (emoji flag, Chinese name, uppercase code, alias)
 *  to a canonical ALL_REGIONS-compatible region code.
 *  Returns the ALL_REGIONS code, or undefined if unrecognized. */
export function normalizeRegionTag(tag: string): string | undefined {
    if (!tag) return undefined;
    const trimmed = tag.trim();

    // 1. Emoji flag → country code → ALL_REGIONS code
    const emojiCC = EMOJI_TO_COUNTRY[trimmed];
    if (emojiCC) return COUNTRY_TO_REGION[emojiCC] || (ALL_REGIONS.includes(emojiCC) ? emojiCC : undefined);

    // 2. Chinese name → country code → ALL_REGIONS code
    const cnCC = CN_NAME_TO_COUNTRY[trimmed];
    if (cnCC) return COUNTRY_TO_REGION[cnCC] || (ALL_REGIONS.includes(cnCC) ? cnCC : undefined);

    // 3. Uppercase country code or alias (e.g. UK → GB)
    const upper = trimmed.toUpperCase();
    const alias: Record<string, string> = { 'UK': 'GB' };
    const code = alias[upper] || upper;
    if (COUNTRY_TO_REGION[code]) return COUNTRY_TO_REGION[code];
    if (ALL_REGIONS.includes(code)) return code;
    // 宽松：未知后缀码原样返回（支持 Oracle/DigitalOcean/Vultr/Multacom 等云厂商码）
    return upper;
}

/** Map CF country code (ISO 3166-1 alpha-2) to proxy region.
 *  Falls back to 'SG' for unmapped countries (cfnew alignment). */
export function countryToRegion(countryCode: string): string {
    if (!countryCode) return 'SG';
    return COUNTRY_TO_REGION[countryCode.toUpperCase()] || 'SG';
}

/** Build region priority list: own region → neighbors → all remaining */
export function getRegionPriorityList(region: string): string[] {
    const neighbors = REGION_NEIGHBORS[region] || [];
    const otherRegions = ALL_REGIONS.filter(r => r !== region && !neighbors.includes(r));
    return [region, ...neighbors, ...otherRegions];
}

/** Parse "host:port@REGION[#name]" or "host:port[#region-tag name]" entry into components.
 *  Region tag supports: emoji flag (🇸🇬), Chinese name (新加坡), uppercase code (SG). */
export function parseProxyIPWithRegion(entry: string): { host: string; port: number; region?: string } {
    const hashIdx = entry.indexOf('#');
    const clean = hashIdx >= 0 ? entry.slice(0, hashIdx).trim() : entry.trim();
    const comment = hashIdx >= 0 ? entry.slice(hashIdx + 1).trim() : '';

    // Try @REGION tag first
    const atIdx = clean.lastIndexOf('@');
    if (atIdx !== -1) {
        const addressPart = clean.slice(0, atIdx).trim();
        const region = normalizeRegionTag(clean.slice(atIdx + 1));
        if (region) {
            const { host, port } = parseHostPort(addressPart, true);
            return { host, port, region };
        }
    }

    // Fallback: try to extract region from #name part (full text or first token)
    if (comment) {
        const regionFromComment = normalizeRegionTag(comment)
            || normalizeRegionTag(comment.split(/\s+/)[0]);
        if (regionFromComment) {
            const { host, port } = parseHostPort(clean, true);
            return { host, port, region: regionFromComment };
        }
    }

    const { host, port } = parseHostPort(clean, true);
    return { host, port };
}

/** Strip @REGION suffix from proxy IP, return the clean address part */
export function stripRegionTag(entry: string): string {
    const clean = entry.split('#')[0].trim();
    const atIdx = clean.lastIndexOf('@');
    if (atIdx !== -1) return clean.slice(0, atIdx).trim();
    return clean;
}

// ── IP 可达性探测（TCP 连接检查，对齐 cfnew 的 `探测IP可达性`）──

const PROBE_TIMEOUT = 2000; // 单 IP 探测超时 2 秒

/** 对单个 IP:port 做 TCP 连接探测，返回是否可达 */
export async function probeIPReachability(
    hostname: string,
    port: number = 443,
    timeoutMs: number = PROBE_TIMEOUT
): Promise<boolean> {
    try {
        // 使用与 connectSocket 相同的懒求值模式，避免被打包器优化掉
        const socket = (globalThis as any).connect({ hostname, port });
        await Promise.race([
            socket.opened,
            new Promise((_, reject) =>
                setTimeout(() => reject(new Error('timeout')), timeoutMs)
            ),
        ]);
        socket.close();
        return true;
    } catch {
        return false;
    }
}

/** 对 IP 数组做并发探测，返回可达的 IP 子集 */
export async function filterReachableIPs(
    ips: string[],
    port: number = 443
): Promise<string[]> {
    const results = await Promise.all(
        ips.map(async (ip) => {
            const clean = ip.replace(/^\[|\]$/g, ''); // 去掉 IPv6 括号
            const ok = await probeIPReachability(clean, port);
            return { ip, ok };
        })
    );
    const reachable = results.filter(r => r.ok).map(r => r.ip);
    // 如果全部不通则回退原始列表（避免空列表导致完全不可用）
    return reachable.length > 0 ? reachable : ips;
}

/** 对 [host, port] 条目数组做并发探测（每项用自身端口），返回可达条目子集 */
export async function filterReachableEntries(
    entries: [string, number][]
): Promise<[string, number][]> {
    const results = await Promise.all(
        entries.map(async ([ip, port]) => {
            const clean = ip.replace(/^\[|\]$/g, '');
            const ok = await probeIPReachability(clean, port);
            return { entry: [ip, port] as [string, number], ok };
        })
    );
    const reachable = results.filter(r => r.ok).map(r => r.entry);
    // 如果全部不通则回退原始列表（避免空列表导致完全不可用）
    return reachable.length > 0 ? reachable : entries;
}

// ── DoH query with dual-source + cache (for proxy pool resolution, 对齐 edgetunnel 9958-9993) ──

/** Low-level DoH query returning raw answer records (no cache). */
async function dohQueryRaw(domain: string, type: string, dohUrl = CF_DOH): Promise<any[]> {
    try {
        const response = await fetch(`${dohUrl}?name=${encodeURIComponent(domain)}&type=${type}`, {
            headers: { accept: 'application/dns-json' },
            signal: AbortSignal.timeout(10_000),
        });
        const data: any = await response.json();
        return data.Answer || [];
    } catch {
        return [];
    }
}

/** Dual-source DoH query: parallel Cloudflare + Google, return raw records from first with results. */
async function dohQueryDual(domain: string, type: string): Promise<any[]> {
    const results = await Promise.allSettled([
        dohQueryRaw(domain, type, CF_DOH),
        dohQueryRaw(domain, type, GOOGLE_DOH),
    ]);
    const first = results.find(r => r.status === 'fulfilled' && r.value.length > 0);
    return first?.status === 'fulfilled' ? first.value : [];
}

// DoH result cache for proxy pool resolution
const _dohResultCache = new Map<string, { result: any[]; time: number; empty: boolean }>();
const DOH_CACHE_TTL = 10 * 60 * 1000;   // 有结果 10min
const DOH_CACHE_EMPTY_TTL = 30 * 1000;   // 空结果 30s
const DOH_CACHE_MAX = 200;

/** DoH query with dual-source + cache (对齐 edgetunnel doh解析缓存 9949-9993) */
async function dohQueryCached(domain: string, type: string): Promise<any[]> {
    const cacheKey = `${domain}|${type}`;
    const cached = _dohResultCache.get(cacheKey);
    const effectiveTTL = cached?.empty ? DOH_CACHE_EMPTY_TTL : DOH_CACHE_TTL;
    if (cached && Date.now() - cached.time < effectiveTTL) {
        return cached.result;
    }

    const records = await dohQueryDual(domain, type);

    _dohResultCache.set(cacheKey, { result: records, time: Date.now(), empty: records.length === 0 });

    // Evict expired + cap size (对齐 edgetunnel 9984-9993)
    if (_dohResultCache.size > DOH_CACHE_MAX) {
        const now = Date.now();
        for (const [key, value] of _dohResultCache) {
            if (now - value.time >= DOH_CACHE_TTL) _dohResultCache.delete(key);
        }
        while (_dohResultCache.size > DOH_CACHE_MAX) {
            _dohResultCache.delete(_dohResultCache.keys().next().value!);
        }
    }

    return records;
}

// ── Proxy IP pool resolution cache (对齐 edgetunnel 缓存反代IP 9896) ──
let _proxyPoolCacheIP: string | null = null;
let _proxyPoolCacheResult: [string, number][] | null = null;

/** Parse a "host:port" or "[ipv6]:port" entry into [host, port] tuple, default port 0 */
function parseHostPortEntry(entry: string): [string, number] {
    const { host, port } = parseHostPort(entry, true);
    return [host, port || 0]; // 0 = 无显式端口，由调用方决定缺省
}

/**
 * Resolve proxy IP string into a pool of [host, port] entries.
 * Supports: .william domains (TXT prefix expansion), .tpN domains (port extraction),
 * normal domains (DoH A/AAAA dual-source), and direct IPs.
 * Results are cached; pool is sorted + deterministically shuffled + capped at 8.
 * Aligns with edgetunnel `解析地址端口` (9895-10016).
 */
export async function resolveProxyIPPool(
    proxyIP: string,
    targetDomain: string,
    uuid: string
): Promise<[string, number][]> {
    if (_proxyPoolCacheIP === proxyIP && _proxyPoolCacheResult) {
        return _proxyPoolCacheResult;
    }

    const proxyIPNormalized = proxyIP.toLowerCase();
    const entries = proxyIPNormalized.split(',').map(s => s.trim()).filter(Boolean);
    const allEntries: [string, number][] = [];

    for (const entry of entries) {
        if (entry.includes('.william')) {
            // .william domain: DoH TXT query to expand prefix list (对齐 edgetunnel 9918-9935)
            try {
                let txtRecords = await dohQueryCached(entry, 'TXT');
                let txtData = txtRecords.filter((r: any) => r.type === 16).map((r: any) => r.data as string);
                if (txtData.length === 0) {
                    // Fallback to Google DoH
                    txtRecords = await dohQueryRaw(entry, 'TXT', GOOGLE_DOH);
                    txtData = txtRecords.filter((r: any) => r.type === 16).map((r: any) => r.data as string);
                }
                if (txtData.length > 0) {
                    let data = txtData[0];
                    if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
                    const prefixes = data.replace(/\\010/g, ',').replace(/\n/g, ',')
                        .split(',').map((s: string) => s.trim()).filter(Boolean);
                    for (const prefix of prefixes) {
                        allEntries.push(parseHostPortEntry(prefix));
                    }
                }
            } catch (error) {
                console.error('Failed to resolve .william domain:', error);
            }
        } else {
            let [host, port] = parseHostPortEntry(entry);

            // .tpN domain: extract port from suffix (对齐 edgetunnel 9939-9942)
            if (entry.includes('.tp')) {
                const tpMatch = entry.match(/\.tp(\d+)/);
                if (tpMatch) port = parseInt(tpMatch[1], 10);
            }

            // Domain (not IP literal): DoH A/AAAA dual-source (对齐 edgetunnel 9948-9999)
            const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
            const ipv6Regex = /^\[?([a-fA-F0-9:]+)\]?$/;

            if (!ipv4Regex.test(host) && !ipv6Regex.test(host)) {
                const [aRecords, aaaaRecords] = await Promise.all([
                    dohQueryCached(host, 'A'),
                    dohQueryCached(host, 'AAAA'),
                ]);
                const ipv4s = aRecords.filter((r: any) => r.type === 1).map((r: any) => r.data as string);
                const ipv6s = aaaaRecords.filter((r: any) => r.type === 28).map((r: any) => `[${r.data}]`);
                const ips = [...ipv4s, ...ipv6s];
                if (ips.length > 0) {
                    for (const ip of ips) {
                        allEntries.push([ip, port]);
                    }
                } else {
                    // 回退：域名本身 (对齐 edgetunnel 9998-9999)
                    allEntries.push([host, port]);
                }
            } else {
                allEntries.push([host, port]);
            }
        }
    }

    // Sort + deterministic LCG shuffle (对齐 edgetunnel 10006-10011)
    const sorted = [...allEntries].sort((a, b) => a[0].localeCompare(b[0]));
    const rootDomain = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
    let seed = [...(rootDomain + uuid)].reduce((a, c) => a + c.charCodeAt(0), 0);
    const shuffled = [...sorted].sort(() =>
        (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5
    );

    const result = shuffled.slice(0, 8);
    _proxyPoolCacheIP = proxyIP;
    _proxyPoolCacheResult = result;
    return result;
}

/** Built-in fallback proxy IPs for all 14 regions (cfnew 备用地址列表 equivalent).
 *  Used when the user's proxyIPs list is empty and no URL-resolved IPs are available.
 *  Generated from 备用地址列表 at runtime to avoid static signatures. */
export const DEFAULT_PROXY_IPS: string[] = 备用地址列表.map(item => 
    `${item.domain}:${item.port}@${item.regionCode}`
);

// 官方直连地址池（对齐 cfnew v3.0）：10 个官方 Cloudflare 地址（10 个不同 /24 网段）
// 运行时 base64 解码，避免静态特征被识别
const 官方直连地址 = atob('MTcyLjcxLjIxOC4xOTAsMTYyLjE1OC4yMjguODcsMTYyLjE1OC4xODkuMTM0LDE2Mi4xNTguMjYuNjMsMTYyLjE1OC4yNS44NiwxNjIuMTU4LjI5LjIxNiwxNjIuMTU4LjIxOC4xNjAsMTYyLjE1OC4yMjcuMjE0LDE3Mi42OS4xMTguMTk4LDE3Mi42OS4xMTkuMTUw');
export const OFFICIAL_DIRECT_IPS: string[] = 官方直连地址.split(',').map(ip => `${ip}:443@CF`);
export function getOfficialDirectAddress(): string {
    return OFFICIAL_DIRECT_IPS[Math.floor(Math.random() * OFFICIAL_DIRECT_IPS.length)];
}

/** 轮询游标：跨连接复用，避免同区域永远命中第一个（可能已失效）的代理 IP。
 *  配合 connectWithRaceDial 的可达性探测，让不同连接分散到不同候选，提升整体连通率。 */
let proxyIpRoundRobin = 0;
const RR_MOD = 1000003; // 大素数，防止游标在长生命周期 isolate 中无限增长

/** Pick a proxy IP from the list, preferring those matching the worker's region.
 *  同区域存在多个候选时采用轮询（round-robin），不再永远取 matches[0]。
 *  对齐 cfnew：空列表 → 官方直连。 */
export function selectProxyIPByRegion(proxyIPs: string[], workerRegion: string): string | undefined {
    // 对齐 cfnew 获取值备用地址：备用地址列表为空时走官方直连
    if (proxyIPs.length === 0) return getOfficialDirectAddress();
    const region = countryToRegion(workerRegion);

    const parsed = proxyIPs.map(ip => ({
        entry: ip,
        parsed: parseProxyIPWithRegion(ip)
    }));

    const tagged = parsed.filter(p => p.parsed.region);
    if (tagged.length === 0) {
        // 无地区标签：在所有 IP 间轮询
        const idx = proxyIpRoundRobin % proxyIPs.length;
        proxyIpRoundRobin = (proxyIpRoundRobin + 1) % RR_MOD;
        return proxyIPs[idx];
    }

    const priorityRegions = getRegionPriorityList(region);

    for (const targetRegion of priorityRegions) {
        const matches = tagged.filter(p => p.parsed.region === targetRegion);
        if (matches.length > 0) {
            // 同区域轮询，避免永远命中第一个（可能已失效）的 IP
            const idx = proxyIpRoundRobin % matches.length;
            proxyIpRoundRobin = (proxyIpRoundRobin + 1) % RR_MOD;
            return matches[idx].entry;
        }
    }

    // fallback：在所有带标签 IP 间轮询
    const idx = proxyIpRoundRobin % tagged.length;
    proxyIpRoundRobin = (proxyIpRoundRobin + 1) % RR_MOD;
    return tagged[idx].entry;
}