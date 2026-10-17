import { evictOldest, safeErrorMessage } from "@common";
import { PUBLIC_PATH_POOL } from "../common/ratelimit";

// ── H6：跨部署硬编码常量的 env 覆盖入口 ──
// 本模块是纯工具模块，拿不到 Env 参数：运行时配置统一从 globalThis 取
// （worker.ts 在每个请求入口把 env 挂到 globalThis.env）。

/** 运行时 env（模块被非请求路径加载时可能为 undefined） */
function runtimeEnv(): any {
    return (globalThis as any).env;
}

/** 解析 env 中的地址列表（换行或逗号分隔）；未设置或解析为空 → undefined（= 沿用内置默认值） */
function parseEnvAddressList(value: unknown): string[] | undefined {
    if (typeof value !== 'string') return undefined;
    const list = value.split(/[\r\n,]+/).map(item => item.trim()).filter(Boolean);
    return list.length ? list : undefined;
}

/** 原地替换数组内容，保持导出引用不变（DEFAULT_PROXY_IPS / OFFICIAL_DIRECT_IPS 是模块级常量数组） */
function replaceList(target: string[], next: string[]): void {
    target.length = 0;
    target.push(...next);
}

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

// ── Clean IPs / Domains 里的代理条目（socks / socks5 / http / https） ──
// 这类条目不是「节点地址」，而是可直接使用的代理：订阅生成时按各客户端格式输出成**独立可选节点**，
// 同时必须从 VLESS/Trojan 的地址链路里剔除（entryAddresses / buildEntryPortMap / findNameForAddress），
// 否则会生成指向 socks 主机的畸形 WS 节点。

export type CleanProxyProtocol = 'socks' | 'socks5' | 'http' | 'https';

export interface CleanProxyEntry {
    protocol: CleanProxyProtocol;
    server: string;      // 已剥离 IPv6 方括号
    port: number;
    username?: string;
    password?: string;
    name?: string;       // 条目 #备注
}

const CLEAN_PROXY_DEFAULT_PORTS: Record<string, number> = {
    socks: 1080,
    socks5: 1080,
    http: 80,
    https: 443
};

/** scheme://[userinfo@]host[:port][/path] —— userinfo 不含 @ / 空白；IPv6 主机可带方括号 */
const CLEAN_PROXY_RE = /^(socks5?|https?):\/\/(?:([^@\s/?#]*)@)?(\[[0-9a-fA-F:.]+\]|[^:/\s?#]+)(?::(\d+))?([^?#\s]*)/i;

/**
 * 解析 Clean IPs / Domains 里的代理条目；非代理返回 null。
 * 启发式区分（http(s) 兼作「远程清单 URL」的写法）：
 *   - socks:// / socks5:// 一律视为代理；
 *   - http(s):// 仅在「带凭据 user:pass@」或「显式端口且无路径」或「无路径的 IP 字面量」时视为代理，
 *     其余（带路径、无凭据、非 IP）继续按远程清单 URL 交给 resolveUrlEntries 拉取。
 */
export function parseCleanProxy(entry: string): CleanProxyEntry | null {
    const raw = (entry || '').trim();
    if (!raw) return null;
    const matched = raw.match(CLEAN_PROXY_RE);
    if (!matched) return null;

    const scheme = matched[1].toLowerCase();
    const userinfo = matched[2] || '';
    const server = (matched[3] || '').replace(/^\[|\]$/g, '');
    const portRaw = matched[4] || '';
    const path = matched[5] || '';
    if (!server) return null;

    if (scheme !== 'socks' && scheme !== 'socks5') {
        const hasCreds = userinfo.length > 0;
        const hasPath = path.length > 1;   // 仅 "/" 不算路径
        const isIPHost = ipv4ToInt(server) !== null || ipv6ToWords(server) !== null;
        if (!hasCreds && !(portRaw && !hasPath) && !(!hasPath && isIPHost)) return null;
    }

    const port = portRaw ? Number(portRaw) : CLEAN_PROXY_DEFAULT_PORTS[scheme];
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;

    let username: string | undefined;
    let password: string | undefined;
    if (userinfo) {
        const sep = userinfo.indexOf(':');
        if (sep === -1) {
            username = userinfo;
        } else {
            username = userinfo.slice(0, sep);
            password = userinfo.slice(sep + 1);
        }
    }

    return {
        protocol: scheme as CleanProxyProtocol,
        server,
        port,
        username: username || undefined,
        password: password || undefined,
        name: entryName(raw)
    };
}

/** 按输入顺序取出列表里的代理条目；同协议+同主机+同端口+同凭据只保留第一条 */
export function cleanProxyEntries(entries: string[]): CleanProxyEntry[] {
    const result: CleanProxyEntry[] = [];
    const seen = new Set<string>();
    for (const entry of entries || []) {
        const proxy = parseCleanProxy(entry);
        if (!proxy) continue;
        const key = `${proxy.protocol}|${proxy.server.toLowerCase()}|${proxy.port}|${proxy.username || ''}|${proxy.password || ''}`;
        if (seen.has(key)) continue;
        seen.add(key);
        result.push(proxy);
    }
    return result;
}

/** 代理条目的分享链接（Raw 订阅用）：socks5://base64(user:pass)@host:port#备注 */
export function cleanProxyShareLink(proxy: CleanProxyEntry): string {
    // 与既有的 Chain Proxy 链接约定一致：凭据整体 base64 后作为 userinfo
    const credentials = (proxy.username || proxy.password)
        ? `${btoa(`${proxy.username || ''}:${proxy.password || ''}`)}@`
        : '';
    const host = proxy.server.includes(':') ? `[${proxy.server}]` : proxy.server;
    const remark = proxy.name ? `#${encodeURIComponent(proxy.name)}` : '';
    return `${proxy.protocol}://${credentials}${host}:${proxy.port}${remark}`;
}

/** 代理节点的备注：条目 #备注 优先，否则 主机:端口 */
export function cleanProxyRemark(proxy: CleanProxyEntry): string {
    return proxy.name || `${proxy.server}:${proxy.port}`;
}

/** Map entries to clean address array（代理条目不是地址，直接跳过） */
export function entryAddresses(entries: string[]): string[] {
    return entries.map(entry => parseCleanProxy(entry) ? '' : entryAddress(entry)).filter(Boolean);
}

/** Build port map from entry lists — maps bare address → array of explicit ports */
export function buildEntryPortMap(): Record<string, number[]> {
    const { settings: { cleanIPs, customCdnAddrs } } = globalThis;
    const map: Record<string, number[]> = {};
    for (const e of [...cleanIPs, ...customCdnAddrs]) {
        if (parseCleanProxy(e)) continue;   // 代理条目自带端口，不参与地址端口表
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
    const candidates = entries.filter(e => !parseCleanProxy(e));   // 代理条目不对应任何地址
    if (port) {
        for (const e of candidates) {
            if (entryAddress(e) === address && entryPort(e) === port) {
                const name = entryName(e);
                if (name) return name;
            }
        }
    }
    for (const e of candidates) {
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
 *  per-URL key for URL_RESOLVE_TTL: both the value's `ts` (read side) and the KV server-side
 *  `expirationTtl` (write side) carry the same window, so the key expires instead of accumulating.
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
    //    已是代理条目的 http(s) 写法（带凭据 / 端口且无路径 / 无路径 IP）不当远程清单 URL
    const urlSet = new Set<string>();
    expandedEntries.forEach(e => {
        if (e.startsWith('http://') || e.startsWith('https://')) {
            if (parseCleanProxy(e)) return;
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
                    // C-10：与读侧的 ts 判定对齐的 KV 服务端 TTL —— 原先注释承诺「带 TTL 缓存」但 put 未传
                    // expirationTtl，键永不过期、随 URL 种类无限累积。Cloudflare KV 的 TTL 按秒计且要求 ≥ 60。
                    await env.kv.put(cacheKey, JSON.stringify({ ts: Date.now(), lines }), {
                        expirationTtl: Math.round(URL_RESOLVE_TTL / 1000),
                    });
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
// ★ 修的是「第二源恒死」，**不是** IPv6 症状的成因（不要误读本条注释）：
//   原值 `https://dns.google/dns-query` 是 RFC8484 的线格式端点，不接受 name/type 参数 ——
//   实测 `https://dns.google/dns-query?name=ipv6.test-ipv6.com&type=AAAA` 恒返回 HTTP 400，响应体是
//   HTML（"RFC8484 handler at /dns-query received parameter 'name', which it does not accept.
//   Did you intend to pass the 'dns' parameter, or call the JSON handler at /resolve"），
//   于是本文件 fetchDNSRecords 里 response.json() 直接抛错 → dualSourceResolve 的 allSettled 把该源
//   判为 rejected，**第二源从未生效**（dohQueryRaw 的 `.william` TXT 兜底同理，一直是死代码）。
//   但 dualSourceResolve 是「先 CF 后 Google，取第一个非空」，而 CF_DOH 这个 JSON DoH 端点本身可用
//   （Cloudflare 官方文档的 dns-json 用法），所以生产上 A/AAAA 一直由 CF 提供：本改动只是**补回
//   冗余**（CF DoH 取不到 / 被墙时还有 AAAA 来源），IPv6 症状的根因在
//   protocols/websocket/common.ts#connectWithDirectRaceDial 丢掉 AAAA。
//   代价（须知）：dualSourceResolve 用 Promise.allSettled 会等**两个源都返回**，改前死源是快速 400
//   失败，改后若某机房到 dns.google 不通，每个记录类型最多多等一次 AbortSignal.timeout(10s)；
//   该源是必要的冗余，但若想彻底零风险可只保留 CF 单源。
//   正确值与 cfnew 一致（cfnew L193 `https://dns.google/resolve`）。
//   /resolve 实测：`https://dns.google/resolve?name=ipv6.test-ipv6.com&type=AAAA`
//   → {"Status":0,...,"Answer":[{"type":28,"data":"2400:8905::2000:6bff:fe22:d426"}]}，字段形状与 CF 一致。
const GOOGLE_DOH = 'https://dns.google/resolve';

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

/**
 * 并发双源查询，取第一个「成功且非空」的结果；两个源都失败或都为空则返回 []。
 * 语义要点（改动前两份实现逐字相同，合并后仍是同一套）：用 allSettled 等**两个源都结束**，
 * 而不是 Promise.any 提前返回 —— 慢源只在真的没有更快结果时才被等待。
 */
async function firstNonEmptyResult<T>(promises: Promise<T[]>[]): Promise<T[]> {
    const results = await Promise.allSettled(promises);
    const first = results.find(r => r.status === 'fulfilled' && r.value.length > 0);
    return first?.status === 'fulfilled' ? first.value : [];
}

/**
 * 单源 JSON DoH 取数（RFC 8484 的 /resolve 风格：accept: application/dns-json）。
 * 失败**一律抛错**：吞错还是上抛由调用方决定（resolveDNS 路径上抛、代理池路径吞成 []）。
 */
async function dohJsonQuery(url: string): Promise<any[]> {
    const response = await fetch(url, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(10_000),
    });
    const data: any = await response.json();
    return data.Answer || [];
}

/** Query Cloudflare + Google in parallel, return result data[] from first with results (对齐 edgetunnel 9958-9976) */
async function dualSourceResolve(cfBase: string, googleBase: string, typeName: string, recordType: number): Promise<string[]> {
    return await firstNonEmptyResult([
        fetchDNSRecords(`${cfBase}&type=${typeName}`, recordType),
        fetchDNSRecords(`${googleBase}&type=${typeName}`, recordType),
    ]);
}

export async function fetchDNSRecords(url: string, recordType: number): Promise<string[]> {
    try {
        const answer = await dohJsonQuery(url);

        return answer
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

/** H6：内置第三方测速域名节点。env.SPEEDTEST_ADDRESS 未设置时保持内置 'www.speedtest.net'；
 *  显式设为空串时不加入该节点；设为其它值时用它替换。 */
function envSpeedtestAddress(): string | undefined {
    const raw = runtimeEnv()?.SPEEDTEST_ADDRESS;
    if (typeof raw !== 'string') return 'www.speedtest.net';
    return raw.trim() || undefined;
}

/** 订阅节点序列的一项：普通地址（生成 VLESS/Trojan 节点）或代理条目（生成独立代理节点） */
export type ConfigItem =
    | { kind: 'address'; value: string }
    | { kind: 'proxy'; value: CleanProxyEntry };

/**
 * 订阅节点的**有序**序列：先域名 / 测速域名 / DNS 解析出的 IP，再按 cleanIPs 的**输入顺序**
 * 交替给出普通地址与代理条目（节点顺序 = 输入框顺序），最后是 customCdnAddrs。
 */
export async function getConfigItems(isFragment: boolean): Promise<ConfigItem[]> {
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

    const items: ConfigItem[] = [];
    const seen = new Set<string>();
    const pushAddress = (addr: string) => {
        if (!addr) return;
        const key = addr.toLowerCase();
        if (seen.has(key)) return;
        seen.add(key);
        items.push({ kind: 'address', value: addr });
    };
    const pushEntries = (entries: string[]) => {
        for (const entry of entries) {
            const proxy = parseCleanProxy(entry);
            if (proxy) {
                // 代理条目按「协议+主机+端口+凭据」去重，与地址去重互不干扰
                const key = `proxy:${proxy.protocol}|${proxy.server.toLowerCase()}|${proxy.port}|${proxy.username || ''}|${proxy.password || ''}`;
                if (seen.has(key)) continue;
                seen.add(key);
                items.push({ kind: 'proxy', value: proxy });
                continue;
            }
            pushAddress(entryAddress(entry));
        }
    };

    pushAddress(hostName);
    const speedtestAddress = envSpeedtestAddress();
    if (speedtestAddress) pushAddress(speedtestAddress);
    reachableIPv4.forEach(pushAddress);
    reachableIPv6.forEach((ip: string) => pushAddress(`[${ip}]`));

    pushEntries(cleanIPs);
    // customCdnAddrs 仍只作地址（既有语义不变），代理写法在 entryAddresses 里被跳过
    if (!isFragment) entryAddresses(customCdnAddrs).forEach(pushAddress);

    return items;
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
    } else if (isBareIPv4(address)) {
        baseName = 'IPv4优选';
    } else if (isBareIPv6(address)) {
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

/** 撞到已占用路径时的重抽次数上限（1-3 段路径空间约 1.7 亿，撞车极罕见，纯属兜底） */
const WS_PATH_MAX_REDRAW = 5;

/**
 * 生成 WS 伪装路径 —— 对齐 edgetunnel `随机路径`（edgetunnel/_worker.js.backup:8524）
 *
 * 路径由公共路径池中 **1-3 个词**用 `/` 拼接而成（`/api`、`/api/video`）：
 * 段数 `k = Math.floor(Math.random() * 3 + 1)`，在 1..3 上均匀分布（不加权）。
 * 抽取方式是「部分 Fisher-Yates 洗牌」：复制池后只洗前 k 个位置（O(k) 替代 O(n)），
 * 因此同一条路径内的各段互不相同，不会出现 `/api/api`。
 *
 * 每段都取自公共路径字典，故天然满足 isPathInDictionary（edgetunnel 于
 * _worker.js.backup:1400-1401 强制同规则），路径保持人类可读，不做 base64 编码。
 *
 * BPB 没有 edgetunnel 的基础节点路径可拼接（只对应 `完整节点路径 === "/"` 分支），
 * 多段随机路径本身就是伪装路径。
 *
 * @param used 同一次生成中已占用的**完整路径**集合（如 `/api/video`），保证节点级唯一：
 *             抽中后写回；撞到已占用路径则重抽（至多 WS_PATH_MAX_REDRAW 次），
 *             重抽次数用尽则返回最后一次结果，绝不抛错、绝不返回 undefined。
 *             注意语义为「整条路径」而非「单词」——段级重复是允许且期望的，
 *             `/api/video` 与 `/api/blog` 可同时存在。不传则为放回抽取。
 */
export function generateWsPath(used?: Set<string>): string {
    if (PUBLIC_PATH_POOL.length === 0) return "/";

    const len = PUBLIC_PATH_POOL.length;
    let path = "";

    for (let attempt = 0; attempt < WS_PATH_MAX_REDRAW; attempt++) {
        // 段数在 1..3 上均匀分布
        const 随机数 = Math.floor(Math.random() * 3 + 1);
        // 部分洗牌: 只随机选取前 k 个元素，O(k) 替代 O(n)
        const shuffleArr = [...PUBLIC_PATH_POOL];

        for (let i = 0; i < 随机数 && i < len; i++) {
            const j = i + Math.floor(Math.random() * (len - i));
            [shuffleArr[i], shuffleArr[j]] = [shuffleArr[j], shuffleArr[i]];
        }

        path = `/${shuffleArr.slice(0, 随机数).join("/")}`;

        if (!used || !used.has(path)) break;
    }

    // 绝不向 used 写入重复项
    if (used && !used.has(path)) used.add(path);

    return path;
}

/**
 * 无放回抽取 early-data 阈值（2048..2560，共 513 个取值），与 generateWsPath 的 `used` 同一套路：
 * 传入同一 `used` 集合即可保证同一份订阅内任意两个节点的 ed 两两不同；
 * 集合耗尽（节点数 > 513）时退化为有放回抽样，绝不抛错、绝不返回区间外的值。
 * 下限不再取更低：ed 是「首包长度阈值」而非缓冲区大小，首包超过它会直接不启用 Early Data（丢 0-RTT）。
 */
export function pickEarlyData(used?: Set<number>): number {
    const ED_MIN = 2048;
    const ED_MAX = 2560;
    const draw = () => ED_MIN + Math.floor(Math.random() * (ED_MAX - ED_MIN + 1));

    if (!used) return draw();
    // 池耗尽兜底：与 generateWsPath 一致，退化为有放回，不抛错
    if (used.size >= ED_MAX - ED_MIN + 1) return draw();

    let value = draw();
    while (used.has(value)) value = draw();
    used.add(value);
    return value;
}

export function pickRandomEch(echServerNames: string[]): string | undefined {
    if (!echServerNames || echServerNames.length === 0) return undefined;
    return echServerNames[Math.floor(Math.random() * echServerNames.length)];
}

export function base64ToDecimal(base64: string | null | undefined): number[] {
    // 容错：空值/非法 base64 降级为 []（= 无 reserved 字节），绝不抛错。
    // reserved 缺失（上游字段变化 / 旧 KV 数据）时若抛错，会让整个 /sub/warp 订阅 500。
    if (typeof base64 !== 'string' || base64.length === 0) return [];

    let binaryString: string;
    try {
        binaryString = atob(base64);
    } catch {
        return [];
    }

    if (!binaryString) return [];

    const hexString = Array
        .from(binaryString)
        .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('');

    const decimalArray = hexString
        .match(/.{2}/g);

    return decimalArray
        ? decimalArray.map(hex => parseInt(hex, 16))
        : [];
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

/**
 * IPv6 文本 → 16 字节原始地址（RFC 4291 文本表示），用于 SOCKS5 的 ATYP=4 地址字段这类
 * 「需要二进制地址」的场合。非法输入返回 null，由调用方决定回退策略（绝不抛错）。
 *
 * 接受：完整 8 段、`::` 压缩（至多一处、至少压缩一个 0 段）、尾部内嵌 IPv4
 * （`::ffff:1.2.3.4` / `64:ff9b::1.2.3.4`）、外层方括号、大小写混合、各段 1-4 位十六进制。
 * 拒绝：非 IPv6（不含 `:`）、zone/scope 后缀（`fe80::1%eth0` —— 它不是地址的一部分，
 * 无法映射到 16 字节）、段数超 8、多于一处 `::`、空段、内嵌 IPv4 含前导 0 或越界。
 *
 * 刻意不复用 ipv6ToWords：那个函数服务于 Cloudflare 网段判定、明确不支持内嵌 IPv4，
 * 改它会连带改变 isCloudflareIP 的判定口径（进而影响首跳路由），不属于本次修复范围。
 */
export function ipv6ToBytes(address: string): Uint8Array | null {
    let text = String(address ?? '').trim();
    if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
    if (!text || text.includes('%') || !text.includes(':')) return null;

    // 尾部内嵌 IPv4 先折成两个 16 位段，后续只处理十六进制写法
    const lastColon = text.lastIndexOf(':');
    const tail = text.slice(lastColon + 1);
    if (tail.includes('.')) {
        const octets = tail.split('.');
        if (octets.length !== 4) return null;
        // 只接受规范十进制（无前导 0），避免 010 这类歧义写法被误读
        const nums = octets.map(o => (/^(0|[1-9][0-9]{0,2})$/.test(o) ? Number(o) : NaN));
        if (nums.some(n => !Number.isInteger(n) || n > 255)) return null;
        const folded = `${(((nums[0] << 8) | nums[1]) >>> 0).toString(16)}:${(((nums[2] << 8) | nums[3]) >>> 0).toString(16)}`;
        text = `${text.slice(0, lastColon + 1)}${folded}`;
    }

    const halves = text.split('::');
    if (halves.length > 2) return null;
    const parseSide = (side: string): number[] | null => {
        if (side === '') return [];
        const groups: number[] = [];
        for (const part of side.split(':')) {
            if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
            groups.push(parseInt(part, 16));
        }
        return groups;
    };
    const left = parseSide(halves[0]);
    if (!left) return null;
    let words: number[];
    if (halves.length === 1) {
        if (left.length !== 8) return null;
        words = left;
    } else {
        const right = parseSide(halves[1]);
        if (!right) return null;
        const zeros = 8 - left.length - right.length;
        if (zeros < 1) return null;   // `::` 至少要压缩掉一段
        words = [...left, ...new Array(zeros).fill(0), ...right];
    }

    const bytes = new Uint8Array(16);
    words.forEach((word, index) => {
        bytes[index * 2] = (word >> 8) & 0xff;
        bytes[index * 2 + 1] = word & 0xff;
    });
    return bytes;
}

/** C-14：「单个可拨号地址」判定 —— 在 isIPv4/isIPv6 基础上排除 CIDR 后缀。
 *  `isIPv4/isIPv6` 保留对 CIDR 的宽松接受是既有对外契约（clash/routing.ts:82-83 依赖它，
 *  并在 `ip.includes('/')` 分支里自行兜底），此处只新增窄判定供按「单地址」使用的调用点使用。 */
export function isBareIPv4(address: string): boolean {
    return isIPv4(address) && !address.includes('/');
}

export function isBareIPv6(address: string): boolean {
    return isIPv6(address) && !address.includes('/');
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
    // 隐私加固：不再随机化 SNI 大小写 —— RFC 6066 规定 SNI 大小写不敏感，
    // 随机大小写没有对抗价值，却制造出「真实浏览器绝不产生」的形态，反而成为异常特征。
    const sni = hostName;

    // H12（未做，需产品决策）：allowInsecure 的**唯一**触发条件是「本条 address 命中 customCdnAddrs」
    // （见上方 isCustomAddr），用户既看不到哪些地址会关掉证书校验、也无法单独开关。
    // 若关校验，则本地址在 Clash(skip-cert-verify)/sing-box(insecure)/URL(allowInsecure=1) 三端一致关闭。
    // 本轮不动：改成显式开关需要新增 settings 字段 + kv.ts 白名单 + global.d.ts 声明 + 面板 UI
    // （均在本文件之外），按工作单约束只记录触发条件，不越界改。
    return { host, sni, allowInsecure: isCustomAddr };
}

export function parseHostPort(input: string, brackets?: boolean): { host: string, port: number } {
    // C-05：统一规范化 —— 首尾空白 + `@REGION` 标签在这里吸收掉，不再要求调用点先 stripRegionTag；
    // 规范化后为空串（或只剩空白）时保持原语义返回 {host:"",port:0}，交给调用点按「无地址」处理。
    const normalized = stripRegionTagRaw(input);
    if (!normalized) return { host: "", port: 0 };

    const bm = normalized.match(/^\[(?<ipv6>.+?)\](?::(?<port>\d+))?$/);
    if (bm?.groups) {
        const host = brackets ? `[${bm.groups.ipv6}]` : bm.groups.ipv6;
        return { host, port: bm.groups.port ? Number(bm.groups.port) : 0 };
    }

    if (normalized.includes('::')) {
        const lastColon = normalized.lastIndexOf(':');
        const afterLastColon = normalized.slice(lastColon + 1);
        if (/^\d+$/.test(afterLastColon)) {
            const hostPart = normalized.slice(0, lastColon);
            if (hostPart.includes(':') && !hostPart.endsWith(':')) {
                return { host: brackets ? `[${hostPart}]` : hostPart, port: Number(afterLastColon) };
            }
        }
        return { host: brackets ? `[${normalized}]` : normalized, port: 0 };
    }

    const hm = normalized.match(/^(?<host>[^:]+)(?::(?<port>\d+))?$/);
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
    // C-08：判空用 `== null` —— 原 `!min || !max` 把合法的数字 0（0ms 延迟 / 0 长度）
    // 当成「未设置」静默丢弃，面板填 0 与生成结果不一致。
    if (min == null || max == null) return undefined;
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

/** 去掉 `#name` 注释、首尾空白与 `@REGION` 标签，返回纯地址部分（不校验 host 合法性）。
 *  C-05：`parseHostPort` / `stripRegionTag` / `parseProxyIPWithRegion` 共用同一套规范化规则，
 *  避免「只靠调用点先 stripRegionTag」的隐式约束再次分叉。 */
function stripRegionTagRaw(entry: string): string {
    const clean = entry.split('#')[0].trim();
    const atIdx = clean.lastIndexOf('@');
    if (atIdx !== -1) return clean.slice(0, atIdx).trim();
    return clean;
}

/** Strip @REGION suffix from proxy IP, return the clean address part */
export function stripRegionTag(entry: string): string {
    return stripRegionTagRaw(entry);
}

// ── IP 可达性探测（TCP 连接检查，对齐 cfnew 的 `探测IP可达性`）──

const PROBE_TIMEOUT = 2000; // 单 IP 探测超时 2 秒

/** 对单个 IP:port 做 TCP 连接探测，返回是否可达 */
export async function probeIPReachability(
    hostname: string,
    port: number = 443,
    timeoutMs: number = PROBE_TIMEOUT
): Promise<boolean> {
    let socket: Socket | null = null;
    try {
        // 使用与 connectSocket 相同的懒求值模式，避免被打包器优化掉
        const createdSocket: Socket = (globalThis as any).connect({ hostname, port });
        socket = createdSocket;
        await Promise.race([
            createdSocket.opened,
            // timer.unref 让挂起的超时定时器不阻止请求结束（对齐 F-09 同类修复）
            new Promise((_, reject) => {
                const timer = setTimeout(() => reject(new Error('timeout')), timeoutMs) as unknown as { unref?: () => void };
                timer.unref?.();
            }),
        ]);
        return true;
    } catch {
        return false;
    } finally {
        // C-09：超时/异常路径同样关闭 socket —— 原先 close 只在成功路径执行，
        // 不可达候选多时未关闭的 TCP 尝试会在 isolate 内累积。
        try {
            socket?.close();
        } catch {}
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

/** 对 [host, port] 条目数组做并发探测（每项用自身端口），返回可达条目子集。
 *  onProbe 可选回调：把每条候选的探测结果交给调用方 —— 反代池用它把「探测不通」的候选
 *  记进临时黑名单（指数退避），避免同一个死候选每连接都白等一次 2 秒探测。 */
export async function filterReachableEntries(
    entries: [string, number][],
    onProbe?: (entry: [string, number], ok: boolean) => void
): Promise<[string, number][]> {
    const results = await Promise.all(
        entries.map(async ([ip, port]) => {
            const clean = ip.replace(/^\[|\]$/g, '');
            const ok = await probeIPReachability(clean, port);
            onProbe?.([ip, port], ok);
            return { entry: [ip, port] as [string, number], ok };
        })
    );
    const reachable = results.filter(r => r.ok).map(r => r.entry);
    // 如果全部不通则回退原始列表（避免空列表导致完全不可用）
    return reachable.length > 0 ? reachable : entries;
}

// ── DoH query with dual-source + cache (for proxy pool resolution, 对齐 edgetunnel 9958-9993) ──

/** Low-level DoH query returning raw answer records (no cache). 吞错返回 []（与 resolveDNS 路径的上抛语义不同，刻意保留） */
async function dohQueryRaw(domain: string, type: string, dohUrl = CF_DOH): Promise<any[]> {
    try {
        return await dohJsonQuery(`${dohUrl}?name=${encodeURIComponent(domain)}&type=${type}`);
    } catch {
        return [];
    }
}

/** Dual-source DoH query: parallel Cloudflare + Google, return raw records from first with results. */
async function dohQueryDual(domain: string, type: string): Promise<any[]> {
    return await firstNonEmptyResult([
        dohQueryRaw(domain, type, CF_DOH),
        dohQueryRaw(domain, type, GOOGLE_DOH),
    ]);
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
        evictOldest(_dohResultCache, DOH_CACHE_MAX);
    }

    return records;
}

// ── Proxy IP pool resolution cache (对齐 edgetunnel 缓存反代IP 9896) ──
// C-04：缓存键原先只有 proxyIP，且无 TTL → 同一 isolate 内第二个 targetDomain/uuid
// 会拿到为第一个域名洗出的同一份 8 条子集，且首次降级结果被永久冻结。
const PROXY_POOL_CACHE_TTL = 10 * 60 * 1000; // 10min：与解析依赖的 DoH 结果缓存 DOH_CACHE_TTL 对齐
const PROXY_POOL_CACHE_MAX = 32;             // 键数量上限，防止长生命周期 isolate 中无界增长
/** 模块级缓存：isolate 生命周期内有效（键 = proxyIP|targetDomain|uuid），命中时校验 TTL，超限时按 LRU 淘汰 */
const _proxyPoolCache = new Map<string, { result: [string, number][]; time: number }>();

/** 单飞表：键 → 进行中的解析 promise。并发同键只解析一次；结束（成功或失败）立即移除。 */
const _proxyPoolInflight = new Map<string, Promise<[string, number][]>>();

/** 代理池缓存键：proxyIP 归一化（trim + 小写）与 targetDomain/uuid 一起参与，避免跨目标域名串味 */
function proxyPoolCacheKey(proxyIP: string, targetDomain: string, uuid: string): string {
    return `${proxyIP.trim().toLowerCase()}|${targetDomain}|${uuid}`;
}

/** Parse a "host:port" or "[ipv6]:port" entry into [host, port] tuple, default port 0 */
function parseHostPortEntry(entry: string): [string, number] {
    const { host, port } = parseHostPort(entry, true);
    return [host, port || 0]; // 0 = 无显式端口，由调用方决定缺省
}

// ── 反代池二级缓存：Cache API（同一数据中心内跨 isolate 共享） ──
// 一级 _proxyPoolCache 是模块级 Map，只在单个 isolate 内有效：新连接落到别的 isolate（并发、
// 或原 isolate 被回收）就要重新走 DoH。caches.default 在同一个 PoP 内跨 isolate 共享，
// 用它兜住这部分重复解析（纯 IP 池不参与，见调用点）。
// 三条约束：
//   1. 只做「读/写」，任何异常都退化成只走一级缓存，绝不影响拨号主流程；
//   2. 空池永不入缓存 —— 否则一次 DoH 失败会把「解析不到」冻结一整个 TTL；
//   3. 响应体里带解析时间戳并校验 TTL。Cache-Control 只用来让 Cache API 愿意保留条目，
//      它的 max-age 与我们的 TTL 语义并不等价，新鲜度一律以体内时间戳为准。
const POOL_CACHE_API_PATH = '/__bpb_pool_cache/v1/';

/** 二级缓存键的 URL：用 Worker 自己的 host 拼，保证 Key 落在本 zone 的 Cache 里。
 *  拿不到 host（异常早期路径）时返回 null → 调用方直接跳过二级缓存。 */
function poolCacheApiRequest(cacheKey: string): Request | null {
    const host = globalThis.httpConfig?.hostName;
    if (!host) return null;
    return new Request(`https://${host}${POOL_CACHE_API_PATH}${encodeURIComponent(cacheKey)}`);
}

/** 取二级缓存的句柄 + 请求键。Cache API 不可用（Node / smoke 环境）或拿不到 host 时返回 null。 */
function poolCacheApiTarget(cacheKey: string): { cache: Cache; request: Request } | null {
    const cache = (globalThis as { caches?: { default?: Cache } }).caches?.default;
    if (!cache) return null;
    const request = poolCacheApiRequest(cacheKey);
    return request ? { cache, request } : null;
}

/** 读二级缓存：未命中 / 已过期 / 结构不符 / 任何异常一律返回 null（调用方继续走 DoH）。 */
async function readProxyPoolCacheApi(cacheKey: string): Promise<{ result: [string, number][]; time: number } | null> {
    try {
        const target = poolCacheApiTarget(cacheKey);
        if (!target) return null;

        const hit = await target.cache.match(target.request);
        if (!hit) return null;

        const body = await hit.json() as { time?: unknown; pool?: unknown };
        const time = body?.time;
        if (typeof time !== 'number' || Date.now() - time >= PROXY_POOL_CACHE_TTL) return null;

        const pool = body.pool;
        if (!Array.isArray(pool) || pool.length === 0) return null;
        for (const entry of pool) {
            // 结构必须与 [string, number][] 一致，否则当未命中处理，绝不把脏数据喂给拨号
            if (!Array.isArray(entry) || typeof entry[0] !== 'string' || !Number.isFinite(entry[1])) return null;
        }
        return { result: pool as [string, number][], time };
    } catch {
        return null;
    }
}

/** 写二级缓存：只写非空池，TTL 与一级缓存同口径；写失败静默忽略。 */
async function writeProxyPoolCacheApi(cacheKey: string, result: [string, number][], time: number): Promise<void> {
    if (result.length === 0) return;
    try {
        const target = poolCacheApiTarget(cacheKey);
        if (!target) return;

        await target.cache.put(target.request, new Response(JSON.stringify({ time, pool: result }), {
            headers: {
                'content-type': 'application/json',
                'cache-control': `public, max-age=${Math.round(PROXY_POOL_CACHE_TTL / 1000)}`
            }
        }));
    } catch {
        // 二级缓存是尽力而为：写不进去只影响下一个 isolate 的命中率，不影响本次结果
    }
}

/**
 * Resolve proxy IP string into a pool of [host, port] entries.
 * Supports: .william domains (TXT prefix expansion), .tpN domains (port extraction),
 * normal domains (DoH A/AAAA dual-source), and direct IPs.
 * Results are cached per (proxyIP, targetDomain, uuid) with a TTL; the pool keeps **all**
 * resolved entries (sorted + deterministically shuffled)，单池不设条数上限 ——
 * 截断会让被砍掉的候选连 2 秒探测的机会都没有（实测地区池 KR=14、SG/JP/通用=50）。
 * 抽取 8 条参与「2 秒探测 + 竞速拨号」的职责移到 connectWithRaceDial：那里按临时黑名单
 * 过滤后随机抽取。
 * 三级顺序：一级 isolate 内 Map → 二级 Cache API（同一 PoP 跨 isolate）→ DoH；
 * 同一键的并发调用走单飞，只解析一次。
 * Aligns with edgetunnel `解析地址端口` (9895-10016).
 */
export async function resolveProxyIPPool(
    proxyIP: string,
    targetDomain: string,
    uuid: string
): Promise<[string, number][]> {
    const cacheKey = proxyPoolCacheKey(proxyIP, targetDomain, uuid);
    const cachedPool = _proxyPoolCache.get(cacheKey);
    if (cachedPool && Date.now() - cachedPool.time < PROXY_POOL_CACHE_TTL) {
        // 命中即刷新 LRU 顺序，保证淘汰的是最久未用的键
        _proxyPoolCache.delete(cacheKey);
        _proxyPoolCache.set(cacheKey, cachedPool);
        return cachedPool.result;
    }
    if (cachedPool) _proxyPoolCache.delete(cacheKey);

    // ── 单飞（in-flight 去重）──
    // 一级缓存要等解析结束才写入，而同一个键在同一秒里可能有多条连接同时到达
    // （浏览器开一个页面就是几十条并发 WS，且每条连接还可能两次进池）。中间这段窗口里
    // N 条连接会各自发起一遍 DoH。这里把「进行中的同键解析」共享出去：只有第一条真正解析，
    // 其余直接 await 它的结果；解析结束（成功或失败）立刻移除，绝不把失败固化进单飞表。
    const pending = _proxyPoolInflight.get(cacheKey);
    if (pending) return await pending;

    const task = resolveProxyPoolUncached(cacheKey, proxyIP, targetDomain, uuid);
    _proxyPoolInflight.set(cacheKey, task);
    try {
        return await task;
    } finally {
        // 单飞期间同一个键只有这里写入，直接删掉即可
        _proxyPoolInflight.delete(cacheKey);
    }
}

/**
 * 真正的解析实现。调用前一级缓存已判定未命中，同键并发已由 resolveProxyIPPool 的单飞收口。
 * cacheKey 由调用方算好传进来，保证回写两级缓存时用的键与查一级缓存时完全一致。
 */
async function resolveProxyPoolUncached(
    cacheKey: string,
    proxyIP: string,
    targetDomain: string,
    uuid: string
): Promise<[string, number][]> {
    // 一级（isolate 内 Map）未命中 → 二级（Cache API，同一 PoP 跨 isolate 共享）。
    // 只有含域名的池才需要 DoH（.william / .tpN / 普通域名）；纯 IP 字面量是纯内存计算，
    // 走 Cache API 反而更贵，直接跳过二级缓存。
    const poolNeedsDns = /[a-z]/i.test(proxyIP);
    if (poolNeedsDns) {
        const sharedPool = await readProxyPoolCacheApi(cacheKey);
        if (sharedPool) {
            // 用二级条目自己的时间戳回填一级：两层共用一个绝对 TTL，
            // 不会因为「命中后回填」把 10 分钟续成 20 分钟。
            _proxyPoolCache.set(cacheKey, { result: sharedPool.result, time: sharedPool.time });
            evictOldest(_proxyPoolCache, PROXY_POOL_CACHE_MAX);
            return sharedPool.result;
        }
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

    // 池内保留**全部**解析结果，不做任何条数截断：实测地区池 KR=14 条、SG/JP/通用=50 条，
    // 截断会让被砍掉的候选连 2 秒探测的机会都没有（那正是本改动要消除的浪费）。
    // 真正的边界来自 DoH 应答本身（一次 DNS 报文 ≤64KB）与 _proxyPoolCache 的 32 键上限。
    const result = shuffled;
    // C-04：写入带时间戳的键化缓存；超限时按插入顺序（LRU）淘汰最旧一条
    const resolvedAt = Date.now();
    _proxyPoolCache.set(cacheKey, { result, time: resolvedAt });
    evictOldest(_proxyPoolCache, PROXY_POOL_CACHE_MAX);
    // 二级缓存：同一 PoP 内其它 isolate 直接复用这份结果（写失败只影响命中率，不影响本次返回）
    if (poolNeedsDns) await writeProxyPoolCacheApi(cacheKey, result, resolvedAt);
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
// ── H6：内置池的 env 覆盖入口 ──
// 出厂内置值快照：在 env 覆盖**之前**捕获（上方原声明保持逐字不变），未设置 env 时用它还原。
const BUILTIN_PROXY_IPS: string[] = [...DEFAULT_PROXY_IPS];
const BUILTIN_OFFICIAL_DIRECT_IPS: string[] = [...OFFICIAL_DIRECT_IPS];

/** H6：env.DEFAULT_PROXY_IPS / env.OFFICIAL_IPS 覆盖内置池（换行或逗号分隔）。
 *  由 init.ts 的 init() 在每个请求入口调用 —— 模块级常量数组在导入期读不到 env。
 *  未设置（或解析为空）时还原为出厂内置值，默认行为逐字不变。 */
export function applyAddressEnvOverrides(env: any): void {
    replaceList(DEFAULT_PROXY_IPS, parseEnvAddressList(env?.DEFAULT_PROXY_IPS) ?? BUILTIN_PROXY_IPS);
    replaceList(OFFICIAL_DIRECT_IPS, parseEnvAddressList(env?.OFFICIAL_IPS) ?? BUILTIN_OFFICIAL_DIRECT_IPS);
}

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

// ── 目标是否为 Cloudflare 承载（出站模式「目标识别式」首跳决策用） ──
// 网段来源：Cloudflare 官方 https://api.cloudflare.com/client/v4/ips
// （etag 38f79d050aa027e3be3865e495dcc9bc：v4 15 段 + v6 7 段）。
// 与仓库其它地址表一致，用 base64 存放避免静态特征；官方调整网段时需同步更新这两条常量。
const 官方CF网段V4 = atob('MTczLjI0NS40OC4wLzIwLDEwMy4yMS4yNDQuMC8yMiwxMDMuMjIuMjAwLjAvMjIsMTAzLjMxLjQuMC8yMiwxNDEuMTAxLjY0LjAvMTgsMTA4LjE2Mi4xOTIuMC8xOCwxOTAuOTMuMjQwLjAvMjAsMTg4LjExNC45Ni4wLzIwLDE5Ny4yMzQuMjQwLjAvMjIsMTk4LjQxLjEyOC4wLzE3LDE2Mi4xNTguMC4wLzE1LDEwNC4xNi4wLjAvMTMsMTA0LjI0LjAuMC8xNCwxNzIuNjQuMC4wLzEzLDEzMS4wLjcyLjAvMjI=');
const 官方CF网段V6 = atob('MjQwMDpjYjAwOjovMzIsMjYwNjo0NzAwOjovMzIsMjgwMzpmODAwOjovMzIsMjQwNTpiNTAwOjovMzIsMjQwNTo4MTAwOjovMzIsMmEwNjo5OGMwOjovMjksMmMwZjpmMjQ4OjovMzI=');

/** IPv4 点分十进制 → 32 位无符号整数；非法返回 null */
function ipv4ToInt(ip: string): number | null {
    const parts = ip.trim().split('.');
    if (parts.length !== 4) return null;
    let value = 0;
    for (const part of parts) {
        if (!/^\d{1,3}$/.test(part)) return null;
        const octet = Number(part);
        if (octet > 255) return null;
        value = value * 256 + octet;
    }
    return value;
}

/** IPv6 文本 → 8 段 16 位数组；非法返回 null（不支持 ::ffff:127.0.0.1 这类内嵌 IPv4 写法） */
function ipv6ToWords(ip: string): number[] | null {
    let text = ip.trim();
    if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
    if (text.includes('%')) text = text.split('%')[0];   // 去掉 zone id
    if (!text.includes(':')) return null;

    const halves = text.split('::');
    if (halves.length > 2) return null;

    const parseGroups = (value: string): number[] | null => {
        if (!value) return [];
        const groups: number[] = [];
        for (const group of value.split(':')) {
            if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
            groups.push(parseInt(group, 16));
        }
        return groups;
    };

    const head = parseGroups(halves[0]);
    const tail = halves.length === 2 ? parseGroups(halves[1]) : [];
    if (!head || !tail) return null;
    if (halves.length === 1) return head.length === 8 ? head : null;

    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    return [...head, ...new Array<number>(missing).fill(0), ...tail];
}

/** IPv6 地址是否落在 base/prefix 网段内 */
function ipv6InPrefix(words: number[], base: number[], prefix: number): boolean {
    let remaining = prefix;
    for (let i = 0; i < 8 && remaining > 0; i++) {
        if (remaining >= 16) {
            if (words[i] !== base[i]) return false;
            remaining -= 16;
        } else {
            const mask = (0xffff << (16 - remaining)) & 0xffff;
            if ((words[i] & mask) !== (base[i] & mask)) return false;
            remaining = 0;
        }
    }
    return true;
}

/** 解析 Cloudflare v4 网段表 → [起始, 结束] 区间（非法条目丢弃） */
const CF_V4_RANGES: [number, number][] = 官方CF网段V4.split(',').flatMap(cidr => {
    const [base, lenRaw] = cidr.trim().split('/');
    const start = ipv4ToInt(base ?? '');
    const len = Number(lenRaw);
    if (start === null || !Number.isInteger(len) || len < 0 || len > 32) return [];
    return [[start, start + 2 ** (32 - len) - 1] as [number, number]];
});

/** 解析 Cloudflare v6 网段表（非法条目丢弃） */
const CF_V6_RANGES: { base: number[]; prefix: number }[] = 官方CF网段V6.split(',').flatMap(cidr => {
    const [base, lenRaw] = cidr.trim().split('/');
    const words = ipv6ToWords(base ?? '');
    const prefix = Number(lenRaw);
    if (!words || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) return [];
    return [{ base: words, prefix }];
});

/** IP 是否落在 Cloudflare 公布的网段内（v4 + v6） */
export function isCloudflareIP(ip: string): boolean {
    const clean = ip.trim().replace(/^\[|\]$/g, '');
    if (!clean) return false;
    const v4 = ipv4ToInt(clean);
    if (v4 !== null) return CF_V4_RANGES.some(([start, end]) => v4 >= start && v4 <= end);
    const words = ipv6ToWords(clean);
    if (!words) return false;
    return CF_V6_RANGES.some(range => ipv6InPrefix(words, range.base, range.prefix));
}

// 目标域名解析缓存：出站模式的目标分类与直连竞速共用，同一域名不再重复 DoH。
// TTL 与既有 DoH 结果缓存同口径（有结果 10 分钟、空结果 30 秒）。
const _targetDnsCache = new Map<string, { ipv4: string[]; ipv6: string[]; time: number; empty: boolean }>();
const TARGET_DNS_TTL = 10 * 60 * 1000;
const TARGET_DNS_EMPTY_TTL = 30 * 1000;
const TARGET_DNS_CACHE_MAX = 200;

/** 目标域名解析（A + AAAA，带 LRU 缓存） */
export async function resolveTargetDNS(domain: string): Promise<DnsResult> {
    const key = domain.toLowerCase();
    const cached = _targetDnsCache.get(key);
    if (cached && Date.now() - cached.time < (cached.empty ? TARGET_DNS_EMPTY_TTL : TARGET_DNS_TTL)) {
        _targetDnsCache.delete(key);   // 命中即刷新 LRU 顺序
        _targetDnsCache.set(key, cached);
        return { ipv4: cached.ipv4, ipv6: cached.ipv6 };
    }
    if (cached) _targetDnsCache.delete(key);

    const result = await resolveDNS(domain, false);
    _targetDnsCache.set(key, {
        ipv4: result.ipv4,
        ipv6: result.ipv6,
        time: Date.now(),
        empty: result.ipv4.length === 0 && result.ipv6.length === 0,
    });
    if (_targetDnsCache.size > TARGET_DNS_CACHE_MAX) {
        evictOldest(_targetDnsCache, TARGET_DNS_CACHE_MAX);
    }
    return result;
}

/** 目标是否由 Cloudflare 承载：IP 字面量直接判段，域名解析后 A / AAAA 任一命中 CF 网段即为真。
 *  解析失败或解析不到地址 → false（首跳按直连目标处理）。
 *  注意：误判不会导致断流 —— 池虽然从首跳消失，但仍留在回退阶梯里兜底。 */
export async function isCloudflareTarget(address: string): Promise<boolean> {
    const clean = (address || '').trim();
    if (!clean) return false;
    if (ipv4ToInt(clean) !== null || ipv6ToWords(clean)) return isCloudflareIP(clean);
    try {
        const { ipv4, ipv6 } = await resolveTargetDNS(clean);
        return ipv4.some(isCloudflareIP) || ipv6.some(isCloudflareIP);
    } catch {
        return false;
    }
}