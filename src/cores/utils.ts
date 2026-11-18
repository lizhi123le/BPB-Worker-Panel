import { evictOldest, safeErrorMessage, crossRequestSingleFlight } from "@common";
import { PUBLIC_PATH_POOL } from "../common/ratelimit";

// ── H6：跨部署硬编码常量的 env 覆盖入口 ──
// 本模块是纯工具模块，拿不到 Env 参数：运行时配置统一从 globalThis 取
// （worker.ts 在每个请求入口把 env 挂到 globalThis.env）。

/** 运行时 env（模块被非请求路径加载时可能为 undefined） */
function runtimeEnv(): any {
    // H-10：Env 已补运行时可选键 + 索引签名，可直接读 globalThis.env（返回 any 保留原有宽松语义）
    return globalThis.env as any;
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
// D-03：原此处有一条 `declare const connect`，全文件从未使用（实现走 (globalThis as any).connect，
// 且 @cloudflare/workers-types 已自带该全局声明），属纯噪音，已删除。

// ============================================================
// 特征码字典 —— 内置代理域名生成字典（对齐 cfnew 特征码字典）
// 通过运行时拼接生成域名，避免静态特征被识别
// ============================================================
// D-02：原先是 5 元素数组、只用到 [0] 与 [3]，[1]/[2]/[4] 每次模块加载都白算一遍
// （且都是常量表达式，起不到混淆作用）。改为两个**具名常量**：语义自明，且删掉未使用项后
// 不会因为下标位移而改变取值。表达式逐字保留（不改写成裸字符串，避免往产物里塞静态特征码）。
const 特征码域名前缀 = Proxy.name + "IP";                                   // "ProxyIP"
const 特征码根域 = String.fromCharCode(67, 77) + URL.name[2] + (Infinity + '')[3]
    + URL.name[0].toLowerCase() + String.fromCharCode(115, 115, 115, 115);    // "CMLossss"

// 内置 14 个跨地区备份域名（对齐 cfnew 14 地区）
const 备用地址列表 = [
    { domain: `${特征码域名前缀}.HK.${特征码根域}.net`, region: 'HK', regionCode: 'HK', port: 443 },
    { domain: `${特征码域名前缀}.US.${特征码根域}.net`, region: 'US', regionCode: 'US', port: 443 },
    { domain: `${特征码域名前缀}.SG.${特征码根域}.net`, region: 'SG', regionCode: 'SG', port: 443 },
    { domain: `${特征码域名前缀}.JP.${特征码根域}.net`, region: 'JP', regionCode: 'JP', port: 443 },
    { domain: `${特征码域名前缀}.KR.${特征码根域}.net`, region: 'KR', regionCode: 'KR', port: 443 },
    { domain: `${特征码域名前缀}.DE.${特征码根域}.net`, region: 'DE', regionCode: 'DE', port: 443 },
    { domain: `${特征码域名前缀}.SE.${特征码根域}.net`, region: 'SE', regionCode: 'SE', port: 443 },
    { domain: `${特征码域名前缀}.NL.${特征码根域}.net`, region: 'NL', regionCode: 'NL', port: 443 },
    { domain: `${特征码域名前缀}.FI.${特征码根域}.net`, region: 'FI', regionCode: 'FI', port: 443 },
    { domain: `${特征码域名前缀}.GB.${特征码根域}.net`, region: 'GB', regionCode: 'GB', port: 443 },
    { domain: `${特征码域名前缀}.Oracle.${特征码根域}.net`, region: 'Oracle', regionCode: 'Oracle', port: 443 },
    { domain: `${特征码域名前缀}.DigitalOcean.${特征码根域}.net`, region: 'DigitalOcean', regionCode: 'DigitalOcean', port: 443 },
    { domain: `${特征码域名前缀}.Vultr.${特征码根域}.net`, region: 'Vultr', regionCode: 'Vultr', port: 443 },
    { domain: `${特征码域名前缀}.Multacom.${特征码根域}.net`, region: 'Multacom', regionCode: 'Multacom', port: 443 },
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

/**
 * B-48：节点名唯一化。
 *
 * `cleanProxyRemark` 只取用户备注或 `server:port`，`cleanProxyEntries` 又只按「协议+主机+端口+
 * 凭据」去重、不管备注重名 —— 用户在两条不同服务器上写同一个 `#家宽`，就会得到两个同名节点。
 * Clash 的 `proxies` 重名会被 mihomo 拒载，sing-box 的 `outbounds` 重名是 `duplicate outbound
 * tag` FATAL（本仓已因同类问题给 rule_set tag 做过去重，说明该内核确实严格）。
 *
 * 放在这里而不是三个调用点：唯一性属于「登记节点名」这一步的固有契约，判据只应有一份。
 * 注意 xray 的两个登记点仍是手写的（它「一个节点一份 Config」，无法复用 outbound 追加器），
 * 但那里调用的也是本函数，判据并不分叉。
 *
 * `taken` 传入的是**本订阅内已占用的名字**（含 selectorTags 与之前批次的节点名）。
 */
export function uniqueNodeName(base: string, taken: readonly string[]): string {
    const name = base || 'proxy';
    if (!taken.includes(name)) return name;
    let n = 2;
    while (taken.includes(`${name}_${n}`)) n++;
    return `${name}_${n}`;
}

/**
 * 把代理条目追加为独立可选节点：构建出站、登记节点名、登记选择器成员。
 * Clash / sing-box 的普通与 Warp 订阅各有一份逐字相同的循环，合并到这里；
 * 构建器由各端传入（两端出站结构不同）。
 *
 * B-48：节点名在这里统一唯一化（重名追加 `_2`/`_3`），批量调用时让 `taken` 顺序推进，
 * 否则同批两个同名条目会拿到同一个后缀。
 */
export function appendCleanProxyNodes<T>(
    proxies: CleanProxyEntry[],
    outbounds: T[],
    proxyTags: string[],
    selectorTags: string[],
    build: (proxy: CleanProxyEntry, tag: string) => T
): void {
    for (const proxy of proxies) {
        const tag = uniqueNodeName(cleanProxyRemark(proxy), selectorTags);
        outbounds.push(build(proxy, tag));
        proxyTags.push(tag);
        selectorTags.push(tag);
    }
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

/** 地址对应的端口列表：该地址有显式端口时用它，否则回退到全局端口列表。
 *  订阅生成的三端（Clash / sing-box / Xray）与 Raw 链接共用这一条取值规则。 */
export function portsForHost(
    entryPortMap: Record<string, number[]>,
    host: string,
    fallbackPorts: number[],
    /**
     * B-52 补口：只保留 HTTPS 端口。
     *
     * 分片订阅（`/sub/fragment/*`）只允许 TLS 节点，调用点已把全局端口列表过滤成 TLS-only，
     * 但 `entryPortMap` 是「条目自带显式端口」的旁路 —— 它对同一个 host 直接返回条目里写的端口，
     * 绕过那次过滤。而该表由 `cleanIPs + customCdnAddrs` **一起**建：只要任一清单里出现
     * `cdn.example.com:80`，另一个清单里的同一个 `cdn.example.com` 也会被判成「只有 80 端口」，
     * 明文端口节点就会混进分片订阅。故过滤必须作用在这里，而不是只筛条目本身。
     *
     * 过滤后为空（该 host 只在明文端口上出现过）→ 退回 `fallbackPorts`（调用点已按需过滤）。
     */
    tlsOnly = false
): number[] {
    const explicit = entryPortMap[host];
    if (!explicit?.length) return fallbackPorts;
    if (!tlsOnly) return explicit;
    const tlsPorts = explicit.filter(isHttps);
    return tlsPorts.length ? tlsPorts : fallbackPorts;
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

    // B-14：**代理条目**（`socks5://user:pass@host:port`、`vless://uuid@host:port` 等）不能按
    // 裸地址口径算键。原写法对 `socks5://user:pass@1.1.1.1:1080` 会把 `@` 当凭据分隔符、
    // `lastIndexOf(':')` 落在 user 与 pass 之间，得到 `socks5://user:pass` —— 于是
    // 「同 scheme 同凭据、不同主机」的条目全部塌缩成一个键，第二条起被静默丢弃
    // （表现为订阅里只剩第一个 socks/http 代理节点）。
    // 这里按 scheme 分流：scheme 统一小写，其余部分逐字保留（不能整体 toLowerCase，那会抹平口令大小写）。
    const scheme = noComment.match(/^([a-z0-9+.-]+):\/\//i);
    if (scheme) return `proxy:${scheme[1].toLowerCase()}://${noComment.slice(scheme[0].length)}`;

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
                    // B-53：过期也先收进内存当**兜底**（下面抓取失败时会用到）。
                    // 原实现只在未过期时 set，于是「列表 URL 临时不可达」会让该 URL 展开出的
                    // 全部节点直接从订阅里消失，且没有任何日志。
                    urlCacheMap.set(url, parsed.lines);
                    if (Date.now() - parsed.ts < URL_RESOLVE_TTL) return;
                }
            } catch {}
        }

        // 缓存未命中或过期，并发发起网络请求
        try {
            const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
            if (!res.ok) {
                console.warn(`[地址列表] ${url} 返回 ${res.status}，沿用上次解析结果（若有）`);
                return;
            }
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
        } catch (error) {
            // B-53：抓取失败必须留痕。节点静默消失是最难排查的一类故障。
            console.warn(`[地址列表] 解析 ${url} 失败，沿用上次解析结果（若有）：${safeErrorMessage(error)}`);
        }
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
//   于是本文件 dohQueryRaw 里 response.json() 直接抛错 → 该源被吞成 []（不贡献答案），
//   **第二源从未生效**（.william TXT 的 Google 兜底同理，一直是死代码）。
//   但 dohAnswersDual 是「先 CF 后 Google，取第一个非空」，而 CF_DOH 这个 JSON DoH 端点本身可用
//   （Cloudflare 官方文档的 dns-json 用法），所以生产上 A/AAAA 一直由 CF 提供：本改动只是**补回
//   冗余**（CF DoH 取不到 / 被墙时还有 AAAA 来源），IPv6 症状的根因在
//   protocols/websocket/common.ts#connectWithDirectRaceDial 丢掉 AAAA。
//   代价（须知）：dohAnswersDual 用 Promise.all 会等**两个源都返回**，改前死源是快速 400
//   失败，改后若某机房到 dns.google 不通，每个记录类型最多多等一次 AbortSignal.timeout(10s)；
//   该源是必要的冗余，但若想彻底零风险可只保留 CF 单源。
//   正确值与 cfnew 一致（cfnew L193 `https://dns.google/resolve`）。
//   /resolve 实测：`https://dns.google/resolve?name=ipv6.test-ipv6.com&type=AAAA`
//   → {"Status":0,...,"Answer":[{"type":28,"data":"2400:8905::2000:6bff:fe22:d426"}]}，字段形状与 CF 一致。
const GOOGLE_DOH = 'https://dns.google/resolve';

// ── DoH 结果缓存（**唯一一份**：原始 Answer）──
// 为什么要有：一次请求里同一个域名会被解析**多次** —— 订阅生成先由 getConfigItems 解析节点域名，
// sing-box 的 DNS 构建（resolveNodeIPs）再解析一次同一个域名；目标分类（isCloudflareTarget）
// 与直连竞速（resolveTargetDNS）也各要一次；反代池解析（A/AAAA/TXT）同样走 DoH。
// 没有缓存时这些是多次真实往返，而单次 DoH 的上限是 AbortSignal.timeout(10s) ——
// 重复解析会把 DNS 阶段的耗时上界成倍放大。
//
// 为什么只存**原始 Answer**、且只留一份：两个消费方要的形状不同 ——
//   · resolveDNS 要「按记录类型过滤后的 v4/v6 字符串」（下面 answersToRecords 投影）；
//   · 反代池要整份 Answer（TXT 前缀展开、v6 加方括号、域名回退等都在它那边做）。
// 原先各存一个 Map（解析结果 / 原始记录），同一域名在两处各打一轮 DoH，两套空结果 TTL 还得
// 各自维护；现在只缓存上游应答本身，形状差异由调用点投影 ——
// 顺带让「反代池域名」与「目标域名」偶发相同时也只解析一次。
//
// TTL：有结果 10 分钟、空结果 30 秒（空结果给短 TTL 是为了上游「刚发布记录」时能快速恢复）。
const DOH_CACHE_TTL = 10 * 60 * 1000;   // 有结果 10min
const DOH_CACHE_EMPTY_TTL = 30 * 1000;  // 空结果 30s
const DOH_CACHE_MAX = 200;
const _dohAnswerCache = new Map<string, { answers: any[]; time: number; empty: boolean }>();

/** 查询类型 → Answer 里的数字记录类型。只用于判「这一种记录确实没有」——
 *  注意**不能**用 `answers.length === 0` 代替：A 应答里常带 CNAME（type 5），此时
 *  「应答非空但没有 A」与「上游暂时答不出来」必须区分开，否则后者会被当成有结果缓存 10 分钟，
 *  与「空结果只缓存 30s、让上游刚发布的记录能快速生效」的口径冲突。 */
const DNS_TYPE_CODE: Record<string, number> = { A: 1, AAAA: 28, TXT: 16 };

/**
 * 单源原始 Answer（RFC 8484 的 /resolve 风格：accept: application/dns-json）。
 *
 * **DoH 的最底层，也是唯一一处 fetch**：网络错误 / HTTP 错误 / JSON 解析失败一律吞成 [] ——
 * 「两个源都失败」与「上游确实没有记录」在这里同形，区别只体现在缓存期限上（空结果 30s，
 * 见 dohAnswersCached）。`dohUrl` 必填：唯一保留「裸单源」语义的地方是 `.william` TXT 的 Google 兜底。
 */
async function dohQueryRaw(domain: string, type: string, dohUrl: string): Promise<any[]> {
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

/**
 * 双源原始 Answer：CF ‖ Google 并发，取**第一个非空**的结果；两个源都空 → []。**DoH 的唯一出站口**
 * （resolveDNS 与反代池解析都从这里取数）。
 *
 * 用 `Promise.all` 等**两个源都结束**，而不是 `Promise.any` 提前返回：CF 优先取用，但慢源只在
 * 「CF 没给出结果」时才真正被需要 —— 提前丢弃它等于把补回的第二源又扔了。
 */
async function dohAnswersDual(domain: string, type: string): Promise<any[]> {
    const [fromCf, fromGoogle] = await Promise.all([
        dohQueryRaw(domain, type, CF_DOH),
        dohQueryRaw(domain, type, GOOGLE_DOH),
    ]);
    return fromCf.length ? fromCf : fromGoogle;
}

/**
 * 带缓存的原始 Answer：`resolveDNS`（节点/目标域名）与反代池解析（A/AAAA/TXT）共用。
 * 键含查询类型（A 与 AAAA 的应答形状不同，不能互相顶替）；域名统一小写（DNS 名大小写不敏感，
 * 否则同一域名换种写法就多存一份）。命中即刷新 LRU 顺序。
 */
async function dohAnswersCached(domain: string, type: string): Promise<any[]> {
    const cacheKey = `${domain.toLowerCase()}|${type}`;
    const cached = _dohAnswerCache.get(cacheKey);
    const effectiveTTL = cached?.empty ? DOH_CACHE_EMPTY_TTL : DOH_CACHE_TTL;
    if (cached && Date.now() - cached.time < effectiveTTL) {
        _dohAnswerCache.delete(cacheKey);   // 命中即刷新 LRU 顺序
        _dohAnswerCache.set(cacheKey, cached);
        return cached.answers;
    }
    if (cached) _dohAnswerCache.delete(cacheKey);

    const answers = await dohAnswersDual(domain, type);
    // 「空」按**查询类型**判（只带 CNAME 的 A 应答也算空），空结果只留 30s（见 DNS_TYPE_CODE）
    const empty = answersToRecords(answers, DNS_TYPE_CODE[type] ?? -1).length === 0;
    _dohAnswerCache.set(cacheKey, { answers, time: Date.now(), empty });

    // 先按绝对 TTL 清过期项，再按 LRU 兜住容量（与反代池缓存同一套）
    if (_dohAnswerCache.size > DOH_CACHE_MAX) {
        const now = Date.now();
        for (const [key, value] of _dohAnswerCache) {
            if (now - value.time >= DOH_CACHE_TTL) _dohAnswerCache.delete(key);
        }
        evictOldest(_dohAnswerCache, DOH_CACHE_MAX);
    }

    return answers;
}

/** Answer → 指定记录类型的字符串列表：CNAME（type 5）与其它无关记录一律丢弃。
 *  `resolveDNS` 投影 v4/v6、`dohAnswersCached` 判空、反代池取 A/AAAA/TXT 都走它 ——
 *  「按类型筛 + 取 data」这一句只保留这一份实现。 */
function answersToRecords(answers: any[], recordType: number): string[] {
    return answers
        .filter((record: any) => record.type === recordType)
        .map((record: any) => record.data);
}

/**
 * 解析域名的 A / AAAA（`onlyIPv4` 时只查 A）。
 *
 * 两个源都不通时返回**空结果**而不是抛错：这条路径上的调用方本来就按「解析不出来」处理
 * （prefix 模式缺 IPv4、直连池空池都各自给精确错误），空结果也只在缓存里停留 30 秒；
 * 原先那层 `throw new Error('Error resolving DNS …')` 从未真正触发过（双源查询把所有拒绝
 * 都吞成 []），留着只会让调用方误以为这里会抛。
 */
export async function resolveDNS(domain: string, onlyIPv4 = false): Promise<DnsResult> {
    const ipv4 = answersToRecords(await dohAnswersCached(domain, 'A'), DNS_TYPE_CODE.A);
    const ipv6 = onlyIPv4 ? [] : answersToRecords(await dohAnswersCached(domain, 'AAAA'), DNS_TYPE_CODE.AAAA);
    return { ipv4, ipv6 };
}

export function getProtocols() {
    const {
        settings: { VLConfigs, TRConfigs },
        dict: { _VL_, _TR_ }
    } = globalThis;

    return concatIf(concatIf([], VLConfigs, _VL_), TRConfigs, _TR_);
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

/** 备注/节点名的键：同一 (地址, 端口) 的 VLESS 与 XHTTP 变体共用基准名（B-48/XHTTP 复用） */
export function remarkKeyOf(host: string, port: number): string {
    return `${host}\u0000${port}`;
}

/** R-08：XHTTP 第二趟遍历的产物 —— 各端只需按自己的结构渲染 */

export interface XpNodePlan {
    host: string;
    port: number;
    /** 节点名（`<基准名> XHTTP`，基准名优先复用同地址 VLESS 节点的备注） */
    tag: string;
    /** 与 WS 节点共用 usedPaths 抽出的伪装路径 */
    path: string;
}

/**
 * R-08：XHTTP 节点枚举（三端第二趟遍历的唯一实现）。
 *
 * 三端（xray / sing-box / clash）此前各有一份近乎逐行相同的循环：跳过代理条目 → 按
 * `portsForHost` 展开端口 → 套用与 WS 节点相同的上游代理排除规则 → 复用/现取基准备注 →
 * 追加 ` XHTTP` 后缀 → 用 `buildXpNodePath` 抽路径。差异只在「最后怎么渲染」。
 *
 * 为什么必须是第二趟、且必须复用 `vlRemarks`：
 * `generateRemark` 的计数是全局递增的。若把 XHTTP 节点插进主循环，会把后续 WS / 链式节点的
 * 备注编号整体顶后一位，违反「既有节点输出逐字不变」。本函数因此**只做枚举**，
 * 且基准名优先复用主循环已生成的备注；只有在 VLESS 被关掉、该键没有记录时才现取一次
 * （此时兜底发生在主循环之后，仍不影响既有编号）。
 *
 * @param vlRemarks 主循环记录的「(地址,端口) → VLESS 备注」表
 * @param nextPath  路径生成器（各端传 `() => buildXpNodePath(randomPath, usedPaths)`）。
 *                  以回调形式传入而非在 @utils 内实现：`buildXpNodePath` 住在 `@cores/xp`，
 *                  而 xp.ts 已 import @utils —— 反向依赖会形成循环。回调按**枚举顺序**逐条调用，
 *                  因此 usedPaths 的消耗顺序与逐端手写循环时完全一致。
 */
export function enumerateXpNodes(options: {
    items: ConfigItem[];
    entryPortMap: Record<string, number[]>;
    ports: number[];
    vlRemarks: Map<string, string>;
    upstreamServer?: string;
    upstreamPort?: number;
    isFragment: boolean;
    nextPath: () => string;
}): XpNodePlan[] {
    const {
        items, entryPortMap, ports, vlRemarks,
        upstreamServer, upstreamPort, isFragment, nextPath
    } = options;

    const plans: XpNodePlan[] = [];

    for (const item of items) {
        // 代理条目有自己的协议与出站，不派生 XHTTP 变体
        if (item.kind !== 'address') continue;

        const host = item.value;
        const addrPorts = portsForHost(entryPortMap, host, ports);

        for (const port of addrPorts) {
            // 与 WS 节点同一条上游代理排除规则，避免上游条目派生出重复的独立节点
            if ((port === upstreamPort) !== (host === upstreamServer)) continue;

            const baseRemark = vlRemarks.get(remarkKeyOf(host, port))
                ?? generateRemark(port, host, globalThis.dict._VL_, isFragment, false);

            plans.push({
                host,
                port,
                tag: `${baseRemark} XHTTP`,
                // 与 WS 节点共用 usedPaths：同一次生成内两种传输的路径互不相同
                path: nextPath()
            });
        }
    }

    return plans;
}

/**
 * 把上游代理条目并入节点序列（订阅生成入口共用）：
 * 端口插到端口列表最前，地址插到节点序列最前，保证上游节点优先输出。
 * `skip` 供分片订阅使用（分片只含 TLS 节点，不并入明文上游条目）。
 */
export function prependUpstreamItem(items: ConfigItem[], ports: number[], skip = false): void {
    const { upstreamParams: { upstreamServer, upstreamPort } } = globalThis.settings;
    if (skip || !upstreamServer || !upstreamPort) return;
    ports.unshift(upstreamPort);
    items.unshift({ kind: 'address', value: upstreamServer });
}

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

    // 对 DNS 解析出的 IP 做可达性探测，过滤不可达地址（两族并行：探测内部各自按 3 条滚动窗口
    // 限流，所以两族同时跑时峰值是 2 × 3 = 6 —— 与运行时「单请求并发出站连接」配额同量级，
    // 属于刻意接受的边界：订阅生成是低频的人机交互，优先让两族同时出结果，而不是把耗时翻倍。
    // 每条 filter 调用另有 PROBE_PHASE_BUDGET_MS(2s) 总预算：主机名解析出的 IP 多于窗口时，
    // 超出预算的候选按 'unknown' 保留（不判死），所以这里不会因为「没测完」而少给 IP。
    // 空数组不需要三元 + `Promise.resolve([] as string[])` 那种类型兼容写法：filterReachableIPs
    // 对空输入本来就返回 []（不发起任何连接），直接传进去语义等价。
    const [reachableIPv4, reachableIPv6] = await Promise.all([
        filterReachableIPs(ipv4),
        filterReachableIPs(ipv6),
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
    // customCdnAddrs 仍只作地址（既有语义不变），代理写法在 entryAddresses 里被跳过。
    // B-52：分片订阅此前整段丢弃 customCdnAddrs（`if (!isFragment)` 一行），于是
    // /sub/fragment/*（xray 与 sing-box 各有入口）比普通订阅**整整少一段节点**。
    // 不能只把这个判断删掉了事：分片订阅只保留 TLS 端口（各端 configs 的
    // `ports.filter(port => !isFragment || isHttps(port))`），而 portsForHost 对
    // 「条目自带显式端口」的地址**不走**那条过滤（它直接返回 entryPortMap 的端口表），
    // 于是放开后 `x.com:80` 这类明文端口节点会混进分片订阅。
    // 正确做法是在**本函数**按条目自带端口逐条筛：显式端口必须是 HTTPS 端口；
    // 没写端口的条目继承全局端口列表，而全局列表在调用点已被 totalPorts 过滤成 TLS-only。
    if (isFragment) {
        for (const entry of customCdnAddrs) {
            if (parseCleanProxy(entry)) continue;   // 与 entryAddresses 同规则：代理条目不是地址
            const port = entryPort(entry);
            if (port && !isHttps(port)) continue;   // 显式明文端口 → 不进分片订阅
            pushAddress(entryAddress(entry));
            // 取舍：customCdnAddrs 是 selectSniHost 里 allowInsecure 的唯一触发源，
            // 并入这些地址即「分片订阅与普通订阅对同一地址给出同一 TLS 判据」——
            // 这是修复前不可能成立的一致性（分片侧根本没有这些节点）。
        }
    } else {
        entryAddresses(customCdnAddrs).forEach(pushAddress);
    }

    return items;
}

// D-02：无原型对象 —— 备注可能是 `constructor` / `toString` 这类原型键，普通 `{}` 会让`+1` 落进函数对象。
const remarkCounter: Record<string, number> = Object.create(null);

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
 *
 * 面板「节点随机路径」（settings.randomPath）关闭时直接返回根路径 `/`，不参与 `used`：
 * 此时所有节点共用同一条路径是有意为之（旧订阅的 `/?ed=…` 形态），刷新订阅路径不再变化。
 */
export function generateWsPath(used?: Set<string>): string {
    // 面板「节点随机路径」关闭：所有节点共用根路径 `/`（旧订阅的 `/?ed=…` 形态）。
    // worker 的 WS 升级守卫本就放行空段路径（`wsSegments.length === 0`），无需额外特例。
    if (globalThis.settings?.randomPath === false) return '/';

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

/**
 * xPadding 抗指纹标识：从 UUID 派生隐蔽的头名/键名（对齐 cfnew 获取叉HTTP填充标识）。
 * 订阅侧（raw URI / xray JSON 的 extra）与服务端（WS 入站、XHTTP 入站）必须用同一份派生规则，
 * 因此单独收敛到这里（@unified 仍保留同名再导出，避免既有 import 失效）。
 * 注意：服务端只用它识别/记录语义，**不回写**该头（回写会把 UUID 的 12 个 hex 字符泄露给未认证调用方）。
 */
export function getXPaddingIdentifier(uuid: string): { header: string; key: string } {
    return { header: uuid.slice(1, 7), key: '_' + uuid.slice(25, 31) };
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

/**
 * R-04：节点 TLS 上下文的**判据对象**（host / sni / isTLS / allowInsecure / ECH 名 / alpn）。
 *
 * 只产出判据，不产出配置：三端（Xray / sing-box / Clash）各自的渲染差异留在各自的
 * build* 函数里（xray 的 tlsSettings、sing-box 的 tls 块、Clash 的 tls 字段），判据只有这一套。
 *
 * 判据要点（三端必须逐条一致）：
 *  1. `isTLS` 由 #isTlsPort 决定：显式端口表里出现过该端口即按 TLS 处理，否则同一节点会出现
 *     URI 写 security=tls、配置写 none 的自相矛盾组合。
 *  2. 随机抽取顺序固定为「先 hostSniList，再 echServerName」：它决定同一份订阅里 SNI 与 ECH 名的
 *     配对。⚠️ 一次性漂移（须知）：本轮把 sing-box 从「先抽 ech 名」对齐到「host 先抽」，
 *     分布不变、但同一份订阅的 SNI/ECH 配对会与旧版本不同 —— 这是有意为之，**不是 bug**，
 *     下一轮不要把它「改回去」。
 *  3. ECH 名名单为空时回退到本节点 host（`pickRandomEch(echServerName) || host`），与
 *     handlers.ts#buildConfig（URI 侧）的同一表达式逐字一致（B-43）。
 *  4. alpn 恒取自前端 ALPN 设置（settings.alpn），**不**因启用 ECH 而抑制：ECH 与 alpn 是两个
 *     独立开关，面板上设了什么就下发什么。三端 JSON 与 URI 侧（handlers.ts#buildConfig）同源同值。
 *  5. `allowInsecure` 只来自 #selectSniHost（地址命中 customCdnAddrs），三端同源同值。
 *
 * `isFragment` 只影响 ECH（分片节点不启用）；Clash 无分片订阅，恒传 false。
 */
export interface NodeTlsCriterion {
    /** selectSniHost 给出的 Host 头值（同时用作 wsSettings / xhttpSettings 的 host） */
    host: string;
    /** TLS 的 serverName（= 节点 SNI） */
    sni: string;
    /** 该 (地址, 端口) 是否按 TLS 处理 */
    isTLS: boolean;
    /** 是否跳过证书校验（仅 customCdnAddrs 命中的地址为 true） */
    allowInsecure: boolean;
    /** 本节点的 ECH 名；undefined = 本节点不启用 ECH */
    echName?: string;
    /** 本节点要下发的 alpn 档位（= 前端 settings.alpn，判据第 4 条） */
    alpn?: string;
}

export function resolveNodeTls(address: string, port: number, isFragment: boolean): NodeTlsCriterion {
    const {
        settings: { alpn, enableECH, echServerName, hostSniList }
    } = globalThis;

    const isTLS = isTlsPort(port, address);
    const { host, sni, allowInsecure } = selectSniHost(address, pickRandomEch(hostSniList));
    const echName = enableECH && !isFragment ? (pickRandomEch(echServerName) || host) : undefined;

    return {
        host,
        sni,
        isTLS,
        allowInsecure,
        echName,
        alpn: alpn || undefined
    };
}

/**
 * R-05：传输层 path 的**唯一预处理判据**（tcp/raw、ws、httpupgrade、grpc 四种分支共用）。
 *
 * 只取首个 `?` 之前的部分：
 *  - B-50 的成因就是这里 —— outProxy 的 `?ed=` 若原样写进 wsSettings.path / ws-opts.path，
 *    客户端会把整串当成 WS 请求路径，节点连不上；early-data 阈值另有 maxEarlyData /
 *    max-early-data 字段承载。
 *  - 普通节点（generateWsPath / buildXpNodePath）的 path 不含 query → 输出逐字不变。
 *  - 判据与传输类型无关（四种分支都无条件剥 query），故签名不带 type：带上只会让人误以为
 *    某些传输被豁免，而三家实际上都不豁免。
 */
export function normalizeTransportPath(path: string = "/"): string {
    return path?.split("?")[0];
}

/**
 * R-05b：WS early-data 的协议头名与「有值才写」判据。
 *
 * 这条判据原先在 6 处重复（xray 的 ws / modifyOutbound、sing-box 的 ws / 链式重抽、
 * clash 的 ws / 链式重抽），且都以 `earlyData ? "Sec-WebSocket-Protocol" : undefined` 的
 * 字面量三元式出现 —— 三端必须完全一致（否则同一份订阅里一种客户端带 early-data、另一种不带）。
 * 值本身也进了三份 .d.ts 的字面量类型，故这里用 `typeof` 保持字面量类型不丢。
 */
const EARLY_DATA_HEADER_NAME = "Sec-WebSocket-Protocol";

/**
 * R-05b：WS early-data 的协议头名与「有值才写」判据（**唯一导出形式**）。
 *
 * 这条判据原先在 6 处重复（xray 的 ws / modifyOutbound、sing-box 的 ws / 链式重抽、
 * clash 的 ws / 链式重抽），且都以 `earlyData ? "Sec-WebSocket-Protocol" : undefined` 的
 * 字面量三元式出现 —— 三端必须完全一致（否则同一份订阅里一种客户端带 early-data、另一种不带）。
 * 常量本身不导出：调用点一律传「已确定的 early-data 值」，让「值」与「是否写头」只有一个判断入口。
 * 返回值保持字面量类型（三份 .d.ts 里该字段就是该字面量），故用 `typeof`。
 */
export function earlyDataHeaderName(earlyData?: number): typeof EARLY_DATA_HEADER_NAME | undefined {
    return earlyData ? EARLY_DATA_HEADER_NAME : undefined;
}

/**
 * R-06：链式克隆体的 early-data 取值（**唯一判据**）。
 *
 * 两条规则原先在 sing-box 与 clash 各写一遍（连注释都同义）：
 *  1. 用户的显式 `ed` 优先，且**只由调用点传给第一个克隆体**（原型不出现在输出里，
 *     不显式传下来就等于静默丢弃用户配置）；
 *  2. 否则从共享 `usedEds` 池无放回抽取 —— `pickEarlyData` 自身会写入池，
 *     但显式值这条路不会，故这里补一次注册，保证同批节点的 ed 仍然两两不同。
 *
 * 返回的阈值由调用方按自己的 schema 落字段（`max_early_data` / `ws-opts["max-early-data"]`）；
 * 「只有 ws 传输才需要」这个前置判断也留在各端（xray 的字段名、clash 的 http-upgrade 判据都不同）。
 */
export function resolveChainEarlyData(usedEds: Set<number> | undefined, explicitEd?: number): number {
    const earlyData = explicitEd ?? pickEarlyData(usedEds);
    if (usedEds && !usedEds.has(earlyData)) usedEds.add(earlyData);
    return earlyData;
}

/**
 * R-06 / B-50：链式出站显式 early-data（outProxy 的 `ed`）的**唯一判据**。
 *
 * 取值来源按 outProxy 形态分流，两个来源互斥：
 *  1) VLESS / Trojan / SS —— kv.ts#extractProxyParams 把 URI 的 query **原样并入** outProxyParams，
 *     故 `ed` 直接读字段即可（不再重解析一遍 URI query，等价且少一次 `new URL` 的抛错面）。
 *  2) VMess（B-50）—— outProxy 是整段 base64（`vmess://<base64>`），`new URL()` 的 search 恒为空，
 *     `ed` 只能藏在 base64 里 JSON 的 `path` 字段（ws 传输的 path 可带 `?ed=`）。
 *     此时 `path` 会被 #normalizeTransportPath 剥掉 query，故 ed 不会漏进 ws 路径，只进 early-data 阈值。
 *
 * 显式值是用户自己写的配置，原样沿用，不做 2048..2560 区间钳制（可能超出，保持既有行为）；
 * 缺失 / 非数值一律返回 undefined（由调用点从 usedEds 池无放回抽取），绝不抛错。
 */
export function getChainExplicitEarlyData(): number | undefined {
    const { outProxyParams } = globalThis.settings;

    // ① query 形态（VLESS / Trojan / SS）：kv 侧已把 `?ed=` 并进同一个对象
    const fromQuery = outProxyParams?.ed;
    if (fromQuery !== undefined && fromQuery !== null && fromQuery !== "" && Number.isFinite(+fromQuery)) {
        return +fromQuery;
    }

    // ② VMess base64 形态（B-50）：ed 藏在 JSON 的 path 字段里
    if (outProxyParams?.protocol === globalThis.dict._VM_) {
        const match = /[?&]ed=([^&#]*)/.exec(outProxyParams.path ?? "");
        if (match && match[1] !== "" && Number.isFinite(+match[1])) return +match[1];
    }

    return undefined;
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

/**
 * 订阅节点端口是否按 TLS 处理（URI 侧与 Clash/sing-box/Xray 三端 JSON 出站共用同一判据）。
 * 任一地址的显式端口表里出现过该端口也视为 TLS，否则同一节点会出现
 * URI 写 security=tls、JSON 写 none 的自相矛盾组合。
 * entryPortMap 只依赖 globalThis.settings，默认按调用求值（请求内局部量，无模块级状态）；
 * 已持有同一映射的调用方可直接传入，避免重复构建。
 */
export function isTlsPort(
    port: number,
    address: string,
    entryPortMap: Record<string, number[]> = buildEntryPortMap()
): boolean {
    const { upstreamParams: { upstreamServer } } = globalThis.settings;
    return isHttps(port) || address === upstreamServer || Object.values(entryPortMap).some(ports => ports.includes(port));
}

/**
 * 制裁域名的 DoH 端点派生（Clash / sing-box / Xray 三端同一口径）：
 * 输入已带 https:// → 直接作为完整 DoH 端点，无明文兜底；
 * 否则拼 `https://<输入>/dns-query`，原输入地址保留作明文兜底。
 * 裸 IPv6 必须加方括号，否则拼出的 URL 不是合法地址（三端都会启动/加载失败）。
 */
export function antiSanctionDohTarget(antiSanctionDNS: string): {
    dohUrl: string;
    plainFallback?: string;
} {
    const isDohUrl = /^https:\/\//i.test(antiSanctionDNS);
    const host = isIPv6(antiSanctionDNS) && !antiSanctionDNS.startsWith('[')
        ? `[${antiSanctionDNS}]`
        : antiSanctionDNS;
    return {
        dohUrl: isDohUrl ? antiSanctionDNS : `https://${host}/dns-query`,
        plainFallback: isDohUrl ? undefined : antiSanctionDNS
    };
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

/**
 * R-13：条件拼接（原 `Array.prototype.concatIf`）。
 *
 * 原实现直接给 `Array.prototype` 赋值，是**可枚举**的原型属性：任何 `for...in` 遍历
 * （本仓目前没有，但产物里还打包了第三方代码，属于「引入即静默」的一类污染）
 * 都会把 `concatIf` 当成数组的一个键。改成普通函数后语义不变，调用点显式传入数组。
 */
export function concatIf<T>(base: T[], condition: boolean, concat: T | T[]): T[] {
    if (!condition) return base;
    return Array.isArray(concat) ? [...base, ...concat] : [...base, concat];
}

/**
 * R-13：空对象/空数组 → undefined（原 `Object.prototype.omitEmpty`）。
 *
 * 同上：`Object.prototype` 上的可枚举属性会出现在**任何**对象的 `for...in` 里。
 * 语义保持逐字一致（`Object.keys([]).length === 0`，故空数组同样返回 undefined ——
 * 这是既有行为，多个调用点依赖它来省略空的 hosts / endpoints 字段）。
 */
export function omitEmpty<T extends object>(value: T): T | undefined {
    return Object.keys(value).length === 0 ? undefined : value;
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

/**
 * 单 IP 探测超时 2 秒。
 * 比竞速拨号的 PROXY_DIAL_TIMEOUT(5s) **更严** —— 探测只负责筛掉明显不可达的候选，
 * 所以「探测判死」不等于「拨号一定连不上」：这正是 connectWithRaceDial 里 allProbeFailed 例外
 * （全部探测失败时不记退避、照常拨号）存在的原因。
 * 反面代价：黑洞候选在第一次遇到时要白等满 2 秒，之后进黑名单退避。
 * 整批耗时不靠「n × 本值」推导 —— 它由下方的 PROBE_PHASE_BUDGET_MS 封顶。
 */
const PROBE_TIMEOUT = 2000;
/**
 * 探测并发上限。**必须和竞速拨号同量级**（那里是 3）：探测是单请求里唯一会成批开出站 TCP
 * 的地方，而运行时对单请求的并发出站连接有配额（约 6 条）—— 一次把全部抽取候选（6 条，
 * 改动前是 8 条）发出去，超出配额的候选会被运行时**直接拒绝**，那不是「候选不通」，
 * 是被自己的探测并发拖累的假失败；而调用方（反代池）会把探测不通的候选记进黑名单
 * （30s 起指数退避），假失败于是连锁误杀好候选。
 * 改成滚动窗口后，**单个 filter 调用内**峰值在飞恒 ≤ 3（订阅生成路径两族并行时是 2 × 3 = 6，
 * 见 getConfigItems 的说明 —— 那是刻意接受的边界，不是这里的疏漏）。这条误判链从根上断掉了，
 * 不需要在「哪些失败该退避」上做区分。
 * 回归钉：tools/proxy-pool-draw.test.mjs 钉两条 —— 事件序列开头连续 3 个 start（窗口宽度）、
 * 全程在飞峰值 ≤ 4（窗口 3 + 反代池探测期间抢跑的那 1 条预热拨号；回到「一次性全发」立刻变 6）。
 */
const PROBE_CONCURRENCY = 3;

/**
 * 探测阶段的**总预算**（毫秒）：整批探测最多占这么久。
 *
 * 与 PROBE_TIMEOUT 分工不同：单条超时决定「一个候选多久判死」，总预算决定「整批最多占用多久」。
 * 为什么必须有总预算：这段耗时**整段落在首包之前**（竞速拨号要等探测结束才开始），而滚动窗口
 * 的天然上界是 ceil(n / PROBE_CONCURRENCY) × PROBE_TIMEOUT —— 反代池 n = 6、窗口 3 → 两波 = 4s，
 * 比「一次性全发」（8 条一波 = 2s）把最坏建连时延整整拉长一倍。预算取 2000 = 一波满窗：
 *   - 候选够快（常态）：两波都在预算内跑完，逐条结论与「不限预算」完全一致；
 *   - 第一波全黑洞：第二波拿不到预算 → 那几条按 unknown 处理，拨号照常立刻开始。
 *
 * unknown 的语义是**「没有结论」**，既不算通也不算不通：
 *   - **不**记黑名单 —— 那正是「假失败连锁误杀好候选」要防的事；
 *   - 仍留在拨号集合里 —— 与 connectWithRaceDial 的 allProbeFailed 同一取向（连通性优先）。
 *
 * 导出（而不仅是模块内常量）：WS 侧的 `WARM_DIAL_TIMEOUT` 直接取本值 —— 「预热拨号的抢跑窗口」
 * 与「它要抢在谁之前的探测预算」在语义上就应该是同一个数，写两处字面量迟早悄悄分叉。
 */
export const PROBE_PHASE_BUDGET_MS = 2000;

/**
 * 剩余预算低于它就不再发起新探测：只跑得满「半个单条超时」的探测拿不到可信结论 ——
 * 发起它既要白开一个 socket，判死时还会把好候选记进 30s 起指数退避的黑名单（误判链见上）。
 */
const PROBE_MIN_LAUNCH_MS = PROBE_TIMEOUT / 2;

/** 单条探测的结论：true / false 是可信结论，'unknown' = 预算内没轮到它（未发起、零 socket） */
type ProbeVerdict = boolean | 'unknown';

/** 滚动窗口并发 map：最多 `concurrency` 条同时在飞，任何一条 settle 立刻补位。
 *  刻意不用「分块 Promise.all」：滚动窗口下快候选不必等慢候选那一整批结束
 *  （6 条里 4 条 3ms 通、2 条黑洞时，分块模式要等满一个探测超时才能开始第二批）。
 *  ⚠️ 滚动窗口本身**不封顶**总耗时（最坏是 ceil(n/3) × PROBE_TIMEOUT，6 条 = 两波 = 4s）。
 *  这个上界由调用方 probeWithinBudget 的 PROBE_PHASE_BUDGET_MS 直接压到 2s ——
 *  所以这里的并发度只决定「一批里能并行几条」，不再决定「整批能拖多久」。 */
async function mapWithConcurrency<T, R>(
    items: T[],
    concurrency: number,
    worker: (item: T) => Promise<R>
): Promise<R[]> {
    const results = new Array<R>(items.length);
    const limit = Math.max(1, Math.min(concurrency, items.length));
    let next = 0;
    // limit 条 runner 共享一个取号游标：同步启动 → 同一 tick 内先发出前 limit 条连接
    const runner = async (): Promise<void> => {
        while (next < items.length) {
            const index = next++;
            results[index] = await worker(items[index]);
        }
    };
    await Promise.all(Array.from({ length: limit }, runner));
    return results;
}

/**
 * 在总预算内对 items 做滚动窗口探测，返回**与 items 等长同序**的结论。
 *
 * 唯一实现：反代池（filterReachableEntries）与订阅侧 IP 过滤（filterReachableIPs）共用，
 * 避免两个调用点各写一套「预算 / 单条超时 / unknown 判据」而口径分叉。
 * 预算用尽后剩下的项一律 'unknown'（**不发起**连接，零 socket、零定时器）。
 * 单条超时取 min(PROBE_TIMEOUT, 剩余预算)：最后一批也必须在预算内收口，否则预算形同虚设。
 */
async function probeWithinBudget<T>(
    items: T[],
    probe: (item: T, timeoutMs: number) => Promise<boolean>
): Promise<Array<{ item: T; verdict: ProbeVerdict }>> {
    const deadline = Date.now() + PROBE_PHASE_BUDGET_MS;
    return await mapWithConcurrency(items, PROBE_CONCURRENCY, async (item): Promise<{ item: T; verdict: ProbeVerdict }> => {
        const remaining = deadline - Date.now();
        if (remaining < PROBE_MIN_LAUNCH_MS) return { item, verdict: 'unknown' };
        const ok = await probe(item, Math.min(PROBE_TIMEOUT, remaining));
        return { item, verdict: ok };
    });
}

/**
 * 结论 → 拨号集合的唯一判据：只剔除**确定不通**（verdict === false）的项，'unknown' 一律保留；
 * 整批都被判死时回退原始列表（空列表会让调用方彻底不可用）。
 * 两个 filter 共用它 —— 它们原先各写了一遍同样的「过滤 + 空则回退」三联表达式。
 */
function dialableFrom<T>(
    outcomes: Array<{ item: T; verdict: ProbeVerdict }>,
    fallback: T[]
): T[] {
    const dialable = outcomes.filter(o => o.verdict !== false).map(o => o.item);
    return dialable.length > 0 ? dialable : fallback;
}

/**
 * 对单个 IP:port 做 TCP 连接探测，返回是否可达。
 *
 * **模块私有**：唯一驱动方是 probeWithinBudget（预算 / 窗口 / 结论口径都在那里）。
 * 不导出、也不给参数默认值 —— 导出去只会诱使别处再写一套「自己算超时、自己判失败」的探测，
 * 把 unknown / 黑名单的口径分叉掉；默认超时则等于悄悄替调用方决定一个预算之外的等待。
 */
async function probeIPReachability(
    hostname: string,
    port: number,
    timeoutMs: number
): Promise<boolean> {
    let socket: Socket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
        // 使用与 connectSocket 相同的懒求值模式，避免被打包器优化掉
        const createdSocket: Socket = (globalThis as any).connect({ hostname, port });
        socket = createdSocket;
        await Promise.race([
            createdSocket.opened,
            // timer.unref 让挂起的超时定时器不阻止请求结束（对齐 F-09 同类修复）
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
                (timer as unknown as { unref?: () => void }).unref?.();
            }),
        ]);
        return true;
    } catch {
        return false;
    } finally {
        if (timer !== undefined) clearTimeout(timer);
        // C-09：超时/异常路径同样关闭 socket —— 原先 close 只在成功路径执行，
        // 不可达候选多时未关闭的 TCP 尝试会在 isolate 内累积。
        try {
            socket?.close();
        } catch {}
    }
}

/**
 * 对 IP 数组做**预算内滚动窗口**探测，返回拨号可用的 IP 子集（保序）。
 * 取舍判据（只剔除确定不通 / 'unknown' 保留 / 全判死则回退原表）统一在 dialableFrom。
 */
export async function filterReachableIPs(
    ips: string[],
    port: number = 443
): Promise<string[]> {
    const outcomes = await probeWithinBudget(ips, (ip, timeoutMs) =>
        probeIPReachability(ip.replace(/^\[|\]$/g, ''), port, timeoutMs)); // 去掉 IPv6 括号
    return dialableFrom(outcomes, ips);
}

/** 对 [host, port] 条目数组做**预算内滚动窗口**探测（每项用自身端口），返回拨号可用条目子集（保序）。
 *  onProbe 可选回调：把每条候选的**可信**探测结论交给调用方 —— 反代池用它把「探测不通」的候选
 *  记进临时黑名单（指数退避），避免同一个死候选每连接都白等满一次探测超时。
 *  'unknown'（预算内没轮到）**不上报**：记成失败就是误杀好候选。
 *  onReachable 可选回调：某条候选**一被测通就立刻**回调（不等整批收口）—— 调用方用它抢跑拨号，
 *  把「等最慢那条探测」的等待从关键路径上摘掉。它可能比本函数的 Promise 更早触发。
 *  探针本身按 PROBE_CONCURRENCY 限流，所以这里的失败是候选自身的结论，不是并发配额打出来的。 */
export async function filterReachableEntries(
    entries: [string, number][],
    onProbe?: (entry: [string, number], ok: boolean) => void,
    onReachable?: (entry: [string, number]) => void
): Promise<[string, number][]> {
    const outcomes = await probeWithinBudget(entries, async (entry, timeoutMs) => {
        // 直接把 entry 透传给 onReachable：不要再拼一个 [ip, port]（同一份数据第二次分配）
        const ok = await probeIPReachability(entry[0].replace(/^\[|\]$/g, ''), entry[1], timeoutMs);
        // 合格即刻上报（不等本批收口）：这是「探测与拨号并行」的唯一触发点
        if (ok) onReachable?.(entry);
        return ok;
    });
    for (const { item, verdict } of outcomes) {
        if (verdict !== 'unknown') onProbe?.(item, verdict);
    }
    return dialableFrom(outcomes, entries);
}

// ── Proxy IP pool resolution cache (对齐 edgetunnel 缓存反代IP 9896) ──
// C-04：缓存键原先只有 proxyIP，且无 TTL → 同一 isolate 内第二个 targetDomain/uuid
// 会拿到为第一个域名洗出的同一份 8 条子集，且首次降级结果被永久冻结。
// 与解析依赖的 DoH 结果缓存同期限（直接引用，避免两处字面量各自漂移）
const PROXY_POOL_CACHE_TTL = DOH_CACHE_TTL;
const PROXY_POOL_CACHE_MAX = 32;             // 键数量上限，防止长生命周期 isolate 中无界增长

/** 反代池缓存诊断日志：仅当面板「Log Level」设为 debug 时输出（与 unified.ts 的 logDebug 同口径）。
 *  一次解析只落一行，按 layer 计数即可算命中率：
 *    L1 hit    —— isolate 内 Map 命中（最热路径，零网络）
 *    L1 stale  —— 有但超过 10min，丢弃后继续往下
 *    inflight  —— 同键已有解析在飞，直接复用
 *    L2 hit    —— Cache API 命中（同一 PoP 其他 isolate 留下的结果）
 *    L2 miss   —— 二级也没有，准备走 DoH
 *    L2 skip   —— 纯 IP 池（官方直连池），解析是内存计算，不碰二级缓存
 *    DoH       —— 真正发了 DNS（ms 是解析耗时） */
function poolCacheLog(message: string): void {
    if (globalThis.settings?.logLevel === 'debug') console.log(`[proxy-pool] ${message}`);
}
/** 模块级缓存：isolate 生命周期内有效（键 = proxyIP|targetDomain|uuid），命中时校验 TTL，超限时按 LRU 淘汰 */
const _proxyPoolCache = new Map<string, { result: [string, number][]; time: number }>();

/**
 * 单飞标记：键 → 「谁正在进行中的解析」。**只存标记，不存 Promise**。
 *
 * 旧实现是 `Map<key, Promise>` 并让并发调用者 await 它。那在 Workers 上会踩
 * `handle_cross_request_promise_resolution`：创建 Promise 的请求先结束（客户端 abort /
 * 连接被关）时它永远无法 settle，后来者 await 直接抛
 * “This promise was created by a request that has since ended”。
 * 现在等待方轮询一级缓存（解析结束时由 resolveProxyPoolUncached 写入），见
 * common.ts 的 crossRequestSingleFlight。
 */
const _proxyPoolLoading = new Set<string>();

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
 * 截断会让被砍掉的候选连一次探测的机会都没有（实测地区池 KR=14、SG/JP/通用=50）。
 * 抽取若干条参与「可达性探测 + 竞速拨号」的职责移到 connectWithRaceDial：那里按临时黑名单
 * 过滤后随机抽取（条数口径见该文件的 RACE_PROBE_COUNT，当前 6）。
 * 三级顺序：一级 isolate 内 Map → 二级 Cache API（同一 PoP 跨 isolate）→ DoH；
 * 同一键的并发调用走单飞，只解析一次。
 * Aligns with edgetunnel `解析地址端口` (9895-10016).
 */
/**
 * 一级缓存条目的新鲜判据。**单一来源**：主路径的「L1 hit/stale」判定与单飞轮询的
 * 「结果是否已落地」判定共用它，避免两处 TTL 比较漂移（一处改了另一处忘改，会出现
 * "主路径认为过期、轮询却认为新鲜"这种难查的分叉）。
 */
function isFreshPoolEntry(entry: { time: number }): boolean {
    return Date.now() - entry.time < PROXY_POOL_CACHE_TTL;
}

export async function resolveProxyIPPool(
    proxyIP: string,
    targetDomain: string,
    uuid: string
): Promise<[string, number][]> {
    const cacheKey = proxyPoolCacheKey(proxyIP, targetDomain, uuid);
    const cachedPool = _proxyPoolCache.get(cacheKey);
    if (cachedPool && isFreshPoolEntry(cachedPool)) {
        // 命中即刷新 LRU 顺序，保证淘汰的是最久未用的键
        _proxyPoolCache.delete(cacheKey);
        _proxyPoolCache.set(cacheKey, cachedPool);
        poolCacheLog(`L1 hit target=${targetDomain} age=${Math.round((Date.now() - cachedPool.time) / 1000)}s n=${cachedPool.result.length}`);
        return cachedPool.result;
    }
    if (cachedPool) {
        poolCacheLog(`L1 stale target=${targetDomain} age=${Math.round((Date.now() - cachedPool.time) / 1000)}s`);
        _proxyPoolCache.delete(cacheKey);
    }

    // ── 单飞（in-flight 去重）──
    // 一级缓存要等解析结束才写入，而同一个键在同一秒里可能有多条连接同时到达
    // （浏览器开一个页面就是几十条并发 WS，且每条连接还可能两次进池）。中间这段窗口里
    // N 条连接会各自发起一遍 DoH。这里只共享「谁正在解析」这个事实：
    // 等待方轮询一级缓存（解析结束即写入），读不到就自己取 —— **绝不 await 别人的 Promise**。
    const pool = await crossRequestSingleFlight<[string, number][]>(
        _proxyPoolLoading,
        cacheKey,
        () => {
            const hit = _proxyPoolCache.get(cacheKey);
            return hit && isFreshPoolEntry(hit) ? hit.result : null;
        },
        () => resolveProxyPoolUncached(cacheKey, proxyIP, targetDomain, uuid),
        { tries: 40, delayMs: 25 }
    );
    // produce() 恒返回数组；null 只可能出现在"等待上界后仍读不到且已退出标记"的理论分支，
    // 这里兜底自己解析一次，避免把空池交给拨号
    return pool ?? await resolveProxyPoolUncached(cacheKey, proxyIP, targetDomain, uuid);
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
            poolCacheLog(`L2 hit target=${targetDomain} age=${Math.round((Date.now() - sharedPool.time) / 1000)}s n=${sharedPool.result.length}`);
            // 用二级条目自己的时间戳回填一级：两层共用一个绝对 TTL，
            // 不会因为「命中后回填」把 10 分钟续成 20 分钟。
            _proxyPoolCache.set(cacheKey, { result: sharedPool.result, time: sharedPool.time });
            evictOldest(_proxyPoolCache, PROXY_POOL_CACHE_MAX);
            return sharedPool.result;
        }
        poolCacheLog(`L2 miss target=${targetDomain}`);
    } else {
        poolCacheLog(`L2 skip target=${targetDomain} (ip-only pool)`);
    }

    const resolveStartedAt = Date.now();
    const proxyIPNormalized = proxyIP.toLowerCase();
    const entries = proxyIPNormalized.split(',').map(s => s.trim()).filter(Boolean);
    const allEntries: [string, number][] = [];

    for (const entry of entries) {
        if (entry.includes('.william')) {
            // .william domain: DoH TXT query to expand prefix list (对齐 edgetunnel 9918-9935)
            try {
                // 与 resolveDNS 共用同一份 Answer 缓存（键含查询类型，TXT 与 A/AAAA 互不覆盖）
                let txtData = answersToRecords(await dohAnswersCached(entry, 'TXT'), DNS_TYPE_CODE.TXT);
                if (txtData.length === 0) {
                    // 双源都没给出 TXT 时才单独问一次 Google（这条兜底只对 .william 生效）
                    txtData = answersToRecords(await dohQueryRaw(entry, 'TXT', GOOGLE_DOH), DNS_TYPE_CODE.TXT);
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
                const [aAnswers, aaaaAnswers] = await Promise.all([
                    dohAnswersCached(host, 'A'),
                    dohAnswersCached(host, 'AAAA'),
                ]);
                const ipv4s = answersToRecords(aAnswers, DNS_TYPE_CODE.A);
                // 池内的 v6 一律以 [v6] 形式承载（与黑名单键、拨号前去括号同一口径）
                const ipv6s = answersToRecords(aaaaAnswers, DNS_TYPE_CODE.AAAA).map((ip) => `[${ip}]`);
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
    // 截断会让被砍掉的候选连一次探测的机会都没有（那正是本改动要消除的浪费）。
    // 真正的边界来自 DoH 应答本身（一次 DNS 报文 ≤64KB）与 _proxyPoolCache 的 32 键上限。
    const result = shuffled;
    // C-04：写入带时间戳的键化缓存；超限时按插入顺序（LRU）淘汰最旧一条
    const resolvedAt = Date.now();
    poolCacheLog(`DoH target=${targetDomain} ms=${resolvedAt - resolveStartedAt} n=${result.length}`);
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

/**
 * 目标域名解析（A + AAAA）。
 * 出站模式的目标分类与直连竞速共用它；**不再维护第二份缓存** —— 原实现自带一套 TTL/空结果/LRU
 * 策略，与 resolveDNS 的口径完全相同，现在直接复用 resolveDNS 的缓存（同一域名在
 * 「节点解析 / 目标解析 / sing-box DNS」之间共享结果，一次请求最多打一轮 DoH）。
 * 保留这个具名入口，是因为调用点读起来是「解析目标」，且它恒为 onlyIPv4=false
 * （目标分类与直连竞速都需要 v6）。
 */
export async function resolveTargetDNS(domain: string): Promise<DnsResult> {
    return await resolveDNS(domain, false);
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