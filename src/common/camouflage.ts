import {
    fetchWithTimeout,
    withTimeout,
    hstsHeaders,
    randomUserAgent,
    randomAcceptLanguage
} from "@common";

/**
 * URL 伪装 — 对齐 cfnew 的伪装首页全路径反代：
 *  - 伪装域名来源：优先取面板 HOST/SNI 输入（globalThis.settings.hostSniList，string[] 数组，面板已按换行/逗号拆分），
 *    其次取 env `FALLBACK`（支持 `a|b|c` 列表随机），特殊值 `nginx` 直接渲染内建欢迎页。
 *  - 对非 / 且非管理路径的请求做反向代理，保留原路径与查询串。
 *  - 图片伪装：探测到图片 URL 时以 data URI 包装或流式直传，含假阳性保护（HTML 降级）。
 *  - 文本类（text/javascript/json/xml）且 <2MB 时缓冲并重写上游 host，内存缓存 5 分钟。
 *  - 其余内容流式转发，过滤可能泄露服务器信息的响应头与 CF 入站头。
 *  - 任何阶段失败降级：首页根路径重试 → nginx 欢迎页。
 */

const MASK_HOME_CACHE_TTL = 300000;       // 5 分钟
const MASK_IMAGE_CACHE_MAX = 12;          // 图片缓存最大张数
const MASK_HOME_CACHE_MAX = 100;          // 文本缓存最大条目
const TEXT_REWRITE_MAX = 2 * 1024 * 1024; // 2MB
const FETCH_TIMEOUT = 39000;

type CacheEntry = {
    body: string | ArrayBuffer;
    status: number;
    contentType: string;
    time: number;
};

const maskHomeCache = new Map<string, CacheEntry>();
const maskImageCache = new Map<string, CacheEntry>();

const CF_INBOUND_HEADERS = [
    'CF-Connecting-IP', 'CF-IPCountry', 'CF-Ray', 'CF-Visitor',
    'CF-Worker', 'CF-Cache-Status', 'True-Client-IP',
    'X-Forwarded-For', 'X-Forwarded-For-Original',
    'X-Forwarded-Proto', 'X-Forwarded-Host',
    'Forwarded', 'Via', 'X-Real-IP', 'X-Originating-IP',
    'X-Remote-IP', 'X-Client-IP', 'Client-IP',
    'X-Cluster-Client-IP', 'CF-Connecting-IPv6', 'CF-Pseudo-IPv4'
];

const CH_HEADERS = [
    'Sec-CH-UA', 'Sec-CH-UA-Arch', 'Sec-CH-UA-Bitness', 'Sec-CH-UA-Full-Version',
    'Sec-CH-UA-Mobile', 'Sec-CH-UA-Model', 'Sec-CH-UA-Platform', 'Sec-CH-UA-Platform-Version'
];

const SAFE_PROXY_HEADERS = new Set([
    'content-type', 'content-length', 'content-encoding', 'transfer-encoding',
    'accept-ranges', 'content-range', 'content-language',
    'cache-control', 'expires', 'last-modified', 'age',
    'vary', 'date', 'content-disposition', 'connection'
]);

const IMAGE_EXT_RE = /\.(jpg|jpeg|png|gif|webp|bmp|svg|ico)(\?|$)|[?&]f=(jpg|jpeg|png|gif|webp|bmp|svg|ico)\b|\/image\/|\/img\/|\/photo\/|\/thumb\/|\/photo-|[?&](auto|fm|format)=(jpg|jpeg|png|gif|webp|bmp|svg|ico)\b/i;

export async function nginxPage(): Promise<string> {
    return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>html{color-scheme:light dark}body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For our documentation and support please refer to <a href="https://nginx.org/">nginx.org</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
}

function maskSources(): string[] {
    const panel = (globalThis.settings?.hostSniList || [])
        .map(s => String(s).trim())
        .filter(Boolean);
    if (panel.length > 0) return panel;

    const fallback = String((globalThis as any).env?.FALLBACK || (globalThis as any).globalConfig?.fallbackDomain || '')
        .split('|')
        .map(s => s.trim())
        .filter(s => s && s.toLowerCase() !== 'nginx');
    return fallback;
}

function normalizeTarget(raw: string): string {
    let target = raw.trim();
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
    if (target.toLowerCase().startsWith('http://')) target = 'https://' + target.substring(7);
    return target.replace(/\/+$/, '');
}

/** 解析伪装配置：列表随机；面板为空且 FALLBACK=nginx → 直接渲染欢迎页。 */
export function resolveMaskTarget(): { target: string; isNginx: boolean } {
    const rawPanel = (globalThis.settings?.hostSniList || [])
        .map(s => String(s).trim())
        .filter(Boolean);
    if (rawPanel.length === 0) {
        const envRaw = String((globalThis as any).env?.FALLBACK || '');
        if (envRaw.trim().toLowerCase() === 'nginx') {
            return { target: '', isNginx: true };
        }
    }
    const sources = maskSources();
    if (sources.length === 0) return { target: '', isNginx: true };
    const picked = sources[Math.floor(Math.random() * sources.length)];
    return { target: normalizeTarget(picked), isNginx: false };
}

/** 构造指纹随机化的出站头（清 CF 入站头与 Sec-CH-UA，重写 Host/Referer/Origin） */
function buildMaskedHeaders(original: Headers, upstream: URL): Headers {
    const out = new Headers();
    for (const [k, v] of original as any) {
        if (CF_INBOUND_HEADERS.includes(k)) continue;
        if (CH_HEADERS.includes(k)) continue;
        if (['host', 'referer', 'origin'].includes(k.toLowerCase())) continue;
        out.set(k, v);
    }
    out.set('Host', upstream.host);
    out.set('Referer', upstream.origin);
    out.set('Origin', upstream.origin);
    out.set('User-Agent', randomUserAgent());
    out.set('Accept-Language', randomAcceptLanguage());
    return out;
}

function filterResponseHeaders(headers: Headers): Record<string, string> {
    const filtered: Record<string, string> = {};
    for (const [k, v] of headers) {
        if (SAFE_PROXY_HEADERS.has(k.toLowerCase())) filtered[k] = v;
    }
    filtered['Cache-Control'] = 'no-store';
    return filtered;
}

function withHsts(headers: Record<string, string>, env: any): Record<string, string> {
    return { ...headers, ...hstsHeaders(env) };
}

function arrayBufferToBase64(bytes: ArrayBuffer): string {
    const u8 = new Uint8Array(bytes);
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < u8.length; i += chunk) {
        binary += String.fromCharCode.apply(null, Array.from(u8.subarray(i, i + chunk)));
    }
    return btoa(binary);
}

/** 将图片缓冲结果包装为内联 data URI 页（cfnew 同款） */
function wrapImageResponse(body: ArrayBuffer, status: number, contentType: string): Response {
    const dataUri = `data:${contentType};base64,${arrayBufferToBase64(body)}`;
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>image</title><style>body{margin:0;overflow:hidden}img{width:100vw;height:100vh;object-fit:fill}</style></head><body><img src="${dataUri}" alt=""></body></html>`;
    return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

/** 图片伪装分支：命中图片 URL 时尝试缓冲缓存；失败返回 null 降级普通伪装。 */
async function tryServeImage(maskURL: URL, request: Request): Promise<Response | null> {
    const cached = maskImageCache.get(maskURL.href);
    if (cached && Date.now() - cached.time < MASK_HOME_CACHE_TTL) {
        return wrapImageResponse(cached.body as ArrayBuffer, cached.status, cached.contentType);
    }
    const headers = buildMaskedHeaders(request.headers, maskURL);
    headers.set('Accept', 'image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8');
    try {
        const resp = await fetchWithTimeout(maskURL.href, { method: request.method, headers, cf: {} }, 5000);
        const contentType = resp.headers.get('content-type') || 'image/jpeg';
        // 假阳性保护：服务器返回 HTML 说明不是图片，降级普通伪装
        if (contentType.startsWith('text/html')) return null;
        const contentLength = parseInt(resp.headers.get('content-length') || '0', 10);
        // content-length 虚标或 ≥2MB 时流式直传（不缓存）
        if (contentLength === 0 || contentLength > TEXT_REWRITE_MAX) {
            return new Response(resp.body, {
                status: resp.status,
                headers: withHsts(filterResponseHeaders(resp.headers), undefined)
            });
        }
        const bytes = await withTimeout(resp.arrayBuffer(), 5000, '图片代理响应体读取');
        if (maskImageCache.size >= MASK_IMAGE_CACHE_MAX) {
            const oldest = maskImageCache.keys().next().value;
            if (oldest) maskImageCache.delete(oldest);
        }
        maskImageCache.set(maskURL.href, { body: bytes, status: resp.status, contentType, time: Date.now() });
        return wrapImageResponse(bytes, resp.status, contentType);
    } catch (e) {
        console.error('伪装图片代理失败:', (e as Error)?.message ?? String(e));
        return null; // fallthrough 到普通伪装逻辑
    }
}

function cacheCleansing(): void {
    const now = Date.now();
    for (const [k, v] of maskHomeCache) {
        if (now - v.time >= MASK_HOME_CACHE_TTL) maskHomeCache.delete(k);
    }
    if (maskHomeCache.size > MASK_HOME_CACHE_MAX) maskHomeCache.clear();
}

/**
 * 主入口：全路径伪装反代。上游 target 由 resolveMaskTarget 决定，
 * 请求路径/查询串原样转发到伪装域名。任何失败降级 nginx 页。
 */
export async function camouflageProxy(request: Request, env: any): Promise<Response> {
    const { target, isNginx } = resolveMaskTarget();
    if (isNginx) {
        return new Response(await nginxPage(), {
            status: 200,
            headers: withHsts({ 'Content-Type': 'text/html; charset=UTF-8' }, env)
        });
    }

    let maskURL: URL;
    try {
        maskURL = new URL(target);
    } catch {
        return new Response(await nginxPage(), {
            status: 200,
            headers: withHsts({ 'Content-Type': 'text/html; charset=UTF-8' }, env)
        });
    }

    // 图片伪装
    if (IMAGE_EXT_RE.test(target)) {
        const imgResp = await tryServeImage(maskURL, request);
        if (imgResp) return imgResp;
    }

    const reqURL = new URL(request.url);
    const cacheKey = maskURL.origin + reqURL.pathname + reqURL.search;
    const cached = maskHomeCache.get(cacheKey);
    if (cached && Date.now() - cached.time < MASK_HOME_CACHE_TTL) {
        return new Response(cached.body, {
            status: cached.status,
            headers: withHsts({ 'Content-Type': cached.contentType, 'Cache-Control': 'no-store' }, env)
        });
    }

    cacheCleansing();

    const headers = buildMaskedHeaders(request.headers, maskURL);
    const fetchInit: RequestInit = { method: request.method, headers, cf: {} };
    if (request.method !== 'GET' && request.body) fetchInit.body = request.body;

    try {
        const resp = await fetchWithTimeout(
            maskURL.origin + reqURL.pathname + reqURL.search,
            fetchInit,
            FETCH_TIMEOUT
        );
        const contentType = resp.headers.get('content-type') || '';
        const contentLength = parseInt(resp.headers.get('content-length') || '0', 10);

        // 文本且 <2MB：缓冲 + 重写上游 host + 缓存
        if (/text|javascript|json|xml/.test(contentType) && (contentLength === 0 || contentLength < TEXT_REWRITE_MAX)) {
            const clone = resp.clone();
            try {
                const text = await withTimeout(clone.text(), 5000, '伪装页读取');
                const rewritten = text.replaceAll(maskURL.host, reqURL.host);
                const filtered = filterResponseHeaders(resp.headers);
                const headersFinal = withHsts(filtered, env);
                maskHomeCache.set(cacheKey, {
                    body: rewritten,
                    status: resp.status,
                    contentType,
                    time: Date.now()
                });
                return new Response(rewritten, { status: resp.status, headers: headersFinal });
            } catch (e) {
                console.warn('伪装页缓冲超时，改为流式转发');
            }
        }
        // 流式转发路径：过滤上游头，防止服务器信息泄露
        return new Response(resp.body, {
            status: resp.status,
            statusText: resp.statusText,
            headers: withHsts(filterResponseHeaders(resp.headers), env)
        });
    } catch (error) {
        console.error('伪装页反代失败:', (error as Error)?.message ?? String(error));
        // 非根路径失败时降级到首页根目录重试
        if (reqURL.pathname !== '/') {
            console.warn('尝试降级到首页根路径:', maskURL.origin);
            const fallbackHeaders = buildMaskedHeaders(request.headers, maskURL);
            fallbackHeaders.set('User-Agent', randomUserAgent());
            fallbackHeaders.set('Accept-Language', randomAcceptLanguage());
            try {
                const fallbackResp = await fetchWithTimeout(
                    maskURL.origin + '/',
                    { method: 'GET', headers: fallbackHeaders, cf: {} },
                    FETCH_TIMEOUT
                );
                if (fallbackResp.ok || fallbackResp.status < 500) {
                    return new Response(fallbackResp.body, {
                        status: fallbackResp.status,
                        statusText: fallbackResp.statusText,
                        headers: withHsts(filterResponseHeaders(fallbackResp.headers), env)
                    });
                }
            } catch (e2) {
                console.error('首页根路径降级也失败:', (e2 as Error)?.message ?? String(e2));
            }
        }
        return new Response(await nginxPage(), {
            status: 200,
            headers: withHsts({ 'Content-Type': 'text/html; charset=UTF-8' }, env)
        });
    }
}
