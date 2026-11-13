import {
    evictOldest,
    fetchWithTimeout,
    withTimeout,
    hstsHeaders,
    randomUserAgent,
    randomAcceptLanguage,
    copySafeOutboundHeaders
} from "@common";

/**
 * URL 伪装 — 对齐 cfnew 的伪装首页全路径反代：
 *  - 伪装域名来源：env `homepage`/`HOMEPAGE`/`URL`/`FALLBACK`（支持 `a|b|c` 列表随机），
 *    特殊值 `nginx` 渲染内建欢迎页；未设置 → 内置 1101 伪装页（hostSniList 仅用于节点 HOST/SNI，不参与伪装页）。
 *  - 对非 / 且非管理路径的请求做反向代理，保留原路径与查询串。
 *  - 图片伪装：探测到图片 URL 时以 data URI 包装或流式直传，含假阳性保护（HTML 降级）。
 *  - 文本类（text/javascript/json/xml）且 <2MB 时缓冲并重写上游 host，内存缓存 5 分钟。
 *  - 其余内容流式转发，过滤可能泄露服务器信息的响应头与 CF 入站头。
 *  - 任何阶段失败降级：首页根路径重试 → nginx 欢迎页。
 */

const MASK_HOME_CACHE_TTL = 300000;       // 5 分钟
const MASK_IMAGE_CACHE_MAX = 12;          // 图片缓存最大张数
const MASK_HOME_CACHE_MAX = 100;          // 文本缓存最大条目
/**
 * 首页缓存的**总字节预算**。这是本文件里最关键的资源上限：
 * isolate 内存只有 128MB，而单条缓存正文最长可达 TEXT_REWRITE_MAX（1MB）。
 * 只按「条目数」限流时，100 条 × 1MB = 100MB，缓存本身就是内存炸弹 ——
 * 逼近上限后 V8 会持续高强度 GC，而 GC 消耗的是**CPU 时间**，
 * 表现为「CPU 超限规律性复发」而不是内存报错。因此必须按字节封顶。
 * 4MB 相对 128MB 只是零头，命中率损失远小于 GC 抖动带来的代价。
 */
const MASK_HOME_CACHE_MAX_BYTES = 4 * 1024 * 1024;
const TEXT_REWRITE_MAX = 1 * 1024 * 1024; // 1MB
const FETCH_TIMEOUT = 39000;

/**
 * 首页真实反代的 CPU 熔断：每 isolate 每窗口最多 MASK_PROXY_MAX_PER_WINDOW 次。
 *
 * 为什么需要：`/` 的 CPU 成本与上游响应体大小线性相关（clone + text() + replaceAll），
 * 批量扫描会把同一个 isolate 打成一串 exceededCpu。超限后改为返回内建 1101 页（0 次 fetch、
 * 0 次字符串改写），把「持续超限」降级成「偶发超限」。
 * 放行额度刻意取得很小：正常访客刷首页不会有节奏地超过 60 次/分钟，
 * 而达到这个量级基本只有抓取/压测。
 */
const MASK_PROXY_WINDOW_MS = 60000;
const MASK_PROXY_MAX_PER_WINDOW = 60;
let maskProxyWindowStart = 0;
let maskProxyCount = 0;

type CacheEntry = {
    body: string | ArrayBuffer;
    status: number;
    contentType: string;
    time: number;
    /** 该条目占用的近似字节数（O(1) 取值，不做真实编码）；用于总分账，不需要精确 */
    bytes: number;
};

const maskHomeCache = new Map<string, CacheEntry>();
const maskImageCache = new Map<string, CacheEntry>();
let maskHomeCacheBytes = 0;

const SAFE_PROXY_HEADERS = new Set([
    'content-type', 'content-length', 'content-encoding', 'transfer-encoding',
    'accept-ranges', 'content-range', 'content-language',
    'cache-control', 'expires', 'last-modified', 'age',
    'vary', 'date', 'content-disposition', 'connection',
    // 3xx 跳转头：丢掉它会让 cover 站返回「没有 Location 的 3xx」，是可判定的反代痕迹（H8）
    'location'
]);

/** 正文会被重写（host 替换）的内容类型：内容不再与上游一致，必须保持 no-store */
const REWRITTEN_CONTENT_TYPE_RE = /text|javascript|json|xml/i;

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

/** 内置 1101 伪装页（对齐 cfnew html1101：Cloudflare Worker threw exception 错误页，随机 Ray ID） */
export async function cf1101Page(host: string, accessIP: string): Promise<string> {
    const now = new Date();
    const timestamp =
        now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') +
        ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
    const randomStr = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');
    return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>
<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->
</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${randomStr} &bull; ${timestamp} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->
            <section></section><!-- spacer -->
            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>
                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>
                </div>
            </div><!-- /.section -->
            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${randomStr}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${accessIP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>
    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->
        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->
     <script>
    window._cf_translation = {};
  </script> 
</body>
</html>`;
}

/**
 * 黑名单 / 限流拦截的统一出口：1101 伪装页 + 429 + Retry-After。
 * firstCheck.ts 的三处拦截与 worker.ts 的 WS 路径字典拦截共用（此前是四份逐字重复的 Response 构造）。
 * 每次调用都新建 headers 对象，调用方之间不共享可变状态。
 */
export async function cf1101RateLimitedResponse(host: string, accessIP: string): Promise<Response> {
    return new Response(await cf1101Page(host, accessIP), {
        status: 429,
        headers: {
            'Content-Type': 'text/html; charset=UTF-8',
            'Retry-After': '3600'
        }
    });
}

/**
 * 伪装地址来源（对齐 cfnew，面板 hostSniList 仅用于节点 HOST/SNI，不参与伪装页）：
 * env `homepage`/`HOMEPAGE`/`URL`/`FALLBACK`（支持 `a|b|c` 列表随机）；
 * 特殊值 `nginx` 渲染内建欢迎页；未设置 → 内置 1101 页。
 */
function maskSources(): string[] {
    const envVal = String(
        (globalThis as any).env?.homepage ||
        (globalThis as any).env?.HOMEPAGE ||
        (globalThis as any).env?.URL ||
        (globalThis as any).env?.FALLBACK ||
        (globalThis as any).globalConfig?.fallbackDomain ||
        ''
    );
    return envVal
        .split('|')
        .map(s => s.trim())
        .filter(s => s && s.toLowerCase() !== 'nginx');
}

function normalizeTarget(raw: string): string {
    let target = raw.trim();
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
    if (target.toLowerCase().startsWith('http://')) target = 'https://' + target.substring(7);
    return target.replace(/\/+$/, '');
}

/** 解析伪装配置：列表随机；未设置 env → 内置 1101 页；FALLBACK=nginx → 内建欢迎页。 */
export function resolveMaskTarget(): { target: string; isNginx: boolean; is1101: boolean } {
    const envRaw = String(
        (globalThis as any).env?.homepage ||
        (globalThis as any).env?.HOMEPAGE ||
        (globalThis as any).env?.URL ||
        (globalThis as any).env?.FALLBACK ||
        (globalThis as any).globalConfig?.fallbackDomain ||
        ''
    ).trim();
    if (envRaw.toLowerCase() === 'nginx') {
        return { target: '', isNginx: true, is1101: false };
    }
    if (!envRaw) return { target: '', isNginx: false, is1101: true };
    const sources = maskSources();
    if (sources.length === 0) return { target: '', isNginx: false, is1101: true };
    const picked = sources[Math.floor(Math.random() * sources.length)];
    return { target: normalizeTarget(picked), isNginx: false, is1101: false };
}

/** 构造指纹随机化的出站头（清会话凭据与 CF 入站头、Sec-CH-UA，重写 Host/Referer/Origin） */
function buildMaskedHeaders(original: Headers, upstream: URL): Headers {
    const out = copySafeOutboundHeaders(original);
    // Sec-CH-UA* 客户端提示头：Headers 迭代产出的头名恒为小写，必须大小写不敏感比较
    for (const [k] of [...out]) {
        if (k.toLowerCase().startsWith('sec-ch-')) out.delete(k);
    }
    out.set('Host', upstream.host);
    out.set('Referer', upstream.origin);
    out.set('Origin', upstream.origin);
    out.set('User-Agent', randomUserAgent());
    out.set('Accept-Language', randomAcceptLanguage());
    return out;
}

/** 取全部 Set-Cookie：运行时（workerd）支持 getSetCookie 时逐条取，否则退化为单条 get（避免静默丢成一条） */
function getSetCookieValues(headers: Headers): string[] {
    const runtime = headers as Headers & { getSetCookie?: () => string[] };
    if (typeof runtime.getSetCookie === 'function') {
        const values = runtime.getSetCookie();
        if (Array.isArray(values) && values.length > 0) return values;
    }
    const single = headers.get('set-cookie');
    return single ? [single] : [];
}

/**
 * 过滤上游响应头（H8）：
 *  - 只放行 SAFE_PROXY_HEADERS，防止服务器信息泄露；
 *  - Location 放行并重写（保守策略，见下）；Set-Cookie 放行且逐条保留；
 *  - 缓存策略按 content-type 区分，不再一律 no-store。
 */
function filterResponseHeaders(headers: Headers, maskURL: URL, reqURL: URL): Headers {
    const out = new Headers();
    for (const [k, v] of headers) {
        if (SAFE_PROXY_HEADERS.has(k.toLowerCase())) out.set(k, v);
    }

    // Location 重写（保守策略）：仅当它是**指向上游伪装域自身**的绝对地址时，才按与正文重写
    // （replaceAll(maskURL.host, reqURL.host)）同款语义改写为面板域名；相对地址（/path）本就指向
    // 面板域，原样放行；指向第三方域的绝对地址不做改写（改写不属于伪装域的跳转不是反代该做的事）。
    const location = headers.get('location');
    if (location) {
        out.set('Location', /^https?:\/\//i.test(location) ? location.replaceAll(maskURL.host, reqURL.host) : location);
    }

    // Set-Cookie：同名头可能有多条，必须逐条 append（Headers 允许重复 set-cookie），不能只留一条
    for (const cookie of getSetCookieValues(headers)) out.append('Set-Cookie', cookie);

    // 缓存策略按 content-type 区分：
    //  - HTML/JS/JSON/XML：正文已被重写，保持 no-store；
    //  - 其余静态体（图片等）：沿用上游 cache-control，缺省时与 tryServeImage 一致用 public, max-age=86400。
    const contentType = headers.get('content-type') || '';
    if (REWRITTEN_CONTENT_TYPE_RE.test(contentType)) {
        out.set('Cache-Control', 'no-store');
    } else if (!out.has('Cache-Control')) {
        out.set('Cache-Control', 'public, max-age=86400');
    }
    return out;
}

function withHsts(headers: Headers | Record<string, string>, env: any): Headers | Record<string, string> {
    const hsts = hstsHeaders(env);
    if (headers instanceof Headers) {
        for (const [k, v] of Object.entries(hsts)) headers.set(k, v);
        return headers;
    }
    return { ...headers, ...hsts };
}

/**
 * 正文被改写后必须清掉的三个头。改写会改变长度、也会改变字节语义，
 * 继续沿用上游的头会让响应在客户端侧「帧错位」：
 *  - content-length：长度已变，客户端按旧值读会截断或挂起；
 *  - content-encoding：fetch 已经把 body 解压成明文，再声明 gzip 会让客户端二次解压而失败；
 *  - transfer-encoding：分块方式由运行时重新决定，手写会与流式 body 冲突。
 * 帧错位的后果不只是页面坏掉：浏览器与各类客户端会**不断重试**，
 * 而每次重试都是一次缓存未命中的昂贵反代 —— 这正是「CPU 超限规律性复发」的来源。
 */
function stripBodyFramingHeaders(headers: Headers): void {
    headers.delete('content-length');
    headers.delete('content-encoding');
    headers.delete('transfer-encoding');
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

/** 将图片缓冲结果包装为内联 data URI 页（对齐 cfnew 生成图片HTML：黑底居中、object-fit:fill 全屏） */
function wrapImageResponse(body: ArrayBuffer, status: number, contentType: string, maskHost: string): Response {
    const dataUri = `data:${contentType || 'image/jpeg'};base64,${arrayBufferToBase64(body)}`;
    // F14：标题取伪装站 host，不再写项目名 + 版本号——伪装面自报项目与版本是可被扫描器
    // 直接抓到的部署指纹；内联 data URI 与伪装站自身资源同源，用它的域名作标题最自洽
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>${maskHost}</title><style>body{margin:0;padding:0;overflow:hidden;background:#000;display:flex;align-items:center;justify-content:center;height:100vh}img{width:100vw;height:100vh;object-fit:fill}</style></head><body><img src="${dataUri}" alt="homepage"></body></html>`;
    return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

/** 图片伪装分支（对齐 cfnew）：
 *  - 无论请求路径是什么（/ 或 /随机路径），都返回同一张样式化图片；
 *    缓存键 = 目标图片完整地址（非请求路径），无 TTL，仅 12 张 FIFO 淘汰。
 *  - 请求带 Referer（伪装域名 origin + /），指纹随机出站头。
 *  - <2MB → 缓冲 + 缓存 + HTML 包装；content-length 虚标或 ≥2MB → 原样流出（带 CORS 头）。
 *  - 失败返回 null，降级普通伪装反代。 */
async function tryServeImage(maskURL: URL): Promise<Response | null> {
    const url = maskURL.href;
    const cached = maskImageCache.get(url);
    if (cached) {
        return wrapImageResponse(cached.body as ArrayBuffer, cached.status, cached.contentType, maskURL.hostname);
    }
    const headers = buildMaskedHeaders(new Headers(), maskURL);
    headers.set('Referer', maskURL.origin + '/');
    headers.set('Accept', 'image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8');
    try {
        const resp = await fetchWithTimeout(url, { method: 'GET', headers, cf: {} }, 10000);
        const contentType = resp.headers.get('content-type') || 'image/jpeg';
        // 假阳性保护：服务器返回 HTML 说明不是图片，降级普通伪装
        if (contentType.startsWith('text/html')) return null;
        const contentLength = parseInt(resp.headers.get('content-length') || '0', 10);
        // content-length 声明 <2MB → 缓冲 + 缓存 + HTML 包装
        if (contentLength > 0 && contentLength < 2 * 1024 * 1024) {
            const bytes = await withTimeout(resp.arrayBuffer(), 5000, '图片代理响应体读取');
            if (bytes.byteLength < 2 * 1024 * 1024) {
                // 插入前腾位置（传 MAX-1），插入后不超过 MASK_IMAGE_CACHE_MAX
                evictOldest(maskImageCache, MASK_IMAGE_CACHE_MAX - 1);
                maskImageCache.set(url, { body: bytes, status: resp.status, contentType, time: Date.now(), bytes: bytes.byteLength });
                return wrapImageResponse(bytes, resp.status, contentType, maskURL.hostname);
            }
            // content-length 虚标（实际 >2MB）：用已读字节流式直传
            const headersOut: Record<string, string> = {
                'Content-Type': contentType,
                'Access-Control-Allow-Origin': '*',
                'Cache-Control': 'public, max-age=86400'
            };
            return new Response(bytes, { status: resp.status, headers: headersOut });
        }
        // 未知长度或无头部 / ≥2MB → 直接流式（不缓冲、不缓存、不包装 HTML）
        const headersOut: Record<string, string> = {
            'Content-Type': contentType,
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=86400'
        };
        return new Response(resp.body, { status: resp.status, headers: headersOut });
    } catch (e) {
        console.error('伪装图片代理失败:', (e as Error)?.message ?? String(e));
        return null; // fallthrough 到普通伪装逻辑
    }
}

function cacheCleansing(): void {
    const now = Date.now();
    for (const [k, v] of maskHomeCache) {
        if (now - v.time >= MASK_HOME_CACHE_TTL) {
            maskHomeCacheBytes -= v.bytes;
            maskHomeCache.delete(k);
        }
    }
}

/**
 * 噪声 query 参数名（小写）。这些只影响上游的统计/归因，不影响返回的页面内容 ——
 * 若纳入缓存键，真实站点首页常见的 `?utm_source=…&_=17…` 会让缓存几乎永不命中，
 * 每个请求都重新走一遍「clone + text + replaceAll」的 CPU 密集路径。
 * 只收高频的几类：长尾参数收益低，而产物体积有硬上限（raw ≤552960）。
 */
const NOISE_QUERY_KEYS: ReadonlySet<string> = new Set([
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'gclid', 'fbclid', 'msclkid', 'dclid', 'spm', '_ga', '_gl', '_'
]);

/**
 * 缓存键归一化：按原出现顺序保留非噪声参数，值原样保留。
 *
 * 刻意不用 url.searchParams 序列化 —— 它会重新编码（空格 %20/+, 中文转义）并重排，
 * 那样「缓存键」与「实际转发给上游的 URL」会变成两个东西，排查时极易误判。
 * 这里只做纯字符串过滤：不命中的参数一段不漏地保留原样。
 */
function normalizeCacheQuery(search: string): string {
    if (!search || search === '?') return '';
    const kept: string[] = [];
    for (const pair of search.slice(1).split('&')) {
        if (!pair) continue;
        const eq = pair.indexOf('=');
        const rawKey = eq === -1 ? pair : pair.slice(0, eq);
        if (NOISE_QUERY_KEYS.has(rawKey.toLowerCase())) continue;
        kept.push(pair);
    }
    return kept.length ? '?' + kept.join('&') : '';
}

/**
 * 首页反代的 CPU 熔断闸门。
 * 返回 true = 本窗口额度已用尽，调用方应直接返回内建页。
 * 窗口整体滚动（不做滑动窗口）：这里只需挡住突发，不需要精确计量。
 */
function maskProxyBudgetExhausted(): boolean {
    const now = Date.now();
    if (now - maskProxyWindowStart >= MASK_PROXY_WINDOW_MS) {
        maskProxyWindowStart = now;
        maskProxyCount = 0;
    }
    if (maskProxyCount >= MASK_PROXY_MAX_PER_WINDOW) return true;
    maskProxyCount++;
    return false;
}

/**
 * 写入首页缓存，同时维持「总字节预算」与「条目上限」两道天花板，并保持最近使用顺序。
 *
 * Map 的插入顺序就是淘汰顺序，所以命中后重新 set 会把该键挪到队尾（最近使用）；
 * 淘汰时从头删，删到的就是最久未使用的条目。
 *
 * 单条超出总预算的正文直接不入缓存：一条就能吃光预算，留着只会把其他热点键挤走。
 */
function cacheHomeEntry(key: string, entry: CacheEntry): void {
    const prev = maskHomeCache.get(key);
    if (prev) {
        maskHomeCacheBytes -= prev.bytes;
        maskHomeCache.delete(key);
    }

    if (entry.bytes > MASK_HOME_CACHE_MAX_BYTES) return;

    while (maskHomeCache.size && (maskHomeCache.size >= MASK_HOME_CACHE_MAX
        || maskHomeCacheBytes + entry.bytes > MASK_HOME_CACHE_MAX_BYTES)) {
        const oldest = maskHomeCache.keys().next();
        if (oldest.done) break;
        const victim = maskHomeCache.get(oldest.value);
        if (victim) maskHomeCacheBytes -= victim.bytes;
        maskHomeCache.delete(oldest.value);
    }

    maskHomeCache.set(key, entry);
    maskHomeCacheBytes += entry.bytes;
}

/**
 * 边流边改写：把上游 body 的每个 chunk 解码、替换 host、再编码流出。
 *
 * 为什么不用 `clone().text()` 一把梭：那会先把整份 body 读进内存再全量 replaceAll，
 * CPU 与体积线性相关。这里同一个 token 预算（TEXT_REWRITE_MAX）卡的是「累计已处理字节」，
 * 一旦超出预算立刻停止改写、把当前与后续 chunk 原样流出 —— 除了一次性的
 * 判断开销，CPU 不再随页面变大而增长。
 *
 * 为什么可以跨 chunk 直接 replace：替换目标是 host（如 `example.com`），
 * 且 replaceAll 是纯字符串替换、不涉及正则会话保持。chunk 边界恰好切断 host 时，
 * 该处替换会被漏掉（极低概率，且只影响页面里对上游域名的引用），
 * 换来的收益是不必在多 MB 文本上做跨 chunk 拼接 —— 这里刻意选择前者。
 */
function streamWithBudgetRewrite(
    resp: Response,
    maskURL: URL,
    reqURL: URL,
    cacheKey: string,
    contentType: string,
    env: any
): Response {
    const source = resp.body;
    const filtered = filterResponseHeaders(resp.headers, maskURL, reqURL);
    // 本函数一定改写正文（至少改到预算上限），长度不再与上游一致
    stripBodyFramingHeaders(filtered);
    const headersOut = withHsts(filtered, env);

    if (!source) {
        return new Response(null, { status: resp.status, statusText: resp.statusText, headers: headersOut });
    }

    const decoder = new TextDecoder('utf-8');
    const encoder = new TextEncoder();
    let processed = 0;
    // 只在「全程未超预算」时才值得缓存：超预算的部分是未改写的原文，缓存它会把错误结果固化 5 分钟
    let rewritable = true;
    let collected = '';

    const transform = new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
            if (!rewritable) {
                controller.enqueue(chunk);
                return;
            }

            // 预算耗尽：本 chunk 与后续一律原样流出，并放弃缓存
            if (processed + chunk.byteLength > TEXT_REWRITE_MAX) {
                rewritable = false;
                collected = '';
                console.warn(`伪装页超过 ${TEXT_REWRITE_MAX}B 改写预算，余下部分原样流出`);
                controller.enqueue(chunk);
                return;
            }
            processed += chunk.byteLength;

            // stream:true 让跨 chunk 的多字节字符不被截断
            const rewritten = decoder.decode(chunk, { stream: true }).replaceAll(maskURL.host, reqURL.host);
            collected += rewritten;
            controller.enqueue(encoder.encode(rewritten));
        },
        flush(controller) {
            const tail = decoder.decode();
            if (tail) {
                const rewrittenTail = tail.replaceAll(maskURL.host, reqURL.host);
                if (rewritable) collected += rewrittenTail;
                controller.enqueue(encoder.encode(rewrittenTail));
            }

            if (rewritable) {
                cacheHomeEntry(cacheKey, {
                    body: collected,
                    status: resp.status,
                    contentType,
                    time: Date.now(),
                    bytes: collected.length
                });
            }
        }
    });

    return new Response(source.pipeThrough(transform), {
        status: resp.status,
        statusText: resp.statusText,
        headers: headersOut
    });
}

/**
 * 主入口：全路径伪装反代。上游 target 由 resolveMaskTarget 决定，
 * 请求路径/查询串原样转发到伪装域名。任何失败降级 nginx 页。
 */
export async function camouflageProxy(request: Request, env: any): Promise<Response> {
    const { target, isNginx, is1101 } = resolveMaskTarget();
    if (is1101) {
        const reqURL = new URL(request.url);
        return new Response(await cf1101Page(reqURL.host, request.headers.get('CF-Connecting-IP') || ''), {
            status: 200,
            headers: withHsts({ 'Content-Type': 'text/html; charset=UTF-8' }, env)
        });
    }
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
        const imgResp = await tryServeImage(maskURL);
        if (imgResp) return imgResp;
    }

    const reqURL = new URL(request.url);
    // 缓存键用「实际转发给上游的 path + query」按噪声参数归一化后拼成，
    // 保证「键」与「内容」严格对应：请求原样转发，只有键被归一化。
    const cacheKey = maskURL.origin + reqURL.pathname + normalizeCacheQuery(reqURL.search);
    const cached = maskHomeCache.get(cacheKey);
    if (cached && Date.now() - cached.time < MASK_HOME_CACHE_TTL) {
        // 命中即提升为「最近使用」，避免热点键在逐条淘汰时先被扔掉
        cacheHomeEntry(cacheKey, cached);
        return new Response(cached.body, {
            status: cached.status,
            headers: withHsts({ 'Content-Type': cached.contentType, 'Cache-Control': 'no-store' }, env)
        });
    }

    cacheCleansing();

    // 熔断必须在 fetch 之前：一旦放行，后面就是 clone + text() + replaceAll 的 1MB 级字符串处理，
    // 事后再想省 CPU 已经晚了。命中额度上限时给内建 1101 页（与「未设置伪装域名」同一张页）。
    // 只对根路径计数：伪装站点自身的子路径流量（访客浏览某篇文章）不足以构成扫描特征，
    // 把它们一并熔断等于让伪装站自己打不开。
    if (reqURL.pathname === '/' && maskProxyBudgetExhausted()) {
        console.warn('[伪装熔断] 本窗口真实反代额度已用尽，降级内建页');
        return new Response(await cf1101Page(reqURL.host, request.headers.get('CF-Connecting-IP') || ''), {
            status: 200,
            headers: withHsts({ 'Content-Type': 'text/html; charset=UTF-8' }, env)
        });
    }

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

        // 文本且长度已知且 <1MB：缓冲 + 重写上游 host + 缓存。
        // 判据与 filterResponseHeaders（缓存策略）共用同一个常量：原先这里内联了一份**少了 /i** 的副本，
        // 大写 content-type（如 `Text/HTML`）会走"不重写"的另一条分支，与缓存策略的判定自相矛盾。
        //
        // contentLength === 0（上游不报长度 / chunked）不再直接进入这条分支：
        // 旧写法会把「未知大小」当成「小」，把任意体积的 body 全部 clone + 解码 + replaceAll，
        // 正是 GET / 打穿 CPU 预算的主要路径。现在改走下面的限流式改写。
        if (REWRITTEN_CONTENT_TYPE_RE.test(contentType) && contentLength > 0 && contentLength < TEXT_REWRITE_MAX) {
            const clone = resp.clone();
            try {
                const text = await withTimeout(clone.text(), 5000, '伪装页读取');
                const rewritten = text.replaceAll(maskURL.host, reqURL.host);
                const filtered = filterResponseHeaders(resp.headers, maskURL, reqURL);
                // 改写后长度已变，且 body 已被 fetch 解压：沿用上游的帧头会让客户端二次解压/按旧长度读取
                stripBodyFramingHeaders(filtered);
                const headersFinal = withHsts(filtered, env);
                cacheHomeEntry(cacheKey, {
                    body: rewritten,
                    status: resp.status,
                    contentType,
                    time: Date.now(),
                    bytes: rewritten.length
                });
                return new Response(rewritten, { status: resp.status, headers: headersFinal });
            } catch (e) {
                console.warn('伪装页缓冲超时，改为流式转发');
            }
        }
        // 长度未知或 ≥1MB 的文本：边流边改写，超过上限立即放弃改写、按原样继续流出。
        // 这样既不把上游域名暴露在「超预算」页面上，也不会因 body 巨大而烧穿 CPU。
        if (REWRITTEN_CONTENT_TYPE_RE.test(contentType)) {
            if (contentLength >= TEXT_REWRITE_MAX) {
                console.warn(`伪装页 ${contentLength}B 超过改写上限，直接流式转发（不重写 host）`);
            }
            return streamWithBudgetRewrite(resp, maskURL, reqURL, cacheKey, contentType, env);
        }
        // 流式转发路径：过滤上游头，防止服务器信息泄露
        return new Response(resp.body, {
            status: resp.status,
            statusText: resp.statusText,
            headers: withHsts(filterResponseHeaders(resp.headers, maskURL, reqURL), env)
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
                // Response.ok 就是 2xx，已被 status < 500 包含，这里只判后者
                if (fallbackResp.status < 500) {
                    return new Response(fallbackResp.body, {
                        status: fallbackResp.status,
                        statusText: fallbackResp.statusText,
                        headers: withHsts(filterResponseHeaders(fallbackResp.headers, maskURL, reqURL), env)
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
