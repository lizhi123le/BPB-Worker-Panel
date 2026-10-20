export enum HttpStatus {
    OK = 200,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    INTERNAL_SERVER_ERROR = 500
}

export function base64EncodeUtf8(str: string): string {
    const bytes = new TextEncoder().encode(str);
    const binary = Array.from(bytes, b => String.fromCharCode(b)).join("");
    return btoa(binary);
}

export function base64DecodeUtf8(base64: string) {
    return new TextDecoder().decode(
        Uint8Array.from(atob(base64), c => c.charCodeAt(0))
    );
}

export function isValidUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

/**
 * KV 绑定是否真的可用（唯一判据，凭据校验与登录首访流程共用）。
 * 不只是「有没有这个属性」：`typeof kv === 'object'` 对 `null` 成立，对 {} 也成立，
 * 而这两种情况一旦走到 kv.get/kv.put 都是 TypeError。缺绑定应当是「明确报错」而不是「崩溃」。
 */
export function isKvBound(env: any): boolean {
    const kv = env?.kv;
    return typeof kv === 'object' && kv !== null && typeof kv.get === 'function';
}

/**
 * 按插入顺序淘汰最旧条目，直到 `map.size <= maxSize`（Map 的迭代顺序就是插入顺序）。
 *
 * 全仓库「内存 Map 容量兜底」共用这一份实现。两点语义要注意，改动时必须对照调用点：
 *  1) 判据是「超出 maxSize 才删」。插入**之后**调用、要求落库后不超过 MAX 的，传 MAX；
 *     插入**之前**先腾位置的（原写法 `while (size >= MAX)`），传 `MAX - 1`，插入后才正好 ≤ MAX。
 *  2) 只在真超限时迭代，未超限时 0 次分配、0 次迭代。
 */
export function evictOldest<K, V>(map: Map<K, V>, maxSize: number): void {
    while (map.size > maxSize) {
        const oldest = map.keys().next();
        if (oldest.done) return;
        map.delete(oldest.value);
    }
}

export function respond(
    success: boolean,
    status: HttpStatus,
    message?: string,
    body?: any,
    customHeaders?: Record<string, string>
): Response {
    const headers = {
        'Content-Type': 'application/json',
        // F13：JSON 接口同样带安全头（含 no-store）。env 由 worker.ts 挂在 globalThis.env。
        ...securityHeaders((globalThis as any)?.env),
        ...customHeaders,
    };

    const responseBody = {
        success,
        status,
        message: message ?? null,
        body: body ?? null,
    };

    return new Response(JSON.stringify(responseBody), { status, headers });
}

/**
 * 订阅配置接口的统一响应：格式化 JSON + 明确不缓存。
 * Clash / sing-box / Xray 三端此前各写一份完全相同的 Response 字面量（共 6 处），
 * 头部语义只在此处维护。
 */
export function configJsonResponse(data: unknown, status: HttpStatus = HttpStatus.OK): Response {
    return new Response(JSON.stringify(data, null, 4), {
        status,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store',
            'CDN-Cache-Control': 'no-store'
        }
    });
}

/**
 * HTML 页面响应的统一封装（面板 / 登录 / 密钥 / 代理 IP / 错误页共用）：
 * text/html + 安全响应头，避免每处重复展开同一份 headers。
 */
export function htmlResponse(
    body: string | ReadableStream<Uint8Array>,
    status: HttpStatus = HttpStatus.OK
): Response {
    return new Response(body as BodyInit, {
        status,
        headers: { 'Content-Type': 'text/html; charset=utf-8', ...securityHeaders((globalThis as any)?.env) }
    });
}

export function safeErrorMessage(error: any): string {
    return error instanceof Error ? error.message : String(error);
}

/**
 * Escape a string for safe insertion into HTML text content.
 * Guards against reflected XSS when error messages (which may echo
 * user-controlled input) are rendered into the error page.
 */
export function escapeHtml(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/** Reject a promise after `ms` milliseconds (or `undefined` signal when ms <= 0). */
export function withTimeout<T>(promise: Promise<T>, ms: number, label = '操作'): Promise<T> {
    if (!ms || ms <= 0) return promise;
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`${label} 超时(${ms}ms)`)), ms);
        promise.then(
            (v) => { clearTimeout(timer); resolve(v); },
            (e) => { clearTimeout(timer); reject(e); }
        );
    });
}

/** fetch with an overall timeout; falls back to AbortSignal.timeout when available. */
export async function fetchWithTimeout(
    url: string | URL,
    init: RequestInit = {},
    ms: number = 30000
): Promise<Response> {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function' && ms > 0) {
        const { signal, ...rest } = init;
        return await fetch(url, { ...rest, signal: signal ?? AbortSignal.timeout(ms) });
    }
    return await withTimeout(fetch(url, init), ms, 'fetch');
}

/** Build optional HSTS header object based on the HSTS_ENABLE flag (cfnew semantics). */
export function hstsHeaders(env: Record<string, string | undefined> | undefined): Record<string, string> {
    if (env && (env.HSTS_ENABLE === '1' || env.HSTS_ENABLE === 'true')) {
        return { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload' };
    }
    return {};
}

/**
 * F13：面板/登录/密钥/错误页与 JSON 接口的通用安全响应头（HSTS 仍按 env 开关，默认不加）。
 *
 * CSP 刻意**只**含 `object-src` / `base-uri` / `frame-ancestors` 三条，不含 `default-src`/`script-src`：
 * 四个 index.html 大量依赖内联 `onclick`（panel/index.html 就有 59 处）与内联 `<script>`，
 * 一旦写 `script-src 'self'` 会直接拦死面板全部交互。未列出的指令不受限，
 * 因此这三条既不改变页面功能，又挡住 <base> 劫持、插件嵌入与跨站 framing。
 */
export function securityHeaders(env?: Record<string, string | undefined>): Record<string, string> {
    return {
        'Content-Security-Policy': "object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-store',
        ...hstsHeaders(env)
    };
}

/**
 * 出站敏感头 denylist（全部小写）。
 * 比较必须用 `k.toLowerCase()`：Headers 迭代产出的头名恒为小写，用大写名单直接比较会静默失配。
 */
export const SENSITIVE_OUTBOUND_HEADERS: ReadonlySet<string> = new Set([
    // 会话凭据
    'cookie', 'authorization', 'proxy-authorization',
    // CF / 代理链路入站头：真实访客 IP 与网络拓扑
    'cf-connecting-ip', 'cf-connecting-ipv6', 'cf-pseudo-ipv4', 'cf-ipcountry',
    'cf-ray', 'cf-visitor', 'cf-worker', 'cf-cache-status',
    'true-client-ip', 'x-forwarded-for', 'x-forwarded-for-original',
    'x-forwarded-proto', 'x-forwarded-host', 'forwarded', 'via',
    'x-real-ip', 'x-originating-ip', 'x-remote-ip', 'x-client-ip',
    'client-ip', 'x-cluster-client-ip'
]);

/** 逐头拷贝并丢弃 {@link SENSITIVE_OUTBOUND_HEADERS}（大小写不敏感）。 */
export function copySafeOutboundHeaders(src: Headers): Headers {
    const out = new Headers();
    for (const [k, v] of src) {
        if (SENSITIVE_OUTBOUND_HEADERS.has(k.toLowerCase())) continue;
        out.set(k, v);
    }
    return out;
}

/** Realistic browser UA pool with weights — cfnew style weighted random selection. */
const BROWSER_UA_POOL = [
    // Chrome (140) — Windows/macOS/Linux/Android
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.7827.103 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/30.0 Chrome/149.0.7827.103 Mobile Safari/537.36',
    // Safari (60) — macOS/iOS/iPadOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 26_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 26_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1',
    // Edge (30)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.4022.69',
    // Firefox (25)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0',
    'Mozilla/5.0 (Android 15; Mobile; rv:151.0) Gecko/151.0 Firefox/151.0',
    // Opera (5)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 OPR/132.0.0.0',
];
const UA_WEIGHTS = [60, 40, 20, 14, 6, 34, 16, 10, 30, 16, 9, 5, 5];

/** Weighted random realistic User-Agent. */
export function randomUserAgent(): string {
    const total = UA_WEIGHTS.reduce((a, b) => a + b, 0);
    let r = Math.random() * total;
    for (let i = 0; i < UA_WEIGHTS.length; i++) {
        r -= UA_WEIGHTS[i];
        if (r <= 0) return BROWSER_UA_POOL[i];
    }
    return BROWSER_UA_POOL[0];
}

const ACCEPT_LANGUAGE_POOL = [
    'en-US,en;q=0.9',
    'en-US,en;q=0.9,zh-CN;q=0.8',
    'en-GB,en;q=0.9',
    'en-CA,en;q=0.9',
    'zh-CN,zh;q=0.9,en;q=0.8',
    'ja-JP,ja;q=0.9,en;q=0.8',
    'ko-KR,ko;q=0.9,en;q=0.8',
    'ru-RU,ru;q=0.9,en;q=0.8',
    'de-DE,de;q=0.9,en;q=0.8',
    'fr-FR,fr;q=0.9,en;q=0.8',
];

/** Random Accept-Language consistent with the fingerprint-randomized UA. */
export function randomAcceptLanguage(): string {
    return ACCEPT_LANGUAGE_POOL[Math.floor(Math.random() * ACCEPT_LANGUAGE_POOL.length)];
}


