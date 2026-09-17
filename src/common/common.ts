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

export function respond(
    success: boolean,
    status: HttpStatus,
    message?: string,
    body?: any,
    customHeaders?: Record<string, string>
): Response {
    const headers = {
        'Content-Type': 'application/json',
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

export function safeErrorMessage(error: any): string {
    return error instanceof Error ? error.message : String(error);
}

/** Alias for safeErrorMessage — matches upstream naming */
export const safeError = safeErrorMessage;

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

/** Decompress gzip-compressed base64-encoded data */
export async function decompressGzipBase64(base64: string): Promise<string> {
    const binaryStr = atob(base64);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
    }
    return await new Response(
        new ReadableStream({
            start(c) {
                c.enqueue(bytes);
                c.close();
            }
        }).pipeThrough(new DecompressionStream('gzip'))
    ).text();
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


