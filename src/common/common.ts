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
 * 按插入顺序淘汰最旧条目，直到 `size <= maxSize`（Map/Set 的迭代顺序就是插入顺序）。
 *
 * 全仓库「内存容器容量兜底」共用这一份实现。三点语义要注意，改动时必须对照调用点：
 *  1) 判据是「超出 maxSize 才删」。插入**之后**调用、要求落库后不超过 MAX 的，传 MAX；
 *     插入**之前**先腾位置的（原写法 `while (size >= MAX)`），传 `MAX - 1`，插入后才正好 ≤ MAX。
 *  2) 只在真超限时迭代，未超限时 0 次分配、0 次迭代。
 *  3) 参数用结构化类型而不是 Map：永久黑名单是 Set，算法完全相同，
 *     不该为了类型差异再写第二份实现。
 */
export function evictOldest<K>(
    container: { size: number; keys(): IterableIterator<K>; delete(key: K): unknown },
    maxSize: number
): void {
    while (container.size > maxSize) {
        const oldest = container.keys().next();
        if (oldest.done) return;
        container.delete(oldest.value);
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

/**
 * 单次 KV **读**的超时（3s）。**唯一来源**：设置缓存（proxySettings / _ver）、WARP 账号与退避标记、
 * 永久黑名单、违规计数共用同一个值。
 * 为什么必须收在一处：这些读几乎都在请求最前面且被 `await`，一条挂住的 KV 读会把整份订阅/整页拖住；
 * 以前这些超时分散成 2000/3000 的字面量，改一处忘一处就会出现「某个读先挂住，其它超时形同虚设」。
 * 取值依据：KV 正常 10~50ms，3s 已经宽容到不会误伤，又能在真挂住时把请求推进下去。
 */
export const KV_READ_TIMEOUT_MS = 3000;

/**
 * 从 env 读数值。**全仓唯一实现**（WS 下行/会话/突发、XHTTP 旋钮、探针总预算都走它）。
 * 语义（顺序即判据）：
 *   - **未设 / 空串** → `fallback`；
 *   - 非数字、负数 → `fallback`（fail-closed：设错了不能静默变成"无上限"或"全关"）；
 *   - **显式 0** → `zeroMeansOff` 时返回 0（关闭/回滚），否则仍是 `fallback`；
 *   - 正数 → 原值。
 *
 * 为什么必须区分「未设」与「显式 0」：默认值一旦不是 0（如下行速率、会话预算），
 * `?? 0` 的写法会把"没设"也当成 0 —— 默认值就永远不生效（本仓库踩过这个坑）。
 * 同时保留显式 0 = 关闭，否则"改默认值"等于"永久失去回滚开关"。
 *
 * 放在本模块（叶子模块、无 import）而不是某个协议文件里：`cores/utils` 与
 * `protocols/websocket/common` 都要用它，谁都不是对方的依赖方向，只有这里两边都拿得到。
 */
export function envNumber(name: string, fallback: number, zeroMeansOff = false): number {
    const value = (globalThis as any).env?.[name];
    if (value === undefined || value === null || value === '') return fallback;
    const raw = Number(value);
    if (!Number.isFinite(raw) || raw < 0) return fallback;
    if (raw === 0) return zeroMeansOff ? 0 : fallback;
    return raw;
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

/** 看门狗默认轮询粒度（调用方可用 intervalMs 覆盖：粒度策略属于协议侧，不在这里猜） */
export const WATCHDOG_INTERVAL_MS = 5000;

export interface SessionWatchdogOptions {
    /** 空闲上限（毫秒）；<= 0 表示不判空闲 */
    idleMs: number;
    /** 最长存活上限（毫秒）；<= 0 / 省略表示不判最长存活 */
    maxMs?: number;
    /** 轮询粒度（毫秒），由调用方按自己协议的自适应策略算好 */
    intervalMs?: number;
    /** 每次 tick 先问「还活着吗」；返回 false 就地停表，不再判超时（用于感知外部关闭） */
    isAlive?: () => boolean;
    /** 到期回调。reason 是给人看的原因，文案由本函数生成 */
    onExpire: (reason: string) => void;
}

export interface SessionWatchdog {
    /** 记一次活动（双向流量都应调用；应放在热路径上，O(1)） */
    touch(): void;
    /** 停表。幂等；到期或连接结束时调用 */
    stop(): void;
}

/**
 * 通用会话看门狗：轮询「空闲」与「最长存活」两个上限，到期回调**一次**后自行停表。
 *
 * 为什么是轮询而不是每次活动重设定时器：调用方在数据面热路径上（下行每秒数千块），
 * 逐块 clearTimeout + setTimeout 本身就是可观开销；固定粒度轮询把成本摊成
 * 「每连接每 intervalMs 一次空跑」。粒度由调用方按自己的超时量级自适应。
 *
 * 为什么 stop() 放在 onExpire 之前调用：这就是「到期只收口一次」的全部保证 ——
 * 定时器已清，后续 tick 不存在；调用方无需再维护 expired 标志。
 *
 * 两个上限都 <= 0 时返回一个空实现（显式 0 = 关闭该保护），调用方不必自己判空。
 */
export function createSessionWatchdog(opts: SessionWatchdogOptions): SessionWatchdog {
    const idleMs = opts.idleMs > 0 ? opts.idleMs : 0;
    const maxMs = opts.maxMs && opts.maxMs > 0 ? opts.maxMs : 0;
    if (!idleMs && !maxMs) return { touch() { /* 两项都关 */ }, stop() { /* 无定时器 */ } };

    const intervalMs = Math.max(1, Math.floor(opts.intervalMs || WATCHDOG_INTERVAL_MS));
    const startedAt = Date.now();
    let lastActivity = startedAt;
    let timer: ReturnType<typeof setInterval> | null = null;

    const stop = (): void => {
        if (timer !== null) {
            clearInterval(timer);
            timer = null;
        }
    };

    timer = setInterval(() => {
        if (opts.isAlive && !opts.isAlive()) { stop(); return; }
        const now = Date.now();
        if (maxMs && now - startedAt >= maxMs) {
            stop();
            opts.onExpire(`reached max ${Math.round(maxMs / 1000)}s`);
            return;
        }
        if (idleMs && now - lastActivity >= idleMs) {
            stop();
            opts.onExpire(`idle ${Math.round((now - lastActivity) / 1000)}s >= ${Math.round(idleMs / 1000)}s`);
        }
    }, intervalMs);
    // 让 Node 桩环境（tools/*.test.mjs）能正常退出；workerd 里 setInterval 返回 number，?. 是 no-op
    (timer as unknown as { unref?: () => void })?.unref?.();

    return {
        touch(): void { lastActivity = Date.now(); },
        stop
    };
}

export interface SignatureGate {
    /** 签名与上次不同 → 返回 true 并记住；相同 → false。用于「生效值只在变化时打一行」 */
    isNew(signature: string): boolean;
}

/** 「同一签名只处理一次」闸门。三个调用点（伪装熔断阈值 / WS 连接上限 / 会话看门狗）共用。 */
export function createSignatureGate(): SignatureGate {
    let last = '';
    return {
        isNew(signature: string): boolean {
            if (signature === last) return false;
            last = signature;
            return true;
        }
    };
}

/**
 * 跨请求安全单飞（同键去重）。**不共享 Promise** —— 这是平台约束，不是风格问题。
 *
 * workerd 的 `handle_cross_request_promise_resolution` 规定：请求 A 里创建的 Promise 只能由
 * A 自己 settle；A 结束后它「永远无法达成」，B 去 await 会拿到
 * “This promise was created by a request that has since ended, so it can never settle.”
 * 而 `Map<key, Promise>` 这种经典单飞表恰好是这么写的 —— 本项目三处都踩过
 * （伪装图片取图、KV 配置加载、反代池解析），客户端中途 abort（浏览器取消 <img>、
 * 用户跳走）时 A 先结束，单飞表里留下的就是一个永远不会 settle 的 Promise。
 *
 * 这里改成只共享「谁正在取」这一**事实**（Set），不共享任何 Promise：
 *   - 生产者在拿到结果、写进缓存后清标记（含失败/异常路径）；
 *   - 等待方用**本请求内创建的定时器**轮询 `read()`，读到即返回；标记消失就自己取；
 *   - 有界等待（默认 40 × 25ms = 1s），绝不无限等；
 *   - 等待方还能带一个 `abandonWhen()` 判据：调用方用它表达「生产者虽然还在跑，但没有进展」，
 *     满足即提前放弃（等着等着发现没戏，比等满上界再重算更划算）。
 *
 * 标记的**所有权归先到者**：等待方即便放弃等待、自己取了一次，也不会摘掉生产者的标记 —
 * 否则第三个调用者立刻看到「没人解析」再算一遍，正是本函数要防的放大。
 *
 * `read()` 必须是同步、幂等、只读已落地结果的函数（拿不到就返回 null）。
 */
export async function crossRequestSingleFlight<T>(
    markers: Set<string>,
    key: string,
    read: () => T | null,
    produce: () => Promise<T | null>,
    options: { tries?: number; delayMs?: number; abandonWhen?: () => boolean } = {}
): Promise<T | null> {
    const ready = read();
    if (ready !== null) return ready;

    if (markers.has(key)) {
        const tries = options.tries ?? 40;
        const delayMs = options.delayMs ?? 25;
        for (let i = 0; i < tries; i++) {
            if (!markers.has(key)) break;
            // 生产者没有进展就不再等（判据由调用方给，本函数不猜什么算「进展」）
            if (options.abandonWhen?.()) break;
            await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
            const waited = read();
            if (waited !== null) return waited;
        }
        const afterWait = read();
        if (afterWait !== null) return afterWait;
        // 标记还在（或刚消失）却始终读不到结果：生产者拿到的是不可缓存结果（如流式响应）
        // 或它已卡住 —— 此时自己去取一次，绝不继续等别人的 Promise。
    }

    const ownsMarker = !markers.has(key);
    if (ownsMarker) markers.add(key);
    try {
        return await produce();
    } finally {
        if (ownsMarker) markers.delete(key);
    }
}

/**
 * Build optional HSTS header object based on the HSTS_ENABLE flag (cfnew semantics).
 * 默认开启：未设置 / '1' / 'true' 都加 HSTS；只有显式 '0' / 'false' 才不加。
 */
export function hstsHeaders(env: Record<string, string | undefined> | undefined): Record<string, string> {
    const flag = env?.HSTS_ENABLE;
    if (flag === '0' || flag === 'false') return {};
    return { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload' };
}

/**
 * F13：面板/登录/密钥/错误页与 JSON 接口的通用安全响应头（HSTS 按 env 开关，**默认加**）。
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


