import { evictOldest, withTimeout } from "@common";

/**
 * 非内置路径速率限制 — 对齐 cfnew：
 * 对非 UUID/管理路径的 GET 请求做路径字典校验，任一段不在公共路径池中就限流
 * （每 IP 每小时最多 6 次，滑动窗口），触限写 KV `ratelimit:<ip>`（值 = 本窗口请求计数）便于面板查看。
 * 内存窗口为主判定（0 KV），KV 只作跨边缘二次判定与留痕：每 IP 每窗口至多 1 读 + 1 写（F-07/F17）。
 */

export const PUBLIC_PATH_DICTIONARY: ReadonlySet<string> = new Set([
    "about", "account", "acg", "act", "activity", "ad",
    "admin", "ads", "ajax", "album", "albums", "anime",
    "api", "app", "apps", "archive", "archives", "article",
    "articles", "ask", "auth", "avatar", "bbs", "bd",
    "blog", "blogs", "book", "books", "bt", "buy",
    "cart", "category", "categories", "cb", "channel", "channels",
    "chat", "china", "city", "class", "classify", "clip",
    "clips", "club", "cn", "code", "collect", "collection",
    "comic", "comics", "community", "company", "config", "contact",
    "content", "course", "courses", "cp", "data", "detail",
    "details", "dh", "directory", "discount", "discuss", "dl",
    "dload", "doc", "docs", "document", "documents", "doujin",
    "download", "downloads", "drama", "edu", "en", "ep",
    "episode", "episodes", "event", "events", "f", "faq",
    "favorite", "favourites", "favs", "feedback", "file", "files",
    "film", "films", "forum", "forums", "friend", "friends",
    "game", "games", "gif", "go", "go.html", "go.php",
    "group", "groups", "help", "home", "hot", "htm",
    "html", "image", "images", "img", "index", "info",
    "intro", "item", "items", "ja", "jp", "jump",
    "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson",
    "lessons", "lib", "library", "link", "links", "list",
    "live", "lives", "m", "mag", "magnet",
    "mall", "manhua", "map", "member", "members", "message",
    "messages", "mobile", "movie", "movies", "music", "my",
    "new", "news", "note", "novel", "novels", "online",
    "order", "out", "out.html", "out.php", "outbound", "p",
    "page", "pages", "pay", "payment", "pdf", "photo",
    "photos", "pic", "pics", "picture", "pictures", "play",
    "player", "playlist", "post", "posts", "product", "products",
    "program", "programs", "project", "qa", "question", "rank",
    "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php",
    "reg", "register", "res", "resource", "retrieve", "sale",
    "search", "season", "seasons", "section", "seller", "series",
    "service", "services", "setting", "settings", "share", "shop",
    "show", "shows", "site", "soft", "sort", "source",
    "special", "star", "stars", "static", "stock", "store",
    "stream", "streaming", "streams", "student", "study", "tag",
    "tags", "task", "teacher", "team", "tech", "temp",
    "test", "thread", "tool", "tools", "topic", "topics",
    "torrent", "trade", "travel", "tv", "txt", "type",
    "u", "upload", "uploads", "url", "urls", "user",
    "users", "v", "version", "video", "videos", "view",
    "vip", "vod", "watch", "web", "wenku", "wiki",
    "work", "www", "zh", "zh-cn", "zh-tw", "zip",
    "about-us", "access", "accounting", "activation", "address", "advertising",
    "affiliate", "agreement", "alert", "alerts", "analytics-dashboard", "announcement",
    "api-docs", "apply", "archive-news", "article-detail", "attendance", "author",
    "auto", "backup", "banner", "billing", "board", "brand",
    "browse-all", "business", "calendar", "campaign", "career", "cart-checkout",
    "catalog", "certificate", "checkout-success", "client", "cloud", "comment",
    "company-info", "competition", "complaint", "conference", "connect", "console",
    "contact-form", "contest", "contract", "contribute", "control", "cookie",
    "copyright", "coupon", "create", "crm", "currency", "custom",
    "customer", "dashboard-admin", "data-center", "deal", "default", "demo",
    "department", "design", "developer", "development", "device", "directory-list",
    "discounts", "display", "donate", "editor", "email", "employee",
    "employment", "enterprise", "entry", "environment", "error-log", "estimate",
    "exam", "example", "exchange", "experience", "expert", "export",
    "faq-page", "feature", "feedback-form", "finance", "financial", "fleet",
    "flow", "form", "gallery", "gateway", "general", "global",
    "guide", "hardware", "health", "history-page", "holiday", "host",
    "hosting", "identity", "image-gallery", "import", "index-page", "industry",
    "info-center", "information", "inquiry", "install", "instruction", "insurance",
    "integration", "interface", "internal", "invoice", "issue", "job",
    "join", "journal", "key", "knowledge-base", "lab", "landing",
    "language", "launch", "legal", "license", "limited", "location",
    "log", "logging", "logs", "machine", "mail", "manage",
    "management", "manual", "map-view", "market", "marketing", "master",
    "media-center", "member-area", "menu", "merchant", "message-board", "meta",
    "method", "metrics", "misc", "moderator", "module", "monitor",
    "monthly", "navigation", "network", "newsletter", "notification", "office",
    "official", "open", "operation", "opinion", "option", "order-detail",
    "organization", "overview", "owner", "package", "partner", "password",
    "payment-info", "people", "performance", "personal", "phone", "photo-gallery",
    "plan", "platform", "policy", "portal", "portfolio", "position",
    "preferences", "press-release", "preview", "pricing", "print", "privacy-policy",
    "problem", "process", "profile-edit", "project-detail", "promotion", "property",
    "proposal", "public", "publication", "purchase", "quality", "queue",
    "quote", "ranking-list", "rate", "rating", "record", "register-form",
    "release", "report", "reporting", "request", "requirement", "research",
    "resource-center", "response", "result", "resume", "review", "role",
    "rule", "sales", "sample", "schedule", "school", "score",
    "screen", "script", "search-results", "section-list", "security", "server",
    "session", "setting-page", "setup", "shop-cart", "shopping", "signin",
    "signup-form", "site-map", "solution", "staff", "statistics", "status-page",
    "storage", "store-front", "studio", "submission", "subscribe-form", "subscription",
    "success", "summary", "support-center", "survey", "system", "table",
    "task-list", "team-member", "template", "terms-of-service", "test-case", "ticket",
    "timeline", "toolbox", "topic-list", "tour", "tracking-info", "training",
    "transaction", "transfer", "translation", "tutorial", "update", "upgrade",
    "upload-file", "usage", "user-guide", "utility", "validation", "value",
    "vendor", "verification", "version-info", "visitor", "voice", "webmail",
    "workflow",
]);

/**
 * 面板内置路由词 —— 与 `src/worker.ts` 的 switch 分支一一对应
 * （panel / sub / login / logout / secrets / favicon.ico / dns-query / proxy-ip）。
 * 这些词绝不能出现在伪装路径池里：否则订阅下发的「伪装路径」本身就是一个真实路由（F-15 ≡ W1-C-11）。
 */
const BUILTIN_ROUTE_WORDS: ReadonlySet<string> = new Set([
    'panel', 'sub', 'login', 'logout', 'secrets', 'favicon.ico', 'dns-query', 'proxy-ip',
]);

/**
 * 伪装路径池 —— 订阅生成时随机抽取 WS 路径的唯一数据源。
 *
 * 与「限流白名单」（`PUBLIC_PATH_DICTIONARY`）解耦：
 * 池仍由字典派生，保证 `generateWsPath` 产出的路径必然通过 `isPathInDictionary`
 * （否则会被自己的限流打死），但派生时显式剔除内置路由词 ——
 * 字典将来新增/回填任何内置路由词，池也不会被污染。
 */
export const PUBLIC_PATH_POOL: readonly string[] = Array.from(PUBLIC_PATH_DICTIONARY)
    .filter(word => !BUILTIN_ROUTE_WORDS.has(word));

/**
 * 首段是否为内置路由词。
 *
 * XHTTP 入站的路径白名单用它做前置排除：白名单本身按 `isPathInDictionary` 判定，
 * 而该字典目前并不含这些路由词 —— 但这是**当前数据**的巧合，不是契约。
 * 字典将来一旦回填 `panel` / `login` 这类词（F-15 禁止它们进伪装池，却没禁止它们进限流白名单），
 * 仅凭字典判定就会让 `POST /panel/...` 被 XHTTP 接管、面板直接坏掉。
 * 把「内置路由词不可用于协议路径」写成显式判据，比依赖字典内容更稳。
 */
export function isBuiltinRouteWord(word: string): boolean {
    return BUILTIN_ROUTE_WORDS.has(word.toLowerCase());
}

const RATE_LIMIT_WINDOW_MS = 3600000; // 1 小时
const RATE_LIMIT_MAX_REQUESTS = 6;    // 每窗口最多 6 次
const RATE_LIMIT_KV_PREFIX = 'ratelimit:';
const RATE_LIMIT_MAX_TRACKED_IPS = 10000; // 内存条目上限（F-07）

interface RateLimitRecord {
    timestamps: number[];
    /** 本窗口是否已写 KV：把「每次超限 1 写」降为「每 IP 每窗口 1 写」（F-07） */
    kvWritten?: boolean;
    /** 本窗口最近一次跨边缘 KV 判定的时间：每窗口每 isolate 至多 1 次读（F17） */
    kvCheckedAt?: number;
    /** 已确认其他边缘判超限：本窗口内直接拦截，零额外 KV（F17） */
    sharedOver?: boolean;
}

const rateLimitPool = new Map<string, RateLimitRecord>();

/**
 * 路径每一段都必须在公共路径字典中才算合法非内置路径。
 * F-06：空段数组上 `every` 恒真，`//`、`///` 之类路径会被判成「字典内合法路径」而跳过限流与违规计数；
 * 因此先把段内连续斜杠归一，再显式拒绝归一后为空的输入。
 */
export function isPathInDictionary(pathSegments: string[]): boolean {
    const segments = pathSegments.flatMap(seg => seg.split('/')).filter(Boolean);
    if (segments.length === 0) return false;
    // B-10：必须大小写归一。同文件的 isBuiltinRouteWord、worker.ts 的 isXpPathAllowed 都做了，
    // 只有这里漏了 → `/Index.html`、`/Images/a.jpg` 一律被判「字典外」，
    // 而浏览器并发拉取伪装站静态资源时大小写混用很常见（判错会一路推到永久封禁）。
    return segments.every(seg => PUBLIC_PATH_DICTIONARY.has(seg.toLowerCase()));
}

/** 检查是否仍在限流（未超限返回 true） */
export function checkRateLimit(ip: string): boolean {
    if (!ip) return true;
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    const record = rateLimitPool.get(ip);
    if (!record) return true;
    record.timestamps = record.timestamps.filter(t => t > windowStart);
    // F-07：窗口内已无有效时间戳的条目立即回收，不再等「同 IP 再次访问」才过滤
    if (record.timestamps.length === 0) {
        rateLimitPool.delete(ip);
        return true;
    }
    return record.timestamps.length < RATE_LIMIT_MAX_REQUESTS;
}

/** 记录一次限流请求 */
export function recordRateLimit(ip: string): void {
    if (!ip) return;
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    let record = rateLimitPool.get(ip);
    if (!record) {
        // F-07：条目上限保护，超出按插入顺序淘汰最旧条目，长生命周期 isolate 下内存有界。
        // 插入前腾位置（传 MAX-1），插入后不超过 RATE_LIMIT_MAX_TRACKED_IPS。
        evictOldest(rateLimitPool, RATE_LIMIT_MAX_TRACKED_IPS - 1);
        record = { timestamps: [] };
        rateLimitPool.set(ip, record);
    }
    record.timestamps = record.timestamps.filter(t => t > windowStart);
    if (record.timestamps.length === 0) {
        // 窗口整体滚动：清掉上一窗口的 KV 写与共享判定标记，本窗口重新计
        record.kvWritten = false;
        record.kvCheckedAt = 0;
        record.sharedOver = false;
    }
    record.timestamps.push(now);
}

/**
 * 触限时写 KV（ttl 与限流窗口一致），值 = 本窗口内的请求计数，供面板查看与跨边缘二次判定（F17）。
 * F-07：每 IP 每窗口只写一次 —— 首次超限之后的重复超限请求不再产生任何 KV 往返；
 * 写失败不重试（宁可少一次留存，也不把写放大放回来）。
 */
export async function writeRateLimitKV(kv: KVNamespace, ip: string, ctx: { waitUntil(p: Promise<unknown>): void }): Promise<void> {
    if (!kv || !ip) return;
    const record = rateLimitPool.get(ip);
    if (!record || record.kvWritten) return;
    record.kvWritten = true;
    // 跨边缘判定已确认超限时，写回值不得低于阈值，否则会把其他边缘推高的计数覆盖回低位
    const count = record.sharedOver
        ? Math.max(record.timestamps.length, RATE_LIMIT_MAX_REQUESTS)
        : record.timestamps.length;
    ctx.waitUntil(
        withTimeout(kv.put(`${RATE_LIMIT_KV_PREFIX}${ip}`, String(count), { expirationTtl: 3600 }), 2000, 'KV 速率限制写入')
            .catch(() => {})
    );
}

/**
 * 跨边缘二次判定（F17）—— 内存 Map 是 isolate 私有的，攻击者换边缘/放慢节奏即可把计数清零；
 * 这里用 KV 里其他边缘写下的窗口计数做一次兜底判定（cfnew 系没有共享态可用，KV 是唯一不引入新依赖的载体）。
 *
 * 成本控制：本函数只在「路径不在字典里」（本来就要限流的可疑流量）时被调用；
 *   每 IP 每窗口每 isolate 至多 1 次 KV 读（内存记 kvCheckedAt），命中即在本窗口内记住 sharedOver、后续零 KV；
 *   字典内路径（正常伪装浏览）0 次 KV 读。KV 未绑定 / 读失败一律放行，不影响内存主判定。
 */
export async function checkRateLimitShared(kv: KVNamespace | undefined, ip: string): Promise<boolean> {
    if (!kv || !ip) return true;
    const record = rateLimitPool.get(ip);
    if (!record) return true;
    if (record.sharedOver) return false;
    const now = Date.now();
    // 本窗口已读过 KV 就不再读；窗口滚动时 recordRateLimit 会清掉该标记
    if (record.kvCheckedAt && now - record.kvCheckedAt < RATE_LIMIT_WINDOW_MS) return true;
    record.kvCheckedAt = now;
    try {
        const raw = await withTimeout(kv.get(`${RATE_LIMIT_KV_PREFIX}${ip}`), 2000, 'KV 速率限制读取');
        if (raw && Number(raw) >= RATE_LIMIT_MAX_REQUESTS) {
            record.sharedOver = true;
            return false;
        }
    } catch (e) {
        console.warn('[速率限制] KV 共享态读取失败，按内存判定放行:', (e as Error)?.message ?? String(e));
    }
    return true;
}

/**
 * 登录口令认证失败限流 — 与上方非内置路径限流完全独立：
 * 独立 Map 与独立窗口/阈值，避免改动 checkRateLimit 语义影响 firstCheck.ts。
 */
const AUTH_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 分钟
const AUTH_RATE_LIMIT_MAX_FAILURES = 10;          // 每窗口最多 10 次失败
/**
 * B-27：本池的内存条目上限，与 RATE_LIMIT_MAX_TRACKED_IPS 同量级。
 * 池是 isolate 私有的，条目数只受「被攻击过的源 IP 数量」约束 —— 分布式口令爆破
 * （每个 IP 只试一次）可以让内存条目单调增长且永不过期，长生命周期 isolate 下就是内存泄漏。
 */
const AUTH_RATE_LIMIT_MAX_TRACKED_IPS = 10000;

const authFailurePool = new Map<string, number[]>();

/**
 * 「每键时间戳窗口」的通用实现（第 2、3 个池共用；第 1 个池 `rateLimitPool` 因为还带
 * kvWritten / kvCheckedAt / sharedOver 三个跨边缘字段，结构不同，保持独立）。
 *
 * 三条不变式集中在这里，避免复制第二遍时漏掉任何一条：
 *  1. **空即删**：窗口内没有有效时间戳时把键删掉，而不是写回空数组 —— 否则该键永久占一个条目；
 *  2. **插入前封顶**：只在新建条目时 `evictOldest(pool, max - 1)`，保证插入后不超过上限；
 *  3. 空键（无法识别的 IP）一律放行 / 不记账。
 */
function windowAllow(pool: Map<string, number[]>, key: string, windowMs: number, max: number): boolean {
    if (!key) return true;
    const record = pool.get(key);
    if (!record) return true;

    const windowStart = Date.now() - windowMs;
    const valid = record.filter(t => t > windowStart);
    if (valid.length === 0) {
        pool.delete(key);
        return true;
    }
    pool.set(key, valid);
    return valid.length < max;
}

function windowRecord(pool: Map<string, number[]>, key: string, windowMs: number, trackedMax: number): void {
    if (!key) return;
    const now = Date.now();
    const windowStart = now - windowMs;
    const existing = pool.get(key);
    if (!existing) evictOldest(pool, trackedMax - 1);
    const record = (existing || []).filter(t => t > windowStart);
    record.push(now);
    pool.set(key, record);
}

/** 检查认证失败是否仍在允许范围内（未超限返回 true；空 ip 放行） */
export function checkAuthRateLimit(ip: string): boolean {
    // B-27：空即删 + 插入前封顶由 windowAllow / windowRecord 统一保证
    return windowAllow(authFailurePool, ip, AUTH_RATE_LIMIT_WINDOW_MS, AUTH_RATE_LIMIT_MAX_FAILURES);
}

/** 记录一次认证失败（空 ip 不计数） */
export function recordAuthFailure(ip: string): void {
    windowRecord(authFailurePool, ip, AUTH_RATE_LIMIT_WINDOW_MS, AUTH_RATE_LIMIT_MAX_TRACKED_IPS);
}

/** 认证成功后清空该 IP 的失败记录（空 ip 忽略） */
export function resetAuthRateLimit(ip: string): void {
    if (!ip) return;
    authFailurePool.delete(ip);
}

/**
 * S-07：DoH 中继（`/dns-query/<subPath>`）的每 IP 频率限制。
 *
 * 为什么需要：`/dns-query` 在 worker.ts 是**内置路由分支**，不经过 `guardNonBuiltinPath`
 * 的限流闸门；而 `subPath` 随订阅 URL 分发给所有用户，等于一个「持订阅者即可用」的无鉴权
 * DoH 转发器（method / content-type / 2KB 体积已收口，但频率此前没有约束）。
 *
 * 口径：60 秒滑动窗口、每 IP 默认 120 次（≈2 次/秒）—— 正常客户端一次页面加载常见的
 * 并发解析是几十次，120 留足余量；`DOH_RATE_PER_MIN=0` 关闭（回滚开关），非法值回退默认。
 * 与其它池一致：空 ip 放行（无法识别就不该拦）、条目有空即删 + 容量封顶。
 */
const DOH_RATE_WINDOW_MS = 60_000;
const DOH_RATE_PER_MIN_DEFAULT = 120;
const DOH_RATE_MAX_TRACKED_IPS = 10000;
const dohRatePool = new Map<string, number[]>();

function dohRateLimitPerMinute(): number {
    const raw = Number((globalThis as any).env?.DOH_RATE_PER_MIN);
    if (!Number.isFinite(raw) || raw < 0) return DOH_RATE_PER_MIN_DEFAULT;
    return Math.floor(raw);
}

/** 检查该 IP 是否仍在 DoH 频率范围内（未超限返回 true；空 ip / 限流关闭一律放行） */
export function checkDohRateLimit(ip: string): boolean {
    const limit = dohRateLimitPerMinute();
    if (!ip || limit === 0) return true;
    return windowAllow(dohRatePool, ip, DOH_RATE_WINDOW_MS, limit);
}

/** 记录一次 DoH 请求（空 ip / 限流关闭时不记账） */
export function recordDohRequest(ip: string): void {
    if (!ip || dohRateLimitPerMinute() === 0) return;
    windowRecord(dohRatePool, ip, DOH_RATE_WINDOW_MS, DOH_RATE_MAX_TRACKED_IPS);
}
