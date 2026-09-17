import { withTimeout } from "@common";

/**
 * 非内置路径速率限制 — 对齐 cfnew：
 * 对非 UUID/管理路径的 GET 请求做路径字典校验，任一段不在公共路径池中就限流
 * （每 IP 每小时最多 6 次，滑动窗口），触限写 KV `ratelimit:<ip>` 便于面板查看。
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
    "live", "lives", "logout", "m", "mag", "magnet",
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

const RATE_LIMIT_WINDOW_MS = 3600000; // 1 小时
const RATE_LIMIT_MAX_REQUESTS = 6;    // 每窗口最多 6 次
const RATE_LIMIT_KV_PREFIX = 'ratelimit:';

interface RateLimitRecord {
    timestamps: number[];
}

const rateLimitPool = new Map<string, RateLimitRecord>();

/** 路径每一段都必须在公共路径字典中才算合法非内置路径 */
export function isPathInDictionary(pathSegments: string[]): boolean {
    return pathSegments.every(seg => PUBLIC_PATH_DICTIONARY.has(seg));
}

function getClientIP(request: Request): string {
    return request.headers.get('CF-Connecting-IP') || '';
}

/** 检查是否仍在限流（未超限返回 true） */
export function checkRateLimit(ip: string): boolean {
    if (!ip) return true;
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    const record = rateLimitPool.get(ip);
    if (!record) return true;
    record.timestamps = record.timestamps.filter(t => t > windowStart);
    if (record.timestamps.length >= RATE_LIMIT_MAX_REQUESTS) return false;
    return true;
}

/** 记录一次限流请求 */
export function recordRateLimit(ip: string): void {
    if (!ip) return;
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    let record = rateLimitPool.get(ip);
    if (!record) {
        record = { timestamps: [] };
        rateLimitPool.set(ip, record);
    }
    record.timestamps = record.timestamps.filter(t => t > windowStart);
    record.timestamps.push(now);
}

/** 触限时写 KV（ttl 与限流窗口一致），便于 Dashboard 查看 */
export async function writeRateLimitKV(kv: KVNamespace, ip: string, ctx: { waitUntil(p: Promise<unknown>): void }): Promise<void> {
    if (!kv || !ip) return;
    ctx.waitUntil(
        withTimeout(kv.put(`${RATE_LIMIT_KV_PREFIX}${ip}`, new Date().toISOString(), { expirationTtl: 3600 }), 2000, 'KV 速率限制写入')
            .catch(() => {})
    );
}

/**
 * 非内置路径守卫：返回 null 表示放行（路径合法），
 * 返回 Response 表示命中限流/黑名单需直接返回。
 */
export async function rateLimitGuard(request: Request, kv: KVNamespace, ctx: { waitUntil(p: Promise<unknown>): void }, nginxPage: () => Promise<string> | string): Promise<Response | null> {
    const ip = getClientIP(request);
    if (!checkRateLimit(ip)) {
        console.warn(`[速率限制] IP ${ip} 超过非管理员路径请求限制`);
        await writeRateLimitKV(kv, ip, ctx);
        return new Response(await nginxPage(), {
            status: 429,
            headers: {
                'Content-Type': 'text/html; charset=UTF-8',
                'Retry-After': '3600'
            }
        });
    }
    recordRateLimit(ip);
    return null;
}
