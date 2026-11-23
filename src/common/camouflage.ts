import {
    evictOldest,
    escapeHtml,
    fetchWithTimeout,
    withTimeout,
    hstsHeaders,
    randomUserAgent,
    randomAcceptLanguage,
    copySafeOutboundHeaders,
    crossRequestSingleFlight,
    createSignatureGate
} from "@common";
// S-03：客户端 IP 的唯一取用点（含形态校验；本文件用它作令牌桶的每 IP 键）
import { clientIp } from './client-ip';

/**
 * URL 伪装 — 对齐 cfnew 的伪装首页全路径反代：
 *  - 伪装域名来源：env `homepage`/`HOMEPAGE`/`URL`/`FALLBACK`（支持 `a|b|c` 列表随机），
 *    特殊值 `nginx` 渲染内建欢迎页（hostSniList 仅用于节点 HOST/SNI，不参与伪装页）。
 *    B-29：未设置**不会**落到 1101 页 —— init() 恒给 `fallbackDomain` 兜底一个域名，
 *    真正的「未配置」行为是反代到那个兜底域；契约见 resolveMaskTarget。
 *  - 对非 / 且非管理路径的请求做反向代理，保留原路径与查询串。
 *  - 图片伪装：探测到图片 URL 时以 data URI 包装或流式直传，含假阳性保护（HTML 降级）。
 *  - 文本类（text/javascript/json/xml）且 <2MB 时缓冲并重写上游 host，内存缓存 5 分钟。
 *  - 其余内容流式转发，过滤可能泄露服务器信息的响应头与 CF 入站头。
 *  - 任何阶段失败降级：首页根路径重试 → nginx 欢迎页。
 *  - **P0**：图片目标取图失败（超时/网络）→ 本地 nginx 页 + 30s 负缓存，
 *    **不再**回落全路径反代（那条路会把请求路径原样转发给伪装域）。
 *  - **P1**：秘密文件 / 版本控制探测族（`.env`、`.git/HEAD` …）→ 朴素 404，零出站
 *    （见 isProbePath / probeNotFoundResponse）。
 */

const MASK_HOME_CACHE_TTL = 300000;       // 5 分钟
/**
 * 图片缓存的出厂默认值（张数 / 总字节）。**两者都可 env 覆盖**：`MASK_IMG_CACHE_MAX` /
 * `MASK_IMG_CACHE_BYTES`（见 readBudgetConfig）。
 *
 * 为什么做成可配：壳页的命中率直接决定「图片路径是否回源」，而访客量级与图源单图体积
 * （几十 KB ~ 2 MB）能差两个数量级 —— 写死 12 张在大图床上几乎等于「每次都回源」，
 * 在小图上又白占内存。改这两个值同样受「单条超预算不入缓存」约束（见 cacheImageEntry）。
 */
const MASK_IMAGE_CACHE_MAX_DEFAULT = 12;
/**
 * 图片缓存的**总字节预算**（按缓存的**原始字节**计）。
 *
 * 缓存存的是原始图片字节（壳页模式的正文只有 ~300B，不需要缓存 HTML）；`<img>` 子请求
 * 复用同一份字节，因此既省掉整段 base64，也让内存口径从「HTML（膨胀 4/3）」回到 raw。
 * 仍必须按字节封顶：12 张 × 2MB 会逼近 isolate 的 128MB 并对 GC 形成持续压力。
 */
const MASK_IMAGE_CACHE_MAX_BYTES_DEFAULT = 8 * 1024 * 1024;
const MASK_HOME_CACHE_MAX = 100;          // 文本缓存最大条目
/**
 * 首页缓存的**总字节预算**。这是本文件里最关键的资源上限：
 * isolate 内存只有 128MB，而单条缓存正文最长可达 `TEXT_REWRITE_MAX_DEFAULT`（默认 1MB，
 * 可用 env `MASK_TEXT_REWRITE_MAX` 调大 —— 调大后这条预算的相对权重同步上升）。
 * 只按「条目数」限流时，100 条 × 1MB = 100MB，缓存本身就是内存炸弹 ——
 * 逼近上限后 V8 会持续高强度 GC，而 GC 消耗的是**CPU 时间**，
 * 表现为「CPU 超限规律性复发」而不是内存报错。因此必须按字节封顶。
 * 4MB 相对 128MB 只是零头，命中率损失远小于 GC 抖动带来的代价。
 */
const MASK_HOME_CACHE_MAX_BYTES = 4 * 1024 * 1024;
/**
 * 单响应改写上限的出厂默认值（字节）。env `MASK_TEXT_REWRITE_MAX` 可覆盖（见 readBudgetConfig）。
 *
 * ⚠️ 它同时是三个东西的边界，改动前请一起读：
 *  1. **缓冲分支的门槛**（`contentLength < 它` 才整份读取 + 改写 + 可缓存，见 camouflageProxy）；
 *  2. **流式分支的切断点**（越过它余下一律原样流出，见 streamWithBudgetRewrite）；
 *  3. 首页缓存**单条正文**的上界（缓存条目越大，`MASK_HOME_CACHE_MAX_BYTES` 装得下的条数越少）。
 *
 * 上界受两个因素夹住：isolate 128MB（`collected` 会整份累积）；以及单 IP 额度
 * `MASK_TEXT_IP_CAP`（默认 4MiB/60s）—— 调大它意味着「一个页面就吃掉单 IP 额度的一大半」，
 * 之后同 IP 的请求统一 1101，反而变成「该站大页面必错」这种可枚举指纹。
 */
const TEXT_REWRITE_MAX_DEFAULT = 1 * 1024 * 1024; // 1MB
/** 下界：低于它连一个读块/页面头都装不下，等于把改写关掉（同 `MASK_TEXT_*` 的回退语义） */
const TEXT_REWRITE_MAX_MIN = 64 * 1024;
const FETCH_TIMEOUT = 39000;

/**
 * 伪装反代的准入额度：**两个令牌桶**，替代原先「60 次/分钟」的计数窗口。
 *
 * 为什么改：4K 播放（分片 + 接口轮询）在 30~60 秒内就会把「次数」额度烧光，之后整站
 * 伪装路径统一降级 1101 —— 那是形态不匹配，不是滥用。真正决定 CPU 的是**被改写的字节数**
 * （decode + replaceAll + encode 与体积线性），所以拆成两条互不干扰的账：
 *
 *  - requests：每次进入伪装反代、且没被 1101/nginx 短路的请求记 1 个令牌。
 *    它约束的是每请求固定成本（头处理、缓存查询、分支判定）与出口带宽。
 *  - textBytes：文本响应**实际被改写**的字节。这是唯一的 CPU 驱动项。
 *
 * 为什么不再单独建「relay 字节桶」：二进制（图片/分片）的出口量已被 requests 的速率间接限住
 * （速率 × 平均单块），而它的 CPU 成本在上一轮优化后已降到 ~0.001ms/MB 量级；再叠一层字节桶
 * 只会在正常 4K 播放时误伤，且「软失败」语义下它并不构成限速（评审两轮都指出这一点）。
 *
 * 语义（评审后定稿）：
 *  - 令牌惰性补充（无定时器），dt 取非负值（时钟回拨不会多补）。
 *  - 桶耗尽只拦**新**请求，不中断在途响应（中断视频流比让它播完更糟）。
 *  - 单个响应的成本 > 桶容量时**放行且不记账**：容量表达的是「稳态允许多大的页面」，
 *    不是「单个页面不得大于它」；否则会出现「该站 >N MB 的文件必错」这种可枚举指纹。
 *  - textBytes 采用「先预留、按实际改写量结算退款」。额度不足时**降级为 1101，而不是把
 *    `未改写的正文原样流出`** —— 未改写正文里带着上游域名，是伪装面最硬的指纹。
 *
 *    ⚠️ 已知遗留（不是本规则能覆盖的）：`streamWithBudgetRewrite` 在单个响应**超过改写上限
 *    `TEXT_REWRITE_MAX_DEFAULT`（默认 1MB，env `MASK_TEXT_REWRITE_MAX` 可调）** 时会停止
 *    改写、把尾部原样流出，那里确实会露出上游域名。
 *    它由体积触发（与额度无关），且既有测试显式钉住了这个行为
 *    （`tools/camouflage-cpu.test.mjs` 的「超大 chunked：预算外部分原样保留」）。
 *    换言之：**上限以内的文本永远不会流出未改写内容；越过上限的尾部仍会**，属于待办而非已修。
 *  - 所有阈值可用 env 覆盖；非法值回退默认并 warn，**绝不 fail-open 成无上限**。
 */
const MASK_REQ_RATE_DEFAULT = 20;                  // 令牌/秒
const MASK_REQ_CAP_DEFAULT = 200;                  // 突发容量（≈ 6 个冷首屏，含图片资源）
const MASK_TEXT_RATE_DEFAULT = 1024 * 1024;        // 1 MiB/s 可持续改写量
const MASK_TEXT_CAP_DEFAULT = 16 * 1024 * 1024;    // 16 MiB 突发容量
const MASK_TEXT_PER_IP_DEFAULT = 4 * 1024 * 1024;  // 单 IP 窗口内可改写字节
const MASK_TEXT_IP_WINDOW_MS = 60 * 1000;          // 单 IP 记账窗口
const MASK_TEXT_IP_MAX_TRACKED = 1024;             // 单 IP 记账表上限（超出丢最旧）

interface BudgetConfig {
    reqRate: number;
    reqCap: number;
    textRate: number;
    textCap: number;
    textPerIp: number;
    /** 单响应改写上限（字节） */
    rewriteMax: number;
    /** 图片缓存张数上限 */
    imgCacheMax: number;
    /** 图片缓存总字节预算 */
    imgCacheBytes: number;
}

type TokenBucket = { tokens: number; last: number };

const maskReqBucket: TokenBucket = { tokens: MASK_REQ_CAP_DEFAULT, last: 0 };
const maskTextBucket: TokenBucket = { tokens: MASK_TEXT_CAP_DEFAULT, last: 0 };
/** 降级日志限频（每桶 1 条/秒），避免攻击期刷爆 Workers Logs */
const maskDegradeLogAt: Record<string, number> = { req: 0, text: 0 };
/** 「生效阈值只在 env 变化时打一行」的闸门（与连接上限、会话看门狗共用同一实现） */
const budgetGate = createSignatureGate();

/**
 * 阈值表 —— **唯一来源**：名字、默认值、下界、取整规则、落到哪个字段，只写这一次。
 * readBudgetConfig 按它读，logBudgetOnce 按它对比和打印。
 *
 * 为什么不用「代码里逐个 pick() + 平行数组做回退提示」：那样加一个 knob 要同步改三处
 * （读取、sig、names），漏一处就是「回退提示指向错的 env」；而且每个 env 名会以
 * 字符串字面量出现两次（字面量在混淆阶段不可密文化，属于纯体积损失）。
 */
type BudgetSpec = {
    readonly key: string;
    readonly field: keyof BudgetConfig;
    readonly def: number;
    readonly min: number;
    /** 非负整数（张数这类） */
    readonly int?: boolean;
};

const BUDGET_SPEC: readonly BudgetSpec[] = [
    { key: 'MASK_REQ_BPS', field: 'reqRate', def: MASK_REQ_RATE_DEFAULT, min: 1 },
    { key: 'MASK_REQ_CAP', field: 'reqCap', def: MASK_REQ_CAP_DEFAULT, min: 1 },
    { key: 'MASK_TEXT_BPS', field: 'textRate', def: MASK_TEXT_RATE_DEFAULT, min: 1024 },
    { key: 'MASK_TEXT_CAP', field: 'textCap', def: MASK_TEXT_CAP_DEFAULT, min: 64 * 1024 },
    { key: 'MASK_TEXT_IP_CAP', field: 'textPerIp', def: MASK_TEXT_PER_IP_DEFAULT, min: 64 * 1024 },
    { key: 'MASK_TEXT_REWRITE_MAX', field: 'rewriteMax', def: TEXT_REWRITE_MAX_DEFAULT, min: TEXT_REWRITE_MAX_MIN },
    { key: 'MASK_IMG_CACHE_MAX', field: 'imgCacheMax', def: MASK_IMAGE_CACHE_MAX_DEFAULT, min: 1, int: true },
    { key: 'MASK_IMG_CACHE_BYTES', field: 'imgCacheBytes', def: MASK_IMAGE_CACHE_MAX_BYTES_DEFAULT, min: 64 * 1024 }
];

function readBudgetConfig(env: any): BudgetConfig {
    // 非法值（NaN / 负数 / 过小）一律回退默认：设错 env 不能让伪装面全挂，
    // 也不能反过来 fail-open 把三轮才稳住的 CPU 保护静默撤掉
    const cfg = {} as BudgetConfig;
    for (const spec of BUDGET_SPEC) {
        const raw = env?.[spec.key];
        const num = raw === undefined || raw === null || raw === '' ? NaN : Number(raw);
        const value = Number.isFinite(num) && num >= spec.min ? num : spec.def;
        cfg[spec.field] = spec.int ? Math.floor(value) : value;
    }
    return cfg;
}

/** 生效阈值只在 env 变化时打一行，便于灰度期核对，避免每请求刷日志 */
function logBudgetOnce(env: any, cfg: BudgetConfig): void {
    const isEmpty = (v: unknown): boolean => v === undefined || v === null || v === '';
    const rows = BUDGET_SPEC.map((spec) => ({ spec, raw: env?.[spec.key] as unknown }));
    if (rows.every(({ raw }) => isEmpty(raw))) return;
    const sig = rows.map(({ raw }) => String(raw ?? '')).join('|');
    if (!budgetGate.isNew(sig)) return;
    console.log(`[伪装熔断] 生效阈值 req=${cfg.reqRate}/s cap=${cfg.reqCap} text=${cfg.textRate}B/s`
        + ` cap=${cfg.textCap}B perIP=${cfg.textPerIp}B rewriteMax=${cfg.rewriteMax}B`
        + ` imgCache=${cfg.imgCacheMax}张/${cfg.imgCacheBytes}B`);
    // 设错 env 必须可见：回退是静默的，但"回退了哪个"要能一眼看出来（限频同上一行）
    const bad = rows
        .filter(({ spec, raw }) => !isEmpty(raw) && Number(raw) !== cfg[spec.field])
        .map(({ spec }) => spec.key);
    if (bad.length) console.warn(`[伪装熔断] 非法或过低、已回退默认值的 env：${bad.join(', ')}`);
}

function refillBucket(bucket: TokenBucket, rate: number, cap: number, now: number): number {
    if (bucket.last === 0) {
        bucket.last = now;
        bucket.tokens = cap;
        return bucket.tokens;
    }
    // 时钟回拨时 dt 取 0：否则负 dt 会凭空"补"令牌，额度被绕过
    const dt = Math.max(0, now - bucket.last) / 1000;
    bucket.last = now;
    bucket.tokens = Math.min(cap, bucket.tokens + dt * rate);
    return bucket.tokens;
}

/** 结构化消耗：额度不足返回 false。cost 恒 ≤ cap（准入成本被 TEXT_ADMIT_COST 压住），
 *  因此不再需要"单次成本 > 容量就放行"的分支——那条分支会与退款逻辑组合成"永不扣费"的后门。 */
function takeTokens(bucket: TokenBucket, rate: number, cap: number, cost: number): boolean {
    const available = refillBucket(bucket, rate, cap, Date.now());
    if (available < cost) return false;
    bucket.tokens = available - cost;
    return true;
}

function returnTokens(bucket: TokenBucket, cap: number, amount: number): void {
    if (amount <= 0) return;
    bucket.tokens = Math.min(cap, bucket.tokens + amount);
}

/**
 * 单次**准入**成本。实际改写量在结算时按真实字节扣/退，因此准入只需要一个小的、稳定的
 * 门槛值 —— 若按"整页大小"或"`budget.rewriteMax`"预留，并发几个未知长度的文本响应就会把
 * per-IP 额度吃光（评审 BLOCKER：4 个并发 1MiB 预留 = 4MiB 上限直接见底）。
 */
const TEXT_ADMIT_COST = 64 * 1024;
/** per-IP 请求额度的窗口（与文本额度的 60s 分开：请求是秒级突发问题） */
const REQ_IP_WINDOW_MS = 10 * 1000;

type IpMeter = { amount: number; at: number };
const maskTextByIp = new Map<string, IpMeter>();
const maskReqByIp = new Map<string, IpMeter>();

/**
 * 惰性衰减的 per-IP 额度。**不是**"成功就刷新时间戳"的窗口 —— 那会让窗口永不结束
 * （累计用满后要静默一整个窗口才恢复，NAT 出口下等于全屋被封）。
 * 这里按「距上次更新流逝的比例」线性回落到 0。
 */
function ipRemaining(map: Map<string, IpMeter>, ip: string, cap: number, windowMs: number, now: number): number {
    const rec = map.get(ip);
    if (!rec) return cap;
    const decayed = Math.max(0, rec.amount - ((now - rec.at) / windowMs) * cap);
    return Math.max(0, cap - decayed);
}

/** 记账（amount 可为负：结算退款时用）。负数下限截到 0。 */
function ipCharge(map: Map<string, IpMeter>, ip: string, cap: number, windowMs: number, now: number, amount: number): void {
    if (!ip) return;
    const rec = map.get(ip);
    const decayed = rec ? Math.max(0, rec.amount - ((now - rec.at) / windowMs) * cap) : 0;
    if (!rec && map.size >= MASK_TEXT_IP_MAX_TRACKED) evictOldest(map, MASK_TEXT_IP_MAX_TRACKED - 1);
    map.set(ip, { amount: Math.max(0, decayed + amount), at: now });
}

function maskRequestAllowed(cfg: BudgetConfig, ip: string): boolean {
    const now = Date.now();
    // per-IP 先判：一个 IP 不应该能把整个 isolate 打成 1101（评审 MAJOR：否则 20 req/s 即可全站降级）
    const ipCap = cfg.reqRate * 3;
    if (ip && ipRemaining(maskReqByIp, ip, ipCap, REQ_IP_WINDOW_MS, now) < 1) return false;
    if (!takeTokens(maskReqBucket, cfg.reqRate, cfg.reqCap, 1)) return false;
    ipCharge(maskReqByIp, ip, ipCap, REQ_IP_WINDOW_MS, now, 1);
    return true;
}

type TextReservation = { ip: string; reserved: number };

/**
 * 文本改写额度预留：只扣一个**准入成本**（TEXT_ADMIT_COST），真实改写量在 settle 里结算。
 * 返回 null 表示额度不足，调用方必须给 1101（**不得**退化成"原样流出"）。
 * 单 IP 先判、再判全局：一个 IP 无法用一条大页面把整桶掏空。
 */
function reserveTextBudget(cfg: BudgetConfig, ip: string, cost: number): TextReservation | null {
    const now = Date.now();
    const admit = Math.min(cost > 0 ? cost : 1, TEXT_ADMIT_COST);
    if (ip && ipRemaining(maskTextByIp, ip, cfg.textPerIp, MASK_TEXT_IP_WINDOW_MS, now) < admit) return null;
    if (!takeTokens(maskTextBucket, cfg.textRate, cfg.textCap, admit)) return null;
    ipCharge(maskTextByIp, ip, cfg.textPerIp, MASK_TEXT_IP_WINDOW_MS, now, admit);
    return { ip, reserved: admit };
}

/**
 * 按实际改写量结算：多退少扣。
 * 少扣时允许全局令牌暂时为负（由补充自愈）—— 这样"单个超大页面"不会被一刀切拒掉，
 * 也就不会留下"该站 >N MB 的文件必错"这种可枚举指纹。
 */
function settleTextReservation(cfg: BudgetConfig, reservation: TextReservation | null, actual: number): void {
    if (!reservation) return;
    const delta = reservation.reserved - Math.max(0, actual);
    if (delta > 0) {
        returnTokens(maskTextBucket, cfg.textCap, delta);
        if (reservation.ip) ipCharge(maskTextByIp, reservation.ip, cfg.textPerIp, MASK_TEXT_IP_WINDOW_MS, Date.now(), -delta);
    } else if (delta < 0) {
        maskTextBucket.tokens -= -delta;
        if (reservation.ip) ipCharge(maskTextByIp, reservation.ip, cfg.textPerIp, MASK_TEXT_IP_WINDOW_MS, Date.now(), -delta);
    }
}

/** 降级日志：带桶名/成本/生效阈值，按桶限频 1 条/秒 */
function logMaskDegrade(bucket: 'req' | 'text', cfg: BudgetConfig, cost = 0): void {
    const now = Date.now();
    if (now - (maskDegradeLogAt[bucket] || 0) < 1000) return;
    maskDegradeLogAt[bucket] = now;
    if (bucket === 'req') {
        console.warn(`[伪装熔断] requests 桶耗尽（rate=${cfg.reqRate}/s cap=${cfg.reqCap}），降级内建页`);
    } else {
        console.warn(`[伪装熔断] textBytes 桶耗尽（rate=${cfg.textRate}B/s cap=${cfg.textCap}B cost=${cost}B），降级内建页`);
    }
}

type CacheEntry = {
    body: string;
    status: number;
    contentType: string;
    time: number;
    /**
     * 该条目占用的近似字节数（O(1) 取值，不做真实编码）。
     * 首页缓存与图片缓存都按字节记账（图片另有张数上限），故为可选。
     */
    bytes?: number;
    /**
     * B-25：写入时的**完整安全响应头快照**（`filterResponseHeaders` 的结果）。
     * 原实现只存 contentType，命中时重建的响应就丢了 Location / Content-Language /
     * Last-Modified 等头 —— 「命中」与「未命中」的响应头集合系统性不同，本身就是
     * 「这份页面来自 isolate 内存」的指纹；3xx 更会退化成「没有 Location 的 3xx」。
     * 旧条目没有该字段 → 按 `?? []` 退化处理，自然完成结构迁移。
     */
    headers?: [string, string][];
};

/**
 * 图片缓存条目：存**原始字节**。
 *
 * 壳页模式下正文只有 ~300B（`<img src="/?<param>=<hash>">`），所以这里不再需要保存 HTML；
 * 复用同一份字节给壳页与 `<img>` 子请求，也顺带省掉了整段 base64。
 * `data` 模式（`MASK_IMG_MODE=data`）只为回滚保留，会在命中时现算 base64。
 * `bytes` 是**原始字节数**，用于 8MB 预算记账（按 raw 计比按 HTML 计更省）。
 */
type ImageCacheEntry = {
    body: ArrayBuffer;
    status: number;
    contentType: string;
    time: number;
    bytes: number;
    /** 内容哈希 ETag（旧条目没有这个字段 → 视为未命中，顺带完成结构版本迁移） */
    etag: string;
};

const maskHomeCache = new Map<string, CacheEntry>();
const maskImageCache = new Map<string, ImageCacheEntry>();
let maskHomeCacheBytes = 0;
let maskImageCacheBytes = 0;

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
    // S-03：两个入参都来自请求（host = URL 的 host，accessIP = `CF-Connecting-IP`），且都被直接
    // 拼进 HTML 文本与 <title>。Host 头可伪造；CF-Connecting-IP 在「前面还挂了一层反代」的部署里
    // 同样由调用方提供 —— 不转义就是反射型注入。渲染侧一律走 escapeHtml（本仓已有，此前未用）。
    // （键侧即限流/黑名单用的 IP 形态校验在 firstCheck.ts，不在本文件范围，见交付报告。）
    const safeHost = escapeHtml(host);
    const safeIP = escapeHtml(accessIP);
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
<title>Worker threw exception | ${safeHost} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0;background:#f7f7f7;color:#333;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}#cf-wrapper{max-width:960px;margin:0 auto;padding:40px 20px}.cf-error-title{font-size:44px;line-height:1.1;margin:0 0 10px;color:#bd2426;font-weight:400}.cf-error-description{font-size:20px;margin:0 0 24px;color:#666}.cf-subheadline{font-size:16px;margin:0 0 8px}.cf-section{margin:24px 0}.cf-columns{display:flex;flex-wrap:wrap;gap:24px}.cf-column{flex:1 1 260px;min-width:0}.cf-error-footer{border-top:1px solid #ddd;margin-top:32px;padding-top:12px;font-size:13px;color:#888}a{color:#2f7bbf;text-decoration:none}a:hover{text-decoration:underline}</style>
<!-- 上面这段内联样式是必要的：本部署没有 /cdn-cgi/styles/cf.errors.css（该路径会被反代到上游 → 404），
     只留外链会让这张错误页退化成"无样式纯文本"，比不伪装更显眼。 -->
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
                            <p>You've requested a page on a website (${safeHost}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>
                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${safeHost}.</p>
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
        <span class="hidden" id="cf-footer-ip">${safeIP}</span>
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
 * 1101 降级页的统一出口（熔断 / 文本额度耗尽 / 未设置伪装域名 共用）。
 *
 * 状态码用 **500** 而不是 200：真实 Cloudflare 的 1101「Worker threw exception」是 5xx，
 * 一张 200 的错误页本身就是可判定特征（`curl -sI` 即可发现"错误页配 200"）。
 * 保留 200 会让整条 cfnew 血统的部署共享同一个指纹。
 */
export async function cf1101Response(host: string, accessIP: string, env: any): Promise<Response> {
    return new Response(await cf1101Page(host, accessIP), {
        status: 500,
        headers: withHsts({ 'Content-Type': 'text/html; charset=UTF-8' }, env) as Record<string, string>
    });
}

/**
 * 黑名单 / 限流拦截的统一出口：1101 伪装页 + 429。
 * firstCheck.ts 的三处拦截与 worker.ts 的 WS 路径字典拦截共用（此前是四份逐字重复的 Response 构造）。
 *
 * 刻意**不带 `Retry-After: 3600`**：真实 Cloudflare 的 429 不会给出这种整小时的固定值，
 * 而"429 + 3600"这个组合在 cfnew 血统里是稳定特征。
 */
export async function cf1101RateLimitedResponse(host: string, accessIP: string): Promise<Response> {
    return new Response(await cf1101Page(host, accessIP), {
        status: 429,
        headers: { 'Content-Type': 'text/html; charset=UTF-8' }
    });
}

/**
 * P1：秘密文件 / 版本控制探测族（`.env`、`.git/HEAD`、`.docker/config.json`、`.pypirc` …）。
 *
 * 这是全网扫描器最高频的一族，且它们**既不是内置路由，也不在伪装字典里** —— 按原逻辑会一路
 * 走到 camouflageProxy，把**同一条路径**转给伪装域。后果三件：
 *  1. Cloudflare 的 `potentialvulnerabilityscan` 检测把这次出站也算进「同族探测」，
 *     后台多出一类无法处置的「An outbound fetch matched the same probe family」；
 *  2. 图片目标形态下这些路径还会拿到 200 壳页 ——「所有路径都 200」是最硬的指纹，
 *     扫描器会把 `.env` / `.git/config` 记成「存在(200)」；
 *  3. 每次探测都要付一次出站（图片形态下甚至 5s wall time）。
 * 直接回朴素 404 与真实站点对 `.env` 的回答一致，且把出站彻底省掉。
 *
 * 分隔符约束（`$` / `/` / `.`）不是可有可无的：裸前缀会连 `/.environment`、
 * `/.gitignore`、`/.awsome` 一起吃掉，那些属于正常页面而不是探测。
 *
 * **必须按「段」匹配，不能只锚定首段**：线上样本里出现最多的触发器是 `/panel/.env`
 * （探测文件名跟在内置路由前缀之后），只锚 `^/\.` 会漏掉它。
 */
const PROBE_PATH_RE = /(?:^|\/)\.(?:env|git|svn|hg|ds_store|aws|docker|npmrc|pypirc|htpasswd|ssh|bash_history)(?:$|[/.])/i;

/**
 * 是否属于「秘密文件 / 版本控制」探测族（任意路径段命中即算）。
 *
 * `/.well-known/`（security.txt、acme-challenge）必须继续走伪装反代而不是 404 ——
 * 这条契约由 `tools/camouflage-cpu.test.mjs` 的负例钉住，**不**在这里加一行
 * `startsWith` 白名单：正则匹配不到它，那行白名单永远不会被求值为真（死代码），
 * 而将来若有人往词表里加了 `well` 之类的词，测试会直接失败，比一行没人走的分支更可靠。
 */
export function isProbePath(pathname: string): boolean {
    return PROBE_PATH_RE.test(pathname);
}

/**
 * P1 的统一出口：朴素 404（真实站点对 `.env` 的典型回答）。
 *
 * 刻意**不**复用 1101 伪装页：那张「Worker threw exception」页会把「这里有个 Worker」
 * 写在脸上，而这批请求本来就来自扫描器，没必要为它们演戏。
 */
export function probeNotFoundResponse(env: any): Response {
    const headers = new Headers({
        'Content-Type': 'text/plain; charset=UTF-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
    });
    return new Response('Not Found', { status: 404, headers: withHsts(headers, env) as Headers });
}

/**
 * 伪装地址来源（对齐 cfnew，面板 hostSniList 仅用于节点 HOST/SNI，不参与伪装页）：
 * env `homepage`/`HOMEPAGE`/`URL`/`FALLBACK`（支持 `a|b|c` 列表随机）；
 * 特殊值 `nginx` 渲染内建欢迎页。**未设置不会落到 1101 页**（见 resolveMaskTarget 的契约说明）。
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

/**
 * 解析伪装配置：列表随机；`FALLBACK=nginx` → 内建欢迎页。
 *
 * B-29（契约，二选一后选定「删死分支」这一侧，因为 init.ts 不在本次改动范围）：
 * 本函数**不再产出**「未设置 → 1101 降级页」这个分支 —— 它在生产里不可达：`init()` 恒把
 * `fallbackDomain` 填成至少 `www.hcaptcha.com`（init.ts 的 `homepage || HOMEPAGE || URL ||
 * FALLBACK || 'www.hcaptcha.com'`），所以「未设置就不出站」这条运维假设根本不成立，
 * 未配置时整站反代到 hcaptcha。1101 页只保留给**运行时降级**（额度/熔断，见 cf1101Response
 * 与 cf1101RateLimitedResponse 的调用点），不再作为「未配置」的产物。
 * 空源列表（`FALLBACK="|"` 这类）仍返回空 target，由 camouflageProxy 的 `new URL` 失败分支
 * 兜到 nginx 欢迎页。**若要恢复「未配置 → 1101」，改的必须是 init.ts 的兜底域，不是这里。**
 */
export function resolveMaskTarget(): { target: string; isNginx: boolean } {
    const envRaw = String(
        (globalThis as any).env?.homepage ||
        (globalThis as any).env?.HOMEPAGE ||
        (globalThis as any).env?.URL ||
        (globalThis as any).env?.FALLBACK ||
        (globalThis as any).globalConfig?.fallbackDomain ||
        ''
    ).trim();
    if (envRaw.toLowerCase() === 'nginx') {
        return { target: '', isNginx: true };
    }
    const sources = maskSources();
    if (!envRaw || sources.length === 0) return { target: '', isNginx: false };
    const picked = sources[Math.floor(Math.random() * sources.length)];
    return { target: normalizeTarget(picked), isNginx: false };
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
    //  - 其余静态体（图片等）：沿用上游 cache-control，缺省时与图片字节分支一致用 public, max-age=86400。
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

/**
 * base64 编码 —— **只有 data 回滚模式用得到**（默认的壳页模式完全不碰 base64）。
 *
 * 三档实现，实测 1MiB：原生 `Uint8Array.prototype.toBase64` 0.18ms → 本文件的查表版 2.08ms
 * → 分块 fromCharCode + btoa 6.95ms → 最初的「Array.from + 32768 实参 + rope」实现 29.9ms。
 *
 * 为什么要留查表版：原生实现依赖运行时 V8 版本（workerd 随 compatibility date 走，不能假定有），
 * 而 data 模式是应急回滚路径 —— 回滚路径本身再踩 10ms 预算就失去意义了。
 * 体积代价约 1KB 源码（混淆后 ~1.2KB），相对预算余量可以接受。
 */
const B64_TABLE = (() => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const table = new Uint8Array(64);
    for (let i = 0; i < 64; i++) table[i] = alphabet.charCodeAt(i);
    return table;
})();
const B64_PAD = 61; // '='

/** 单遍查表编码到 ASCII 字节（不逐字符拼字符串，避免产生中间 rope） */
function tableBase64ToAscii(u8: Uint8Array): Uint8Array {
    const len = u8.length;
    const out = new Uint8Array(((len + 2) / 3 | 0) * 4);
    let o = 0;
    let i = 0;
    for (; i + 2 < len; i += 3) {
        const n = (u8[i] << 16) | (u8[i + 1] << 8) | u8[i + 2];
        out[o++] = B64_TABLE[(n >> 18) & 63];
        out[o++] = B64_TABLE[(n >> 12) & 63];
        out[o++] = B64_TABLE[(n >> 6) & 63];
        out[o++] = B64_TABLE[n & 63];
    }
    const rem = len - i;
    if (rem === 1) {
        const n = u8[i] << 16;
        out[o++] = B64_TABLE[(n >> 18) & 63];
        out[o++] = B64_TABLE[(n >> 12) & 63];
        out[o++] = B64_PAD;
        out[o++] = B64_PAD;
    } else if (rem === 2) {
        const n = (u8[i] << 16) | (u8[i + 1] << 8);
        out[o++] = B64_TABLE[(n >> 18) & 63];
        out[o++] = B64_TABLE[(n >> 12) & 63];
        out[o++] = B64_TABLE[(n >> 6) & 63];
        out[o++] = B64_PAD;
    }
    return out;
}

/**
 * ASCII 字节 → 字符串：优先 `TextDecoder('latin1')`（base64 字母表全在 ASCII 区间，
 * latin1/windows-1252 都是恒等映射，实测 0.4~0.5ms/MiB）；标签缺失时退回 8KiB 分块
 * fromCharCode（9.2ms/MiB，仍远好于最初的 32768 实参 + rope）。
 */
let asciiDecoder: TextDecoder | null | undefined;
function asciiToString(ascii: Uint8Array): string {
    if (asciiDecoder === undefined) {
        try { asciiDecoder = new TextDecoder('latin1'); } catch { asciiDecoder = null; }
    }
    if (asciiDecoder) return asciiDecoder.decode(ascii);
    const parts: string[] = [];
    const STEP = 8192;
    for (let i = 0; i < ascii.length; i += STEP) {
        parts.push(String.fromCharCode.apply(null, ascii.subarray(i, i + STEP) as unknown as number[]));
    }
    return parts.join('');
}

function bytesToBase64(bytes: ArrayBuffer): string {
    const u8 = new Uint8Array(bytes);
    const native = (u8 as unknown as { toBase64?: () => string }).toBase64;
    if (typeof native === 'function') return native.call(u8);
    return asciiToString(tableBase64ToAscii(u8));
}

/**
 * 图片页（壳页 / data 页）的缓存策略：**no-store**。
 * 页面里引用的图 URL 带着「上游图地址的哈希」，换 homepage 后新 URL 必须立刻生效；
 * 页面若被浏览器缓存住，用户会一直看到旧壳页指旧图。
 */
const HTML_PAGE_CACHE_CONTROL = 'no-store';
/**
 * 图片字节的缓存策略：URL 里含图地址哈希，但**同一 URL 的内容仍可能被上游替换**，
 * 因此不用 immutable（那会让换图后最长 24h 不可见），改为 1 小时 + **内容哈希 ETag**：
 * 过期后浏览器带 If-None-Match 回来，内容没变就是 304（无 body），变了才重下整张图。
 */
const IMAGE_BYTES_CACHE_CONTROL = 'public, max-age=3600';

/** FNV-1a 32 位 → 8 位十六进制（短、稳定、不可枚举），用于图片子请求参数值 */
function shortHash(input: string): string {
    let h = 0x811c9dc5;
    for (let i = 0; i < input.length; i++) {
        h ^= input.charCodeAt(i);
        h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
}

/**
 * `<img>` 子请求的参数名：由本部署的 UUID 派生，**不写死字面量**。
 * 写死会让所有同项目部署共享同一个可探测特征（`GET /?<字面量>=1` 即可判定同款面板）。
 */
function maskImgParamName(): string {
    const seed = String((globalThis as any).globalConfig?.userID || '');
    return 'm' + shortHash('maskimg:' + seed).slice(0, 6);
}

/** 参数值 = 上游图地址的短哈希：壳页因此能精确指回同一张图（多源随机抽源时也不漂移） */
function maskImgParamValue(maskURL: URL): string {
    return shortHash(maskURL.href);
}

/** 内容哈希 ETag：长度 + 前 64 字节。同一 URL 内容变了 → ETag 变 → 浏览器重新取图。 */
function imageContentEtag(body: ArrayBuffer): string {
    const head = new Uint8Array(body, 0, Math.min(64, body.byteLength));
    return `"${shortHash(body.byteLength + '|' + head.join(','))}"`;
}

/**
 * HTML 页响应（壳页 / data 页 / nginx 兜底页）：与图片字节分支用**同一套安全头**
 * （nosniff + HSTS + no-store），避免同一站点两套头策略（评审：壳页原先只有 Content-Type）；
 * HEAD 补 Content-Length、不带正文。
 *
 * nginx 兜底页的四处出口（`FALLBACK=nginx` / 目标 URL 解析失败 / 反代彻底失败 / 取图失败）
 * 全部走这里 —— 它们原先各自手写了一份「Content-Type + HSTS」的 Response 构造。
 */
function htmlPageResponse(request: Request, html: string, env: any): Response {
    const headers = new Headers({
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': HTML_PAGE_CACHE_CONTROL,
        'X-Content-Type-Options': 'nosniff'
    });
    const isHead = request.method === 'HEAD';
    if (isHead) headers.set('Content-Length', String(new TextEncoder().encode(html).byteLength));
    return new Response(isHead ? null : html, {
        status: 200,
        headers: withHsts(headers, env) as Headers
    });
}

/**
 * 页面标题取**请求路径**（真实图片站的常见形态）。
 * 绝不写上游 host —— 页面由面板域提供、标题却是上游域，是最直接的代理指纹
 * （评审两轮都点名了这一处既有泄露）。
 */
function maskPageTitle(reqURL: URL): string {
    const seg = reqURL.pathname.replace(/^\//, '');
    return seg || reqURL.host;
}

/**
 * 页面盐：由本部署 UUID 派生。用来把类名与规则写法打成「每部署不同」，
 * 避免整页字节是一个可被一条正则/一次哈希命中的固定常量
 *（评审 A：壳页正文从 ~2.7MB 缩到 ~300B 后，整页哈希变得稳定可指纹）。
 */
function maskPageSalt(): string {
    const seed = String((globalThis as any).globalConfig?.userID || '');
    return shortHash('maskpage:' + seed).slice(0, 5);
}

/**
 * 图片页公共骨架（壳页与 data 回滚页共用）。
 *
 * 类名带部署盐；居中实现按盐在 flex / grid 两种等价写法之间二选一 ——
 * 两处都只影响字节，不影响渲染结果。
 */
function buildImagePageHtml(reqURL: URL, imgSrc: string): string {
    const salt = maskPageSalt();
    const wrapCls = `w${salt}`;
    const picCls = `p${salt}`;
    const centering = (parseInt(salt.slice(-1), 16) & 1)
        ? 'display:flex;align-items:center;justify-content:center'
        : 'display:grid;place-items:center';
    const style = 'body{margin:0;padding:0;overflow:hidden;background:#000}'
        + `.${wrapCls}{${centering};height:100vh}`
        + `.${picCls}{width:100vw;height:100vh;object-fit:fill}`;
    return '<!DOCTYPE html><html><head><meta charset="utf-8">'
        + '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
        + `<title>${maskPageTitle(reqURL)}</title><style>${style}</style></head>`
        + `<body><div class="${wrapCls}"><img src="${imgSrc}" class="${picCls}" alt=""></div></body></html>`;
}

/** 壳页：正文 ~300B，图片由浏览器按 URL 缓存，后续访问不再回源 */
function buildImageShellPage(reqURL: URL, paramName: string, paramValue: string): string {
    return buildImagePageHtml(reqURL, `/?${paramName}=${paramValue}`);
}

/**
 * data URI 页 —— **仅回滚用**（env `MASK_IMG_MODE=data`）。
 * 它把整条链路压在一个响应里，出问题时能立刻退回已知可用形态；代价是每请求构造
 * ~2.7MB 字符串（base64 膨胀 4/3），不要在生产长期开启。
 */
function buildImageDataPage(body: ArrayBuffer, contentType: string, reqURL: URL): string {
    return buildImagePageHtml(reqURL, `data:${contentType || 'image/jpeg'};base64,${bytesToBase64(body)}`);
}

/**
 * 图片缓存写入：张数上限 + **总字节预算**双天花板，Map 插入顺序即淘汰顺序（FIFO）。
 * 两个天花板都来自 `BudgetConfig`（env `MASK_IMG_CACHE_MAX` / `MASK_IMG_CACHE_BYTES`）。
 */
function cacheImageEntry(url: string, entry: ImageCacheEntry, budget: BudgetConfig): void {
    const prev = maskImageCache.get(url);
    if (prev) {
        maskImageCacheBytes -= prev.bytes;
        maskImageCache.delete(url);
    }
    // 单张超预算直接不入缓存：否则它会在下面的淘汰循环里把所有已缓存图片清空，自己留下来 ——
    // 命中率归零而内存照占（与首页缓存 cacheHomeEntry 的同一条判据）。默认 8MiB 下不可达
    // （单张 ≤ MASK_IMAGE_MAX_BUFFER=2MiB），但字节预算可被 env 调小到 64KiB。
    if (entry.bytes > budget.imgCacheBytes) return;
    // 单条上限另由 fetchImageLoad（≤2MB 才缓冲）保证，这里只需维持字节预算与张数上限
    while (maskImageCache.size && (maskImageCache.size >= budget.imgCacheMax
        || maskImageCacheBytes + entry.bytes > budget.imgCacheBytes)) {
        const oldest = maskImageCache.keys().next();
        if (oldest.done) break;
        const victim = maskImageCache.get(oldest.value);
        if (victim) maskImageCacheBytes -= victim.bytes;
        maskImageCache.delete(oldest.value);
    }
    maskImageCache.set(url, entry);
    maskImageCacheBytes += entry.bytes;
}

/** 可缓冲的图片上限：≥它或长度未知 → 流式直传（与既有行为一致） */
const MASK_IMAGE_MAX_BUFFER = 2 * 1024 * 1024;

/** 图片缓存命中则返回条目（不发任何网络请求）；结构不认识一律当未命中 */
function peekImageBytes(maskURL: URL): ImageCacheEntry | null {
    const hit = maskImageCache.get(maskURL.href);
    // 结构判别带上「bytes 与 body 长度一致 + etag 存在」：旧条目存的也是 ArrayBuffer，
    // 只判 instanceof 挡不住热更新残留，而错误的 bytes 会把字节预算减成 NaN（从此预算失效）
    return hit && hit.body instanceof ArrayBuffer && hit.bytes === hit.body.byteLength
        && typeof hit.etag === 'string'
        ? hit
        : null;
}

type ImageLoad =
    | { kind: 'bytes'; body: ArrayBuffer; status: number; contentType: string; etag: string }
    | { kind: 'stream'; resp: Response; contentType: string }
    /**
     * 取图失败（超时 / 网络错误 / 读体失败）。
     * 调用方**必须**用它短路成本地页，不得回落全路径反代 —— 原因见 failedImageResponse。
     */
    | { kind: 'failed' };

/**
 * 取图出站超时（原 10000ms）。
 *
 * 图片目标形态下，**每个**字节未命中的页面请求都会先走这条出站（任意未知路径，例如 `/foo`）：
 * 让一次冷取图占满 10 秒 wall time 没有收益 —— 失败后的出口已经是本地页
 * （failedImageResponse），不再依赖这次出站的成败。5s 对冷取图足够。
 */
const IMAGE_FETCH_TIMEOUT_MS = 5000;

/**
 * 取图失败的负缓存（TTL / 条目上限）。
 *
 * 图源超时后，30 秒内的后续页面请求直接回本地页、**不再出站** —— 否则扫描器每秒几十条探测
 * 会各自烧掉一次 5s 出站与一个子请求。取 30s 而不是更长：负缓存期间页面退化成 nginx 页，
 * 那是**故障态**，图源恢复后要尽快回到正常形态。
 */
const IMAGE_FAIL_CACHE_TTL_MS = 30_000;
const IMAGE_FAIL_CACHE_MAX = 64;

/** url → 失效时刻（毫秒）。有界 FIFO，与图片字节缓存（maskImageCache）分开计账。 */
const maskImageFailCache = new Map<string, number>();

function isImageFailCached(url: string): boolean {
    const until = maskImageFailCache.get(url);
    if (until === undefined) return false;
    if (Date.now() < until) return true;
    maskImageFailCache.delete(url);
    return false;
}

function cacheImageFail(url: string): void {
    // 先删再插：同一条失败被再次确认时按「最近失败」重新计时，而不是留在队列原位等淘汰
    maskImageFailCache.delete(url);
    evictOldest(maskImageFailCache, IMAGE_FAIL_CACHE_MAX - 1);
    maskImageFailCache.set(url, Date.now() + IMAGE_FAIL_CACHE_TTL_MS);
}

/**
 * 冷取图单飞去重：**只存「谁正在取」的标记，不存 Promise**。
 *
 * 旧实现是 `Map<url, Promise>`（N 个并发 `<img>` 只打一次上游）。那在 Workers 上是错的：
 * 浏览器中途 abort 掉一个 `<img>` 请求时，创建 Promise 的那个请求先结束，表里留下的是
 * 一个「永远无法达成」的 Promise —— 后来者 await 它会直接拿到
 * “This promise was created by a request that has since ended”。
 * 详见 common.ts 的 crossRequestSingleFlight 注释。
 */
const maskImageLoading = new Set<string>();

/**
 * 取图（缓存优先、并发合并）。
 *
 * 返回 `null` = 上游明确说「这不是图片」（HTML 假阳性）→ 调用方降级普通反代（**原设计**，
 * 这是「伪装目标填错/图床返回错误页」时的正确行为，不要顺手删掉）；
 * 返回 `{ kind: 'failed' }` = 取图失败 → 调用方回本地页，**绝不**把请求路径转发出去。
 */
async function fetchImageLoad(maskURL: URL, budget: BudgetConfig): Promise<ImageLoad | null> {
    const url = maskURL.href;
    return await crossRequestSingleFlight<ImageLoad>(
        maskImageLoading,
        url,
        // 只把**已入缓存**的字节当作"就绪"：流式结果不可缓存，等待方应该自己取一份
        () => {
            const cached = peekImageBytes(maskURL);
            if (cached) {
                return { kind: 'bytes', body: cached.body, status: cached.status, contentType: cached.contentType, etag: cached.etag };
            }
            // P0：失败的负缓存对**等待方**同样生效 —— 否则同一批并发（一个页面 + N 个 <img>）
            // 会在生产者失败后各自再打一次图源。读函数只读「已落地结论」，符合本函数的契约。
            return isImageFailCached(url) ? { kind: 'failed' } : null;
        },
        async () => {
            const headers = buildMaskedHeaders(new Headers(), maskURL);
            headers.set('Referer', maskURL.origin + '/');
            headers.set('Accept', 'image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8');
            try {
                const resp = await fetchWithTimeout(url, { method: 'GET', headers, cf: {} }, IMAGE_FETCH_TIMEOUT_MS);
                const contentType = resp.headers.get('content-type') || 'image/jpeg';
                // 假阳性保护：服务器返回 HTML 说明不是图片，降级普通伪装反代
                if (contentType.startsWith('text/html')) return null;
                const contentLength = parseInt(resp.headers.get('content-length') || '0', 10);
                if (contentLength > 0 && contentLength < MASK_IMAGE_MAX_BUFFER) {
                    const body = await withTimeout(resp.arrayBuffer(), 5000, '图片代理响应体读取');
                    const etag = imageContentEtag(body);
                    if (body.byteLength <= MASK_IMAGE_MAX_BUFFER) {
                        cacheImageEntry(url, {
                            body,
                            status: resp.status,
                            contentType,
                            time: Date.now(),
                            bytes: body.byteLength,
                            etag
                        }, budget);
                    }
                    return { kind: 'bytes', body, status: resp.status, contentType, etag };
                }
                // 未知长度 / ≥2MB：不缓冲、不缓存，直接流式
                return { kind: 'stream', resp, contentType };
            } catch (e) {
                console.error('伪装图片代理失败:', (e as Error)?.message ?? String(e));
                cacheImageFail(url);
                return { kind: 'failed' };
            }
        }
    );
}

/**
 * 二进制响应的最小头集。**刻意不复用** `filterResponseHeaders`：它会按 content-type 塞
 * `no-store`/CORS，并且只放行白名单头，用在图片字节上会把缓存策略写坏。
 *
 * `Accept-Ranges: bytes` 是刻意的：真实静态站/CDN 的图片几乎都支持 Range，
 * 而"这张图不支持 Range"是一条一条 `curl -r 0-99` 就能验出来的可判定特征。
 */
function imageBytesHeaders(
    load: { status: number; contentType: string },
    etag: string,
    env: any,
    opts: { contentLength?: number; contentRange?: string; lastModified?: string; cacheable?: boolean } = {}
): Headers {
    const headers = new Headers();
    headers.set('Content-Type', load.contentType || 'image/jpeg');
    headers.set('ETag', etag);
    headers.set('Accept-Ranges', 'bytes');
    headers.set('Cache-Control',
        (opts.cacheable ?? (load.status >= 200 && load.status < 300)) ? IMAGE_BYTES_CACHE_CONTROL : 'no-store');
    headers.set('X-Content-Type-Options', 'nosniff');
    if (opts.lastModified) headers.set('Last-Modified', opts.lastModified);
    if (opts.contentRange) headers.set('Content-Range', opts.contentRange);
    // HEAD / 206 没有完整 body，长度只能手写；其余交给 Response 自己算
    if (opts.contentLength !== undefined && opts.contentLength >= 0) {
        headers.set('Content-Length', String(opts.contentLength));
    }
    return withHsts(headers, env) as Headers;
}

/** 流式图片响应（未知长度 / ≥2MB）：不缓冲不缓存，直接透传（两个入口共用） */
function streamImageResponse(
    load: Extract<ImageLoad, { kind: 'stream' }>,
    request: Request,
    env: any
): Response {
    const headers = new Headers({
        'Content-Type': load.contentType || 'image/jpeg',
        'Cache-Control': 'public, max-age=86400'
    });
    return new Response(request.method === 'HEAD' ? null : load.resp.body, {
        status: load.resp.status,
        headers: withHsts(headers, env) as Headers
    });
}

/**
 * 解析单段 Range 请求头（`bytes=a-b` / `bytes=a-` / `bytes=-n`）。
 * 只支持单段：多段 Range 需要 multipart/byteranges 编码，收益远小于复杂度，
 * 而浏览器取图只会发单段。返回 null 表示「忽略 Range，回 200 全长」。
 */
function parseSingleRange(
    header: string | null,
    size: number
): { start: number; end: number } | null {
    if (!header || !/^bytes=\d*-\d*$/.test(header.trim())) return null;
    const spec = header.trim().slice(6);
    const dash = spec.indexOf('-');
    const startRaw = spec.slice(0, dash);
    const endRaw = spec.slice(dash + 1);
    if (startRaw === '' && endRaw === '') return null;
    let start: number;
    let end: number;
    if (startRaw === '') {
        // 后缀范围：bytes=-N 表示最后 N 字节
        const suffix = Number(endRaw);
        if (!Number.isFinite(suffix) || suffix <= 0) return null;
        start = Math.max(0, size - suffix);
        end = size - 1;
    } else {
        start = Number(startRaw);
        end = endRaw === '' ? size - 1 : Number(endRaw);
        if (!Number.isFinite(start) || !Number.isFinite(end)) return null;
        if (start >= size) return null;
        if (end >= size) end = size - 1;
    }
    if (start > end) return null;
    return { start, end };
}

/**
 * P0：图片目标取图失败的统一出口 —— **本地页，零出站**。
 *
 * 为什么不能像以前那样 `return null` 让它继续往下走：那条路会进入全路径伪装反代，把
 * `reqURL.pathname` 原样拼到伪装域上再出站。于是 `GET /.env.bak` 会变成
 * `GET https://<伪装域>/.env.bak` —— 这正是 Cloudflare 检测
 * 「A request matched secret-files scanning patterns. **An outbound fetch matched the same
 * probe family**」的唯一产生方式，也让一次探测白占 10 秒 wall time + 2 次出站。
 *
 * 出口选 nginx 欢迎页（与 camouflageProxy 的三处兜底同一个出口 htmlPageResponse，200 HTML）：
 *  · 对正常访客：图源挂掉时看到一张「普通的默认页」，比 5xx 更像真实站点；
 *  · 对扫描器：不会因为「200 + 图片壳页」被记成「秘密文件存在」。
 */
async function failedImageResponse(request: Request, env: any): Promise<Response> {
    return htmlPageResponse(request, await nginxPage(), env);
}

/** 图片目标的常规请求：返回壳页（默认）或 data 页（回滚模式）；假阳性返回 null 交给普通反代 */
async function buildImagePageResponse(
    request: Request,
    reqURL: URL,
    maskURL: URL,
    env: any,
    budget: BudgetConfig
): Promise<Response | null> {
    const load = await fetchImageLoad(maskURL, budget);
    // null = 上游明确回 HTML（不是图片）：按原设计降级普通反代
    if (!load) return null;
    // P0：取图失败**绝不**回落全路径反代（理由见 failedImageResponse）
    if (load.kind === 'failed') return await failedImageResponse(request, env);

    if (load.kind === 'bytes') {
        const mode = String(env?.MASK_IMG_MODE || 'shell').toLowerCase();
        // data 回滚模式：整张图内联进 HTML（base64 有原生实现时 0.18ms/MiB，查表回退 2.08ms/MiB，
        // 2MB 图最坏约 4.2ms，仍在 10ms 预算内 —— 因此这里不再需要额外的内联上限）
        const html = mode === 'data'
            ? buildImageDataPage(load.body, load.contentType, reqURL)
            : buildImageShellPage(reqURL, maskImgParamName(), maskImgParamValue(maskURL));
        return htmlPageResponse(request, html, env);
    }

    // 流式分支（未知长度 / ≥2MB）：没有可缓存的字节，直接把图片本身返回（既有行为）
    return streamImageResponse(load, request, env);
}

/** 按哈希找回当前配置里的图源：多源随机抽源时，壳页必须能指回同一张 */
function findMaskURLByHash(value: string): URL | null {
    for (const raw of maskSources()) {
        try {
            const u = new URL(normalizeTarget(raw));
            if (maskImgParamValue(u) === value) return u;
        } catch { /* 跳过非法源 */ }
    }
    return null;
}

/**
 * 图片子请求的统一中性出口：一张 1×1 透明 PNG + 完整的图片头（见下）。
 *
 * 为什么不回裸状态码：参数名可由 UUID 派生、值又是图地址哈希，裸 4xx/5xx（无 Content-Type、
 * 无 nosniff、无 HSTS）会让「正确参数名 + 错值」与「任意路径」形成干净的**部署存在性 oracle**；
 * 回一张合法图片则与真实图床行为一致（且 `<img>` 不会破图）。
 *
 * B-28：降级态（`status = 503`）也走这里而不是裸 `new Response(null, {status:503})` ——
 * 「有 body、有类型」与「什么都没有」在响应头层面是可判定的差异，属于同一类指纹。
 * 状态码保留 503 是刻意的：`<img>` 子请求被额度降级时不该被浏览器当成真图收下
 * （tools/camouflage-cpu.test.mjs 也钉住了这个语义）。
 */
const MASK_PLACEHOLDER_PNG = Uint8Array.from(
    atob('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=='),
    (c) => c.charCodeAt(0)
);

function placeholderImageResponse(request: Request, env: any, status = 200): Response {
    const headers = new Headers({
        'Content-Type': 'image/png',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
    });
    return new Response(request.method === 'HEAD' ? null : MASK_PLACEHOLDER_PNG, {
        status,
        headers: withHsts(headers, env) as Headers
    });
}

/**
 * `<img>` 子请求。**未命中时也必须回图片字节，绝不能回壳页 HTML**——`<img>` 收到 text/html
 * 就是坏图，而且「图片地址返回 HTML」本身是强指纹。
 *
 * 三处与真实静态站对齐（评审 A/B 项）：
 *  - `ETag` 用**内容哈希**（不是 URL 哈希）：同一 URL 换图后 ETag 变，浏览器不会再拿到 304 旧图；
 *  - `Accept-Ranges` + 单段 206：字节已在内存里，切片近乎零成本；
 *  - `Last-Modified` 取缓存条目时间，与 `If-Modified-Since` 配合。
 */
async function serveMaskedImage(paramValue: string, request: Request, env: any, budget: BudgetConfig): Promise<Response> {
    const maskURL = findMaskURLByHash(paramValue);
    if (!maskURL) return placeholderImageResponse(request, env);
    const load = await fetchImageLoad(maskURL, budget);
    // B-28：取图失败也走中性占位图 —— 裸 503（无 Content-Type/nosniff/HSTS）与同文件其它
    // 兜底响应的头策略不一致，而这正是「这台部署有没有在代理图片」的旁路指纹。
    if (!load) return placeholderImageResponse(request, env);
    // P0：取图失败（超时/网络）同样走中性占位图 —— `<img>` 不能收到 HTML；
    // 这也让下面的类型收窄只剩 bytes / stream 两支。
    if (load.kind === 'failed') return placeholderImageResponse(request, env);

    if (load.kind === 'stream') return streamImageResponse(load, request, env);

    const { etag } = load;
    const size = load.body.byteLength;
    const cached = peekImageBytes(maskURL);
    const lastModified = cached ? new Date(cached.time).toUTCString() : undefined;
    const isHead = request.method === 'HEAD';

    // 条件请求：内容没变 → 304（无 body，最省的一次往返）
    if (request.headers.get('If-None-Match') === etag) {
        return new Response(null, {
            status: 304,
            headers: imageBytesHeaders(load, etag, env, { cacheable: true, lastModified })
        });
    }

    // 单段 Range → 206。多段 Range 直接忽略（回 200 全长），浏览器取图不会发多段。
    const range = parseSingleRange(request.headers.get('Range'), size);
    if (range && !isHead) {
        // B-28：用 Uint8Array 视图切片，不再整段复制 ArrayBuffer（原写法每个 206 多一次全片拷贝）。
        // 视图直接作为 Response body 是安全的：底层 ArrayBuffer 在响应被消费期间一定还活着。
        const slice = new Uint8Array(load.body, range.start, range.end - range.start + 1);
        return new Response(slice, {
            status: 206,
            headers: imageBytesHeaders(load, etag, env, {
                cacheable: true,
                lastModified,
                contentLength: slice.byteLength,
                contentRange: `bytes ${range.start}-${range.end}/${size}`
            })
        });
    }

    return new Response(isHead ? null : load.body, {
        status: load.status,
        headers: imageBytesHeaders(load, etag, env, {
            lastModified,
            contentLength: isHead ? size : undefined
        })
    });
}

function cacheCleansing(): void {
    const now = Date.now();
    for (const [k, v] of maskHomeCache) {
        if (now - v.time >= MASK_HOME_CACHE_TTL) {
            maskHomeCacheBytes -= v.bytes ?? 0;
            maskHomeCache.delete(k);
        }
    }
}

/**
 * 噪声 query 参数名（小写）。这些只影响上游的统计/归因，不影响返回的页面内容 ——
 * 若纳入缓存键，真实站点首页常见的 `?utm_source=…&_=17…` 会让缓存几乎永不命中，
 * 每个请求都重新走一遍「clone + text + replaceAll」的 CPU 密集路径。
 * 只收高频的几类：长尾参数收益低，而产物体积有硬上限（见 harden.config.json 的 targetBytes）。
 */
const NOISE_QUERY_KEYS: ReadonlySet<string> = new Set([
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'gclid', 'fbclid', 'msclkid', 'dclid', 'spm', '_ga', '_gl', '_'
]);

/**
 * 时间戳类参数名：**只有在「值形态可自证是缓存破坏参数」时才从缓存键里剔除**。
 *
 * B-26：判据选错了对象。原实现在**任意路径**上都把「落在 now±1h 的 10 位秒级时间戳」剔掉，
 * 而「以当前时刻为内容键」的接口（行情、直播抽帧、实时榜单）恰好就是这个形状 ——
 * 首个访客的快照被折叠成同一个缓存键，5 分钟内发给所有人。
 * 现在秒级与毫秒级一样**只在静态资源路径**上归一（`STATIC_ASSET_PATH_RE`）：那里的 `?t=`/`?v=`
 * 才是真·缓存破坏参数，归一不会改变内容；接口路径上的一律保留。
 *
 * ⚠️ 不要反向改成「剔远离 now 的值」：那会把 `t=1700000000`（上一年的 as-of 快照）这类
 * 真正的语义参数折叠掉，撞上 camouflage-cpu.test.mjs 明确钉住的「历史时刻不归一」防投毒红线。
 *
 * 刻意不收 `r`/`rand`/`random`/`cb`/`nonce`：它们的值不是 epoch，无法用值形态自证无害。
 */
const TIMESTAMP_QUERY_KEYS: ReadonlySet<string> = new Set(['t', 'ts', '_t', '_ts', 'time', 'timestamp']);
const EPOCH_WINDOW_SEC = 3600;
const EPOCH_WINDOW_MS = 3600 * 1000;
const EMPTY_KEY_SET: ReadonlySet<string> = new Set();
/** 静态资源路径：只有这类路径上的时间戳才当作缓存破坏参数（见 isNearNowEpoch） */
export const STATIC_ASSET_PATH_RE = /\.(?:js|mjs|css|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|json|map|txt)$/i;
/**
 * 出现这些参数名时**整条查询串都不做时间戳归一**：它们通常是对象 ID / 游标 / 签名，
 * 剔错就是缓存投毒（不同对象折叠成同一键 → 跨访客拿到同一份内容）。
 */
const SEMANTIC_QUERY_KEYS: ReadonlySet<string> = new Set([
    'id', 'ids', 'page', 'p', 'cursor', 'offset', 'since', 'until', 'from', 'to',
    'sign', 'signature', 'token', 'key', 'q', 'query', 'search', 'filter'
]);

function isNearNowEpoch(value: string, now: number, allowStatic: boolean): boolean {
    // B-26：`allowStatic` = 路径命中 STATIC_ASSET_PATH_RE。非静态资源路径一律不归一 ——
    // 「值看起来像现在」并不能证明「值不影响内容」，行情/实时榜单正是反例。
    // 契约（已同步落地）：tools/camouflage-cpu.test.mjs 里对应的两条用例已按本语义改写 ——
    // 「接口路径上的 t= 保留」与「静态资源路径上的 t= 归一」各钉一条。
    if (!allowStatic) return false;
    if (/^\d{10}$/.test(value)) return Math.abs(Number(value) - now / 1000) <= EPOCH_WINDOW_SEC;
    // 13 位毫秒：同上，只允许出现在静态资源路径上。日志/订单/消息这类以毫秒时间戳作对象 ID 的
    // 接口路径上若也归一，最近 1 小时内的所有不同对象都会被折叠成一个缓存键。
    return /^\d{13}$/.test(value) && Math.abs(Number(value) - now) <= EPOCH_WINDOW_MS;
}

/** 运维追加的噪声参数（`MASK_CACHE_NOISE_EXTRA="k1,k2"`）：按名字无条件剔除，责任在运维 */
function extraNoiseKeys(env: any): ReadonlySet<string> {
    const raw = String(env?.MASK_CACHE_NOISE_EXTRA || '');
    if (!raw) return EMPTY_KEY_SET;
    return new Set(raw.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
}

/**
 * 缓存键归一化：按原出现顺序保留非噪声参数，值原样保留。
 *
 * 刻意不用 url.searchParams 序列化 —— 它会重新编码（空格 %20/+, 中文转义）并重排，
 * 那样「缓存键」与「实际转发给上游的 URL」会变成两个东西，排查时极易误判。
 * 这里只做纯字符串过滤：不命中的参数一段不漏地保留原样。
 *
 * `MASK_CACHE_TS_NORM=0` 可整体关闭时间戳归一（回滚开关，默认开启）。
 */
function normalizeCacheQuery(search: string, env: any, pathname: string): string {
    if (!search || search === '?') return '';
    const tsNorm = String(env?.MASK_CACHE_TS_NORM ?? '1') !== '0';
    const extra = extraNoiseKeys(env);
    const now = Date.now();
    const pairs = search.slice(1).split('&').filter(Boolean);

    // 前瞻一遍：出现语义参数就整条不做时间戳归一（宁可少省 CPU，也不冒缓存投毒的风险）
    let hasSemantic = false;
    for (const pair of pairs) {
        const eq = pair.indexOf('=');
        if (SEMANTIC_QUERY_KEYS.has((eq === -1 ? pair : pair.slice(0, eq)).toLowerCase())) {
            hasSemantic = true;
            break;
        }
    }
    const allowStatic = STATIC_ASSET_PATH_RE.test(pathname);

    const kept: string[] = [];
    for (const pair of pairs) {
        const eq = pair.indexOf('=');
        const rawKey = (eq === -1 ? pair : pair.slice(0, eq)).toLowerCase();
        if (NOISE_QUERY_KEYS.has(rawKey) || extra.has(rawKey)) continue;
        if (tsNorm && !hasSemantic && TIMESTAMP_QUERY_KEYS.has(rawKey)) {
            const value = eq === -1 ? '' : pair.slice(eq + 1);
            if (isNearNowEpoch(value, now, allowStatic)) continue;
        }
        kept.push(pair);
    }
    return kept.length ? '?' + kept.join('&') : '';
}

/**
 * S-02：查询串里出现噪声参数时**完全绕过首页缓存**。
 *
 * 原实现只是把 `utm_*` / `gclid` / `fbclid` 等从**缓存键**里剔掉（`normalizeCacheQuery`），
 * 于是 `GET /?utm_source=<script>…` 得到的响应会以「无 query」的键被缓存 5 分钟、
 * 发给之后所有访客。若上游把 utm_source 回显进 HTML（营销落地页极常见），
 * 就等于在面板**同源**上执行任意脚本 —— 而这份代理响应没有任何 CSP。
 *
 * 绕过缓存后：带噪声参数的请求既不污染别人，也不会因为「每次 query 都不同」把缓存打散
 * （那本来是剔除噪声参数的初衷）。代价只是这类请求多一次回源，且它们本来就是低频的。
 */
function hasNoiseQuery(search: string): boolean {
    if (!search || search === '?') return false;
    for (const [key] of new URLSearchParams(search)) {
        if (NOISE_QUERY_KEYS.has(key.toLowerCase())) return true;
    }
    return false;
}

/**
 * B-25：缓存条目的响应头快照。
 * 必须剔掉 Set-Cookie —— 命中时原样回放会把「第一个访客的会话」发给之后 5 分钟内的所有人。
 * 入参是 `filterResponseHeaders` 的产物（已按白名单过滤），HSTS 由命中侧 `withHsts` 重新追加。
 */
function snapshotCacheHeaders(headers: Headers): [string, string][] {
    return [...headers].filter(([k]) => k.toLowerCase() !== 'set-cookie');
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
    const size = entry.bytes ?? 0;
    const prev = maskHomeCache.get(key);
    if (prev) {
        maskHomeCacheBytes -= prev.bytes ?? 0;
        maskHomeCache.delete(key);
    }

    if (size > MASK_HOME_CACHE_MAX_BYTES) return;

    while (maskHomeCache.size && (maskHomeCache.size >= MASK_HOME_CACHE_MAX
        || maskHomeCacheBytes + size > MASK_HOME_CACHE_MAX_BYTES)) {
        const oldest = maskHomeCache.keys().next();
        if (oldest.done) break;
        const victim = maskHomeCache.get(oldest.value);
        if (victim) maskHomeCacheBytes -= victim.bytes ?? 0;
        maskHomeCache.delete(oldest.value);
    }

    maskHomeCache.set(key, entry);
    maskHomeCacheBytes += size;
}

/**
 * 边流边改写：把上游 body 的每个 chunk 解码、替换 host、再编码流出。
 *
 * 为什么不用 `clone().text()` 一把梭：那会先把整份 body 读进内存再全量 replaceAll，
 * CPU 与体积线性相关。这里同一个 token 预算（`budget.rewriteMax`，env `MASK_TEXT_REWRITE_MAX`）
 * 卡的是「累计已处理字节」，
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
    env: any,
    budget: BudgetConfig,
    reservation: TextReservation,
    /**
     * B-08/B-25：是否允许把这份响应写进首页缓存。
     * 调用方传「GET + 2xx + 无噪声参数」。原实现没有这道门禁 —— 流式分支（上游不给
     * content-length 时，gzip 响应正是这种）会把任意 method、任意状态码的响应都写进缓存。
     */
    cacheable: boolean
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
            if (processed + chunk.byteLength > budget.rewriteMax) {
                rewritable = false;
                collected = '';
                console.warn(`伪装页超过 ${budget.rewriteMax}B 改写预算，余下部分原样流出`);
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

            // 按「实际改写过的字节」结算（预留的只是准入成本 TEXT_ADMIT_COST，见 reserveTextBudget）
            settleTextReservation(budget, reservation, processed);

            if (rewritable && cacheable) {
                cacheHomeEntry(cacheKey, {
                    body: collected,
                    status: resp.status,
                    contentType,
                    time: Date.now(),
                    bytes: collected.length,
                    headers: snapshotCacheHeaders(filtered)
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
    // B-29：不再有 is1101 分支 —— 「未配置伪装域名」在生产不可达（契约见 resolveMaskTarget）。
    // 空 target 会落到下面的 `new URL` 失败分支，回 nginx 欢迎页。
    const { target, isNginx } = resolveMaskTarget();
    if (isNginx) {
        return htmlPageResponse(request, await nginxPage(), env);
    }

    let maskURL: URL;
    try {
        maskURL = new URL(target);
    } catch {
        return htmlPageResponse(request, await nginxPage(), env);
    }

    const reqURL = new URL(request.url);
    const budget = readBudgetConfig(env);
    logBudgetOnce(env, budget);
    // S-03：IP 一律取校验过的形态（非法头视为无 IP）。这里是**令牌桶的每 IP 键**，
    // 原先直接读裸头 = 每请求换个假 IP 就能把每 IP 额度无限切分。
    // 副作用须知：无法识别 IP 的请求会共用「空键」那一个桶 —— 与「该头缺失」的既有行为一致。
    const clientIP = clientIp(request);

    // 准入额度（requests 桶）：每一次进入伪装链的请求都记 1，**含缓存命中** ——
    // 缓存命中仍要付头处理与分支判定的固定成本，而且这是"拿缓存当免费带宽"的唯一约束。
    // 放在最前面，保证图片分支 / 缓存分支 / 反代分支全部受约束（熔断必须覆盖全路径）。
    if (!maskRequestAllowed(budget, clientIP)) {
        // `<img>` 子请求被降级时必须回**图片字节**（绝不是 HTML）：否则 `<img>` 收到 HTML = 破图 +
        // 「图片地址返回 HTML」这一强指纹（评审 MAJOR）。
        // B-28：与其它兜底统一走 placeholderImageResponse（完整图片头 + nosniff + HSTS），
        // 只是状态码仍是 503 —— 额度降级不该让浏览器把占位图当成真图收下。
        if (IMAGE_EXT_RE.test(target) && reqURL.pathname === '/' && request.method !== 'POST'
            && reqURL.searchParams.has(maskImgParamName())) {
            return placeholderImageResponse(request, env, 503);
        }
        logMaskDegrade('req', budget);
        return await cf1101Response(reqURL.host, clientIP, env);
    }

    const isImageTarget = IMAGE_EXT_RE.test(target);

    // `<img>` 子请求（壳页里的图片资源）：值 = 上游图地址短哈希，只在根路径生效。
    // 命中缓存零出站；未命中直接取图并回**图片字节**（绝不回壳页 HTML）。
    if (isImageTarget && reqURL.pathname === '/' && request.method !== 'POST') {
        const want = reqURL.searchParams.get(maskImgParamName());
        if (want) return await serveMaskedImage(want, request, env, budget);
    }

    // 图片目标的常规请求：壳页（默认）/ data 页（回滚）。缓存字节命中时零上游。
    if (isImageTarget) {
        const page = await buildImagePageResponse(request, reqURL, maskURL, env, budget);
        if (page) return page;
    }

    // 缓存键用「实际转发给上游的 path + query」按噪声参数归一化后拼成，
    // 保证「键」与「内容」严格对应：请求原样转发，只有键被归一化。
    //
    // B-08 / S-01：键必须同时含 **method** 与 **访问 Host**（原实现只有 origin+path+query）：
    //  · 缺 method → 流式分支会把 `POST /` 的上游响应写进「GET /」的键，任何人一条 POST
    //    就能把首页占位 5 分钟（上游若回显 POST body，则是同源任意 HTML）；
    //  · 缺 host → 同一 Worker 常绑多个入口（自定义域 + *.workers.dev + 多条 route），
    //    A 域写入的正文（内部链接全是 A 域）会被 B 域访客命中，泄露部署的另一个主机名。
    // maskURL.origin 仍保留：它区分上游站点（status / content-type 可能不同）。
    const cacheKey = `${request.method} ${reqURL.host} ${maskURL.origin}${reqURL.pathname}${normalizeCacheQuery(reqURL.search, env, reqURL.pathname)}`;
    // S-02：带噪声参数的请求完全绕过缓存（见 hasNoiseQuery）
    const skipCache = hasNoiseQuery(reqURL.search);
    const cached = skipCache ? undefined : maskHomeCache.get(cacheKey);
    if (cached && Date.now() - cached.time < MASK_HOME_CACHE_TTL) {
        // 命中即提升为「最近使用」，避免热点键在逐条淘汰时先被扔掉
        cacheHomeEntry(cacheKey, cached);
        // B-25：用写入时的完整安全头快照重建，只补 Content-Type 兜底。
        // 注意键必须小写：快照来自 Headers（键恒小写），若这里用 'Cache-Control' 再叠加，
        // Record 里会出现两个大小写不同的同义键 → `new Response(body,{headers})` 会 append 两次，
        // 得到 `no-store, no-store` —— 那正是本条要消灭的「命中/未命中头集合不同」。
        const cachedHeaders: Record<string, string> = { 'cache-control': 'no-store' };
        for (const [k, v] of cached.headers ?? []) cachedHeaders[k.toLowerCase()] = v;
        if (cached.contentType && !cachedHeaders['content-type']) cachedHeaders['Content-Type'] = cached.contentType;
        return new Response(cached.body, { status: cached.status, headers: withHsts(cachedHeaders, env) });
    }

    cacheCleansing();

    // 注意：准入额度已在函数开头（图片/缓存分支之前）判定，这里不再重复。
    // 文本改写的**字节**额度在下面两条文本分支里"先预留、按实际改写量结算"；
    // 额度不足时降级 1101，而不是把未改写正文原样流出（那会带出上游域名）。
    // 例外见文件头注释的「已知遗留」：单响应 >`budget.rewriteMax` 的尾部仍会原样流出。

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
        // 只判定一次：下面两条改写分支与流式兜底都要用它
        const isTextBody = REWRITTEN_CONTENT_TYPE_RE.test(contentType);

        // 文本且长度已知且 <1MB：缓冲 + 重写上游 host + 缓存。
        // contentLength === 0（上游不报长度 / chunked）不走这条分支：
        // 旧写法把「未知大小」当成「小」，会把任意体积的 body 全部 clone + 解码 + replaceAll，
        // 正是 GET / 打穿 CPU 预算的主要路径。现在交给下面的流式改写。
        if (isTextBody && contentLength > 0 && contentLength < budget.rewriteMax) {
            // 改写前先预留额度：不足就降级 1101 —— **绝不**退化成"直接流未改写正文"，
            // 那会把上游域名发给访客，是比 1101 更严重的指纹（评审 BLOCKER）。
            const reservation = reserveTextBudget(budget, clientIP, contentLength);
            if (!reservation) {
                logMaskDegrade('text', budget, contentLength);
                // 降级前先把上游 body 丢弃：否则每个 1101 都会留下一个没人读的响应流
                try { await resp.body?.cancel(); } catch { /* 已消费/已关闭 */ }
                return await cf1101Response(reqURL.host, clientIP, env);
            }
            // P-04：**不再 clone()**。旧写法 clone 出第二条 body 分支，而原 resp.body 从头到尾
            // 无人消费 —— 同一份响应在内存里存两份（clone 内部是 tee，未读分支还会把字节一路缓存），
            // 常驻内存翻倍。这里直接读原 body：只有一份，读到的就是最终要用的那份。
            try {
                const text = await withTimeout(resp.text(), 5000, '伪装页读取');
                const rewritten = text.replaceAll(maskURL.host, reqURL.host);
                // 按**解压后**的实际字符数结算（上游 content-length 是压缩后字节，gzip 下会低估算 5~10 倍）
                settleTextReservation(budget, reservation, text.length);
                const filtered = filterResponseHeaders(resp.headers, maskURL, reqURL);
                // 改写后长度已变，且 body 已被 fetch 解压：沿用上游的帧头会让客户端二次解压/按旧长度读取
                stripBodyFramingHeaders(filtered);
                const headersFinal = withHsts(filtered, env);
                // 只缓存「GET + 2xx + 不带噪声参数」：
                //  · HEAD 的上游通常回空体（原注释）；
                //  · 非 2xx 被固化 5 分钟等于把「后端挂了」放大成全站可见（B-25）；
                //  · 噪声参数见 hasNoiseQuery（S-02）。
                if (request.method === 'GET' && resp.ok && !skipCache) {
                    cacheHomeEntry(cacheKey, {
                        body: rewritten,
                        status: resp.status,
                        contentType,
                        time: Date.now(),
                        bytes: rewritten.length,
                        headers: snapshotCacheHeaders(filtered)
                    });
                }
                return new Response(rewritten, { status: resp.status, headers: headersFinal });
            } catch (e) {
                // 失败/超时：预留全额退回，避免一次失败就把额度吃掉
                settleTextReservation(budget, reservation, 0);
                // P-04：单份内存的代价 —— body 此刻已被 text() 读过（或被 withTimeout 超时打断
                // 但读取仍在进行），**不可能**再退回流式转发（那只会拿到 locked/已消费的 body，
                // 还会漏掉流式分支预留下的准入额度）。这里尽力取消，
                // 然后交回外层统一兜底（首页根路径重试 → nginx 页），与其它抓取失败同一出口。
                try { await resp.body?.cancel(); } catch { /* text() 仍持锁 / 已消费：无可取消 */ }
                console.warn('伪装页缓冲读取失败，交由外层兜底:', (e as Error)?.message ?? String(e));
                throw e;
            }
        }
        // 长度未知、或 ≥ 改写上限（budget.rewriteMax）的文本：边流边改写，超过预算立即停止改写、余下原样流出。
        // 超预算的具体日志在 streamWithBudgetRewrite 内（那里才是真正发生的地方），此处不重复打印。
        if (isTextBody) {
            // 流式分支先按改写上限预留（reserveTextBudget 内部会把它夹到 TEXT_ADMIT_COST），
            // 实际改写量在 flush 里结算退款
            const reservation = reserveTextBudget(budget, clientIP, budget.rewriteMax);
            if (!reservation) {
                logMaskDegrade('text', budget, budget.rewriteMax);
                try { await resp.body?.cancel(); } catch { /* 已消费/已关闭 */ }
                return await cf1101Response(reqURL.host, clientIP, env);
            }
            return streamWithBudgetRewrite(resp, maskURL, reqURL, cacheKey, contentType, env, budget, reservation, request.method === 'GET' && resp.ok && !skipCache);
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
        return htmlPageResponse(request, await nginxPage(), env);
    }
}
