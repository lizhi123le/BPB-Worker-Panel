import { getDataset } from "@kv";
import { isKvBound, isValidUUID } from "@common";
import { applyAddressEnvOverrides } from "@utils";
// 出厂默认值移至零依赖的 ./defaults，使 @kv 也能以它作校验基准而不产生循环依赖。
// 这里保留同名再导出，既有的 `import { DEFAULT_SETTINGS } from "@init"`（如 @handlers）继续可用。
import { DEFAULT_SETTINGS } from "./defaults";
// R-12：端口表的唯一来源（构建期 build.js 也读同一文件，注入面板页面）
import PORTS from './ports.json';

export { DEFAULT_SETTINGS };

/** dict._public_proxy_ip_ 的出厂默认值（env.PUBLIC_PROXY_IP 覆盖时用于还原；base64 原文不变） */
const PUBLIC_PROXY_IP_DEFAULT = atob('YnBiLnlvdXNlZi5pc2VnYXJvLmNvbQ==');

globalThis.dict = {
    _VL_: atob('dmxlc3M='),
    _VL_CAP_: atob('VkxFU1M='),
    _VM_: atob('dm1lc3M='),
    _TR_: atob('dHJvamFu'),
    _TR_CAP_: atob('VHJvamFu'),
    _SS_: atob('c2hhZG93c29ja3M='),
    _V2_: atob('djJyYXk='),
    _project_: atob('QlBC'),
    _website_: atob('aHR0cHM6Ly9iaWEtcGFpbi1iYWNoZS5naXRodWIuaW8vQlBCLVdvcmtlci1QYW5lbC8='),
    _public_proxy_ip_: PUBLIC_PROXY_IP_DEFAULT
};

globalThis.settings = structuredClone(DEFAULT_SETTINGS);

export async function setSettings(request: Request, env: Env) {
    const dataset = await getDataset(request, env);
    const settings = dataset.settings;
    if (settings) {
        // URL 不再在此解析（原会在每次请求都 fetch）；改为在订阅拉取 / 连接时按需解析并缓存
        // 合并而非替换，确保新字段（alpn, hostSniList, regionMatch 等）不会被旧 KV 数据覆盖；
        // 注意这是浅合并：数组字段仍与 dataset 共享引用，要改数组内容必须先拷贝（如 [...settings.ports]）
        Object.assign(globalThis.settings, settings);
    }

    // 对齐 cfnew v3.0：wk 为空时走官方直连（CF），不再记录 Worker 所在地
}

/**
 * F-14：安全解码。畸形 `%` 编码（如 `/%zz`）会让 decodeURIComponent 抛 URIError，
 * 冒泡到 worker 顶层 catch 就变成 BPB 错误页 —— 任何人一行畸形 URL 即可指纹识别本部署。
 * 解码失败返回 null，调用方按「未解码原样」处理：路由自然落到 default → 伪装反代。
 */
function safeDecodePath(raw: string): string | null {
    try {
        return decodeURIComponent(raw);
    } catch {
        return null;
    }
}

/**
 * B-56：路径归一化（去尾斜杠，兜底根路径）。
 *
 * 此前这段归一化只在 `initHttp` 内部算出来喂给凭据校验，**没有回流路由**：
 * `globalConfig.pathName` 保留的是原样路径，而 `handleLogin` / `handlePanel` /
 * `handleSubscriptions` / `handleProxyIPs` 全部按 pathName **精确**匹配，
 * 于是 `/login/`、`/panel/settings/`、`/sub/normal/<x>/` 一律落到 fallback 伪装页 ——
 * 与 initHttp 注释里「`/secrets/` 与 `/secrets` 等价」的承诺相反
 * （那个承诺只在 worker.ts 的首段级 switch 上侥幸成立，二级路由全部不成立）。
 *
 * 单一来源：init() 与 initHttp() 都用这一个函数，避免「校验看 A、路由看 B」再次分叉。
 */
function normalizePath(raw: string): string {
    return raw.replace(/\/+$/, '') || '/';
}

/**
 * KV 校验的豁免路径：登录页首访「设置管理员口令」流程要在没绑 KV 的情况下也能打开，
 * 并把「还没绑 KV」用可读 JSON（POST /login/set-password）说清楚，而不是先被拦成通用错误页。
 * 只豁免 KV 这一条 —— UUID / TR_PASS 是部署必填凭据，仍然照旧强制。
 */
const KV_CHECK_EXEMPT_PATHS = ['/login', '/login/set-password'];

/**
 * 必填凭据校验（C-13）：UUID / TR_PASS 齐备、UUID 合法、KV 已绑定。HTTP（initHttp）与 WS 升级分支共用。
 *
 * 此前只有 HTTP 路径调用这段校验，WS 分支完全跳过：缺凭据时 WS 表现为「101 后静默鉴权失败」，
 * 部署者看到的现象只是「客户端连不上」，无法区分配置问题还是网络问题。
 * 判据（含错误消息与 cause）与改动前 initHttp 内联版本逐字一致，/secrets、/favicon.ico
 * 首访引导流程照旧豁免，因此只在凭据真的缺失/非法时抛错。
 */
export function assertRequiredCredentials(env: any, normalizedPath: string): void {
    const { _VL_CAP_, _TR_CAP_ } = globalThis.dict;
    const { UUID, TR_PASS } = env;

    if (['/secrets', '/favicon.ico'].includes(normalizedPath)) return;

    if (!UUID || !TR_PASS) throw new Error(`Please set ${_VL_CAP_} UUID and ${_TR_CAP_} password first. Visit /secrets to generate them.`, { cause: "missing-credentials" });
    if (!isValidUUID(UUID)) throw new Error(`Invalid UUID: ${UUID}`, { cause: "init" });
    if (KV_CHECK_EXEMPT_PATHS.includes(normalizedPath)) return;
    if (!isKvBound(env)) throw new Error(`KV Dataset is not properly set! Please refer to the tutorials.`, { cause: "kv-not-set" });
}

/**
 * R-12：TLS / 明文端口表的**服务端单一来源**（此前 initHttp 里内联一份字面量）。
 *
 * 为什么做不到「全仓唯一」：面板（src/assets/panel/script.js）是静态资源，读不到服务端常量；
 * 把常量注入面板需要 scripts/build.js 做模板替换（本轮不可改），而面板能拿到的
 * 只有 `settings.ports`（用户勾选后的结果，不是端口全集），无法反推全集。
 * 因此落地方式是「服务端唯一 + 面板逐字同步」，面板侧的告警注释见 panel/script.js 顶部。
 *
 * ⚠ 两处必须保持**集合相同**（新增端口两侧同时改；漏一处的后果是「面板选不到的端口」或
 * 「服务端不认的端口 → isHttps 判成明文」）。顺序则**不要**顺手排序：服务端只用 `includes`
 * 做成员判定（顺序不可观测），但面板侧的顺序决定它提交的 `settings.ports` 顺序，
 * 而订阅节点的输出顺序就是 ports 的顺序 —— 排序会改变订阅输出。
 */
// R-12：表本身移进 ./ports.json（单一来源），面板侧由 scripts/build.js 在构建期注入。
export const DEFAULT_HTTP_PORTS: number[] = PORTS.http;
export const DEFAULT_HTTPS_PORTS: number[] = PORTS.https;

/**
 * R-11：伪装 / 兜底域名的出厂默认值（未命中任何路由的请求会被反代到这里）。
 *
 * ⚠ **本常量目前不是全仓唯一来源**：本轮可改的文件里只有 init 侧
 * （camouflage.ts / handlers.ts 不在工作单允许改动的范围内），所以只归一了 init 这一处：
 *  - `camouflage.ts` 的 `maskSources()` 与 `resolveMaskTarget()` 仍各自抄了一遍
 *    `homepage || HOMEPAGE || URL || FALLBACK || globalConfig.fallbackDomain` 的 env 链
 *    （两者归一化语义还不一致：一个按 `|` 切分并丢 `nginx`，一个先判 `nginx` 再切分）；
 *  - `handlers.ts` 的 `fallback()` 自己又写了一份 `'www.hcaptcha.com'` 字面量兜底。
 * 所以「改这里就完事」是**错的**：改本值必须同步 handlers.ts 的那份字面量，
 * 否则 `/panel/*` 等路径的兜底域会与「未命中路由」的兜底域分叉。
 * 下一轮把上面三处（camouflage 两个函数 + handlers 的字面量）都改为引用本常量，
 * 才算真正的单一来源 —— init 侧已就绪，引用即可。
 */
export const DEFAULT_FALLBACK_DOMAIN = 'www.hcaptcha.com';

export function init(request: Request, env: Env) {
    const { pathname } = new URL(request.url);
    const { UUID, TR_PASS, DOH_URL } = env;

    // 伪装页环境变量对齐 cfnew：homepage / HOMEPAGE / URL 优先，FALLBACK 兼容保留
    // R-11：出厂默认值改由 DEFAULT_FALLBACK_DOMAIN 提供（单一来源；残留的第二份实现见该常量注释）
    const fallback = String((env as any).homepage || (env as any).HOMEPAGE || (env as any).URL || env.FALLBACK || DEFAULT_FALLBACK_DOMAIN);

    // H6：env 覆盖出厂默认的公共出口域名（未设置 → 还原出厂值，行为逐字不变）
    (globalThis.dict as any)._public_proxy_ip_ = (env as any).PUBLIC_PROXY_IP || PUBLIC_PROXY_IP_DEFAULT;

    // H6：env 覆盖内置代理中继池 / 官方直连池（DEFAULT_PROXY_IPS / OFFICIAL_IPS）
    applyAddressEnvOverrides(env);

    globalThis.globalConfig = {
        // B-01：必须小写化。isValidUUID 的正则带 /i（接受 A1B2…），但服务端从首包 16 字节
        // 重建出的 UUID 恒为小写（unified.ts 的 stringify 结尾 .toLowerCase()），比较是全等，
        // 因此大写 UUID 部署会让**每一条 VLESS 连接**在首包被判 "invalid user" → close(1008)，
        // 而面板 / 登录 / 订阅全部正常 —— 最难自查的一类故障。
        // 注意：resolveSubPath 仍读 env.UUID（旧部署的 subPath 因此保留原大小写），
        // 不要把它「顺手统一」成 globalConfig.userID，否则老订阅 URL 会静默变号。
        userID: String(UUID).toLowerCase(),
        TrPass: TR_PASS,
        // F-14：畸形编码不再抛 URIError（顶层 catch 的 BPB 错误页 = 部署指纹），
        // 解码失败保留原始未解码路径 → 交回既有路由：default 分支走伪装反代，
        // 首段命中内置路由（如 /panel/%zz）则落到该处理器自身的 fallback 兜底，同样不返回错误页
        // B-56：归一化结果直接进路由，二级路由（/panel/settings/ 等）不再落到伪装页
        pathName: normalizePath(safeDecodePath(pathname) ?? pathname),
        fallbackDomain: fallback,
        dohURL: DOH_URL || 'https://cloudflare-dns.com/dns-query'
    };
}

export function initWs(env: any) {
    const { _public_proxy_ip_ } = globalThis.dict;

    globalThis.wsConfig = {
        envProxyIPs: env.PROXY_IP,
        envPrefixes: env.PREFIX,
        defaultProxyIPs: [_public_proxy_ip_],
        defaultPrefixes: [
            '[2a02:898:146:64::]',
            '[2602:fc59:b0:64::]',
            '[2602:fc59:11:64::]'
        ],
        proxyMode: 'proxyip' // 默认模式，后续由 handleWebsocket 根据 settings 覆盖
    };
}

/** KV 键：subPath 的持久值（H8(b)：首次解析时写入，运维可改此键轮换订阅路径） */
const SUB_PATH_KV_KEY = 'subPath';
/**
 * isolate 级缓存：命中后本 isolate 不再为 subPath 读 KV（HTTP 热路径每个请求都要它）。
 *
 * B-33：必须带 TTL。原实现是**永久**缓存，而文件头承诺「运维可改 KV 的 subPath 轮换订阅路径」——
 * 轮换后要等 isolate 回收才生效（可能数小时），承诺与行为不符。
 * 5 分钟与 kv-cache 的 CACHE_TTL 同量级：轮换延迟可控，而热路径依然是 0 次 KV 读。
 */
const SUB_PATH_CACHE_TTL_MS = 300_000;
let cachedSubPath: string | null = null;
let cachedSubPathAt = 0;

/**
 * H8(b)：由 UUID 单向派生独立 subPath（仅全新部署使用）。
 * HMAC-SHA256(key=UUID, msg='bpb-sub-path') → base64url 前 24 字符。
 * 单向：泄露订阅 URL 反推不出 UUID；确定性：跨 isolate / 跨边缘结果恒定，
 * 不依赖 KV 写的落库顺序，避免并发首次初始化时生成出两个值抖动订阅 URL。
 */
async function deriveIndependentSubPath(UUID: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', encoder.encode(String(UUID)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode('bpb-sub-path'));
    return btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')
        .slice(0, 24);
}

/**
 * H8(b)：把 subPath（订阅 URL / `/dns-query/<subPath>` 的路径秘密）与 UUID（代理凭据）解耦。
 *
 * 原实现 `SUB_PATH || UUID` 让一个秘密承担两种身份：订阅 URL 本来就是要发给用户和第三方的，
 * 泄露一次等于同时泄露 VLESS UUID（且 `/dns-query/<subPath>` 是开放 DoH 中继）。
 *
 * 解析优先级（向后兼容优先，不改老部署的既有值）：
 *   1. `env.SUB_PATH`：运维显式指定，最高优先，语义逐字不变；
 *   2. KV `subPath`：已持久化的值（新部署首次解析写入；运维可改此键轮换）；
 *   3. 老部署（KV 里已有 `proxySettings`，说明本部署早已初始化）→ 沿用旧值 UUID 并落 KV，
 *      已发出的订阅 URL / DoH URL 一个都不会失效（兼容期，轮换靠第 2 条或 SUB_PATH）；
 *   4. 全新部署（KV 里什么都没有）→ 独立派生值（见 deriveIndependentSubPath）并落 KV。
 *
 * KV 未绑定或读失败时一律退回旧值 UUID：不能因为读不到 KV 就把订阅打废。
 */
export async function resolveSubPath(env: any): Promise<string> {
    const { UUID, SUB_PATH, kv } = env;
    if (SUB_PATH) return String(SUB_PATH);
    if (cachedSubPath && Date.now() - cachedSubPathAt < SUB_PATH_CACHE_TTL_MS) return cachedSubPath;
    if (!kv || typeof kv.get !== 'function') return UUID;
    // 凭据尚未配置（/secrets 首访引导流程）：不派生也不写 KV，保持改动前的旧值语义
    if (!UUID || !isValidUUID(UUID)) return UUID;

    let stored: string | null = null;
    try {
        stored = await kv.get(SUB_PATH_KV_KEY);
    } catch {
        return UUID;
    }
    if (stored) {
        cachedSubPath = stored;
        cachedSubPathAt = Date.now();
        return stored;
    }

    // 读到 proxySettings 即「本部署早已初始化」→ 必须沿用旧值（第 3 条）；读失败按老部署处理
    let initialized = true;
    try {
        initialized = (await kv.get('proxySettings')) !== null;
    } catch {
        initialized = true;
    }

    // 独立值只在全新部署生成；派生异常一律退回旧值（不能因为派生失败把订阅打废）
    let resolved = UUID;
    if (!initialized) {
        try {
            resolved = await deriveIndependentSubPath(UUID);
        } catch {
            resolved = UUID;
        }
    }

    try {
        await kv.put(SUB_PATH_KV_KEY, resolved);
    } catch {
        // 独立值没能落住 → 退回旧值，避免本 isolate 与其它 isolate 看到不同的 subPath
        if (!initialized) return UUID;
    }
    cachedSubPath = resolved;
    cachedSubPathAt = Date.now();
    return resolved;
}

export async function initHttp(request: Request, env: any) {
    const { pathname, origin, searchParams, hostname } = new URL(request.url);

    // 尾部斜杠归一化：/secrets/ 与 /secrets 等价。否则用户多打一个斜杠就落到错误页，
    // 而错误页正是他此时唯一的自救入口（未配置凭据时无处可去），会形成死循环。
    // F-14：畸形 `%` 编码不再抛 URIError（否则顶层 catch 返回 BPB 错误页 = 任何人可指纹识别本部署）；
    // 解码失败保留原始未解码路径 → 交回既有路由（default 分支 / 各处理器 fallback 兜底），不再出现错误页
    const normalizedPath = normalizePath(safeDecodePath(pathname) ?? pathname);

    assertRequiredCredentials(env, normalizedPath);

    // searchParams.get 已解码一层，这里是历史语义上的再解一层；同样不再允许抛错
    const appParam = searchParams.get('app') ?? '';

    globalThis.httpConfig = {
        panelVersion: __VERSION__,
        // R-12：端口表来自本文件顶部的单一来源。每次请求按值拷贝一份 —— 常量是模块级的，
        // 若将来某处写成 `httpConfig.defaultHttpsPorts.push(...)`，共享引用会把常量改坏并跨请求串味。
        defaultHttpPorts: [...DEFAULT_HTTP_PORTS],
        defaultHttpsPorts: [...DEFAULT_HTTPS_PORTS],
        hostName: hostname,
        client: safeDecodePath(appParam) ?? appParam,
        urlOrigin: origin,
        subPath: await resolveSubPath(env),
    };
}