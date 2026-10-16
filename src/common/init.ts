import { getDataset } from "@kv";
import { isKvBound, isValidUUID } from "@common";
import { applyAddressEnvOverrides } from "@utils";
// 出厂默认值移至零依赖的 ./defaults，使 @kv 也能以它作校验基准而不产生循环依赖。
// 这里保留同名再导出，既有的 `import { DEFAULT_SETTINGS } from "@init"`（如 @handlers）继续可用。
import { DEFAULT_SETTINGS } from "./defaults";

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

export function init(request: Request, env: Env) {
    const { pathname } = new URL(request.url);
    const { UUID, TR_PASS, DOH_URL } = env;

    // 伪装页环境变量对齐 cfnew：homepage / HOMEPAGE / URL 优先，FALLBACK 兼容保留
    const fallback = String((env as any).homepage || (env as any).HOMEPAGE || (env as any).URL || env.FALLBACK || 'www.hcaptcha.com');

    // H6：env 覆盖出厂默认的公共出口域名（未设置 → 还原出厂值，行为逐字不变）
    (globalThis.dict as any)._public_proxy_ip_ = (env as any).PUBLIC_PROXY_IP || PUBLIC_PROXY_IP_DEFAULT;

    // H6：env 覆盖内置代理中继池 / 官方直连池（DEFAULT_PROXY_IPS / OFFICIAL_IPS）
    applyAddressEnvOverrides(env);

    globalThis.globalConfig = {
        userID: UUID,
        TrPass: TR_PASS,
        // F-14：畸形编码不再抛 URIError（顶层 catch 的 BPB 错误页 = 部署指纹），
        // 解码失败保留原始未解码路径 → 交回既有路由：default 分支走伪装反代，
        // 首段命中内置路由（如 /panel/%zz）则落到该处理器自身的 fallback 兜底，同样不返回错误页
        pathName: safeDecodePath(pathname) ?? pathname,
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
/** isolate 级缓存：命中后本 isolate 不再为 subPath 读 KV（HTTP 热路径每个请求都要它） */
let cachedSubPath: string | null = null;

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
    if (cachedSubPath) return cachedSubPath;
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
    return resolved;
}

export async function initHttp(request: Request, env: any) {
    const { pathname, origin, searchParams, hostname } = new URL(request.url);

    // 尾部斜杠归一化：/secrets/ 与 /secrets 等价。否则用户多打一个斜杠就落到错误页，
    // 而错误页正是他此时唯一的自救入口（未配置凭据时无处可去），会形成死循环。
    // F-14：畸形 `%` 编码不再抛 URIError（否则顶层 catch 返回 BPB 错误页 = 任何人可指纹识别本部署）；
    // 解码失败保留原始未解码路径 → 交回既有路由（default 分支 / 各处理器 fallback 兜底），不再出现错误页
    const normalizedPath = (safeDecodePath(pathname) ?? pathname).replace(/\/+$/, '') || '/';

    assertRequiredCredentials(env, normalizedPath);

    // searchParams.get 已解码一层，这里是历史语义上的再解一层；同样不再允许抛错
    const appParam = searchParams.get('app') ?? '';

    globalThis.httpConfig = {
        panelVersion: __VERSION__,
        defaultHttpPorts: [80, 8080, 2052, 2082, 2086, 2095, 8880],
        defaultHttpsPorts: [443, 8443, 2053, 2083, 2087, 2096],
        hostName: hostname,
        client: safeDecodePath(appParam) ?? appParam,
        urlOrigin: origin,
        subPath: await resolveSubPath(env),
    };
}