import { isPermanentBlacklisted, recordViolationAndMaybeBan } from "./blacklist";
import { isPathInDictionary, checkRateLimit, checkRateLimitShared, recordRateLimit, writeRateLimitKV } from "./ratelimit";
import { camouflageProxy, cf1101RateLimitedResponse } from "./camouflage";

/**
 * 非内置路径守卫 — 对齐 cfnew 的安全三件套：
 *  1. 永久黑名单检查（IP 累计违规超阈值 → 直接 429）
 *  2. 路径字典校验 + 速率限制（字典路径视为合法公开路径，不限流不计数；
 *     仅路径含字典外段才触发限流与违规计数，避免误伤伪装站点正常流量）
 *  3. 未命中限流 → 全路径伪装反代（字典内路径同样伪装）
 *
 * 对齐 cfnew 排除语义：POST、根路径 /、首段为 login、首段为管理路径(UUID/SUB_PATH) 不进入守卫。
 */

interface GuardContext {
    waitUntil(p: Promise<unknown>): void;
}

/**
 * 永久黑名单守卫 —— 只对「不像内置随机路径」的请求生效。
 *
 * 豁免范围：根路径，以及**每段都在路径字典内**的组合（1~N 段）——
 *   这正是 generateWsPath 生成节点随机路径的取值形态（PUBLIC_PATH_POOL ⊂ 字典）。
 *   只要一段落不进字典，就仍按探测处理、照常查黑名单。
 *
 * 为什么必须豁免，两条理由：
 *  1) 成本模型（主因）：黑名单是整表 JSON，刷新 = KV 读 + JSON.parse(整个名单) + new Set(全部条目)，
 *     成本 O(名单规模)，且每 60s 由「第一个到达的请求」**一次性**承担。
 *     实测 2 万条 ≈4.3ms、5 万条 ≈13.7ms、10 万条 ≈25ms（Free 计划总预算只有 10ms）。
 *     随机路径是节点主路径、流量最大，不能让它去扛这个尖峰 —— 根路径同理（已撤回）。
 *  2) 语义：拉黑是为了拦扫描探测，而随机路径是合法客户端入口。让被拉黑的 IP
 *     继续使用它自己知道的随机路径，比让每个正常连接去摊销解析成本更划算。
 *     随机路径的 CPU 上限由 camouflageProxy 的熔断兜底（覆盖全部路径、O(1)）。
 *
 * 缺 IP / 缺 env.kv 时一律放行：KV 未绑定不能把隧道打死。
 */
export async function guardPermanentBlacklist(request: Request, env: any): Promise<Response | null> {
    const ip = request.headers.get('CF-Connecting-IP') || '';
    const kv = env?.kv as KVNamespace | undefined;
    if (!ip || !kv) return null;

    const reqURL = new URL(request.url);
    // 根路径（空段）与「每段都在字典内」的随机路径组合：豁免，不触发整表解析
    const segments = reqURL.pathname.split('/').filter(Boolean);
    if (segments.length === 0 || isPathInDictionary(segments)) return null;

    if (!await isPermanentBlacklisted(ip, kv)) return null;

    console.warn(`[永久黑名单] IP ${ip} 命中永久黑名单，直接拦截`);
    return await cf1101RateLimitedResponse(reqURL.host, ip);
}

/**
 * 对非内置路径请求执行守卫。
 * 返回 Response：命中黑名单/限流（429 nginx 页）或伪装反代结果。
 * 返回 null：属于排除路径，应继续由上层内置逻辑处理。
 */
export async function guardNonBuiltinPath(
    request: Request,
    env: any,
    ctx: GuardContext
): Promise<Response | null> {
    // cfnew 排除语义：POST、根路径、login、管理路径不进入伪装/限流
    if (request.method === 'POST') return null;
    const reqURL = new URL(request.url);
    if (reqURL.pathname === '/') return null;

    const segments = reqURL.pathname.split('/').filter(Boolean);
    if (segments[0] === 'login') return null;

    // 管理路径：面板 subPath（默认 UUID）—— 与 cfnew 的“管理员路径”语义对齐
    const adminPath = String((globalThis as any).httpConfig?.subPath || (globalThis as any).globalConfig?.userID || '')
        .toLowerCase()
        .replace(/^\//, '');
    if (adminPath && segments[0].toLowerCase() === adminPath) return null;

    const ip = request.headers.get('CF-Connecting-IP') || '';
    const kv = env?.kv as KVNamespace | undefined;

    // 1. 永久黑名单（与根路径、WS 升级共用同一份守卫）
    const blocked = await guardPermanentBlacklist(request, env);
    if (blocked) return blocked;

    // 2. 路径字典校验 + 限流（字典路径视为合法公开路径，不限流不计数；
    //    仅路径含字典外段才触发限流与违规计数，避免误伤伪装站点正常流量）
    if (!isPathInDictionary(segments)) {
        // F17：内存 Map 是 isolate 私有的，换边缘即可把计数清零；内存未超限时再看一次
        // KV 里的跨边缘计数（每 IP 每窗口至多 1 次读，KV 未绑定/读失败一律放行）。
        if (!checkRateLimit(ip) || !(await checkRateLimitShared(kv, ip))) {
            console.warn(`[速率限制] IP ${ip} 超过非管理员路径请求限制`);
            if (kv) await writeRateLimitKV(kv, ip, ctx);
            if (ip && kv) ctx.waitUntil(recordViolationAndMaybeBan(ip, kv, ctx));
            return await cf1101RateLimitedResponse(reqURL.host, ip);
        }
        recordRateLimit(ip);
    }

    // 3. 全路径伪装反代（字典内路径同样伪装；命中限流已在上面拦截）
    return await camouflageProxy(request, env);
}
