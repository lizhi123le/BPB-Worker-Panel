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
 * WS 升级分支的永久黑名单守卫（H5）：只做永久黑名单检查。
 *
 * 路径字典校验不在本函数：F-22 已在 worker.ts 的 WS 分支前置完成（与 HTTP 非内置路径同一判据，
 *   并豁免根路径与管理员路径），此处不再重复。
 * 为何不加限流：每一次 WS 连接（含客户端断线自动重连）都是一个请求，
 *   套用现有「6 次/小时」的路径限流会直接打死所有客户端，可用性损失远大于探测面收益。
 * 缺 IP / 缺 env.kv 时一律放行：KV 未绑定不能把隧道打死。
 */
export async function guardWebsocketBlacklist(request: Request, env: any): Promise<Response | null> {
    const ip = request.headers.get('CF-Connecting-IP') || '';
    const kv = env?.kv as KVNamespace | undefined;
    if (!ip || !kv) return null;

    if (!await isPermanentBlacklisted(ip, kv)) return null;

    console.warn(`[永久黑名单] WS 升级 IP ${ip} 命中永久黑名单，直接拦截`);
    const reqURL = new URL(request.url);
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

    // 1. 永久黑名单
    if (ip && kv && await isPermanentBlacklisted(ip, kv)) {
        console.warn(`[永久黑名单] IP ${ip} 命中永久黑名单，直接拦截`);
        return await cf1101RateLimitedResponse(reqURL.host, ip);
    }

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
