import { isPermanentBlacklisted, recordViolationAndMaybeBan } from "./blacklist";
import { isPathInDictionary, checkRateLimit, recordRateLimit, writeRateLimitKV } from "./ratelimit";
import { camouflageProxy, cf1101Page } from "./camouflage";

/**
 * 非内置路径守卫 — 对齐 cfnew 的安全三件套：
 *  1. 永久黑名单检查（IP 累计违规超阈值 → 直接返回内置 1101 页，状态码 200）
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
 * 对非内置路径请求执行守卫。
 * 返回 Response：命中黑名单/限流（内置 1101 页，状态码 200）或伪装反代结果。
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
        return new Response(await cf1101Page(reqURL.host, ip), {
            status: 200,
            headers: {
                'Content-Type': 'text/html; charset=UTF-8'
            }
        });
    }

    // 2. 路径字典校验 + 限流（字典路径视为合法公开路径，不限流不计数；
    //    仅路径含字典外段才触发限流与违规计数，避免误伤伪装站点正常流量）
    if (!isPathInDictionary(segments)) {
        if (!checkRateLimit(ip)) {
            console.warn(`[速率限制] IP ${ip} 超过非管理员路径请求限制`);
            if (kv) await writeRateLimitKV(kv, ip, ctx);
            if (ip && kv) ctx.waitUntil(recordViolationAndMaybeBan(ip, kv, ctx));
            return new Response(await cf1101Page(reqURL.host, ip), {
                status: 200,
                headers: {
                    'Content-Type': 'text/html; charset=UTF-8'
                }
            });
        }
        recordRateLimit(ip);
    }

    // 3. 全路径伪装反代（字典内路径同样伪装；命中限流已在上面拦截）
    return await camouflageProxy(request, env);
}
