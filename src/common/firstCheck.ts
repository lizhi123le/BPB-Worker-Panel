import { isPermanentBlacklisted, recordViolationAndMaybeBan } from "./blacklist";
import { isPathInDictionary, checkRateLimit, checkRateLimitShared, recordRateLimit, writeRateLimitKV } from "./ratelimit";
import {
    camouflageProxy,
    cf1101RateLimitedResponse,
    isProbePath,
    probeNotFoundResponse,
    STATIC_ASSET_PATH_RE
} from "./camouflage";
// S-03：CF-Connecting-IP 的唯一取用点（含形态校验，非法即视为无 IP）
import { clientIp } from "./client-ip";

/**
 * 非内置路径守卫 — 对齐 cfnew 的安全三件套：
 *  1. 永久黑名单检查（IP 累计违规超阈值 → 直接 429）；
 *     注意：根路径与「每段都在字典内」的随机路径组合豁免此步，见 guardPermanentBlacklist。
 *  2. 路径字典校验 + 速率限制（字典路径视为合法公开路径，不限流不计数；
 *     仅路径含字典外段才触发限流与违规计数，避免误伤伪装站点正常流量）
 *  3. **秘密文件 / 版本控制探测族短路**（`.env`、`.git/HEAD` …）→ 朴素 404，零出站（P1）
 *  4. 未命中限流 → 全路径伪装反代（字典内路径同样伪装）
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
 *
 * @param segments 调用方已算好的路径段。传进来可省掉本函数内一次 split 与字典判定
 *                 （调用方通常已经为「字典校验」算过同一组段）。
 */
export async function guardPermanentBlacklist(
    request: Request,
    env: any,
    segments?: string[]
): Promise<Response | null> {
    const ip = clientIp(request);
    const kv = env?.kv as KVNamespace | undefined;
    if (!ip || !kv) return null;

    const reqURL = new URL(request.url);
    // 根路径（空段）与「每段都在字典内」的随机路径组合：豁免，不触发整表解析
    const segs = segments ?? reqURL.pathname.split('/').filter(Boolean);
    if (segs.length === 0 || isPathInDictionary(segs)) return null;

    if (!await isPermanentBlacklisted(ip, kv)) return null;

    console.warn(`[永久黑名单] IP ${ip} 命中永久黑名单，直接拦截`);
    return await cf1101RateLimitedResponse(reqURL.host, ip);
}

/**
 * 对非内置路径请求执行守卫。
 * 返回 Response：命中黑名单/限流（429 nginx 页）、探测族短路（朴素 404）或伪装反代结果。
 * 返回 null：属于排除路径，应继续由上层内置逻辑处理。
 */
export async function guardNonBuiltinPath(
    request: Request,
    env: any,
    ctx: GuardContext
): Promise<Response | null> {
    // 排除语义（对齐 cfnew）：根路径、login、管理路径不进入伪装/限流。
    //
    // B-09：**POST 不再整条豁免**。原实现第一行 `if (request.method === 'POST') return null;`
    // 让 POST /<任意路径> 同时绕过永久黑名单、限流与违规计数，被罚的 IP 换个 method 就继续畅通，
    // 而且请求会被 worker.ts 无配额地转发到兜底域（一条免费的 POST 出口）。
    // 现在 POST 与 GET 走同一套判据；内置路由（/panel、/login 等）在 worker.ts 的 switch 里
    // 就已分流，XHTTP 的 POST 走的是公共伪装字典路径（字典内路径不限流），
    // 因此这两条正常链路都不受影响。
    const reqURL = new URL(request.url);
    if (reqURL.pathname === '/') return null;

    const segments = reqURL.pathname.split('/').filter(Boolean);
    // ⚠️ 这行**不是死代码**，删之前先读完这段：
    //   worker.ts 的 switch 用 `pathName.split('/')[1]` 取首段，这里用 `filter(Boolean)[0]` ——
    //   对 `//login/x`（双前导斜杠）两者给出不同答案（前者 `''` → default 分支，后者 `'login'`）。
    //   也就是说双斜杠路径确实会绕过 switch 进到本函数，而这行保证它与 `/login/x` **同构**：
    //   同样落到 handlers.fallback()，而不是被当成「字典外路径」限流 + 违规计数 + 伪装反代。
    //   回归用例：tools/camouflage-cpu.test.mjs「双斜杠 login 路径与 /login/... 同构」。
    if (segments[0] === 'login') return null;

    // 管理路径：面板 subPath（默认 UUID）—— 与 cfnew 的“管理员路径”语义对齐
    const adminPath = String((globalThis as any).httpConfig?.subPath || (globalThis as any).globalConfig?.userID || '')
        .toLowerCase()
        .replace(/^\//, '');
    if (adminPath && segments[0].toLowerCase() === adminPath) return null;

    const ip = clientIp(request);
    const kv = env?.kv as KVNamespace | undefined;

    // 1. 永久黑名单（与 WS 升级共用同一份守卫；传入已算好的 segments 避免重复判定）
    const blocked = await guardPermanentBlacklist(request, env, segments);
    if (blocked) return blocked;

    // 2. 路径字典校验 + 限流（字典路径视为合法公开路径，不限流不计数；
    //    仅路径含字典外段才触发限流与违规计数，避免误伤伪装站点正常流量）
    if (!isPathInDictionary(segments)) {
        // F17：内存 Map 是 isolate 私有的，换边缘即可把计数清零；内存未超限时再看一次
        // KV 里的跨边缘计数（每 IP 每窗口至多 1 次读，KV 未绑定/读失败一律放行）。
        if (!checkRateLimit(ip) || !(await checkRateLimitShared(kv, ip))) {
            console.warn(`[速率限制] IP ${ip} 超过非管理员路径请求限制`);
            if (kv) await writeRateLimitKV(kv, ip, ctx);
            // B-10：只有「看着像扫描探测」的请求才推进违规计数（阈值 22 → 永久封禁，成员无 TTL）。
            // 伪装站首页一次加载就能并发 6+ 个字典外静态资源，原本足够把一个**正常访客**
            // （以及 CGNAT 后面的一整片用户）推到永久黑名单。静态资源、以及浏览器会带
            // 真实 Referer 的资源请求，都不该算探测 —— 它们由限流挡住就够了。
            const looksLikeProbe = !STATIC_ASSET_PATH_RE.test(reqURL.pathname);
            if (ip && kv && looksLikeProbe) ctx.waitUntil(recordViolationAndMaybeBan(ip, kv, ctx));
            return await cf1101RateLimitedResponse(reqURL.host, ip);
        }
        recordRateLimit(ip);
    }

    // 3. P1：秘密文件 / 版本控制探测族 → 朴素 404，**不产生任何出站**。
    //    放在限流之后是刻意的：这些请求照样计入违规计数（喂永久黑名单），
    //    只是不再被转给伪装域 —— 否则 Cloudflare 会把这次出站也算进「同族探测」，
    //    后台多出一类「An outbound fetch matched the same probe family」告警。
    //    本函数只覆盖「非内置路径」；`/panel/.env` 这类带内置路由前缀的请求在
    //    handlers.fallback 里由同一判据拦截（两个入口互不重叠，见各自注释）。
    if (isProbePath(reqURL.pathname)) return probeNotFoundResponse(env);

    // 4. 全路径伪装反代（字典内路径同样伪装；命中限流已在上面拦截）
    return await camouflageProxy(request, env);
}
