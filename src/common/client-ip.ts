/**
 * S-03：客户端 IP 的**唯一取用点**（含形态校验）。
 *
 * 为什么需要校验：`CF-Connecting-IP` 在标准 CF 链路下由边缘覆写，但它同时被当作
 * **限流键**与**永久黑名单键**（firstCheck / blacklist / ratelimit / auth 四处）。
 * 一旦部署形态是「Worker 前面还挂了另一层反代 / service binding / 自建隧道 / wrangler dev」，
 * 这个头就是客户端完全可控的 —— 每请求换一个假 IP 即可让限流、跨边缘判定与永久黑名单全部失效，
 * 并且会反向污染 KV（`ratelimit:<假IP>` / `violation:<假IP>` 各写一条，正好打满写额度）。
 *
 * 判据：只接受**裸 IP 字面量**（IPv4 / IPv6，允许 IPv6 带方括号）；其它形态一律视为「无法识别」，
 * 返回空串 —— 调用方据此跳过计数与拉黑，而不是拿一个假键去记账。
 *
 * 单独成模块的原因：`@utils` 已经 import 了 `@common` 与 `./ratelimit`，把本函数放进那两者之一
 * 都会形成循环依赖；这里只单向依赖 `@utils`，谁都可以安全引用。
 */
import { isBareIPv4, isBareIPv6 } from '@utils';

/** 取出并校验客户端 IP；无法识别时返回 `''`（调用方必须按「没有 IP」处理） */
export function clientIp(request: Request): string {
    const raw = request.headers.get('CF-Connecting-IP');
    if (!raw) return '';

    // IPv6 允许以方括号形式出现（RFC 3986 字面量），校验前去掉
    const ip = raw.trim().replace(/^\[|\]$/g, '');
    if (!ip) return '';

    return isBareIPv4(ip) || isBareIPv6(ip) ? ip : '';
}
