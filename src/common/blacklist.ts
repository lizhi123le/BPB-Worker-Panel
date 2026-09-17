import { withTimeout } from "@common";

/**
 * 永久黑名单 — IP 累计违规超过阈值后永久封禁（内存缓存 + KV 持久化）。
 * 对齐 cfnew：KV 键 `permanentBlacklist` 存 IP 数组，`violation:<ip>` 存累计违规次数。
 * 非永久黑名单 IP 的计数 7 天过期自动归零；已被永久封禁的 IP 计数持久保存（不重置）。
 */

const BLACKLIST_KV_KEY = 'permanentBlacklist';
const VIOLATION_PREFIX = 'violation:';
const PERMANENT_BLACKLIST_THRESHOLD = 22;
const CACHE_TTL_MS = 60 * 1000; // 60s 内存缓存

let blacklistCache: Set<string> | null = null;
let blacklistCacheTime = 0;

async function loadPermanentBlacklist(kv: KVNamespace): Promise<Set<string>> {
    if (blacklistCache && (Date.now() - blacklistCacheTime) < CACHE_TTL_MS) {
        return blacklistCache;
    }
    try {
        const raw = await withTimeout(kv.get(BLACKLIST_KV_KEY), 3000, 'KV 永久黑名单读取');
        blacklistCache = raw ? new Set(JSON.parse(raw)) : new Set();
        blacklistCacheTime = Date.now();
    } catch (e) {
        // 读取失败：保留已有缓存，避免每次请求都触 KV
        blacklistCache = blacklistCache || new Set();
        console.warn('[永久黑名单] KV 读取失败:', (e as Error)?.message ?? String(e));
    }
    return blacklistCache;
}

/** 检查 IP 是否已在永久黑名单中 */
export async function isPermanentBlacklisted(ip: string, kv: KVNamespace): Promise<boolean> {
    if (!ip) return false;
    const blacklist = await loadPermanentBlacklist(kv);
    return blacklist.has(ip);
}

/**
 * 记录一次违规并检查是否达到永久封禁阈值。
 * `ctx.waitUntil` 用于后台写 KV，避免阻塞响应。
 */
export async function recordViolationAndMaybeBan(
    ip: string,
    kv: KVNamespace,
    ctx: { waitUntil(p: Promise<unknown>): void }
): Promise<void> {
    if (!ip || !kv) return;
    try {
        const key = `${VIOLATION_PREFIX}${ip}`;
        const raw = await withTimeout(kv.get(key), 3000, 'KV 违规计数读取');
        const currentCount = (raw ? Number(raw) : 0) + 1;
        const blacklist = await loadPermanentBlacklist(kv);
        const alreadyBanned = blacklist.has(ip);

        if (alreadyBanned) {
            // 已永久封禁 IP：计数持久保存（无 expirationTtl）
            ctx.waitUntil(
                withTimeout(kv.put(key, String(currentCount)), 2000, 'KV 违规计数写入')
                    .catch(() => {})
            );
        } else {
            // 非永久封禁 IP：计数每周重置（7 天过期自动归零）
            ctx.waitUntil(
                withTimeout(kv.put(key, String(currentCount), { expirationTtl: 86400 * 7 }), 2000, 'KV 违规计数写入')
                    .catch(() => {})
            );
        }

        if (currentCount >= PERMANENT_BLACKLIST_THRESHOLD && !alreadyBanned) {
            blacklist.add(ip);
            blacklistCacheTime = Date.now();
            ctx.waitUntil(
                withTimeout(kv.put(BLACKLIST_KV_KEY, JSON.stringify([...blacklist])), 2000, 'KV 黑名单写入')
                    .catch(() => {})
            );
            console.warn(`[永久黑名单] IP ${ip} 累计违规 ${currentCount} 次，已加入永久黑名单`);
        }
    } catch (err) {
        console.warn('[永久黑名单] 记录违规失败:', (err as Error)?.message ?? String(err));
    }
}

/** 供测试/内存重置使用（清空内存缓存，下次读取重新从 KV 加载） */
export function clearBlacklistMemoryCache(): void {
    blacklistCache = null;
    blacklistCacheTime = 0;
}
