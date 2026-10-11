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

/**
 * 违规计数合并参数（F-08）：
 * KV 读-改-写 + `waitUntil` 异步写在同一 IP 并发时会互相覆盖，计数长期到不了阈值。
 * 改为「内存累计 + KV 兜底」：同 isolate 内的并发请求只在内存里自增（无丢失），
 * KV 只承担跨 isolate 的基准与持久化，并按下列步长合并，把 KV 往返从「每次违规」降下来。
 */
const VIOLATION_MEMORY_TTL_MS = 5 * 60 * 1000; // 内存款有效期：过期后重新取 KV 基准（取 max 合并，不会回退）
const VIOLATION_MEMORY_MAX_IPS = 10000;        // 内存条目上限，超出按插入顺序淘汰最旧条目
const VIOLATION_KV_WRITE_STEP = 5;             // 每累计 5 次违规写一次 KV（达阈值时必写）

/** 单 IP 的违规计数合并状态（F-08） */
interface ViolationRecord {
    count: number;     // 内存累计（已与 KV 基准取 max）
    loadedAt: number;  // 最近一次取 KV 基准的时间
    written: number;   // 最近一次写进 KV 的计数
}

const violationPool = new Map<string, ViolationRecord>();

let blacklistCache: Set<string> | null = null;
let blacklistCacheTime = 0;
// 是否曾成功从 KV 载入过完整黑名单：未确认载入时禁止整体写回，
// 否则「达阈值入列」的 [...blacklist] 会把 KV 中既有的永久封禁覆写为仅含新 IP。
let blacklistLoaded = false;

/**
 * 强制从 KV 重读永久黑名单（忽略内存 TTL），并与内存中已确知的内容合并。
 * 返回 null 表示读取失败 —— 调用方必须跳过写回，绝不缩小既有封禁集合。
 */
async function readPermanentBlacklist(kv: KVNamespace): Promise<Set<string> | null> {
    try {
        const raw = await withTimeout(kv.get(BLACKLIST_KV_KEY), 3000, 'KV 永久黑名单读取');
        const parsed = raw ? JSON.parse(raw) : [];
        // 非数组形态视为数据损坏：按读取失败处理，不据此覆写 KV
        if (!Array.isArray(parsed)) throw new Error('KV 永久黑名单数据格式异常');
        const fresh = new Set<string>(parsed);
        for (const ip of blacklistCache ?? []) fresh.add(ip);
        return fresh;
    } catch (e) {
        console.warn('[永久黑名单] KV 读取失败:', (e as Error)?.message ?? String(e));
        return null;
    }
}

async function loadPermanentBlacklist(kv: KVNamespace): Promise<Set<string>> {
    if (blacklistCache && (Date.now() - blacklistCacheTime) < CACHE_TTL_MS) {
        return blacklistCache;
    }
    const fresh = await readPermanentBlacklist(kv);
    if (fresh) {
        blacklistCache = fresh;
        blacklistCacheTime = Date.now();
        blacklistLoaded = true;
        return fresh;
    }
    // 读取失败：保留已有缓存（避免每次请求都触 KV），但标记「未确认载入」→ 禁止整体写回
    blacklistCache = blacklistCache || new Set();
    blacklistLoaded = false;
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
 *
 * F-08：计数以内存为主（同 isolate 内并发自增无丢失），KV 只作基准与持久化 ——
 * 阈值判定看内存计数，因此并发下「22 次违规必然封禁」不依赖 KV 的读-改-写是否成功。
 */
export async function recordViolationAndMaybeBan(
    ip: string,
    kv: KVNamespace,
    ctx: { waitUntil(p: Promise<unknown>): void }
): Promise<void> {
    if (!ip || !kv) return;
    try {
        const key = `${VIOLATION_PREFIX}${ip}`;
        const now = Date.now();

        let record = violationPool.get(ip);
        if (!record) {
            while (violationPool.size >= VIOLATION_MEMORY_MAX_IPS) {
                const oldest = violationPool.keys().next();
                if (oldest.done) break;
                violationPool.delete(oldest.value);
            }
            record = { count: 0, loadedAt: 0, written: 0 };
            violationPool.set(ip, record);
        }

        // 1) KV 基准：懒惰读取（每 5 分钟至多 1 次），取 max 合并 —— 内存计数只增不减；
        //    先打标记再 await，否则同 isolate 的并发请求会同时读到旧基准、把这次读放大成 N 次；
        //    读失败保留内存计数，绝不把已累计的次数丢掉。
        if (now - record.loadedAt >= VIOLATION_MEMORY_TTL_MS) {
            record.loadedAt = now;
            try {
                const raw = await withTimeout(kv.get(key), 3000, 'KV 违规计数读取');
                record.count = Math.max(record.count, raw ? (Number(raw) || 0) : 0);
            } catch (e) {
                console.warn('[永久黑名单] KV 违规计数读取失败，按内存计数继续:', (e as Error)?.message ?? String(e));
            }
        }

        // 2) 内存自增：同 isolate 内并发请求各自加一，不经过 KV，因此不存在读-改-写丢失
        record.count += 1;
        const currentCount = record.count;

        let blacklist = await loadPermanentBlacklist(kv);
        const alreadyBanned = blacklist.has(ip);

        // 3) 合并写回：达阈值必写（跨 isolate 的阈值判定与 F-05 兜底都依赖它），否则每累计 5 次写一次
        const atThreshold = currentCount >= PERMANENT_BLACKLIST_THRESHOLD && !alreadyBanned;
        if (atThreshold || currentCount - record.written >= VIOLATION_KV_WRITE_STEP) {
            record.written = currentCount;
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
        }

        if (currentCount >= PERMANENT_BLACKLIST_THRESHOLD && !alreadyBanned) {
            // 写回前必须确认黑名单内容来自 KV：未成功载入时先重读一次（带超时）并合并，
            // 仍读不到就跳过写回 —— 宁可不加新封禁，也绝不把既有封禁覆写成「仅含新 IP」。
            if (!blacklistLoaded) {
                const refreshed = await readPermanentBlacklist(kv);
                if (!refreshed) {
                    console.warn(`[永久黑名单] IP ${ip} 累计违规 ${currentCount} 次，但黑名单未成功载入，跳过黑名单写回，避免覆写既有封禁`);
                    return;
                }
                blacklist = refreshed;
                blacklistCache = refreshed;
                blacklistLoaded = true;
            }

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
    blacklistLoaded = false;
    violationPool.clear();
}
