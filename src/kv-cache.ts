/**
 * In-memory KV cache with version-based invalidation
 *
 * Aligned with cfnew 加载键值配置() pattern:
 *   1. TTL window (5min) → trust cache, 0 KV reads
 *   2. Out of TTL → lightweight `proxySettings_ver` check (~13B)
 *   3. Version unchanged → refresh timestamp, return cached config
 *   4. Version changed → read full config + post-read version re-check (race detection)
 *   5. Error → preserve existing cache, don't cascade failure
 */

import { crossRequestSingleFlight } from '@common';

const CACHE_TTL = 300_000; // 5min, same as cfnew 键值缓存期限

interface KvCacheStore {
    settings: Settings | null;
    timestamp: number;
    version: string;
}

function getStore(): KvCacheStore {
    if (!globalThis.__kvCache) {
        globalThis.__kvCache = {
            settings: null,
            timestamp: 0,
            version: ''
        };
    }
    return globalThis.__kvCache;
}

/**
 * 单飞标记：**只存「谁正在读 KV」，不存 Promise**。
 *
 * 旧实现把正在进行的读存在模块级 `loadingPromise` 里、并发请求直接 await 它。那在 Workers 上
 * 是错的：`handle_cross_request_promise_resolution` 下，创建它的请求先结束（客户端 abort、
 * 跳走）时它永远无法 settle，后来者 await 会直接抛
 * “This promise was created by a request that has since ended”。
 * 详见 common.ts 的 crossRequestSingleFlight 注释。
 */
const KV_SETTINGS_KEY = 'proxySettings';
const kvLoadingMarkers = new Set<string>();

/** 缓存的「已就绪」判据：读成功过一轮（含空 KV 的情形由 timestamp=0 表示未就绪） */
function cachedSettings(): Settings | null {
    const store = getStore();
    return store.timestamp > 0 ? store.settings : null;
}

/**
 * Force clear cache — next call to getKvCache will re-read from KV
 */
export function clearKvCache(): void {
    getStore().timestamp = 0;
}

/**
 * Directly populate the cache store (used after initializing KV with defaults).
 * Takes a deep copy to isolate the cache from subsequent Object.assign mutations.
 */
export function setKvCache(settings: Settings, version: string): void {
    const store = getStore();
    store.settings = JSON.parse(JSON.stringify(settings));
    store.version = version;
    store.timestamp = Date.now();
}

/**
 * Read proxySettings from KV with in-memory caching.
 *
 * Return order:
 *   1. Cached settings (if TTL hit)
 *   2. Fresh settings from KV (if another request finished first, this returns its result)
 *   3. null (if KV empty — caller should initialize)
 */
export async function getKvCache(env: Env): Promise<Settings | null> {
    const store = getStore();
    const cached = cachedSettings();

    // P1: TTL window — 完全信任缓存，跳过所有 KV 读取。
    // 复用 cachedSettings() 的「已就绪」判据，不在这里重写一遍 settings/timestamp 的组合条件
    if (cached && Date.now() - store.timestamp < CACHE_TTL) {
        return cached;
    }

    // P1.5: 同键并发去重（跨请求安全：轮询结果，不 await 别人的 Promise）。
    // 等待上限 200ms：KV 正常情况下 10~20ms 就回，等太久反而拖慢首屏。
    return await crossRequestSingleFlight<Settings>(
        kvLoadingMarkers,
        KV_SETTINGS_KEY,
        cachedSettings,
        () => loadSettingsFromKv(env),
        { tries: 20, delayMs: 10 }
    );
}

/** 真正读一次 KV（原 loadingPromise 的 body，逐字搬过来） */
async function loadSettingsFromKv(env: Env): Promise<Settings | null> {
    const store = getStore();
    const now = Date.now();
    try {
        // P2: 轻量版本检查（~13B），cfnew 的 c_ver
        let currentVer = '';
        try {
            currentVer = (await env.kv.get('proxySettings_ver')) || '';
        } catch { /* KV read timeout — proceed without version */ }

        // 版本未变化且已有缓存 → 仅刷新时间戳，跳过完整读取
        if (currentVer && currentVer === store.version && store.settings) {
            store.timestamp = now;
            return store.settings;
        }

        // P3: 读取完整配置
        const raw: Settings | null = await env.kv.get('proxySettings', { type: 'json' });
        if (raw) {
            // P3-2: 读后重读版本，检测写入端竞态（cfnew: 重读 c_ver）
            let postVer = '';
            try {
                postVer = (await env.kv.get('proxySettings_ver')) || '';
            } catch {}

            if (postVer && postVer !== currentVer) {
                // 版本在读取过程中变化 → 重新读取配置
                const retry: Settings | null = await env.kv.get('proxySettings', { type: 'json' });
                if (retry) {
                    store.settings = JSON.parse(JSON.stringify(retry));
                    store.version = postVer;
                    store.timestamp = Date.now();
                    return store.settings;
                }
            }

            // 深拷贝隔离缓存，防止 Object.assign 污染
            store.settings = JSON.parse(JSON.stringify(raw));
            store.version = currentVer || '';
            store.timestamp = Date.now();
        } else {
            // KV 尚无配置（首次部署）— 返回 null 让调用方初始化
            store.settings = null;
            store.timestamp = 0;
            store.version = '';
        }

        return store.settings;
    } catch (err) {
        // 读取失败时保留现有缓存（cfnew: 避免临时故障导致配置丢失）
        if (!store.settings) throw err;
        return store.settings;
    }
}
