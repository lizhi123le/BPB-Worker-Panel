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

// Singleton loading promise for concurrent request dedup (cfnew: kvLoadingPromise)
let loadingPromise: Promise<Settings | null> | null = null;

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
 *   1. Cached settings (if TTL hit or version unchanged)
 *   2. Fresh settings from KV (if cache expired or version changed)
 *   3. null (if KV empty — caller should initialize)
 */
export async function getKvCache(env: Env): Promise<Settings | null> {
    const store = getStore();
    const now = Date.now();

    // P1: TTL window — 完全信任缓存，跳过所有 KV 读取
    if (store.settings && store.timestamp > 0 && (now - store.timestamp) < CACHE_TTL) {
        return store.settings;
    }

    // P1.5: 并发去重 — 共享一次 KV 读取（cfnew: kvLoadingPromise）
    if (loadingPromise) return loadingPromise;

    loadingPromise = (async (): Promise<Settings | null> => {
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
        } finally {
            loadingPromise = null;
        }
    })();

    return loadingPromise;
}
