import { fetchWarpAccounts } from '@warp';
import { getDomain, parseHostPort, resolveDNS } from '@utils';
import { base64DecodeUtf8, safeErrorMessage } from '@common';
import { getKvCache, setKvCache, clearKvCache } from './kv-cache';
// 零依赖的出厂默认值：只作「字段类型基准」，绝不写入 KV、也不当作当前值使用
import { DEFAULT_SETTINGS } from './common/defaults';

/**
 * warpAccounts 读入守卫：KV 里的账号可能被手工改过、或残留旧格式（reserved 空串 / 缺字段），
 * 坏值不该继续往下传 —— 下游会拿 reserved 解 base64，并按 [0]/[1] 两个账号建 outbound。
 */
function isValidWarpAccount(account: unknown): boolean {
    if (!account || typeof account !== 'object') return false;

    const { privateKey, publicKey, warpIPv6, reserved } = account as Record<string, unknown>;
    return typeof privateKey === 'string' && privateKey.length > 0
        && typeof publicKey === 'string' && publicKey.length > 0
        && typeof warpIPv6 === 'string' && warpIPv6.length > 0
        && typeof reserved === 'string' && reserved.length > 0;
}

/**
 * 形状不合法（含不足 warp/wow 两个账号）→ 返回 null，由调用方交回 fetchWarpAccounts；
 * 不在此处重新实现注册逻辑。
 */
function normalizeWarpAccounts(value: unknown): WarpAccount[] | null {
    if (!Array.isArray(value) || value.length < 2) return null;

    for (const account of value) {
        if (!isValidWarpAccount(account)) return null;
    }

    return value as WarpAccount[];
}

export async function getDataset(
    request: Request,
    env: Env
): Promise<{ settings: Settings, warpAccounts: WarpAccount[] }> {
    const { httpConfig, settings } = globalThis;
    const panelVersion = httpConfig?.panelVersion;
    let proxySettings: Settings | null, warpAccounts: WarpAccount[] | null;

    try {
        // 对齐 cfnew：通过内存缓存读取，减少 KV 读取次数
        proxySettings = await getKvCache(env);
        // 读入即守卫：坏形状（reserved 空串 / 缺字段 / 账号数不足）→ null，走下面的重新获取
        warpAccounts = normalizeWarpAccounts(await env.kv.get('warpAccounts', { type: 'json' }));

        if (!proxySettings) {
            // KV 尚无配置（首次部署）→ 写入默认值
            const initVer = String(Date.now());
            await env.kv.put("proxySettings", JSON.stringify(settings));
            await env.kv.put("proxySettings_ver", initVer);
            // 直接填充缓存，避免下一个请求再读 KV
            setKvCache(settings, initVer);
            proxySettings = settings;
        }

        if (proxySettings && typeof (proxySettings as any).echServerName === 'string') {
            const val = (proxySettings as any).echServerName;
            (proxySettings as any).echServerName = val ? [val] : [];
        }

        if (!warpAccounts) {
            // 无账号或形状不合法：交回 fetchWarpAccounts（其内部已有「上游失败 → 内置默认账号」的回退）
            warpAccounts = await fetchWarpAccounts(env);
        }

        if (panelVersion && panelVersion !== proxySettings.panelVersion) {
            // 迁移前清缓存，使 updateDataset 读取最新 KV 数据而非 5min 内的旧缓存
            clearKvCache();
            proxySettings = await updateDataset(request, env);
        }

        return {
            settings: proxySettings,
            warpAccounts
        };
    } catch (error) {
        console.log(error);
        throw new Error(`An error occurred while getting KV: ${safeErrorMessage(error)}`);
    }
}

/**
 * 设置校验失败 —— 携带非法字段名，供上层返回 400 并指明具体字段；
 * 抛出时 KV 尚未写入，保证「全有或全无」（不会落半成品配置）。
 */
export class InvalidSettingsError extends Error {
    readonly fields: string[];

    constructor(fields: string[]) {
        super(`Invalid settings value for field(s): ${fields.join(', ')}`);
        this.name = 'InvalidSettingsError';
        this.fields = fields;
    }
}

/** 端口合法区间 */
const MIN_PORT = 1;
const MAX_PORT = 65535;

/** 出厂默认为 undefined 的可选数字字段：无法从默认值推断类型，单独指定 */
const OPTIONAL_NUMBER_FIELDS: Array<keyof Settings> = ['fragmentMaxSplitMin', 'fragmentMaxSplitMax'];

/** 已确认元素为 string 的数组字段：额外校验元素类型 */
const STRING_ARRAY_FIELDS: Array<keyof Settings> = [
    'proxyIPs', 'officialIPs', 'prefixes', 'cleanIPs', 'customCdnAddrs', 'echServerName',
    'hostSniList', 'customBypassRules', 'customBlockRules', 'customBypassSanctionRules',
    'warpEndpoints', 'customSubs', 'customConfigs'
];

/** 端口数组字段：额外校验 1..65535 范围 */
const PORT_ARRAY_FIELDS: Array<keyof Settings> = ['ports'];

type SettingsValueKind = 'string' | 'number' | 'boolean' | 'array' | 'object' | 'unknown';

function valueKind(value: unknown): SettingsValueKind {
    if (Array.isArray(value)) return 'array';

    switch (typeof value) {
        case 'string': return 'string';
        case 'number': return 'number';
        case 'boolean': return 'boolean';
        case 'object': return value === null ? 'unknown' : 'object';
        default: return 'unknown';
    }
}

/**
 * 按出厂默认（DEFAULT_SETTINGS）同名字段的运行时类型判断单个值是否非法：
 * 默认数组 → 必须数组；string → string；number → number 且有限；boolean → boolean；对象 → 对象。
 *
 * 基准必须是 DEFAULT_SETTINGS 而非 globalThis.settings：后者在暖 isolate 上被
 * setSettings 用 KV 值浅合并过，KV 里本就错型的字段会污染基准、导致非法值被放行。
 */
function isInvalidSettingsValue(field: string, value: unknown): boolean {
    const defaults = DEFAULT_SETTINGS as unknown as Record<string, unknown>;
    const key = field as keyof Settings;

    if (OPTIONAL_NUMBER_FIELDS.includes(key)) {
        // 可选字段允许 null（表示未设置），其余必须是有限数字
        return value !== null && (typeof value !== 'number' || !Number.isFinite(value));
    }

    const expected = valueKind(defaults[field]);
    if (expected === 'unknown') return false; // 无法从默认值推断类型 → 不校验

    if (expected !== valueKind(value)) return true;

    if (expected === 'number') return !Number.isFinite(value as number);

    if (expected === 'array') {
        if (STRING_ARRAY_FIELDS.includes(key) && !(value as unknown[]).every(item => typeof item === 'string')) return true;

        if (PORT_ARRAY_FIELDS.includes(key)
            && !(value as unknown[]).every(port => typeof port === 'number' && Number.isInteger(port) && port >= MIN_PORT && port <= MAX_PORT)) return true;
    }

    return false;
}

/** body 是否真的提供了该字段的值（null / undefined 会经 `??` 回落到历史值） */
function hasBodyValue(body: Record<string, unknown> | null, field: string): boolean {
    return !!body && body[field] !== undefined && body[field] !== null;
}

/** 历史脏值兜底用的出厂默认值（浅拷贝，避免把 DEFAULT_SETTINGS 的引用写进 KV / 缓存） */
function cloneDefaultValue(field: keyof Settings): unknown {
    const fallback = (DEFAULT_SETTINGS as unknown as Record<string, unknown>)[field as string];
    if (Array.isArray(fallback)) return fallback.map(item => (item && typeof item === 'object' ? { ...item } : item));
    if (fallback && typeof fallback === 'object') return { ...(fallback as object) };
    return fallback;
}

export async function updateDataset(request: Request, env: Env): Promise<Settings> {
    const { settings, httpConfig } = globalThis;
    const panelVersion = httpConfig?.panelVersion;
    const newSettings: Settings | null = request.method === 'PUT' ? await request.json() : null;
    let currentSettings: Settings | null;

    try {
        // 对齐 cfnew：通过缓存读取当前配置
        currentSettings = await getKvCache(env);
    } catch (error) {
        console.log(error);
        throw new Error(`An error occurred while getting current KV settings: ${safeErrorMessage(error)}`);
    }

    const getParam = async <T extends keyof Settings>(
        field: keyof Settings,
        callback?: (value: Settings[T]) => any | Promise<any>
    ) => {
        const value = newSettings?.[field] ?? currentSettings?.[field] ?? settings[field];
        return callback ? await callback(value) : value;
    };

    const fields: Array<
        [keyof Settings] |
        [keyof Settings, keyof Settings, (key: any) => any | Promise<any>]
    > = [
            ["remoteDNS"],
            ["remoteDnsHost", "remoteDNS", getDnsParams],
            ["localDNS"],
            ["antiSanctionDNS"],
            ["enableIPv6"],
            ["fakeDNS"],
            ["logLevel"],
            ["allowLANConnection"],
            ["proxyIPMode"],
            ["regionMatch"],
            ["wkRegion"],
            ["proxyOnly"],
            ["proxyDegrade"],
            ["proxyIPs"],
            ["officialIPs"],
            ["prefixes"],
            ["upstreamProxy"],
            ["upstreamParams", "upstreamProxy", extractUpstreamParams],
            ["outProxy"],
            ["outProxyParams", "outProxy", extractProxyParams],
            ["cleanIPs"],
            ["customCdnAddrs"],
            ["bestVLTRInterval"],
            ["VLConfigs"],
            ["TRConfigs"],
            ["ports"],
            ["fingerprint"],
            ["alpn"],
            ["enableTFO"],
            ["fragmentMode"],
            ["fragmentLengthMin"],
            ["fragmentLengthMax"],
            ["fragmentIntervalMin"],
            ["fragmentIntervalMax"],
            ["fragmentMaxSplitMin"],
            ["fragmentMaxSplitMax"],
            ["fragmentPackets"],
            ["enableECH"],
            ["echServerName", "echServerName", normalizeEchNames],
            ["hostSniList", "hostSniList", normalizeEchNames],
            ["bypassIran"],
            ["bypassChina"],
            ["bypassRussia"],
            ["bypassOpenAi"],
            ["bypassGoogleAi"],
            ["bypassMicrosoft"],
            ["bypassOracle"],
            ["bypassDocker"],
            ["bypassAdobe"],
            ["bypassEpicGames"],
            ["bypassIntel"],
            ["bypassAmd"],
            ["bypassNvidia"],
            ["bypassAsus"],
            ["bypassHp"],
            ["bypassLenovo"],
            ["blockAds"],
            ["blockPorn"],
            ["blockUDP443"],
            ["blockMalware"],
            ["blockPhishing"],
            ["blockCryptominers"],
            ["customBypassRules"],
            ["customBlockRules"],
            ["customBypassSanctionRules"],
            ["warpRemoteDNS"],
            ["warpEndpoints"],
            ["bestWarpInterval"],
            ["xrayUdpNoises"],
            ["knockerNoiseMode"],
            ["noiseCountMin"],
            ["noiseCountMax"],
            ["noiseSizeMin"],
            ["noiseSizeMax"],
            ["noiseDelayMin"],
            ["noiseDelayMax"],
            ["amneziaNoiseCount"],
            ["amneziaNoiseSizeMin"],
            ["amneziaNoiseSizeMax"],
            ["customSubs"],
            ["customConfigs"],
            ["aclEnabled"],
            ["aclTemplate"]
        ];

    const bodyObj = (newSettings && typeof newSettings === 'object' && !Array.isArray(newSettings))
        ? newSettings as unknown as Record<string, unknown>
        : null;

    // C-03（延伸）：校验要覆盖「最终将被写入的值」，而不只是 body 里出现的字段 ——
    //  · body 提供了值（非 null/undefined）→ 沿用严格校验，任一字段非法即整体拒绝（KV 零写入）；
    //  · body 未提供（含 null 回落）→ 写入的是 currentSettings / globalThis.settings 里的历史值，
    //    非法时不再放行写回，而是在下面取值处安全归一到出厂默认（历史脏 KV 不会把用户锁在门外）。
    if (bodyObj) {
        const bodyFields = new Set<string>(
            fields.map(([key, callbackKey]) => (callbackKey ?? key) as string)
        );
        const invalidFields = [...bodyFields].filter(
            field => field in bodyObj && isInvalidSettingsValue(field, bodyObj[field])
        );
        if (invalidFields.length) throw new InvalidSettingsError(invalidFields);
    }

    const entries = await Promise.all(
        fields.map(async ([key, callbackKey, callbackFunc]) => {
            const source = (callbackKey ?? key) as string;
            let value = await getParam(callbackKey ?? key, callbackFunc) as unknown;

            // 写入前最后一道：值来自 body 却仍非法 → 整体拒绝；来自历史 → 归一，不把脏值写回 KV
            if (isInvalidSettingsValue(key as string, value)) {
                if (hasBodyValue(bodyObj, source)) throw new InvalidSettingsError([key as string]);
                value = cloneDefaultValue(key);
            }

            return [key, value];
        })
    );

    const updatedSettings: Settings = {
        ...Object.fromEntries(entries),
        panelVersion: panelVersion
    };

    try {
        await env.kv.put("proxySettings", JSON.stringify(updatedSettings));
        // 对齐 cfnew：写入后更新版本键，使其它 isolate 在下个请求时检测变更
        const newVer = String(Date.now());
        await env.kv.put("proxySettings_ver", newVer).catch(() => {});
        // 对齐 cfnew：前端保存后直接填充内存缓存，后续请求 0 KV 读取
        setKvCache(updatedSettings, newVer);
        return updatedSettings;
    } catch (error) {
        console.log(error);
        throw new Error(`An error occurred while updating KV: ${safeErrorMessage(error)}`);
    }
}

async function getDnsParams(dns: string): Promise<DnsHost> {
    const { host, isHostDomain } = getDomain(dns);
    const dohHost: DnsHost = { host, isDomain: isHostDomain, ipv4: [], ipv6: [] };

    if (isHostDomain) {
        const { ipv4, ipv6 } = await resolveDNS(host);
        dohHost.ipv4 = ipv4;
        dohHost.ipv6 = ipv6;
    }

    return dohHost;
}

function extractProxyParams(chainProxy: string) {
    if (!chainProxy) return {};

    const { _SS_, _TR_, _VL_, _VM_ } = globalThis.dict;
    let url = new URL(chainProxy);
    const protocol = url.protocol.slice(0, -1);
    const stdProtocol = protocol === "ss" ? _SS_ : protocol.replace("socks5", "socks");

    if (stdProtocol === _VM_) {
        const config = JSON.parse(base64DecodeUtf8(url.host));
        return {
            protocol: stdProtocol,
            uuid: config.id,
            server: config.add,
            port: +config.port,
            aid: +config.aid,
            type: config.net,
            headerType: config.type,
            serviceName: config.path,
            authority: config.authority,
            path: config.path || undefined,
            host: config.host || undefined,
            security: config.tls,
            sni: config.sni,
            fp: config.fp,
            alpn: config.alpn || undefined
        };
    }

    const configParams: Record<string, string | number | undefined> = {
        protocol: stdProtocol,
        server: url.hostname,
        port: +url.port
    };

    const parseParams = (queryParams: boolean, customParams: Record<string, string | undefined>) => {
        if (queryParams) {
            for (const [key, value] of url.searchParams) {
                configParams[key] = value || undefined;
            }
        }

        return {
            ...configParams,
            ...customParams
        };
    }

    switch (stdProtocol) {
        case _VL_:
            return parseParams(true, {
                uuid: url.username
            });

        case _TR_:
            return parseParams(true, {
                password: url.username
            });

        case _SS_:
            const auth = base64DecodeUtf8(url.username);
            const [first, ...rest] = auth.split(':');
            return parseParams(true, {
                method: first,
                password: rest.join(':')
            });

        case 'socks':
        case 'http':
            let user, pass;
            try {
                const userInfo = base64DecodeUtf8(url.username);
                if (userInfo.includes(":")) [user, pass] = userInfo.split(":");
            } catch (error) {
                user = url.username;
                pass = url.password;
            }

            return parseParams(false, {
                user: user || undefined,
                pass: pass || undefined
            });

        default:
            return {};
    }
}

function extractUpstreamParams(upstreamProxy: string): UpstreamProxy {
    let upstreamServer, upstreamPort;
    if (upstreamProxy) ({ host: upstreamServer, port: upstreamPort } = parseHostPort(upstreamProxy, true));
    return { upstreamServer, upstreamPort };
}


function normalizeEchNames(val: unknown): string[] {
    if (!val) return [];
    if (Array.isArray(val)) return val;
    if (typeof val === 'string') return [val];
    return [];
}
