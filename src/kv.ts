import { fetchWarpAccounts, DEFAULT_WARP_ACCOUNTS } from '@warp';
import { getDomain, parseHostPort, resolveDNS } from '@utils';
import { base64DecodeUtf8, KV_READ_TIMEOUT_MS, safeErrorMessage, withTimeout } from '@common';
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

/**
 * B-02：WARP 注册失败的「退避标记」。
 *
 * 原实现：注册失败 → 返回内置账号但**不写 KV** → `getDataset` 每见到「KV 里没有有效账号」
 * 就再注册一次。而 `getDataset` 由 `setSettings` 调用，`setSettings` 又在**每次 WS 升级与
 * 每次 XHTTP 请求**上执行 —— 上游被墙时，每条代理连接都付 2 次 X25519 密钥生成 + 至少
 * 1 次外网请求（最坏挂到 8s 超时）。
 *
 * 这里改成「失败只付一次」：写一个带 TTL 的时间戳，窗口内直接使用内置账号、完全不碰网络。
 *
 * 为什么**不**把内置账号写进 KV（这是最容易想到的写法，但会反噬）：
 * 重新注册的判据是 `!normalizeWarpAccounts(kv.get('warpAccounts'))`，而内置账号两条都
 * 形状合法 → 一旦落库，判据永远为 false，上游恢复后也**再也不会**注册。那不是修，是把
 * 「每次重试」变成「永不重试」。
 */
const WARP_STALE_KV_KEY = 'warpAccountsStaleAt';
const WARP_STALE_TTL_SECONDS = 20 * 60;
const WARP_STALE_TTL_MS = WARP_STALE_TTL_SECONDS * 1000;
/** isolate 内闸门：KV 写入对上层的可见性有秒级延迟，没有它就会在窗口内被每个请求各写一次 */
let warpStaleMarkedAt = 0;

async function readWarpStaleAt(env: Env): Promise<number> {
    try {
        // 带超时：这条读在「KV 里没有有效账号」的分支上，是决定「要不要真去注册」的前置判断，
        // 挂住它等于把整份订阅挂住（注册本身已有 8s×2 的上限）。
        const raw = await withTimeout(env.kv.get(WARP_STALE_KV_KEY), KV_READ_TIMEOUT_MS, 'KV WARP 退避标记读取');
        const at = Number(raw);
        return Number.isFinite(at) ? at : 0;
    } catch {
        return 0;
    }
}

/**
 * 注册一次；失败时写退避标记。
 * 标记写失败（KV 写额度/临时故障）不得让请求失败 —— 退化成「下次再试」即可。
 */
async function registerWarpAccounts(env: Env): Promise<WarpAccount[]> {
    const { accounts, fallback } = await fetchWarpAccounts(env);

    if (fallback && Date.now() - warpStaleMarkedAt > WARP_STALE_TTL_MS / 2) {
        warpStaleMarkedAt = Date.now();
        try {
            await env.kv.put(WARP_STALE_KV_KEY, String(warpStaleMarkedAt), {
                expirationTtl: WARP_STALE_TTL_SECONDS
            });
        } catch { /* 标记写失败只影响退避效果，不影响本次请求 */ }
    }

    return accounts;
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
        warpAccounts = normalizeWarpAccounts(await withTimeout(
            env.kv.get('warpAccounts', { type: 'json' }),
            KV_READ_TIMEOUT_MS,
            'KV WARP 账号读取'
        ));

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

        // 向后兼容：旧 KV 里没有「节点随机路径」开关（面板后续新增）时按出厂默认补齐。
        // 只在内存里补，不写 KV —— 用户下次保存设置时才落库；否则面板下拉会取到 undefined 而显示空白。
        if (proxySettings && typeof (proxySettings as any).randomPath !== 'boolean') {
            (proxySettings as any).randomPath = DEFAULT_SETTINGS.randomPath;
        }

        // 向后兼容：该开关改过名（旧键 `xhttpConfigs` → 新键 `xpConfigs`，传输名不进部署面）。
        // **必须读旧键**：已开启该传输的存量部署里 KV 存的还是旧名，不迁移就表现为
        // 「升级后面板开关变灰、节点消失」，而且不报任何错。策略是只读旧名、只写新名 ——
        // 下次用户在面板保存设置时自然落成新名，不需要额外迁移脚本。
        // （全仓唯一保留 `xhttpConfigs` 字面量的地方，删掉它就等于丢掉老用户的配置。）
        // 另外：没有该字段时必须补出厂默认，否则面板 initiatePanel 用 `VL + TR + xp` 求和会得到
        // NaN，「至少选一个协议」的拦截随即可被绕过（`NaN === 0` 恒 false）。
        if (proxySettings && typeof (proxySettings as any).xpConfigs !== 'boolean') {
            const legacyXpConfigs = (proxySettings as any).xhttpConfigs;
            (proxySettings as any).xpConfigs = typeof legacyXpConfigs === 'boolean'
                ? legacyXpConfigs
                : DEFAULT_SETTINGS.xpConfigs;
        }

        if (!warpAccounts) {
            // B-02：先看退避标记。窗口内直接用内置账号（0 次网络请求、0 次密钥生成）；
            // 标记缺失或已过期才真正去注册一次，注册失败会重新写标记。
            const staleAt = await readWarpStaleAt(env);
            warpAccounts = staleAt && Date.now() - staleAt < WARP_STALE_TTL_MS
                ? [...DEFAULT_WARP_ACCOUNTS]
                : await registerWarpAccounts(env);
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
    let newSettings: Settings | null = null;
    if (request.method === 'PUT') {
        // B-30：`request.json()` 原先在 try 之外 —— body 不是合法 JSON 时 SyntaxError 一路冒到
        // handlers.ts 的 catch，用户拿到的是 `{"success":false,"status":500}`。这是**入站字段**
        // 的问题（坏请求体），按「非法字段」映射成 400，与其它校验失败同一条出口。
        try {
            newSettings = await request.json() as Settings;
        } catch {
            throw new InvalidSettingsError(['<request body>']);
        }
    }
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
            ["xpConfigs"],
            ["ports"],
            ["fingerprint"],
            ["alpn"],
            ["randomPath"],
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

        // B-54：白名单外的字段此前被**静默丢弃** —— 面板字段一旦改名，写入既不报错也不生效，
        // 这正是「闸门恒过」的第二个原因（smoke 里那批不存在的字段名即便改成 JSON 也会被静默吞掉）。
        // 这里改成可见告警而不是 400：面板 PUT 的 body 由 `Object.fromEntries(new FormData(form))`
        // 序列化，天然带三类**前端专用键**，用 400 判它们会让正常保存直接失败：
        //   · `outboundMode`（面板下拉，由 JS 折算成 proxyOnly/proxyDegrade）
        //   · `udpXrayNoise*`（噪声块动态生成的 input，由 JS 合并成 xrayUdpNoises 数组）
        //   · 改密弹窗的 `newPassword` / `confirmPassword`
        // 真正的契约守卫交给离线测试 tools/settings-fields.test.mjs（HTML 的 name 集合 vs 本白名单）。
        const UI_ONLY_FIELDS = new Set(['outboundMode', 'newPassword', 'confirmPassword']);
        const unknownFields = Object.keys(bodyObj).filter(
            field => !bodyFields.has(field)
                && !UI_ONLY_FIELDS.has(field)
                && !field.startsWith('udpXrayNoise')
        );
        if (unknownFields.length) {
            console.warn(`[设置写入] 忽略未知字段：${unknownFields.join(', ')}（若为面板新增字段，请同步本文件的 fields 白名单）`);
        }
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

/**
 * B-30：`outProxy` 的解析护栏。
 *
 * 面板里把出链代理填错一个字符（`socks5://user@host`、`vmess://` 后面跟了坏 base64、裸 `foo`）
 * 会让 `new URL` / `JSON.parse` / base64 解码抛错。原先这个异常在 `entries.map` 里冒到
 * handlers.ts 的 catch，前端拿到的是 **500**「Error occurred while updating settings」——
 * 而事实是「这个字段非法」。这里统一映射成 `InvalidSettingsError(['outProxy'])` → 400 + 字段名，
 * 与其它字段校验同一条出口（KV 零写入，全有或全无）。
 */
function extractProxyParams(chainProxy: string) {
    try {
        return extractProxyParamsUnsafe(chainProxy);
    } catch (error) {
        if (error instanceof InvalidSettingsError) throw error;
        throw new InvalidSettingsError(['outProxy']);
    }
}

function extractProxyParamsUnsafe(chainProxy: string) {
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
