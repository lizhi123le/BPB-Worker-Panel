import { Authenticate, generateJWTToken, resetPassword } from "@auth";
import { getDataset, updateDataset, InvalidSettingsError } from "@kv";
import { setKvCache, clearKvCache } from "../kv-cache";
import { DEFAULT_SETTINGS, setSettings } from "@init";
import { getClNormalConfig, getClWarpConfig } from "@clash/configs";
import { getSbCustomConfig, getSbWarpConfig } from "@sing-box/configs";
import { getXrCustomConfigs, getXrWarpConfigs } from "@xray/configs";
import { fetchWarpAccounts } from "@warp";
import { UnifiedWSHandler, getXPaddingIdentifier } from "@unified";
import { base64DecodeUtf8, base64EncodeUtf8, copySafeOutboundHeaders, escapeHtml, HttpStatus, respond, safeErrorMessage, securityHeaders } from "@common";
import { buildEntryPortMap, countryToRegion, DEFAULT_PROXY_IPS, entryPort, generateRemark, generateWsPath, getConfigAddresses, OFFICIAL_DIRECT_IPS, parseHostPort, parseProxyIPWithRegion, pickEarlyData, pickRandomEch, resetRemarkCounter, resolveDNS, resolveUrlEntries, selectProxyIPByRegion, selectSniHost } from "@utils";
import JSZip from "jszip";

/**
 * 归一化官方直连 IP 条目：裸 IP（无端口）或未带 @CF 标签的条目，
 * 统一补齐 :443 端口，使其与内置池语义（始终拨 443）完全兼容。
 * 保留 @region 标签与 #comment 后缀。
 *
 * C-06/C-07：畸形条目（host 为空、端口越界）改为**返回空串丢弃**（调用方 filter），
 * 不再「修」成 `:443`、也不再让 `1.1.1.1:70000` 原样透传；
 * IPv6 方括号归一提到端口分支之前，带端口的裸 IPv6 同样会补上括号。
 */
function normalizeOfficialIP(entry: string): string {
    const hashIdx = entry.indexOf('#');
    const addressPart = (hashIdx !== -1 ? entry.slice(0, hashIdx) : entry).trim();
    const comment = hashIdx !== -1 ? entry.slice(hashIdx) : '';
    if (!addressPart) return '';

    const atIdx = addressPart.lastIndexOf('@');
    const clean = atIdx !== -1 ? addressPart.slice(0, atIdx).trim() : addressPart;
    const regionSuffix = atIdx !== -1 ? addressPart.slice(atIdx) : '';

    const { host, port } = parseHostPort(clean, true);
    if (!host) return ''; // 畸形条目（如裸 `:443`）：host 为空即丢弃

    // IPv6 安全网：任何路径下若 host 含 ':' 但未加方括号，则补上。
    // parseHostPort(brackets=true) 已给 IPv6 补了括号，故先剥掉已有括号再判定，
    // 否则 `2606:4700::1111:8443` 这种「原文未加括号」的条目会漏过（旧代码 `if (port) return entry` 正是如此）。
    const bareHost = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
    const normalizedHost = bareHost.includes(':') ? `[${bareHost}]` : bareHost;

    // parseHostPort 用 0 表示「无端口」。显式 `:0` 属于端口越界，但 IPv6 末段（如 `2001:db8::0`）不是端口。
    if (port === 0) {
        if (!bareHost.includes(':') && /:0$/.test(clean)) return '';
        return `${normalizedHost}:443${regionSuffix}${comment}`;
    }

    // C-06：端口必须落在 1–65535，越界（如 `1.1.1.1:70000`）丢弃而不是原样透传
    if (!Number.isInteger(port) || port < 1 || port > 65535) return '';

    // 原文已是规范形式则逐字返回，不改写用户的空白/大小写
    return clean === `${normalizedHost}:${port}` ? entry : `${normalizedHost}:${port}${regionSuffix}${comment}`;
}

export async function handleWebsocket(request: Request, env: Env): Promise<Response> {
    // 对齐 cfnew：路径不包含协议信息，协议由首包内容自动识别
    // 客户端统一连接同一个 WS 端点，服务端根据首包判断 VLESS 或 Trojan

    const reqUrl = new URL(request.url);
    const queryWk = (reqUrl.searchParams.get('wk') || '').toUpperCase();
    const queryRm = reqUrl.searchParams.get('rm');
    const queryQj = (reqUrl.searchParams.get('qj') || '').toLowerCase();

    const {
        regionMatch: kvRegionMatch,
        wkRegion: kvWkRegion,
        proxyIPMode,
        proxyOnly: kvProxyOnly,
        proxyDegrade: kvProxyDegrade
    } = globalThis.settings;
    const rawProxyIPs = globalThis.settings.proxyIPs || [];
    const proxyIPs = await resolveUrlEntries(rawProxyIPs, env); // 连接时解析（带 KV 缓存）

    // 1. wkRegion：URL query wk > KV wkRegion > 空（空 = 官方直连 CF，对齐 cfnew v3.0）
    const effectiveWkRegion = queryWk || kvWkRegion || '';

    // 2. regionMatch：URL query rm(no=关闭) > KV regionMatch > 默认开启
    const effectiveRegionMatch = queryRm !== null
        ? queryRm.toLowerCase() !== 'no'
        : (kvRegionMatch ?? true);

    // 3. proxyMode：URL query qj(only=仅走代理/no=代理降级) > KV proxyOnly/proxyDegrade > 默认两者皆 false
    const effectiveProxyOnly = queryQj === 'only'
        ? true
        : (queryQj === 'no' ? false : (kvProxyOnly ?? false));
    const effectiveProxyDegrade = queryQj === 'only'
        ? false
        : (queryQj === 'no' ? true : (kvProxyDegrade ?? false));

    // 3. proxyIPs：KV proxyIPs > envProxyIPs > DEFAULT_PROXY_IPS（对齐 cfnew 备用地址列表）
    const envFallbackIPs = globalThis.wsConfig?.envProxyIPs
        ? [globalThis.wsConfig.envProxyIPs]
        : [];
    // 自定义代理 = 面板手动设置的 proxyIPs 非空，或配置了 env PROXY_IP（envFallbackIPs 非空）。
    // 写入 wsConfig.hasCustomProxyIPs：未配置自定义代理时直连优先（cfnew 默认策略），
    // 与上方 effectivePanelIPs 的取值链（proxyIPs > envFallbackIPs > DEFAULT_PROXY_IPS）保持一致。
    const hasCustomProxyIPs = proxyIPs.length > 0 || envFallbackIPs.length > 0;
    const effectivePanelIPs = proxyIPs.length > 0
        ? proxyIPs
        : (envFallbackIPs.length > 0 ? envFallbackIPs : DEFAULT_PROXY_IPS);

    globalThis.wsConfig = {
        ...globalThis.wsConfig,
        proxyMode: proxyIPMode,
        panelIPs: effectivePanelIPs,
        regionMatch: effectiveRegionMatch,
        wkRegion: effectiveWkRegion,
        hasCustomProxyIPs,
        proxyOnly: effectiveProxyOnly,
        proxyDegrade: effectiveProxyDegrade
    };

    // Detect worker region: manual wkRegion > 官方直连（CF，对齐 cfnew v3.0）
    // wk 为空时不再用 cf.country 自动检测，而是走官方直连（内置 10 个官方 Cloudflare IP）
    // 自定义 proxyIP（面板手动设置）同样启用自动地区检测：列表带 @ 后缀码时
    // 按访客地区匹配对应域名（对齐用户需求：自动地区匹配/指定地区按 @ 后缀码匹配）
    globalThis.wsConfig.workerRegion = effectiveWkRegion || 'CF';

    // 官方直连（对齐 cfnew v3.0）：workerRegion = 'CF'（wk 留空）时，
    // 出口语义 = 官方 Cloudflare IP（内置 10 个，或面板自定义 officialIPs），
    // 与自定义反代 proxyIPs 无关 —— 反代仅在显式指定地区（wk 非空）时生效。
    if (globalThis.wsConfig.workerRegion === 'CF') {
        const officialIPs = globalThis.settings.officialIPs?.length
            ? globalThis.settings.officialIPs
            : OFFICIAL_DIRECT_IPS;
        // C-06：非法条目在归一化阶段丢弃；自定义池若整池非法则回退内置官方池，
        // 避免 panelIPs 为空导致后续选 IP / 拨号直接失败（旧行为是把畸形项当合法 IP 用）。
        const normalized = officialIPs.map(normalizeOfficialIP).filter(Boolean);
        if (normalized.length === 0) {
            console.warn('[officialIPs] 自定义官方直连条目全部非法，回退内置官方直连池');
        }
        globalThis.wsConfig.panelIPs = normalized.length > 0
            ? normalized
            : OFFICIAL_DIRECT_IPS.map(normalizeOfficialIP).filter(Boolean);
    }

    // 对齐 cfnew：连接时按 workerRegion 动态选择 Proxy IP（服务端选择，不暴露给客户端）
    // 仅当列表含 @ 地区标签时收敛到匹配域名（纯 IP/IP:port 列表不收敛，全部参与 IP 池轮询）
    // CF 为 anycast，无地区选择概念：跳过收敛，避免 countryToRegion('CF')→'SG' 把 10 IP 池塌缩成 1 个
    if (effectiveRegionMatch && globalThis.wsConfig.workerRegion !== 'CF' && globalThis.wsConfig.workerRegion && effectivePanelIPs.length > 0) {
        const hasRegionTags = effectivePanelIPs.some(p => parseProxyIPWithRegion(p).region);
        if (hasRegionTags) {
            const selected = selectProxyIPByRegion(effectivePanelIPs, globalThis.wsConfig.workerRegion);
            if (selected) {
                globalThis.wsConfig.panelIPs = [selected];
            }
        }
    }

    // 使用统一处理器，协议由首包内容自动识别
    return await UnifiedWSHandler(request);
}

export async function handlePanel(request: Request, env: Env): Promise<Response> {
    const { pathName } = globalThis.globalConfig;

    switch (pathName) {
        case '/panel':
            return await renderPanel(request, env);

        case '/panel/settings':
            return await getSettings(request, env);

        case '/panel/update-settings':
            return await updateSettings(request, env);

        case '/panel/reset-settings':
            return await resetSettings(request, env);

        case '/panel/reset-password':
            return await resetPassword(request, env);

        case '/panel/my-ip':
            return await getMyIP(request, env);

        case '/panel/region':
            return await getRegionInfo(request, env);

        case '/panel/update-warp':
            return await updateWarpConfigs(request, env);

        case '/panel/get-warp-configs':
            return await getWarpConfigs(request, env);

        default:
            return await fallback(request);
    }
}

export async function handleProxyIPs(request: Request, env: Env): Promise<Response> {
    const auth = await Authenticate(request, env);

    if (!auth) {
        const { urlOrigin } = globalThis.httpConfig;
        return Response.redirect(`${urlOrigin}/login`, 302);
    }

    const { pathName } = globalThis.globalConfig;

    switch (pathName) {
        case '/proxy-ip':
            return await renderProxyIPs();

        case '/proxy-ip/get':
            return await getProxyIPsInfo();

        default:
            return await fallback(request);
    }
}

/**
 * F16：错误页消息脱敏。
 * init.ts 会抛出 `Invalid UUID: <UUID>`，UUID 即 VLESS 凭据，经错误页回显给任意未授权访客。
 * 这里先按「部署自身凭据」逐字抹除（UUID / TR_PASS），再用 UUID 形状的兜底正则兜住其它来源。
 * 短于 4 字符的值不参与逐字抹除：它们不是有意义的凭据，却可能把消息抹成乱码。
 */
function redactSecrets(message: string): string {
    const env = (globalThis as any)?.env || {};
    const secrets = [
        (globalThis as any)?.globalConfig?.userID,
        env.UUID,
        env.TR_PASS
    ].filter((v): v is string => typeof v === 'string' && v.length >= 4);

    let out = message;
    for (const secret of secrets) out = out.split(secret).join('***');

    return out.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '***');
}

export async function renderError(error: any): Promise<Response> {
    const html = await decompressHtml(__ERROR_HTML_CONTENT__, true) as string;
    // 消息一律 escapeHtml（防反射 XSS）。**可点击的出口不能写进 throw 的消息里**——那会被转义成裸标签，
    // 用户看到 <a href=...> 却点不动（原先就是这个问题）。改为按 error.cause 在这里追加，
    // 且只拼接可信来源：/secrets 是硬编码常量，tutorials 取自 dict 常量并做属性转义。
    const message = escapeHtml(redactSecrets(safeErrorMessage(error)));
    let action = '';
    if (error?.cause === 'missing-credentials') {
        action = ' <a href="/secrets">Open /secrets</a>';
    } else if (error?.cause === 'kv-not-set') {
        const site = String((globalThis as any).dict?._website_ ?? '');
        if (site) action = ` <a href="${escapeHtml(site)}" target="_blank" rel="noopener">tutorials</a>`;
    }
    // 函数式替换：避免 String.replace 把消息里的 $&/$'/$` 当插值序列解释
    const errorPage = html.replace('__ERROR_MESSAGE__', () => message + action);

    return new Response(errorPage, {
        // F16：此前一律返回 200，掩盖故障并让监控/缓存/重试语义全错。
        // 本仓库能走到这个兜底的异常只有两类：部署配置错误（缺 env / KV 未绑定 / UUID 非法）与上游连接失败，
        // 都不属于客户端可修复的 4xx，硬造 404/401 只会撒谎，故统一 500。
        status: HttpStatus.INTERNAL_SERVER_ERROR,
        headers: { 'Content-Type': 'text/html; charset=utf-8', ...securityHeaders((globalThis as any)?.env) }
    });
}

async function renderProxyIPs() {
    const html = await decompressHtml(__PROXY_IP_HTML_CONTENT__, false);
    return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8', ...securityHeaders((globalThis as any)?.env) }
    });
}

export async function handleLogin(request: Request, env: Env): Promise<Response> {
    const { pathName } = globalThis.globalConfig;

    if (pathName === '/login') {
        return await renderLogin(request, env);
    }

    if (pathName === '/login/authenticate') {
        return await generateJWTToken(request, env);
    }

    return await fallback(request);
}

export function logout(): Response {
    // F19：Cookie 属性与登录（auth.ts 的 `HttpOnly; Secure; Max-Age; Path=/; SameSite=Strict`）对齐。
    // 旧值 `SameSite=None` 且缺 HttpOnly：任意跨站 `<img src=".../logout">` 即可强制登出。
    // 注：`/logout` 的「GET 也可触发 / 无鉴权」属 worker.ts 路由层（`case 'logout'` 直接调用本函数、
    // 不传 request），不在本次可改文件范围内。
    return respond(true, HttpStatus.OK, 'Successfully logged out!', null, {
        'Set-Cookie': 'jwtToken=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'Content-Type': 'text/plain'
    });
}

export async function handleSubscriptions(request: Request, env: Env): Promise<Response> {
    await setSettings(request, env);
    // 仅在拉取订阅时解析 cleanIPs / customCdnAddrs 的 URL 并写入 KV 缓存；
    // 前端设置只保存 URL 本身，不展示解析后的地址
    globalThis.settings.cleanIPs = await resolveUrlEntries(globalThis.settings.cleanIPs || [], env);
    globalThis.settings.customCdnAddrs = await resolveUrlEntries(globalThis.settings.customCdnAddrs || [], env);
    const {
        globalConfig: { pathName },
        httpConfig: { client, subPath }
    } = globalThis;

    switch (pathName) {
        case `/sub/normal/${subPath}`:
            switch (client) {
                case 'xray':
                    return await getXrCustomConfigs(false);

                case 'sing-box':
                    return await getSbCustomConfig(false);

                case 'clash':
                    return await getClNormalConfig();

                default:
                    return await fallback(request);
            }

        case `/sub/raw/${subPath}`:
            switch (client) {
                case 'xray':
                case 'sing-box':
                    return await getURLConfigs();

                default:
                    return await fallback(request);
            }

        case `/sub/fragment/${subPath}`:
            switch (client) {
                case 'xray':
                    return await getXrCustomConfigs(true);

                case 'sing-box':
                    return await getSbCustomConfig(true);

                default:
                    return await fallback(request);
            }

        case `/sub/warp/${subPath}`:
            switch (client) {
                case 'xray':
                    return await getXrWarpConfigs(request, env, false, false);

                case 'sing-box':
                    return await getSbWarpConfig(request, env);

                case 'clash':
                    return await getClWarpConfig(request, env, false);

                default:
                    return await fallback(request);
            }

        case `/sub/warp-pro/${subPath}`:
            switch (client) {
                case 'xray':
                    return await getXrWarpConfigs(request, env, true, false);

                case 'xray-knocker':
                    return await getXrWarpConfigs(request, env, true, true);

                case 'clash':
                    return await getClWarpConfig(request, env, true);

                default:
                    return await fallback(request);
            }

        default:
            return await fallback(request);
    }
}

async function updateSettings(request: Request, env: Env): Promise<Response> {
    if (request.method !== 'PUT') {
        return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'Method not allowed.');
    }

    const auth = await Authenticate(request, env);

    if (!auth) {
        return respond(false, HttpStatus.UNAUTHORIZED, 'Unauthorized or expired session.');
    }

    try {
        const proxySettings = await updateDataset(request, env);
        return respond(true, HttpStatus.OK, '', proxySettings);
    } catch (error) {
        console.log(error);
        // 校验失败：400 + 指明具体非法字段名；此时 KV 未被写入（全有或全无）
        if (error instanceof InvalidSettingsError) {
            return respond(false, HttpStatus.BAD_REQUEST, `Invalid settings value for field(s): ${error.fields.join(', ')}`);
        }
        return respond(false, HttpStatus.INTERNAL_SERVER_ERROR, `Error occurred while updating settings: ${safeErrorMessage(error)}`);
    }
}

async function resetSettings(request: Request, env: Env): Promise<Response> {
    if (request.method !== 'POST') {
        return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'Method not allowed!');
    }

    const auth = await Authenticate(request, env);

    if (!auth) {
        return respond(false, HttpStatus.UNAUTHORIZED, 'Unauthorized or expired session.');
    }

    try {
        // 重置 = 写回明确的出厂默认，与 isolate 内存状态无关（冷/暖 isolate 结果一致）
        const defaults = structuredClone(DEFAULT_SETTINGS);
        await env.kv.put("proxySettings", JSON.stringify(defaults));
        // 对齐 cfnew：重置后更新版本键 + 填充内存缓存
        const newVer = String(Date.now());
        await env.kv.put("proxySettings_ver", newVer).catch(() => {});
        setKvCache(defaults, newVer);
        // 同步当前 isolate 内存，避免后续请求继续沿用被合并过的旧值
        Object.assign(globalThis.settings, defaults);
        return respond(true, HttpStatus.OK, '', defaults);
    } catch (error) {
        console.log(error);
        return respond(false, HttpStatus.INTERNAL_SERVER_ERROR, `Error occurred while resetting settings: ${safeErrorMessage(error)}`);
    }
}

async function getSettings(request: Request, env: Env): Promise<Response> {
    const isPassSet = Boolean(await env.kv.get('pwd'));
    const auth = await Authenticate(request, env);

    if (!auth) {
        // F20：未鉴权时不再下发 isPassSet（未授权访客可据此精确判定「尚未设口令」，直接衔接抢注）。
        // 仍返回空对象而非 null：面板脚本 panel/script.js:31 直接读 `body.isPassSet`，
        // body 为 null 会抛 TypeError 并中断首访「设置口令」弹窗流程（见回报中的取舍说明）。
        return respond(false, HttpStatus.UNAUTHORIZED, 'Unauthorized or expired session.', {});
    }

    try {
        const dataset = await getDataset(request, env);
        const { subPath } = globalThis.httpConfig;

        const data = {
            proxySettings: dataset.settings,
            isPassSet,
            subPath: subPath
        };

        return respond(true, HttpStatus.OK, undefined, data);
    } catch (error) {
        console.log(error);
        return respond(false, HttpStatus.INTERNAL_SERVER_ERROR, `Error occurred while fetching settings: ${safeErrorMessage(error)}`);
    }
}

export async function fallback(request: Request): Promise<Response> {
    // 伪装地址来源：FALLBACK 环境变量，支持 `a|b|c` 多地址随机（与 camouflage 伪装反代链路一致）
    const raw = String(globalThis.globalConfig?.fallbackDomain || '')
        .split('|')
        .map(s => s.trim())
        .filter(s => s && s.toLowerCase() !== 'nginx');
    const fallbackDomain = (raw.length > 0 ? raw[Math.floor(Math.random() * raw.length)] : 'www.hcaptcha.com')
        .replace(/^https?:\/\//i, '')
        .replace(/\/+$/, '');
    const { url, method, body } = request;

    const newURL = new URL(url);
    newURL.hostname = fallbackDomain;
    newURL.protocol = 'https:';
    const newRequest = new Request(newURL.toString(), {
        method,
        // 剥离 Cookie / CF-Connecting-IP 等出站敏感头，避免凭据与真实访客 IP 外泄给兜底域
        headers: copySafeOutboundHeaders(request.headers),
        body,
        redirect: 'manual'
    });

    return await fetch(newRequest);
}

async function getMyIP(request: Request, env: Env): Promise<Response> {
    if (request.method !== 'POST') {
        return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'Method not allowed.');
    }

    const auth = await Authenticate(request, env);

    if (!auth) {
        return respond(false, HttpStatus.UNAUTHORIZED, 'Unauthorized or expired session.');
    }

    const ip = await request.text();

    try {
        const response = await fetch(`http://ip-api.com/json/${ip}?nocache=${Date.now()}`);
        const geoLocation = await response.json();
        return respond(true, HttpStatus.OK, '', geoLocation);
    } catch (error) {
        console.error('Error fetching IP address:', error);
        return respond(false, HttpStatus.INTERNAL_SERVER_ERROR, `Error fetching IP address: ${safeErrorMessage(error)}`)
    }
}

async function getRegionInfo(request: Request, env: Env): Promise<Response> {
    const auth = await Authenticate(request, env);

    if (!auth) {
        return respond(false, HttpStatus.UNAUTHORIZED, 'Unauthorized or expired session.');
    }

    try {
        await setSettings(request, env);

        const cf = (request as any).cf || {};
        const country = cf.country || '';
        const colo = cf.colo || '';
        const city = cf.city || '';
        const clientIP = request.headers.get('CF-Connecting-IP') || '';

        // Fetch client geolocation
        interface GeoResponse { country: string; countryCode: string; city: string; isp: string; }
        let clientGeo: GeoResponse | null = null;
        if (clientIP) {
            try {
                const geoRes = await fetch(`http://ip-api.com/json/${clientIP}?fields=query,country,countryCode,city,isp,status&nocache=${Date.now()}`);
                clientGeo = await geoRes.json();
            } catch { /* ignore */ }
        }

        const manualRegion = (globalThis.settings?.wkRegion || '').trim();
        // 对齐 cfnew v3.0：wk 为空时走官方直连（CF）；显式设置时按手动地区映射
        const resolvedProxyRegion = manualRegion ? countryToRegion(manualRegion) : 'CF';

        return respond(true, HttpStatus.OK, '', {
            workerRegion: country,
            workerColo: colo,
            workerCity: city,
            clientIP,
            clientCountry: clientGeo?.country || '',
            clientCountryCode: clientGeo?.countryCode || '',
            clientCity: clientGeo?.city || '',
            clientIsp: clientGeo?.isp || '',
            wkRegion: manualRegion,
            resolvedProxyRegion
        });
    } catch (error) {
        console.error('Error fetching region info:', error);
        return respond(false, HttpStatus.INTERNAL_SERVER_ERROR, `Error fetching region info: ${safeErrorMessage(error)}`)
    }
}

async function getWarpConfigs(request: Request, env: Env): Promise<Response> {
    const {
        httpConfig: { client },
        dict: { _project_ }
    } = globalThis;

    const isPro = client === 'amnezia';
    const auth = await Authenticate(request, env);

    if (!auth) {
        return new Response('Unauthorized or expired session.', { status: HttpStatus.UNAUTHORIZED });
    }

    
    try {
        const { warpAccounts, settings } = await getDataset(request, env);
        const { warpIPv6, publicKey, privateKey } = warpAccounts[0];
        const {
            warpEndpoints,
            warpRemoteDNS,
            amneziaNoiseCount,
            amneziaNoiseSizeMin,
            amneziaNoiseSizeMax
        } = settings;
    
        const zip = new JSZip();
        const trimLines = (str: string) => str.split("\n").map(line => line.trim()).join("\n");

        warpEndpoints?.forEach((endpoint, index) => {
            const config =
                `[Interface]
                PrivateKey = ${privateKey}
                Address = 172.16.0.2/32, ${warpIPv6}
                DNS = ${warpRemoteDNS}
                MTU = 1280
                ${isPro ?
                    `Jc = ${amneziaNoiseCount}
                    Jmin = ${amneziaNoiseSizeMin}
                    Jmax = ${amneziaNoiseSizeMax}
                    S1 = 0
                    S2 = 0
                    H1 = 0
                    H2 = 0
                    H3 = 0
                    H4 = 0`
                    : ''
                }
                [Peer]
                PublicKey = ${publicKey}
                AllowedIPs = 0.0.0.0/0, ::/0
                Endpoint = ${endpoint}
                PersistentKeepalive = 25`;

            zip.file(`${_project_}-Warp-${index + 1}.conf`, trimLines(config));
        });

        const zipBlob = await zip.generateAsync({ type: "blob" });
        const arrayBuffer = await zipBlob.arrayBuffer();

        return new Response(arrayBuffer, {
            headers: {
                "Content-Type": "application/zip",
                "Content-Disposition": `attachment; filename="${_project_}-Warp-${isPro ? "Pro-" : ""}configs.zip"`,
            },
        });
    } catch (error) {
        return respond(false, HttpStatus.INTERNAL_SERVER_ERROR, `Error generating ZIP file: ${safeErrorMessage(error)}`);
    }
}

async function getProxyIPsInfo(): Promise<Response> {
    const ips = await resolveDNS(globalThis.dict._public_proxy_ip_, true);
    const geoLocInfo = await geoLookupBatch(ips.ipv4);
    return respond(true, HttpStatus.OK, undefined, geoLocInfo);
}

export async function serveIcon(): Promise<Response> {
    const faviconBase64 = __ICON__;
    const body = Uint8Array.from(atob(faviconBase64), c => c.charCodeAt(0));

    return new Response(body, {
        headers: {
            'Content-Type': 'image/x-icon',
            'Cache-Control': 'public, max-age=86400',
        }
    });
}

async function renderPanel(request: Request, env: Env): Promise<Response> {
    const pwd = await env.kv.get('pwd');

    if (pwd) {
        const auth = await Authenticate(request, env);
        if (!auth) {
            const { urlOrigin } = globalThis.httpConfig;
            return Response.redirect(`${urlOrigin}/login`, 302);
        }
    }

    const html = await decompressHtml(__PANEL_HTML_CONTENT__, false);
    return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8', ...securityHeaders((globalThis as any)?.env) }
    });
}

async function renderLogin(request: Request, env: Env): Promise<Response> {
    const auth = await Authenticate(request, env);
    if (auth) {
        const { urlOrigin } = globalThis.httpConfig;
        return Response.redirect(`${urlOrigin}/panel`, 302);
    }

    const html = await decompressHtml(__LOGIN_HTML_CONTENT__, false);
    return new Response(html, {
        headers: {
            'Content-Type': 'text/html; charset=utf-8',
            ...securityHeaders((globalThis as any)?.env)
        }
    });
}

export async function renderSecrets(): Promise<Response> {
    const html = await decompressHtml(__SECRETS_HTML_CONTENT__, false);
    return new Response(html, {
        headers: {
            'Content-Type': 'text/html; charset=utf-8',
            ...securityHeaders((globalThis as any)?.env)
        }
    });
}

async function updateWarpConfigs(request: Request, env: Env): Promise<Response> {
    if (request.method !== 'POST') return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'Method not allowed.');
    const auth = await Authenticate(request, env);

    if (!auth) {
        return respond(false, HttpStatus.UNAUTHORIZED, 'Unauthorized.');
    }

    try {
        await fetchWarpAccounts(env);
        return respond(true, HttpStatus.OK, 'Warp configs updated successfully!');
    } catch (error) {
        console.log(error);
        return respond(false, HttpStatus.INTERNAL_SERVER_ERROR, `An error occurred while updating Warp configs: ${safeErrorMessage(error)}`);
    }
}

async function decompressHtml(content: string, asString: boolean): Promise<string | ReadableStream<Uint8Array>> {
    const bytes = Uint8Array.from(atob(content), c => c.charCodeAt(0));
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));

    if (asString) {
        const decompressedArrayBuffer = await new Response(stream).arrayBuffer();
        const decodedString = new TextDecoder().decode(decompressedArrayBuffer);
        return decodedString;
    }

    return stream;
}

export async function handleDoH(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const { subPath } = globalThis.httpConfig;
    const { dohURL } = globalThis.globalConfig;

    if (url.pathname !== `/dns-query/${subPath}`) {
        return fallback(request);
    }

    const targetURL = new URL(dohURL);
    url.searchParams.forEach((value, key) => {
        targetURL.searchParams.set(key, value);
    });

    // 显式构造：headers 剥离出站敏感头（原 `new Request(url, request)` 会把 Cookie 等整体复制给 DOH_URL）
    const noBodyMethod = request.method === 'GET' || request.method === 'HEAD';
    const proxyRequest = new Request(targetURL.toString(), {
        method: request.method,
        headers: copySafeOutboundHeaders(request.headers),
        body: noBodyMethod ? undefined : request.body,
        redirect: request.redirect
    });
    return fetch(proxyRequest);
}

interface IpApiBatchResponse {
    query: string;
    city?: string;
    country?: string;
    countryCode?: string;
    isp?: string;
    status: "success" | "fail";
    message?: string;
}

interface GeoResult {
    ip: string;
    city?: string;
    country?: string;
    countryCode?: string;
    isp?: string;
}

function chunkArray<T>(arr: T[], size: number): T[][] {
    const chunks: T[][] = [];

    for (let i = 0; i < arr.length; i += size) {
        chunks.push(arr.slice(i, i + size));
    }

    return chunks;
}

async function geoLookupBatch(ipList: string[]): Promise<GeoResult[]> {
    const batches = chunkArray(ipList, 100);
    const results: GeoResult[] = [];

    for (const batch of batches) {
        const res = await fetch(
            "http://ip-api.com/batch?fields=query,city,country,countryCode,isp,status",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(batch),
            }
        );

        if (!res.ok) {
            throw new Error(`ip-api request failed: ${res.status}`);
        }

        const data: IpApiBatchResponse[] = await res.json();

        for (const item of data) {
            if (item.status === "success") {
                results.push({
                    ip: item.query,
                    city: item.city,
                    country: item.country,
                    countryCode: item.countryCode,
                    isp: item.isp,
                });
            }
        }
    }

    return results;
}

export async function getURLConfigs() {
    resetRemarkCounter();
    const {
        globalConfig: { userID, TrPass },
        httpConfig: { defaultHttpsPorts },
        dict: { _VL_, _TR_, _project_ },
        settings: {
            fingerprint,
            alpn,
            VLConfigs,
            TRConfigs,
            enableECH,
            echServerName,
            hostSniList,
            outProxy,
            remoteDNS,
            customConfigs,
            customSubs,
            upstreamParams: { upstreamServer, upstreamPort }
        }
    } = globalThis;

    // 端口列表必须先拷贝：解构得到的是 globalThis.settings.ports 的引用，
    // 而它与 KV 缓存（kv-cache）是同一数组对象，原地 unshift 会在同一 isolate 内
    // 随每次订阅请求累积（[443] → [1080,443] → [1080,1080,443]）并被后续 PUT 持久化。
    const ports = [...(globalThis.settings.ports || [])];

    // 已占用路径池词集合：本次请求内 VLESS / Trojan 各抽一个互不相同的伪装路径
    const usedPaths = new Set<string>();
    // 已占用 early-data 阈值池：同一份订阅内各节点 ed 两两不同（无放回抽取），作用域与 usedPaths 一致（一次请求一个集合）
    const usedEds = new Set<number>();

    const buildConfig = (protocol: string, addr: string, port: number, host: string, sni: string, remark: string, allowInsecure: boolean) => {
        const isTLS = defaultHttpsPorts.includes(port) || addr === upstreamServer || Object.values(entryPortMap).some(ports => ports.includes(port));
        const security = isTLS ? 'tls' : 'none';
        const config = new URL(`${protocol}://config`);

        if (protocol === _VL_) {
            config.username = userID;
            config.searchParams.append('encryption', 'none');
            // 对齐 cfnew 52143dccb：xPadding 抗指纹 —— 订阅链接带 extra 约定
            const { header: xPaddingHeader, key: xPaddingKey } = getXPaddingIdentifier(userID);
            config.searchParams.append('extra', JSON.stringify({
                xPaddingObfsMode: true,
                xPaddingMethod: 'tokenish',
                xPaddingPlacement: 'queryInHeader',
                xPaddingHeader,
                xPaddingKey
            }));
        } else {
            config.username = TrPass;
        }

        config.hostname = parseHostPort(addr, true).host;
        config.port = port.toString();
        config.searchParams.append('host', host);
        config.searchParams.append('type', 'ws');
        config.searchParams.append('security', security);
        // H11：isTLS=false 的端口会生成 security=none 的明文节点（UUID/口令随首帧明文出网），
        // 在节点备注上显式告警；不改动生成语义（是否使用由用户决定）。
        config.hash = isTLS ? remark : `${remark} ⚠️明文(无TLS)`;

        // 对齐 cfnew：ed 从共享的 usedEds 池无放回抽取（2048..2560 闭区间，513 个取值），
        // 保证同一份订阅内任意两个节点的 ed 两两不同（独立随机会有明显重复率），同时仍消除固定长度指纹。
        // 下限不再取更低：ed 是「首包长度阈值」而非缓冲区大小，首包超过它就直接不启用 Early Data（丢 0-RTT），
        // 而本项目自身的 0xED7F 首包填充有 64..2048 字节，低阈值会让连接大概率退化为非 0-RTT。
        const ed = pickEarlyData(usedEds);
        config.searchParams.append('path', `${generateWsPath(usedPaths)}?ed=${ed}`);

        if (isTLS) {
            config.searchParams.append('sni', sni);
            config.searchParams.append('fp', fingerprint);
            // C-15(W2a)：selectSniHost 的 allowInsecure 原先只被 Clash（skip-cert-verify）/sing-box（insecure）消费，
            // URL 订阅侧被丢弃 → 两类订阅 TLS 策略不一致。按 v2rayN/sing-box 的 URI 约定补 allowInsecure=1。
            if (allowInsecure) config.searchParams.append('allowInsecure', '1');
            if (!enableECH && alpn) config.searchParams.append('alpn', alpn);
            if (enableECH) {
                config.searchParams.append('ech', `${pickRandomEch(echServerName) || host}+${remoteDNS}`);
            }
        }

        return config.href;
    }

    let VLConfs = '', TRConfs = '', chainProxy = '';
    const addrs = await getConfigAddresses(false);

    if (upstreamServer && upstreamPort) {
        ports.unshift(upstreamPort);
        addrs.unshift(upstreamServer);
    }

    const entryPortMap = buildEntryPortMap();

    for (const addr of addrs) {
        const addrPorts = entryPortMap[addr]?.length ? entryPortMap[addr] : ports;

        for (const port of addrPorts) {
            const { host, sni, allowInsecure } = selectSniHost(addr, pickRandomEch(hostSniList));
            if ((port === upstreamPort) !== (addr === upstreamServer)) continue;

            if (VLConfigs) {
                const remark = generateRemark(port, addr, _VL_, false, false);
                const vlConfig = buildConfig(atob('dmxlc3M='), addr, port, host, sni, remark, allowInsecure);
                VLConfs += `${vlConfig}\n`;
            }

            if (TRConfigs) {
                const remark = generateRemark(port, addr, _TR_, false, false);
                const trConfig = buildConfig(atob('dHJvamFu'), addr, port, host, sni, remark, allowInsecure);
                TRConfs += `${trConfig}\n`;
            }
        }
    }

    if (outProxy) {
        let chainRemark = `#${encodeURIComponent('🔗 链式代理')}`;
        if (outProxy.startsWith('socks') || outProxy.startsWith('http')) {
            const regex = /^(?:socks|http):\/\/([^@]+)@/;
            const isUserPass = outProxy.match(regex);
            const userPass = isUserPass ? isUserPass[1] : false;
            chainProxy = userPass
                ? outProxy.replace(userPass, btoa(userPass)) + chainRemark
                : outProxy + chainRemark;
        } else {
            chainProxy = outProxy.split('#')[0] + chainRemark;
        }
    }

    const customConfs = joinConfigSections(customConfigs.join("\n"), await fetchCustomSubs(customSubs));
    const configs = base64EncodeUtf8(joinConfigSections(VLConfs, TRConfs, chainProxy, customConfs));

    return new Response(configs, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'CDN-Cache-Control': 'no-store',
            'Profile-Title': `base64:${base64EncodeUtf8(`${_project_} Raw`)}`,
            'DNS': remoteDNS
        }
    });
}

async function fetchCustomSubs(subs: string[]): Promise<string> {
    const results = await Promise.all(
        subs.map(async (url) => {
            try {
                const res = await fetch(url);
                if (!res.ok) return "";

                const text = (await res.text()).trim();
                if (!text) return "";

                if (isBase64(text)) {
                    try {
                        return base64DecodeUtf8(text);
                    } catch {
                        return text;
                    }
                }

                return text;
            } catch {
                return "";
            }
        })
    );

    return results
        .filter(Boolean)
        .join("\n");
}

/**
 * 拼接订阅文本段：保证相邻两段之间恰好一个换行。
 * 此前用 `+` 直接相连，chainProxy / customConfigs / customSubs 之间各自没有尾换行，
 * 相邻两段会粘成一行（`vless://a` + `vless://b` → `vless://avless://b`），客户端导入失败或丢节点。
 * VLConfs/TRConfs 逐行追加时自带尾换行，故已正确的组合（如 VLESS+Trojan）剥离中段多余尾换行后
 * 输出字节与既有行为完全一致；仅一段非空时原样返回，单段订阅输出字节不变。
 */
function joinConfigSections(...sections: string[]): string {
    const nonEmpty = sections.filter(section => section !== '');
    if (nonEmpty.length <= 1) return nonEmpty[0] ?? '';

    const head = nonEmpty.slice(0, -1).map(section => section.replace(/\n+$/, '')).join('\n');
    // 末段保留原样：其既有尾换行属于既有输出的一部分
    return `${head}\n${nonEmpty[nonEmpty.length - 1]}`;
}

function isBase64(str: string): boolean {
    // Strip newlines first so multi-line plain-text configs are not misidentified as base64
    const cleaned = str.replace(/[\r\n]/g, '');
    if (!cleaned || cleaned.length % 4 !== 0) return false;
    return /^[A-Za-z0-9+/=]+$/.test(cleaned);
}
