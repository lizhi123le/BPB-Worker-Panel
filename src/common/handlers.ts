import { Authenticate, generateJWTToken, resetPassword } from "@auth";
import { getDataset, updateDataset } from "@kv";
import { setKvCache, clearKvCache } from "../kv-cache";
import { setSettings } from "@init";
import { getClNormalConfig, getClWarpConfig } from "@clash/configs";
import { getSbCustomConfig, getSbWarpConfig } from "@sing-box/configs";
import { getXrCustomConfigs, getXrWarpConfigs } from "@xray/configs";
import { fetchWarpAccounts } from "@warp";
import { UnifiedWSHandler, getXPaddingIdentifier } from "@unified";
import { base64DecodeUtf8, base64EncodeUtf8, HttpStatus, respond, safeErrorMessage } from "@common";
import { buildEntryPortMap, countryToRegion, DEFAULT_PROXY_IPS, entryPort, generateRemark, generateWsPath, getConfigAddresses, OFFICIAL_DIRECT_IPS, parseHostPort, parseProxyIPWithRegion, pickRandomEch, resetRemarkCounter, resolveDNS, resolveUrlEntries, selectProxyIPByRegion, selectSniHost } from "@utils";
import JSZip from "jszip";

/**
 * 归一化官方直连 IP 条目：裸 IP（无端口）或未带 @CF 标签的条目，
 * 统一补齐 :443 端口，使其与内置池语义（始终拨 443）完全兼容。
 * 保留 @region 标签与 #comment 后缀。
 */
function normalizeOfficialIP(entry: string): string {
    const hashIdx = entry.indexOf('#');
    const addressPart = (hashIdx !== -1 ? entry.slice(0, hashIdx) : entry).trim();
    const comment = hashIdx !== -1 ? entry.slice(hashIdx) : '';
    if (!addressPart) return entry;

    const atIdx = addressPart.lastIndexOf('@');
    const clean = atIdx !== -1 ? addressPart.slice(0, atIdx).trim() : addressPart;
    const regionSuffix = atIdx !== -1 ? addressPart.slice(atIdx) : '';

    const { host, port } = parseHostPort(clean, true);
    if (port) return entry; // 已有端口，原样返回

    // IPv6 安全网：任何路径下若 host 含 ':' 但未加方括号，则补上
    const normalizedHost = host.includes(':') && !host.startsWith('[')
        ? `[${host}]`
        : host;

    return `${normalizedHost}:443${regionSuffix}${comment}`;
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
        globalThis.wsConfig.panelIPs = officialIPs.map(normalizeOfficialIP);
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
            return await getMyIP(request);

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

export async function renderError(error: any): Promise<Response> {
    const html = await decompressHtml(__ERROR_HTML_CONTENT__, true) as string;
    const errorPage = html.replace('__ERROR_MESSAGE__', safeErrorMessage(error));

    return new Response(errorPage, {
        status: HttpStatus.OK,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
}

async function renderProxyIPs() {
    const html = await decompressHtml(__PROXY_IP_HTML_CONTENT__, false);
    return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
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
    return respond(true, HttpStatus.OK, 'Successfully logged out!', null, {
        'Set-Cookie': 'jwtToken=; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
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
        const { settings } = globalThis;
        await env.kv.put("proxySettings", JSON.stringify(settings));
        // 对齐 cfnew：重置后更新版本键 + 填充内存缓存
        const newVer = String(Date.now());
        await env.kv.put("proxySettings_ver", newVer).catch(() => {});
        setKvCache(settings, newVer);
        return respond(true, HttpStatus.OK, '', settings);
    } catch (error) {
        console.log(error);
        return respond(false, HttpStatus.INTERNAL_SERVER_ERROR, `Error occurred while resetting settings: ${safeErrorMessage(error)}`);
    }
}

async function getSettings(request: Request, env: Env): Promise<Response> {
    const isPassSet = Boolean(await env.kv.get('pwd'));
    const auth = await Authenticate(request, env);

    if (!auth) {
        return respond(false, HttpStatus.UNAUTHORIZED, 'Unauthorized or expired session.', { isPassSet });
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
    const { fallbackDomain } = globalThis.globalConfig;
    const { url, method, headers, body } = request;

    const newURL = new URL(url);
    newURL.hostname = fallbackDomain;
    newURL.protocol = 'https:';
    const newRequest = new Request(newURL.toString(), {
        method,
        headers,
        body,
        redirect: 'manual'
    });

    return await fetch(newRequest);
}

async function getMyIP(request: Request): Promise<Response> {
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
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
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
            'Content-Type': 'text/html; charset=utf-8'
        }
    });
}

export async function renderSecrets(): Promise<Response> {
    const html = await decompressHtml(__SECRETS_HTML_CONTENT__, false);
    return new Response(html, {
        headers: {
            'Content-Type': 'text/html; charset=utf-8'
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

    const proxyRequest = new Request(targetURL.toString(), request);
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
        httpConfig: { defaultHttpsPorts, client, hostName },
        dict: { _VL_, _TR_, _project_ },
        settings: {
            fingerprint,
            alpn,
            ports,
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

    const buildConfig = (protocol: string, addr: string, port: number, host: string, sni: string, remark: string) => {
        const isTLS = defaultHttpsPorts.includes(port) || addr === upstreamServer || Object.values(entryPortMap).includes(port);
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

        const path = generateWsPath();
        config.hostname = parseHostPort(addr, true).host;
        config.port = port.toString();
        config.searchParams.append('host', host);
        config.searchParams.append('type', 'ws');
        config.searchParams.append('security', security);
        config.hash = remark;

        if (client === 'sing-box') {
            config.searchParams.append('eh', 'Sec-WebSocket-Protocol');
            config.searchParams.append('ed', '2560');
            config.searchParams.append('path', path);
        } else {
            config.searchParams.append('path', path);
            config.searchParams.append('ed', '2560');
        }

        if (isTLS) {
            config.searchParams.append('sni', sni);
            config.searchParams.append('fp', fingerprint);
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
        const addrPorts = entryPortMap[addr] ? [entryPortMap[addr]] : ports;

        for (const port of addrPorts) {
            const { host, sni } = selectSniHost(addr, pickRandomEch(hostSniList));
            if ((port === upstreamPort) !== (addr === upstreamServer)) continue;

            if (VLConfigs) {
                const remark = generateRemark(port, addr, _VL_, false, false);
                const vlConfig = buildConfig(atob('dmxlc3M='), addr, port, host, sni, remark);
                VLConfs += `${vlConfig}\n`;
            }

            if (TRConfigs) {
                const remark = generateRemark(port, addr, _TR_, false, false);
                const trConfig = buildConfig(atob('dHJvamFu'), addr, port, host, sni, remark);
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

    const customConfs = customConfigs.join("\n") + await fetchCustomSubs(customSubs);
    const configs = base64EncodeUtf8(VLConfs + TRConfs + chainProxy + customConfs);

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

function isBase64(str: string): boolean {
    // Strip newlines first so multi-line plain-text configs are not misidentified as base64
    const cleaned = str.replace(/[\r\n]/g, '');
    if (!cleaned || cleaned.length % 4 !== 0) return false;
    return /^[A-Za-z0-9+/=]+$/.test(cleaned);
}
