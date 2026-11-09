import {
    DEFAULT_PROXY_IPS,
    OFFICIAL_DIRECT_IPS,
    parseHostPort,
    parseProxyIPWithRegion,
    resolveUrlEntries,
    selectProxyIPByRegion
} from '@utils';

/**
 * 归一化官方直连 IP 条目：裸 IP（无端口）或未带 @CF 标签的条目，
 * 统一补齐 :443 端口，使其与内置池语义（始终拨 443）完全兼容。
 * 保留 @region 标签与 #comment 后缀。
 *
 * C-06/C-07：畸形条目（host 为空、端口越界）改为**返回空串丢弃**（调用方 filter），
 * 不再「修」成 `:443`、也不再让 `1.1.1.1:70000` 原样透传；
 * IPv6 方括号归一提到端口分支之前，带端口的裸 IPv6 同样会补上括号。
 */
export function normalizeOfficialIP(entry: string): string {
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

/**
 * 连通性运行时配置准备（WS 升级与 XHTTP 入站共用）。
 *
 * 此前这段逻辑内联在 handleWebsocket 里：解析 URL query（wk / rm / qj）→ 与 KV 设置合并出
 * 反代池 / 官方直连池 / 地区匹配 / 出站模式 → 写入 globalThis.wsConfig。XHTTP 入站走的是
 * 同一套出站策略（同一批 IP 池、同一套首跳语义），必须共用同一份推导，否则两条入站会给出
 * 不一致的出口行为。纯搬运，语义与搬运前逐字一致。
 *
 * 前置条件：worker.ts 已调用 initWs(env) 与 setSettings(request, env)（与搬运前 handleWebsocket 的调用点一致）。
 */
export async function prepareWsRuntimeConfig(request: Request, env: Env): Promise<void> {
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

    // 3. proxyMode：URL query qj(only=仅走代理/no=直连目标) > KV proxyOnly/proxyDegrade > 默认两者皆 false
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
    // 仅用于区分「用户显式配置的反代池实体」与内置 DEFAULT_PROXY_IPS 公共备用中继：
    // customProxyPool 只装前者（CF 模式下「仅走代理」拨它）；内置池经 panelIPs 兜底参与拨号。
    const hasCustomProxyIPs = proxyIPs.length > 0 || envFallbackIPs.length > 0;
    const effectivePanelIPs = proxyIPs.length > 0
        ? proxyIPs
        : (envFallbackIPs.length > 0 ? envFallbackIPs : DEFAULT_PROXY_IPS);
    // 用户显式配置的反代池实体（不含内置 DEFAULT_PROXY_IPS，也不含下方 CF 模式替换的官方直连池）。
    // CF 模式会把 panelIPs 整份换成官方池，而「仅走代理」要与指定地区保持同一套逻辑
    // （只要配了反代池就能用），因此单列一份供它拨号。
    const customProxyPool = hasCustomProxyIPs ? effectivePanelIPs : [];

    // 官方直连 IP 池（面板 officialIPs，未配置则内置 10 个）：只归一化这一次，
    // 「CF 模式下的 panelIPs」与「出站模式的 CF 内置 IP 池兜底层」共用同一份结果，
    // 避免两处各算一遍导致内容/顺序不一致。
    const officialIPsRaw = globalThis.settings.officialIPs?.length
        ? globalThis.settings.officialIPs
        : OFFICIAL_DIRECT_IPS;
    // C-06：非法条目在归一化阶段丢弃；自定义池若整池非法则回退内置官方池，
    // 避免拨号池为空导致后续选 IP / 拨号直接失败（旧行为是把畸形项当合法 IP 用）。
    const normalizedOfficial = officialIPsRaw.map(normalizeOfficialIP).filter(Boolean);
    if (normalizedOfficial.length === 0) {
        console.warn('[officialIPs] 自定义官方直连条目全部非法，回退内置官方直连池');
    }
    const officialPool = normalizedOfficial.length > 0
        ? normalizedOfficial
        : OFFICIAL_DIRECT_IPS.map(normalizeOfficialIP).filter(Boolean);

    globalThis.wsConfig = {
        ...globalThis.wsConfig,
        proxyMode: proxyIPMode,
        panelIPs: effectivePanelIPs,
        customProxyPool,
        officialPool,
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
        globalThis.wsConfig.panelIPs = officialPool;
    }

    // 对齐 cfnew：连接时按 workerRegion 动态选择 Proxy IP（服务端选择，不暴露给客户端）
    // 仅当列表含 @ 地区标签时收敛到匹配域名（纯 IP/IP:port 列表不收敛，全部参与 IP 池轮询）
    // CF 为 anycast，无地区选择概念：跳过收敛，避免 countryToRegion('CF')→'SG' 把 10 IP 池塌缩成 1 个
    if (effectiveRegionMatch && globalThis.wsConfig.workerRegion !== 'CF' && effectivePanelIPs.length > 0) {
        const hasRegionTags = effectivePanelIPs.some(p => parseProxyIPWithRegion(p).region);
        if (hasRegionTags) {
            const selected = selectProxyIPByRegion(effectivePanelIPs, globalThis.wsConfig.workerRegion);
            if (selected) {
                globalThis.wsConfig.panelIPs = [selected];
            }
        }
    }
}
