/**
 * tools/xhttp-node.test.mjs
 *
 * XHTTP 节点生成契约的行为测试。运行：node tools/xhttp-node.test.mjs
 *
 * 为什么需要它：XHTTP 是「WS 之外的第二种传输」，它有两份输出、必须逐字对应：
 *   · /sub/raw/<sub>?app=xray    —— VLESS-XHTTP 的分享链接（type=xhttp&mode=stream-one&extra=…）；
 *   · /sub/normal/<sub>?app=xray —— Xray JSON 里 network=xhttp 的 outbound + xhttpSettings。
 * 两份输出一旦漂移（mode / 路径 / xPadding 头名键名任一不一致），同一份订阅在两类客户端上
 * 就会填出不同的请求特征，而「看着有节点、实际连不上」的问题在 smoke 里完全发现不了。
 *
 * 另外三件事必须钉住：
 *   · 出厂默认 xhttpConfigs=false —— 关闭时 raw 订阅的节点形态与改动前完全一致（回归钉）；
 *   · ?app=sing-box 的 raw 订阅不含 xhttp 节点（sing-box 原生没有该传输，混进去只会丢节点）；
 *   · /sub/normal 的 sing-box 订阅按 cfnew-panel 约定沿用 WS 传输接入同一 Worker（tag 带 ` XHTTP` 后缀），
 *     绝不能下发 type:"xhttp"（sing-box 解析失败会让整份配置不可用）；
 *   · XHTTP outbound 不进「最佳延迟」balancer/urltest（不改变既有 WS 节点组的行为）。
 *
 * 实现方式：与 random-path.test.mjs 同构 —— 父进程先 seed 出一份完整出厂设置（补 cleanIPs，
 * 否则没有节点），再按不同开关组合 spawn 子进程拉订阅；子进程只采集观测值落盘成 JSON，
 * 断言全部集中在父进程，避免每个 phase 各写一份断言。
 * 全程只加载 .build/worker.reference.js（混淆前产物）、冻结 WARP 账号与出站网络。
 *
 * 前提：先构建过（npm run build，或快速版 NODE_ENV=mangle node scripts/build.js）。
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const BUNDLE = '.build/worker.reference.js';
const SEED_FILE = '.build/xhttp-node.settings.json';
const OBS_PREFIX = '.build/xhttp-node';
const SELF = fileURLToPath(import.meta.url);
const UUID = '11111111-2222-4333-8444-555555555555';
const TR_PASS = 'trojan-secret';
const SUB_PATH = 'xhttp-node-sub';
const ORIGIN = 'https://panel.example.com';

/** 冻结的 WARP 账号：形状合法 → 跳过 fetchWarpAccounts（那里会用到真正的随机密钥生成与联网）。 */
const WARP_ACCOUNTS = [
    {
        privateKey: 'sBmQVHEywGAKQ8Ratzo/f5OUCa7MSozZpz1JK2PSVXE=',
        publicKey: 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
        warpIPv6: '2606:4700:110:8dd8:de5f:9a89:bfac:749c/128',
        reserved: '59nK'
    },
    {
        privateKey: 'OPiD4dePq8652DICknJsTJS4UH0FoWY1ffOZzZhIsUs=',
        publicKey: 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
        warpIPv6: '2606:4700:110:8912:1225:70c8:1ad7:6ce0/128',
        reserved: 'G/nh'
    }
];

/** xPadding 头名/键名由 UUID 派生（@utils#getXPaddingIdentifier 的契约）。 */
const EXPECTED_XPADDING = {
    xPaddingObfsMode: true,
    xPaddingMethod: 'tokenish',
    xPaddingPlacement: 'queryInHeader',
    xPaddingHeader: UUID.slice(1, 7),
    xPaddingKey: '_' + UUID.slice(25, 31)
};

/** generateWsPath 产物的形态：1-3 段公共字典路径（不含 query）。 */
const DICT_PATH_RE = /^\/(?:[^/?#]+\/){0,2}[^/?#]+$/;

let failures = 0;
const out = (...args) => process.stdout.write(args.join(' ') + '\n');
const check = (name, ok, detail = '') => {
    out(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
    if (!ok) failures++;
};

if (!existsSync(BUNDLE)) {
    console.error(`找不到 ${BUNDLE} —— 请先构建：npm run build`);
    process.exit(1);
}

// ── 桩：出站网络（WARP 账号已冻结，这里只兜底任何意外 fetch）；必须早于 bundle 导入
globalThis.fetch = async () =>
    new Response('<!DOCTYPE html><html><body>stub</body></html>', { headers: { 'content-type': 'text/html' } });

const handler = (await import(pathToFileURL(BUNDLE).href)).default;
const ctx = { waitUntil() {}, passThroughOnException() {} };

function makeKv(seed = {}) {
    const store = new Map(Object.entries(seed));
    return {
        store,
        async get(key, opts) {
            const value = store.has(key) ? store.get(key) : null;
            if (value === null) return null;
            if (opts && opts.type === 'json') return typeof value === 'string' ? JSON.parse(value) : value;
            return value;
        },
        async put(key, value) { store.set(key, value); },
        async delete(key) { store.delete(key); },
        async list() { return { keys: [], list_complete: true, cursor: '' }; }
    };
}

function makeEnv(kvStore) {
    return {
        UUID,
        TR_PASS,
        SUB_PATH,
        DOH_URL: 'https://cloudflare-dns.com/dns-query',
        FALLBACK: 'www.hcaptcha.com',
        kv: kvStore
    };
}

/** 解析 raw 订阅里的分享链接（vless/trojan），只保留判断节点形态需要的字段。 */
function parseRawNodes(text) {
    const nodes = [];
    for (const line of text.split(/\r?\n/)) {
        if (!line.startsWith('vless://') && !line.startsWith('trojan://')) continue;
        const url = new URL(line);
        const params = Object.fromEntries(url.searchParams);
        nodes.push({
            protocol: url.protocol.replace(':', ''),
            host: url.hostname,
            port: url.port,
            transport: params.type || '',
            security: params.security || '',
            sni: params.sni || '',
            hostHeader: params.host || '',
            path: params.path || '',
            mode: params.mode || '',
            extraRaw: params.extra || '',
            remark: decodeURIComponent(url.hash.slice(1))
        });
    }
    return nodes;
}

/** 从 xray JSON 配置数组里拍平出所有「带 streamSettings 的 outbound」观测值。 */
function summarizeXrayConfigs(configs) {
    const rows = [];
    for (const config of configs) {
        const isBalancer = /最佳延迟/.test(config.remarks || '');
        for (const outbound of config.outbounds || []) {
            const ss = outbound.streamSettings;
            if (!ss || !ss.network) continue;
            rows.push({
                configRemark: config.remarks || '',
                isBalancer,
                tag: outbound.tag || '',
                protocol: outbound.protocol || '',
                address: outbound.settings?.vnext?.[0]?.address || '',
                port: outbound.settings?.vnext?.[0]?.port ?? null,
                network: ss.network,
                security: ss.security || '',
                serverName: ss.tlsSettings?.serverName || '',
                host: ss.wsSettings?.host ?? ss.xhttpSettings?.host ?? '',
                path: ss.wsSettings?.path ?? ss.xhttpSettings?.path ?? '',
                mode: ss.xhttpSettings?.mode ?? '',
                extra: ss.xhttpSettings?.extra ?? null
            });
        }
    }
    return rows;
}

/** 从 Clash 配置里拍平出 proxies / proxy-groups 观测值。Clash 的响应是单份 Config 对象。 */
function summarizeClashConfig(config) {
    const proxies = (config.proxies || []).map((proxy) => ({
        name: proxy.name || '',
        type: proxy.type || '',
        server: proxy.server || '',
        port: proxy.port ?? null,
        network: proxy.network || '',
        servername: proxy.servername ?? proxy.sni ?? '',
        xhttpOpts: proxy['xhttp-opts'] ?? null,
        wsOpts: proxy['ws-opts'] ?? null
    }));
    const groups = (config['proxy-groups'] || []).map((group) => ({
        name: group.name || '',
        type: group.type || '',
        proxies: group.proxies || []
    }));
    return { proxies, groups };
}

/** 从 sing-box 配置里拍平出 outbounds 观测值（同名 outbounds 数组里也含 selector / urltest 分组）。 */
function summarizeSingboxConfig(config) {
    return {
        outbounds: (config.outbounds || []).map((outbound) => ({
            tag: outbound.tag || '',
            type: outbound.type || '',
            server: outbound.server ?? '',
            serverPort: outbound.server_port ?? null,
            tlsServerName: outbound.tls?.server_name ?? '',
            transportType: outbound.transport?.type ?? '',
            transportPath: outbound.transport?.path ?? '',
            hostHeader: outbound.transport?.headers?.Host ?? '',
            maxEarlyData: outbound.transport?.max_early_data ?? null,
            earlyDataHeaderName: outbound.transport?.early_data_header_name ?? '',
            // selector / urltest 分组用 outbounds 列出成员 tag；真实节点没有该字段
            memberTags: Array.isArray(outbound.outbounds) ? outbound.outbounds : null
        }))
    };
}

/** 子进程：拉一次订阅，把观测值落盘。断言全部在父进程。 */
async function collect(phase, settings) {
    const env = makeEnv(makeKv({
        proxySettings: JSON.stringify(settings),
        proxySettings_ver: '1',
        warpAccounts: JSON.stringify(WARP_ACCOUNTS)
    }));

    let payload;
    if (phase.startsWith('raw-')) {
        const app = phase === 'raw-singbox' ? 'sing-box' : 'xray';
        const response = await handler.fetch(
            new Request(`${ORIGIN}/sub/raw/${SUB_PATH}?app=${app}`, { headers: { Host: 'panel.example.com' } }),
            env,
            ctx
        );
        const decoded = Buffer.from((await response.text()).trim(), 'base64').toString('utf8');
        payload = { nodes: parseRawNodes(decoded) };
    } else {
        const app = phase.startsWith('clash-') ? 'clash' : phase.startsWith('sb-') ? 'sing-box' : 'xray';
        const response = await handler.fetch(
            new Request(`${ORIGIN}/sub/normal/${SUB_PATH}?app=${app}`, { headers: { Host: 'panel.example.com' } }),
            env,
            ctx
        );
        // configJsonResponse：xray 是「配置数组」，clash / sing-box 是「单份配置对象」，格式漂移时直接在这里炸
        const parsed = JSON.parse(await response.text());
        payload = phase.startsWith('clash-')
            ? { clash: summarizeClashConfig(parsed) }
            : phase.startsWith('sb-')
                ? { singbox: summarizeSingboxConfig(parsed) }
                : { rows: summarizeXrayConfigs(parsed) };
    }

    writeFileSync(`${OBS_PREFIX}.${phase}.json`, JSON.stringify(payload));
    process.exit(0);
}

function runPhase(phase, settings) {
    const child = spawnSync(process.execPath, [SELF], {
        stdio: 'inherit',
        env: {
            ...process.env,
            XN_PHASE: phase,
            ...(settings ? { XN_SETTINGS: JSON.stringify(settings) } : {})
        }
    });
    if (child.error) {
        out(`FAIL  ${phase} 子进程启动失败：${child.error.message}`);
        return false;
    }
    return child.status === 0;
}

const PHASE = process.env.XN_PHASE || 'parent';

// ── 子进程分支：采集后退出
if (PHASE !== 'parent') {
    await collect(PHASE, JSON.parse(process.env.XN_SETTINGS || '{}'));
}

// ============================ 父进程 ============================

/** 1) seed：空 KV 拉一次订阅，让 worker 把完整的出厂设置写进 KV */
console.error = () => {};
const seedKv = makeKv({ warpAccounts: JSON.stringify(WARP_ACCOUNTS) });
await handler.fetch(
    new Request(`${ORIGIN}/sub/raw/${SUB_PATH}?app=xray`, { headers: { Host: 'panel.example.com' } }),
    makeEnv(seedKv),
    ctx
);
const baseSettings = JSON.parse(seedKv.store.get('proxySettings'));
// cleanIPs 决定订阅里会不会出现节点（出厂默认是空列表 = 没有节点）
baseSettings.cleanIPs = ['104.16.0.1'];
writeFileSync(SEED_FILE, JSON.stringify(baseSettings));

check('出厂默认 xhttpConfigs=false（新部署写入 KV 的设置里该字段为 false）',
    baseSettings.xhttpConfigs === false, `xhttpConfigs=${baseSettings.xhttpConfigs}`);
check('出厂默认 randomPath=true（对照 XHTTP 路径规则的前提）',
    baseSettings.randomPath === true, `randomPath=${baseSettings.randomPath}`);

const settings = baseSettings;
const phases = [
    ['raw-on', { ...settings, xhttpConfigs: true, randomPath: true }],
    ['raw-off', { ...settings, xhttpConfigs: false, randomPath: true }],
    ['raw-fixed', { ...settings, xhttpConfigs: true, randomPath: false }],
    ['raw-singbox', { ...settings, xhttpConfigs: true, randomPath: true }],
    ['json-on', { ...settings, xhttpConfigs: true, randomPath: true }],
    ['clash-on', { ...settings, xhttpConfigs: true, randomPath: true }],
    ['clash-off', { ...settings, xhttpConfigs: false, randomPath: true }],
    ['sb-on', { ...settings, xhttpConfigs: true, randomPath: true }],
    ['sb-off', { ...settings, xhttpConfigs: false, randomPath: true }],
    ['sb-fixed', { ...settings, xhttpConfigs: true, randomPath: false }]
];
let allOk = true;
for (const [phase, phaseSettings] of phases) allOk = runPhase(phase, phaseSettings) && allOk;

if (!allOk) {
    check('所有采集 phase 正常退出', false, '子进程失败，后续断言跳过');
} else {
    const load = (phase) => JSON.parse(readFileSync(`${OBS_PREFIX}.${phase}.json`, 'utf8'));
    const isXhttp = (node) => node.transport === 'xhttp';
    const wsVlessOf = (nodes) => nodes.filter((node) => node.protocol === 'vless' && node.transport === 'ws');
    const nodeKey = (node) => `${node.host}:${node.port}`;
    const stripEd = (path) => path.replace(/\?ed=\d+$/, '');

    // ── (a) 关闭开关：raw 输出与 xhttp 无关（回归钉）
    const off = load('raw-off');
    const on = load('raw-on');
    const onX = on.nodes.filter(isXhttp);
    const offX = off.nodes.filter(isXhttp);

    check('关闭 xhttpConfigs：raw 订阅不含任何 type=xhttp 节点', offX.length === 0,
        `xhttp 节点=${offX.length}`);
    check('关闭 xhttpConfigs：仍生成 WS VLESS 节点（对照组有效）', wsVlessOf(off.nodes).length > 0,
        `nodes=${off.nodes.length}`);
    check('关闭开关的节点总数 = 开启时总数 - XHTTP 节点数（开关只增不减）',
        off.nodes.length === on.nodes.length - onX.length,
        `off=${off.nodes.length} on=${on.nodes.length} xhttp=${onX.length}`);
    check('关闭开关时非 XHTTP 节点备注与开启时逐字一致（XHTTP 不消耗 remark 编号）',
        JSON.stringify(off.nodes.map((n) => n.remark).sort()) ===
            JSON.stringify(on.nodes.filter((n) => !isXhttp(n)).map((n) => n.remark).sort()),
        `off=${JSON.stringify(off.nodes.map((n) => n.remark))} on=${JSON.stringify(on.nodes.filter((n) => !isXhttp(n)).map((n) => n.remark))}`);

    // ── (b) 开启开关：raw 订阅的 XHTTP 节点契约
    const onVlWs = wsVlessOf(on.nodes);
    const wsByKey = new Map();
    for (const node of onVlWs) if (!wsByKey.has(nodeKey(node))) wsByKey.set(nodeKey(node), node);
    const pairs = onX.map((node) => ({ node, ws: wsByKey.get(nodeKey(node)) }));

    check('开启 xhttpConfigs：raw 订阅出现 XHTTP 节点', onX.length > 0, `xhttp 节点=${onX.length}`);
    check('XHTTP 节点全部是 VLESS（worker 只承载 VLESS，不生成 Trojan-XHTTP）',
        onX.length > 0 && onX.every((node) => node.protocol === 'vless'),
        JSON.stringify(onX.map((n) => n.protocol)));
    check('每个 XHTTP 节点 type=xhttp & mode=stream-one',
        onX.length > 0 && onX.every((node) => node.transport === 'xhttp' && node.mode === 'stream-one'),
        JSON.stringify(onX.map((n) => ({ type: n.transport, mode: n.mode }))));
    check('XHTTP 节点数 == WS VLESS 节点数（每个地址/端口的并列变体）',
        onX.length === onVlWs.length, `xhttp=${onX.length} wsVLESS=${onVlWs.length}`);
    check('XHTTP 与同地址 WS 节点的 security/sni/host 一致',
        pairs.length > 0 && pairs.every(({ node, ws }) => ws && node.security === ws.security && node.sni === ws.sni && node.hostHeader === ws.hostHeader),
        JSON.stringify(pairs.map(({ node, ws }) => ({ x: [node.security, node.sni, node.hostHeader], ws: ws ? [ws.security, ws.sni, ws.hostHeader] : null }))));
    check('XHTTP 备注是「同地址 WS 节点同名 + XHTTP」',
        pairs.length > 0 && pairs.every(({ node, ws }) => ws && node.remark === `${ws.remark} XHTTP`),
        JSON.stringify(pairs.map(({ node, ws }) => ({ x: node.remark, ws: ws ? `${ws.remark} XHTTP` : null }))));

    const extras = onX.map((node) => {
        try { return JSON.parse(node.extraRaw); } catch { return null; }
    });
    check('每个 XHTTP 节点的 extra 是合法 JSON', onX.length > 0 && extras.every(Boolean),
        JSON.stringify(onX.map((n) => n.extraRaw)));
    check('extra 的值与 UUID 派生一致（xPaddingHeader=UUID[1,7) / xPaddingKey=_UUID[25,31)）',
        extras.length > 0 && extras.every((extra) => extra &&
            Object.entries(EXPECTED_XPADDING).every(([key, value]) => extra[key] === value)),
        JSON.stringify(extras));

    check('randomPath=true：XHTTP 路径是 1-3 段字典随机路径且不带 ?ed=',
        onX.length > 0 && onX.every((node) => DICT_PATH_RE.test(node.path) && !node.path.includes('?')),
        JSON.stringify(onX.map((n) => n.path)));
    check('randomPath=true：同一次生成内 XHTTP 路径两两不同',
        new Set(onX.map((n) => n.path)).size === onX.length,
        JSON.stringify(onX.map((n) => n.path)));
    check('randomPath=true：XHTTP 路径与 WS 路径互不撞车（共用 usedPaths）',
        onX.every((node) => !new Set(onVlWs.map((n) => stripEd(n.path))).has(node.path)),
        JSON.stringify({ xhttp: onX.map((n) => n.path), ws: onVlWs.map((n) => stripEd(n.path)) }));

    // ── (b2) randomPath=false：路径收敛到根路径
    const fixed = load('raw-fixed');
    const fixedX = fixed.nodes.filter(isXhttp);
    const fixedWs = wsVlessOf(fixed.nodes);
    check('randomPath=false 且开启 XHTTP：仍生成 XHTTP 节点', fixedX.length > 0, `xhttp=${fixedX.length}`);
    check('randomPath=false：XHTTP 路径固定为根路径 /（且不带 ed 参数）',
        fixedX.length > 0 && fixedX.every((node) => node.path === '/'),
        JSON.stringify(fixedX.map((n) => n.path)));
    check('randomPath=false：WS 路径同为根路径（对照，证明开关确实生效）',
        fixedWs.length > 0 && fixedWs.every((node) => stripEd(node.path) === '/'),
        JSON.stringify(fixedWs.map((n) => n.path)));

    // ── (c) ?app=sing-box：不混入 xhttp 节点
    const sing = load('raw-singbox');
    check('app=sing-box 且开启 XHTTP：raw 订阅仍生成节点（对照组有效）',
        sing.nodes.length > 0, `nodes=${sing.nodes.length}`);
    check('app=sing-box：raw 订阅不含任何 type=xhttp 节点',
        sing.nodes.every((node) => !isXhttp(node)),
        JSON.stringify(sing.nodes.filter(isXhttp).map((n) => n.remark)));

    // ── (d) /sub/normal?app=xray：JSON 里的 xhttp outbound
    const json = load('json-on');
    const jsonX = json.rows.filter((row) => row.network === 'xhttp');
    const jsonWs = json.rows.filter((row) => row.network === 'ws');
    const jsonXKinds = new Set(jsonX.map((row) => `${row.address}:${row.port}`));
    // 只比较 VLESS 的 WS 出站：XHTTP 只承载 VLESS，而 Trojan 出站的地址在 settings.servers[0]
    // （不是 vnext），混进来会得到空地址/空端口，把种类集合凭空撑大。
    const jsonWsVless = jsonWs.filter((row) => !row.isBalancer && row.protocol === 'vless');
    const jsonWsKinds = new Set(jsonWsVless.map((row) => `${row.address}:${row.port}`));
    const wsJsonByKey = new Map();
    for (const row of jsonWsVless) wsJsonByKey.set(`${row.address}:${row.port}`, row);

    check('Xray JSON：出现 network=xhttp 的 outbound', jsonX.length > 0, `xhttp=${jsonX.length}`);
    check('Xray JSON：WS 出站仍存在（回归钉）', jsonWs.length > 0, `ws=${jsonWs.length}`);
    check('Xray JSON：XHTTP outbound 是 VLESS 且带 xhttpSettings 的 path/mode/host/extra',
        jsonX.length > 0 && jsonX.every((row) => row.protocol === 'vless' && row.path && row.mode === 'stream-one' && row.host && row.extra),
        JSON.stringify(jsonX.map((r) => ({ p: r.protocol, path: r.path, mode: r.mode, host: r.host, extra: !!r.extra }))));
    check('Xray JSON：xhttpSettings.extra 与 raw extra 同源（header/key 由 UUID 派生）',
        jsonX.length > 0 && jsonX.every((row) => row.extra &&
            Object.entries(EXPECTED_XPADDING).every(([key, value]) => row.extra[key] === value)),
        JSON.stringify(jsonX.map((r) => r.extra)));
    check('Xray JSON：XHTTP 与同地址 WS 出站的 security/serverName 一致',
        jsonX.length > 0 && jsonX.every((row) => {
            const ws = wsJsonByKey.get(`${row.address}:${row.port}`);
            return ws && row.security === ws.security && row.serverName === ws.serverName;
        }),
        JSON.stringify(jsonX.map((r) => ({ key: `${r.address}:${r.port}`, sec: [r.security, r.serverName] }))));
    check('Xray JSON：XHTTP 节点数与 WS 地址节点数一致（每个地址/端口一个并列变体）',
        jsonXKinds.size > 0 && jsonXKinds.size === jsonWsKinds.size,
        `xhttp=${jsonXKinds.size} ws=${jsonWsKinds.size}：${JSON.stringify([...jsonWsKinds])}`);
    check('Xray JSON：XHTTP 不进「最佳延迟」balancer',
        jsonX.every((row) => !row.isBalancer),
        JSON.stringify(jsonX.filter((r) => r.isBalancer).map((r) => r.configRemark)));

    // ── (e) Clash / mihomo（≥ 1.19.22）：network=xhttp + xhttp-opts
    const clashOn = load('clash-on').clash;
    const clashOff = load('clash-off').clash;
    const cOnX = clashOn.proxies.filter((proxy) => proxy.network === 'xhttp');
    const cOffX = clashOff.proxies.filter((proxy) => proxy.network === 'xhttp');
    const cOnWsVless = clashOn.proxies.filter((proxy) => proxy.network === 'ws' && proxy.type === 'vless');
    const cOffWsVless = clashOff.proxies.filter((proxy) => proxy.network === 'ws' && proxy.type === 'vless');
    const cWsByKey = new Map();
    for (const proxy of cOnWsVless) cWsByKey.set(`${proxy.server}:${proxy.port}`, proxy);
    const cPairs = cOnX.map((proxy) => ({ proxy, ws: cWsByKey.get(`${proxy.server}:${proxy.port}`) }));
    const cXhttpNames = new Set(cOnX.map((proxy) => proxy.name));
    const cUrlTestGroups = clashOn.groups.filter((group) => group.type === 'url-test');

    check('Clash：xhttpConfigs=false 时没有任何 network=xhttp 的 proxy', cOffX.length === 0,
        JSON.stringify(cOffX.map((p) => p.name)));
    check('Clash：xhttpConfigs=true 时出现 network=xhttp 的 proxy', cOnX.length > 0,
        `xhttp=${cOnX.length}`);
    check('Clash：XHTTP proxy 是 VLESS 且 xhttp-opts 带 path/host/mode=stream-one',
        cOnX.length > 0 && cOnX.every((p) => p.type === 'vless' && p.xhttpOpts &&
            p.xhttpOpts.path && p.xhttpOpts.host && p.xhttpOpts.mode === 'stream-one'),
        JSON.stringify(cOnX.map((p) => ({ type: p.type, opts: p.xhttpOpts }))));
    check('Clash：xhttp-opts 的 x-padding-* 与 UUID 派生一致（与 raw/xray 同源）',
        cOnX.length > 0 && cOnX.every((p) => p.xhttpOpts &&
            p.xhttpOpts['x-padding-obfs-mode'] === EXPECTED_XPADDING.xPaddingObfsMode &&
            p.xhttpOpts['x-padding-method'] === EXPECTED_XPADDING.xPaddingMethod &&
            p.xhttpOpts['x-padding-placement'] === EXPECTED_XPADDING.xPaddingPlacement &&
            p.xhttpOpts['x-padding-header'] === EXPECTED_XPADDING.xPaddingHeader &&
            p.xhttpOpts['x-padding-key'] === EXPECTED_XPADDING.xPaddingKey),
        JSON.stringify(cOnX.map((p) => p.xhttpOpts)));
    check('Clash：XHTTP 备注 =「同地址 WS VLESS 备注 + XHTTP」',
        cPairs.length > 0 && cPairs.every(({ proxy, ws }) => ws && proxy.name === `${ws.name} XHTTP`),
        JSON.stringify(cPairs.map(({ proxy, ws }) => ({ x: proxy.name, ws: ws ? `${ws.name} XHTTP` : null }))));
    check('Clash：开关前后 WS VLESS 节点数与备注逐字不变（回归钉）',
        cOnWsVless.length > 0 && cOnWsVless.length === cOffWsVless.length &&
            JSON.stringify(cOnWsVless.map((p) => p.name).sort()) === JSON.stringify(cOffWsVless.map((p) => p.name).sort()),
        `on=${cOnWsVless.length} off=${cOffWsVless.length}`);
    check('Clash：XHTTP 不进 url-test 组（不参与「最佳延迟」采样）',
        cUrlTestGroups.every((group) => !group.proxies.some((name) => cXhttpNames.has(name))),
        JSON.stringify(cUrlTestGroups.map((g) => ({ name: g.name, hit: g.proxies.filter((n) => cXhttpNames.has(n)) }))));
    check('Clash：XHTTP 出现在 select 分组里（✅ Selector / ACL 分组，UI 可选）',
        cOnX.length > 0 && clashOn.groups.some((group) => group.type === 'select' &&
            cOnX.every((p) => group.proxies.includes(p.name))),
        JSON.stringify(clashOn.groups.map((g) => ({ name: g.name, type: g.type }))));

    // ── (f) sing-box：内核没有原生 xhttp transport
    // 按 cfnew-panel（src/singbox.mjs）的约定：沿用一个 WS 传输接到同一个 Worker，tag 保留 ` XHTTP` 后缀。
    // 一旦这里被改成 type:"xhttp"，sing-box 会整份配置报错（不是跳过该节点）→ 订阅直接不可用。
    const sbOn = load('sb-on').singbox;
    const sbOff = load('sb-off').singbox;
    const sbFixed = load('sb-fixed').singbox;
    const isSbXhttp = (node) => node.tag.endsWith(' XHTTP');
    const sbWsVless = (cfg) => cfg.outbounds.filter((o) => o.type === 'vless' && o.transportType === 'ws' && !isSbXhttp(o));
    const sbOnX = sbOn.outbounds.filter(isSbXhttp);
    const sbOffX = sbOff.outbounds.filter(isSbXhttp);
    const sbWsByKey = new Map();
    for (const node of sbWsVless(sbOn)) sbWsByKey.set(`${node.server}:${node.serverPort}`, node);
    const sbPairs = sbOnX.map((node) => ({ node, ws: sbWsByKey.get(`${node.server}:${node.serverPort}`) }));
    const sbXhttpTags = new Set(sbOnX.map((node) => node.tag));
    const sbUrlTests = sbOn.outbounds.filter((node) => node.type === 'urltest');
    const sbSelector = sbOn.outbounds.find((node) => node.type === 'selector' && node.tag === '✅ Selector');

    check('sing-box：xhttpConfigs=false 时没有任何 tag 以「 XHTTP」结尾的出站', sbOffX.length === 0,
        JSON.stringify(sbOffX.map((n) => n.tag)));
    check('sing-box：关闭开关时 WS VLESS 出站数与 tag 集合与开启后逐字一致（回归钉）',
        sbWsVless(sbOff).length > 0 && sbWsVless(sbOff).length === sbWsVless(sbOn).length &&
            JSON.stringify(sbWsVless(sbOff).map((n) => n.tag).sort()) ===
                JSON.stringify(sbWsVless(sbOn).map((n) => n.tag).sort()),
        `off=${JSON.stringify(sbWsVless(sbOff).map((n) => n.tag))} on=${JSON.stringify(sbWsVless(sbOn).map((n) => n.tag))}`);
    check('sing-box：xhttpConfigs=true 时出现「<WS VLESS tag> XHTTP」的 VLESS 出站',
        sbOnX.length > 0 && sbOnX.every((node) => node.type === 'vless'),
        JSON.stringify(sbOnX.map((n) => ({ tag: n.tag, type: n.type }))));
    check('sing-box：XHTTP 沿用 WS 传输（transport.type=ws）且 path 符合随机路径规则',
        sbOnX.length > 0 && sbOnX.every((node) =>
            node.transportType === 'ws' && DICT_PATH_RE.test(node.transportPath) && !node.transportPath.includes('?')),
        JSON.stringify(sbOnX.map((n) => ({ type: n.transportType, path: n.transportPath }))));
    check('sing-box：XHTTP 与同地址 WS 节点的 server/server_port/tls.server_name/transport.headers.Host 一致',
        sbPairs.length > 0 && sbPairs.every(({ node, ws }) => ws &&
            node.server === ws.server && node.serverPort === ws.serverPort &&
            node.tlsServerName === ws.tlsServerName && node.hostHeader === ws.hostHeader),
        JSON.stringify(sbPairs.map(({ node, ws }) => ({ x: [node.server, node.serverPort, node.tlsServerName, node.hostHeader], ws: ws ? [ws.server, ws.serverPort, ws.tlsServerName, ws.hostHeader] : null }))));
    check('sing-box：XHTTP 的 max_early_data/early_data_header_name 与 WS 节点同形',
        sbPairs.length > 0 && sbPairs.every(({ node, ws }) => ws &&
            typeof node.maxEarlyData === 'number' && node.maxEarlyData > 0 &&
            node.earlyDataHeaderName === ws.earlyDataHeaderName &&
            node.earlyDataHeaderName === 'Sec-WebSocket-Protocol'),
        JSON.stringify(sbPairs.map(({ node, ws }) => ({ x: [node.maxEarlyData, node.earlyDataHeaderName], ws: ws ? [ws.maxEarlyData, ws.earlyDataHeaderName] : null }))));
    check('sing-box：XHTTP tag =「同地址 WS VLESS tag + XHTTP」',
        sbPairs.length > 0 && sbPairs.every(({ node, ws }) => ws && node.tag === `${ws.tag} XHTTP`),
        JSON.stringify(sbPairs.map(({ node, ws }) => ({ x: node.tag, ws: ws ? `${ws.tag} XHTTP` : null }))));
    check('sing-box：XHTTP 出站数 == 地址类 WS VLESS 出站数',
        sbOnX.length > 0 && sbOnX.length === sbWsVless(sbOn).length,
        `xhttp=${sbOnX.length} wsVless=${sbWsVless(sbOn).length}`);
    check('sing-box：XHTTP 出现在 ✅ Selector 的成员里（UI / ACL 可选）',
        !!sbSelector && sbOnX.length > 0 && sbOnX.every((node) => sbSelector.memberTags.includes(node.tag)),
        JSON.stringify(sbSelector ? sbSelector.memberTags : null));
    check('sing-box：XHTTP 不在任何 urltest（最佳延迟 🚀）分组成员里',
        sbUrlTests.length > 0 && sbUrlTests.every((group) => !group.memberTags.some((tag) => sbXhttpTags.has(tag))),
        JSON.stringify(sbUrlTests.map((g) => ({ tag: g.tag, hit: g.memberTags.filter((t) => sbXhttpTags.has(t)) }))));
    check('sing-box：randomPath=false 时 XHTTP 的 transport.path 固定为 /',
        sbFixed.outbounds.filter(isSbXhttp).length > 0 &&
            sbFixed.outbounds.filter(isSbXhttp).every((node) => node.transportPath === '/'),
        JSON.stringify(sbFixed.outbounds.filter(isSbXhttp).map((n) => n.transportPath)));
}

out('');
out(failures === 0 ? 'xhttp-node: OK' : `xhttp-node: ${failures} 项失败`);
process.exit(failures === 0 ? 0 : 1);
