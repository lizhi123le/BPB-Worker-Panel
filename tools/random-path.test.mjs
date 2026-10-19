/**
 * tools/random-path.test.mjs
 *
 * 面板「节点随机路径」开关（settings.randomPath）的行为测试。运行：node tools/random-path.test.mjs
 *
 * 为什么需要它：WS 伪装路径有两套合法形态 ——
 *   · 开启（出厂默认）：每个节点各自抽 1-3 段字典路径（`/api/video?ed=2400`），同次生成内互不相同；
 *   · 关闭：所有节点共用根路径（`/?ed=2400`），刷新订阅路径不再变化。
 * worker 的 WS 守卫只对「根路径 / 管理员路径 / 字典内路径」放行，所以这两套形态都必须钉住：
 * 一旦关闭分支落到某个既不在字典、也不在放行清单里的固定路径，客户端会静默连不上。
 *
 * 实现方式：同一个脚本跑三个进程，避免手抄一份 defaults：
 *   1) seed      —— 空 KV 拉一次订阅，让 worker 把**完整**出厂设置写进 KV，落盘成 JSON（补一个 cleanIP）；
 *   2) enabled   —— 用这份设置（randomPath=true）拉原始订阅，断言随机路径形态与逐节点唯一；
 *   3) disabled  —— 同一份设置只把 randomPath 改成 false，断言所有节点都是固定根路径。
 * 全程冻结凭据与出站网络，只加载 .build/worker.reference.js（混淆前产物）。
 *
 * 前提：先构建过（`npm run build`，或快速版 `NODE_ENV=mangle node scripts/build.js`）。
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const BUNDLE = '.build/worker.reference.js';
const SEED_FILE = '.build/random-path.settings.json';
const SELF = fileURLToPath(import.meta.url);
const UUID = '11111111-2222-4333-8444-555555555555';
const TR_PASS = 'trojan-secret';
const SUB_PATH = 'random-path-sub';
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

/** 拉一次原始订阅（xray raw），返回每个节点的 { path, ed } 观测值。 */
async function fetchRawNodes(kvSeed) {
    const env = {
        UUID,
        TR_PASS,
        SUB_PATH,
        DOH_URL: 'https://cloudflare-dns.com/dns-query',
        FALLBACK: 'www.hcaptcha.com',
        kv: makeKv(kvSeed)
    };

    const response = await handler.fetch(
        new Request(`${ORIGIN}/sub/raw/${SUB_PATH}?app=xray`, { headers: { Host: 'panel.example.com' } }),
        env,
        ctx
    );
    const body = await response.text();
    const decoded = Buffer.from(body.trim(), 'base64').toString('utf8');

    const nodes = [];
    for (const line of decoded.split(/\r?\n/)) {
        if (!line.startsWith('vless://') && !line.startsWith('trojan://')) continue;
        const url = new URL(line);
        const path = url.searchParams.get('path') || '';
        const edMatch = path.match(/\?ed=(\d+)$/);
        // `path` 含每节点独有的 `?ed=`，比较路径本身时要剥掉它
        nodes.push({ path, wsPath: path.replace(/\?ed=\d+$/, ''), ed: edMatch ? Number(edMatch[1]) : null });
    }

    return { env, nodes };
}

function runPhase(phase, settings) {
    const child = spawnSync(process.execPath, [SELF], {
        stdio: 'inherit',
        env: {
            ...process.env,
            RP_PHASE: phase,
            ...(settings ? { RP_SETTINGS: JSON.stringify(settings) } : {})
        }
    });
    if (child.error) {
        out(`FAIL  ${phase} 子进程启动失败：${child.error.message}`);
        return false;
    }
    return child.status === 0;
}

const PHASE = process.env.RP_PHASE || 'parent';

// ── 1) seed：空 KV 跑一次，让 worker 写出一份完整的出厂设置
if (PHASE === 'seed') {
    // fetchWarpAccounts 的兜底会打一行 error 日志，这里不关心
    console.error = () => {};
    const { env } = await fetchRawNodes({ warpAccounts: JSON.stringify(WARP_ACCOUNTS) });
    const settings = JSON.parse(env.kv.store.get('proxySettings'));
    // cleanIPs 决定订阅里会不会出现节点（出厂默认是空列表 = 没有节点）
    settings.cleanIPs = ['104.16.0.1'];
    writeFileSync(SEED_FILE, JSON.stringify(settings));
    process.exit(0);
}

// ── 2) enabled / disabled：用同一份设置，只差 randomPath
if (PHASE === 'enabled' || PHASE === 'disabled') {
    const settings = JSON.parse(process.env.RP_SETTINGS || '{}');
    settings.randomPath = PHASE === 'enabled';
    const { nodes } = await fetchRawNodes({
        proxySettings: JSON.stringify(settings),
        proxySettings_ver: '1',
        warpAccounts: JSON.stringify(WARP_ACCOUNTS)
    });

    const sameOf = (key) => new Set(nodes.map((node) => node[key])).size === nodes.length;
    const label = PHASE === 'enabled' ? '开启随机路径' : '关闭随机路径';

    check(`${label}：订阅仍生成了节点`, nodes.length > 0, `nodes=${nodes.length}`);
    check(
        PHASE === 'enabled'
            ? `${label}：每个节点是 1-3 段字典路径 + ?ed=（与改动前形态一致）`
            : `${label}：所有节点的 WS 路径都是固定根路径 /（旧订阅的 /?ed= 形态）`,
        nodes.length > 0 &&
            nodes.every(({ path, wsPath }) =>
                PHASE === 'enabled'
                    ? /^\/(?:[^/?#]+\/){0,2}[^/?#]+\?ed=\d+$/.test(path)
                    : /\?ed=\d+$/.test(path) && wsPath === '/'
            ),
        nodes.map(({ path }) => path).join(' | ')
    );
    check(
        PHASE === 'enabled' ? `${label}：同一次生成内路径两两不同（usedPaths 无放回语义未丢）` : `${label}：所有节点路径一致`,
        PHASE === 'enabled'
            ? new Set(nodes.map(({ wsPath }) => wsPath)).size === nodes.length
            : new Set(nodes.map(({ wsPath }) => wsPath)).size === 1,
        JSON.stringify(nodes.map(({ wsPath }) => wsPath))
    );
    check(
        `${label}：ed 仍逐节点无放回抽取（不被开关影响）`,
        sameOf('ed') && nodes.every(({ ed }) => ed !== null),
        JSON.stringify(nodes.map(({ ed }) => ed))
    );

    out('');
    out(failures === 0 ? `random-path(${PHASE}): OK` : `random-path(${PHASE}): ${failures} 项失败`);
    process.exit(failures === 0 ? 0 : 1);
}

// ── 父进程：seed → enabled → disabled
let ok = runPhase('seed');
if (ok) {
    const settings = JSON.parse(readFileSync(SEED_FILE, 'utf8'));
    check('出厂默认 randomPath=true（写入 KV 的新部署设置里带该字段）', settings.randomPath === true, `randomPath=${settings.randomPath}`);
    ok = runPhase('enabled', settings);
}
if (ok) {
    const settings = JSON.parse(readFileSync(SEED_FILE, 'utf8'));
    ok = runPhase('disabled', settings);
}
if (!ok) failures++;

out('');
out(failures === 0 ? 'random-path: OK' : `random-path: ${failures} 项失败`);
process.exit(failures === 0 ? 0 : 1);
