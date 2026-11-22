/**
 * tools/kv-read-budget.test.mjs
 *
 * KV 读预算回归：`getDataset` 的 `needWarp` 开关 + `warpAccounts` 的 isolate 级缓存。
 * 运行：node tools/kv-read-budget.test.mjs
 * （package.json 里是 `npm run test:kvbudget`）
 *
 * 为什么需要它：这两条改动都属于"功能零变化、只是少读一次 KV"的纯优化 ——
 *   · 配置（proxySettings）本来就有 kv-cache 的 5 分钟内存缓存；
 *   · 但 warpAccounts 原先在 getDataset 里**无条件直读 KV**，而 getDataset 被 setSettings
 *     在每条 WS 连接 / 每个 XHTTP 请求上调用 ⇒ 一条代理连接固定付 1 次 KV 读；
 *   · 一次订阅拉取里 configs 还会再调 getDataset，同一份账号被重复读。
 * 行为测试与 smoke 都不可能发现"多读了一次"（响应逐字节相同），只能靠**读计数**钉住。
 *
 * 判据（实测值，见每条断言）：
 *   1. 冷 isolate 首次 WS 升级：只读配置（版本键 + 整份配置 = 2 次；空 KV 没有版本复读），
 *      **0 次 warpAccounts** —— 数据面不读账号
 *   2. 第二次 WS 升级：**0 次 KV 读**（配置走内存缓存，账号不读）—— 本次优化的主命题
 *   3. 订阅拉取：**1 次 warpAccounts**（首次填充缓存）
 *   4. 第二次订阅：**0 次**（isolate 级缓存命中，不再重复读同一份账号）
 *   5. clash 配置生成（另一条 getDataset 调用链）：**0 次**
 *   6. 缓存 TTL（300s）到期后：重新读一次 KV（缓存不是永久的）
 *   7. 失败态不缓存：KV 里没有有效账号 + 注册失败时，每次请求都要重新判定
 *      （否则「退避窗口结束后重新注册」会被拖成「窗口外再等一个 TTL」——见 kv.ts 的注释）
 *
 * 注意：
 *  · WS 分支要求路径在公共路径字典内；本测试用 env.SUB_PATH 走管理员路径豁免，
 *    与 ws-firstpacket 的口径一致。connect 桩一律抛错（不需要真的建连）。
 *  · 第 7 条必须跑在**独立进程**里：isolate 级缓存与设置缓存都是模块级全局，同进程里前面
 *    成功读过的账号会把"未缓存"的观察掩盖掉。生产只有一个真实 KV，但测试需要干净进程 ——
 *    这也正是 smoke.mjs 一进程一份 bundle 的理由。
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
    makeReporter, makeEnv, makeKv, installWebStubs, captureConsole,
    importBundle, earlyDataRequest, vlessPacket, ORIGIN
} from './ws-test-harness.mjs';

/** 失败态那一节在子进程里跑（见文件头「注意」第 2 条） */
const FAILURE_PHASE_FLAG = '--failure-phase';

const { out, check, failures } = makeReporter();

globalThis.connect = () => {
    throw new Error('connect() is not available in the test harness');
};

installWebStubs();
const { restore } = captureConsole();
const handler = await importBundle();
const ctx = { waitUntil() {}, passThroughOnException() {} };

/** 形状合法的两条 WARP 账号（对齐 normalizeWarpAccounts 的守卫），保证走 KV 命中而不是注册 */
const WARP_ACCOUNT = {
    privateKey: 'YI9lLc0S3z4PqyZ7wJk6v1Bn2Xm5Tg8RhQdVcFbAeUs=',
    publicKey: 'Q2FzZVVuaXRRdWlja0Jyb3duRm94SnVtcHNPdmVyTGF6eURvZz0=',
    warpIPv6: '2606:4700:110:8a1b::1/128',
    reserved: 'AbCd'
};

/**
 * 计数版 KV：包一层 makeKv，把每次 get 的键名记下来。
 * 只统计 get —— 写次数与本次优化无关，混在一起反而看不清。
 */
function makeCountingKv(seed = {}) {
    const base = makeKv(seed);
    const reads = [];
    return {
        reads,
        kv: {
            ...base,
            async get(key, opts) {
                reads.push(key);
                return base.get(key, opts);
            }
        }
    };
}

const countOf = (keys, key) => keys.filter((k) => k === key).length;

async function fetchPath(path, env) {
    const response = await handler.fetch(new Request(ORIGIN + path, { headers: { Host: 'panel.example.com' } }), env, ctx);
    await response.text();
    return response.status;
}

// ============================================================ 子进程：失败态不缓存
if (process.argv.includes(FAILURE_PHASE_FLAG)) {
    // 空 KV（没有 warpAccounts）⇒ 走注册；fetch 桩返回伪装页 HTML ⇒ 注册失败 ⇒ 内置兜底账号
    const emptyAccountsKv = makeCountingKv({});
    const envEmpty = makeEnv({ kv: emptyAccountsKv.kv, SUB_PATH: 'kv-budget-empty' });
    const subEmpty = () => fetchPath('/sub/raw/kv-budget-empty?app=xray', envEmpty);

    const status = await subEmpty();
    check('空 KV 的订阅请求：200（注册失败回退内置账号，不影响出配置）', status === 200, `status=${status}`);

    const warpReadsAfterFirst = countOf(emptyAccountsKv.reads, 'warpAccounts');
    await subEmpty();
    const warpReadsAfterSecond = countOf(emptyAccountsKv.reads, 'warpAccounts');

    check('失败态没有被缓存：第二次请求仍在读 warpAccounts',
        warpReadsAfterFirst >= 1 && warpReadsAfterSecond > warpReadsAfterFirst,
        `第一次后 ${warpReadsAfterFirst} 次 / 第二次后 ${warpReadsAfterSecond} 次`);

    restore();
    out(failures() === 0 ? '  （失败态子进程：OK）' : '  （失败态子进程：FAILED）');
    process.exit(failures() === 0 ? 0 : 1);
}

// ============================================================ 主进程
/** 预置两条形状合法账号：保证走 KV 命中，不会真的去 POST 注册接口 */
const accountsKv = makeCountingKv({
    warpAccounts: JSON.stringify([WARP_ACCOUNT, { ...WARP_ACCOUNT, privateKey: 'Zk8yN2J4cTZ3eDFCbjJYbTVUZzhSaFFkVmNGYkFlVXM=' }])
});

const env = makeEnv({ kv: accountsKv.kv, SUB_PATH: 'kv-budget-sub-path' });
const takeReads = () => accountsKv.reads.splice(0, accountsKv.reads.length);

/** 一次 WS 升级（带 VLESS 首包，进入真实拨号链路；connect 桩抛错即止） */
async function wsUpgrade() {
    takeReads();
    const response = await handler.fetch(earlyDataRequest(vlessPacket()), env, ctx);
    // 首包处理在上行泵的异步链里，等它跑完再收账，避免漏计
    await new Promise((r) => setTimeout(r, 300));
    return { status: response.status, reads: takeReads() };
}

async function sub(path) {
    takeReads();
    const status = await fetchPath(path, env);
    return { status, reads: takeReads() };
}

// ── 1) 冷 isolate 首次 WS 升级：读配置，不读账号
let r = await wsUpgrade();
check('首次 WS 升级：101', r.status === 101, `status=${r.status}`);
check('首次 WS 升级：0 次 warpAccounts 读（数据面不需要账号）',
    countOf(r.reads, 'warpAccounts') === 0, r.reads.join(', '));
check('首次 WS 升级：配置读只发生一次（版本键 + 整份配置）',
    r.reads.length === 2 && r.reads.includes('proxySettings_ver') && r.reads.includes('proxySettings'),
    r.reads.join(', '));

// ── 2) 第二次 WS 升级：稳态 0 读
r = await wsUpgrade();
check('第二次 WS 升级：101', r.status === 101, `status=${r.status}`);
check('第二次 WS 升级：0 次 KV 读（配置内存缓存 + 不读账号）',
    r.reads.length === 0, r.reads.join(', '));

// ── 3) 订阅拉取：首次填充账号缓存
r = await sub('/sub/raw/kv-budget-sub-path?app=xray');
check('订阅拉取（raw/xray）：200', r.status === 200, `status=${r.status}`);
check('订阅拉取：恰好 1 次 warpAccounts 读（配置已在内存缓存里）',
    r.reads.length === 1 && countOf(r.reads, 'warpAccounts') === 1, r.reads.join(', '));

// ── 4) 第二次订阅：账号走 isolate 缓存
r = await sub('/sub/raw/kv-budget-sub-path?app=xray');
check('第二次订阅拉取：200', r.status === 200, `status=${r.status}`);
check('第二次订阅拉取：0 次 KV 读（账号命中 isolate 级缓存）',
    r.reads.length === 0, r.reads.join(', '));

// ── 5) 另一条 getDataset 调用链（clash 配置生成）同样不重复读账号
r = await sub('/sub/normal/kv-budget-sub-path?app=clash');
check('订阅拉取（normal/clash）：200', r.status === 200, `status=${r.status}`);
check('订阅拉取（clash 链）：0 次 KV 读（getDataset 第二、三次调用全部命中缓存）',
    r.reads.length === 0, r.reads.join(', '));

// ── 6) 缓存不是永久的：TTL（300s）到期后必须重新读一次 KV
const realNow = Date.now;
Date.now = () => realNow() + 301_000;
r = await sub('/sub/raw/kv-budget-sub-path?app=xray');
Date.now = realNow;
check('账号缓存 TTL 到期后重新读 warpAccounts',
    r.status === 200 && countOf(r.reads, 'warpAccounts') === 1, r.reads.join(', '));

// ── 7) 失败态不缓存（独立进程）
const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), FAILURE_PHASE_FLAG], {
    encoding: 'utf8',
    // 子进程自带完整环境；父进程的 console 被 captureConsole 换过，不影响子进程
    env: process.env
});
if (child.stdout) out(child.stdout.trimEnd());
if (child.status !== 0 && child.stderr) out(child.stderr.trimEnd());
check('失败态不缓存（子进程核查通过）', child.status === 0, `child exit=${child.status}`);

restore();
out(failures() === 0 ? '\nkv-read-budget: OK' : `\nkv-read-budget: ${failures()} 项失败`);
process.exit(failures() === 0 ? 0 : 1);
