/**
 * tools/pool-probe.test.mjs
 *
 * 池探针路由 `/panel/pool-probe` 的行为测试。运行：node tools/pool-probe.test.mjs
 * （package.json 里是 `npm run test:probe`）
 *
 * 为什么需要它：这是个**新的管理接口**，三件事必须钉住 ——
 *   1. 鉴权：没有面板会话一律 401（它是 GET，且会发起出站连接，不能裸奔）；
 *   2. 池来源口径：面板 `officialIPs` 有值探面板的，**没设置就探内置官方池**
 *      （否则「面板空池」会探出一张空表，等于这个诊断工具在最常见的情形下失效）；
 *   3. 结论口径：每条都要「通/不通 + 耗时」，且 timeout 参数被钳到 300~3000ms。
 *
 * 打桩：globalThis.connect 由本测试接管 —— 白名单里的 host 立刻 opened（通），
 * 其余返回一个**永不 resolve 的 opened**（模拟黑洞候选，靠探测超时收口）。
 */
import {
    makeReporter, makeEnv, installWebStubs, captureConsole, importBundle, ORIGIN
} from './ws-test-harness.mjs';

const { out, check, failures } = makeReporter();

/**
 * 撑住事件循环：`probeIPReachability` 的超时定时器刻意 `unref()`（Workers 语义：挂起的定时器
 * 不该拖住请求），于是黑洞候选在这里不会自己让 Node 存活 —— 事件循环一空，Node 就会以
 * 「unsettled top-level await」退出。所以测试自己留一个 ref 的定时器，跑完清掉。
 */
const keepAlive = setInterval(() => {}, 1000);

const PASSWORD = 'Probe-pass-1';

/** 立刻连通的地址（其余一律黑洞） */
const GOOD = new Set(['172.71.218.190', '162.158.228.87', '1.1.1.1']);

/** 记录每一次 connect 的目标，便于断言「探的确实是这条」 */
const dialed = [];
globalThis.connect = ({ hostname, port }) => {
    dialed.push(`${hostname}:${port}`);
    return {
        opened: GOOD.has(hostname) ? Promise.resolve() : new Promise(() => {}),
        closed: new Promise(() => {}),
        close() {}
    };
};

installWebStubs();
const { logs, restore } = captureConsole();
const handler = await importBundle();
const ctx = { waitUntil() {}, passThroughOnException() {} };
const env = makeEnv();
const call = (path, init = {}) =>
    handler.fetch(new Request(ORIGIN + path, { ...init, headers: { Host: 'panel.example.com', ...(init.headers || {}) } }), env, ctx);

// ── 0) 先设口令拿会话（后续每个用例都要它）
let res = await call('/login/set-password', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: PASSWORD });
const cookie = (res.headers.get('set-cookie') || '').match(/jwtToken=([^;]+)/)?.[1] || '';
const auth = { cookie: `jwtToken=${cookie}` };
check('取得面板会话', cookie.length > 10, `set-cookie 里没有 jwtToken`);

// ── 0.5) 面板页真的带上了 IP Test 块与处理函数
// 构建期会把 HTML 压缩后嵌进产物（源码里有 ≠ 产物里有），源码级测试看不到这一步，
// 所以在这里从**渲染出来的 /panel** 上再确认一次。
res = await call('/panel', { headers: auth });
const panelHtml = await res.text();
check('面板页含 IP Test 悬浮块（构建链路没有丢块）',
    res.status === 200 && panelHtml.includes('ip-test-container'), `status=${res.status}`);
check('面板页含 testPoolIPs 处理函数（onclick 能接通）',
    panelHtml.includes('testPoolIPs'), `len=${panelHtml.length}`);

// ── 1) 无会话 → 401（不是 200，也不落到伪装兜底）
dialed.length = 0;
res = await call('/panel/pool-probe');
let json = await res.json();
check('无会话：401 + success=false', res.status === 401 && json.success === false, `status=${res.status} body=${JSON.stringify(json)}`);
check('无会话：没有发起任何出站连接', dialed.length === 0, dialed.join(', '));

// ── 2) 自定义列表：通/不通与耗时都要有结论，顺序保持入参顺序
dialed.length = 0;
res = await call('/panel/pool-probe?ips=172.71.218.190,162.158.228.87,10.99.99.99&timeout=300', { headers: auth });
json = await res.json();
let body = json.body || {};
check('自定义列表：200 且 success=true', res.status === 200 && json.success === true, `status=${res.status} body=${JSON.stringify(json).slice(0, 200)}`);
check('自定义列表：source=custom / count=3 / ok=2',
    body.source === 'custom' && body.count === 3 && body.ok === 2,
    `source=${body.source} count=${body.count} ok=${body.ok}`);
check('自定义列表：结果按入参顺序返回',
    (body.results || []).map((r) => r.ip).join(',') === '172.71.218.190,162.158.228.87,10.99.99.99',
    JSON.stringify(body.results));
check('自定义列表：黑洞候选被标成 ok=false 且耗时接近 timeout',
    (() => {
        const dead = (body.results || []).find((r) => r.ip === '10.99.99.99') || {};
        return dead.ok === false && dead.ms >= 250 && dead.ms < 2000;
    })(), JSON.stringify(body.results));
check('自定义列表：fastest 只含可用的、按耗时升序',
    Array.isArray(body.fastest) && body.fastest.length === 2
    && body.fastest.every((r) => GOOD.has(r.ip))
    && body.fastest[0].ms <= body.fastest[1].ms,
    JSON.stringify(body.fastest));
check('自定义列表：确实拨了这三条', dialed.length === 3, dialed.join(', '));

// ── 3) timeout 参数钳制
res = await call('/panel/pool-probe?ips=172.71.218.190&timeout=99999', { headers: auth });
json = await res.json();
check('timeout 过大：钳到 3000ms', json.body?.timeoutMs === 3000, String(json.body?.timeoutMs));

res = await call('/panel/pool-probe?ips=172.71.218.190&timeout=1', { headers: auth });
json = await res.json();
check('timeout 过小：钳到 300ms', json.body?.timeoutMs === 300, String(json.body?.timeoutMs));

res = await call('/panel/pool-probe?ips=172.71.218.190&timeout=abc', { headers: auth });
json = await res.json();
check('timeout 非法：用默认 1500ms', json.body?.timeoutMs === 1500, String(json.body?.timeoutMs));

// ── 4) 面板没设置 officialIPs → 探**内置官方池**（本轮需求的主命题）
res = await call('/panel/pool-probe?timeout=300', { headers: auth });
json = await res.json();
body = json.body || {};
check('面板空池：source=official:builtin（回落到内置官方池，不是空表）',
    body.source === 'official:builtin' && body.count === 6,
    `source=${body.source} count=${body.count}`);
check('面板空池：内置池里可用的两条被认出来（ok=2）', body.ok === 2, `ok=${body.ok} results=${JSON.stringify(body.results)}`);

// ── 5) 面板设置了 officialIPs → 探面板那份
res = await call('/panel/update-settings', {
    method: 'PUT',
    headers: { ...auth, 'Content-Type': 'application/json' },
    body: JSON.stringify({ officialIPs: ['1.1.1.1:443'] })
});
json = await res.json();
check('写入面板 officialIPs 成功', res.status === 200 && json.success === true, `status=${res.status} body=${JSON.stringify(json).slice(0, 160)}`);

dialed.length = 0;
res = await call('/panel/pool-probe?timeout=300', { headers: auth });
json = await res.json();
body = json.body || {};
check('面板已设置：source=official:panel 且只探面板那条',
    body.source === 'official:panel' && body.count === 1 && (body.results || [])[0]?.ip === '1.1.1.1',
    `source=${body.source} results=${JSON.stringify(body.results)}`);
check('面板已设置：确实只拨了面板那条', dialed.join(',') === '1.1.1.1:443', dialed.join(','));

// ── 6) 条目归一化：裸地址补 443、@地区/#备注被剥掉、重复项去重
dialed.length = 0;
const decorated = encodeURIComponent('172.71.218.190:443@HK#note');
res = await call(`/panel/pool-probe?ips=${decorated},172.71.218.190&timeout=300`, { headers: auth });
json = await res.json();
body = json.body || {};
check('归一化：`@地区`/`#备注` 被剥离、同一地址去重后 count=1',
    body.count === 1 && (body.results || [])[0]?.ip === '172.71.218.190',
    `count=${body.count} results=${JSON.stringify(body.results)}`);

// ── 7) 请求绑定的建连器优先：生产上全局 connect 可能根本不存在
//    这条钉的是「探测全判死但拨号却成功」那个静默降级 —— 建连器解析必须走 @common#connectTCP。
const stubConnect = globalThis.connect;
globalThis.connect = () => {
    throw new Error('no global connect in this runtime');
};
const requestWithFetcher = (path) => {
    const request = new Request(ORIGIN + path, { headers: { Host: 'panel.example.com', ...auth } });
    // Workers 里建连器挂在请求对象上；这里直接挂实例属性模拟同一形态
    request.fetcher = { connect: stubConnect };
    return request;
};
res = await handler.fetch(requestWithFetcher('/panel/pool-probe?ips=172.71.218.190&timeout=300'), env, ctx);
json = await res.json();
check('全局 connect 不可用：用 request.fetcher.connect 仍然探通',
    json.body?.ok === 1 && (json.body?.results || [])[0]?.ok === true,
    JSON.stringify(json.body));

// ── 8) 两个建连器都没有：不得静默失败，必须有一条 warn + 结论 0/N
delete globalThis.connect;
res = await handler.fetch(
    new Request(ORIGIN + '/panel/pool-probe?ips=172.71.218.190&timeout=300', { headers: { Host: 'panel.example.com', ...auth } }),
    env, ctx);
json = await res.json();
check('没有任何建连器：结论 0/1', json.body?.ok === 0 && json.body?.count === 1, JSON.stringify(json.body));
check('没有任何建连器：打一条可诊断的 warn（不是静默「不可达」）',
    logs.some((line) => line.includes('没有可用的 TCP 建连器')), logs.slice(-4).join(' | '));
globalThis.connect = stubConnect;

// ── 6.5) 反代池（pool=proxy）的回落链：面板 > env PROXY_IP > 内置池（与 ws-runtime 同一条链）

// a) 面板为空、env 也没有 → 内置反代池（条目是域名，直接交给 connect() 探测，不做 DoH）
dialed.length = 0;
res = await call('/panel/pool-probe?pool=proxy&timeout=300', { headers: auth });
json = await res.json();
body = json.body || {};
check('反代池：面板/env 都没设置时回落到内置池（source=proxy:builtin）',
    body.source === 'proxy:builtin' && body.count > 0,
    `source=${body.source} count=${body.count} body=${JSON.stringify(body).slice(0, 160)}`);
check('反代池：内置池的域名条目被逐条拨号（不做 DoH，直接把域名交给 connect）',
    dialed.length === body.count && dialed.every((entry) => /[a-z]/i.test(entry)),
    `count=${body.count} dialed=${dialed.join(',')}`);

// b) env 有 PROXY_IP → 用它（IP 字面量，不发 DoH）
dialed.length = 0;
res = await handler.fetch(
    new Request(ORIGIN + '/panel/pool-probe?pool=proxy&timeout=300', { headers: { Host: 'panel.example.com', ...auth } }),
    { ...env, PROXY_IP: '1.1.1.1' }, ctx);
json = await res.json();
body = json.body || {};
check('反代池：面板为空但 env PROXY_IP 有值时用 env（source=proxy:env）',
    body.source === 'proxy:env' && body.count === 1 && (body.results || [])[0]?.ip === '1.1.1.1',
    `source=${body.source} results=${JSON.stringify(body.results)}`);

// c) 面板填了 proxyIPs → 面板优先
res = await call('/panel/update-settings', {
    method: 'PUT',
    headers: { ...auth, 'Content-Type': 'application/json' },
    body: JSON.stringify({ proxyIPs: ['1.1.1.1:443'] })
});
check('写入面板 proxyIPs 成功', res.status === 200, `status=${res.status}`);
dialed.length = 0;
res = await call('/panel/pool-probe?pool=proxy&timeout=300', { headers: auth });
json = await res.json();
body = json.body || {};
check('反代池：面板填了就只探面板那份（source=proxy:panel）',
    body.source === 'proxy:panel' && body.count === 1 && dialed.join(',') === '1.1.1.1:443',
    `source=${body.source} dialed=${dialed.join(',')}`);

// ── 9) ips= 支持远程清单 URL：整行一个 URL（查询串里的逗号 / 花括号属于 URL 本身）
//    与池走同一条 resolveUrlEntries，所以「抓回后按行展开再探测」是这里要钉的行为。
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
    const target = String(url);
    if (!target.includes('/api/nodes')) return realFetch(url);
    return new Response(
        '172.71.218.190:443@SG\n162.158.228.87:443@HK\n10.99.99.99:443@SG\n',
        { headers: { 'content-type': 'text/plain; charset=utf-8' } }
    );
};

const REMOTE_URL = 'https://proxy.example.cn/api/nodes?region=SG,HK&limit=15&format={ip}:{port}@{region}';
dialed.length = 0;
res = await call(`/panel/pool-probe?ips=${encodeURIComponent(REMOTE_URL)}&timeout=300`, { headers: auth });
json = await res.json();
body = json.body || {};
check('远程清单：整条 URL 被展开成 3 条候选（逗号没把它拆坏）',
    body.count === 3 && body.requested === 3, `count=${body.count} requested=${body.requested} body=${JSON.stringify(body).slice(0, 200)}`);
check('远程清单：确实逐条拨号（3 条）', dialed.length === 3, dialed.join(','));
check('远程清单：结果里是裸地址（@地区 已剥离，不参与探测）',
    (body.results || []).every((item) => !item.ip.includes('@')),
    JSON.stringify(body.results));

// ── 10) 上限 50 条：候选 60 条时只探前 50，但 requested 如实报告 60
const manyIPs = Array.from({ length: 60 }, (_, index) => `10.10.0.${index + 1}`).join(',');
res = await call(`/panel/pool-probe?ips=${encodeURIComponent(manyIPs)}&timeout=300`, { headers: auth });
json = await res.json();
body = json.body || {};
check('上限 50：count=50 且 requested=60（截断但如实报告）',
    body.count === 50 && body.requested === 60, `count=${body.count} requested=${body.requested}`);

globalThis.fetch = realFetch;

restore();
clearInterval(keepAlive);
out(failures() === 0 ? '\npool-probe: OK' : `\npool-probe: ${failures()} 项失败`);
process.exit(failures() === 0 ? 0 : 1);
