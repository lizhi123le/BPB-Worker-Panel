/**
 * tools/login-firstrun.test.mjs
 *
 * 登录页首访「设置管理员口令」的行为测试。运行：node tools/login-firstrun.test.mjs
 * （package.json 里是 `npm run test:login`）
 *
 * 前提：先构建过（`npm run build`，或快速版 `NODE_ENV=mangle node scripts/build.js`），
 * 本测试直接加载 .build/worker.reference.js —— 混淆前的 esbuild+terser 产物，
 * 与 dist/worker.js 行为等价但可读，且不需要跑 ChaCha20 解码。
 *
 * 覆盖：
 *   1. KV 已绑定但没有 `pwd`：GET /login 应是 setup（设置口令）模式；
 *   2. POST /login/set-password 设口令 → 当场拿到会话 → /panel、/panel/settings 可用；
 *   3. 口令已存在：GET /login 回到 login 模式，未登录再设置一律 401 且不能覆盖原口令；
 *   4. KV 没绑定：/login 仍能打开（setup 模式），设置口令失败时回可读 JSON 「先绑定 KV」；
 *   5. 回归：已登录访问 /login 仍 302 到 /panel；缺凭据仍是原错误页；
 *   6. 首访只有 /login 一条入口：无口令时 /panel 302 到 /login，未登录的 /panel/reset-password 一律被拒，
 *      已登录改密仍可用且改密即吊销旧会话；两条路都不能覆盖已有口令。
 *
 * 不启动任何真实网络：出站 fetch 被冻结成一份固定 HTML。
 */
import { readFileSync } from 'fs';
import { pathToFileURL } from 'url';

const UUID = '11111111-2222-4333-8444-555555555555';
const TR_PASS = 'trojan-secret';
const PASSWORD = 'Admin-pass-1';
const ORIGIN = 'https://panel.example.com';
const BUNDLE = '.build/worker.reference.js';

let failures = 0;
const check = (name, ok, detail = '') => {
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
    if (!ok) failures++;
};

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
        async list() { return { keys: [...store.keys()].map((name) => ({ name })), list_complete: true, cursor: '' }; }
    };
}

globalThis.fetch = async () => new Response('<!DOCTYPE html><html><body>upstream</body></html>', { headers: { 'content-type': 'text/html' } });

let handler;
try {
    handler = (await import(pathToFileURL(BUNDLE).href)).default;
} catch (error) {
    console.error(`找不到可加载的 ${BUNDLE} —— 请先构建：npm run build\n${error.message}`);
    process.exit(1);
}
if (!handler || typeof handler.fetch !== 'function') throw new Error(`${BUNDLE} 没有 default.fetch()`);

const ctx = { waitUntil() {}, passThroughOnException() {} };
const makeEnv = (kv) => ({
    UUID,
    TR_PASS,
    SUB_PATH: 'test-sub-path',
    DOH_URL: 'https://cloudflare-dns.com/dns-query',
    FALLBACK: 'www.hcaptcha.com',
    kv
});
const call = async (env, path, init = {}) =>
    handler.fetch(new Request(ORIGIN + path, { ...init, headers: { Host: 'panel.example.com', ...(init.headers || {}) } }), env, ctx);
const post = (body) => ({ method: 'POST', headers: { 'Content-Type': 'text/plain' }, body });
/**
 * 取 <body> 上的模式标记。必须锚定 body 标签：页面内联的 CSS 里也有
 * `body[data-auth-mode="setup"] #loginForm`，直接全文 search 「data-auth-mode」会永远命中 CSS 里的 setup。
 */
const modeOf = (html) => html.match(/<body[^>]*data-auth-mode=(["']?)([a-z-]+)\1/)?.[2];

// ================================================ 1) KV 已绑定但还没设口令：登录页给设置表单
const env = makeEnv(makeKv());
let res = await call(env, '/login');
let html = await res.text();
check('空口令时 GET /login = 200', res.status === 200, `status=${res.status}`);
check('空口令时页面进入 setup 模式', modeOf(html) === 'setup', modeOf(html));
check('页面含设置口令表单（setupForm / newPassword / confirmPassword）',
    html.includes('setupForm') && html.includes('newPassword') && html.includes('confirmPassword'));
check('页面含口令强度提示', html.includes('at least one capital letter'));
check('setup 模式下 CSS 直接隐藏登录表单（脚本执行前也不闪错表单）',
    /body\[data-auth-mode=["']?setup["']?\]\s*#loginForm/.test(html));
check('login 模式下 CSS 直接隐藏设置表单',
    /body\[data-auth-mode=["']?login["']?\]\s*#setupForm/.test(html));

// 前端脚本已内联，且它引用的每个元素 id 都真的在页面里（防「改 HTML 忘改脚本」这类静默失效）
const scriptSrc = readFileSync('src/assets/login/script.js', 'utf8');
const referencedIds = [...new Set([...scriptSrc.matchAll(/getElementById\('([^']+)'\)/g)].map((m) => m[1]))];
const missingIds = referencedIds.filter((id) => !html.includes(`id=${id}`) && !html.includes(`id="${id}"`));
check('脚本引用的元素 id 都存在于页面', missingIds.length === 0, missingIds.join(', '));
check('页面内联了首访设置口令流程', html.includes('/login/set-password'));

// ================================================ 2) 设置口令 → 当场登录
res = await call(env, '/login/set-password', post(''));
let json = await res.json();
check('空口令被拒 400（避免落成「空口令即可登录」）', res.status === 400 && json.success === false, `status=${res.status} ${JSON.stringify(json).slice(0, 120)}`);

res = await call(env, '/login/set-password', post(PASSWORD));
json = await res.json();
const setCookie = res.headers.get('set-cookie') || '';
const token = setCookie.match(/jwtToken=([^;]+)/)?.[1] || '';
check('未设口令时 POST /login/set-password 成功', json.success === true && res.status === 200, JSON.stringify(json).slice(0, 160));
check('KV 写入 pwd', env.kv.store.get('pwd') === PASSWORD, String(env.kv.store.get('pwd')));
check('设置口令的同时签发会话 Cookie', token.length > 10 && /HttpOnly/.test(setCookie) && /SameSite=Strict/.test(setCookie), setCookie.slice(0, 60));

res = await call(env, '/panel', { headers: { cookie: `jwtToken=${token}` } });
const panelHtml = await res.text();
check('带会话 GET /panel = 200 面板页', res.status === 200 && panelHtml.includes('<title>BPB Panel</title>'), `status=${res.status}`);

res = await call(env, '/panel/settings', { headers: { cookie: `jwtToken=${token}` } });
json = await res.json();
check('带会话 GET /panel/settings 通过并回设置与 subPath', json.success === true && json.body?.subPath === 'test-sub-path' && !!json.body?.proxySettings, JSON.stringify(json).slice(0, 160));
check('/panel/settings 不再下发 isPassSet（已无消费方）', !('isPassSet' in (json.body || {})), JSON.stringify(json.body)?.slice(0, 120));

// ================================================ 3) 口令已存在：回到登录模式，未登录不能覆盖
res = await call(env, '/login');
html = await res.text();
check('口令已设置后 GET /login 为 login 模式', modeOf(html) === 'login', modeOf(html));

res = await call(env, '/login/set-password', post('Other-pass-1'));
json = await res.json();
check('口令已存在时未登录设置被拒 401', res.status === 401 && json.success === false, `status=${res.status} ${JSON.stringify(json).slice(0, 140)}`);
check('被拒后原口令未被覆盖', env.kv.store.get('pwd') === PASSWORD, String(env.kv.store.get('pwd')));

res = await call(env, '/login/authenticate', post(PASSWORD));
json = await res.json();
check('普通登录流程不受影响', json.success === true, JSON.stringify(json).slice(0, 140));

res = await call(env, '/login', { headers: { cookie: `jwtToken=${token}` } });
check('已登录访问 /login 仍 302 到 /panel', res.status === 302 && (res.headers.get('location') || '').endsWith('/panel'), `status=${res.status} loc=${res.headers.get('location')}`);

// ================================================ 4) KV 没绑定：登录页可开，保存口令时提示绑定 KV
const noKvEnv = { UUID, TR_PASS, DOH_URL: 'https://cloudflare-dns.com/dns-query', FALLBACK: 'www.hcaptcha.com' };

res = await call(noKvEnv, '/login');
html = await res.text();
check('未绑定 KV 时 GET /login 仍可打开且为 setup 模式', res.status === 200 && modeOf(html) === 'setup', `status=${res.status} mode=${modeOf(html)}`);

res = await call(noKvEnv, '/login/set-password', post(PASSWORD));
json = await res.json();
check('未绑定 KV 时保存口令回可读 JSON，且点名小写变量名 kv',
    res.status === 500 && json.success === false && /KV namespace is not bound/.test(json.message || '') && /"kv" \(lowercase\)/.test(json.message || ''),
    `status=${res.status} ${JSON.stringify(json).slice(0, 240)}`);

res = await call(noKvEnv, '/panel');
check('未绑定 KV 时 /panel 仍是原错误页（行为未变）', res.status === 500, `status=${res.status}`);

// ================================================ 5) 缺必填凭据：登录页照旧给错误页（C-13 未放宽）
const noCredEnv = { kv: makeKv() };
res = await call(noCredEnv, '/login');
const credBody = await res.text();
check('缺 UUID / Trojan 口令时 /login 仍是凭据错误页', res.status === 500 && credBody.includes('/secrets'), `status=${res.status}`);

// ================================================ 6) 首访只有 /login 一条入口，面板接口只服务已登录改密
// 6a) 无口令时 /panel 302 到 /login；/panel/settings 未认证不下发任何部署状态
// 6b) 未设口令时，未登录直接打 /panel/reset-password 也必须被拒（冗余入口已封闭）
// 6c) 首访设好口令后，已登录改密仍可用，且改密即吊销旧会话（既有 F9 语义）
const panelEnv = makeEnv(makeKv());
res = await call(panelEnv, '/panel');
check('无口令时 GET /panel 302 到 /login（不再渲染面板外壳）',
    res.status === 302 && (res.headers.get('location') || '').endsWith('/login'), `status=${res.status} loc=${res.headers.get('location')}`);

res = await call(panelEnv, '/login');
html = await res.text();
check('无口令时 /login 给的是设置口令表单', modeOf(html) === 'setup', modeOf(html));

res = await call(panelEnv, '/panel/settings');
json = await res.json();
check('未认证 GET /panel/settings 回 401 且不下发部署状态（空 body）',
    res.status === 401 && json.success === false && Object.keys(json.body || {}).length === 0, `status=${res.status} ${JSON.stringify(json).slice(0, 160)}`);

res = await call(panelEnv, '/panel/reset-password', post('Panel-pass-1'));
json = await res.json();
check('未设口令时未登录 POST /panel/reset-password 被拒（首访唯一入口是 /login/set-password）',
    res.status === 401 && panelEnv.kv.store.get('pwd') === undefined, `status=${res.status} pwd=${panelEnv.kv.store.get('pwd')}`);

res = await call(panelEnv, '/login/set-password', post('Panel-pass-1'));
json = await res.json();
const panelCookie = (res.headers.get('set-cookie') || '').match(/jwtToken=([^;]+)/)?.[1] || '';
check('用 /login 首访设好口令并拿到会话', json.success === true && panelCookie.length > 10, JSON.stringify(json).slice(0, 140));

res = await call(panelEnv, '/panel/reset-password', { method: 'POST', headers: { 'Content-Type': 'text/plain', cookie: `jwtToken=${panelCookie}` }, body: 'Panel-pass-2' });
json = await res.json();
check('已登录改密仍可用（/panel/reset-password）', json.success === true && panelEnv.kv.store.get('pwd') === 'Panel-pass-2', JSON.stringify(json).slice(0, 140));

res = await call(panelEnv, '/panel/settings', { headers: { cookie: `jwtToken=${panelCookie}` } });
check('改密即吊销旧会话（F9：轮换签名密钥）', res.status === 401, `status=${res.status}`);

res = await call(panelEnv, '/login/set-password', post('Hijack-pass-1'));
json = await res.json();
check('面板已设口令后 /login/set-password 不能覆盖', res.status === 401 && panelEnv.kv.store.get('pwd') === 'Panel-pass-2', `status=${res.status} pwd=${panelEnv.kv.store.get('pwd')}`);

res = await call(panelEnv, '/login/authenticate', post('Panel-pass-2'));
json = await res.json();
check('改密后的新口令可以直接在 /login 登录', json.success === true, JSON.stringify(json).slice(0, 140));

// 6d) 反向：/login 首访设好口令后，未带会话的 /panel 一样是 302 到 /login（不再有「白送面板外壳」的中间态）
res = await call(env, '/panel/settings');
check('/login 首访设好口令后 /panel/settings 未带会话仍是 401（面板走登录重定向）', res.status === 401, `status=${res.status}`);
res = await call(env, '/panel');
check('/login 首访设好口令后未带会话 GET /panel 重定向到 /login', res.status === 302 && (res.headers.get('location') || '').endsWith('/login'), `status=${res.status} loc=${res.headers.get('location')}`);

console.log(failures === 0 ? '\nlogin-firstrun: OK' : `\nlogin-firstrun: ${failures} 项失败`);
process.exit(failures === 0 ? 0 : 1);
