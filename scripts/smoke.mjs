/**
 * scripts/smoke.mjs
 *
 * 混淆产物的行为闸门。运行：node scripts/smoke.mjs [参考] [产物]
 *
 * 默认值：参考 = .build/worker.reference.js（esbuild+terser 之后、混淆之前）
 *         产物 = dist/worker.js（混淆之后）
 *
 * 它把两份 bundle 各自放进**独立进程**、用同一套 Cloudflare 风格桩加载，回放同一段真实会话：
 *   /login、/secrets、/favicon.ico、/panel（未配置/已登录）、/login/authenticate、
 *   /panel/settings、/panel/update-settings（JSON）、/panel/region、/panel/my-ip、/proxy-ip、/proxy-ip/get、
 *   /sub/raw/<subPath>（xray / sing-box）、/sub/normal/<subPath>（clash / sing-box / xray + 各种 query）、
 *   /sub/<错误 subPath>（应落伪装兜底）、/dns-query/<subPath>、/logout、根路径伪装、
 *   未知路径（黑名单 + 限流 + 伪装反代）、畸形编码路径，以及一次 WebSocket 升级。
 *
 * 请求清单之外还有一张行为断言表（BEHAVIOR）：它检查"这条路径真的被路由到了 / 真的写进去了"，
 * 而不只是"两份产物在这个请求上表现一致" —— 两边一起 500、一起落伪装兜底也是"一致"的，
 * 那样三核心配置生成与设置写入这两层就永远没被执行过。
 *
 * 每份 bundle 都固定了 Math.random / Date / crypto.getRandomValues，并冻结了出站网络，
 * 所以两份产物的每一对响应都必须逐字节相同。任何差异都意味着混淆改变了行为。
 *
 * 为什么要独立进程：workerd 里每个 isolate 都是干净的，而本仓库的 worker 会写
 * globalThis.settings / dict / globalConfig / httpConfig 等共享全局。两份 bundle 在同一个进程里
 * 跑，第二份会看到第一份留下的状态（还会踩到重复包装 Response/fetch 的坑），
 * 于是"行为差异"里混进大量假阳性。一进程一份 bundle 才是忠实的隔离模型。
 *
 * 参数：
 *   --bench[=N]          额外测量冷启动与热请求耗时（两份 bundle 对照）
 *   --run <bundle> <tag> 内部使用：只跑一份 bundle，把会话结果写成 JSON
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'fs';
import { spawnSync } from 'child_process';
import { pathToFileURL, fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SELF = fileURLToPath(import.meta.url);
const FLAGS = process.argv.slice(2).filter((a) => a.startsWith('--'));
const POSITIONAL = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const REFERENCE = resolve(ROOT, POSITIONAL[0] || '.build/worker.reference.js');
const ARTIFACT = resolve(ROOT, POSITIONAL[1] || 'dist/worker.js');
const TMP = join(ROOT, '.build/smoke');
const VERBOSE = !!process.env.SMOKE_VERBOSE;

const BENCH_ROUNDS = (() => {
  const flag = FLAGS.find((f) => f.startsWith('--bench'));
  if (!flag) return 0;
  const value = flag.includes('=') ? Number(flag.split('=')[1]) : 200;
  return Number.isFinite(value) && value > 0 ? value : 200;
})();

// 冻结的凭据 / 时钟。UUID 必须是合法 v4，否则 initHttp 直接抛凭据错误。
const UUID = '11111111-2222-4333-8444-555555555555';
const TR_PASS = 'trojan-secret';
const SUB_PATH = 'smoke-sub-path';
const PASSWORD = 'Smoke-pass-1';
const FIXED_NOW = 1735689600000; // 2025-01-01T00:00:00Z
const ORIGIN = 'https://panel.example.com';
/** 需要"上一步刚拿到的登录 cookie"的请求用这个哨兵，实际值在发请求时替换。 */
const COOKIE_SENTINEL = '__live_cookie__';

// 让"挂在那里"的 WebSocket 上行泵 promise 自己烂掉，而不是拖死进程。
// uncaughtException 故意不吞：真崩溃必须让闸门失败。
process.on('unhandledRejection', (reason) => {
  const message = reason && reason.message ? reason.message : String(reason);
  if (VERBOSE) console.log(`  note  忽略未处理的 rejection: ${message}`);
});

// =========================================================== 单进程桩（--run）
class FakeWebSocket {
  constructor() {
    this.readyState = 1;
    this.listeners = {};
    this.sent = [];
  }
  accept() {}
  addEventListener(type, fn) {
    (this.listeners[type] ||= []).push(fn);
  }
  removeEventListener(type, fn) {
    this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn);
  }
  close() {}
  send(payload) {
    this.sent.push(payload);
  }
}

function installStubs() {
  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = new FakeWebSocket();
      this[1] = new FakeWebSocket();
    }
  };

  // undici 拒绝 status 101，而代理处理函数会正常返回 101。
  const RealResponse = globalThis.Response;
  globalThis.Response = class extends RealResponse {
    constructor(body, init = {}) {
      if (init && init.status === 101) {
        super(null);
        Object.defineProperty(this, 'status', { value: 101, configurable: true });
        Object.defineProperty(this, 'webSocket', { value: init.webSocket, configurable: true });
      } else {
        super(body, init);
      }
    }
    static redirect(url, status) {
      return RealResponse.redirect(url, status);
    }
  };

  // 出站网络全部冻结：同一 URL 永远给同一份响应。
  globalThis.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    // ip-api 的批量端点要的是**数组**（处理函数对它做 for...of），必须先于单条分支匹配。
    if (url.includes('ip-api.com/batch')) {
      let ips = ['203.0.113.7'];
      try {
        const parsed = JSON.parse(typeof init?.body === 'string' ? init.body : '[]');
        if (Array.isArray(parsed) && parsed.length) ips = parsed;
      } catch {
        /* 用默认值 */
      }
      return new RealResponse(
        JSON.stringify(
          ips.map((ip) => ({
            status: 'success',
            query: ip,
            city: 'Testville',
            country: 'Testland',
            countryCode: 'TL',
            isp: 'Test ISP'
          }))
        ),
        { headers: { 'content-type': 'application/json' } }
      );
    }
    if (url.includes('ip-api.com')) {
      return new RealResponse(
        JSON.stringify({
          status: 'success',
          query: '203.0.113.7',
          country: 'Testland',
          countryCode: 'TL',
          city: 'Testville',
          isp: 'Test ISP'
        }),
        { headers: { 'content-type': 'application/json' } }
      );
    }
    if (url.includes('ipv4.geojs.io')) {
      return new RealResponse(JSON.stringify({ ip: '203.0.113.7' }), {
        headers: { 'content-type': 'application/json' }
      });
    }
    if (url.includes('icanhazip.com')) {
      return new RealResponse('203.0.113.7\n', { headers: { 'content-type': 'text/plain' } });
    }
    if (url.includes('cloudflare-dns.com') || url.includes('dns-query')) {
      return new RealResponse(
        JSON.stringify({
          Status: 0,
          Answer: [
            { name: 'panel.example.com', type: 1, data: '104.16.0.1' },
            { type: 28, data: '2606:4700::1111' }
          ]
        }),
        { headers: { 'content-type': 'application/dns-json' } }
      );
    }
    if (url.includes('cloudflareclient.com')) {
      return new RealResponse(
        JSON.stringify({
          id: 'smoke-device',
          config: { peers: [{ public_key: 'peer-key' }], interface: { addresses: { v4: '172.16.0.2', v6: '2606:4700:110::2' } } }
        }),
        { headers: { 'content-type': 'application/json' } }
      );
    }
    // 伪装反代 / 可达性探测 / 自定义订阅 URL：一律给一份稳定的 HTML。
    return new RealResponse('<!DOCTYPE html><html><body>smoke upstream</body></html>', {
      headers: { 'content-type': 'text/html' }
    });
  };

  // TCP 拨号在 Node 里没有对应实现：同步抛错，让代理路径快速、确定地走失败分支。
  globalThis.connect = () => {
    throw new Error('connect() is not available in the smoke harness');
  };
}

function makeKv(seed = {}) {
  const store = new Map(Object.entries(seed));
  return {
    store,
    async get(key, opts) {
      const value = store.has(key) ? store.get(key) : null;
      if (value === null) return null;
      if (opts && opts.type === 'json') return typeof value === 'string' ? JSON.parse(value) : value;
      if (opts && opts.type === 'arrayBuffer') return new TextEncoder().encode(String(value)).buffer;
      return value;
    },
    async put(key, value) {
      store.set(key, value);
    },
    async delete(key) {
      store.delete(key);
    },
    async list() {
      return { keys: [...store.keys()].map((name) => ({ name })), list_complete: true, cursor: '' };
    }
  };
}

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

/**
 * 固定 Math.random / crypto.getRandomValues / crypto.randomUUID / 整个 Date。
 *
 * Date 必须替换**构造器**而不只是 Date.now：jose 的 setIssuedAt() 走 `new Date()`，
 * 只补 Date.now 会得到 iat=真实时间、exp=冻结时间 → 令牌一签发就"已过期"，
 * 所有认证路由都会退化成 401，闸门就白跑了。
 */
function freezeEntropy(seed) {
  const next = seededRandom(seed);
  const realRandom = Math.random;
  const realCrypto = globalThis.crypto;
  const realDate = globalThis.Date;

  const FrozenDate = class extends realDate {
    constructor(...args) {
      if (args.length === 0) super(FIXED_NOW);
      else super(...args);
    }
    static now() {
      return FIXED_NOW;
    }
  };

  const stub = {
    getRandomValues(typedArray) {
      const bytes = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
      for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(next() * 256);
      return typedArray;
    },
    randomUUID() {
      const bytes = new Uint8Array(16);
      stub.getRandomValues(bytes);
      bytes[6] = (bytes[6] & 0x0f) | 0x40;
      bytes[8] = (bytes[8] & 0x3f) | 0x80;
      const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
      return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    },
    subtle: realCrypto.subtle
  };

  Math.random = () => next();
  globalThis.Date = FrozenDate;
  Object.defineProperty(globalThis, 'crypto', { value: stub, configurable: true, writable: true });

  return () => {
    Math.random = realRandom;
    globalThis.Date = realDate;
    Object.defineProperty(globalThis, 'crypto', { value: realCrypto, configurable: true, writable: true });
  };
}

/**
 * 把 cloudflare:sockets 换成本地桩模块再加载。
 * 本仓库当前产物里没有 import（已确认），保留这一步是为了将来真的用上时不会突然炸。
 */
function prepareBundle(sourcePath, name) {
  const raw = readFileSync(sourcePath, 'utf8');
  if (!raw.includes('cloudflare:sockets')) return sourcePath;

  mkdirSync(TMP, { recursive: true });
  writeFileSync(
    join(TMP, 'cf-sockets.mjs'),
    'export function connect() { throw new Error("connect() is not available in the smoke harness"); }\n'
  );
  const rewritten = raw.replace(/from\s*(["'])cloudflare:sockets\1/g, 'from"./cf-sockets.mjs"');
  if (rewritten === raw) throw new Error(`${sourcePath}: 无法改写 cloudflare:sockets import`);
  const out = join(TMP, name);
  writeFileSync(out, rewritten);
  return out;
}

const ctx = { waitUntil() {}, passThroughOnException() {} };

/**
 * 响应体归一化：抹掉"只反映构建差异、不反映行为差异"的部分。
 *
 * - 堆栈帧（`    at fn (file:///…dist/worker.js:1:12345)`）：文件名与混淆后的函数名不可能一致。
 * - V8 报错文本里内嵌的标识符名：`data is not iterable` → 混淆后 `Dz11iE is not iterable`。
 *   只替换"某个标识符 + 固定句式"这个形状，消息本身的语义（不可迭代 / 未定义 / 不是函数）
 *   原样保留；`Cannot read properties of undefined (reading 'x')` 里的属性名是真实取值，不动。
 *
 * 堆栈帧只认**带位置**的形状（`…:行:列`）。旧写法是「空白 + at + 一直吃到行尾」，它一路吃到
 * 行尾，而单行响应体（压缩后的 HTML 页、raw base64 订阅）里"行尾"就是响应结尾 —— 于是这两类
 * 响应体被整段删空，比对等于什么都没查。JSON 响应是 `JSON.stringify(data, null, 4)` 的多行
 * 形态，行尾恰好是帧的结尾，所以旧写法在它们上面才碰巧是对的。
 * （注意：本注释里刻意不写那个旧正则的字面量 —— 它包含星号加斜杠，会把块注释提前闭合。）
 */
function normalizeBody(body) {
  return body
    .replace(/\s+at\s+(?:async\s+)?[^\s(]*\([^)\n]*:\d+:\d+\)/g, ' <frame>')
    .replace(/\s+at\s+(?:async\s+)?[^\s(]+:\d+:\d+/g, ' <frame>')
    .replace(/([A-Za-z_$][\w$]*)( is not )(iterable|defined|a function|a constructor|an object)/g, '<ident>$2$3')
    .replace(/(Identifier ')[^']+(' has already been declared)/g, '$1<ident>$2')
    .replace(/(Cannot access ')[^']+(' before initialization)/g, '$1<ident>$2');
}

/** 冻结的 WARP 账号：形状合法 → 跳过 fetchWarpAccounts（那里会用到真正的随机密钥生成）。 */
const WARP_ACCOUNTS = [
  { privateKey: 'a'.repeat(44), publicKey: 'b'.repeat(44), warpIPv6: '2606:4700:110:8f1a:1:2:3:4/128', reserved: 'AAAA' },
  { privateKey: 'c'.repeat(44), publicKey: 'd'.repeat(44), warpIPv6: '2606:4700:110:8f1b:1:2:3:4/128', reserved: 'BBBB' }
];

function makeEnv() {
  return {
    UUID,
    TR_PASS,
    SUB_PATH,
    DOH_URL: 'https://cloudflare-dns.com/dns-query',
    FALLBACK: 'www.hcaptcha.com',
    homepage: 'www.hcaptcha.com',
    PUBLIC_PROXY_IP: 'proxy.example.com',
    PROXY_IP: '203.0.113.9',
    PREFIX: '',
    kv: makeKv({
      pwd: PASSWORD,
      secretKey: 'smoke-secret-key-0123456789abcdef',
      warpAccounts: JSON.stringify(WARP_ACCOUNTS)
    })
  };
}

/** 请求清单：顺序即状态演化顺序，两份 bundle 完全一致。 */
function requests() {
  return [
    ['GET /login', '/login', {}],
    ['GET /login/ (尾斜杠归一化)', '/login/', {}],
    ['GET /secrets', '/secrets', {}],
    ['GET /favicon.ico', '/favicon.ico', {}],
    ['GET /panel (已配置口令，未带 cookie)', '/panel', {}],
    ['POST /login/authenticate (错口令)', '/login/authenticate', { method: 'POST', body: 'wrong-password' }],
    ['GET /panel/settings (未认证)', '/panel/settings', {}],
    ['POST /panel/my-ip', '/panel/my-ip', { method: 'POST', body: '203.0.113.7' }],

    ['POST /login/authenticate (对口令)', '/login/authenticate', { method: 'POST', body: PASSWORD }],
    ['GET /panel (已认证)', '/panel', { headers: { cookie: COOKIE_SENTINEL } }],
    ['GET /panel/settings (已认证)', '/panel/settings', { headers: { cookie: COOKIE_SENTINEL } }],
    [
      'PUT /panel/update-settings (已认证)',
      '/panel/update-settings',
      {
        method: 'PUT',
        headers: { cookie: COOKIE_SENTINEL, 'content-type': 'application/json' },
        // 服务端是 `await request.json()`（src/kv.ts 的 updateDataset），面板本身也发 JSON
        // （src/assets/panel/script.js 的 updateSettings）。字段名必须是 kv.ts 的 fields 白名单里
        // 认得的名字：旧版本这里是 x-www-form-urlencoded + 自造字段名（vlessConfigs / protocol…），
        // 于是 request.json() 必然抛错 → 500，而"参考与产物都 500"又必然一致 → 写设置这条链路
        // （JSON 解析 → 逐字段校验 → KV 写入 → 版本键）从来没被执行过。
        // ports / VLConfigs / TRConfigs / xpConfigs 决定订阅里生成哪些节点，cleanIPs 留默认。
        body: JSON.stringify({
          remoteDNS: 'https://8.8.8.8/dns-query',
          ports: [443],
          VLConfigs: true,
          TRConfigs: true,
          xpConfigs: false
        })
      }
    ],
    ['GET /panel/region', '/panel/region', { headers: { cookie: COOKIE_SENTINEL } }],
    ['GET /proxy-ip (已认证)', '/proxy-ip', { headers: { cookie: COOKIE_SENTINEL } }],
    ['GET /proxy-ip/get (已认证)', '/proxy-ip/get', { headers: { cookie: COOKIE_SENTINEL } }],

    // 必须是 handleSubscriptions 真正 switch 得到的路径：`/sub/normal/<subPath>`（clash / sing-box /
    // xray）与 `/sub/raw/<subPath>`（xray / sing-box）。`app=` 也不能省：client 由 `?app=` 解析
    // （src/common/init.ts 的 httpConfig.client），空 client 在每个 case 里都落 default → fallback。
    // 旧版本用的是 `/sub/<subPath>?app=…`：一个 case 都匹配不上，五次请求全部落到伪装兜底，
    // 于是三核心配置生成层一次都没跑过。
    ['GET /sub/raw/<subPath>?app=xray', `/sub/raw/${SUB_PATH}?app=xray`, {}],
    ['GET /sub/raw/<subPath>?app=sing-box', `/sub/raw/${SUB_PATH}?app=sing-box`, {}],
    ['GET /sub/normal/<subPath>?app=clash', `/sub/normal/${SUB_PATH}?app=clash`, {}],
    ['GET /sub/normal/<subPath>?app=sing-box', `/sub/normal/${SUB_PATH}?app=sing-box`, {}],
    // rm/qj/wk 覆盖出站模式与地区，走的是同一 case 的另一条分支，故意保留。
    ['GET /sub/normal/<subPath>?app=xray&rm=no&qj=only&wk=NL', `/sub/normal/${SUB_PATH}?app=xray&rm=no&qj=only&wk=NL`, {}],
    // 负例（URL 故意保持"能匹配形状、但 subPath 不对"）：必须落到伪装兜底，不能被任何 case 误接。
    ['GET /sub/<uuid> (错误 subPath)', `/sub/${UUID}`, {}],
    ['GET /dns-query/<subPath>', `/dns-query/${SUB_PATH}?name=example.com&type=A`, {}],

    ['GET /logout', '/logout', {}],
    ['GET / (根路径伪装反代)', '/', {}],
    ['GET /unknown-path (未认证探测)', '/definitely-not-a-real-path', {}],
    ['GET /%zz (畸形编码)', '/%zz', {}],
    ['WS upgrade /', '/', { headers: { Upgrade: 'websocket', 'sec-websocket-protocol': 'earlyData' } }]
  ];
}

async function runSession(modulePath, tag) {
  const restore = freezeEntropy(12345);
  installStubs();

  // worker 自己的 console 噪音（鉴权日志、伪装页告警…）会淹没闸门结论：
  // 会话在独立子进程里跑，这里直接吞掉，SMOKE_VERBOSE=1 时才转发出来。
  // 注意必须用**绑定过的原始函数**转发，直接取 console.log 会自我递归爆栈。
  const levels = ['log', 'info', 'warn', 'error', 'debug', 'trace'];
  const originalLevels = {};
  for (const level of levels) {
    originalLevels[level] = typeof console[level] === 'function' ? console[level].bind(console) : undefined;
    console[level] = (...args) => {
      if (VERBOSE && originalLevels[level]) originalLevels[level]('[worker]', ...args);
    };
  }
  const restoreConsole = () => {
    for (const level of levels) {
      if (originalLevels[level]) console[level] = originalLevels[level];
    }
  };

  const mod = await import(pathToFileURL(modulePath).href);
  const handler = mod.default;
  if (!handler || typeof handler.fetch !== 'function') {
    restoreConsole();
    restore();
    throw new Error(`${modulePath} 的 default 导出没有 fetch()`);
  }

  const env = makeEnv();
  const results = [];
  let cookie = '';

  const call = async (name, path, init = {}) => {
    let record;
    try {
      const headers = { Host: 'panel.example.com', ...(init.headers || {}) };
      if (headers.cookie === COOKIE_SENTINEL) headers.cookie = cookie;
      const request = new Request(ORIGIN + path, { ...init, headers });
      // 单条请求加一个上限：WS 分支可能因为拨号而挂住，挂住本身也是一种可比较的行为。
      let timer;
      const response = await Promise.race([
        handler.fetch(request, env, ctx),
        new Promise((r) => {
          timer = setTimeout(() => r('__timeout__'), 5000);
        })
      ]);
      clearTimeout(timer);
      if (response === '__timeout__') {
        record = { timeout: true };
      } else {
        let body = null;
        try {
          body = await response.clone().text();
        } catch {
          body = '<unreadable>';
        }
        const setCookie = response.headers.get('set-cookie');
        if (setCookie && setCookie.includes('jwtToken=') && !/Max-Age=0/.test(setCookie)) {
          const match = setCookie.match(/jwtToken=([^;]+)/);
          cookie = `jwtToken=${match ? match[1] : ''}`;
        }
        record = {
          status: response.status,
          type: response.headers.get('content-type'),
          location: response.headers.get('location'),
          webSocket: !!response.webSocket,
          cookie: setCookie ? (/jwtToken=[^;]{10,}/.test(setCookie) ? '<jwt>' : setCookie) : null,
          // 响应体里会出现两类"只跟构建有关、与行为无关"的噪音，先抹掉再比较：
          //  1. 堆栈帧带着各自产物的文件名与混淆后的函数名；
          //  2. V8 的报错文本会把**标识符名字**写进去（`data is not iterable`），
          //     混淆后变成 `Dz11iE is not iterable` —— 语义相同、名字不同。
          body: body === null ? null : normalizeBody(body)
        };
      }
    } catch (error) {
      record = { threw: String(error && error.message ? error.message : error) };
      if (VERBOSE) console.log(`  note  ${name} 抛错:\n${error && error.stack ? error.stack : error}`);
    }
    results.push([name, record]);
  };

  for (const [name, path, init] of requests()) {
    await call(name, path, init);
  }

  let bench = null;
  if (BENCH_ROUNDS > 0) {
    const coldStart = performance.now();
    await handler.fetch(new Request(`${ORIGIN}/login`, { headers: { Host: 'panel.example.com' } }), env, ctx);
    const cold = performance.now() - coldStart;
    const warmStart = performance.now();
    for (let i = 0; i < BENCH_ROUNDS; i++) {
      await handler.fetch(new Request(`${ORIGIN}/login`, { headers: { Host: 'panel.example.com' } }), env, ctx);
    }
    bench = {
      cold,
      warm: (performance.now() - warmStart) / BENCH_ROUNDS,
      bytes: readFileSync(modulePath, 'utf8').length
    };
  }

  restoreConsole();
  restore();
  return { results, bench };
}

// =============================================================== 驱动模式
/**
 * 没有参考产物时的内容断言（审计下载来的 _worker.js 时用）。
 * 这些标题来自 src/assets 下各页面的 index.html，能证明密文在运行时确实解回了正确的页面。
 */
const EXPECTED = {
  'GET /login': ['<!DOCTYPE html>', '<title>Login</title>'],
  'GET /secrets': ['<!DOCTYPE html>', '<title>Secrets</title>'],
  'GET /panel (已认证)': ['<!DOCTYPE html>', '<title>BPB Panel</title>']
};

function assertExpected(results) {
  let failures = 0;
  for (const [name, needles] of Object.entries(EXPECTED)) {
    if (!needles) continue;
    const entry = results.find(([n]) => n === name);
    if (!entry) {
      console.log(`  FAIL  会话里没有 ${name}`);
      failures++;
      continue;
    }
    const body = typeof entry[1].body === 'string' ? entry[1].body : '';
    const missing = needles.filter((needle) => !body.includes(needle));
    if (missing.length === 0) {
      console.log(`  PASS  ${name} 渲染出预期内容`);
    } else {
      console.log(`  FAIL  ${name} 缺少预期内容 ${JSON.stringify(missing)}（status=${entry[1].status}）`);
      failures++;
    }
  }
  return failures;
}

// ------------------------------------------------- 行为断言（每案：这条路径真的跑到了吗）
/** 冻结 fetch 对"未知 URL"的固定响应 —— 伪装反代把上游响应原样回给请求方，就是这个形状。 */
const UPSTREAM_STUB_BODY = '<!DOCTYPE html><html><body>smoke upstream</body></html>';

const clip = (text, max = 160) => {
  const value = typeof text === 'string' ? text : String(text);
  return value.length > max ? `${value.slice(0, max)}…` : value;
};

/**
 * 「这条路径真的被路由到了」的判据：响应不能是伪装兜底页。
 *
 * 兜底 = 把请求原样转给伪装域名并返回上游响应，所以在桩环境里它的特征就是 `text/html`
 * 与上游桩那段固定 HTML。判据只认这两点，**不认具体订阅字节**：Clash 字段名、base64 换行
 * 之类的格式改动不会让这里假失败（逐字节一致性另有参考/产物对照负责）。
 */
function notFallback(record) {
  if (record.threw) return `请求抛错：${record.threw}`;
  if (record.timeout) return '请求 5 秒超时';
  if (record.status !== 200) return `期望 200，实际 ${record.status}（${clip(record.body)}）`;
  const type = String(record.type || '');
  if (type.includes('text/html')) return `响应是 HTML（content-type=${type}）—— 落到了伪装兜底`;
  const body = typeof record.body === 'string' ? record.body : '';
  if (body === UPSTREAM_STUB_BODY) return '响应体等于上游桩正文 —— 落到了伪装兜底';
  if (body.length === 0) return '响应体为空';
  return null;
}

/** raw 订阅：单行 base64（`getURLConfigs` 对节点文本做 base64EncodeUtf8）。 */
function expectRawSubscription(record) {
  const reason = notFallback(record);
  if (reason) return reason;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(record.body)) return `raw 订阅不是单行 base64：${clip(record.body)}`;
  return null;
}

/** 三核心 JSON 订阅：能落到兜底之外的正文，再去认一个核心特有的顶层键。 */
function expectCoreConfig(keys) {
  return (record) => {
    const reason = notFallback(record);
    if (reason) return reason;
    const missing = keys.filter((key) => !record.body.includes(`"${key}"`));
    return missing.length === 0 ? null : `配置里缺少顶层键 ${missing.join(', ')}：${clip(record.body)}`;
  };
}

/** 设置写入：200 + success:true，且响应回显了刚写进去的值（KV 写入 + 版本键真的走完了）。 */
function expectSettingsWritten(record) {
  if (record.threw) return `请求抛错：${record.threw}`;
  if (record.timeout) return '请求 5 秒超时';
  if (record.status !== 200) return `期望 200，实际 ${record.status}（${clip(record.body)}）`;
  let parsed;
  try {
    parsed = JSON.parse(record.body);
  } catch {
    return `响应不是 JSON：${clip(record.body)}`;
  }
  if (parsed.success !== true) return `success !== true（message=${clip(parsed.message)}）`;
  const written = parsed.body;
  if (!written || written.remoteDNS !== 'https://8.8.8.8/dns-query') {
    return `响应体没有回显写入后的设置（body.remoteDNS）：${clip(JSON.stringify(written))}`;
  }
  if (!Array.isArray(written.ports) || written.ports[0] !== 443) {
    return `响应体没有回显写入后的端口（body.ports）：${clip(JSON.stringify(written.ports))}`;
  }
  return null;
}

/** 负例：错误 subPath 必须落到伪装兜底（而不是被某个 case 误接成订阅）。 */
function expectFallback(record) {
  if (record.threw) return `请求抛错：${record.threw}`;
  if (record.timeout) return '请求 5 秒超时';
  const type = String(record.type || '');
  if (!type.includes('text/html')) return `期望伪装兜底（text/html），实际 content-type=${type}`;
  if (record.body !== UPSTREAM_STUB_BODY) return `期望上游桩正文，实际 ${clip(record.body)}`;
  return null;
}

/**
 * 行为断言表。键必须与 requests() 里的名字**逐字一致**（对不上会以"会话里没有 X"失败，
 * 而不是静默跳过）。
 */
const BEHAVIOR = [
  ['PUT /panel/update-settings (已认证)', expectSettingsWritten],
  ['GET /sub/raw/<subPath>?app=xray', expectRawSubscription],
  ['GET /sub/raw/<subPath>?app=sing-box', expectRawSubscription],
  ['GET /sub/normal/<subPath>?app=clash', expectCoreConfig(['proxies'])],
  ['GET /sub/normal/<subPath>?app=sing-box', expectCoreConfig(['outbounds'])],
  ['GET /sub/normal/<subPath>?app=xray&rm=no&qj=only&wk=NL', expectCoreConfig(['outbounds'])],
  ['GET /sub/<uuid> (错误 subPath)', expectFallback]
];

function assertBehavior(results) {
  let failures = 0;
  for (const [name, check] of BEHAVIOR) {
    const entry = results.find(([n]) => n === name);
    if (!entry) {
      console.log(`  FAIL  会话里没有 ${name}（requests() 与 BEHAVIOR 的名字必须逐字一致）`);
      failures++;
      continue;
    }
    const reason = check(entry[1]);
    if (reason) {
      console.log(`  FAIL  ${name} — ${reason}`);
      failures++;
    } else {
      console.log(`  PASS  ${name}（路径确实被路由到，未落伪装兜底）`);
    }
  }
  return failures;
}

/** 用独立进程跑一份 bundle，避免共享 globalThis 造成假差异。 */
function runInChild(bundlePath, tag) {
  mkdirSync(TMP, { recursive: true });
  const outPath = join(TMP, `${tag}.json`);
  if (existsSync(outPath)) rmSync(outPath);
  const args = [SELF, '--run', bundlePath, tag];
  if (BENCH_ROUNDS > 0) args.push(`--bench=${BENCH_ROUNDS}`);
  const result = spawnSync(process.execPath, args, { stdio: 'inherit', cwd: ROOT });
  if (result.error) throw result.error;
  if (result.status !== 0 || !existsSync(outPath)) {
    throw new Error(`${tag} 会话进程失败（exit=${result.status}）`);
  }
  return JSON.parse(readFileSync(outPath, 'utf8'));
}

function toModulePath(bundlePath, tag) {
  return prepareBundle(bundlePath, `${tag}.mjs`);
}

async function main() {
  // 内部模式：只跑一份 bundle，把结果落成 JSON 后退出。
  if (FLAGS.includes('--run')) {
    const bundlePath = POSITIONAL[0];
    const tag = POSITIONAL[1];
    const session = await runSession(toModulePath(resolve(ROOT, bundlePath), tag), tag);
    mkdirSync(TMP, { recursive: true });
    writeFileSync(join(TMP, `${tag}.json`), JSON.stringify(session));
    return;
  }

  if (!existsSync(ARTIFACT)) {
    console.log(`smoke: 找不到产物 ${ARTIFACT}`);
    process.exit(1);
  }

  console.log(`smoke: 产物 ${ARTIFACT}`);
  const artifactRun = runInChild(ARTIFACT, 'artifact');
  let failures = 0;

  if (!existsSync(REFERENCE)) {
    console.log('smoke: 没有参考文件 —— 退化为内容断言模式');
    failures += assertExpected(artifactRun.results);
    failures += assertBehavior(artifactRun.results);
  } else {
    console.log(`smoke: 参考 ${REFERENCE}`);
    const referenceRun = runInChild(REFERENCE, 'reference');

    const refMap = new Map(referenceRun.results);
    let compared = 0;
    const diffs = [];
    for (const [name, record] of artifactRun.results) {
      compared++;
      if (JSON.stringify(refMap.get(name)) !== JSON.stringify(record)) {
        diffs.push({ name, expected: refMap.get(name), actual: record });
      }
    }

    if (diffs.length === 0) {
      console.log(`  PASS  ${compared} 条请求与未混淆参考逐字节一致`);
    } else {
      failures += diffs.length;
      console.log(`  FAIL  ${diffs.length}/${compared} 条请求与参考不一致`);
      for (const diff of diffs.slice(0, 6)) {
        const show = (r) => {
          const text = JSON.stringify(r);
          return text.length > 400 ? text.slice(0, 400) + '…' : text;
        };
        console.log(`    - ${diff.name}`);
        console.log(`        参考: ${show(diff.expected)}`);
        console.log(`        产物: ${show(diff.actual)}`);
      }
    }
    failures += assertExpected(artifactRun.results);
    failures += assertBehavior(artifactRun.results);

    if (referenceRun.bench && artifactRun.bench) {
      const fmt = (n) => `${n.toFixed(2)} ms`;
      console.log('\n  bench（GET /login，独立进程内对照）');
      console.log(
        `    产物体积  参考 ${referenceRun.bench.bytes} B -> 混淆 ${artifactRun.bench.bytes} B` +
          `（+${((artifactRun.bench.bytes / referenceRun.bench.bytes - 1) * 100).toFixed(1)}%）`
      );
      console.log(`    冷启动    参考 ${fmt(referenceRun.bench.cold)} -> 混淆 ${fmt(artifactRun.bench.cold)}`);
      console.log(`    热请求    参考 ${fmt(referenceRun.bench.warm)} -> 混淆 ${fmt(artifactRun.bench.warm)}（${BENCH_ROUNDS} 次均值）`);
    }
  }

  console.log(failures === 0 ? 'smoke: OK' : `smoke: ${failures} 项失败`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error('smoke 崩溃:', error);
  process.exit(1);
});
