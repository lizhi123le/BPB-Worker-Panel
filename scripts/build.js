import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname as pathDirname } from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'node:child_process';
import pkg from '../package.json' with { type: 'json' };
import { gzipSync } from 'zlib';
import { ensureDeps } from './ensure-deps.mjs';
import { formatSizeSpec, loadParams } from './build-params.mjs';

// 构建参数：CLI > 环境变量 > harden.config.json > 默认值（见 scripts/build-params.mjs）。
// 例：node scripts/build.js --target-zip=320k --target-bytes=70%
const BUILD_PARAMS = loadParams(process.argv.slice(2));

// 构建期依赖先自检/自补，再动态 import。
// 静态 import 会在"包根本没装"时于模块链接阶段就抛 ERR_MODULE_NOT_FOUND，那时这段自检
// 根本执行不到 —— 正是 `npm install --production` 漏装 devDependencies 时的现场。
await ensureDeps();
const { build } = await import('esbuild');
const { globSync } = await import('glob');
const { minify: jsMinify } = await import('terser');
const { minify: htmlMinify } = await import('html-minifier');
const { default: JSZip } = await import('jszip');

const env = process.env.NODE_ENV || 'obfuscate';
const mangleMode = env === 'mangle';

const __filename = fileURLToPath(import.meta.url);
const __dirname = pathDirname(__filename);

const ASSET_PATH = join(__dirname, '../src/assets');
const DIST_PATH = join(__dirname, '../dist/');
const WORKER_PATH = join(DIST_PATH, 'worker.js');
const ZIP_PATH = join(DIST_PATH, 'worker.zip');
// 构建中间产物（混淆前基准、构建报告、smoke 会话快照）刻意放在 dist/ **之外**：
// dist/ 是会被整体部署/上传的目录，把未混淆的 worker.reference.js 留在里面等于把
// 明文包一起发出去。.build/ 不被 .gitignore 的白名单收录，也不会进任何部署路径。
const BUILD_DIR = join(__dirname, '../.build/');
const REFERENCE_PATH = join(BUILD_DIR, 'worker.reference.js');

const green = '\x1b[32m';
const red = '\x1b[31m';
const reset = '\x1b[0m';

const success = `${green}✔${reset}`;
const failure = `${red}✗${reset}`;

const version = pkg.version;

async function processHtmlPages() {
    const indexFiles = globSync('**/index.html', { cwd: ASSET_PATH });
    const result = {};

    for (const relativeIndexPath of indexFiles) {
        const dir = pathDirname(relativeIndexPath);
        const base = (file) => join(ASSET_PATH, dir, file);

        const indexHtml = readFileSync(base('index.html'), 'utf8');
        let finalHtml = indexHtml.replaceAll('__VERSION__', version);

        if (dir !== 'error') {
            const styleCode = readFileSync(base('style.css'), 'utf8');
            const scriptCode = readFileSync(base('script.js'), 'utf8');
            const finalScriptCode = await jsMinify(scriptCode);
            finalHtml = finalHtml
                .replaceAll('__STYLE__', `<style>${styleCode}</style>`)
                .replaceAll('__SCRIPT__', finalScriptCode.code);
        }

        const minifiedHtml = htmlMinify(finalHtml, {
            collapseWhitespace: true,
            removeAttributeQuotes: true,
            minifyCSS: true
        });

        const compressed = gzipSync(minifiedHtml);
        const htmlBase64 = compressed.toString('base64');
        result[dir] = JSON.stringify(htmlBase64);
    }

    console.log(`${success} Assets bundled successfuly!`);
    return result;
}

/**
 * 生成模拟 CF Worker 模式的垃圾代码，增强静态分析难度
 * - 变量名模仿真实代码风格（_a, _b, ... + 随机后缀）
 * - 包含条件/循环/字符串操作/try-catch，与真实逻辑难以区分
 */
function generateJunkCode() {
    const minStmts = 80, maxStmts = 400;
    const stmtCount = Math.floor(Math.random() * (maxStmts - minStmts + 1)) + minStmts;

    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const randName = (len = 6) => {
        let r = '';
        for (let i = 0; i < len; i++) r += chars[Math.floor(Math.random() * chars.length)];
        return r;
    };

    // 预生成一组变量名，模拟真实代码的声明
    const varPool = Array.from({ length: Math.floor(stmtCount * 0.3) }, () => `_${randName(4)}`);
    const ops = ['+', '-', '*', '/', '%'];
    const templates = [
        // 字符串拼接 + 条件判断
        () => {
            const v = varPool[Math.floor(Math.random() * varPool.length)];
            const s = randName(8);
            return `if(${v}>${Math.floor(Math.random()*200)}){let _t="${s}"+(${v}+${Math.floor(Math.random()*50)}).toString();${v}=parseInt(_t.slice(0,3))||${Math.floor(Math.random()*100)};}`;
        },
        // try-catch 模拟网络操作
        () => {
            const v = varPool[Math.floor(Math.random() * varPool.length)];
            return `try{${v}=(${v}??0)+${Math.floor(Math.random()*50)};if(${v}>${Math.floor(Math.random()*500+100)})${v}=${Math.floor(Math.random()*100)};}catch(_e){${v}=${Math.floor(Math.random()*100)};}`;
        },
        // 循环 + 数组操作
        () => {
            const v = varPool[Math.floor(Math.random() * varPool.length)];
            const arr = `_${randName(4)}`;
            const len = Math.floor(Math.random() * 20 + 3);
            return `let ${arr}=[];for(let _i=0;_i<${len};_i++){${arr}.push((${v}??0)+_i*${Math.floor(Math.random()*10+1)});}${v}=${arr}.reduce((_a,_b)=>_a+_b,0);`;
        },
        // 对象键值对模拟配置处理
        () => {
            const v = varPool[Math.floor(Math.random() * varPool.length)];
            const obj = `_${randName(3)}`;
            return `let ${obj}={${randName(4)}:${Math.floor(Math.random()*100)},${randName(4)}:"${randName(3)}",${randName(4)}:!!(${v}??0)};${v}=Object.keys(${obj}).length;`;
        },
        // 三元表达式 + 数学运算
        () => {
            const a = varPool[Math.floor(Math.random() * varPool.length)];
            const b = varPool[Math.floor(Math.random() * varPool.length)];
            const op = ops[Math.floor(Math.random() * ops.length)];
            return `${a}=(${b}>${Math.floor(Math.random()*100)})?(${a}${op}${b}):(${b}${op}${Math.floor(Math.random()*50+1)});`;
        },
        // switch-case 模拟路由分发
        () => {
            const v = varPool[Math.floor(Math.random() * varPool.length)];
            const cases = Array.from({length: 4}, () => Math.floor(Math.random()*10)).join(',');
            return `switch(${v}%${Math.floor(Math.random()*8+3)}){${['','','',''].map((_,i)=>`case ${i}:${v}=${Math.floor(Math.random()*500)};break;`).join('')}default:${v}=${Math.floor(Math.random()*999)};}`;
        },
        // URL/路径模拟
        () => {
            const v = varPool[Math.floor(Math.random() * varPool.length)];
            const path = `/${randName(4)}/${randName(5)}`;
            return `${v}=(${v}+"").indexOf("${path}")>=0?${v}:${v}+"${path}";`;
        },
    ];

    const lines = [];
    // 变量声明
    for (const v of varPool) {
        lines.push(`let ${v}=${Math.floor(Math.random() * 9999)};`);
    }
    // 垃圾语句
    for (let i = 0; i < stmtCount; i++) {
        const tpl = templates[Math.floor(Math.random() * templates.length)];
        lines.push(tpl());
    }

    return lines.join('\n') + '\n';
}

/** esbuild plugin: shim 'jszip' import to use globalThis.__jszip__ at runtime */
const jszipShimPlugin = {
    name: 'jszip-shim',
    setup(build) {
        build.onResolve({ filter: /^jszip$/ }, args => {
            if (args.kind === 'require') return;
            return { path: args.path, namespace: 'jszip-shim' };
        });
        build.onLoad({ filter: /.*/, namespace: 'jszip-shim' }, () => ({
            contents: 'const __jszip__ = globalThis.__jszip__; export { __jszip__ as default }',
            loader: 'js'
        }));
    }
};

/** Build JSZip as a standalone IIFE that sets globalThis.__jszip__ */
async function buildJszipRuntime() {
    const JSDIR = join(__dirname, '..', 'node_modules', 'jszip', 'dist');
    const entry = join(JSDIR, 'jszip.min.js');
    if (!existsSync(entry)) throw new Error('jszip/dist/jszip.min.js not found — run npm install');

    const result = await build({
        entryPoints: [{ in: entry, out: 'jszip' }],
        bundle: true,
        format: 'iife',
        globalName: '__jszip__',
        write: false,
        platform: 'browser',
        target: 'esnext',
        legalComments: 'none'
    });

    let text = result.outputFiles[0].text.replace(/\/\/ .*/g, '');
    // In CF Workers ESM context (export default in worker code),
    // `var __jszip__` at module top-level is module-scoped and does
    // NOT set globalThis.__jszip__. Replace with an explicit global
    // assignment so the shim (const x = globalThis.__jszip__) works.
    text = text.replace('var __jszip__ =', 'globalThis.__jszip__ =');
    return text;
}

async function buildWorker() {

    const htmls = await processHtmlPages();
    const faviconBuffer = readFileSync('./src/assets/favicon.ico');
    const faviconBase64 = faviconBuffer.toString('base64');

    const code = await build({
        entryPoints: [join(__dirname, '../src/worker.ts')],
        bundle: true,
        format: 'esm',
        write: false,
        external: ['cloudflare:sockets'],
        plugins: [jszipShimPlugin],
        platform: 'browser',
        target: 'esnext',
        legalComments: 'none',
        loader: { '.ts': 'ts' },
        define: {
            __PANEL_HTML_CONTENT__: htmls['panel'] ?? '""',
            __LOGIN_HTML_CONTENT__: htmls['login'] ?? '""',
            __ERROR_HTML_CONTENT__: htmls['error'] ?? '""',
            __SECRETS_HTML_CONTENT__: htmls['secrets'] ?? '""',
            __PROXY_IP_HTML_CONTENT__: htmls['proxy-ip'] ?? '""',
            __ICON__: JSON.stringify(faviconBase64),
            __VERSION__: JSON.stringify(version)
        }
    });

    console.log(`${success} Worker built successfuly!`);

    // mangle 默认开启（传统 mangle 模式用）；交给 js-confuser 混淆时**必须关掉**：
    // terser 会把形参和 catch 参数复用成同一个短名（例如 `async function Kt(e){...catch(e){}}`），
    // 而 js-confuser 2.0 的 renameVariables 是按名字解析绑定的，遇到这种同名不同绑定
    // 就会把闭包里的引用改到错误的绑定上 —— 实测表现为 `env.kv` 变成别的对象的属性，
    // KV 读取全部 500。让 js-confuser 面对未压缩的标识符，重命名由它自己统一完成。
    const minifyCode = async (code, { mangle = true } = {}) => {
        const minified = await jsMinify(code, {
            module: true,
            mangle,
            output: {
                comments: false
            },
            compress: {
                dead_code: false,
                unused: false
            }
        });

        console.log(`${success} Worker minified successfuly!${mangle ? '' : '（保留标识符，交给 js-confuser 改名）'}`);
        return minified;
    }

    const jszipRuntime = await buildJszipRuntime();
    let finalCode;

    if (mangleMode) {
        const junkCode = generateJunkCode();
        const minifiedCode = await minifyCode(junkCode + code.outputFiles[0].text);
        finalCode = minifiedCode.code;
    } else {
        const minifiedCode = await minifyCode(code.outputFiles[0].text, { mangle: false });
        finalCode = minifiedCode.code;
    }

    // 混淆前的基准产物：esbuild 打包 + terser 压缩 + JSZip 运行时。
    // 它同时是 obfuscate 的输入、verify/smoke 的比对参考，所以先落盘再进入混淆阶段。
    const reference = `${jszipRuntime}${finalCode}`.replace(/\/\/ .*/g, '').replace(/\n+/g, '');
    // dist/ 与 .build/ 都不在版本控制里（.gitignore 只放行源码），全新检出时并不存在。
    // 这里必须把 dist/ 一起建出来：mangle 模式直接写 WORKER_PATH，混淆模式由
    // scripts/obfuscate.mjs 写 dist/worker.js、最后还要写 dist/worker.zip ——
    // 少了这个 mkdir，本地有 dist/ 时看不出来，CI 上必然 ENOENT。
    mkdirSync(BUILD_DIR, { recursive: true });
    mkdirSync(DIST_PATH, { recursive: true });
    writeFileSync(REFERENCE_PATH, reference, 'utf8');
    console.log(`${success} Pre-obfuscation reference written: ${REFERENCE_PATH} (${reference.length} bytes)`);

    if (mangleMode) {
        // 传统 mangle 模式（NODE_ENV=mangle）：垃圾代码 + terser，不做字符串密文化。
        writeFileSync(WORKER_PATH, reference, 'utf8');
    } else {
        await obfuscateWithGates();
    }

    const worker = readFileSync(WORKER_PATH, 'utf8');
    if (BUILD_PARAMS.params.oneLine && worker.trimEnd().includes('\n')) {
        throw new Error(
            `产物不是单行（内部换行数 ${worker.trimEnd().split('\n').length - 1}）。` +
                '混淆器 compact 输出应为一行，追加的解码器由 scripts/obfuscate.mjs 压成单行；' +
                '请检查 build-params / --one-line 设置。'
        );
    }
    const zip = new JSZip();
    zip.file('_worker.js', worker);
    // 必须 await：之前是 fire-and-forget，进程有可能先退出，zip 永远写不出来。
    const nodebuffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
    writeFileSync(ZIP_PATH, nodebuffer);

    // 体积预算兜底：obfuscate.mjs 已按参数搜索；这里只对绝对字节目标再确认一次，
    // 百分比目标依赖「首次产物」基准，由 obfuscate 内部保证。
    const rawTarget =
        BUILD_PARAMS.params.targetBytes && BUILD_PARAMS.params.targetBytes.kind === 'bytes'
            ? BUILD_PARAMS.params.targetBytes.value
            : 0;
    const zipTarget =
        BUILD_PARAMS.params.targetZipBytes && BUILD_PARAMS.params.targetZipBytes.kind === 'bytes'
            ? BUILD_PARAMS.params.targetZipBytes.value
            : 0;
    if (rawTarget && worker.length > rawTarget) {
        throw new Error(`dist/worker.js ${worker.length} B 超过 --target-bytes=${rawTarget}`);
    }
    if (zipTarget && nodebuffer.length > zipTarget) {
        throw new Error(`dist/worker.zip ${nodebuffer.length} B 超过 --target-zip=${zipTarget}`);
    }

    console.log(
        `${success} Done! worker.js ${worker.length} bytes, worker.zip ${nodebuffer.length} bytes` +
            `${
                BUILD_PARAMS.params.targetBytes
                    ? `（目标 raw ≤${formatSizeSpec(BUILD_PARAMS.params.targetBytes)}）`
                    : ''
            }` +
            `${
                BUILD_PARAMS.params.targetZipBytes
                    ? `（目标 zip ≤${formatSizeSpec(BUILD_PARAMS.params.targetZipBytes)}）`
                    : ''
            }`
    );
}

/**
 * 混淆 + 闸门组 + 重试。
 *
 * 每次尝试都用一条**全新的随机 ChaCha20 密钥**，所以重试出来的产物互不相同；
 * 静态闸门（verify）与行为闸门（smoke）随重试重跑。
 * tools/ 行为闸门组只依赖源码与混淆前产物，与本次密钥和混淆强度无关，所以只在
 * 「静态+行为闸门都过了」的这一份产物上跑一次，失败直接终止。
 * 闸门跑在独立进程里（stdio inherit），这样单个闸门崩溃不会污染构建进程。
 */
async function obfuscateWithGates() {
    const attempts = Math.max(1, Number(process.env.HARDEN_ATTEMPTS || 3));
    const smokeEvery = process.env.SMOKE_EVERY !== '0';
    // tools/ 行为闸门组：钉的是源码行为本身（多数只读混淆前产物，proxy-pool-cache 直接读源码）。
    //   · 面板布局           —— Subscriptions 表格/行铺满、按钮列钉右（CSS 契约，防回退）
    //   · WS 首包判定        —— VLESS/Trojan 识别与非法首包收口
    //   · 首访设置口令       —— /login 首访设口令、登录、改密吊销旧会话
    //   · /proxy-ip 取数规则 —— A+AAAA 双栈、合计 ≤100 全列、超出按 1:1 且不足从多的那类补齐
    //   · 反代池缓存         —— isolate 内 Map / Cache API 跨 isolate / 单飞去重 / 各种降级安全
    //   · 反代池抽取与退避   —— 全量入池（含 A+AAAA，不砍 IPv6）/ 洗牌抽 8 / 探测不通按指数退避隐退 /
    //                           到期回池 / 50 条大池不截断 / @REGION 地区池互不串味（约 40s，其中 31s
    //                           是等 30s 退避到期以验证「回池」）
    // TOOLS_GATE=0 跳过整组；POOL_GATE=0 只跳过最慢的反代池抽取那项。
    const toolsGate = process.env.TOOLS_GATE !== '0';
    const poolGate = toolsGate && process.env.POOL_GATE !== '0';
    const toolsGates = [
        { script: 'tools/panel-layout.test.mjs', label: '面板 Subscriptions 布局：表格/行铺满容器、操作按钮列钉在右边缘（CSS 契约）' },
        { script: 'tools/ws-firstpacket.test.mjs', label: 'WS 首包判定（VLESS/Trojan 识别与非法首包收口）' },
        { script: 'tools/login-firstrun.test.mjs', label: '首访设置口令 / 登录 / 改密吊销旧会话' },
        { script: 'tools/proxy-ip-limit.test.mjs', label: '/proxy-ip 取数规则（A+AAAA 双栈 / 上限 100 / 超出 1:1 / 不足从多的那类补齐）' },
        { script: 'tools/proxy-pool-cache.test.mjs', label: '反代池缓存：isolate 内 Map / Cache API 跨 isolate 复用 / 同键并发单飞 / 降级安全 / debug 分层日志' },
        { script: 'tools/proxy-pool-draw.test.mjs', label: '反代池：全量入池（含 A+AAAA，不砍 IPv6）/ 洗牌抽 8 / 退避隐退与回池 / 地区隔离（约 40s）' }
    ].filter(({ script }) => (script.endsWith('proxy-pool-draw.test.mjs') ? poolGate : toolsGate));

    const run = (script, args = []) => {
        const result = spawnSync(process.execPath, [join(__dirname, '..', script), ...args], {
            stdio: 'inherit',
            cwd: join(__dirname, '..')
        });
        if (result.error) throw result.error;
        return result.status === 0;
    };

    // 把体积/单行参数原样传给 obfuscate 子进程（百分比目标也保留，由子进程解析）。
    const forwardArgs = [];
    const params = BUILD_PARAMS.params;
    if (params.targetBytes) forwardArgs.push(`--target-bytes=${formatSizeSpec(params.targetBytes)}`);
    if (params.targetZipBytes) forwardArgs.push(`--target-zip=${formatSizeSpec(params.targetZipBytes)}`);
    forwardArgs.push(
        `--max-runs=${params.maxRuns}`,
        `--one-line=${params.oneLine}`,
        `--min-string=${params.minString}`,
        `--max-string=${params.maxString}`
    );
    if (BUILD_PARAMS.flags.has('config')) forwardArgs.push(`--config=${params.configPath}`);
    console.log(
        `${success} 体积参数：raw=${formatSizeSpec(params.targetBytes) || '不限制'}，` +
            `zip=${formatSizeSpec(params.targetZipBytes) || '不限制'}，` +
            `maxRuns=${params.maxRuns}，oneLine=${params.oneLine}` +
            `${BUILD_PARAMS.flags.has('config') ? `，config=${params.configPath}` : ''}`
    );

    // 先验证密码本身（ChaCha20 已知答案向量 + 编解码往返），再花时间跑整包混淆。
    if (!run('tools/cipher.test.mjs')) {
        throw new Error('ChaCha20 密文自检未通过 —— 先修 tools/cipher.mjs，不要继续构建');
    }

    for (let attempt = 1; attempt <= attempts; attempt++) {
        console.log(`\n${success} 混淆尝试 ${attempt}/${attempts}`);
        if (!run('scripts/obfuscate.mjs', ['.build/worker.reference.js', 'dist/worker.js', ...forwardArgs])) {
            console.error(`${failure} obfuscate 失败，重试`);
            continue;
        }
        if (!run('scripts/verify.mjs')) {
            console.error(`${failure} verify 未通过，换一条密钥重试`);
            continue;
        }
        if (smokeEvery && !run('scripts/smoke.mjs')) {
            console.error(`${failure} smoke 未通过，换一条密钥重试`);
            continue;
        }
        // 最后一组：tools 行为闸门（只依赖源码与混淆前产物，故只在这一份已过静态+行为闸门的
        // 产物上跑一次，不随重试重复）。任何一项失败都直接终止：换密钥不会让源码行为变对。
        for (const { script, label } of toolsGates) {
            console.log(`\n${success} tools 行为闸门（本次混淆尝试 ${attempt}/${attempts} 的产物）：${script}`);
            console.log(`      ${label}`);
            if (!run(script)) {
                throw new Error(
                    `tools 行为闸门未通过（${script}）—— 不要部署 dist/worker.js。` +
                        `它钉的是：${label}。` +
                        '该组闸门只依赖源码与混淆前产物、与本次密钥和混淆强度无关，所以不重试；' +
                        '确认是有意改动可设 TOOLS_GATE=0 跳过整组，或 POOL_GATE=0 只跳过反代池抽取那项。'
                );
            }
        }
        return;
    }

    throw new Error(
        `混淆产物连续 ${attempts} 次未通过验证闸门 —— 不要部署 dist/worker.js。` +
            `可调 HARDEN_STRINGS / HARDEN_OPAQUE / HARDEN_MAX_STRING 降低激进程度，` +
            `或设 SMOKE_EVERY=0 先只跑静态闸门看具体报错。`
    );
}

buildWorker().catch(err => {
    console.error(`${failure} Build failed:`, err);
    process.exit(1);
});
