import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname as pathDirname } from 'path';
import { fileURLToPath } from 'url';
import { build } from 'esbuild';
import { globSync } from 'glob';
import { minify as jsMinify } from 'terser';
import { minify as htmlMinify } from 'html-minifier';
import JSZip from "jszip";
import obfs from 'javascript-obfuscator';
import pkg from '../package.json' with { type: 'json' };
import { gzipSync } from 'zlib';

const env = process.env.NODE_ENV || 'mangle';
const mangleMode = env === 'mangle';

const __filename = fileURLToPath(import.meta.url);
const __dirname = pathDirname(__filename);

const ASSET_PATH = join(__dirname, '../src/assets');
const DIST_PATH = join(__dirname, '../dist/');

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

    const minifyCode = async (code) => {
        const minified = await jsMinify(code, {
            module: true,
            output: {
                comments: false
            },
            compress: {
                dead_code: false,
                unused: false
            }
        });

        console.log(`${success} Worker minified successfuly!`);
        return minified;
    }

    const jszipRuntime = await buildJszipRuntime();
    let finalCode;

    if (mangleMode) {
        const junkCode = generateJunkCode();
        const minifiedCode = await minifyCode(junkCode + code.outputFiles[0].text);
        finalCode = minifiedCode.code;
    } else {
        const minifiedCode = await minifyCode(code.outputFiles[0].text);
        const obfuscationResult = obfs.obfuscate(minifiedCode.code, {
            // ── 字符串数组：全部提取 + 多层编码(RC4→Base64) + 索引偏移 ──
            stringArray: true,
            stringArrayThreshold: 1,
            stringArrayEncoding: ["rc4", "base64"],
            stringArrayIndexShift: true,
            stringArrayIndexesType: ['hexadecimal-number'],
            stringArrayWrappersCount: 5,
            stringArrayWrappersChainedCalls: true,
            stringArrayWrappersParametersMaxCount: 4,

            // ── 字符串拆分：10 字符一段，交叉引用，防 grep ──
            splitStrings: true,
            splitStringsChunkLength: 10,

            // ── 控制流混淆：函数内逻辑打散为 switch-case 调度 ──
            controlFlowFlattening: true,
            controlFlowFlatteningThreshold: 0.75,

            // ── 数字/表达式 ──
            numbersToExpressions: true,

            // ── 对象键混淆 ──
            transformObjectKeys: true,

            // ── 标识符：打乱顺序 + 混合命名 ──
            identifierNamesGenerator: 'mangled-shuffled',
            identifiersPrefix: '',
            renameGlobals: false,

            // ── 死代码注入 ──
            deadCodeInjection: true,
            deadCodeInjectionThreshold: 0.4,

            // ── Unicode 转义 ──
            unicodeEscapeSequence: true,

            target: "browser"
        });

        console.log(`${success} Worker obfuscated successfuly!`);
        finalCode = obfuscationResult.getObfuscatedCode();
    }

    const worker = `${jszipRuntime}${finalCode}`.replace(/\/\/ .*/g, '').replace(/\n+/g, '');
    mkdirSync(DIST_PATH, { recursive: true });
    writeFileSync('./dist/worker.js', worker, 'utf8');

    const zip = new JSZip();
    zip.file('_worker.js', worker);
    zip.generateAsync({
        type: 'nodebuffer',
        compression: 'DEFLATE'
    }).then(nodebuffer => writeFileSync('./dist/worker.zip', nodebuffer));

    console.log(`${success} Done!`);
}

buildWorker().catch(err => {
    console.error(`${failure} Build failed:`, err);
    process.exit(1);
});

