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

/** Lightweight string obfuscation: encode critical strings as charCode arrays
 *  to avoid plaintext exposure of protocol names, paths, and config keys. */
function obfuscateStrings(code) {
    // Replace critical string CONTENT with hex escapes inside existing quotes.
    // The lookbehind/lookahead keep the quotes intact — only inner text is hex-escaped.
    const sensitivePatterns = [
        { re: /(?<=["'`])vless(?=["'`])/gi, key: 'vless' },
        { re: /(?<=["'`])trojan(?=["'`])/gi, key: 'trojan' },
        { re: /(?<=["'`])proxyip(?=["'`])/gi, key: 'proxyip' },
    ];
    let result = code;
    const encoded = new Set();
    for (const { re, key } of sensitivePatterns) {
        result = result.replace(re, (match) => {
            if (encoded.has(key)) return match;
            encoded.add(key);
            return [...match].map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
        });
    }
    return result;
}

function generateJunkCode() {
    // Realistic-looking identifier tokens — no __ prefix, no detectable pattern
    const tokens = [
        'cdn','dns','tls','url','ip','port','host','path','route','edge',
        'node','link','data','flow','cache','pool','list','map','set','key',
        'val','src','dst','req','res','msg','buf','ctx','env','cfg',
        'tag','pos','idx','tmp','acc','sum','min','max','len','ptr',
        'opt','ref','raw','seg','pid','sid','uid','ttl','hop','mtu',
    ];

    const funcCount = 80 + Math.floor(Math.random() * 120);
    const names = [];
    for (let i = 0; i < funcCount; i++) {
        const a = tokens[Math.floor(Math.random() * tokens.length)];
        const b = tokens[Math.floor(Math.random() * tokens.length)];
        const c = tokens[Math.floor(Math.random() * tokens.length)];
        // Mix two- and three-token names so there's no uniform pattern
        names.push(i % 3 === 0 ? `${a}${b.charAt(0).toUpperCase()}${b.slice(1)}${c.charAt(0).toUpperCase()}${c.slice(1)}`
            : i % 3 === 1 ? `${a}${b.charAt(0).toUpperCase()}${b.slice(1)}`
            : `${b}${a.charAt(0).toUpperCase()}${a.slice(1)}`);
    }

    let code = '';

    // Cross-referencing junk functions with varied body patterns
    for (let i = 0; i < names.length; i++) {
        const refCount = 1 + Math.floor(Math.random() * 3);
        const refs = [...new Set(Array.from({ length: refCount }, () => {
            const ri = Math.floor(Math.random() * names.length);
            return ri !== i ? names[ri] : null;
        }).filter(Boolean))];

        const refCall = refs.length > 0 ? `+(${refs.map(r => `${r}(a,b)`).join('+')})` : '';
        const pattern = Math.floor(Math.random() * 4);

        switch (pattern) {
            case 0: // string manipulation
                code += `function ${names[i]}(a,b){try{return(a??0)+(b??0)${refCall}}catch(e){return 0}}`;
                break;
            case 1: // bitwise / math
                code += `function ${names[i]}(a,b){try{return((a??0)*(b??0)+(a??0)^(b??0))${refCall}}catch(e){return-1}}`;
                break;
            case 2: // ternary chain
                code += `function ${names[i]}(a,b){try{return(a??0)>(b??0)?(a??0)${refCall}:(b??0)${refCall}}catch(e){return 0}}`;
                break;
            case 3: // object property
                code += `function ${names[i]}(a,b){try{var o={x:(a??0),y:(b??0)};return o.x+o.y${refCall}}catch(e){return 0}}`;
                break;
        }
    }

    // Config-like variable declarations (look like real worker state)
    const cfgCount = 5 + Math.floor(Math.random() * 10);
    for (let i = 0; i < cfgCount; i++) {
        const a = tokens[Math.floor(Math.random() * tokens.length)];
        const b = tokens[Math.floor(Math.random() * tokens.length)];
        const name = `${a}${b.charAt(0).toUpperCase()}${b.slice(1)}`;
        const useStr = Math.random() > 0.5;
        code += useStr
            ? `var ${name}="${Math.random().toString(36).substring(2, 10)}";`
            : `var ${name}=${Math.floor(Math.random() * 65535)};`;
    }

    // Dummy side-effect call that terser can't eliminate even with dead_code optimization
    // because it references a non-pure function (Math.random).
    code += `if(typeof globalThis!=='undefined'&&Math.random()>2){globalThis.${names[Math.floor(Math.random()*names.length)]}=${names[0]}(1,2)}`;

    return code;
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

    // Pre-obfuscation: scramble critical strings in the bundled code
    const scrambledCode = obfuscateStrings(code.outputFiles[0].text);

    if (mangleMode) {
        const junkCode = generateJunkCode();
        const minifiedCode = await minifyCode(junkCode + scrambledCode);
        finalCode = minifiedCode.code;
        console.log(`${success} Mangle mode: junk (${junkCode.length}B) + string obfuscation applied`);
    } else {
        const minifiedCode = await minifyCode(scrambledCode);
        const obfuscationResult = obfs.obfuscate(minifiedCode.code, {
            stringArrayThreshold: 0.6,
            stringArrayEncoding: [
                "base64"
            ],
            stringArrayIndexesType: [
                "hexadecimal-number"
            ],
            stringArrayIndexShift: true,
            stringArrayWrappersCount: 2,
            stringArrayWrappersChainedCalls: true,
            stringArrayWrappersType: 'function',
            splitStrings: true,
            splitStringsChunkLength: 10,
            numbersToExpressions: false,
            transformObjectKeys: false,
            renameGlobals: false,
            deadCodeInjection: false,
            controlFlowFlattening: true,
            controlFlowFlatteningThreshold: 0.3,
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

