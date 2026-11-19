/**
 * tools/lib/utils-bundle.mjs
 *
 * 两个「只测 src/cores/utils.ts」的闸门（`proxy-pool-cache.test.mjs` / `doh-source.test.mjs`）
 * 共用的脚手架，收在一处是因为这些都不该有第二份：
 *   · `bundleUtils`     —— 用 esbuild 把 utils.ts 打成单文件（走 tsconfig 的 paths 别名，与构建链路一致）
 *   · `isolateLoader`   —— 每次调用返回一个**全新模块实例**（= 新的 isolate，一级缓存/模块级状态都是空的）
 *   · `createReporter`  —— PASS/FAIL 行与收尾汇总（失败退出码 1）
 *   · `asSet`           —— 池按集合比较（顺序是目标无关的确定性洗牌，不做字面断言）
 *
 * 为什么必须唯一：闸门的「汇总格式 + 失败退出码」就是 CI 的判据。两个文件各写一份时，
 * 很容易一个改了格式、另一个忘了 —— 那会让失败在日志里看起来像通过。
 *
 * 约定：调用方先装好自己的全局桩（fetch / caches / settings / env），再 `await bundleUtils(...)`，
 * 之后用 `isolateLoader` 取模块 —— 模块在 import 时才读全局，装桩顺序反了会打到真网络。
 */
import { build } from 'esbuild';
import { mkdirSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

/** 仓库根：本文件在 tools/lib/ 下，故上两级 */
export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

/** 把 utils.ts 打成单文件，只导出 `names` 指定的符号（入口文件由构建期生成，不落盘） */
export async function bundleUtils({ outFile, names }) {
    mkdirSync(dirname(outFile), { recursive: true });
    await build({
        stdin: {
            contents: `export { ${names.join(', ')} } from './src/cores/utils';`,
            resolveDir: ROOT,
            sourcefile: 'utils-entry.ts',
            loader: 'ts'
        },
        outfile: outFile,
        bundle: true,
        format: 'esm',
        platform: 'node',
        target: 'esnext',
        external: ['cloudflare:sockets'],
        legalComments: 'none'
    });
}

/** 返回一个 loader：每次调用都 import 一个带新查询串的模块实例（= 模拟落到另一个 isolate） */
export function isolateLoader(bundlePath) {
    let seq = 0;
    return async function load() {
        seq++;
        return await import(`${pathToFileURL(bundlePath).href}?iso=${seq}`);
    };
}

/** `[ [host, port], ... ]` 按集合比较（`${host}:${port}` 升序） */
export const asSet = (pool) => [...pool].map(([host, port]) => `${host}:${port}`).sort();

/** PASS/FAIL 行 + 收尾汇总（有失败项时 exit 1，与 build.js 的闸门判定一致） */
export function createReporter(label) {
    let failures = 0;
    const out = (...args) => process.stdout.write(args.join(' ') + '\n');
    return {
        out,
        check(name, fn) {
            try {
                fn();
                out(`PASS  ${name}`);
            } catch (err) {
                out(`FAIL  ${name}\n      ${err.message}`);
                failures++;
            }
        },
        finish() {
            out('');
            if (failures) {
                out(`${label}: FAILED（${failures} 项）`);
                process.exit(1);
            }
            out(`${label}: OK`);
        }
    };
}
