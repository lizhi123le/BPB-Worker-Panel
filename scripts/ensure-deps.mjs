/**
 * scripts/ensure-deps.mjs
 *
 * 构建前置自检 + 自动补装依赖。
 *
 * 为什么需要它
 *   构建期工具包分属两个 section：esbuild / glob / terser / html-minifier / jszip 在
 *   dependencies，而 js-confuser（混淆）、@babel/parser（静态闸门 verify）与 typescript
 *   （npm run check）在 devDependencies。只要安装步骤带了 `--production`（或 NODE_ENV=production），
 *   devDependencies 会被整体跳过：
 *     - `scripts/obfuscate.mjs` 的静态 import 在链接阶段直接抛 ERR_MODULE_NOT_FOUND，
 *       报错栈落在 300 行之外，看不出"其实是依赖没装"；
 *     - 更阴的是 `npm run check`：GitHub 的 ubuntu 镜像用 toolset 全局装了 typescript
 *       （actions/runner-images 的 images/ubuntu/toolsets/toolset-2404.json 里有
 *       {"name":"typescript","command":"tsc"}），类型检查会被镜像里那个 tsc 兜住、显示成绿，
 *       直到构建阶段才炸。
 *
 * 判定口径
 *   只看 `项目根/node_modules/<pkg>/package.json` 是否存在，**故意不用模块解析**：
 *     - 模块解析会向上翻父目录，父级 node_modules 里蹭到的包会掩盖"本项目没装"；
 *       （本仓库真实踩过：项目 node_modules 整个不存在，构建却因为 D:\...\Desktop\node_modules
 *        里恰好有 @babel/parser / typescript 而"部分可用"，报错点因此漂移到别的包上。）
 *     - 纯类型包（@cloudflare/workers-types）没有运行时入口，import.meta.resolve 必然失败。
 *
 * 行为
 *   - 全部就位：静默通过（几毫秒）。
 *   - 有缺失：打印缺哪些包 -> 自动 `npm install --include=dev` -> 复查 -> 仍缺则抛错。
 *   - BPB_SKIP_AUTO_INSTALL=1：只报错、不自动安装（想 fail-fast 时用）。
 *   - npm 自身参数由 npm_config_* 环境变量透传（npm_config_cache / npm_config_ignore_scripts 等）。
 *
 * 单独运行：node scripts/ensure-deps.mjs  或  npm run ensure-deps
 */
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const NODE_MODULES = join(ROOT, 'node_modules');

/**
 * 构建 / 类型检查链上必需的包。
 * 其余 devDependencies（eslint、@eslint/* 等）只服务 lint，缺了不影响构建。
 */
export const REQUIRED_DEPS = [
    // 产物构建（scripts/build.js）
    'esbuild',
    'glob',
    'terser',
    'html-minifier',
    'jszip',
    // 混淆 + 静态闸门（scripts/obfuscate.mjs / scripts/verify.mjs）
    'js-confuser',
    '@babel/parser',
    // 类型检查（npm run check）—— 不装就会被 CI 镜像里的全局 tsc 假绿
    'typescript',
    '@cloudflare/workers-types',
];

/** 包是否装在**本项目**的 node_modules 里（不向上解析）。 */
export function isInstalled(name) {
    return existsSync(join(NODE_MODULES, ...name.split('/'), 'package.json'));
}

export function findMissingDeps(deps = REQUIRED_DEPS) {
    return deps.filter((name) => !isInstalled(name));
}

/**
 * 确保构建依赖可用；缺则自动安装。
 * @returns {boolean} 依赖已就绪时返回 true；需要修复且修复失败时抛错。
 */
export function ensureDeps({ deps = REQUIRED_DEPS, autoInstall = process.env.BPB_SKIP_AUTO_INSTALL !== '1' } = {}) {
    let missing = findMissingDeps(deps);
    if (missing.length === 0) return true;

    const list = missing.join(', ');
    if (!autoInstall) {
        throw new Error(
            `构建依赖缺失：${list}\n` +
                `已设 BPB_SKIP_AUTO_INSTALL=1，跳过自动安装。请手动执行：npm install --include=dev`
        );
    }

    console.log(`\n  ! 本项目 node_modules 里缺少：${list}`);
    console.log('  → 自动执行 npm install --include=dev（会联网下载）...\n');

    const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    // 整条命令交给 shell：Windows 上 npm 是 npm.cmd，不用 shell 起不来；而
    // "shell:true + args 数组"会触发 Node 的 DEP0190（args 不做转义）。这里是固定字面量。
    const command = 'npm install --include=dev --no-audit --no-fund';
    // --include=dev 是关键：它会盖掉环境里可能存在的 NODE_ENV=production / --omit=dev，
    // 否则"自动补装"会以同样的方式再漏掉 devDependencies 一次。
    const result = spawnSync(command, {
        cwd: ROOT,
        stdio: 'inherit',
        shell: true,
    });

    if (result.error) {
        throw new Error(
            `无法启动 npm（${npm}）：${result.error.message}\n请手动执行：npm install --include=dev`
        );
    }
    if (result.status !== 0) {
        throw new Error(
            `npm install 退出码 ${result.status}。请在有网络的环境手动执行：npm install --include=dev`
        );
    }

    missing = findMissingDeps(deps);
    if (missing.length > 0) {
        throw new Error(
            `自动安装后仍然缺少：${missing.join(', ')}\n` + `请手动执行：npm install --include=dev，然后重试。`
        );
    }

    console.log('  ✔ 构建依赖已补齐\n');
    return true;
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
    try {
        ensureDeps();
        console.log(`构建依赖齐全（${REQUIRED_DEPS.length} 个）。`);
    } catch (err) {
        console.error(err.message);
        process.exit(1);
    }
}
