/**
 * eslint.config.mjs — 最小 lint 环节（审查项 H-01，方案 a）
 *
 * 为什么是「最小」
 *   本仓长期装着 4 个 eslint devDependency + 只服务 lint 的 globals，却没有配置也没有脚本，
 *   于是 lint 从未跑过（`_verify.js` 那种「"type":"module" 里写 require」的残骸就是因为没有
 *   任何环节会报错才活下来的）。这里只引入 `@eslint/js` 的 recommended，并显式钉住
 *   `no-unused-vars` / `no-undef` 两条最容易暴露真实 bug 的规则；
 *   不引任何第三方 plugin / parser，避免为一个 lint 环节新增供应链与 node_modules 体积。
 *
 * 覆盖范围
 *   scripts/**\/*.mjs  —— Node 侧的构建 / 混淆 / 闸门脚本，纯 ESM，核心 eslint 可直接解析。
 *
 *   ⚠️ 为什么**没有**覆盖 src/**\/*.ts
 *   核心 eslint 用的 espree 解析不了 TypeScript 语法，直连的结果不是「告警」而是每个文件一条
 *   致命解析错误（实测 `src/common/common.ts`：`Parsing error: Unexpected token enum`），
 *   42 个 .ts 文件 = 42 条无信息的 error，等于把 lint 变成一个恒红的噪声源。
 *   要让 eslint 真正检查 .ts，必须引入 `@typescript-eslint/parser`（+ 其依赖树），
 *   这与本仓「体积 / 供应链敏感」的前提冲突，且属于另一项独立决策，故不在此处擅自引入。
 *   src/**\/*.ts 的静态保障仍然由 `npm run check`（tsc --noEmit）承担；
 *   若要覆盖「未使用变量」，在 tsconfig.json 里开 noUnusedLocals / noUnusedParameters 即可
 *   （审查报告的 D-01 就是这条路径，全仓仅 2 处违例）。
 *
 * 用法
 *   npm run lint            # 等价于 eslint .
 *   npm run lint -- --fix   # 需要时
 *
 * 退出码说明
 *   现有代码存在历史问题（首次运行见下方 error 计数），因此本配置**不承诺 0 error**；
 *   它承诺的是「配置本身正确、可重复运行、新代码的未定义变量/未使用变量会被拦下」。
 */
import js from '@eslint/js';
import globals from 'globals';

export default [
    // 产物与本地状态：不参与 lint
    {
        ignores: ['dist/**', '.build/**', '.wrangler/**', 'node_modules/**', 'site/**'],
    },

    // Node 侧脚本（构建链 / 混淆 / 静态闸门 / smoke）
    {
        files: ['scripts/**/*.mjs'],
        languageOptions: {
            ecmaVersion: 'latest',
            sourceType: 'module',
            globals: {
                ...globals.node,
            },
        },
        rules: {
            ...js.configs.recommended.rules,
            // 显式覆盖 recommended 的默认值，便于一眼看出本仓的取舍：
            //   - 允许以 _ 开头的未使用参数（回调签名需要占位）
            //   - 不检查 catch 绑定（`catch (err)` 只用于兜底时是合法写法）
            'no-unused-vars': [
                'error',
                {
                    args: 'after-used',
                    argsIgnorePattern: '^_',
                    caughtErrors: 'none',
                    ignoreRestSiblings: true,
                },
            ],
            'no-undef': 'error',
        },
    },
];
