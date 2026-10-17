/**
 * tools/panel-layout.test.mjs
 *
 * 面板 Subscriptions 表格布局的 CSS 契约测试（无浏览器）。
 * 运行：node tools/panel-layout.test.mjs
 *
 * 为什么需要它：`.table-container tbody { display:flex }` 让 <table> 退出表格布局、退化成
 * 收缩宽度（实测 718px 容器里只有 300px），表现为：
 *   · 复制 / 二维码 / 下载 三个按钮紧贴「客户端类型」而不是排在深色卡片右边缘；
 *   · 鼠标悬浮的行底色与行分隔线只包住左侧客户端列，右侧一大片空白。
 * 修复只有一条：把 <table> 显式改成块级，它会自动铺满容器、行随之撑满。
 * 这类问题 UI 上肉眼可见、但 smoke / verify 都看不见，所以在这里钉死最小契约：
 *   · `.table-container table { display:block }` —— 根因修复本身
 *   · `.table-container td { width:100% }` —— 左列吃掉剩余宽度（把右列顶开的一半）
 *   · `.table-container tr td:nth-child(2) { width:fit-content }` —— 操作列不参与拉伸（另一半）
 *     两者缺一，三个按钮就会缩回「客户端类型」旁边
 *   · 5 个子表格确实都挂在 .table-container 下（选择器不能悬空）
 * 不再钉 `tr{width:100%}` / `td:first-child{flex}` / `td2{justify-content}` 这类 reinforcement ——
 * 实测它们在该层叠下不改变盒模型（360~1262px 六档逐像素相同），钉住只会拦住正当的 CSS 精简。
 *
 * 顺带覆盖构建链路：这里的 HTML 装配 + html-minifier(minifyCSS) 与 scripts/build.js 的
 * processHtmlPages 完全同参，能同时验证「改过的 CSS 仍能过 clean-css、规则没被压没」。
 */
import { readFileSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';
import { minify as htmlMinify } from 'html-minifier';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PANEL = join(ROOT, 'src/assets/panel');

let failures = 0;
const out = (...args) => process.stdout.write(args.join(' ') + '\n');
const check = (name, fn) => {
    try { fn(); out(`PASS  ${name}`); }
    catch (err) { out(`FAIL  ${name}\n      ${err.message}`); failures++; }
};

const html = readFileSync(join(PANEL, 'index.html'), 'utf8');
const css = readFileSync(join(PANEL, 'style.css'), 'utf8');

/** 取压缩后 CSS 里某个选择器所在规则的声明块；找不到返回 null（= 规则被删掉或被压没）。
 *  不能按 `selector{` 直接找：clean-css 会把选择器列表重排成 `.table-container td,.table-container th{...}`，
 *  这里按「选择器列表 → 声明块」逐条遍历，再用逗号拆开比对。 */
function rule(minifiedCss, selector) {
    const ruleRe = /([^{}]+)\{([^{}]*)\}/g;
    let m;
    while ((m = ruleRe.exec(minifiedCss))) {
        if (m[1].split(',').map((s) => s.trim()).includes(selector)) return m[2];
    }
    return null;
}

const hasDecl = (body, decl) => typeof body === 'string' && body.includes(decl);

// ── 按 scripts/build.js#processHtmlPages 的同一套参数装配并压缩 ──
// __SCRIPT__ 用占位符代替：这里不重复跑 terser，CSS 才是被测对象。
let minified = '';
try {
    minified = htmlMinify(
        html
            .replaceAll('__VERSION__', '0.0.0')
            .replaceAll('__STYLE__', `<style>${css}</style>`)
            .replaceAll('__SCRIPT__', '/*test*/'),
        { collapseWhitespace: true, removeAttributeQuotes: true, minifyCSS: true }
    );
} catch (err) {
    out(`FAIL  面板 HTML+CSS 过不了构建链路的 clean-css 压缩\n      ${err.message}`);
    failures++;
}

check('面板 HTML+CSS 能被构建链路压缩（clean-css 不报错）', () => {
    if (!minified) throw new Error('压缩产物为空');
});

// ── 契约 1：表格必须是块级，否则宽度会收缩到内容宽度、按钮缩回客户端类型旁边 ──
const tableRule = rule(minified, '.table-container table');
check('.table-container table 被撑成块级（表格不再收缩到内容宽度）', () => {
    if (!tableRule) throw new Error('找不到 .table-container table 规则');
    if (!hasDecl(tableRule, 'display:block')) throw new Error(`缺 display:block，实际：${tableRule}`);
});

// ── 契约 2：左列 td 必须吃掉剩余宽度（右对齐的另一半；缺了它按钮会缩回客户端类型旁边）──
// 注意这里匹配的是 `.table-container th,.table-container td{...}` 那条合并规则里的 td 分支。
const cellRule = rule(minified, '.table-container td');
check('.table-container td 有 width:100%（左列吃掉剩余宽度，把操作列顶开）', () => {
    if (!cellRule) throw new Error('找不到 .table-container td 规则');
    if (!hasDecl(cellRule, 'width:100%')) throw new Error(`缺 width:100%，实际：${cellRule}`);
});

// ── 契约 3：操作列保持 fit-content（自身不拉伸），才会被左列顶到最右边 ──
const actionRule = rule(minified, '.table-container tr td:nth-child(2)');
check('操作按钮列 width:fit-content（不参与拉伸，才会被推到右边缘）', () => {
    if (!actionRule) throw new Error('找不到 .table-container tr td:nth-child(2) 规则');
    if (!hasDecl(actionRule, 'width:fit-content')) throw new Error(`缺 width:fit-content，实际：${actionRule}`);
});

// ── 契约 4：规则确实作用到订阅表格上：5 个 .table-container 内部各自都包着 <table> ──
check('5 个 .table-container 内部都包着 <table>（选择器没有悬空）', () => {
    const blocks = html.split('<div class="table-container">').slice(1);
    if (blocks.length !== 5) throw new Error(`期望 5 个 .table-container，实际 ${blocks.length}`);
    blocks.forEach((block, index) => {
        const end = block.indexOf('</table>');
        if (end < 0) throw new Error(`第 ${index + 1} 个 .table-container 里没有 <table>`);
    });
});

out('');
if (failures) {
    out(`panel-layout: FAILED（${failures} 项）`);
    process.exit(1);
}
out('panel-layout: OK');
