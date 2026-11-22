/**
 * tools/url-region-anchor.test.mjs
 *
 * 「远程清单里的 @地区 锚定」回归。运行：node tools/url-region-anchor.test.mjs
 * （package.json 里是 `npm run test:urlregion`）
 *
 * 为什么需要它：反代池支持把 `http(s)://…` 当远程清单，而这类接口（如
 * `…/api/nodes?format={ip}:{port}@{region}`）返回的正是 `ip:port@REGION`。
 * 解析器曾经在「判端口」时没先剥掉 `@地区`：末段是 `443@SG` 而不是纯数字，于是被当成
 * 「没有端口」，拼成 `ip:443@SG:443` —— 地区变成 `SG:443`，
 * `selectProxyIPByRegion` 永远匹配不上，地区锚定静默退化成「任意带标签条目轮询」。
 * 这条测试把解析结果与最终选中项一起钉住。
 */
import { join } from 'path';
import { ROOT, bundleUtils, isolateLoader } from './lib/utils-bundle.mjs';

const OUT_DIR = join(ROOT, '.build/url-region-anchor');
const BUNDLE_PATH = join(OUT_DIR, 'utils-bundle.mjs');

let failures = 0;
const out = (...args) => process.stdout.write(args.join(' ') + '\n');
const check = (name, fn) => {
    try { fn(); out(`PASS  ${name}`); }
    catch (err) { out(`FAIL  ${name}\n      ${err.message}`); failures++; }
};

// utils 是纯工具模块：先装全局桩，再 bundle、再取模块实例
globalThis.settings = {};
globalThis.httpConfig = { defaultHttpsPorts: [443], defaultHttpPorts: [80] };
globalThis.caches = undefined;

const BODY = [
    // 带端口的（就是 seeck 那种 format={ip}:{port}@{region} 的返回形态）
    '104.17.67.169:443@SG',
    '172.68.173.110:8443@SG',
    // 不带端口、只带地区 → 应补成 :443 且地区仍在
    '8.39.204.129@GL',
    // 无地区、无端口 → 应补 :443
    '1.1.1.1',
    // IPv6 带端口 + 地区
    '[2606:4700::1111]:443@HK',
    // 注释行应被跳过
    '# comment line',
    '// another comment'
].join('\n');

/** 记录每次出站抓到的 URL（用来验证「查询串里的逗号没被拆开」「花括号被编码」） */
const fetchedUrls = [];

globalThis.fetch = async (url) => {
    fetchedUrls.push(String(url));
    return new Response(BODY, { headers: { 'content-type': 'text/plain; charset=utf-8' } });
};

await bundleUtils({
    outFile: BUNDLE_PATH,
    names: ['resolveUrlEntries', 'parseProxyIPWithRegion', 'selectProxyIPByRegion', 'normalizeRegionTag']
});
const utils = await (isolateLoader(BUNDLE_PATH))();

const URL_ENTRY = 'https://proxy.example.cn/api/nodes?region=SG&limit=15&format={ip}:{port}@{region}';
const resolved = await utils.resolveUrlEntries([URL_ENTRY]);

check('远程清单被展开成 5 条（注释行跳过）', () => {
    if (resolved.length !== 5) throw new Error(`实际 ${resolved.length} 条：${resolved.join(' | ')}`);
});

check('带端口的 @地区 条目不被二次补端口（不能出现 "@SG:443"）', () => {
    const bad = resolved.filter((entry) => /@[A-Za-z]+:\d+$/.test(entry));
    if (bad.length) throw new Error(`被拼坏了：${bad.join(' | ')}`);
    if (!resolved.includes('172.68.173.110:8443@SG')) throw new Error(`8443 端口丢失：${resolved.join(' | ')}`);
});

check('无端口的 @地区 条目补成 host:443@REGION（顺序正确）', () => {
    if (!resolved.includes('8.39.204.129:443@GL')) throw new Error(resolved.join(' | '));
});

check('无地区无端口 → host:443', () => {
    if (!resolved.includes('1.1.1.1:443')) throw new Error(resolved.join(' | '));
});

check('IPv6 + 端口 + 地区：host/port/region 三段都解析正确', () => {
    const parsed = utils.parseProxyIPWithRegion('[2606:4700::1111]:443@HK');
    if (parsed.region !== 'HK' || parsed.port !== 443 || !parsed.host.startsWith('[2606:4700::1111]')) {
        throw new Error(JSON.stringify(parsed));
    }
});

check('地区锚定生效：SG 选中 SG 条目、GL 选中 GL 条目（不是退化成轮询）', () => {
    const sg = utils.selectProxyIPByRegion([...resolved], 'SG');
    const gl = utils.selectProxyIPByRegion([...resolved], 'GL');
    if (!/@SG$/.test(sg || '')) throw new Error(`SG 选中了 ${sg}`);
    if (!/@GL$/.test(gl || '')) throw new Error(`GL 选中了 ${gl}`);
});

// ── 远程清单 URL 自身的「,」与「{}」必须被兼容（不能被拆开 / 也不能原样发出去）──
const checkAsync = async (name, fn) => {
    try { await fn(); out(`PASS  ${name}`); }
    catch (err) { out(`FAIL  ${name}\n      ${err.message}`); failures++; }
};

fetchedUrls.length = 0;
const REGION_PAIR_URL = 'https://proxy.example.cn/api/nodes?region=SG,HK&limit=15&format={ip}:{port}@{region}';
const pairResolved = await utils.resolveUrlEntries([REGION_PAIR_URL]);

check('「,」在查询串里：整行当一个 URL 抓，只抓一次', () => {
    if (fetchedUrls.length !== 1) throw new Error(`抓了 ${fetchedUrls.length} 次：${fetchedUrls.join(' | ')}`);
    if (!fetchedUrls[0].includes('region=SG,HK')) throw new Error(`URL 被拆坏了：${fetchedUrls[0]}`);
});

check('花括号在发请求前被编码（%7B / %7D），但解析结果不受影响', () => {
    if (!fetchedUrls[0].includes('format=%7Bip%7D:%7Bport%7D@%7Bregion%7D')) {
        throw new Error(`未编码：${fetchedUrls[0]}`);
    }
    if (pairResolved.length !== 5) throw new Error(`解析出 ${pairResolved.length} 条：${pairResolved.join(' | ')}`);
});

await checkAsync('两个 URL 用逗号并列时仍然拆成两条（原有用法不能被破坏）', async () => {
    fetchedUrls.length = 0;
    const list = await utils.resolveUrlEntries(['https://a.example/list,https://b.example/list']);
    if (fetchedUrls.length !== 2) throw new Error(`抓了 ${fetchedUrls.length} 次：${fetchedUrls.join(' | ')}`);
    // 两个清单内容相同 → 按 host:port 去重后仍是 5 条（去重是既有行为，不是拆分失败）
    if (list.length !== 5) throw new Error(`去重后应 5 条，实际 ${list.length}：${list.join(' | ')}`);
});

await checkAsync('裸地址仍按逗号拆（`1.1.1.1,8.8.8.8` → 两条，不发请求）', async () => {
    fetchedUrls.length = 0;
    const list = await utils.resolveUrlEntries(['1.1.1.1,8.8.8.8']);
    if (fetchedUrls.length !== 0) throw new Error(`不该发请求：${fetchedUrls.join(' | ')}`);
    if (list.join(',') !== '1.1.1.1,8.8.8.8') throw new Error(list.join(' | '));
});

out('');
if (failures) {
    out(`url-region-anchor: FAILED（${failures} 项）`);
    process.exit(1);
}
out('url-region-anchor: OK');
