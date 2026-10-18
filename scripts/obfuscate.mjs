/**
 * scripts/obfuscate.mjs
 *
 * 读取构建产物（默认 dist/worker.reference.js，即 esbuild + terser 之后、未混淆的同一份文件），
 * 用 js-confuser 加一层"每次构建一条随机 ChaCha20 密钥"的字符串密文，然后写回 dist/worker.js。
 *
 * 运行：node scripts/obfuscate.mjs [输入] [输出] [--target-zip=320k] [--target-bytes=70%]
 *       参数优先级 CLI > 环境变量 > harden.config.json；大小支持 320000/320k/1m/75%。
 *       默认体积目标：--target-bytes=512k --target-zip=236k（显式设 0 可关闭）。
 *
 * 与参考实现（MOD-Worker-Panel/obfuscate.mjs）的关系：
 *  - 密文换成真 ChaCha20（RFC 8439）+ 每条字符串独立 8 字节 nonce，密钥每次构建随机，
 *    而不是 `(x - SHIFT) % 128 ^ XOR` 这种 16k 密钥空间、有损、确定性的变换。
 *  - 提供 `decode`，因此 js-confuser 会对**每一条**被隐藏的字符串做往返校验，
 *    校验不过就退回明文（fail-safe，而不是产出解不开的产物）。
 *  - `stringConcealing` 默认隐藏所有字符串字面量（含属性名），不再是只藏 3 个词。
 *  - 加固选项全部由环境变量控制，见下面的 HARDENING。
 *
 * HARDENING（环境变量 -> 默认值）：
 *   HARDEN_STRINGS=true      隐藏所有字符串 + 属性名
 *                            false = 只藏命中敏感词表的字符串（sensitive_words_auto.txt）
 *   HARDEN_MAX_STRING=0      超过该长度的字符串不隐藏（0 = 不限制）。
 *                            本仓库内置了 gzip+base64 页面大块（最大 26KB），需要限制时可调小。
 *   HARDEN_MIN_STRING=0      短于该长度的不隐藏。谓词同时作用于属性名，调大能明显压缩载荷表，
 *                            代价是 `obj.get` 这类短属性名留在明处。敏感词始终强制隐藏。
 *   HARDEN_ONE_LINE=true     产物保持单行（追加的解码器源码也压成一行）
 *   HARDEN_TARGET_BYTES=0    产物原始字节预算；>0 时启用参数搜索（0 = 不限制，单次混淆）
 *   HARDEN_TARGET_ZIP_BYTES=0 dist/worker.zip 压缩字节预算（DEFLATE，与 build.js 相同算法）
 *   HARDEN_SIZE_MAX_RUNS=12  体积搜索最多跑几次混淆（每次约 3.5s）
 *   HARDEN_OPAQUE=0.1        不透明谓词概率
 *   HARDEN_CFF=0             控制流平坦化 —— 必须保持 0，它会生成 `with`，
 *                            在 ES 模块（严格模式）里是语法错误（js-confuser 的已知缺陷）
 *   HARDEN_INTEGRITY=false   逐函数校验锁定 —— 见下面的警告
 *   HARDEN_ANTIDEBUG=false   注入 debugger
 *   HARDEN_SELFDEFENDING=false
 *   HARDEN_MINIFY=false      js-confuser 自带的压缩（terser 已经做过，且它与页面字符串里的 CSS 冲突）
 *   HARDEN_IDENTIFIER_GENERATOR=mangled   见下面"标识符陷阱"
 *   HARDEN_RENAME_VARIABLES / HARDEN_RENAME_GLOBALS / HARDEN_MOVED_DECLARATIONS /
 *   HARDEN_OBJECT_EXTRACTION / HARDEN_AST_SCRAMBLER  = true（逐个可关，用于定位问题）
 *   HARDEN_ATTEMPTS=3        单个产物最多重试几次（由 scripts/build.js 驱动）
 *
 * 标识符陷阱（本仓库实测，务必保留 build.js 里的 `mangle: false`）
 *   js-confuser 2.0 的 renameVariables 会按**名字**解析作用域绑定。如果交给它的代码里本来就有
 *   "同名不同绑定"的嵌套作用域，闭包引用会被改到错误的绑定上。terser 恰恰最爱这么复用短名：
 *
 *     // terser 之后（worker.reference.js）—— 形参和 catch 参数都叫 e
 *     async function Kt(e){ ... (async()=>{ await e.kv.get("proxySettings_ver") })() ...
 *                           catch(e){ if(!t.settings) throw e } }
 *     // js-confuser 之后 —— 形参变 a，闭包里的 e.kv 被改成了 catch 的绑定
 *     function eI(a){ ... h["kv"].get(...) ... catch(h){...} }
 *
 *   后果是 env.kv 变成别的对象的属性，所有 KV 读取 500（scripts/smoke.mjs 会当场抓到）。
 *   解法：混淆阶段不要 terser mangle（`mangle:false`），让 js-confuser 面对未短名化的标识符。
 *   换 identifierGenerator 并不能绕开它（'randomized' 一样命中），只是换个名字。
 *
 * 为什么 integrity 默认关闭
 *   js-confuser 2.0 的 integrity 在最后运行，它给包装函数生成局部名时用的 NameGen 并不知道
 *   renameVariables 已经分发过哪些名字。撞名时包装器会遮蔽掉哈希函数本身：
 *
 *     function dJ(){var aV=dJ.aU||(dJ.aU=aV(ba,9897108)); ... }   // aV === 哈希函数
 *
 *   于是被包装函数的每次调用都抛 "TypeError: aV is not a function"。它是按构建抽签的：
 *   这次产物没事、下次就坏，而且坏在你 smoke 覆盖不到的路径上。verify.mjs 会在静态层面
 *   直接拒绝这种形状，所以这个开关是"开了要担责"的：校验锁不值一次线上随机故障。
 */

import { default as JsConfuser } from 'js-confuser';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';
import {
  randomKey,
  keyToBase64,
  buildDecoderSource,
  makeCodec,
  randomHelperName,
} from '../tools/cipher.mjs';
import { formatSizeSpec, loadParams } from './build-params.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BUILD_PARAMS = loadParams(process.argv.slice(2));
const INPUT_PATH = resolve(
  ROOT,
  BUILD_PARAMS.positional[0] || '.build/worker.reference.js'
);
const OUTPUT_PATH = resolve(ROOT, BUILD_PARAMS.positional[1] || 'dist/worker.js');
const REPORT_PATH = join(ROOT, '.build/last-build.json');

// ---------------------------------------------------------------- 配置读取
function num(value, fallback) {
  if (value === undefined || value === '') return fallback;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > 1) {
    throw new Error(`Invalid probability "${value}" (expected 0..1)`);
  }
  return n;
}
function int(value, fallback) {
  if (value === undefined || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new Error(`Invalid integer "${value}"`);
  return n;
}
function bool(value, fallback) {
  if (value === undefined || value === '') return fallback;
  return value !== 'false' && value !== '0';
}

const CONFIG = {
  concealAllStrings: bool(process.env.HARDEN_STRINGS, true),
  maxConcealedLength: BUILD_PARAMS.params.maxString,
  // 太短的字符串不隐藏。这个谓词同时作用于字符串字面量与**属性名**，所以调大它可以显著
  // 压缩"载荷表"（属性名数量远多于字面量：本仓库 3,983 条字面量 → 13,507 条载荷），
  // 代价是 `obj.get` 这类短属性名会留在明处。敏感词始终强制隐藏。
  minConcealedLength: BUILD_PARAMS.params.minString,
  opaquePredicates: num(process.env.HARDEN_OPAQUE, 0.1),
  // 控制流平坦化会生成 `with`，在严格模式 / 任何 ES 模块里都是语法错误，必须为 0。
  controlFlowFlattening: num(process.env.HARDEN_CFF, 0),
  integrity: bool(process.env.HARDEN_INTEGRITY, false),
  antiDebug: bool(process.env.HARDEN_ANTIDEBUG, false),
  selfDefending: bool(process.env.HARDEN_SELFDEFENDING, false),
  minify: bool(process.env.HARDEN_MINIFY, false),
  // 标识符策略。
  //
  // 'mangled' 紧凑（本仓库产物约 790KB，'randomized' 约 976KB），但它会**跨作用域复用短名**，
  // 一旦输入里本来就有"同名不同绑定"的嵌套作用域就会改名错位。实测踩过：
  //   terser 把形参和 catch 参数都压成 e → js-confuser 把闭包里的 e 改到了 catch 的绑定上
  //   → `env.kv` 变成别的对象，KV 读取全 500。
  // 因此前提是 scripts/build.js 给混淆阶段传 `mangle: false`（不要让 terser 先复用短名）。
  // 换生成器（randomized）并不能修这个问题，只是让它更难命中。
  identifierGenerator: process.env.HARDEN_IDENTIFIER_GENERATOR || 'mangled',
  movedDeclarations: bool(process.env.HARDEN_MOVED_DECLARATIONS, true),
  objectExtraction: bool(process.env.HARDEN_OBJECT_EXTRACTION, true),
  astScrambler: bool(process.env.HARDEN_AST_SCRAMBLER, true),
  renameVariables: bool(process.env.HARDEN_RENAME_VARIABLES, true),
  renameGlobals: bool(process.env.HARDEN_RENAME_GLOBALS, true),
  // 产物保持单行：js-confuser 的 compact 输出本身是一行，追加的解码器源码默认是多行，
  // 这里把解码器也压成一行（--one-line=false / HARDEN_ONE_LINE=0 可保留可读格式）。
  oneLine: BUILD_PARAMS.params.oneLine,
};

if (CONFIG.controlFlowFlattening > 0 && process.env.HARDEN_ALLOW_CFF !== 'true') {
  throw new Error(
    'HARDEN_CFF > 0 不可用于本产物：js-confuser 的控制流平坦化会生成 `with` 语句，' +
      '在 ES 模块 / 严格模式下是语法错误。请设 HARDEN_CFF=0；' +
      '确实知道自己在做什么时用 HARDEN_ALLOW_CFF=true 放行，或改用 HARDEN_OPAQUE / HARDEN_INTEGRITY。'
  );
}

// ------------------------------------------------------------------ 体积预算
// 参数优先级：CLI > 环境变量 > harden.config.json > 默认值（见 scripts/build-params.mjs）。
//   --target-bytes=620000 / 620k / 70%   worker.js 原始字节预算（70% = 首次混淆产物的 70%）
//   --target-zip=320k / 320000 / 75%     worker.zip 预算（同 build.js 的 DEFLATE）
//   --max-runs=12                        搜索最多跑几次混淆
// 不设目标时行为与之前完全一致（单次混淆）。
const SIZE_RAW_SPEC = BUILD_PARAMS.params.targetBytes;
const SIZE_ZIP_SPEC = BUILD_PARAMS.params.targetZipBytes;
const SIZE_MAX_RUNS = BUILD_PARAMS.params.maxRuns;
const SIZE_SEARCH = Boolean(SIZE_RAW_SPEC || SIZE_ZIP_SPEC);

// 绝对目标先确定；百分比目标在量到「首次混淆产物」后解析（相对同口径大小）。
let SIZE_TARGET_RAW = SIZE_RAW_SPEC && SIZE_RAW_SPEC.kind === 'bytes' ? SIZE_RAW_SPEC.value : 0;
let SIZE_TARGET_ZIP = SIZE_ZIP_SPEC && SIZE_ZIP_SPEC.kind === 'bytes' ? SIZE_ZIP_SPEC.value : 0;
const SIZE_PERCENT_RAW = SIZE_RAW_SPEC && SIZE_RAW_SPEC.kind === 'percent' ? SIZE_RAW_SPEC.value : null;
const SIZE_PERCENT_ZIP = SIZE_ZIP_SPEC && SIZE_ZIP_SPEC.kind === 'percent' ? SIZE_ZIP_SPEC.value : null;
let sizeTargetsResolved = SIZE_PERCENT_RAW === null && SIZE_PERCENT_ZIP === null;

function resolvePercentTargets(firstMetrics) {
  if (SIZE_PERCENT_RAW !== null) {
    SIZE_TARGET_RAW = Math.max(1, Math.floor((firstMetrics.rawBytes * SIZE_PERCENT_RAW) / 100));
  }
  if (SIZE_PERCENT_ZIP !== null) {
    if (firstMetrics.zipBytes === null) {
      throw new Error('百分比 zip 目标需要测量 zip 大小（内部错误：zipBytes 为空）');
    }
    SIZE_TARGET_ZIP = Math.max(1, Math.floor((firstMetrics.zipBytes * SIZE_PERCENT_ZIP) / 100));
  }
  sizeTargetsResolved = true;
}

// ---------------------------------------------------------------------- 辅助
const COUNTERMEASURE_NAME = '__bpbFail';

/** 校验锁失败必须响亮，但绝不能把 isolate 卡死（不能 while(true){}）。 */
const COUNTERMEASURE_SOURCE = `
function ${COUNTERMEASURE_NAME}() {
  throw new Error('integrity check failed: the script was modified after build');
}
`;

function readSensitiveWords() {
  try {
    return readFileSync(join(ROOT, 'sensitive_words_auto.txt'), 'utf-8')
      .split('\n')
      .map((w) => w.trim().toLowerCase())
      .filter(Boolean);
  } catch {
    return ['bpb', 'vless', 'trojan'];
  }
}
const sensitiveWords = readSensitiveWords();

// --------------------------------------------------------------------- 流水线
const key = randomKey();
const codec = makeCodec(key);

// 密文运行时是在 js-confuser 跑完之后追加到产物尾部的，混淆后的代码以**未绑定的全局标识符**
// 引用它。两个原因：
//
//  1. js-confuser 的 stringConcealing 连属性名一起隐藏，解码器如果活在 AST 里，
//     就得先解码自己的载荷才能解码任何东西 —— 无限递归。
//  2. 在模块里没有绑定的标识符不会被 renameVariables 改名，所以事后声明的函数仍然能绑上。
//
// 函数声明会提升，ChaCha20 密钥写在函数体内，因此从模块初始化那一刻起就可调用。
const helperName = randomHelperName();
const keyStreamName = randomHelperName();
const runtimeSuffix = buildDecoderSource(key, { ks: keyStreamName, dec: helperName });

/**
 * 解码器源码压成单行。它没有 `//` 行注释，字符串字面量只有空串/方法名，
 * 因此把换行换成空格、合并缩进是安全的；verify/smoke 会兜底。
 */
function compactRuntime(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '') // 保险：去掉块注释
    .replace(/\r?\n/g, ' ')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();
}
const runtimeSuffixInline = compactRuntime(runtimeSuffix);

const sourceCode = readFileSync(INPUT_PATH, 'utf8');

// 只有 integrity 的反制函数必须存在于 AST 中（Lock 插件按名字查找它）。
// 它的错误消息字符串和其他字符串一样会被隐藏 —— 现在解码器不再依赖载荷数组，这是安全的。
let prepared = sourceCode;
if (CONFIG.integrity || CONFIG.antiDebug || CONFIG.selfDefending) {
  prepared = `${COUNTERMEASURE_SOURCE}\n${prepared}`;
}

/** 敏感词永远隐藏（不受 min/max 长度影响），保证 verify 的禁止词闸门。 */
function isSensitiveString(str) {
  const lower = str.toLowerCase();
  return sensitiveWords.some((word) => lower.includes(word));
}

/** 按体积预算参数生成 stringConcealing 谓词。 */
function makeConcealPredicate(cfg) {
  return (str) => {
    if (isSensitiveString(str)) return true;
    if (cfg.maxConcealedLength > 0 && str.length > cfg.maxConcealedLength) return false;
    if (str.length < cfg.minConcealedLength) return false;
    return CONFIG.concealAllStrings;
  };
}

function buildOptions(cfg) {
  return {
  target: 'browser',

  // 字符串密文必需
  stringConcealing: makeConcealPredicate(cfg),
  customStringEncodings: [
    {
      code: `function {fnName}(str) { return ${helperName}(str); }`,
      encode: (str) => codec.encode(str),
      decode: (str) => codec.decode(str),
    },
  ],

  // 标识符 / 结构混淆
  renameVariables: CONFIG.renameVariables,
  renameGlobals: CONFIG.renameGlobals,
  renameLabels: true,
  identifierGenerator: CONFIG.identifierGenerator,
  movedDeclarations: CONFIG.movedDeclarations,
  objectExtraction: CONFIG.objectExtraction,
  compact: true,
  hexadecimalNumbers: true,
  astScrambler: CONFIG.astScrambler,

  // 有意关闭：在本产物上没有收益，且会消耗 Workers 的 CPU / 体积预算
  calculator: false,
  deadCode: false,
  dispatcher: false,
  duplicateLiteralsRemoval: false,
  flatten: false,
  preserveFunctionLength: false,
  stringSplitting: false,
  stringCompression: false,
  globalConcealing: false,
  shuffle: false,
  variableMasking: false,
  minify: CONFIG.minify,
  rgf: false,

  // 加固（概率，见文件头 HARDENING）
  opaquePredicates: cfg.opaquePredicates,
  controlFlowFlattening: CONFIG.controlFlowFlattening,

  lock: {
    integrity: CONFIG.integrity,
    // 良性反制：被改过的脚本响亮报错，而不是在 while(true){} 里空转烧掉 isolate。
    countermeasures:
      CONFIG.integrity || CONFIG.antiDebug || CONFIG.selfDefending
        ? COUNTERMEASURE_NAME
        : undefined,
    antiDebug: CONFIG.antiDebug,
    selfDefending: CONFIG.selfDefending,
    tamperProtection: false, // 需要非严格模式；本产物是 ES 模块
  },
  };
}

// ------------------------------------------------------------ 体积预算搜索
// 主导旋钮是 minConcealedLength（数字面量/属性名数量约 13.5k），其次 maxConcealedLength
// （可把 26KB 的页面 gzip blob 留在明文）；opaque/ast 等对体积影响很小，这里不动它们。
async function zipSize(code) {
  const { default: JSZip } = await import('jszip');
  const zip = new JSZip();
  zip.file('_worker.js', code);
  const buffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
  return buffer.length;
}

const baseCfg = {
  minConcealedLength: CONFIG.minConcealedLength,
  maxConcealedLength: CONFIG.maxConcealedLength,
  opaquePredicates: CONFIG.opaquePredicates,
};

const attempts = [];
const candidateCache = new Map();
let runs = 0;

async function runCandidate(cfg) {
  const cacheKey = `${cfg.minConcealedLength}:${cfg.maxConcealedLength}`;
  if (candidateCache.has(cacheKey)) return candidateCache.get(cacheKey);
  const startedAt = Date.now();
  const result = await JsConfuser.obfuscate(prepared, buildOptions(cfg));
  // 追加密文运行时。它**故意不参与混淆**：它绝不能依赖它所解码的那个载荷数组。
  if (CONFIG.oneLine && result.code.includes('\n')) {
    throw new Error('js-confuser 的 compact 输出不是单行 —— 请设 HARDEN_MINIFY=false 并检查 compact 选项');
  }
  const code = CONFIG.oneLine
    ? `${result.code};${runtimeSuffixInline}\n`
    : `${result.code}\n${runtimeSuffix}\n`;
  const metrics = {
    minConcealedLength: cfg.minConcealedLength,
    maxConcealedLength: cfg.maxConcealedLength,
    opaquePredicates: cfg.opaquePredicates,
    rawBytes: code.length,
    zipBytes:
      SIZE_TARGET_ZIP > 0 || SIZE_PERCENT_ZIP !== null ? await zipSize(code) : null,
    ms: Date.now() - startedAt,
  };
  runs += 1;
  attempts.push(metrics);
  console.log(
    `  体积候选 #${runs}: min=${cfg.minConcealedLength} max=${cfg.maxConcealedLength}` +
      ` -> ${metrics.rawBytes} B${metrics.zipBytes !== null ? ` / zip ${metrics.zipBytes} B` : ''}` +
      `${fits(metrics) ? ' ✅' : ''}`
  );
  const candidate = { code, cfg, metrics };
  candidateCache.set(cacheKey, candidate);
  return candidate;
}

function fits(metrics) {
  if (!sizeTargetsResolved) return false;
  if (SIZE_TARGET_RAW > 0 && metrics.rawBytes > SIZE_TARGET_RAW) return false;
  if (SIZE_TARGET_ZIP > 0 && metrics.zipBytes !== null && metrics.zipBytes > SIZE_TARGET_ZIP) {
    return false;
  }
  return true;
}

async function tryCandidate(cfg) {
  if (runs >= SIZE_MAX_RUNS && !candidateCache.has(`${cfg.minConcealedLength}:${cfg.maxConcealedLength}`)) {
    const last = attempts[attempts.length - 1];
    throw new Error(
      `体积预算搜索已达上限 ${SIZE_MAX_RUNS} 次（HARDEN_SIZE_MAX_RUNS）；最后一次 ${last.rawBytes} B` +
        `${last.zipBytes !== null ? ` / zip ${last.zipBytes} B` : ''}，仍未达到目标。` +
        '放宽目标，或用 HARDEN_MIN_STRING / HARDEN_MAX_STRING 手动取舍，或增大 HARDEN_SIZE_MAX_RUNS。'
    );
  }
  return runCandidate(cfg);
}

let chosen;
if (!SIZE_SEARCH) {
  chosen = await runCandidate(baseCfg);
} else {
  const targetLabel = [
    SIZE_RAW_SPEC ? `worker.js<=${formatSizeSpec(SIZE_RAW_SPEC)}` : '',
    SIZE_ZIP_SPEC ? `worker.zip<=${formatSizeSpec(SIZE_ZIP_SPEC)}` : '',
  ]
    .filter(Boolean)
    .join('，');
  console.log(`体积预算：${targetLabel}（最多 ${SIZE_MAX_RUNS} 次混淆）`);

  const first = await tryCandidate(baseCfg);
  resolvePercentTargets(first.metrics);
  if (SIZE_PERCENT_RAW !== null || SIZE_PERCENT_ZIP !== null) {
    console.log(
      `  百分比目标解析（以首次产物为基准）：` +
        [
          SIZE_TARGET_RAW > 0 ? `worker.js<=${SIZE_TARGET_RAW}B` : '',
          SIZE_TARGET_ZIP > 0 ? `worker.zip<=${SIZE_TARGET_ZIP}B` : '',
        ]
          .filter(Boolean)
          .join('，')
    );
  }
  if (fits(first.metrics)) {
    chosen = first;
  } else {
    // 先按 min 翻倍找到达标点，再二分找「刚好达标」的最小 min（尽量保留混淆）。
    // 搜索下界不低过用户显式设置的 HARDEN_MIN_STRING。
    const minFloor = Math.max(1, baseCfg.minConcealedLength);
    let hi = null;
    let hiResult = null;
    for (const min of [4, 8, 16, 32, 64, 96, 128].filter((value) => value > baseCfg.minConcealedLength)) {
      const candidate = await tryCandidate({ ...baseCfg, minConcealedLength: min });
      if (fits(candidate.metrics)) {
        hi = min;
        hiResult = candidate;
        break;
      }
    }

    if (hi !== null) {
      chosen = hiResult;
      let lo = minFloor;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        const candidate = await tryCandidate({ ...baseCfg, minConcealedLength: mid });
        if (fits(candidate.metrics)) {
          hi = mid;
          chosen = candidate;
        } else {
          lo = mid + 1;
        }
      }
    } else {
      // 短字符串全隐藏仍超标 → 再把大字符串（页面 gzip blob）排除
      const maxCandidates = baseCfg.maxConcealedLength > 0
        ? [baseCfg.maxConcealedLength]
        : [65536, 32768, 16384, 8192, 4096, 2048];
      for (const max of maxCandidates) {
        const highMin = Math.max(64, baseCfg.minConcealedLength);
        const candidate = await tryCandidate({
          ...baseCfg,
          minConcealedLength: highMin,
          maxConcealedLength: max,
        });
        if (!fits(candidate.metrics)) continue;
        chosen = candidate;
        // 同一 max 下再二分找更小的 min，尽量多隐藏一些字符串
        let lo = minFloor;
        let hiMin = highMin;
        while (lo < hiMin) {
          const mid = (lo + hiMin) >> 1;
          const refined = await tryCandidate({
            ...baseCfg,
            minConcealedLength: mid,
            maxConcealedLength: max,
          });
          if (fits(refined.metrics)) {
            hiMin = mid;
            chosen = refined;
          } else {
            lo = mid + 1;
          }
        }
        break;
      }
      if (!chosen) {
        const last = attempts[attempts.length - 1];
        throw new Error(
          `体积预算无法满足（${targetLabel}）；最后一次 ${last.rawBytes} B` +
            `${last.zipBytes !== null ? ` / zip ${last.zipBytes} B` : ''}。` +
            '可放宽目标，或用 HARDEN_MIN_STRING / HARDEN_MAX_STRING 手动取舍，' +
            '或增大 HARDEN_SIZE_MAX_RUNS。'
        );
      }
    }
  }
}

const effective = {
  ...CONFIG,
  minConcealedLength: chosen.cfg.minConcealedLength,
  maxConcealedLength: chosen.cfg.maxConcealedLength,
  opaquePredicates: chosen.cfg.opaquePredicates,
};
const output = chosen.code;
const elapsedMs = attempts.length ? attempts.reduce((sum, item) => sum + item.ms, 0) : 0;
writeFileSync(OUTPUT_PATH, output);

mkdirSync(dirname(REPORT_PATH), { recursive: true });
writeFileSync(
  REPORT_PATH,
  JSON.stringify(
    {
      keyBase64: keyToBase64(key),
      cipher: 'chacha20-rfc8439',
      nonceBytesPerString: 8,
      helperName,
      keyStreamName,
      config: effective,
      sensitiveWords: CONFIG.concealAllStrings ? undefined : sensitiveWords,
      sourceBytes: sourceCode.length,
      outputBytes: output.length,
      zipBytes: chosen.metrics.zipBytes,
      obfuscateMs: elapsedMs,
      sizeSearch: SIZE_SEARCH
        ? {
            configFile: BUILD_PARAMS.params.configPath,
            targets: {
              raw: formatSizeSpec(SIZE_RAW_SPEC) || undefined,
              zip: formatSizeSpec(SIZE_ZIP_SPEC) || undefined,
              resolvedRawBytes: SIZE_TARGET_RAW || undefined,
              resolvedZipBytes: SIZE_TARGET_ZIP || undefined,
            },
            runs,
            selected: {
              minConcealedLength: chosen.cfg.minConcealedLength,
              maxConcealedLength: chosen.cfg.maxConcealedLength,
            },
            attempts,
          }
        : undefined,
      input: INPUT_PATH,
      output: OUTPUT_PATH,
      generatedAt: new Date().toISOString(),
    },
    null,
    2
  )
);

console.log(
  `js-confuser + ChaCha20 完成：${sourceCode.length} -> ${output.length} 字节` +
    `${chosen.metrics.zipBytes !== null ? `（zip ${chosen.metrics.zipBytes}）` : ''}，` +
    `${elapsedMs} ms，混淆 ${runs} 次，${CONFIG.oneLine ? '单行' : '多行解码器'}` +
    `（字符串=${CONFIG.concealAllStrings ? (effective.maxConcealedLength ? `全部<=${effective.maxConcealedLength}` : '全部') : '仅敏感词'}` +
    `, min=${effective.minConcealedLength}, max=${effective.maxConcealedLength}` +
    `, opaque=${effective.opaquePredicates}, cff=${CONFIG.controlFlowFlattening}, integrity=${CONFIG.integrity}）`
);
