/**
 * scripts/verify.mjs
 *
 * 构建后静态闸门。运行：node scripts/verify.mjs [产物] [参考]
 *
 * 默认值：产物 = dist/worker.js，参考 = .build/worker.reference.js
 *
 * 检查项
 *  1. 产物能作为 ES 模块解析，并且仍然导出 default（否则 Worker 根本加载不起来）。
 *  2. 混淆前存在的每一条字符串都仍然可恢复：要么还是明文，要么能从 ChaCha20
 *     载荷数组里解出来。这是"没有功能数据丢失"的证明。
 *  3. 硬性禁止词（sensitive_words_auto.txt）不得以明文幸存。扫描前会先把 \xNN 转义
 *     还原、并把密文块挖空，所以"拆成单字符转义"这种伪隐藏也逃不掉，而随机 base64
 *     也不会造成误报。
 *  4. 构建期密钥确实就是产物里那把密钥（往返探测）。
 *  5. 产物里那一段追加的解码器可以独立求值，并能解开产物里的密文
 *     —— 证明"构建期加密"和"线上解密"没有漂移。
 *  6. 注入的运行时标识符没有被改名掉（指纹 < 0）。
 *  7. 自遮蔽初始化器：`var x = ... x(...) ...`（integrity 包装器可能产生的形态），
 *     局部 x 被提升为 undefined，调用它必然抛 TypeError。
 *
 * 没有参考文件时（例如审计一个下载来的 zip），1-3-4-5-6 仍然会跑。
 */

import { readFileSync, existsSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';
import { parse } from '@babel/parser';
import { makeCodec, keyFromBase64, KS_NAME, DEC_NAME } from '../tools/cipher.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ARTIFACT = resolve(ROOT, process.argv[2] || 'dist/worker.js');
const REFERENCE = resolve(ROOT, process.argv[3] || '.build/worker.reference.js');
const REPORT = join(ROOT, '.build/last-build.json');

let failures = 0;
let warnings = 0;
const pass = (m) => console.log('  PASS  ' + m);
const fail = (m) => {
  failures++;
  console.log('  FAIL  ' + m);
};
const warn = (m) => {
  warnings++;
  console.log('  WARN  ' + m);
};

// ------------------------------------------------------------------ AST 工具
const SKIP_KEYS = new Set(['loc', 'start', 'end', 'range', 'leadingComments', 'trailingComments', 'innerComments', 'extra']);

function walk(node, visit) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const child of node) walk(child, visit);
    return;
  }
  if (typeof node.type === 'string') visit(node);
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = node[key];
    if (value && typeof value === 'object') walk(value, visit);
  }
}

function collectStrings(source) {
  const ast = parse(source, { sourceType: 'module', allowReturnOutsideFunction: true });
  const specifiers = new Set();
  const strings = new Set();

  walk(ast, (node) => {
    if (node.type === 'ImportDeclaration' || node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') {
      if (node.source && typeof node.source.value === 'string') specifiers.add(node.source.value);
    }
  });

  walk(ast, (node) => {
    if (node.type === 'StringLiteral' && typeof node.value === 'string') {
      // import 说明符不能被藏起来，任何构建器都会原样保留它，所以不计入覆盖统计。
      if (!specifiers.has(node.value)) strings.add(node.value);
    }
  });

  return { ast, strings };
}

// ------------------------------------------------------------------- 自检
if (!existsSync(ARTIFACT)) {
  console.log(`verify: 找不到产物 ${ARTIFACT}`);
  process.exit(1);
}

const artifact = readFileSync(ARTIFACT, 'utf8');
console.log(`verify: ${ARTIFACT} (${artifact.length} bytes)`);

// 1. 语法 + default 导出
let artifactStrings;
let artifactAst = null;
try {
  const parsed = collectStrings(artifact);
  artifactStrings = parsed.strings;
  artifactAst = parsed.ast;
  const hasDefault = parsed.ast.program.body.some(
    (n) =>
      n.type === 'ExportDefaultDeclaration' ||
      (n.type === 'ExportNamedDeclaration' && n.specifiers?.some((s) => (s.exported?.name || s.exported?.value) === 'default'))
  );
  hasDefault ? pass('可作为 ES 模块解析，并且导出了 default') : fail('找不到 default 导出（Worker 无法加载）');
} catch (error) {
  fail('产物无法解析: ' + error.message);
  artifactStrings = new Set();
}

// 3. 对照混淆前参考的覆盖检查（先加载，下面的载荷识别也要用它）
//
// 参考文件是"同一份 esbuild/terser 产物、只是没混淆"，所以它同时能证明某段明文是真实存在
// 过的：像 JSZip 的 "PK\x03\x04"、全零缓冲这种含控制字符的二进制型字符串，光靠"可打印性"
// 是筛不出来的，但参考文件里确实有它们。
let refStrings = null;
if (existsSync(REFERENCE)) {
  try {
    refStrings = collectStrings(readFileSync(REFERENCE, 'utf8')).strings;
  } catch (error) {
    fail('参考文件无法解析: ' + error.message);
    refStrings = new Set();
  }
} else {
  warn(`参考文件 ${REFERENCE} 不存在 —— 跳过覆盖检查`);
}

// 4. 密钥往返
let ciphertexts = new Set();
let decoded = new Set();
let report = null;
let codec = null;

// 构建报告只对它自己那一份产物有效；对不上就退化成审计模式。
if (existsSync(REPORT)) {
  const parsed = JSON.parse(readFileSync(REPORT, 'utf8'));
  if (typeof parsed.outputBytes === 'number' && parsed.outputBytes !== artifact.length) {
    warn(`构建报告描述的是另一份产物（${parsed.outputBytes} vs ${artifact.length} 字节）—— 忽略它`);
  } else {
    report = parsed;
  }
}

if (!report) {
  // 审计模式（构建报告已丢失，例如审计下载来的 zip）。密钥就随产物发布，所以逐个尝试
  // 文件里的 32 字节数组，取能解开最多载荷字面量的那一把。
  const candidates = artifact.match(/\[\d{1,3}(?:,\d{1,3}){31}\]/g) || [];
  let best = null;
  for (const literal of candidates) {
    const key = Uint8Array.from(literal.slice(1, -1).split(',').map(Number));
    if (key.length !== 32 || key.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) continue;
    const attempt = makeCodec(key);
    let hits = 0;
    for (const value of artifactStrings) {
      if (value.length < 16 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) continue;
      try {
        if (!attempt.decode(value).includes('\ufffd')) hits++;
      } catch {
        /* 不是载荷字面量 */
      }
    }
    if (!best || hits > best.hits) best = { key, codec: attempt, hits };
  }
  if (best && best.hits > 20) {
    codec = best.codec;
    warn(`没有构建报告：已从产物中恢复密钥（${candidates.length} 个候选数组，${best.hits} 条载荷可解）`);
  } else {
    fail(`没有构建报告，也恢复不出可用密钥（${candidates.length} 个候选数组）`);
  }
} else {
  codec = makeCodec(keyFromBase64(report.keyBase64));
}

if (codec) {
  const probe = 'probe-\u4e2d\u6587-\ud83d\ude0e';
  if (codec.decode(codec.encode(probe)) === probe) {
    pass('ChaCha20 编解码往返正常');
  } else {
    fail('ChaCha20 编解码往返被打断');
  }

  // 2. 解开每一条载荷字面量
  const printable = /^[\t\n\r\x20-\x7e\u00a0-\uffff]*$/;
  const provenReal = (s) => printable.test(s) || (refStrings ? refStrings.has(s) : false);
  let tried = 0;
  for (const literal of artifactStrings) {
    if (literal.length < 16) continue;
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(literal)) continue;
    tried++;
    let plain;
    try {
      plain = codec.decode(literal);
    } catch {
      continue;
    }
    if (plain.includes('\ufffd')) continue;
    if (plain.length < 3) continue;
    if (!provenReal(plain)) continue;
    ciphertexts.add(literal);
    decoded.add(plain);
  }
  if (ciphertexts.size === 0) {
    fail(`在 ${tried} 条候选字面量里一条 ChaCha20 载荷都解不出来`);
  } else {
    pass(`${ciphertexts.size} 条被隐藏的字符串可用产物自带密钥解开`);
  }
}

// 5. 产物里的解码器本体：独立求值 + 交叉解密
{
  const helperName =
    report?.helperName ||
    (artifact.match(/function\s+(_0x[0-9a-f]{6,10})\s*\(/g) || []).pop()?.replace(/^function\s+/, '').replace(/\s*\($/, '');
  const keyStreamName = report?.keyStreamName;

  if (helperName) {
    const declared = artifact.includes(`function ${helperName}(`);
    const references = (artifact.match(new RegExp(`\\b${helperName}\\(`, 'g')) || []).length;
    if (declared && references >= 2) {
      pass(`密文运行时 "${helperName}" 已声明并被引用（${references - 1} 处调用）`);
    } else {
      fail(`密文运行时 "${helperName}" 缺失（declared=${declared}, 调用点=${references - 1}）`);
    }
    const stray = new RegExp(`\\b(${KS_NAME}|${DEC_NAME}|__bpbENC|__bpbFail)\\b`).test(artifact);
    stray ? fail('构建内部运行时名泄露到了产物里') : pass('产物里没有构建内部运行时名');

    // 把追加在文件尾部的运行时代码切出来，直接求值，用它解开产物里的一条密文。
    if (ciphertexts.size > 0) {
      const anchor = keyStreamName ? `function ${keyStreamName}(` : `function ${helperName}(`;
      let start = artifact.indexOf(anchor);
      if (start < 0) start = artifact.indexOf(`function ${helperName}(`);
      if (start >= 0) {
        const runtimeSource = artifact.slice(start);
        try {
          const decode = new Function(runtimeSource + `\nreturn ${helperName};`)();
          const literal = [...ciphertexts][0];
          const viaShipped = decode(literal);
          const viaBuild = codec.decode(literal);
          if (viaShipped === viaBuild && viaShipped.length > 0) {
            pass('产物内解码器可独立求值，解出的明文与构建期一致');
          } else {
            fail('产物内解码器解出的明文与构建期不一致（编码/解码漂移）');
          }
        } catch (error) {
          fail('产物内解码器无法求值: ' + error.message);
        }
      } else {
        warn('定位不到追加的运行时源码，跳过解码器独立求值');
      }
    }
  } else {
    warn('无法确定密文运行时函数名，跳过运行时检查');
  }
}

// 3b. 覆盖统计（参考字符串已在上面加载）
if (refStrings) {
  const union = new Set([...artifactStrings, ...decoded]);
  const missing = [];
  for (const value of refStrings) {
    if (value.length < 3) continue; // js-confuser 从不隐藏这么短的字符串
    if (!union.has(value)) missing.push(value);
  }
  if (missing.length === 0) {
    pass(`参考里的 ${refStrings.size} 条字符串全部可恢复（没有数据丢失）`);
  } else {
    fail(`${missing.length} 条参考字符串在产物里找不回来，例如 ${JSON.stringify(missing.slice(0, 3))}`);
  }
}

// 3b. 明文泄露（先把 \xNN 转义还原、再把密文块挖空）
function readList(name, fallback) {
  try {
    return readFileSync(join(ROOT, name), 'utf-8');
  } catch {
    return fallback;
  }
}

const unescape = (s) =>
  s
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

const bannedWords = readList('sensitive_words_auto.txt', 'bpb\nvless\ntrojan\n')
  .split('\n')
  .map((w) => w.trim())
  .filter((w) => w && !w.startsWith('#'));

let visibled = unescape(artifact);
for (const literal of ciphertexts) {
  visibled = visibled.split(JSON.stringify(literal)).join('""');
}
const leaked = bannedWords.filter((word) => new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(visibled));
if (leaked.length === 0) {
  pass(`硬性禁止词无一以明文幸存（${bannedWords.join(', ')}）`);
} else {
  fail(`禁止词以明文出现在产物里: ${leaked.join(', ')}`);
}

const manualTerms = readList('sensitive_words_manual.txt', '')
  .split('\n')
  .map((w) => w.trim())
  .filter((w) => w && !w.startsWith('#'));
const manualVisible = manualTerms.filter((term) => visibled.includes(term));
if (manualVisible.length > 0) {
  warn(`${manualVisible.length} 个观察词仍可见，例如 ${manualVisible.slice(0, 5).join(', ')}`);
} else {
  pass('观察词表里的特征串均不可见');
}

// 7. 自遮蔽初始化器
//
// 真正危险的形状是"初始化期间就会执行"的自调用，例如 js-confuser integrity 包装器生成的
//   function dJ(){var aV=dJ.aU||(dJ.aU=aV(ba,9897108)); ...}
// 局部 aV 被提升为 undefined，调用它必然抛 TypeError。
//
// 但 `var f = async (a, f) => f(a)`（参数遮蔽）与 `var s = new WritableStream({ start(){ s(...) } })`
// （回调延迟执行）都是安全的，所以只有在自调用不处于任何函数/方法/类体内、且初始化器
// 本身也不是函数时才算命中。
const DEFERRED_NODE = /Function|ObjectMethod|ClassMethod|ClassPrivateMethod/;

function callsItselfDuringInit(init, name) {
  let hit = false;
  const visit = (node, deferred) => {
    if (hit || !node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const child of node) visit(child, deferred);
      return;
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === name && !deferred) {
      hit = true;
      return;
    }
    const next = deferred || DEFERRED_NODE.test(node.type);
    for (const key of Object.keys(node)) {
      if (SKIP_KEYS.has(key)) continue;
      const value = node[key];
      if (value && typeof value === 'object') visit(value, next);
    }
  };
  visit(init, DEFERRED_NODE.test(init.type));
  return hit;
}

if (artifactAst) {
  const shadowed = [];
  walk(artifactAst, (node) => {
    if (node.type !== 'VariableDeclarator' || !node.init) return;
    if (node.id.type !== 'Identifier') return;
    if (callsItselfDuringInit(node.init, node.id.name)) shadowed.push(node.id.name);
  });
  if (shadowed.length === 0) {
    pass('没有会在初始化期间自调用的变量（integrity 包装器的经典崩法）');
  } else {
    fail(
      `${shadowed.length} 个变量在自己的初始化器里立刻调用了自己 ` +
        `(${[...new Set(shadowed)].slice(0, 5).join(', ')}) —— 被包装的函数会抛 TypeError`
    );
  }
}

console.log(
  failures === 0
    ? `verify: OK（${warnings} 条警告）`
    : `verify: ${failures} 项失败，${warnings} 条警告`
);
process.exit(failures === 0 ? 0 : 1);
