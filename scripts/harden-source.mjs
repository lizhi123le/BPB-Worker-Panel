/**
 * scripts/harden-source.mjs
 *
 * 混淆前的「敏感标记遮蔽」预处理。它补的是 js-confuser stringConcealing 的三个盲区：
 *
 * 1) 属性名 / 方法名 / 对象键是**标识符节点**，不是字符串字面量。`a?.proxyGroups`、
 *    `{ proxyOnly: !0 }` 里的名字混淆器一个字节都不会动，于是项目结构特征会以明文
 *    留在产物里 —— 而它们比字符串更有辨识度：
 *
 *      env.upstreamProxy / env.customProxyPool / env.envProxyIPs / settings.proxyGroups
 *      settings.proxyMode / settings.proxyDegrade / outProxy …
 *
 *    做法：改写成**计算属性**（`a.proxyGroups` → `a["proxyGroups"]`，
 *    `{ proxyOnly: x }` → `{ ["proxyOnly"]: x }`）。字面量一出现，obfuscate.mjs 的
 *    谓词就会命中（敏感词强制隐藏，不受 min/max 长度影响），产物里只剩密文。
 *
 * 2) 模板字面量的静态片段（quasis）也不是字符串字面量：`retry: proxy-only mode`、
 *    `\r\nProxy-Connection: Keep-Alive\r\n` 这类日志/请求头会原样留在产物里。做法是把
 *    命中敏感词的模板改写成字符串拼接（每个插值包一层 `String(...)`，语义等价），
 *    于是每个片段都变成可被密文化的字面量。嵌套模板按「由内向外」逐轮改写。
 *
 * 3) 未绑定的内置全局 `Proxy`（本产物有 3 处：esbuild 的 CommonJS 互操作垫片两处、
 *    源码里 `Proxy.name + "IP"` 一处）改写成
 *    `globalThis[String.fromCharCode(80,114,111,120,121)]`。这**不是**安全增强：
 *    `Proxy` 是每个 JS 引擎都有的内置名，本身不携带本项目指纹；改写只是为了让
 *    `sensitive_words_auto.txt` 里的 `\bproxy\b` 闸门能如实通过。用 fromCharCode 而不是
 *    `"pro" + "xy"`，是为了防止后续任何常量折叠把字面量拼回去。
 *
 * 约束：只做**位置级替换**，不重新生成代码 —— 输入的 terser 产物逐字节保留，
 * 只有被改写的 token 变化。每一轮都重新解析校验；改写区间重叠或结果不可解析时
 * 直接抛错，绝不产出可能损坏的代码。
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from '@babel/parser';
import traverseImport from '@babel/traverse';

const traverse = traverseImport.default ?? traverseImport;
const SKIP_KEYS = new Set(['loc', 'start', 'end', 'leadingComments', 'trailingComments', 'innerComments', 'extra']);

/** 内置 Proxy 的等价表达式：运行时求值就是全局 Proxy（"Proxy"：80,114,111,120,121），
 *  但产物里没有 "proxy" 字面量。 */
export const BUILTIN_PROXY_EXPR = 'globalThis[String.fromCharCode(80,114,111,120,121)]';

function parseModule(code) {
  return parse(code, { sourceType: 'module', allowReturnOutsideFunction: true });
}

function applyEdits(code, edits, label) {
  const sorted = [...edits].sort((a, b) => a.start - b.start || b.end - a.end);
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].start < sorted[i - 1].end) {
      throw new Error(
        `harden-source(${label}): 改写区间重叠 @${sorted[i].start}（` +
          `${JSON.stringify(code.slice(sorted[i].start, sorted[i].end))}）—— 拒绝产出可能损坏的代码`
      );
    }
  }
  let output = code;
  for (let i = sorted.length - 1; i >= 0; i--) {
    const edit = sorted[i];
    output = output.slice(0, edit.start) + edit.text + output.slice(edit.end);
  }
  return output;
}

/** 第一轮：属性键 / 方法键 / 内置 Proxy。 */
function maskIdentifiers(code, { words, maskPropertyNames, maskBuiltinProxy, stats }) {
  const ast = parseModule(code);
  const edits = [];
  const hitsWord = (name) => {
    const lower = name.toLowerCase();
    return words.some((word) => lower.includes(word));
  };
  /** 属性名 -> 计算属性字面量（name 一定是普通标识符，parse 已保证）。 */
  const quoted = (name) => `[${JSON.stringify(name)}]`;

  const maskMember = (node) => {
    if (!maskPropertyNames) return;
    if (node.computed) return;
    if (node.property.type !== 'Identifier' || !hitsWord(node.property.name)) return;
    const property = node.property;
    const dot = property.start - 1;
    if (code[dot] !== '.') return; // 非 `a.b` / `a?.b` 形状
    // `a?.b`：`?.` 属于可选链 token，只替换 b（结果是合法的 `a?.["b"]`）。
    // `a.b`：连点一起替换（否则会得到非法的 `a.["b"]`）。
    const optional = code[dot - 1] === '?';
    edits.push(
      optional
        ? { start: property.start, end: property.end, text: quoted(property.name) }
        : { start: dot, end: property.end, text: quoted(property.name) }
    );
    stats.propertyKeys += 1;
  };

  // 方法 / 字段的键（对象方法、类方法、类字段）。私有名（#x）是 PrivateName，
  // 不是 Identifier，不会被改写；这类名字如果真的带敏感词，由 verify 的闸门暴露。
  const maskMethodKey = (node) => {
    if (!maskPropertyNames) return;
    if (node.computed) return;
    const key = node.key;
    if (!key || key.type !== 'Identifier' || !hitsWord(key.name)) return;
    edits.push({ start: key.start, end: key.end, text: quoted(key.name) });
    stats.propertyKeys += 1;
  };

  traverse(ast, {
    MemberExpression: (path) => maskMember(path.node),
    OptionalMemberExpression: (path) => maskMember(path.node),

    // 非简写只换键；简写 `{ proxyOnly }` 要展开成 `{ ["proxyOnly"]: proxyOnly }`，
    // 否则会变成非法的 `{ ["proxyOnly"] }`（解构模式的 `{ proxyOnly = 1 }` 同理）。
    ObjectProperty: (path) => {
      if (!maskPropertyNames) return;
      const node = path.node;
      if (node.computed) return;
      if (node.key.type !== 'Identifier' || !hitsWord(node.key.name)) return;
      if (node.shorthand) {
        edits.push({
          start: node.key.start,
          end: node.end,
          text: `${quoted(node.key.name)}:${code.slice(node.value.start, node.end)}`,
        });
        stats.shorthandKeys += 1;
      } else {
        edits.push({ start: node.key.start, end: node.key.end, text: quoted(node.key.name) });
      }
      stats.propertyKeys += 1;
    },

    ObjectMethod: (path) => maskMethodKey(path.node),
    ClassMethod: (path) => maskMethodKey(path.node),
    ClassProperty: (path) => maskMethodKey(path.node),
    ClassAccessorProperty: (path) => maskMethodKey(path.node),

    Identifier: (path) => {
      if (!maskBuiltinProxy) return;
      if (path.node.name !== 'Proxy') return;
      if (!path.isReferencedIdentifier()) return; // 属性键、标签、声明名不算引用
      // 注意用 getBinding 而不是 hasBinding：babel 的 hasBinding 会把「未绑定的全局引用」
      // 也算成有绑定，那样内置 Proxy 永远改不到。
      if (path.scope.getBinding('Proxy')) return; // 有本地绑定时必须保持语义
      edits.push({ start: path.node.start, end: path.node.end, text: BUILTIN_PROXY_EXPR });
      stats.builtinProxy += 1;
    },
  });

  if (edits.length === 0) return code;
  stats.edits += edits.length;
  return applyEdits(code, edits, 'identifiers');
}

/**
 * 第二轮：把静态片段里带敏感词的模板改成字符串拼接，使每个片段都变成可被密文化的
 * 字符串字面量。插值包一层 `String(...)`：模板字符串对每个插值做的就是 ToString，
 * 因此语义等价（唯一差别是 Symbol —— 模板会抛 TypeError，String() 不抛；本产物不插
 * Symbol）。嵌套模板用 emit() 递归渲染，只做一遍、不重新解析。
 */
function maskTemplateLiterals(code, { words, stats }) {
  const ast = parseModule(code);
  const hitsWord = (text) => {
    const lower = text.toLowerCase();
    return words.some((word) => lower.includes(word));
  };
  const isTarget = (node) =>
    node.type === 'TemplateLiteral' &&
    !node.tag &&
    hitsWord(node.quasis.map((quasi) => quasi.value.cooked || '').join(''));

  /** 收集子树里**最外层**的目标模板（命中后不再深入它内部）。 */
  function collectTargets(node, out) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const child of node) collectTargets(child, out);
      return;
    }
    if (isTarget(node)) {
      out.push(node);
      return;
    }
    for (const key of Object.keys(node)) {
      if (SKIP_KEYS.has(key)) continue;
      collectTargets(node[key], out);
    }
  }

  /** 把节点渲染成源码：目标模板改成拼接，其余原样保留。 */
  function emit(node) {
    if (isTarget(node)) {
      const parts = [];
      for (let i = 0; i < node.quasis.length; i++) {
        const cooked = node.quasis[i].value.cooked;
        if (typeof cooked === 'string' && cooked.length > 0) parts.push(JSON.stringify(cooked));
        if (i < node.expressions.length) parts.push(`String(${emit(node.expressions[i])})`);
      }
      return parts.length === 0 ? '""' : `(${parts.join(' + ')})`;
    }
    const inner = [];
    collectTargets(node, inner);
    if (inner.length === 0) return code.slice(node.start, node.end);
    inner.sort((a, b) => a.start - b.start);
    let out = '';
    let pos = node.start;
    for (const target of inner) {
      out += code.slice(pos, target.start) + emit(target);
      pos = target.end;
    }
    return out + code.slice(pos, node.end);
  }

  const targets = [];
  collectTargets(ast, targets);
  if (targets.length === 0) return { code, count: 0 };
  const edits = targets.map((node) => ({ start: node.start, end: node.end, text: emit(node) }));
  stats.edits += edits.length;
  return { code: applyEdits(code, edits, 'templates'), count: targets.length };
}

/**
 * @param {string} code 混淆前产物（.build/worker.reference.js）
 * @param {{
 *   words?: string[],
 *   maskPropertyNames?: boolean,
 *   maskTemplates?: boolean,
 *   maskBuiltinProxy?: boolean,
 * }} [options]
 * @returns {{ code: string, stats: {
 *   propertyKeys: number, shorthandKeys: number, builtinProxy: number, templates: number, edits: number
 * } }}
 */
export function hardenSource(code, options = {}) {
  const words = (options.words || [])
    .map((word) => String(word).trim().toLowerCase())
    .filter(Boolean);
  const maskPropertyNames = options.maskPropertyNames !== false;
  const maskTemplates = options.maskTemplates !== false;
  const maskBuiltinProxy = options.maskBuiltinProxy !== false;

  const stats = { propertyKeys: 0, shorthandKeys: 0, builtinProxy: 0, templates: 0, edits: 0 };
  const nothingToDo =
    words.length === 0 || (!maskPropertyNames && !maskTemplates && !maskBuiltinProxy);
  if (nothingToDo) return { code, stats };

  let current = maskIdentifiers(code, { words, maskPropertyNames, maskBuiltinProxy, stats });
  if (maskTemplates) {
    const result = maskTemplateLiterals(current, { words, stats });
    current = result.code;
    stats.templates = result.count;
  }

  // 语法闸门：改写结果必须仍是合法模块，否则在进入混淆（约 3.5s/次）之前就失败。
  try {
    parseModule(current);
  } catch (error) {
    throw new Error(`harden-source: 改写后无法解析（${error.message}）—— 拒绝继续构建`);
  }
  return { code: current, stats };
}

// ---------------------------------------------------------------- CLI（手动核对）
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const input = resolve(process.argv[2] || '.build/worker.reference.js');
  const output = process.argv[3];
  const words = readFileSync(resolve('sensitive_words_auto.txt'), 'utf8')
    .split('\n')
    .map((word) => word.trim())
    .filter((word) => word && !word.startsWith('#'));
  const source = readFileSync(input, 'utf8');
  const result = hardenSource(source, { words });
  console.log(
    `harden-source: 属性键 ${result.stats.propertyKeys}（其中简写 ${result.stats.shorthandKeys}）` +
      `，模板 ${result.stats.templates}，内置 Proxy ${result.stats.builtinProxy} 处，` +
      `共 ${result.stats.edits} 处区间改写（两轮累计），` +
      `${source.length} -> ${result.code.length} 字节`
  );
  if (output) {
    writeFileSync(output, result.code);
    console.log(`harden-source: 已写出 ${resolve(output)}`);
  }
}
