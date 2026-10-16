/**
 * tools/cipher.test.mjs
 *
 * 密码本身的守卫测试，在构建开始前执行（见 package.json 的 test:cipher / build 链）。
 * 覆盖四件事：
 *   1. ChaCha20 内核与 RFC 8439 §2.3.2 已知答案向量一致（不是"自己对自己"的往返）。
 *   2. 构建期 codec 往返无损，且同一明文两次加密产物不同（nonce 新鲜）。
 *   3. 随产物发布的解码器源码可直接求值，并能解开构建期 codec 的密文
 *      —— 保证"构建期加密"与"线上解密"不会漂移。
 *   4. 发布用解码器不含字符串字面量、不含编码器（否则 js-confuser 会把它藏起来造成自举死锁）。
 *
 * 运行：node tools/cipher.test.mjs
 */

import {
  KS_NAME,
  DEC_NAME,
  ENC_NAME,
  buildCodecSource,
  buildDecoderSource,
  makeCodec,
  randomKey,
  keyToBase64,
  keyFromBase64,
} from './cipher.mjs';

let failures = 0;
const pass = (m) => console.log('  PASS  ' + m);
const fail = (m) => {
  failures++;
  console.log('  FAIL  ' + m);
};
const check = (ok, m) => (ok ? pass(m) : fail(m));
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(' ');

// ------------------------------------------------------- 1. RFC 8439 known answer
// 原始 DJB 布局（32 位计数器 + 64 位 nonce）下，RFC 8439 §2.3.2 的 counter=1 分组
// 等价于 n8 = 00 00 00 09 00 00 00 4a，密钥 00..1f，取第 2 个 64 字节分组。
{
  const key = Uint8Array.from({ length: 32 }, (_, i) => i);
  const n8 = Uint8Array.from([0, 0, 0, 9, 0, 0, 0, 0x4a]);
  const runtime = new Function(
    buildCodecSource(key) + `;return {ks:${KS_NAME}, dec:${DEC_NAME}, enc:${ENC_NAME}};`
  )();
  const stream = runtime.ks(n8, 128);
  const second = stream.slice(64, 128);
  const expected = Uint8Array.from([
    0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
  ]);
  if (hex(second) === hex(expected)) {
    pass('ChaCha20 密钥流与 RFC 8439 §2.3.2 向量一致');
  } else {
    fail('ChaCha20 密钥流与 RFC 8439 向量不一致\n    实际: ' + hex(second) + '\n    期望: ' + hex(expected));
  }
}

// ------------------------------------------------------------------ 2. round trips
{
  const key = randomKey();
  const codec = makeCodec(key);

  const samples = [
    '',
    'a',
    'vless://11111111-2222-4333-8444-555555555555@example.com:443?type=ws#remark',
    'BPB',
    'trojan',
    'shadowsocks',
    '2026-01-01T00:00:00.000Z',
    '中文订阅名称 / 节点 01',
    '林檎と申します',
    '😀🎉🚀 mixed with ascii',
    'quotes \' " ` backtick \\ backslash \n newline \t tab',
    'x'.repeat(200000),
    Buffer.from('gzip-payload-ish').toString('base64'),
    JSON.stringify({ cleanIPs: ['104.16.0.1', '104.17.0.2'], ports: [443, 8443] }),
  ];

  let ok = true;
  let firstBad = null;
  for (const s of samples) {
    const encoded = codec.encode(s);
    const decoded = codec.decode(encoded);
    if (decoded !== s) {
      ok = false;
      firstBad = s;
      break;
    }
  }
  check(ok, `构建期 codec 往返无损（${samples.length} 个样本，含 200KB 长串、CJK、emoji）`);
  if (!ok) fail('往返失败样本: ' + JSON.stringify(String(firstBad).slice(0, 60)));

  // nonce 新鲜：同一明文两次密文必须不同，且互解正确
  const a = codec.encode('same-plaintext');
  const b = codec.encode('same-plaintext');
  check(a !== b, '同一明文两次加密得到不同密文（8 字节随机 nonce 生效）');
  check(codec.decode(a) === 'same-plaintext' && codec.decode(b) === 'same-plaintext', '两条密文都能解回原明文');

  // 密文必须是可打印 base64（否则会被转义成 \xNN，体积翻倍）
  check(/^[A-Za-z0-9+/]+={0,2}$/.test(codec.encode('中文与 emoji 😀')), '密文是纯 base64 可打印字符');
}

// ------------------------------------------- 3./4. 发布用解码器：纯度 + 交叉验证
{
  const key = randomKey();
  const helper = '_0xtestc0de';
  const ksName = '_0xtestks01';
  const shipped = buildDecoderSource(key, { ks: ksName, dec: helper });

  check(!shipped.includes('/*ENC-START*/') && !shipped.includes('ENC-START'), '发布用解码器已剥离编码器区块');
  check(!new RegExp(`\\b${ENC_NAME}\\b`).test(shipped), '发布用解码器不含编码器函数名');
  check(!/\b(__bpbKS|__bpbDEC|__bpbENC)\b/.test(shipped), '发布用解码器不含构建内部函数名');
  check(!new RegExp(`\\b${KS_NAME}\\b|\\b${DEC_NAME}\\b`).test(shipped), '发布用解码器的函数名已按构建随机化');

  // 字符串字面量检查：非空字面量一个都不允许（js-confuser 会把它们藏起来 → 自举死锁）。
  // 空串 `''`（var str = ''）放行：它不含任何信息，也不参与解码。
  const withoutComments = shipped.replace(/\/\*[\s\S]*?\*\//g, '');
  const literals = (withoutComments.match(/(['"])(?:\\.|(?!\1)[^\\])*\1/g) || []).filter((l) => l.length > 2);
  check(literals.length === 0, `发布用解码器不含非空字符串字面量（发现 ${literals.length} 个）`);
  if (literals.length) fail('发现的字面量: ' + literals.slice(0, 5).join(', '));

  // 关键交叉验证：把发布用解码器当独立模块求值，用它解构建期 codec 的密文
  const codec = makeCodec(key);
  const evalShipped = new Function(
    'atob',
    'btoa',
    'TextEncoder',
    'TextDecoder',
    'Uint8Array',
    'crypto',
    shipped + `;return ${helper};`
  );
  const decode = evalShipped(atob, btoa, TextEncoder, TextDecoder, Uint8Array, globalThis.crypto);

  const probes = [
    'BPB-Worker-Panel',
    'vless://x@y:443',
    '',
    '中文标签 😀',
    'A'.repeat(70000),
  ];
  let ok = true;
  let bad = null;
  for (const p of probes) {
    let out;
    try {
      out = decode(codec.encode(p));
    } catch (error) {
      ok = false;
      bad = `${JSON.stringify(p.slice(0, 20))} -> 抛错 ${error.message}`;
      break;
    }
    if (out !== p) {
      ok = false;
      bad = `${JSON.stringify(p.slice(0, 20))} -> ${JSON.stringify(String(out).slice(0, 20))}`;
      break;
    }
  }
  check(ok, '发布用解码器可独立求值并解开构建期密文（无编解码漂移）');
  if (!ok) fail('交叉验证失败: ' + bad);
}

// ------------------------------------------------------- 5. 密钥序列化往返
{
  const key = randomKey();
  const restored = keyFromBase64(keyToBase64(key));
  check(restored.length === 32 && hex(restored) === hex(key), '构建密钥 base64 序列化往返一致');
}

console.log(
  failures === 0
    ? 'cipher: OK（ChaCha20 RFC 8439 向量 + 往返 + 发布解码器纯度/交叉验证通过）'
    : `cipher: ${failures} 项失败`
);
process.exit(failures === 0 ? 0 : 1);
