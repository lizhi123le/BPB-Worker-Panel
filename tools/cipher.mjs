/**
 * tools/cipher.mjs
 *
 * 混淆阶段使用的载荷密码唯一实现（single source of truth）。
 *
 * 设计要点（为什么长这样）：
 * - js-confuser 的 `stringConcealing` 解码器必须 **同步**（它被放在表达式位置调用），
 *   所以 WebCrypto 的 AES-GCM（异步）不可用；ChaCha20（RFC 8439）是标准同步流密码。
 * - 每条被隐藏的字符串都有自己随机的 8 字节 nonce，前缀在密文之前 → 不存在密钥流复用，
 *   同一个明文在不同位置不会产生相同密文。
 * - 密文以 base64 承载，生成的 JS 字符串字面量保持可打印且紧凑（裸字节会被转义成 \xNN，
 *   体积翻倍）。
 * - Worker 侧运行时（RUNTIME）**故意不含任何字符串字面量**：一旦含了，js-confuser 会把它
 *   也藏起来，解码器就必须先解码自己才能解码别人（自举死锁）。
 * - Node 侧的编码器由同一份 RUNTIME 源码求值而来，因此"构建期加密"与"线上解密"永不漂移。
 *
 * 与参考实现（MOD-Worker-Panel）的差别：仅命名与注释本地化，算法逐字保持一致
 * （已由 tools/cipher.test.mjs 的双向用例与外部向量覆盖）。
 */

import { randomBytes } from 'node:crypto';

export const KS_NAME = '__bpbKS';
export const DEC_NAME = '__bpbDEC';
export const ENC_NAME = '__bpbENC';

/**
 * Worker 侧运行时。`__KEY__` 会被替换成 32 个数字的数组。
 * ENC 被专用标记包住，便于从最终产物里剥离（产物只需要解密）。
 */
export const RUNTIME = `
function ${KS_NAME}(n8, len) {
  var key = __KEY__;
  var out = new Uint8Array(len);
  var st = new Uint32Array(16);
  var w = new Uint32Array(16);
  var ctr = 0;
  var o = 0;
  var i = 0;
  var j = 0;
  while (o < len) {
    st[0] = 1634760805; st[1] = 857760878; st[2] = 2036477234; st[3] = 1797285236;
    for (i = 0; i < 8; i++) {
      st[4 + i] = key[4 * i] | (key[4 * i + 1] << 8) | (key[4 * i + 2] << 16) | (key[4 * i + 3] << 24);
    }
    st[12] = ctr++;
    st[13] = n8[0] | (n8[1] << 8) | (n8[2] << 16) | (n8[3] << 24);
    st[14] = n8[4] | (n8[5] << 8) | (n8[6] << 16) | (n8[7] << 24);
    st[15] = 0;
    for (i = 0; i < 16; i++) w[i] = st[i];
    for (i = 0; i < 10; i++) {
      qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
      qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14);
    }
    for (i = 0; i < 16; i++) {
      var add = (w[i] + st[i]) >>> 0;
      var n = len - o;
      if (n > 4) n = 4;
      for (j = 0; j < n; j++) out[o + j] = (add >>> (8 * j)) & 255;
      o += n;
      if (o >= len) break;
    }
  }
  return out;
}
function qr(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = (s[d] ^ s[a]) >>> 0; s[d] = ((s[d] << 16) | (s[d] >>> 16)) >>> 0;
  s[c] = (s[c] + s[d]) >>> 0; s[b] = (s[b] ^ s[c]) >>> 0; s[b] = ((s[b] << 12) | (s[b] >>> 20)) >>> 0;
  s[a] = (s[a] + s[b]) >>> 0; s[d] = (s[d] ^ s[a]) >>> 0; s[d] = ((s[d] << 8) | (s[d] >>> 24)) >>> 0;
  s[c] = (s[c] + s[d]) >>> 0; s[b] = (s[b] ^ s[c]) >>> 0; s[b] = ((s[b] << 7) | (s[b] >>> 25)) >>> 0;
}
function ${DEC_NAME}(s) {
  var raw = atob(s);
  var n = raw.length;
  var all = new Uint8Array(n);
  var i = 0;
  for (i = 0; i < n; i++) all[i] = raw.charCodeAt(i);
  var body = n - 8;
  var ks = ${KS_NAME}(all, body);
  var out = new Uint8Array(body);
  var ascii = true;
  for (i = 0; i < body; i++) {
    var b = all[8 + i] ^ ks[i];
    out[i] = b;
    if (b > 127) ascii = false;
  }
  if (ascii) {
    var str = '';
    for (i = 0; i < body; i++) str += String.fromCharCode(out[i]);
    return str;
  }
  return new TextDecoder().decode(out);
}
/*ENC-START*/
function ${ENC_NAME}(str) {
  var bytes = new TextEncoder().encode(str);
  var n8 = new Uint8Array(8);
  crypto.getRandomValues(n8);
  var ks = ${KS_NAME}(n8, bytes.length);
  var all = new Uint8Array(8 + bytes.length);
  all.set(n8, 0);
  var i = 0;
  for (i = 0; i < bytes.length; i++) all[8 + i] = bytes[i] ^ ks[i];
  var bin = '';
  for (i = 0; i < all.length; i++) bin += String.fromCharCode(all[i]);
  return btoa(bin);
}
/*ENC-END*/
`;

const ENC_BLOCK = /\/\*ENC-START\*\/[\s\S]*?\/\*ENC-END\*\//;

function keyLiteral(keyBytes) {
  return '[' + Array.from(keyBytes).join(',') + ']';
}

/** 完整运行时（编码 + 解码），本地 Node 使用。 */
export function buildCodecSource(keyBytes) {
  return RUNTIME.replace('__KEY__', keyLiteral(keyBytes));
}

/**
 * 随产物发布的运行时：只有解码器，没有编码器，没有注释。
 *
 * `names` 每次构建换掉两个函数名，产物因此不携带固定指纹；替换只在单词边界上进行。
 *
 * 重要：这段源码是在 js-confuser **跑完之后**追加到产物尾部的。
 * js-confuser 的 `stringConcealing` 会连**属性名**一起隐藏（`obj.prop` -> `obj[dec(i)]`），
 * 所以如果解码器活在 AST 里，它得先解码自己的密钥才能解码自己 —— 永远不会终止。
 * 把它放在 AST 之外还顺带保证了它不含任何字符串字面量。
 */
export function buildDecoderSource(keyBytes, names = { ks: KS_NAME, dec: DEC_NAME }) {
  let src = buildCodecSource(keyBytes).replace(ENC_BLOCK, '').trim();
  if (names.ks && names.ks !== KS_NAME) {
    src = src.replace(new RegExp(`\\b${KS_NAME}\\b`, 'g'), names.ks);
  }
  if (names.dec && names.dec !== DEC_NAME) {
    src = src.replace(new RegExp(`\\b${DEC_NAME}\\b`, 'g'), names.dec);
  }
  return src;
}

/** 每次构建、每个产物独立的 helper 名（混淆时未绑定，混淆之后才声明）。 */
export function randomHelperName() {
  return '_0x' + randomBytes(4).toString('hex');
}

/** 构建期 codec：{ encode(str) -> base64, decode(base64) -> str }。 */
export function makeCodec(keyBytes) {
  const factory = new Function(
    buildCodecSource(keyBytes) + `;return {e:${ENC_NAME},d:${DEC_NAME}};`
  );
  const { e, d } = factory();
  return { encode: e, decode: d };
}

export function randomKey() {
  return new Uint8Array(randomBytes(32));
}

export function keyToBase64(keyBytes) {
  return Buffer.from(keyBytes).toString('base64');
}

export function keyFromBase64(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}
