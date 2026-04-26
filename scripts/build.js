import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname as pathDirname } from 'path';
import { fileURLToPath } from 'url';
import { build } from 'esbuild';
import { minify as jsMinify } from 'terser';
import JSZip from 'jszip';
import JsConfuser from 'js-confuser';

const __filename = fileURLToPath(import.meta.url);
const __dirname = pathDirname(__filename);

const DIST_PATH = join(__dirname, '../dist/');
const ENTRY = join(__dirname, '../origin.js');
const SENSITIVE_WORDS_FILE = join(__dirname, '../sensitive_words_auto.txt');

// Helper: random int in [min, max]
function getRandomInt(min, max) {
min = Math.ceil(min);
max = Math.floor(max);
return Math.floor(Math.random() * (max - min + 1)) + min;
}

// ---------- customObfuscate (替换整个函数) ----------
async function customObfuscate(sourceCode) {
  // Define encryption keys
  const BASE_KEY = 128; // 若需要完整 Unicode，请改为 65536
  const SHIFT_KEY = getRandomInt(1, BASE_KEY - 1);
  const XOR_KEY = getRandomInt(1, BASE_KEY - 1);
  console.log("Using XOR_KEY: " + XOR_KEY + " with SHIFT_KEY: " + SHIFT_KEY + " with BASE_KEY: " + BASE_KEY);

  // Load sensitive words from file (如果文件不存在，使用空数组)
  let sensitiveWords = [];
  if (existsSync(SENSITIVE_WORDS_FILE)) {
    sensitiveWords = readFileSync(SENSITIVE_WORDS_FILE, 'utf-8')
      .split('\n')
      .map(w => w.trim())
      .filter(w => w.length > 0);
  } else {
    console.warn('敏感词文件不存在，继续但不会进行敏感词判断。路径:', SENSITIVE_WORDS_FILE);
  }

  // decoder template string - this will be injected into the obfuscated output
  // Note: JsConfuser expects `code` to be a string containing a function definition that it can call.
  const decodeFnTemplate = `
function {fnName}(str){
  var out = '';
  for(var i=0;i<str.length;i++){
    var code = str.charCodeAt(i);
    code = (code - ${SHIFT_KEY} + ${BASE_KEY}) % ${BASE_KEY};
    code = code ^ ${XOR_KEY};
    out += String.fromCharCode(code);
  }
  return out;
}
`;

  // encoder used by JsConfuser customStringEncodings.encode:
  function encoder(str) {
    // returns the encoded string expected by the decoder above
    return str.split('').map(ch => {
      let code = ch.charCodeAt(0);
      code = code ^ XOR_KEY;
      code = (code + SHIFT_KEY) % BASE_KEY;
      return String.fromCharCode(code);
    }).join('');
  }

  const options = {
    target: 'browser',
    // Only conceal strings that contain sensitive words (if none provided, do not conceal anything)
    stringConcealing: (str) => {
      if (!sensitiveWords || sensitiveWords.length === 0) return false;
      const lower = str.toLowerCase();
      return sensitiveWords.some(w => lower.includes(w.toLowerCase()));
    },
    renameVariables: true,
    renameGlobals: true,
    renameLabels: true,
    identifierGenerator: 'mangled',
    customStringEncodings: [
      {
        // JsConfuser expects `code` to be a function-string template (with {fnName})
        code: decodeFnTemplate,
        encode: encoder
      }
    ],
    movedDeclarations: true,
    objectExtraction: true,
    compact: true,
    hexadecimalNumbers: true,
    astScrambler: true,
    preserveFunctionLength: true,
    // disable problematic transforms
    dispatcher: false,
    stringSplitting: false,
    controlFlowFlattening: false,
    minify: false,
  };

  const result = await JsConfuser.obfuscate(sourceCode, options);

  if (!result || !result.code) {
    throw new Error('JsConfuser failed to produce obfuscated code.');
  }

  return result.code;
}
// ---------- end customObfuscate ----------

async function buildWorker() {
try {
console.clear();

// 1) bundle with esbuild
const buildResult = await build({
  entryPoints: [ENTRY],
  bundle: true,
  format: 'esm',
  write: false,
  external: ['cloudflare:sockets'],
  platform: 'browser',
  target: 'es2020'
});

const bundled = buildResult.outputFiles[0].text;

// 2) minify with terser
const minified = await jsMinify(bundled, {
  module: true,
  output: { comments: false }
});

if (!minified || !minified.code) {
  throw new Error('Terser minify failed.');
}

console.log('✅ Worker minified successfully!');
console.log(`📊 Minified size: ${Math.round(minified.code.length / 1024)}KB`);

// Ensure output dir exists
mkdirSync(DIST_PATH, { recursive: true });

// Write non-obfuscated worker for convenience
const plainPath = join(DIST_PATH, 'worker.js');
writeFileSync(plainPath, '// @ts-nocheck\n' + minified.code, 'utf8');

// 3) obfuscate only the file output/_worker.js content (we'll create it from minified code)
// Prepare content for _worker.js (this is the content that will be obfuscated)
  const underscoreWorkerContent = minified.code;

  // Only obfuscate this worker content (we're not touching other files)
  const obfuscatedCode = await customObfuscate(underscoreWorkerContent);

  // Write obfuscated to output/_worker.js
  const undersPath = join(DIST_PATH, '_worker.js');
  writeFileSync(undersPath, '// @ts-nocheck\n' + obfuscatedCode, 'utf8');

  console.log('✅ Worker obfuscated successfully!');
  console.log(`📊 Obfuscated size: ${Math.round(obfuscatedCode.length / 1024)}KB`);

  // 4) zip the _worker.js file into worker.zip
  const zip = new JSZip();
  zip.file('_worker.js', '// @ts-nocheck\n' + obfuscatedCode);

  const nodebuffer = await zip.generateAsync({
    type: 'nodebuffer',
    compression: 'DEFLATE'
  });

  const zipPath = join(DIST_PATH, 'worker.zip');
  writeFileSync(zipPath, nodebuffer);

console.log('✅ worker.zip created at', zipPath);
console.log('✅ Done!');
} catch (err) {
console.error('Build failed:', err);
process.exit(1);
}
}

// Run
buildWorker().catch(err => {
    console.error('❌ Build failed:', err);
    process.exit(1);

});
