/**
 * scripts/build-params.mjs
 *
 * 构建参数的唯一入口：CLI > 环境变量 > harden.config.json > 默认值。
 *
 * 体积目标支持三种写法：
 *   320000 / 320k / 1m     绝对字节（k/m 按 1024 进制）
 *   75%                    相对「首次混淆产物」的百分比（zip 目标相对 zip，raw 相对 raw）
 *
 * 配置文件默认是仓库根目录 harden.config.json（可选），也可以 --config=path 指定。
 * 未显式指定时默认构建即启用体积控制：raw ≤ 520 KiB、zip ≤ 236 KiB（设 0 可关闭）。
 * 例：
 *   { "targetBytes": "520k", "targetZipBytes": "236k", "maxRuns": 20, "oneLine": true }
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_CONFIG_PATH = path.join(ROOT, 'harden.config.json');
export const PROJECT_ROOT = ROOT;

const SIZE_RE = /^(\d+(?:\.\d+)?)\s*(b|k|kb|kib|m|mb|mib)?$/i;

/** 解析体积参数；返回 { kind: 'bytes'|'percent', value } 或 null。 */
export function parseSizeSpec(value, label = '体积参数') {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value < 0) throw new Error(`${label} 必须是非负数：${value}`);
    const bytes = Math.round(value);
    return bytes > 0 ? { kind: 'bytes', value: bytes } : null;
  }
  const text = String(value).trim().toLowerCase();
  if (text.endsWith('%')) {
    const percent = Number(text.slice(0, -1));
    if (!Number.isFinite(percent) || percent <= 0) {
      throw new Error(`${label} 百分比不合法：${value}（应形如 75%）`);
    }
    return { kind: 'percent', value: percent };
  }
  const match = text.match(SIZE_RE);
  if (!match) {
    throw new Error(`${label} 无法解析：${value}（支持 320000 / 320k / 1m / 75%）`);
  }
  const unit = (match[2] || 'b').toLowerCase();
  const factor = unit === 'b' ? 1 : unit.startsWith('k') ? 1024 : 1024 * 1024;
  const bytes = Math.round(Number(match[1]) * factor);
  return bytes > 0 ? { kind: 'bytes', value: bytes } : null;
}

/** 传给子进程 / 报告时用的规范字符串。 */
export function formatSizeSpec(spec) {
  if (!spec) return '';
  return spec.kind === 'percent' ? `${spec.value}%` : String(spec.value);
}

function toBool(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const text = String(value).toLowerCase();
  if (text === 'false' || text === '0' || text === 'no') return false;
  if (text === 'true' || text === '1' || text === 'yes') return true;
  throw new Error(`布尔参数不合法：${value}`);
}

function toInt(value, fallback, label) {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new Error(`${label} 必须是非负整数：${value}`);
  return n;
}

function readConfig(configPath, required) {
  if (!fs.existsSync(configPath)) {
    if (required) throw new Error(`找不到配置文件：${configPath}`);
    return {};
  }
  const raw = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`配置文件必须是 JSON 对象：${configPath}`);
  }
  return raw;
}

/**
 * @returns {{
 *   params: {
 *     configPath: string,
 *     targetBytes: {kind:string,value:number}|null,
 *     targetZipBytes: {kind:string,value:number}|null,
 *     maxRuns: number, oneLine: boolean, minString: number, maxString: number,
 *   },
 *   positional: string[],
 *   flags: Map<string,string>,
 * }}
 */
export function loadParams(argv = process.argv.slice(2), env = process.env) {
  const flags = new Map();
  const positional = [];
  for (const arg of argv) {
    const match = String(arg).match(/^--([a-z0-9-]+)(?:=(.*))?$/i);
    if (!match) {
      positional.push(String(arg));
      continue;
    }
    flags.set(match[1].toLowerCase(), match[2] ?? 'true');
  }

  const configPath = path.resolve(
    ROOT,
    flags.get('config') || env.HARDEN_CONFIG || DEFAULT_CONFIG_PATH
  );
  const config = readConfig(configPath, flags.has('config'));

  const pick = (flag, envName, configKey) => {
    if (flags.has(flag)) return flags.get(flag);
    if (env[envName] !== undefined && env[envName] !== '') return env[envName];
    if (config[configKey] !== undefined) return config[configKey];
    return undefined;
  };

  const rawTargetValue = pick('target-bytes', 'HARDEN_TARGET_BYTES', 'targetBytes');
  const zipTargetValue = pick('target-zip', 'HARDEN_TARGET_ZIP_BYTES', 'targetZipBytes');
  const params = {
    configPath,
    // 默认构建即控制体积：raw ≤ 520 KiB，zip ≤ 236 KiB；显式设为 0 可关闭。
    targetBytes: parseSizeSpec(rawTargetValue === undefined ? '520k' : rawTargetValue, 'targetBytes'),
    targetZipBytes: parseSizeSpec(zipTargetValue === undefined ? '236k' : zipTargetValue, 'targetZipBytes'),
    maxRuns: Math.max(
      1,
      toInt(pick('max-runs', 'HARDEN_SIZE_MAX_RUNS', 'maxRuns'), 20, 'maxRuns')
    ),
    oneLine: toBool(pick('one-line', 'HARDEN_ONE_LINE', 'oneLine'), true),
    minString: toInt(pick('min-string', 'HARDEN_MIN_STRING', 'minString'), 0, 'minString'),
    maxString: toInt(pick('max-string', 'HARDEN_MAX_STRING', 'maxString'), 0, 'maxString'),
  };

  return { params, positional, flags };
}
