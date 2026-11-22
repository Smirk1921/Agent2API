// CodeArts 账号状态体检（只读）。
//
// 用法：
//   node check-codearts.mjs --db "<data>/agent2api.db" --key "<data>/account.key" [--json]
//
// 输出每个账号的：槽状态（ready/pending/blocked/missing）、账号版本与槽是否一致、
// 以及耐久日志里待补结算的行数。全部 ready 且无日志时退出码 0，否则 1。
// 只读，不修改库；服务运行中也可执行。
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && index + 1 < process.argv.length ? process.argv[index + 1] : fallback;
}
const DB_PATH = arg('db');
const KEY_PATH = arg('key');
const JSON_OUT = process.argv.includes('--json');
if (!DB_PATH || !KEY_PATH) {
  console.error('用法: node check-codearts.mjs --db <agent2api.db> --key <account.key> [--json]');
  process.exit(2);
}
const key = fs.readFileSync(KEY_PATH);
if (key.length !== 32) throw new Error('account.key 不是 32 字节');

const decode = (env) => {
  const b = Buffer.from(env.slice(5), 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(0, 12));
  d.setAuthTag(b.subarray(b.length - 16));
  return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]).toString('utf8');
};

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA busy_timeout = 3000');
const hasSlots = Number(db.prepare(
  "SELECT COUNT(*) n FROM sqlite_schema WHERE type='table' AND name='codearts_refresh_slots'").get().n) === 1;
const hasJournal = Number(db.prepare(
  "SELECT COUNT(*) n FROM sqlite_schema WHERE type='table' AND name='codearts_refresh_results'").get().n) === 1;

const rows = db.prepare("SELECT id, enabled, data FROM accounts WHERE provider='codearts' ORDER BY id").all();
// 同义字段必须逐字一致：宿主在换票前会强校验，分叉的账号直到 AT 过期
// 才会以“续期未确认/材料失败”暴露，提前体检能把它挡在维护之前。
const ALIAS_GROUPS = [
  ['access_key_id', 'accessKeyId', 'accessToken'],
  ['secret_access_key', 'secretAccessKey'],
  ['security_token', 'securityToken'],
  ['refresh_token', 'refreshToken'],
];
const accounts = rows.map((row) => {
  const out = { id: row.id, enabled: row.enabled === 1 || row.enabled === true, slot: 'missing', revision: null, version: null, match: false, aliasConflict: false, expiryConflict: false };
  try {
    const rec = JSON.parse(decode(row.data));
    out.version = rec._hostCredentialVersion?.revision ?? null;
    out.needsRelogin = rec.needsRelogin === true || rec.pluginSecret?.needsRelogin === true || rec.pluginPublic?.needsRelogin === true;
    for (const target of [rec, rec.pluginSecret].filter((value) => value && typeof value === 'object')) {
      for (const aliases of ALIAS_GROUPS) {
        const values = aliases.filter((name) => typeof target[name] === 'string' && target[name]).map((name) => target[name]);
        if (new Set(values).size > 1) out.aliasConflict = true;
      }
    }
    const expiresAt = typeof rec.expiresAt === 'number' ? rec.expiresAt : null;
    if (expiresAt) {
      const iso = new Date(expiresAt).toISOString();
      for (const target of [rec, rec.pluginSecret].filter((value) => value && typeof value === 'object')) {
        // RFC3339 允许可变小数位（.18Z 与 .180Z 是同一毫秒），按解析后的时间戳比较。
        if (target.expiration !== undefined && Date.parse(target.expiration) !== expiresAt) out.expiryConflict = true;
        if (target.expires_at !== undefined && Date.parse(target.expires_at) !== expiresAt) out.expiryConflict = true;
      }
    }
    if (hasSlots) {
      const slotRow = db.prepare('SELECT payload FROM codearts_refresh_slots WHERE account_id=?').get(row.id);
      if (slotRow) {
        try {
          const slot = JSON.parse(decode(slotRow.payload));
          out.slot = slot.state?.kind ?? 'invalid';
          out.revision = slot.revision;
          const ver = rec._hostCredentialVersion;
          out.match = Boolean(ver && slot.dbEpoch === ver.dbEpoch && slot.born === ver.born && slot.revision === ver.revision);
        } catch { out.slot = 'invalid'; }
      }
    }
  } catch { out.slot = 'unreadable'; }
  return out;
});
let journal = 0;
if (hasJournal) journal = Number(db.prepare('SELECT COUNT(*) n FROM codearts_refresh_results').get().n);

const counts = accounts.reduce((acc, item) => {
  const key = item.aliasConflict || item.expiryConflict
    ? 'material-conflict'
    : item.slot === 'ready' && item.match ? 'ready' : item.slot;
  acc[key] = (acc[key] ?? 0) + 1;
  return acc;
}, {});
const ok = counts.ready === accounts.length && journal === 0;
if (JSON_OUT) {
  console.log(JSON.stringify({ ok, total: accounts.length, counts, journal, accounts }, null, 2));
} else {
  for (const item of accounts) {
    const state = item.aliasConflict || item.expiryConflict
      ? `material-conflict${item.aliasConflict ? '(aliases)' : ''}${item.expiryConflict ? '(expiry)' : ''}`
      : item.slot === 'ready' && item.match ? 'ready' : `${item.slot}${item.slot === 'ready' ? '(version-mismatch)' : ''}`;
    console.log(`${state.padEnd(24)} enabled=${String(item.enabled).padEnd(5)} rev=${item.version ?? '-'} ${item.id}`);
  }
  console.log('统计:', JSON.stringify(counts), '| 待补结算日志:', journal);
  console.log(ok ? 'CHECK-OK' : 'CHECK-NOT-READY');
}
db.close();
process.exit(ok ? 0 : 1);
