// CodeArts 续期登记补齐工具（给"导入了账号但没有登记槽"的实例用）
//
// 背景：v3.5 起 CodeArts 自动续期只认 codearts_refresh_slots 里的 Ready 槽。
// 账号文件导入 / 手工迁移只写 accounts 行，不会建槽；缺槽时刷新会报
// 「CodeArts 当前账号没有可用的受控续期登记」。本脚本按宿主存储格式补齐：
//   accounts.data 里的 _hostCredentialVersion + codearts_refresh_slots 的 Ready 行，
//   kv 里没有 accountCredentialEpoch 时一并创建。
//
// 用法（必须先停服务；默认 dry-run，加 --apply 才写库）：
//   node enroll-codearts.mjs --db "D:/工具/Agent2API/data/agent2api.db" \
//                            --key "D:/工具/Agent2API/data/account.key" [--apply]
//
// 要求：Node.js >= 22.5（node:sqlite）。库与 key 建议先备份。
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && index + 1 < process.argv.length ? process.argv[index + 1] : fallback;
}
const DB_PATH = arg('db');
const KEY_PATH = arg('key');
const APPLY = process.argv.includes('--apply');
const CLIENT_ID = arg('client-id', 'codearts-agent');

if (!DB_PATH || !KEY_PATH) {
  console.error('用法: node enroll-codearts.mjs --db <agent2api.db> --key <account.key> [--apply]');
  process.exit(2);
}
const key = fs.readFileSync(KEY_PATH);
if (key.length !== 32) throw new Error('account.key 不是 32 字节');

const hex64 = () => crypto.randomBytes(32).toString('hex');
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const decode = (env) => {
  if (!env.startsWith('enc1:')) throw new Error('账号行不是 enc1 信封');
  const b = Buffer.from(env.slice(5), 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(0, 12));
  d.setAuthTag(b.subarray(b.length - 16));
  return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]).toString('utf8');
};
const seal = (text) => {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([c.update(Buffer.from(text, 'utf8')), c.final()]);
  return 'enc1:' + Buffer.concat([nonce, ct, c.getAuthTag()]).toString('base64');
};

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA busy_timeout = 3000');
const rows = db.prepare("SELECT id, enabled, data FROM accounts WHERE provider='codearts' ORDER BY priority, id").all();
if (rows.length === 0) {
  console.log('库里没有 codearts 账号，无需处理');
  process.exit(0);
}
const hasSlotTable = Number(db.prepare(
  "SELECT COUNT(*) n FROM sqlite_schema WHERE type='table' AND name='codearts_refresh_slots'").get().n) === 1;
const slotOf = (id) => hasSlotTable
  ? db.prepare('SELECT payload FROM codearts_refresh_slots WHERE account_id=?').get(id)
  : null;
const epochRow = db.prepare("SELECT value FROM kv WHERE key='accountCredentialEpoch'").get();
const epoch = epochRow ? String(epochRow.value) : hex64();

const plan = [];
const report = [];
for (const row of rows) {
  let rec;
  try {
    rec = JSON.parse(decode(row.data));
  } catch (error) {
    report.push({ id: row.id, action: 'skip', reason: `账号行解不开: ${error.message}` });
    continue;
  }
  const context = rec.pluginSecret?.oauth_context ?? rec.oauth_context;
  const hasContext = context && context.pkce_pair?.code_verifier && context.dpop_key_pair;
  if (!hasContext) {
    report.push({ id: row.id, action: 'skip', reason: '缺少 oauth_context，需重新登录' });
    continue;
  }
  const expect = b64u(crypto.createHash('sha256').update(context.pkce_pair.code_verifier).digest());
  if (expect !== context.pkce_pair.code_challenge) {
    report.push({ id: row.id, action: 'skip', reason: 'PKCE 不自洽，需重新登录' });
    continue;
  }
  const ver = rec._hostCredentialVersion;
  const slotRow = slotOf(row.id);
  let slot = null;
  if (slotRow) {
    try { slot = JSON.parse(decode(slotRow.payload)); } catch { slot = null; }
  }
  if (slot && ver && slot.state?.kind === 'ready'
      && slot.accountId === row.id && slot.dbEpoch === ver.dbEpoch
      && slot.born === ver.born && slot.revision === ver.revision) {
    report.push({ id: row.id, action: 'keep', reason: `已登记（revision=${ver.revision}）` });
    continue;
  }
  if (!context.client_id) context.client_id = CLIENT_ID;
  if (rec.pluginSecret?.oauth_context && !rec.pluginSecret.oauth_context.client_id) {
    rec.pluginSecret.oauth_context.client_id = CLIENT_ID;
  }
  const born = hex64();
  rec._hostCredentialVersion = { schema: 1, dbEpoch: epoch, born, revision: 1 };
  plan.push({ id: row.id, data: seal(JSON.stringify(rec)), born });
  report.push({ id: row.id, action: slot ? 'reset' : 'enroll', reason: slot ? '槽与账号版本不一致，重登记' : '缺槽，补登记' });
}

const counts = report.reduce((acc, item) => (acc[item.action] = (acc[item.action] ?? 0) + 1, acc), {});
for (const item of report) console.log(`${item.action.padEnd(6)} ${item.id}  ${item.reason}`);
console.log('统计:', JSON.stringify(counts), '| 待写:', plan.length, '| epoch:', epochRow ? 'existing' : 'will-create');
if (!APPLY || plan.length === 0) {
  if (!APPLY) console.log('dry-run：确认无误后加 --apply 写库（写库前请停服务并备份）');
  db.close();
  process.exit(0);
}

db.exec('BEGIN IMMEDIATE');
try {
  if (!epochRow) db.prepare("INSERT INTO kv(key,value) VALUES('accountCredentialEpoch',?)").run(epoch);
  db.exec(`CREATE TABLE IF NOT EXISTS main.codearts_refresh_slots (
    account_id TEXT NOT NULL PRIMARY KEY
      CHECK (typeof(account_id) = 'text' AND octet_length(account_id) BETWEEN 1 AND 512),
    payload TEXT NOT NULL
      CHECK (typeof(payload) = 'text' AND octet_length(payload) BETWEEN 1 AND 8192)
  ) WITHOUT ROWID;`);
  const update = db.prepare("UPDATE accounts SET data=?2 WHERE id=?1 AND provider='codearts'");
  const insert = db.prepare(`INSERT INTO codearts_refresh_slots(account_id,payload) VALUES(?,?)
    ON CONFLICT(account_id) DO UPDATE SET payload=excluded.payload`);
  for (const item of plan) {
    if (update.run(item.id, item.data).changes !== 1) throw new Error(`更新账号失败: ${item.id}`);
    const slot = {
      schema: 1, provider: 'codearts', accountId: item.id,
      dbEpoch: epoch, born: item.born, revision: 1,
      generation: hex64(),
      state: { kind: 'ready', settled_operation: null },
    };
    insert.run(item.id, seal(JSON.stringify(slot)));
  }
  db.exec('COMMIT');
} catch (error) {
  db.exec('ROLLBACK');
  throw error;
}

let verified = 0;
for (const item of plan) {
  const rec = JSON.parse(decode(db.prepare('SELECT data FROM accounts WHERE id=?').get(item.id).data));
  const slot = JSON.parse(decode(db.prepare('SELECT payload FROM codearts_refresh_slots WHERE account_id=?').get(item.id).payload));
  const ver = rec._hostCredentialVersion;
  if (ver.dbEpoch === epoch && ver.born === slot.born && slot.revision === ver.revision && slot.state.kind === 'ready') verified += 1;
}
console.log(`已写入 ${plan.length} 个账号，回读校验通过 ${verified} 个`);
db.close();
