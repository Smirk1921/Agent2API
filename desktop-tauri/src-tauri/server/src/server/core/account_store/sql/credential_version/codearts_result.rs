//! CodeArts 换票结果的耐久日志（恢复用）。
//!
//! 上游换票成功、本地结算（写账号 + 推进槽）失败时，新令牌只在内存里，旧令牌已经
//! 被上游消费 —— 账号就此死亡。这里把**上游响应**在结算前加密落盘，并把本次 Pending
//! 的 operation / generation / 账号版本一并记下；恢复流程只在账号与槽仍指向同一次
//! Pending 时使用它完成结算，绝不重发旧刷新令牌。
//!
//! 存储形态与续期槽一致：按需建表（不改 user_version），payload 是 `enc1:` 信封。
//! 一行一个账号：新的换票会覆盖同一账号的旧记录，避免堆积历史令牌。

use rusqlite::{params, types::ValueRef, Connection};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{storage, Error, StorageFailure, Version};
use crate::server::core::crypto;

const MAX_BODY: usize = 96 * 1024;
const TABLE: &str = "codearts_refresh_results";

/// 一条待结算记录。`body` 是上游返回的凭证 JSON（与 `prepare_replacement` 同形）。
pub(in crate::server::core::account_store) struct Entry {
    pub account: String,
    pub operation: String,
    pub generation: String,
    pub version: Version,
    pub body: Value,
}

fn sql_error(error: rusqlite::Error) -> Error {
    storage::sql_error(error, StorageFailure::Read)
}

fn write_error(error: rusqlite::Error) -> Error {
    storage::sql_error(error, StorageFailure::Write)
}

fn exists(conn: &Connection) -> Result<bool, Error> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema
            WHERE type = 'table' AND name = 'codearts_refresh_results')",
        [],
        |row| row.get(0),
    )
    .map_err(sql_error)
}

fn ensure(conn: &Connection) -> Result<(), Error> {
    exists(conn)?;
    conn.execute_batch(crate::server::db::schema::CODEARTS_REFRESH_RESULT_SCHEMA)
        .map_err(write_error)
}

/// 落盘一次换票结果；同一账号的新结果覆盖旧行。
pub(in crate::server::core::account_store) fn put(
    conn: &Connection,
    key: &[u8; 32],
    account: &str,
    operation: &str,
    generation: &str,
    version: &Version,
    body: &Value,
) -> Result<(), Error> {
    ensure(conn)?;
    let plain = Zeroizing::new(serde_json::to_vec(body).map_err(|_| Error::InvalidRecord)?);
    if plain.len() > MAX_BODY {
        return Err(Error::LimitExceeded);
    }
    let envelope =
        crypto::seal_with_key(&plain, key).map_err(|_| Error::Storage(StorageFailure::Encryption))?;
    if envelope.len() > 196608 {
        return Err(Error::LimitExceeded);
    }
    let changed = conn
        .execute(
            "INSERT INTO main.codearts_refresh_results
                (account_id, operation, generation, db_epoch, born, revision, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(account_id) DO UPDATE SET
                operation = excluded.operation,
                generation = excluded.generation,
                db_epoch = excluded.db_epoch,
                born = excluded.born,
                revision = excluded.revision,
                payload = excluded.payload,
                created_at = excluded.created_at",
            params![
                account,
                operation,
                generation,
                version.epoch,
                version.born,
                version.revision as i64,
                envelope,
                crate::server::logging::now_ms(),
            ],
        )
        .map_err(write_error)?;
    if changed != 1 {
        return Err(Error::Storage(StorageFailure::Write));
    }
    Ok(())
}

/// 读出全部待结算记录；没有表时返回空（未发生过换票结果落盘）。
pub(in crate::server::core::account_store) fn list(conn: &Connection, key: &[u8; 32]) -> Result<Vec<Entry>, Error> {
    if !exists(conn)? {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(
            "SELECT account_id, operation, generation, db_epoch, born, revision, payload
             FROM main.codearts_refresh_results",
        )
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut entries = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        let text = |column: usize| -> Result<String, Error> {
            let value = row.get_ref(column).map_err(sql_error)?;
            let ValueRef::Text(bytes) = value else {
                return Err(Error::InvalidRecord);
            };
            std::str::from_utf8(bytes)
                .map(str::to_string)
                .map_err(|_| Error::InvalidRecord)
        };
        let account = text(0)?;
        let operation = text(1)?;
        let generation = text(2)?;
        let epoch = text(3)?;
        let born = text(4)?;
        let revision = match row.get_ref(5).map_err(sql_error)? {
            ValueRef::Integer(value) if value > 0 => value as u64,
            _ => return Err(Error::InvalidRecord),
        };
        let payload = text(6)?;
        let plain = Zeroizing::new(
            crypto::open_with_key(&payload, key).map_err(|_| Error::InvalidRecord)?,
        );
        let body: Value = serde_json::from_slice(&plain).map_err(|_| Error::InvalidRecord)?;
        if !body.is_object() {
            return Err(Error::InvalidRecord);
        }
        entries.push(Entry {
            account,
            operation,
            generation,
            version: Version { epoch, born, revision },
            body,
        });
    }
    Ok(entries)
}

/// 删除指定账号的**同一次**待结算记录（operation 不匹配时保留，避免误删新记录）。
pub(in crate::server::core::account_store) fn delete(conn: &Connection, account: &str, operation: &str) -> Result<(), Error> {
    if !exists(conn)? {
        return Ok(());
    }
    conn.execute(
        "DELETE FROM main.codearts_refresh_results
         WHERE account_id = ?1 AND operation = ?2",
        params![account, operation],
    )
    .map_err(write_error)?;
    Ok(())
}

/// 删除某账号的任意待结算记录（恢复判定为陈旧/已结算时使用）。
pub(in crate::server::core::account_store) fn delete_any(conn: &Connection, account: &str) -> Result<(), Error> {
    if !exists(conn)? {
        return Ok(());
    }
    conn.execute(
        "DELETE FROM main.codearts_refresh_results WHERE account_id = ?1",
        params![account],
    )
    .map_err(write_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    fn version(revision: u64) -> Version {
        Version {
            epoch: "epoch-1".into(),
            born: "born-1".into(),
            revision,
        }
    }

    fn body(refresh: &str) -> Value {
        serde_json::json!({
            "accessToken": "at-value",
            "refreshToken": refresh,
            "expiresAt": 1_700_000_000_000u64,
            "expiration": 1_700_000_000u64,
        })
    }

    fn connection() -> Connection {
        Connection::open_in_memory().expect("内存库应当可建")
    }

    #[test]
    fn roundtrip_is_encrypted_and_bound_to_version() {
        let conn = connection();
        put(&conn, &KEY, "acc-1", "op-1", "gen-1", &version(3), &body("rt-1")).expect("落盘应当成功");
        let entries = list(&conn, &KEY).expect("读取应当成功");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].account, "acc-1");
        assert_eq!(entries[0].operation, "op-1");
        assert_eq!(entries[0].generation, "gen-1");
        assert_eq!(entries[0].version.revision, 3);
        assert_eq!(entries[0].version.epoch, "epoch-1");
        assert_eq!(entries[0].version.born, "born-1");
        assert_eq!(entries[0].body["refreshToken"], "rt-1");

        // 明文令牌不能出现在库里：唯一能落盘的是 enc1: 信封。
        let payload: String = conn
            .query_row("SELECT payload FROM main.codearts_refresh_results", [], |row| row.get(0))
            .expect("应当有一行");
        assert!(payload.starts_with("enc1:"), "载荷必须是密文信封：{payload}");
        assert!(!payload.contains("rt-1"));
    }

    #[test]
    fn one_row_per_account_and_new_result_replaces_old() {
        let conn = connection();
        put(&conn, &KEY, "acc-1", "op-1", "gen-1", &version(3), &body("rt-1")).unwrap();
        put(&conn, &KEY, "acc-1", "op-2", "gen-2", &version(4), &body("rt-2")).unwrap();
        let entries = list(&conn, &KEY).unwrap();
        assert_eq!(entries.len(), 1, "同一账号只保留最新一次换票结果");
        assert_eq!(entries[0].operation, "op-2");
        assert_eq!(entries[0].body["refreshToken"], "rt-2");
    }

    #[test]
    fn delete_only_matches_the_same_operation() {
        let conn = connection();
        put(&conn, &KEY, "acc-1", "op-1", "gen-1", &version(3), &body("rt-1")).unwrap();
        delete(&conn, "acc-1", "op-other").unwrap();
        assert_eq!(list(&conn, &KEY).unwrap().len(), 1, "操作不匹配时不能删掉别人的记录");
        delete(&conn, "acc-1", "op-1").unwrap();
        assert!(list(&conn, &KEY).unwrap().is_empty());
        delete_any(&conn, "acc-1").unwrap();
    }

    #[test]
    fn tampered_payload_is_reported_not_silently_used() {
        let conn = connection();
        put(&conn, &KEY, "acc-1", "op-1", "gen-1", &version(3), &body("rt-1")).unwrap();
        conn.execute(
            "UPDATE main.codearts_refresh_results SET payload = 'enc1:AAAA' WHERE account_id = 'acc-1'",
            [],
        )
        .unwrap();
        assert!(matches!(list(&conn, &KEY), Err(Error::InvalidRecord)));
    }

    #[test]
    fn empty_database_lists_nothing() {
        let conn = connection();
        assert!(list(&conn, &KEY).unwrap().is_empty(), "还没换过票时不应建表或报错");
        delete(&conn, "acc-1", "op-1").unwrap();
        delete_any(&conn, "acc-1").unwrap();
    }
}
