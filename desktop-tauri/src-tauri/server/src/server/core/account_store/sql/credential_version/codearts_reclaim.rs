//! CodeArts 封锁槽自动 reclaim 的冷却记录。
//!
//! 只存「最近一次自动回退尝试的时间」，不存凭据、不参与槽校验。目的是让维护
//! 周期既能自动恢复“发送前/发送中失败但令牌仍可能有效”的账号，又不会对真正
//! 失效的账号每个周期都打一次上游。

use rusqlite::{params, Connection};

use super::{storage, Error, StorageFailure};

const TABLE: &str = "codearts_refresh_reclaims";

fn sql_error(error: rusqlite::Error) -> Error {
    storage::sql_error(error, StorageFailure::Read)
}

fn write_error(error: rusqlite::Error) -> Error {
    storage::sql_error(error, StorageFailure::Write)
}

fn exists(conn: &Connection) -> Result<bool, Error> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type = 'table' AND name = 'codearts_refresh_reclaims')",
        [],
        |row| row.get(0),
    )
    .map_err(sql_error)
}

fn ensure(conn: &Connection) -> Result<(), Error> {
    exists(conn)?;
    conn.execute_batch(crate::server::db::schema::CODEARTS_RECLAIM_SCHEMA)
        .map_err(write_error)
}

/// 最近一次自动 reclaim 的时间（毫秒）；没有记录时返回 0。
pub(in crate::server::core::account_store) fn last(conn: &Connection, account: &str) -> Result<i64, Error> {
    if !exists(conn)? {
        return Ok(0);
    }
    let value = conn
        .query_row(
            "SELECT attempted_at FROM main.codearts_refresh_reclaims WHERE account_id = ?1",
            params![account],
            |row| row.get::<_, i64>(0),
        )
        .ok();
    Ok(value.unwrap_or(0))
}

/// 记录一次自动 reclaim；同一账号覆盖旧值。
pub(in crate::server::core::account_store) fn mark(conn: &Connection, account: &str, at: i64) -> Result<(), Error> {
    ensure(conn)?;
    conn.execute(
        "INSERT INTO main.codearts_refresh_reclaims (account_id, attempted_at) VALUES (?1, ?2)
         ON CONFLICT(account_id) DO UPDATE SET attempted_at = excluded.attempted_at",
        params![account, at],
    )
    .map_err(write_error)?;
    Ok(())
}

/// 账号被删除或槽已正常结算时清掉冷却记录。
pub(in crate::server::core::account_store) fn delete(conn: &Connection, account: &str) -> Result<(), Error> {
    if !exists(conn)? {
        return Ok(());
    }
    conn.execute(
        "DELETE FROM main.codearts_refresh_reclaims WHERE account_id = ?1",
        params![account],
    )
    .map_err(write_error)?;
    Ok(())
}
