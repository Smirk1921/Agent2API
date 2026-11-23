//! CodeArts单账号严格Ready/Pending存储。缺版本/槽/旧epoch从不建表、重建或自动纳管。
//! SQL返回的只是同事务候选；真实COMMIT+连接收尾由原来源门面确认后才交付对象。
//! 本家固定短期材料/原操作结清/下一Ready同事务，未知只能Blocked或保持Pending。

mod record;
mod final_check;
pub(in crate::server::core::account_store) use final_check::verify_pending_current;

use rusqlite::Connection;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::projection::Projection;
use super::{bounded, storage, CommitReceipt, Conflict, Error, Stamp, StorageFailure, Version};
use crate::server::core::account_store::state::StoredAccount;
use record::{Slot, State};

pub(in crate::server::core::account_store) use record::RetainedRows;

#[derive(Debug)]
pub(crate) enum SlotFailure {
    Account(Error),
    Schema,
    Missing,
    Invalid,
    NotReady,
    ReceiptChanged,
    RequiresNewAuthorization,
    IncompleteReplacement,
    Interrupted,
}

impl From<Error> for SlotFailure {
    fn from(error: Error) -> Self {
        Self::Account(error)
    }
}

impl SlotFailure {
    /// 恢复日志用的稳定短标签；不输出任何凭证/账号内容。
    pub(in crate::server::core::account_store) fn reason(&self) -> &'static str {
        match self {
            Self::Account(_) => "account-storage",
            Self::Schema => "slot-schema",
            Self::Missing => "slot-missing",
            Self::Invalid => "slot-invalid",
            Self::NotReady => "slot-not-ready",
            Self::ReceiptChanged => "receipt-changed",
            Self::RequiresNewAuthorization => "requires-new-authorization",
            Self::IncompleteReplacement => "incomplete-replacement",
            Self::Interrupted => "interrupted",
        }
    }
}

/// 不公开随机字段；只由严格读取真实Ready槽构造，不接JSON/账号/计时/默认代次。
pub(in crate::server::core::account_store) struct ReadyGeneration {
    generation: String,
}

pub(in crate::server::core::account_store) struct ReadyCandidate {
    pub(in crate::server::core::account_store) stamp: Stamp,
    pub(in crate::server::core::account_store) generation: ReadyGeneration,
    pub(in crate::server::core::account_store) proxy: Value,
}

/// 只是事务内Pending候选；提交前不能外发。字段私有，无Clone/Debug/serde。
pub(in crate::server::core::account_store) struct PendingWrite {
    generation: String,
    operation: String,
}

pub(crate) enum Settlement {
    Rotated(CommitReceipt),
    Blocked(SlotFailure),
}

/// 外层锁外纯校验得到的完整五项；不是上游响应回执。该对象不改变身份/OAuth。
pub(in crate::server::core::account_store) struct Replacement {
    fields: Map<String, Value>,
    expires_at: i64,
}

impl Drop for Replacement {
    fn drop(&mut self) {
        record::wipe_fields(&mut self.fields);
    }
}

/// 固定首次登记事务的无槽核对；任何存在的行均拒绝，不读取payload补造资格。
pub(in crate::server::core::account_store::sql::credential_version) fn require_initial_absent(
    conn: &Connection,
    id: &str,
) -> Result<(), SlotFailure> {
    record::require_absent(conn, id)
}

pub(in crate::server::core::account_store::sql::credential_version) fn remove_for_new_login(conn: &Connection, id: &str) -> Result<(), SlotFailure> {
    record::remove_for_new_login(conn, id)
}

/// 仅首次显式登记事务可调用；原行已经写入最终版本，此处从不自行纳管旧账号。
pub(in crate::server::core::account_store::sql::credential_version) fn establish_initial(
    conn: &Connection,
    key: &[u8; 32],
    id: &str,
    version: &Version,
) -> Result<(), SlotFailure> {
    let generation = storage::random_id()?;
    record::insert_initial(
        conn,
        key,
        &Slot {
            schema: 1,
            provider: "codearts".to_string(),
            account_id: id.to_string(),
            db_epoch: version.epoch.clone(),
            born: version.born.clone(),
            revision: version.revision,
            generation,
            state: State::Ready {
                settled_operation: None,
            },
        },
    )
}

/// 导入完成后的自动登记：按账号当前版本建立 Ready 槽。
///
/// - 已有同版本的 Ready 槽：什么都不做，返回 false（不覆盖正常槽）；
/// - 缺槽、槽版本不符或槽停在 Pending/Blocked：删掉旧行后按当前版本重建。
///
/// 材料合法性由调用方先校验；这里只处理槽的存储状态。整段必须在事务内。
pub(in crate::server::core::account_store) fn establish_imported(
    conn: &Connection,
    key: &[u8; 32],
    id: &str,
    version: &Version,
) -> Result<bool, SlotFailure> {
    if conn.is_autocommit() {
        return Err(Error::Storage(StorageFailure::Begin).into());
    }
    record::initialize_empty(conn)?;
    if let Ok(slot) = record::load(conn, key, id) {
        if slot.db_epoch == version.epoch
            && slot.born == version.born
            && slot.revision == version.revision
            && matches!(slot.state, State::Ready { .. })
        {
            return Ok(false);
        }
    }
    conn.execute(
        "DELETE FROM main.codearts_refresh_slots WHERE account_id = ?1",
        [id],
    )
    .map_err(|error| storage::sql_error(error, StorageFailure::Write))?;
    establish_initial(conn, key, id, version)?;
    Ok(true)
}

/// 只读同原FULL/IMMEDIATE事务：读取真实加密行、已有版本/epoch、完整投影与同代Ready。
/// 不调用prepare/establish_epoch/initialize_empty；缺任何前置都拒绝，无写入动作。
pub(in crate::server::core::account_store) fn read_ready(
    conn: &Connection,
    key: &[u8; 32],
    id: &str,
    retained: &mut RetainedRows,
) -> Result<ReadyCandidate, SlotFailure> {
    if conn.is_autocommit() {
        return Err(Error::Storage(StorageFailure::Begin).into());
    }
    super::check_target("codearts", id)?;
    let index = record::load_account(conn, key, id, retained)?;
    let account = retained.account(index);
    eligible(account)?;
    let version =
        storage::version(account)?.ok_or(Error::Conflict(super::Conflict::UnestablishedVersion))?;
    let epoch =
        storage::epoch(conn)?.ok_or(Error::Conflict(super::Conflict::DatabaseEpochChanged))?;
    if version.epoch != epoch {
        return Err(Error::Conflict(super::Conflict::DatabaseEpochChanged).into());
    }
    let slot = record::load(conn, key, id)?;
    if slot.db_epoch != version.epoch
        || slot.born != version.born
        || slot.revision != version.revision
    {
        return Err(SlotFailure::ReceiptChanged);
    }
    if !matches!(&slot.state, State::Ready { .. }) {
        return Err(SlotFailure::NotReady);
    }
    let proxy = retained.account(index).get("proxy")
        .or_else(|| retained.account(index).get("pluginSecret").and_then(|secret| secret.get("proxy")))
        .cloned().unwrap_or(Value::Null);
    bounded::check(&proxy, 64 * 1024)?;
    let projection = retained.read_projection(index)?;
    Ok(ReadyCandidate {
        stamp: Stamp {
            id: id.to_string(),
            version,
            projection,
        },
        generation: ReadyGeneration { generation: slot.generation },
        proxy,
    })
}

/// 原ReadyRead按值消费；与原ReadStamp完整投影/版本及真实Ready generation逐一核对。
pub(in crate::server::core::account_store) fn begin(
    conn: &Connection,
    key: &[u8; 32],
    stamp: &Stamp,
    ready: &ReadyGeneration,
    retained: &mut RetainedRows,
) -> Result<PendingWrite, SlotFailure> {
    let index = current(conn, key, stamp, retained)?;
    eligible(retained.account(index))?;
    let mut slot = record::load(conn, key, &stamp.id)?;
    require_binding(&slot, stamp)?;
    if slot.generation != ready.generation {
        return Err(SlotFailure::ReceiptChanged);
    }
    let State::Ready { settled_operation } = &slot.state else {
        return Err(SlotFailure::NotReady);
    };
    let operation = storage::random_id()?;
    if operation == slot.generation || settled_operation.as_ref() == Some(&operation) {
        return Err(Error::Storage(StorageFailure::RandomUnavailable).into());
    }
    slot.state = State::Pending {
        operation: operation.clone(),
    };
    record::update(conn, key, &slot)?;
    Ok(PendingWrite {
        generation: slot.generation,
        operation,
    })
}

/// 原Pending结清：本次五项完整值/私有版本/下一Ready只占原行原槽，同事务回读确认。
/// replacement从锁外预检按借用传入；任何错误都不沿用旧刷新令牌或另取来源。
pub(in crate::server::core::account_store) fn complete(
    conn: &Connection,
    key: &[u8; 32],
    stamp: &Stamp,
    pending: &PendingWrite,
    replacement: &Replacement,
    retained: &mut RetainedRows,
) -> Result<Settlement, SlotFailure> {
    let mut slot = pending_slot(conn, key, stamp, pending)?;
    let index = match current(conn, key, stamp, retained) {
        Ok(index) => index,
        Err(error) => return block_with(conn, key, &mut slot, error),
    };
    if let Err(error) = eligible(retained.account(index)) {
        return block_with(conn, key, &mut slot, error);
    }
    let now = crate::server::logging::now_ms();
    if now <= 0 || replacement.expires_at <= now {
        return block_with(conn, key, &mut slot, SlotFailure::IncompleteReplacement);
    }
    let original_index = index;
    let index = match record::apply_replacement(
        retained,
        index,
        &replacement.fields,
        replacement.expires_at,
    ) {
        Ok(index) => index,
        Err(error) => return block_with(conn, key, &mut slot, error),
    };
    if let Err(error) =
        validate_replacement_view(retained.account(original_index), retained.account(index))
    {
        return block_with(conn, key, &mut slot, error);
    }
    let Some(revision) = stamp.version.revision.checked_add(1) else {
        return block_with(conn, key, &mut slot, Error::VersionExhausted.into());
    };
    // 完整新投影也只在外层持有，SQL返回/设置恢复失败不会在外层锁内丢弃其内容。
    if let Err(error) = retained.keep_projection(index) {
        return block_with(conn, key, &mut slot, error);
    }
    let next_generation = storage::random_id()?;
    if next_generation == slot.generation || next_generation == pending.operation {
        return Err(Error::Storage(StorageFailure::RandomUnavailable).into());
    }
    record::set_field(
        retained,
        index,
        crate::server::core::account_store::credential_version::PRIVATE_FIELD,
        serde_json::json!({ "schema":1, "dbEpoch":stamp.version.epoch, "born":stamp.version.born, "revision":revision }),
    );
    record::set_field(retained, index, "updatedAt", Value::from(now));
    record::write_account(conn, key, retained, index)?;
    let readback = record::load_account(conn, key, &stamp.id, retained)?;
    if retained.account(readback).fields() != retained.account(index).fields() {
        return Err(Error::Storage(StorageFailure::Write).into());
    }
    slot.revision = revision;
    slot.generation = next_generation;
    slot.state = State::Ready {
        settled_operation: Some(pending.operation.clone()),
    };
    record::update(conn, key, &slot)?;
    // 本轮已真正换票成功：清掉自动 reclaim 冷却，下一次新的封锁可以立即恢复。
    let _ = super::codearts_reclaim::delete(conn, &stamp.id);
    Ok(Settlement::Rotated(CommitReceipt {
        revision_advanced: true,
    }))
}

/// 原Pending唯一操作收据才能封锁；缺槽、旧Db/epoch/generation或其它操作不能代替。
pub(in crate::server::core::account_store) fn block(
    conn: &Connection,
    key: &[u8; 32],
    stamp: &Stamp,
    pending: &PendingWrite,
) -> Result<(), SlotFailure> {
    let mut slot = pending_slot(conn, key, stamp, pending)?;
    slot.state = State::Blocked {
        operation: pending.operation.clone(),
    };
    record::update(conn, key, &slot)
}

/// 请求确定**尚未发出**时的安全回退：Pending → Ready。
///
/// 调用方必须先证明 HTTP 请求没有执行（例如在 `execute` 之前就失败）：
/// 此时上游没有消费刷新令牌，账号材料不需要推进版本，只需把槽恢复成
/// 新代次的 Ready，下一次维护可以继续尝试。与 block 一样，必须持本次
/// Pending 的唯一收据（operation/generation 与槽一致），否则拒绝。
pub(in crate::server::core::account_store) fn cancel_pending(
    conn: &Connection,
    key: &[u8; 32],
    stamp: &Stamp,
    pending: &PendingWrite,
) -> Result<(), SlotFailure> {
    let mut slot = pending_slot(conn, key, stamp, pending)?;
    let next = storage::random_id()?;
    if next == slot.generation || next == pending.operation {
        return Err(Error::Storage(StorageFailure::RandomUnavailable).into());
    }
    slot.generation = next;
    slot.state = State::Ready {
        settled_operation: Some(pending.operation.clone()),
    };
    record::update(conn, key, &slot)
}

/// 自动 reclaim 一个 Blocked 槽：改回 Ready（同 revision、新 generation）。
///
/// 只允许在账号版本与槽绑定完全一致时执行；版本不一致说明账号在封锁后被
/// 重新导入/改过，回退 Ready 也过不了读校验，交给登记流程处理，返回 false。
/// Blocked 的操作语义是「可能已发出但结果未确认」，重试不会造成二次消费：
/// 令牌若已被消费，上游只会再拒绝一次；若没有，则正好恢复。
pub(in crate::server::core::account_store) fn reclaim_blocked(
    conn: &Connection,
    key: &[u8; 32],
    id: &str,
) -> Result<bool, SlotFailure> {
    if conn.is_autocommit() {
        return Err(Error::Storage(StorageFailure::Begin).into());
    }
    let mut slot = record::load(conn, key, id)?;
    let State::Blocked { operation } = &slot.state else {
        return Ok(false);
    };
    let operation = operation.clone();
    let account = storage::load(conn, key, id)?;
    let Some(version) = storage::version(&account)? else {
        return Ok(false);
    };
    if slot.db_epoch != version.epoch
        || slot.born != version.born
        || slot.revision != version.revision
    {
        return Ok(false);
    }
    let next = storage::random_id()?;
    if next == slot.generation || next == operation {
        return Err(Error::Storage(StorageFailure::RandomUnavailable).into());
    }
    slot.generation = next;
    slot.state = State::Ready {
        settled_operation: Some(operation),
    };
    record::update(conn, key, &slot)?;
    Ok(true)
}

fn current(
    conn: &Connection,
    key: &[u8; 32],
    stamp: &Stamp,
    retained: &mut RetainedRows,
) -> Result<usize, SlotFailure> {
    if conn.is_autocommit() {
        return Err(Error::Storage(StorageFailure::Begin).into());
    }
    let epoch =
        storage::epoch(conn)?.ok_or(Error::Conflict(super::Conflict::DatabaseEpochChanged))?;
    if epoch != stamp.version.epoch {
        return Err(Error::Conflict(super::Conflict::DatabaseEpochChanged).into());
    }
    let index = record::load_account(conn, key, &stamp.id, retained)?;
    let version = storage::version(retained.account(index))?
        .ok_or(Error::Conflict(super::Conflict::UnestablishedVersion))?;
    if version != stamp.version {
        return Err(Error::Conflict(super::Conflict::VersionChanged).into());
    }
    let projection = retained.keep_projection(index)?;
    if retained.projection(projection) != &stamp.projection {
        return Err(Error::Conflict(super::Conflict::AuthorizationChanged).into());
    }
    Ok(index)
}

fn eligible(account: &StoredAccount) -> Result<(), SlotFailure> {
    for fields in [
        Some(account.fields()),
        account.get("pluginSecret").and_then(Value::as_object),
        account.get("pluginPublic").and_then(Value::as_object),
    ]
    .into_iter()
    .flatten()
    {
        if fields
            .get("needsRelogin")
            .is_some_and(|value| value.as_bool() != Some(false))
        {
            return Err(SlotFailure::RequiresNewAuthorization);
        }
        if fields
            .get("desktop")
            .is_some_and(|value| value.as_bool() != Some(false))
        {
            return Err(SlotFailure::Invalid);
        }
    }
    Ok(())
}

fn require_binding(slot: &Slot, stamp: &Stamp) -> Result<(), SlotFailure> {
    if slot.account_id != stamp.id
        || slot.db_epoch != stamp.version.epoch
        || slot.born != stamp.version.born
        || slot.revision != stamp.version.revision
    {
        return Err(SlotFailure::ReceiptChanged);
    }
    Ok(())
}

fn pending_slot(
    conn: &Connection,
    key: &[u8; 32],
    stamp: &Stamp,
    pending: &PendingWrite,
) -> Result<Slot, SlotFailure> {
    let epoch =
        storage::epoch(conn)?.ok_or(Error::Conflict(super::Conflict::DatabaseEpochChanged))?;
    if epoch != stamp.version.epoch {
        return Err(Error::Conflict(super::Conflict::DatabaseEpochChanged).into());
    }
    let slot = record::load(conn, key, &stamp.id)?;
    require_binding(&slot, stamp)?;
    if slot.generation != pending.generation
        || !matches!(&slot.state, State::Pending { operation } if operation == &pending.operation)
    {
        return Err(SlotFailure::ReceiptChanged);
    }
    Ok(slot)
}

fn block_with(
    conn: &Connection,
    key: &[u8; 32],
    slot: &mut Slot,
    error: SlotFailure,
) -> Result<Settlement, SlotFailure> {
    let State::Pending { operation } = &slot.state else {
        return Err(SlotFailure::ReceiptChanged);
    };
    slot.state = State::Blocked {
        operation: operation.clone(),
    };
    record::update(conn, key, slot)?;
    // Ok仅要求真实提交Blocked，业务结果绝不是成功。
    Ok(Settlement::Blocked(error))
}

const MATERIAL: &[&str] = &[
    "access_key_id",
    "accessKeyId",
    "accessToken",
    "secret_access_key",
    "secretAccessKey",
    "security_token",
    "securityToken",
    "refresh_token",
    "refreshToken",
    "expiration",
    "expires_at",
    "expiresAt",
];
const PUBLIC_SCALARS: &[&str] = &[
    "tokenTail",
    "hasAccessToken",
    "hasRefreshToken",
    "hasToken",
    "hasCredentials",
    "canRefresh",
    "available",
    "expiresAt",
    "expiresAtMs",
    "tokenExpireAt",
    "tokenExpiresAt",
    "accessTokenExpiresAt",
    "refreshTokenExpiresAt",
    "needsRelogin",
    "needsReloginReason",
];

/// 固定替换仍核对原生/secret/容器的非材料字段，防止新增实现洗掉身份/原OAuth或未知字段。
/// 公开视图不允许旧/新敏感材料回显；只借用两份外层保留原行，无JSON克隆和锁内销毁。
fn validate_replacement_view(
    original: &StoredAccount,
    next: &StoredAccount,
) -> Result<(), SlotFailure> {
    fn same(left: &Map<String, Value>, right: &Map<String, Value>, containers: bool) -> bool {
        for (name, value) in left {
            if MATERIAL.contains(&name.as_str()) {
                continue;
            }
            if containers
                && matches!(
                    name.as_str(),
                    "credential" | "codearts_provider_credential" | "auth"
                )
            {
                let (Some(left), Some(right)) = (
                    value.as_object(),
                    right.get(name).and_then(Value::as_object),
                ) else {
                    return false;
                };
                if !same(left, right, false) {
                    return false;
                }
            } else if right.get(name) != Some(value) {
                return false;
            }
        }
        right
            .keys()
            .all(|name| MATERIAL.contains(&name.as_str()) || left.contains_key(name))
    }
    let old_secret = original.get("pluginSecret").and_then(Value::as_object);
    let new_secret = next.get("pluginSecret").and_then(Value::as_object);
    match (old_secret, new_secret) {
        (Some(left), Some(right)) if same(left, right, true) => {}
        (None, None) => {}
        _ => return Err(SlotFailure::Invalid),
    }
    for name in ["credential", "codearts_provider_credential", "auth"] {
        match (original.get(name), next.get(name)) {
            (Some(Value::Object(left)), Some(Value::Object(right))) if same(left, right, false) => {
            }
            (None, None) => {}
            _ => return Err(SlotFailure::Invalid),
        }
    }
    let public = next
        .get("pluginPublic")
        .and_then(Value::as_object)
        .ok_or(SlotFailure::Invalid)?;
    fn sensitive(name: &str) -> bool {
        let name = Zeroizing::new(name.to_ascii_lowercase().replace(['_', '-'], ""));
        let name = name.as_str();
        name.contains("token")
            || name.contains("password")
            || name.contains("secret")
            || name.contains("cookie")
            || name.contains("authorization")
            || name.contains("privatekey")
            || name == "oauthcontext"
            || name == "auth"
            || name == "key"
            || name == "accesskeyid"
            || name == "codeverifier"
            || name == "d"
    }
    fn collect<'a>(
        fields: &'a Map<String, Value>,
        secrets: &mut Vec<&'a str>,
        protected: bool,
    ) -> Result<(), SlotFailure> {
        for (name, value) in fields {
            gather(value, secrets, protected || sensitive(name))?;
        }
        Ok(())
    }
    fn gather<'a>(
        value: &'a Value,
        secrets: &mut Vec<&'a str>,
        protected: bool,
    ) -> Result<(), SlotFailure> {
        match value {
            Value::Object(fields) => collect(fields, secrets, protected),
            Value::Array(items) => {
                for value in items {
                    gather(value, secrets, protected)?;
                }
                Ok(())
            }
            Value::String(text) if protected && !text.is_empty() => {
                if secrets.len() >= 4096 {
                    return Err(Error::LimitExceeded.into());
                }
                secrets.push(text);
                Ok(())
            }
            _ => Ok(()),
        }
    }
    fn scalar(name: &str, value: &Value) -> bool {
        match name {
            "hasAccessToken" | "hasRefreshToken" | "hasToken" | "hasCredentials" | "canRefresh"
            | "available" | "needsRelogin" => value.is_boolean(),
            "expiresAt"
            | "expiresAtMs"
            | "tokenExpireAt"
            | "tokenExpiresAt"
            | "accessTokenExpiresAt"
            | "refreshTokenExpiresAt" => {
                value.is_null() || value.as_i64().is_some_and(|value| value > 0)
            }
            "tokenTail" => {
                value.is_null()
                    || value.as_str().is_some_and(|text| {
                        text.chars().count() <= 6 && !text.chars().any(char::is_control)
                    })
            }
            "needsReloginReason" => {
                value.is_null()
                    || value.as_str().is_some_and(|text| {
                        text.len() <= 2048 && !text.chars().any(char::is_control)
                    })
            }
            _ => false,
        }
    }
    fn check(value: &Value, secrets: &[&str]) -> bool {
        match value {
            Value::Object(fields) => fields.iter().all(|(name, value)| {
                let private =
                    crate::server::core::account_store::credential_version::private_field(name);
                !private
                    && (!sensitive(name)
                        || PUBLIC_SCALARS.contains(&name.as_str()) && scalar(name, value))
                    && check(value, secrets)
            }),
            Value::Array(items) => items.iter().all(|value| check(value, secrets)),
            Value::String(text) => !secrets.iter().any(|secret| text.contains(secret)),
            _ => true,
        }
    }
    let mut secrets = Vec::new();
    for row in [original, next] {
        for name in MATERIAL {
            if let Some(value) = row.get(name) {
                gather(value, &mut secrets, true)?;
            }
        }
        for name in [
            "oauth_context",
            "pluginSecret",
            "credential",
            "codearts_provider_credential",
            "auth",
        ] {
            if let Some(value) = row.get(name) {
                gather(
                    value,
                    &mut secrets,
                    matches!(name, "oauth_context" | "auth"),
                )?;
            }
        }
    }
    if !public.iter().all(|(name, value)| {
        !crate::server::core::account_store::credential_version::private_field(name)
            && (!sensitive(name) || PUBLIC_SCALARS.contains(&name.as_str()) && scalar(name, value))
            && check(value, &secrets)
    }) {
        return Err(SlotFailure::Invalid);
    }
    Ok(())
}

const ALIASES: &[&[&str]] = &[
    &["access_key_id", "accessKeyId", "accessToken"],
    &["secret_access_key", "secretAccessKey"],
    &["security_token", "securityToken"],
    &["refresh_token", "refreshToken"],
    &["expiration", "expires_at"],
];

pub(in crate::server::core::account_store) fn prepare_replacement(
    credentials: &Value,
) -> Result<Replacement, SlotFailure> {
    // 纯校验由PendingSlot门面在取任何存储锁之前调用，候选从不构造来源或发送回执。
    bounded::check(credentials, bounded::MAX_SECRET_BYTES)?;
    let fields = credentials
        .as_object()
        .ok_or(SlotFailure::IncompleteReplacement)?;
    if fields
        .keys()
        .any(|key| key != "expiresAt" && !ALIASES.iter().any(|group| group.contains(&key.as_str())))
    {
        return Err(SlotFailure::IncompleteReplacement);
    }
    let mut replacement = Replacement {
        fields: Map::new(),
        expires_at: 0,
    };
    for (index, aliases) in ALIASES.iter().enumerate() {
        let text = replacement_text(fields, aliases, if index == 4 { 1024 } else { 32 * 1024 })?;
        if matches!(index, 0 | 2) && !text.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(SlotFailure::IncompleteReplacement);
        }
        for name in *aliases {
            replacement
                .fields
                .insert((*name).to_string(), Value::String(text.to_string()));
        }
        if index == 4 {
            let expires = chrono::DateTime::parse_from_rfc3339(text)
                .map_err(|_| SlotFailure::IncompleteReplacement)?
                .timestamp_millis();
            let now = crate::server::logging::now_ms();
            if now <= 0
                || expires <= now
                || fields
                    .get("expiresAt")
                    .is_some_and(|value| value.as_i64() != Some(expires))
            {
                return Err(SlotFailure::IncompleteReplacement);
            }
            replacement.expires_at = expires;
            replacement
                .fields
                .insert("expiresAt".to_string(), Value::from(expires));
        }
    }
    drop(Zeroizing::new(bounded::encode_fields(
        &replacement.fields,
        bounded::MAX_SECRET_BYTES,
    )?));
    Ok(replacement)
}

fn replacement_text<'a>(
    fields: &'a Map<String, Value>,
    aliases: &[&str],
    maximum: usize,
) -> Result<&'a str, SlotFailure> {
    let mut found = None;
    for name in aliases {
        if let Some(value) = fields.get(*name) {
            let text = value.as_str().ok_or(SlotFailure::IncompleteReplacement)?;
            if text.is_empty()
                || text.len() > maximum
                || text.trim() != text
                || text.chars().any(char::is_control)
                || found.is_some_and(|previous| previous != text)
            {
                return Err(SlotFailure::IncompleteReplacement);
            }
            found = Some(text);
        }
    }
    found.ok_or(SlotFailure::IncompleteReplacement)
}

/// 换票结果恢复的结论：完成结算 / 判定陈旧并丢弃 / 无法恢复（槽已落 Blocked）。
pub(in crate::server::core::account_store) enum Recovery {
    Completed,
    Discarded,
    Failed(SlotFailure),
}

impl PendingWrite {
    pub(in crate::server::core::account_store) fn operation(&self) -> &str {
        &self.operation
    }

    pub(in crate::server::core::account_store) fn generation(&self) -> &str {
        &self.generation
    }
}

/// 用耐久日志里的一次上游响应补完结算。
///
/// 只在账号版本、槽的 operation/generation/版本全部仍指向同一次 Pending 时执行；
/// 其余情形一律判陈旧并交由调用方删除记录——绝不重发旧刷新令牌，也不猜测代次。
pub(in crate::server::core::account_store) fn recover_one(
    conn: &Connection,
    key: &[u8; 32],
    entry: &super::codearts_result::Entry,
) -> Result<Recovery, Error> {
    if conn.is_autocommit() {
        return Err(Error::Storage(StorageFailure::Begin));
    }
    let account = match storage::load(conn, key, &entry.account) {
        Ok(account) => account,
        Err(Error::Conflict(Conflict::MissingAccount)) => return Ok(Recovery::Discarded),
        // 存储/解密失败不是“陈旧”：保留日志等下一轮，绝不因一次读失败丢掉唯一副本。
        Err(error) => return Err(error),
    };
    let Some(version) = storage::version(&account)? else {
        return Ok(Recovery::Discarded);
    };
    if version != entry.version {
        return Ok(Recovery::Discarded);
    }
    let slot = match record::load(conn, key, &entry.account) {
        Ok(slot) => slot,
        Err(SlotFailure::Account(error)) => return Err(error),
        Err(_) => return Ok(Recovery::Discarded),
    };
    match &slot.state {
        // 已经结算过（槽版本不落后）：日志只是没删掉。
        State::Ready { .. } if slot.revision >= version.revision => return Ok(Recovery::Discarded),
        State::Pending { operation }
            if operation == &entry.operation
                && slot.generation == entry.generation
                && slot.revision == version.revision
                && slot.born == version.born
                && slot.db_epoch == version.epoch => {}
        _ => return Ok(Recovery::Discarded),
    }
    let projection = Projection::read(&account)?;
    let stamp = Stamp {
        id: entry.account.clone(),
        version: version.clone(),
        projection,
    };
    let pending = PendingWrite {
        generation: entry.generation.clone(),
        operation: entry.operation.clone(),
    };
    let replacement = match prepare_replacement(&entry.body) {
        Ok(replacement) => replacement,
        Err(error) => {
            let _ = block(conn, key, &stamp, &pending);
            return Ok(Recovery::Failed(error));
        }
    };
    let mut retained = RetainedRows::new();
    match complete(conn, key, &stamp, &pending, &replacement, &mut retained) {
        Ok(Settlement::Rotated(_)) => Ok(Recovery::Completed),
        Ok(Settlement::Blocked(error)) => Ok(Recovery::Failed(error)),
        Err(error) => {
            let _ = block(conn, key, &stamp, &pending);
            Ok(Recovery::Failed(error))
        }
    }
}

/// 导入后自动登记的结果；`Skipped` 只携带固定原因码，不回显凭据。
pub(in crate::server::core::account_store) enum ImportedEnrollmentResult {
    Established,
    Already,
    Skipped(&'static str),
}

fn pick_material(
    secret: &Map<String, Value>,
    fields: &Map<String, Value>,
    aliases: &[&str],
) -> Result<Option<String>, &'static str> {
    for source in [secret, fields] {
        let mut found: Option<String> = None;
        for alias in aliases {
            let Some(Value::String(text)) = source.get(*alias) else {
                continue;
            };
            if text.is_empty() {
                continue;
            }
            match &found {
                None => found = Some(text.clone()),
                Some(previous) if previous == text => {}
                Some(_) => return Err("alias-conflict"),
            }
        }
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}

/// 只从已存账号里取登记白名单字段；未知字段与嵌套结构不进入校验。
fn imported_material(account: &StoredAccount) -> Result<Value, &'static str> {
    let empty = Map::new();
    let (secret, fields) = match account.get("pluginSecret") {
        Some(Value::Object(secret)) if !secret.is_empty() => (secret, account.fields()),
        _ => (&empty, account.fields()),
    };
    let access = pick_material(secret, fields, &["access_key_id", "accessKeyId", "accessToken"])?
        .ok_or("missing-access")?;
    let secret_key = pick_material(secret, fields, &["secret_access_key", "secretAccessKey"])?
        .ok_or("missing-secret")?;
    let security = pick_material(secret, fields, &["security_token", "securityToken"])?
        .ok_or("missing-security")?;
    let refresh = pick_material(secret, fields, &["refresh_token", "refreshToken"])?
        .ok_or("missing-refresh")?;
    let expiration = pick_material(secret, fields, &["expiration", "expires_at"])?
        .ok_or("missing-expiration")?;
    let domain = pick_material(secret, fields, &["domain_id", "account_id", "domainId"])?
        .ok_or("missing-domain")?;
    let user = pick_material(secret, fields, &["user_id", "principal_id", "userId"])?
        .ok_or("missing-user")?;
    let context = secret
        .get("oauth_context")
        .or_else(|| fields.get("oauth_context"))
        .cloned()
        .ok_or("missing-oauth")?;
    let mut out = Map::new();
    out.insert("provider".into(), Value::String("codearts".into()));
    out.insert("access_key_id".into(), Value::String(access));
    out.insert("secret_access_key".into(), Value::String(secret_key));
    out.insert("security_token".into(), Value::String(security));
    out.insert("refresh_token".into(), Value::String(refresh));
    out.insert("expiration".into(), Value::String(expiration));
    out.insert("domain_id".into(), Value::String(domain));
    out.insert("user_id".into(), Value::String(user));
    out.insert("oauth_context".into(), context);
    let expires_at = secret
        .get("expiresAt")
        .and_then(Value::as_i64)
        .or_else(|| fields.get("expiresAt").and_then(Value::as_i64));
    if let Some(ms) = expires_at {
        out.insert("expiresAt".into(), Value::from(ms));
    }
    let name = account
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .or_else(|| secret.get("user_name").and_then(Value::as_str))
        .or_else(|| fields.get("user_name").and_then(Value::as_str));
    if let Some(name) = name {
        out.insert("name".into(), Value::String(name.to_string()));
    }
    Ok(Value::Object(out))
}

/// 同一条事务内完成“读账号 → 校验材料 → 建立 Ready 槽”，避免校验与登记之间
/// 账号被改动。材料不合法时返回固定原因码，不抛错。
pub(in crate::server::core::account_store) fn enroll_imported(
    conn: &Connection,
    key: &[u8; 32],
    id: &str,
) -> Result<ImportedEnrollmentResult, SlotFailure> {
    if conn.is_autocommit() {
        return Err(Error::Storage(StorageFailure::Begin).into());
    }
    let account = match storage::load(conn, key, id) {
        Ok(account) => account,
        Err(Error::Conflict(Conflict::MissingAccount)) => {
            return Ok(ImportedEnrollmentResult::Skipped("account-unavailable"))
        }
        Err(error) => return Err(error.into()),
    };
    if account.provider() != "codearts" {
        return Ok(ImportedEnrollmentResult::Skipped("not-codearts"));
    }
    let Some(version) = storage::version(&account)? else {
        return Ok(ImportedEnrollmentResult::Skipped("no-version"));
    };
    let candidate = match imported_material(&account) {
        Ok(candidate) => candidate,
        Err(reason) => return Ok(ImportedEnrollmentResult::Skipped(reason)),
    };
    let Some(fields) = candidate.as_object() else {
        return Ok(ImportedEnrollmentResult::Skipped("material-invalid"));
    };
    if let Err(error) =
        crate::server::core::account_store::credential_version::validate_imported(fields)
    {
        return Ok(ImportedEnrollmentResult::Skipped(error.code()));
    }
    match establish_imported(conn, key, id, &version) {
        Ok(true) => Ok(ImportedEnrollmentResult::Established),
        Ok(false) => Ok(ImportedEnrollmentResult::Already),
        Err(error) => {
            let _ = error;
            Ok(ImportedEnrollmentResult::Skipped("slot-state"))
        }
    }
}
