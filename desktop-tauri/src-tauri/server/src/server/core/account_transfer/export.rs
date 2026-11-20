use serde::Serialize;
use serde_json::Value;
use std::io::{Cursor, Write};

use zip::write::SimpleFileOptions;

use crate::server::core::account_store::sql;
use crate::server::core::account_store::state::StoredAccount;
use crate::server::core::account_store::{AccountStore, AccountStoreError};

use super::identity::CREDENTIAL_KEYS;

pub const ACCOUNT_FILE_FORMAT: &str = "agent2api-account";

pub enum ExportSelection {
    Account(String),
    Provider(String),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountFile {
    pub id: String,
    pub name: String,
    pub file_name: String,
    pub content: Value,
}

#[derive(Serialize)]
pub struct ExportFailure {
    pub id: String,
    pub name: String,
    pub error: String,
}

#[derive(Serialize)]
pub struct AccountFiles {
    pub total: usize,
    pub files: Vec<AccountFile>,
    pub failed: Vec<ExportFailure>,
}

pub fn export_account_files(
    store: &AccountStore,
    selection: ExportSelection,
) -> Result<AccountFiles, AccountStoreError> {
    let definitions = crate::server::core::custom_providers::list();
    let stamp = crate::server::logging::now_ms();
    store.with_lock(|guard| {
        let ids = match selection {
            ExportSelection::Account(id) => vec![id],
            ExportSelection::Provider(provider) => {
                let mut rows = store.with_conn(guard, sql::queue_rows)?;
                rows.retain(|row| row.provider == provider);
                rows.sort_by_key(|row| (row.priority, row.added_at, row.id.clone()));
                rows.into_iter().map(|row| row.id).collect()
            }
        };
        let mut result = AccountFiles {
            total: ids.len(),
            files: Vec::new(),
            failed: Vec::new(),
        };
        for (index, id) in ids.into_iter().enumerate() {
            let record = match store.with_conn(guard, |conn| sql::load_by_id(conn, &id)) {
                Ok(Some(record)) => record,
                Ok(None) => {
                    result.failed.push(ExportFailure {
                        id,
                        name: String::new(),
                        error: "账号不存在".to_string(),
                    });
                    continue;
                }
                Err(error) => {
                    result.failed.push(ExportFailure {
                        id,
                        name: String::new(),
                        error: error.message,
                    });
                    continue;
                }
            };
            match account_file(&record, &definitions, stamp, index + 1) {
                Ok(file) => result.files.push(file),
                Err(error) => result.failed.push(ExportFailure {
                    id,
                    name: record.name(),
                    error,
                }),
            }
        }
        Ok(result)
    })
}

fn account_file(
    record: &StoredAccount,
    definitions: &[Value],
    stamp: i64,
    index: usize,
) -> Result<AccountFile, String> {
    let provider = record.provider();
    let mut content = super::to_export_record(record)
        .as_object()
        .cloned()
        .unwrap_or_default();
    content.retain(|key, _| !key.starts_with("pluginLedger."));
    // 插件凭证优先于顶层镜像；摊平后仍保留原始 secret，兼容凭证导入与备份回流。
    if let Some(Value::Object(secret)) = record.get("pluginSecret") {
        // 旧记录的镜像可能已失效；插件 secret 是凭证的权威副本。
        for key in CREDENTIAL_KEYS {
            content.remove(*key);
        }
        for (key, value) in secret {
            if key.starts_with('_')
                || key.starts_with("pluginLedger.")
                || matches!(
                    key.as_str(),
                    "id" | "provider"
                        | "name"
                        | "priority"
                        | "enabled"
                        | "addedAt"
                        | "updatedAt"
                        | "rateLimits"
                        | "pluginSecret"
                        | "pluginPublic"
                        | "customProviders"
                )
            {
                continue;
            }
            content.insert(key.clone(), value.clone());
        }
    }
    let desktop =
        record.is_desktop() || content.get("desktop").and_then(Value::as_bool) == Some(true);
    if desktop && super::identity::is_reserved_desktop_id(record.id()) {
        return Err(
            "桌面端实时登录态的凭证不随账号文件迁移，请在目标机器重新导入桌面端登录态".to_string(),
        );
    }
    if desktop {
        let credentials = record
            .get("pluginSecret")
            .and_then(Value::as_object)
            .unwrap_or(record.fields());
        let has_token = CREDENTIAL_KEYS.iter().any(|key| {
            credentials
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        });
        if !has_token {
            return Err("桌面端实时登录态的凭证未保存在账号库中，无法导出；请在目标机器重新导入桌面端登录态".to_string());
        }
        content.remove("desktop");
        if let Some(Value::Object(secret)) = content.get_mut("pluginSecret") {
            secret.remove("desktop");
        }
        if let Some(Value::Object(public)) = content.get_mut("pluginPublic") {
            public.insert("desktop".to_string(), Value::Bool(false));
        }
    }
    if !record.has_credentials() {
        return Err("账号未配置凭证，无法导出".to_string());
    }
    let name = record.name();
    content.insert("id".to_string(), Value::String(record.id().to_string()));
    content.insert("provider".to_string(), Value::String(provider.clone()));
    content.insert("name".to_string(), Value::String(name.clone()));
    content.insert(
        "format".to_string(),
        Value::String(ACCOUNT_FILE_FORMAT.to_string()),
    );
    if let Some(Value::Object(secret)) = record.get("pluginSecret") {
        let has_access = content
            .get("accessToken")
            .and_then(Value::as_str)
            .is_some_and(|token| !token.trim().is_empty());
        if !has_access {
            if let Some(token) = ["token", "access_token", "session"].iter().find_map(|key| {
                secret
                    .get(*key)
                    .and_then(Value::as_str)
                    .filter(|token| !token.trim().is_empty())
            }) {
                content.insert("accessToken".to_string(), Value::String(token.to_string()));
            }
        }
    }
    if provider.starts_with(crate::server::core::custom_providers::ID_PREFIX) {
        let definition = definitions
            .iter()
            .find(|item| item.get("id").and_then(Value::as_str) == Some(provider.as_str()))
            .ok_or_else(|| "自定义提供商定义不存在，无法导出可迁移的账号".to_string())?;
        content.insert(
            "customProviders".to_string(),
            Value::Array(vec![definition.clone()]),
        );
    }
    let label = if name.trim().is_empty() {
        record.id()
    } else {
        name.trim()
    };
    let stem = safe_file_stem(&format!("{provider}-{label}"));
    Ok(AccountFile {
        id: record.id().to_string(),
        name,
        file_name: format!("{stem}-{stamp}-{index:03}.json"),
        content: Value::Object(content),
    })
}

fn safe_file_stem(value: &str) -> String {
    let stem: String = value
        .chars()
        .take(90)
        .map(|char| {
            if char.is_control()
                || matches!(char, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
            {
                '_'
            } else {
                char
            }
        })
        .collect();
    let stem = stem.trim().trim_end_matches(['.', ' ']);
    if stem.is_empty() {
        "account".to_string()
    } else {
        stem.to_string()
    }
}

/// 批量导出方式（账号页「批量操作 → 导出」的两个选项）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BatchExportMode {
    /// 所有选中账号合并进一个导入文件（`{ accounts: [...] }`）。
    Combined,
    /// 每个账号一个 JSON，打包成 zip。
    Separate,
}

/// 批量导出的成品：字节在内存里构造完成，落盘 / 下载 / 导出后删除都由调用方决定。
///
/// 删除放在调用方而不是这里：导出成功才删，删失败只记 `deleteFailed`，
/// 不能因为一个账号删不掉就把整批导出判成失败。
pub struct BatchExport {
    pub bytes: Vec<u8>,
    pub file_name: String,
    pub mime: &'static str,
    /// 成功导出的账号数（= `exported_ids.len()`）。
    pub count: usize,
    /// 单条导出失败（账号不存在 / 无凭证 / 桌面端登录态不可导出）。
    pub failed: Vec<ExportFailure>,
    /// 成功导出的账号 id —— 「导出后删除」只删这一批。
    pub exported_ids: Vec<String>,
}

/// 批量导出：逐个走单账号导出（同一份内容与命名规则），再按模式拼成品。
///
/// 为什么逐个调用而不是先取一次锁：`export_account_files` 已经带锁、带定义合并、
/// 带桌面端拒绝规则，直接复用能保证「单账号导出」与批量里的单文件逐字节同形；
/// 一次选中几十个账号的开销主要在 IO 与序列化，多取几次锁可以忽略。
pub fn export_batch(
    store: &AccountStore,
    ids: &[String],
    mode: BatchExportMode,
) -> Result<BatchExport, AccountStoreError> {
    let mut files: Vec<AccountFile> = Vec::new();
    let mut failed: Vec<ExportFailure> = Vec::new();
    for id in ids {
        let result = export_account_files(store, ExportSelection::Account(id.clone()))?;
        failed.extend(result.failed);
        files.extend(result.files);
    }
    assemble_batch(files, failed, mode)
}

/// 把已导出的单账号文件拼成最终成品（合并 JSON / 逐账号 zip）。
///
/// 与存储解耦：`export_batch` 负责取数，这里只做装配 —— 单测可以直接喂构造好的
/// `AccountFile`，不必拉起账号库。
fn assemble_batch(
    files: Vec<AccountFile>,
    failed: Vec<ExportFailure>,
    mode: BatchExportMode,
) -> Result<BatchExport, AccountStoreError> {
    let count = files.len();
    let exported_ids: Vec<String> = files.iter().map(|file| file.id.clone()).collect();
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    match mode {
        BatchExportMode::Combined => {
            // 自定义提供商定义随账号一起带走（与 v2 导出文件同口径），按 id 去重。
            let mut providers: Vec<Value> = Vec::new();
            for file in &files {
                if let Some(Value::Array(items)) = file.content.get("customProviders") {
                    for item in items {
                        let duplicate = providers
                            .iter()
                            .any(|existing| existing.get("id") == item.get("id"));
                        if !duplicate {
                            providers.push(item.clone());
                        }
                    }
                }
            }
            let content = serde_json::json!({
                "version": super::EXPORT_VERSION,
                "exportedAt": crate::server::logging::now_ms(),
                "accounts": files.iter().map(|file| file.content.clone()).collect::<Vec<_>>(),
                "customProviders": providers,
            });
            let bytes = serde_json::to_vec_pretty(&content)
                .map_err(|_| AccountStoreError::new("批量导出内容序列化失败", 500))?;
            Ok(BatchExport {
                bytes,
                file_name: format!("agent2api-accounts-{stamp}.json"),
                mime: "application/json",
                count,
                failed,
                exported_ids,
            })
        }
        BatchExportMode::Separate => {
            let mut cursor = Cursor::new(Vec::<u8>::new());
            {
                let mut writer = zip::ZipWriter::new(&mut cursor);
                let options = SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(0o644);
                let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
                for file in &files {
                    let bytes = serde_json::to_vec_pretty(&file.content)
                        .map_err(|_| AccountStoreError::new("批量导出内容序列化失败", 500))?;
                    // 同名账号（备注名重复）会让 zip 里出现两个同名条目；按后缀去重。
                    let mut name = file.file_name.clone();
                    let stem = file.file_name.trim_end_matches(".json").to_string();
                    let mut suffix = 2;
                    while !used.insert(name.clone()) {
                        name = format!("{stem}-{suffix}.json");
                        suffix += 1;
                    }
                    writer
                        .start_file(name, options)
                        .map_err(|_| AccountStoreError::new("批量导出压缩包写入失败", 500))?;
                    writer
                        .write_all(&bytes)
                        .map_err(|_| AccountStoreError::new("批量导出压缩包写入失败", 500))?;
                }
                writer
                    .finish()
                    .map_err(|_| AccountStoreError::new("批量导出压缩包收尾失败", 500))?;
            }
            Ok(BatchExport {
                bytes: cursor.into_inner(),
                file_name: format!("agent2api-accounts-{stamp}.zip"),
                mime: "application/zip",
                count,
                failed,
                exported_ids,
            })
        }
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use serde_json::json;
    use std::io::{Cursor, Read};

    fn file(id: &str, name: &str, extra: Value) -> AccountFile {
        let mut content = json!({
            "format": ACCOUNT_FILE_FORMAT,
            "provider": "codearts",
            "id": id,
            "name": name,
            "accessToken": "token",
        });
        if let (Some(target), Some(extra)) = (content.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                target.insert(key.clone(), value.clone());
            }
        }
        AccountFile {
            id: id.to_string(),
            name: name.to_string(),
            file_name: format!("codearts-{name}-1-001.json"),
            content,
        }
    }

    #[test]
    fn combined_merges_accounts_and_dedupes_providers() {
        let files = vec![
            file("a", "one", json!({"customProviders": [{"id": "custom-x", "label": "X"}]})),
            file(
                "b",
                "two",
                json!({"customProviders": [{"id": "custom-x", "label": "X"}, {"id": "custom-y"}]}),
            ),
        ];
        let out =
            assemble_batch(files, Vec::new(), BatchExportMode::Combined).expect("combined export");
        assert_eq!(out.count, 2);
        assert_eq!(out.mime, "application/json");
        assert_eq!(out.exported_ids, vec!["a".to_string(), "b".to_string()]);
        let value: Value = serde_json::from_slice(&out.bytes).expect("json");
        assert_eq!(value["accounts"].as_array().map(Vec::len), Some(2));
        assert_eq!(value["customProviders"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn separate_zip_has_one_entry_per_account_and_unique_names() {
        let files = vec![
            file("a", "same", json!({})),
            file("b", "same", json!({})),
        ];
        let out =
            assemble_batch(files, Vec::new(), BatchExportMode::Separate).expect("zip export");
        assert_eq!(out.count, 2);
        assert_eq!(out.mime, "application/zip");
        let mut archive = zip::ZipArchive::new(Cursor::new(out.bytes)).expect("zip open");
        assert_eq!(archive.len(), 2);
        let mut names = Vec::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).expect("entry");
            names.push(entry.name().to_string());
            let mut text = String::new();
            entry.read_to_string(&mut text).expect("read entry");
            let parsed: Value = serde_json::from_str(&text).expect("entry json");
            assert_eq!(parsed["format"], ACCOUNT_FILE_FORMAT);
        }
        assert!(names[0].ends_with(".json"));
        assert_ne!(names[0], names[1]);
    }
}
