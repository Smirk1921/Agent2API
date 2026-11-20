use axum::body::Bytes;
use axum::http::header::CACHE_CONTROL;
use axum::http::HeaderValue;
use axum::response::Response;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Value};

use super::accounts::{parse_json_body, store_error};
use crate::server::core::account_transfer::{
    export_account_files, export_batch, BatchExportMode, ExportSelection, ACCOUNT_FILE_FORMAT,
};
use crate::server::errors::management_error;
use crate::server::http::ok_json;
use crate::server::ServerState;

pub async fn account_files(state: &ServerState, body: &Bytes) -> Response {
    let payload = match parse_json_body(body, "请求内容不是有效 JSON") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let text = |key: &str| {
        payload
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
    };
    let selection = match (text("id"), text("provider")) {
        (id, "") if !id.is_empty() => ExportSelection::Account(id.to_string()),
        ("", provider) if !provider.is_empty() => ExportSelection::Provider(provider.to_string()),
        _ => return management_error(400, "请指定一个账号 id 或一个提供商分组"),
    };
    let result = match export_account_files(state.store(), selection) {
        Ok(result) => result,
        Err(error) => return store_error(error),
    };
    match serde_json::to_value(result) {
        Ok(value) => {
            let mut response = ok_json(value);
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(_) => management_error(500, "账号导出内容序列化失败"),
    }
}

/// `POST /api/accounts/export-batch` —— 批量导出，可选导出后删除。
///
/// 请求：
/// ```json
/// { "ids": ["id1", "id2"], "mode": "combined" | "separate", "deleteAfter": true }
/// ```
/// - `combined`：一个导入文件（`{version, exportedAt, accounts, customProviders}`）；
/// - `separate`：每个账号一个 JSON，打包成 zip。
///
/// 成品以 base64 放进 JSON 信封：网页端直接转 Blob 下载、桌面端写入系统对话框选的
/// 路径，两边共用同一份字节，不必为「下载」再开一条二进制端点。
/// `deleteAfter` 只删**导出成功**的账号（`exported_ids`）；删除失败逐条回显，
/// 不让一个账号删不掉把整批导出判成失败。
pub async fn batch_export(state: &ServerState, body: &Bytes) -> Response {
    let payload = match parse_json_body(body, "请求内容不是有效 JSON") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut ids: Vec<String> = Vec::new();
    if let Some(items) = payload.get("ids").and_then(Value::as_array) {
        for item in items {
            if let Some(text) = item.as_str() {
                let text = text.trim();
                if !text.is_empty() && !ids.iter().any(|existing| existing == text) {
                    ids.push(text.to_string());
                }
            }
        }
    }
    if ids.is_empty() {
        return management_error(400, "缺少要导出的账号 id");
    }
    let mode = match payload
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("combined")
        .trim()
    {
        "" | "combined" => BatchExportMode::Combined,
        "separate" => BatchExportMode::Separate,
        _ => return management_error(400, "导出方式只能是 combined 或 separate"),
    };
    let delete_after = payload
        .get("deleteAfter")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let result = match export_batch(state.store(), &ids, mode) {
        Ok(result) => result,
        Err(error) => return store_error(error),
    };
    let mut deleted: Vec<String> = Vec::new();
    let mut delete_failed: Vec<Value> = Vec::new();
    if delete_after {
        for id in &result.exported_ids {
            match state.store().remove_account(id) {
                Ok(()) => deleted.push(id.clone()),
                Err(error) => {
                    delete_failed.push(json!({ "id": id, "error": error.message }));
                }
            }
        }
    }
    let mut response = ok_json(json!({
        "count": result.count,
        "fileName": result.file_name,
        "mime": result.mime,
        "contentBase64": BASE64.encode(&result.bytes),
        "failed": result.failed,
        // 成功导出的账号 id：客户端据此在文件落盘之后再删除（先落盘、后删除，
        // 避免响应中断时「账号没了、文件也没拿到」）
        "exportedIds": result.exported_ids,
        "deleted": deleted,
        "deleteFailed": delete_failed,
        "list": state.store().list_visible_accounts(),
    }));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn import_account_file(
    state: &ServerState,
    provider: &str,
    payload: &Value,
    name: Option<&str>,
) -> Option<Response> {
    let selected_proxy = payload.get("proxy");
    let file = payload
        .get("authFileContent")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<Value>(text).ok());
    let payload = file.as_ref().unwrap_or(payload);
    if payload.get("format").and_then(Value::as_str) != Some(ACCOUNT_FILE_FORMAT) {
        return None;
    }
    if payload.get("provider").and_then(Value::as_str) != Some(provider) {
        return Some(management_error(
            400,
            "账号文件的提供商与当前选择不一致，请选择对应的提供商后再导入",
        ));
    }
    let id = payload
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if id.is_empty() {
        return Some(management_error(400, "账号导出文件缺少 id"));
    }
    let mut account = payload.clone();
    if let Some(proxy) = selected_proxy {
        account["proxy"] = proxy.clone();
    }
    if let Some(name) = name.filter(|name| !name.trim().is_empty()) {
        account["name"] = Value::String(name.trim().to_string());
        account["nameCustom"] = Value::Bool(true);
    }
    let mut body = json!({ "accounts": [account] });
    if let Some(definitions) = payload.get("customProviders") {
        body["customProviders"] = definitions.clone();
    }
    let result = match crate::server::core::account_transfer::import_accounts(state.store(), &body)
    {
        Ok(result) => result,
        Err(error) => return Some(store_error(error)),
    };
    if result.get("failed").and_then(Value::as_u64).unwrap_or(0) > 0
        || result.get("skipped").and_then(Value::as_u64).unwrap_or(0) > 0
    {
        let message = result
            .get("errors")
            .and_then(Value::as_array)
            .and_then(|errors| errors.first())
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("账号文件导入失败");
        return Some(management_error(400, message));
    }
    let imported_id = result
        .get("importedIds")
        .and_then(Value::as_array)
        .and_then(|ids| ids.first())
        .and_then(Value::as_str)
        .unwrap_or(id);
    let mut response = json!({
        "created": result.get("added").and_then(Value::as_u64).unwrap_or(0) > 0,
    });
    super::account_import_setup::complete(state, &[imported_id.to_string()], &mut response).await;
    response["account"] = state.store().plugin_account(imported_id)
        .and_then(|record| record.get("public").cloned())
        .unwrap_or(Value::Null);
    response["list"] = state.store().list_visible_accounts();
    Some(ok_json(response))
}
