//! CodeArts 原调用的一次换证工作；取消等待不丢已消费 Pending、已发 HTTP 或同步保存。
//! 原行、原出口、原请求和响应均由一个工作所有者持到实际收尾，未知结果不重新发送。

use std::collections::HashMap;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use agent2api_provider_protocol as proto;
use serde_json::Value;
use tokio::{sync::{oneshot, Notify, OwnedSemaphorePermit, Semaphore}, task::JoinHandle, time::Instant};
use zeroize::Zeroizing;

use super::{call::Call, protocol::{RefreshMaterial, RequestParts, ResponseCandidate, TOKEN_URI, MAX_RESPONSE_BYTES}};
use crate::server::core::{
    account_store::{credential_version::{PendingSlot, PendingCompletionCallback, PendingCompletionState, PendingCommitFact, ReadyRead, SlotOutcome, SlotSettlement}, plugin_accounts},
    egress::managed::FrozenHttpClient,
};

const MAX_WORKERS: usize = 64;
/// CodeArts 换票的进程级最小间隔。
///
/// 华为 STS 对本机 IP 的限流约 20 次/秒；启动时插件会把所有到期账号几乎同时
/// 打过来（实测 50+ 并发），超限后大量 429，失败路径会把槽封成 Blocked ——
/// 表面上是“全部更新失败”，其实令牌还活着。这里把发送串行化到约 8 次/秒，
/// 低于限流阈值；单次 25 秒的请求预算足够排完一整批。
const REFRESH_MIN_INTERVAL: Duration = Duration::from_millis(120);
static REFRESH_PACING: OnceLock<tokio::sync::Mutex<Option<Instant>>> = OnceLock::new();

async fn pace_refresh() {
    let gate = REFRESH_PACING.get_or_init(|| tokio::sync::Mutex::new(None));
    let mut last = gate.lock().await;
    if let Some(previous) = *last {
        let earliest = previous + REFRESH_MIN_INTERVAL;
        if earliest > Instant::now() {
            tokio::time::sleep_until(earliest).await;
        }
    }
    *last = Some(Instant::now());
}

struct Job {
    handle: Option<JoinHandle<()>>,
    waiting: bool,
    settled: bool,
}
struct Operation {
    id: String,
    host: Weak<crate::server::core::plugin_host::Host>,
    call: Weak<Call>,
    job: Mutex<Job>,
    completed: AtomicBool,
    save_commit: std::sync::atomic::AtomicU8,
    save_storage_closed: AtomicBool,
    changed: Notify,
}
struct Ownership {
    operation: Arc<Operation>,
    call: Option<Arc<Call>>,
    ready: Option<ReadyRead>,
    pending: Option<PendingSlot>,
    client: Option<FrozenHttpClient>,
    parts: Option<RequestParts>,
    request: Option<reqwest::Request>,
    candidate: Option<ResponseCandidate>,
    permit: Option<OwnedSemaphorePermit>,
}
impl Drop for Ownership {
    fn drop(&mut self) {
        // 未完成工作销毁保持原持久 Pending，不在析构联网、重读账号或恢复 Ready。
        drop(self.request.take());
        drop(self.candidate.take());
        drop(self.parts.take());
        drop(self.ready.take());
        drop(self.pending.take());
        drop(self.client.take());
        drop(self.call.take());
        drop(self.permit.take());
        self.operation.completed.store(true, Ordering::Release);
        self.operation.changed.notify_waiters();
    }
}
struct Waiter { call: Arc<Call>, returned: bool }
impl Drop for Waiter {
    fn drop(&mut self) { if !self.returned { self.call.close(); } }
}

fn registry() -> &'static Mutex<HashMap<String, Arc<Operation>>> {
    static ITEMS: OnceLock<Mutex<HashMap<String, Arc<Operation>>>> = OnceLock::new();
    ITEMS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn slots() -> Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(4))).clone()
}
fn finished(operation: &Operation) -> bool {
    operation.completed.load(Ordering::Acquire) && operation.job.try_lock().is_ok_and(|job| {
        !job.waiting && (job.settled || job.handle.as_ref().is_some_and(JoinHandle::is_finished))
    })
}

pub(super) async fn exchange(call: Arc<Call>) -> Result<Value, proto::WireError> {
    let mut waiter = Waiter { call: call.clone(), returned: false };
    call.prepare_once()?;
    let permit = slots().try_acquire_owned().map_err(|_| unknown())?;
    let mut bytes = [0u8; 24];
    getrandom::getrandom(&mut bytes).map_err(|_| unknown())?;
    if bytes.iter().all(|byte| *byte == 0) { return Err(unknown()); }
    let id = bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let operation = Arc::new(Operation { id: id.clone(), host: Arc::downgrade(call.host()), call: Arc::downgrade(&call),
        job: Mutex::new(Job { handle: None, waiting: false, settled: false }),
        completed: AtomicBool::new(false), save_commit: std::sync::atomic::AtomicU8::new(0),
        save_storage_closed: AtomicBool::new(false), changed: Notify::new() });
    let mut ownership = Ownership { operation: operation.clone(), call: Some(call.clone()),
        ready: None, pending: None, client: None, parts: None, request: None, candidate: None, permit: Some(permit) };
    let removed = {
        let mut table = registry().lock().map_err(|_| unknown())?;
        let expired = table.iter().filter(|(_, operation)| finished(operation)).map(|(id, _)| id.clone()).collect::<Vec<_>>();
        let removed = expired.into_iter().filter_map(|id| table.remove(&id)).collect::<Vec<_>>();
        if table.len() >= MAX_WORKERS || table.contains_key(&id)
            || table.values().any(|old| Weak::ptr_eq(&old.call, &operation.call)) {
            drop(table); drop(removed); return Err(unknown());
        }
        table.insert(id, operation.clone());
        removed
    };
    drop(removed);
    let (begin, ready) = oneshot::channel();
    let (sent, received) = oneshot::channel();
    {
        let mut job = operation.job.lock().map_err(|_| unknown())?;
        if job.handle.is_some() || job.waiting || job.settled { return Err(unknown()); }
        job.handle = Some(crate::spawn_task(async move {
            let outcome = if ready.await.is_ok() { run(&mut ownership).await } else { Err(unknown()) };
            drop(ownership);
            let _ = sent.send(outcome);
        }));
    }
    operation.changed.notify_waiters();
    begin.send(()).map_err(|_| unknown())?;
    let outcome = tokio::select! {
        biased;
        _ = call.closed() => return Err(unknown()),
        outcome = received => outcome.map_err(|_| unknown())?,
    };
    waiter.returned = true;
    outcome
}

async fn run(owner: &mut Ownership) -> Result<Value, proto::WireError> {
    let call = owner.call.as_ref().cloned().ok_or_else(unknown)?;
    let store = plugin_accounts::shared().ok_or_else(unknown)?;
    call.with_current(|| Ok(()))?;
    let account = call.account().to_string();
    let result = tokio::task::spawn_blocking(move || store.read_codearts_ready(&account)).await
        .map_err(|_| unknown())?.map_err(|_| unknown())?;
    owner.ready = match result { SlotOutcome::Committed(ready) => Some(ready), _ => return Err(unknown()) };
    call.with_current(|| Ok(()))?;
    let material = RefreshMaterial::from_stamp(owner.ready.as_ref().ok_or_else(unknown)?.borrow_stamp())
        .map_err(|_| unknown())?;
    let mut jti = [0u8; 32];
    getrandom::getrandom(&mut jti).map_err(|_| unknown())?;
    owner.parts = Some(material.build(crate::server::logging::now_ms(), jti).map_err(|_| unknown())?);
    let path = call.take_path(owner.ready.as_ref().ok_or_else(unknown)?)?;
    owner.client = Some(tokio::time::timeout_at(call.deadline().min(Instant::now() + Duration::from_secs(5)),
        FrozenHttpClient::from_path(path)).await.map_err(|_| unknown())?.map_err(|_| unknown())?);
    let parts = owner.parts.as_ref().ok_or_else(unknown)?;
    let client = owner.client.as_ref().ok_or_else(unknown)?;
    let mut request = client.client().map_err(|_| unknown())?.post(parts.uri());
    for (name, value) in parts.headers() { request = request.header(name, value); }
    let request = request.body(parts.form().as_bytes().to_vec()).build().map_err(|_| unknown())?;
    if request.method() != reqwest::Method::POST || request.url().as_str() != TOKEN_URI
        || request.body().and_then(reqwest::Body::as_bytes) != Some(parts.form().as_bytes()) {
        return Err(unknown());
    }
    owner.request = Some(request);
    // 排队等待节拍放在 “Ready→Pending” 之前：等待期间槽仍是 Ready，
    // 进程若在这时退出也不会留下悬挂的 Pending；等待也不计入 HTTP 预算。
    pace_refresh().await;
    call.with_current(|| Ok(()))?;
    let ready = owner.ready.take().ok_or_else(unknown)?;
    let result = tokio::task::spawn_blocking(move || ready.consume_pending()).await
        .map_err(|_| unknown())?.map_err(|_| unknown())?;
    owner.pending = match result {
        SlotOutcome::Committed(pending) => Some(pending),
        _ => return Err(stage("codearts_refresh_not_ready")),
    };
    if call.submit_pending_once(owner.pending.as_ref().ok_or_else(unknown)?).is_err() {
        // 收据提交失败发生在任何 HTTP 之前：请求确定没有发出，RT 未被消费。
        // 插件侧用 try_lock 取生命周期锁，争用时是**瞬时**失败；先短暂重试，
        // 仍失败才把槽回退为 Ready —— 不能因为一次锁竞争就把账号封成
        // “上次续期未确认”，那需要人工停服务重置。
        let mut submitted = false;
        for attempt in 0..4 {
            tokio::time::sleep(Duration::from_millis(20 << attempt)).await;
            let Some(pending) = owner.pending.as_ref() else { break };
            if call.submit_pending_once(pending).is_ok() {
                submitted = true;
                break;
            }
        }
        if !submitted {
            return cancel_pre_send(owner).await;
        }
    }
    let request = owner.request.take().ok_or_else(unknown)?;
    let http = {
        let client = owner.client.as_ref().ok_or_else(unknown)?;
        match client.client() {
            Ok(http) => http,
            // 同上：客户端尚未构造出请求，也未发出任何字节。
            Err(_) => return cancel_pre_send(owner).await,
        }
    };
    // 25 秒预算只覆盖实际请求（节拍等待已在 Ready→Pending 之前完成）。
    let deadline = call.deadline().min(Instant::now() + Duration::from_secs(25));
    let read = tokio::time::timeout_at(deadline, async move {
        // 到这里才开始真正发送；之后的任何失败都按“可能已发出”处理。
        let mut response = http.execute(request).await.map_err(|_| unknown())?;
        let status = response.status().as_u16();
        if response.url().as_str() != TOKEN_URI || response.headers().contains_key("location")
            || response.content_length().is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) { return Err(unknown()); }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| unknown())? {
            if bytes.len().checked_add(chunk.len()).is_none_or(|length| length > MAX_RESPONSE_BYTES) { return Err(unknown()); }
            bytes.extend_from_slice(&chunk);
        }
        ResponseCandidate::parse(status, &bytes, crate::server::logging::now_ms()).map_err(|_| unknown())
    }).await;
    owner.candidate = match read {
        Ok(Ok(candidate)) => Some(candidate),
        _ => return block(owner, "codearts_refresh_send_failed").await,
    };
    if call.with_current(|| Ok(())).is_err() {
        return block(owner, "codearts_refresh_post_response").await;
    }
    let candidate = owner.candidate.take().ok_or_else(unknown)?;
    let pending = owner.pending.take().ok_or_else(unknown)?;
    let journal_account = pending.account().to_string();
    let journal_operation = pending.operation_id();
    let original = call.clone();
    let operation = owner.operation.clone();
    let result = tokio::task::spawn_blocking(move || {
        // 先把上游响应落盘为恢复日志：此后任何结算失败都能在恢复流程里补完，
        // 新令牌不再只存在于内存。落盘失败时退回“失败即 Blocked”的旧纪律。
        let journaled = pending.journal_refresh_result(candidate.credentials());
        let access = match candidate.credentials()["access_key_id"].as_str() {
            Some(access) => Zeroizing::new(access.to_string()),
            None => {
                if !journaled {
                    let _ = pending.block();
                }
                return Err(stage("codearts_refresh_complete_failed"));
            }
        };
        let completion = match pending.prepare_completion(candidate.credentials()) {
            Ok(completion) => completion,
            // prepare_completion 在密钥不可用时已自行落 Blocked。
            Err(_) => return Err(stage("codearts_refresh_complete_failed")),
        };
        let checked = match original.complete_pending_once(&completion) {
            Ok(checked) => checked,
            Err(error) => {
                // 有日志时保留 Pending：恢复流程会用同一份响应补完；
                // 没有日志才封锁，避免留下无法恢复的悬挂 Pending。
                if !journaled {
                    let _ = completion.block();
                }
                return Err(error);
            }
        };
        let (commit, storage_closed) = checked.facts();
        operation.save_commit.store(match commit {
            PendingCommitFact::NotAttempted => 0,
            PendingCommitFact::Confirmed => 1,
            PendingCommitFact::Unconfirmed => 2,
        }, Ordering::Release);
        operation.save_storage_closed.store(storage_closed, Ordering::Release);
        let state = checked.into_state();
        match state {
            PendingCompletionState::Entered {
                result: PendingCompletionCallback::Returned(Ok(SlotSettlement::Rotated(_))),
                commit: PendingCommitFact::Confirmed, storage_closed: true,
            } => {
                if let Some(store) = plugin_accounts::shared() {
                    store.clear_codearts_refresh_result(&journal_account, &journal_operation);
                }
                Ok(Value::String(access.to_string()))
            }
            _ => {
                original.close();
                if !journaled {
                    let _ = completion.block();
                }
                Err(stage("codearts_refresh_complete_failed"))
            }
        }
    }).await.map_err(|_| stage("codearts_refresh_complete_failed"))?;
    result
}

async fn block(owner: &mut Ownership, code: &str) -> Result<Value, proto::WireError> {
    if let Some(pending) = owner.pending.take() {
        // 同步存储工作仍由原独立worker等待，取消方不能把它丢弃后重新占槽。
        let _ = tokio::task::spawn_blocking(move || pending.block()).await;
    }
    Err(stage(code))
}

/// 请求确定未发出时的收尾：Pending 回退为 Ready，并关闭本次插件调用。
async fn cancel_pre_send(owner: &mut Ownership) -> Result<Value, proto::WireError> {
    let account = owner.call.as_ref().map(|call| call.account().to_string());
    let label = account.as_deref().unwrap_or("未知账号");
    if let Some(pending) = owner.pending.take() {
        let outcome = tokio::task::spawn_blocking(move || pending.cancel_pre_send()).await;
        let committed = matches!(
            outcome,
            Ok(Ok(crate::server::db::CodeArtsTransaction::Committed { .. }))
        );
        if committed {
            // 失败已按“未发送”处理并回退成功：这条是正常自愈，不是故障。
            crate::server::logging::log(
                "[Accounts]",
                &format!("CodeArts 换票在发送前失败，账号 {label} 的续期槽已回退为 Ready，下一轮重试"),
            );
        } else {
            // 回退失败只剩两种结果：槽仍是 Pending（下次报“上次续期未确认”）
            // 或已被其它操作接手。留一条日志，避免只看到一条 pre_send 失败。
            crate::server::logging::log(
                "[Accounts]",
                &format!(
                    "CodeArts 换票在发送前失败，但账号 {label} 的续期槽未能回退为 Ready；下次维护会提示“上次续期未确认”"
                ),
            );
        }
    }
    if let Some(call) = owner.call.take() { call.close(); }
    Err(stage("codearts_refresh_pre_send"))
}

fn for_host(host: &crate::server::core::plugin_host::Host) -> Vec<Arc<Operation>> {
    registry().lock().map(|table| table.values().filter(|operation| {
        std::ptr::eq(operation.host.as_ptr(), host)
    }).cloned().collect()).unwrap_or_default()
}

pub(in crate::server::core::plugin_host::wasm) fn close_for_host(host: &crate::server::core::plugin_host::Host) {
    for operation in for_host(host) {
        if let Some(call) = operation.call.upgrade() { call.close(); }
    }
}

pub(in crate::server::core::plugin_host::wasm) fn release_ready(host: &crate::server::core::plugin_host::Host) -> bool {
    registry().try_lock().is_ok_and(|table| table.values().filter(|operation| {
        std::ptr::eq(operation.host.as_ptr(), host)
    }).all(|operation| finished(operation)))
}

pub(in crate::server::core::plugin_host::wasm) async fn wait_for_host(host: &crate::server::core::plugin_host::Host) {
    for operation in for_host(host) { wait(operation).await; }
}
struct Waiting { operation: Arc<Operation>, job: Option<JoinHandle<()>> }
impl Drop for Waiting {
    fn drop(&mut self) {
        if let Some(job) = self.job.take() {
            let mut slot = self.operation.job.lock().unwrap_or_else(|error| error.into_inner());
            if slot.handle.is_none() { slot.handle = Some(job); }
            slot.waiting = false;
            drop(slot);
            self.operation.changed.notify_waiters();
        }
    }
}
async fn wait(operation: Arc<Operation>) {
    loop {
        let changed = operation.changed.notified();
        tokio::pin!(changed); changed.as_mut().enable();
        let job = {
            let mut slot = operation.job.lock().unwrap_or_else(|error| error.into_inner());
            if slot.settled { return; }
            if !slot.waiting && slot.handle.is_some() { slot.waiting = true; slot.handle.take() }
            else if !slot.waiting && operation.completed.load(Ordering::Acquire) { return; }
            else { None }
        };
        let mut waiting = Waiting { operation: operation.clone(), job };
        if let Some(job) = waiting.job.as_mut() {
            let _ = job.await; waiting.job.take();
            let mut slot = operation.job.lock().unwrap_or_else(|error| error.into_inner());
            slot.waiting = false; slot.settled = true;
            drop(slot); operation.changed.notify_waiters(); return;
        }
        changed.await;
    }
}
fn unknown() -> proto::WireError {
    stage("codearts_refresh_unconfirmed")
}

/// 统一文案 + 阶段码：`code` 会进日志事件与错误响应，排障时不必再靠耗时猜阶段。
fn stage(code: &str) -> proto::WireError {
    proto::WireError::with_code(
        "CodeArts本次换证、原槽保存或收尾未确认，未重发、重新占槽或沿用旧值冒充成功",
        code,
    )
}
