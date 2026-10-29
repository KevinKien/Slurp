//! Backend capture audits. Probes use the shared sender and never enter proxy History.
use axum::{Extension, Json};
use proxy_core::{Intercept, TrafficEntry, TrafficEvent, TrafficStorage};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, Duration},
};

type PendingApis = Arc<Mutex<HashSet<(String, String)>>>;
type AuditJob = (String, Option<(String, String)>);
struct PendingApi(PendingApis, Option<(String, String)>);
impl Drop for PendingApi {
    fn drop(&mut self) {
        if let Some(key) = self.1.take() { self.0.lock().unwrap().remove(&key); }
    }
}
fn digest_id(prefix: &str, bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    format!("{prefix}{}", digest.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>())
}
fn api_id(request: &Value) -> String {
    let (mut clean, _) = anonymous(request);
    let ordered: BTreeMap<_, _> = clean["headers"].as_object().unwrap().iter().map(|(k,v)| (k.to_ascii_lowercase(), v.clone())).collect();
    clean["headers"] = json!(ordered);
    digest_id("auto-api-", clean.to_string().as_bytes())
}
pub(super) fn forbidden_id(request: &Value) -> String {
    // Keep credentials in the digest: different users must be audited independently.
    digest_id("auto-403-", request.to_string().as_bytes())
}
fn audit_id(entry: &TrafficEntry, request: &Value) -> String {
    if entry.status_code == 403 { forbidden_id(request) } else { api_id(request) }
}
fn complete_api(run: &Value) -> bool {
    ["noauthen", "cors"].iter().all(|id| run["checks"].as_array().is_some_and(|checks| checks.iter().any(|c| c["checkId"] == *id && matches!(c["status"].as_str(), Some("passed" | "findings")))))
}

#[derive(Clone)]
pub struct AuditState(Arc<Inner>);
struct Inner {
    enabled: AtomicBool,
    queued: AtomicUsize,
    active: AtomicUsize,
    completed: AtomicUsize,
    skipped: AtomicUsize,
    errors: AtomicUsize,
}
pub struct AuditRuntime(Vec<JoinHandle<()>>);
impl Drop for AuditRuntime {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}
impl AuditState {
    pub(super) fn enabled(&self) -> bool {
        self.0.enabled.load(Ordering::Relaxed)
    }
    fn status(&self) -> Value {
        json!({"enabled":self.enabled(),"queued":self.0.queued.load(Ordering::Relaxed),
            "active":self.0.active.load(Ordering::Relaxed),"completed":self.0.completed.load(Ordering::Relaxed),
            "skipped":self.0.skipped.load(Ordering::Relaxed),"errors":self.0.errors.load(Ordering::Relaxed)})
    }
}
pub async fn status(Extension(state): Extension<AuditState>) -> Json<Value> {
    Json(state.status())
}
#[derive(Deserialize)]
pub struct Settings {
    enabled: bool,
}
pub async fn settings(
    Extension(state): Extension<AuditState>,
    Json(settings): Json<Settings>,
) -> Json<Value> {
    state.0.enabled.store(settings.enabled, Ordering::Relaxed);
    Json(state.status())
}

pub fn start(
    storage: Arc<TrafficStorage>,
    intercept: Arc<Intercept>,
) -> (AuditState, AuditRuntime) {
    let state = AuditState(Arc::new(Inner {
        enabled: AtomicBool::new(true),
        queued: AtomicUsize::new(0),
        active: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        skipped: AtomicUsize::new(0),
        errors: AtomicUsize::new(0),
    }));
    // Separate queues keep active API timeouts from delaying passive JavaScript analysis.
    let (api_tx, api_rx) = mpsc::channel::<AuditJob>(128);
    let (js_tx, js_rx) = mpsc::channel::<AuditJob>(128);
    let mut events = storage.subscribe();
    let state_events = state.clone();
    let pending: PendingApis = Arc::new(Mutex::new(HashSet::new()));
    let pending_events = pending.clone();
    let capture_storage = storage.clone();
    let capture = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(TrafficEvent::NewEntry { entry } | TrafficEvent::EntryUpdated { entry }) => {
                    if !state_events.enabled() || !eligible(&entry) {
                        continue;
                    }
                    let queue = if super::js_audit::is_javascript(&entry) {
                        &js_tx
                    } else if is_api(&entry) {
                        &api_tx
                    } else {
                        continue;
                    };
                    let reservation = if super::js_audit::is_javascript(&entry) { None } else {
                        let Some(request) = request(&entry) else { continue; };
                        let id = audit_id(&entry, &request);
                        if entry.status_code == 403 && capture_storage.has_completed_automatic_check(&entry.workspace_id, &id, "403-bypass").unwrap_or(false) { continue; }
                        if capture_storage.get_scan_run(&entry.workspace_id, &id).ok().flatten().as_ref().is_some_and(|run| entry.status_code != 403 && complete_api(run)) { continue; }
                        let key = (entry.workspace_id.clone(), id);
                        if !pending_events.lock().unwrap().insert(key.clone()) { continue; }
                        Some(key)
                    };
                    state_events.0.queued.fetch_add(1, Ordering::Relaxed);
                    if queue.try_send((entry.id, reservation.clone())).is_err() {
                        if let Some(key) = reservation { pending_events.lock().unwrap().remove(&key); }
                        state_events.0.queued.fetch_sub(1, Ordering::Relaxed);
                        state_events.0.skipped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                    state_events
                        .0
                        .skipped
                        .fetch_add(count as usize, Ordering::Relaxed);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                _ => {}
            }
        }
    });
    let api = tokio::spawn(worker(
        storage.clone(),
        intercept.clone(),
        state.clone(),
        api_rx,
        false,
        pending.clone(),
    ));
    let storage_for_crlf = storage.clone();
    let intercept_for_crlf = intercept.clone();
    let js = tokio::spawn(worker(storage, intercept, state.clone(), js_rx, true, pending));
    let mut tasks = vec![capture, api, js];
    tasks.extend(start_header_audit(storage_for_crlf.clone(), intercept_for_crlf.clone(), state.clone(),false));
    tasks.extend(start_header_audit(storage_for_crlf.clone(), intercept_for_crlf.clone(), state.clone(),true));
    tasks.extend(start_cve_audit(storage_for_crlf.clone(), intercept_for_crlf.clone(), state.clone(), "php2shell"));
    tasks.extend(start_cve_audit(storage_for_crlf.clone(), intercept_for_crlf.clone(), state.clone(), "http2shell"));
    tasks.extend(start_cve_audit(storage_for_crlf, intercept_for_crlf, state.clone(), "react2shell"));
    (state, AuditRuntime(tasks))
}

fn cve_eligible(check: &str, entry: &TrafficEntry) -> bool {
    match check {
        "php2shell" => super::php2shell::eligible(entry),
        "http2shell" => super::http2shell::eligible(entry),
        "react2shell" => super::react2shell::eligible(entry),
        _ => false,
    }
}

fn cve_key(check: &str, request: &Value) -> String {
    match check {
        "php2shell" => super::php2shell::key(request),
        "http2shell" => super::http2shell::key(request),
        _ => super::react2shell::key(request),
    }
}

/// CVE exposure audits keep their own queue and dedup key so one check cannot delay another.
/// `php2shell` is passive, `http2shell` sends one bounded differential probe and `react2shell`
/// sends one ordinary RSC navigation; none sends an exploit payload.
fn start_cve_audit(
    storage: Arc<TrafficStorage>,
    intercept: Arc<Intercept>,
    state: AuditState,
    check: &'static str,
) -> Vec<JoinHandle<()>> {
    let (tx, mut rx) = mpsc::channel::<(String, String, String)>(64);
    let pending: PendingApis = Arc::new(Mutex::new(HashSet::new()));
    let mut events = storage.subscribe();
    let source = storage.clone();
    let status = state.clone();
    let reservations = pending.clone();
    let capture = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(TrafficEvent::NewEntry { entry } | TrafficEvent::EntryUpdated { entry }) => {
                    let wanted = cve_eligible(check, &entry);
                    if !status.enabled() || !eligible(&entry) || !wanted {
                        continue;
                    }
                    let Some(request) = request(&entry) else { continue; };
                    let key = cve_key(check, &request);
                    // One attempt per deployment: a saved run in any state is final until deleted.
                    if source
                        .get_scan_run(&entry.workspace_id, &key)
                        .ok()
                        .flatten()
                        .is_some()
                    {
                        continue;
                    }
                    let reservation = (entry.workspace_id.clone(), key.clone());
                    if !reservations.lock().unwrap().insert(reservation.clone()) {
                        continue;
                    }
                    status.0.queued.fetch_add(1, Ordering::Relaxed);
                    if tx.try_send((entry.id, entry.workspace_id, key)).is_err() {
                        reservations.lock().unwrap().remove(&reservation);
                        status.0.queued.fetch_sub(1, Ordering::Relaxed);
                        status.0.skipped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                    status.0.skipped.fetch_add(count as usize, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    });
    let worker = tokio::spawn(async move {
        while let Some((id, workspace, key)) = rx.recv().await {
            state.0.queued.fetch_sub(1, Ordering::Relaxed);
            let _reservation = PendingApi(pending.clone(), Some((workspace, key.clone())));
            let Some(entry) = storage.get(&id).ok().flatten() else {
                continue;
            };
            if !state.enabled() || !intercept.scope().matches(&entry.host) {
                continue;
            }
            if storage
                .get_scan_run(&entry.workspace_id, &key)
                .ok()
                .flatten()
                .is_some()
            {
                continue;
            }
            let run_id = key.clone();
            state.0.active.fetch_add(1, Ordering::Relaxed);
            let result = match check {
                "php2shell" => super::php2shell::audit(&entry, &run_id, &state, &intercept).await,
                "http2shell" => super::http2shell::audit(&entry, &run_id, &state, &intercept).await,
                _ => super::react2shell::audit(&entry, &run_id, &state, &intercept).await,
            };
            if let Some(run) = result {
                if storage.get(&id).ok().flatten().is_some() {
                    if super::scan::validate_run(&run_id, &run).is_ok()
                        && storage
                            .put_scan_run(&entry.workspace_id, &run_id, &run)
                            .is_ok()
                    {
                        state.0.completed.fetch_add(1, Ordering::Relaxed);
                    } else {
                        state.0.errors.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!("Could not save automatic {check} audit {run_id}");
                    }
                }
            } else {
                state.0.skipped.fetch_add(1, Ordering::Relaxed);
            }
            state.0.active.fetch_sub(1, Ordering::Relaxed);
        }
    });
    vec![capture, worker]
}

fn start_header_audit(
    storage: Arc<TrafficStorage>,
    intercept: Arc<Intercept>,
    state: AuditState,
    host: bool,
) -> Vec<JoinHandle<()>> {
    let check_id=if host {"host-header"}else{"header-injection"};
    let (tx, mut rx) = mpsc::channel::<(String, String, String)>(128);
    let pending: PendingApis = Arc::new(Mutex::new(HashSet::new()));
    let mut events = storage.subscribe();
    let source = storage.clone();
    let status = state.clone();
    let reservations = pending.clone();
    let capture = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(TrafficEvent::NewEntry { entry } | TrafficEvent::EntryUpdated { entry }) => {
                    if !status.enabled()
                        || !eligible(&entry)
                        || !(if host {super::host_audit::eligible(&entry)}else{super::crlf_audit::eligible(&entry)})
                    {
                        continue;
                    }
                    let Some(request) = request(&entry) else {
                        continue;
                    };
                    let key = if host {super::host_audit::key(&request)}else{super::crlf_audit::key(&request)};
                    if source
                        .has_completed_automatic_check(
                            &entry.workspace_id,
                            &key,
                            check_id,
                        )
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let reservation = (entry.workspace_id.clone(), key.clone());
                    if !reservations.lock().unwrap().insert(reservation.clone()) {
                        continue;
                    }
                    status.0.queued.fetch_add(1, Ordering::Relaxed);
                    if tx.try_send((entry.id, entry.workspace_id, key)).is_err() {
                        reservations.lock().unwrap().remove(&reservation);
                        status.0.queued.fetch_sub(1, Ordering::Relaxed);
                        status.0.skipped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    status.0.skipped.fetch_add(n as usize, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    });
    let worker = tokio::spawn(async move {
        while let Some((id, workspace, key)) = rx.recv().await {
            state.0.queued.fetch_sub(1, Ordering::Relaxed);
            let _reservation = PendingApi(pending.clone(), Some((workspace, key.clone())));
            let Some(entry) = storage.get(&id).ok().flatten() else {
                continue;
            };
            if !state.enabled()
                || !intercept.scope().matches(&entry.host)
                || storage
                    .has_completed_automatic_check(&entry.workspace_id, &key, check_id)
                    .unwrap_or(false)
            {
                continue;
            }
            let run_id = if storage
                .get_scan_run(&entry.workspace_id, &key)
                .ok()
                .flatten()
                .is_some()
            {
                digest_id(if host {"auto-host-retry-"}else{"auto-crlf-retry-"}, format!("{key}:{id}").as_bytes())
            } else {
                key.clone()
            };
            state.0.active.fetch_add(1, Ordering::Relaxed);
            let result = if host { super::host_audit::audit(&entry, &run_id, &state, &intercept).await }else{super::crlf_audit::audit(&entry, &run_id, &state, &intercept).await};
            if let Some(run) = result {
                if storage.get(&id).ok().flatten().is_some() {
                    if super::scan::validate_run(&run_id, &run).is_ok()
                        && storage
                            .put_scan_run(&entry.workspace_id, &run_id, &run)
                            .is_ok()
                    {
                        state.0.completed.fetch_add(1, Ordering::Relaxed);
                    } else {
                        state.0.errors.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!("Could not save automatic header audit {run_id}");
                    }
                }
            } else {
                state.0.skipped.fetch_add(1, Ordering::Relaxed);
            }
            state.0.active.fetch_sub(1, Ordering::Relaxed);
        }
    });
    vec![capture, worker]
}

fn eligible(entry: &TrafficEntry) -> bool {
    entry.source == "proxy"
        && (200..600).contains(&entry.status_code)
        && entry.error.is_none()
        && ["http", "https"].contains(&entry.scheme.as_str())
        && !headers(&entry.request_headers).contains_key("upgrade")
}
fn is_api(entry: &TrafficEntry) -> bool {
    let mime = entry
        .response_content_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let request_mime = entry
        .request_content_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = entry
        .path
        .split('?')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if [
        ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
    {
        return false;
    }
    mime.contains("json")
        || request_mime.contains("json")
        || request_mime.contains("graphql")
        || path == "/api"
        || path.starts_with("/api/")
        || path.contains("/graphql")
        || headers(&entry.request_headers)
            .keys()
            .any(|name| credential_header(name))
}
async fn worker(
    storage: Arc<TrafficStorage>,
    intercept: Arc<Intercept>,
    state: AuditState,
    mut queue: mpsc::Receiver<AuditJob>,
    javascript: bool,
    pending: PendingApis,
) {
    while let Some((id, reservation)) = queue.recv().await {
        let _reservation = PendingApi(pending.clone(), reservation);
        state.0.queued.fetch_sub(1, Ordering::Relaxed);
        let Some(entry) = storage.get(&id).ok().flatten() else {
            continue;
        };
        let run_id = if javascript { format!("auto-{}", entry.id) } else {
            let Some(request) = request(&entry) else { continue; };
            audit_id(&entry, &request)
        };
        if !state.enabled() || !intercept.scope().matches(&entry.host) { continue; }
        let forbidden = !javascript && entry.status_code == 403;
        if forbidden {
            match storage.has_completed_automatic_check(&entry.workspace_id, &run_id, "403-bypass") {
                Ok(true) => continue,
                Ok(false) => {},
                Err(_) => { state.0.errors.fetch_add(1, Ordering::Relaxed); continue; }
            }
        }
        match storage.get_scan_run(&entry.workspace_id, &run_id) {
            Ok(Some(run)) if javascript || (!forbidden && complete_api(&run)) => continue,
            Ok(Some(_)) => {
                // Failed/incomplete probes may be retried by a later capture without overwriting evidence.
            }
            Ok(None) => {}
            Err(_) => { state.0.errors.fetch_add(1, Ordering::Relaxed); continue; }
        }
        if !javascript && !forbidden {
            let original = request(&entry).unwrap();
            match storage.legacy_automatic_api_requests(&entry.workspace_id, original["method"].as_str().unwrap(), original["body"].as_str().unwrap()) {
                Ok(requests) if requests.iter().any(|(request, complete)| *complete && api_id(request) == run_id) => continue,
                Ok(_) => {}
                Err(_) => { state.0.errors.fetch_add(1, Ordering::Relaxed); continue; }
            }
        }
        // Preserve immutable failed reports; subsequent attempts get a capture-specific suffix.
        let run_id = if !javascript && storage.get_scan_run(&entry.workspace_id, &run_id).ok().flatten().is_some() { digest_id("auto-retry-", format!("{run_id}:{}", entry.id).as_bytes()) } else { run_id };
        state.0.active.fetch_add(1, Ordering::Relaxed);
        let run = if javascript {
            super::js_audit::scan(&entry, &run_id)
        } else if forbidden {
            let mut bypass = super::forbidden_audit::audit(&entry, &run_id, &state, &intercept).await;
            // Keep the existing NoAuthen/CORS checks without repeating completed audits.
            let original = request(&entry).unwrap();
            let prior = storage.legacy_automatic_api_requests(&entry.workspace_id, original["method"].as_str().unwrap(), original["body"].as_str().unwrap());
            match prior {
                Ok(requests) if !requests.iter().any(|(request, complete)| *complete && api_id(request) == api_id(&original)) => {
                    if let (Some(bypass), Some(general)) = (&mut bypass, audit_api(&entry, &run_id, &state, &intercept).await) {
                        for field in ["findings", "checks"] {
                            bypass[field].as_array_mut().unwrap().extend(general[field].as_array().unwrap().iter().cloned());
                        }
                        bypass["evidence"].as_array_mut().unwrap().extend(general["evidence"].as_array().unwrap().iter().skip(1).cloned());
                        bypass["sent"] = json!(bypass["sent"].as_u64().unwrap() + general["sent"].as_u64().unwrap());
                        bypass["bytes"] = json!(bypass["bytes"].as_u64().unwrap() + general["bytes"].as_u64().unwrap());
                        bypass["plan"]["checks"] = json!(bypass["checks"].as_array().unwrap().iter().map(|c|c["checkId"].clone()).collect::<Vec<_>>());
                        bypass["plan"]["maxRequests"] = json!(24);
                        bypass["finishedAt"] = json!(chrono::Utc::now().to_rfc3339());
                    }
                }
                Ok(_) => {},
                Err(_) => { state.0.errors.fetch_add(1, Ordering::Relaxed); }
            }
            bypass
        } else {
            audit_api(&entry, &run_id, &state, &intercept).await
        };
        if let Some(run) = run {
            // Deleted captures/workspaces must not be recreated by a late audit.
            if storage.get(&id).ok().flatten().is_some() {
                if super::scan::validate_run(&run_id, &run).is_ok()
                    && (if javascript {
                        storage.put_unique_js_scan_run(&entry.workspace_id, &run_id, &run).map(|_| ())
                    } else {
                        storage.put_scan_run(&entry.workspace_id, &run_id, &run)
                    }).is_ok()
                {
                    state.0.completed.fetch_add(1, Ordering::Relaxed);
                } else {
                    state.0.errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("Could not save automatic audit {run_id}");
                }
            }
        } else {
            state.0.skipped.fetch_add(1, Ordering::Relaxed);
        }
        state.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) fn headers(raw: &str) -> Map<String, Value> {
    let data: Value = serde_json::from_str(raw).unwrap_or(json!({}));
    data.as_object()
        .into_iter()
        .flatten()
        .map(|(name, value)| {
            let text = if let Some(values) = value.as_array() {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                value.as_str().unwrap_or("").to_string()
            };
            (name.to_ascii_lowercase(), json!(text))
        })
        .collect()
}
pub(crate) fn request(entry: &TrafficEntry) -> Option<Value> {
    if entry.request_size > entry.request_body.len() as u64 {
        return None;
    }
    let body = std::str::from_utf8(&entry.request_body).ok()?;
    let data = json!({"method":entry.method,"url":entry.url,"headers":headers(&entry.request_headers),"body":body,"timeout":10000});
    super::http_sender::validate(&data).ok()?;
    Some(data)
}
pub(crate) fn preview(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}
pub(crate) fn observed(entry: &TrafficEntry, request: &Value) -> Value {
    let body = String::from_utf8_lossy(&entry.response_body);
    let truncated =
        entry.response_size > entry.response_body.len() as u64 || body.chars().count() > 32000;
    let mut response_headers = headers(&entry.response_headers);
    response_headers.retain(|_, value| value.as_str().is_some_and(|s| s.len() <= 8192));
    let response_headers: Map<_, _> = response_headers.into_iter().take(200).collect();
    json!({"id":"observed","label":"Captured response","timestamp":entry.timestamp.to_rfc3339(),"request":request,
        "response":{"status":entry.status_code,"responseHeaders":response_headers,"responseBody":preview(&body,32000)},
        "setCookies":[],"duration":entry.duration_ms.min(3600000),"size":entry.response_size.min(2000000),"truncated":truncated})
}
pub(crate) fn run(
    entry: &TrafficEntry,
    id: &str,
    request: &Value,
    evidence: Vec<Value>,
    findings: Vec<Value>,
    checks: Vec<Value>,
    sent: usize,
    mode: &str,
) -> Value {
    let bytes: u64 = evidence.iter().filter_map(|v| v["size"].as_u64()).sum();
    json!({"version":1,"id":id,"origin":"automatic","sourceTrafficId":entry.id,
        "startedAt":entry.timestamp.to_rfc3339(),"finishedAt":chrono::Utc::now().to_rfc3339(),"status":"completed",
        "message":"Automatic capture audit","plan":{"request":request,"mode":mode,"checks":checks.iter().map(|v|v["checkId"].clone()).collect::<Vec<_>>(),
            "parameters":[],"allowSending":mode=="active","baselineSamples":1,"maxRequests":2,"rate":2,"delay":500,"diffOptions":{}},
        "sent":sent,"bytes":bytes,"baselineStable":null,"baselineIds":["observed"],"evidence":evidence,"findings":findings,"checks":checks})
}
fn credential_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "x-api-key"
            | "api-key"
            | "apikey"
            | "x-auth-token"
            | "x-access-token"
            | "access-token"
            | "token"
    )
}
fn credential_parameter(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "access_token" | "auth_token" | "api_key" | "apikey" | "token" | "jwt" | "id_token"
    )
}
fn anonymous(request: &Value) -> (Value, Vec<String>) {
    let mut request = request.clone();
    let mut removed = vec![];
    request["headers"]
        .as_object_mut()
        .unwrap()
        .retain(|name, _| {
            if credential_header(&name.to_ascii_lowercase()) {
                removed.push(format!("header {name}"));
                false
            } else {
                true
            }
        });
    let mut url = reqwest::Url::parse(request["url"].as_str().unwrap()).unwrap();
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter_map(|(key, value)| {
            if credential_parameter(&key) {
                removed.push(format!("query parameter {key}"));
                None
            } else {
                Some((key.into_owned(), value.into_owned()))
            }
        })
        .collect();
    if removed.iter().any(|v| v.starts_with("query parameter ")) {
        url.set_query(None);
        if !pairs.is_empty() {
            url.query_pairs_mut().extend_pairs(pairs);
        }
        request["url"] = json!(url.as_str());
    }
    (request, removed)
}
pub(crate) fn finding(
    check: &str,
    id: &str,
    title: &str,
    summary: String,
    evidence: Vec<&str>,
    excerpts: Vec<String>,
    severity: &str,
) -> Value {
    json!({"id":id,"fingerprint":format!("{check}:{id}"),"checkId":check,"title":title,"summary":summary,
        "severity":severity,"confidence":"medium","status":"needs_review","evidenceIds":evidence,"excerpts":excerpts.into_iter().map(|v|preview(&v,4000)).collect::<Vec<_>>(),
        "verification":{"method":"Captured response and automatic audit","outcome":"inconclusive","reason":"Observed behavior requires manual review of intended access policy and impact."},
        "remediation":if check=="noauthen" {"Require server-side authentication and authorization on protected APIs."} else {"Review the finding evidence and restrict access to sensitive data."}})
}
async fn audit_api(
    entry: &TrafficEntry,
    id: &str,
    state: &AuditState,
    intercept: &Intercept,
) -> Option<Value> {
    let original = request(entry)?;
    let mut evidence = vec![observed(entry, &original)];
    let mut findings = vec![];
    let mut checks = vec![];
    let mut sent = 0;
    let (anonymous, removed) = anonymous(&original);
    let mut cors = original.clone();
    cors["headers"]
        .as_object_mut()?
        .insert("origin".into(), json!("https://evil.com"));
    for (check, request) in [("noauthen", anonymous), ("cors", cors)] {
        // Without a recognized credential the "anonymous" request equals the original one, so a
        // 200 proves nothing about authentication. Count it as clean and send nothing.
        if check == "noauthen" && removed.is_empty() {
            checks.push(json!({"checkId":check,"status":"passed","message":"Request carried no recognized credentials; nothing to remove, so no authentication comparison was made","findingIds":[]}));
            continue;
        }
        if !state.enabled() || !intercept.scope().matches(&entry.host) {
            checks.push(json!({"checkId":check,"status":"skipped","message":"Automatic audit disabled or target left scope","findingIds":[]}));
            continue;
        }
        // A single API worker makes at most two request starts per second.
        sleep(Duration::from_millis(500)).await;
        if !state.enabled() || !intercept.scope().matches(&entry.host) {
            continue;
        }
        let result = super::http_sender::send(Json(request.clone())).await.0;
        sent += 1;
        let mut item = json!({"id":check,"label":if check=="cors" {"Origin: https://evil.com"} else {"Credentials removed"},
            "timestamp":chrono::Utc::now().to_rfc3339(),"request":request,"setCookies":[],"duration":result["duration"].as_u64().unwrap_or(0),
            "size":result["size"].as_u64().unwrap_or(0),"truncated":false});
        let mut finding_ids = vec![];
        if result["ok"] == true {
            let body = result["responseBody"].as_str().unwrap_or("");
            let mut bounded_headers = result["responseHeaders"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            let header_count = bounded_headers.len();
            bounded_headers.retain(|_, v| v.as_str().is_some_and(|s| s.len() <= 8192));
            let bounded_headers: Map<_, _> = bounded_headers.into_iter().take(200).collect();
            item["truncated"] =
                json!(body.chars().count() > 32000 || bounded_headers.len() != header_count);
            item["response"] = json!({"status":result["status"],"responseHeaders":bounded_headers,"responseBody":preview(body,32000)});
            if check == "noauthen" && result["status"] == 200 {
                let removed = if removed.is_empty() {
                    "No recognized header/query credentials were present".to_string()
                } else {
                    format!("Removed: {}", removed.join(", "))
                };
                findings.push(finding(check,"noauthen","NoAuthen: API returned 200 without recognized credentials",
                    format!("{removed}. The audit response was HTTP 200. Public endpoints and login/error pages may intentionally return 200; this does not prove an authentication bypass. Request body credentials and application-specific authentication require manual review."),
                    vec!["observed",check],vec![format!("Captured status: {}; audit status: 200",entry.status_code),removed],"medium"));
                finding_ids.push("noauthen");
            }
            if check == "cors" {
                let allow = result["responseHeaders"]
                    .as_object()
                    .and_then(|h| {
                        h.iter().find(|(name, _)| {
                            name.eq_ignore_ascii_case("access-control-allow-origin")
                        })
                    })
                    .and_then(|(_, v)| v.as_str())
                    .unwrap_or("")
                    .trim();
                if ["*", "https://evil.com"].contains(&allow) {
                    let credentials = result["responseHeaders"]["access-control-allow-credentials"]
                        .as_str()
                        .unwrap_or("");
                    findings.push(finding(check,"cors","CORS: untrusted origin allowed",
                        "The response allows a wildcard or the supplied untrusted origin. Browser exploitability depends on credentials, response data and preflight behavior; wildcard with credentials is rejected by browsers.".into(),
                        vec!["observed",check],vec!["Origin: https://evil.com".into(),format!("Access-Control-Allow-Origin: {allow}"),format!("Access-Control-Allow-Credentials: {credentials}")],if allow=="https://evil.com"&&credentials=="true" {"medium"} else {"low"}));
                    finding_ids.push("cors");
                }
            }
        } else {
            item["error"] = json!(preview(
                result["error"].as_str().unwrap_or("Request failed"),
                4000
            ));
        }
        checks.push(json!({"checkId":check,"status":if result["ok"]!=true {"inconclusive"} else if finding_ids.is_empty() {"passed"} else {"findings"},
            "message":if result["ok"]!=true {"Probe failed; not a clean result"} else {"Automatic probe completed; review response evidence"},"findingIds":finding_ids}));
        evidence.push(item);
    }
    Some(run(
        entry, id, &original, evidence, findings, checks, sent, "active",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::{HeaderMap, StatusCode},
        routing::any,
        Router,
    };
    use proxy_core::{ScopeSettings, TEMP_WORKSPACE_ID};
    fn captured(url: &str) -> TrafficEntry {
        let mut entry = TrafficEntry::new_request(
            "POST",
            url,
            "127.0.0.1",
            "/api/test",
            "http",
            r#"{"Authorization":["Bearer original"],"Cookie":["sid=original"],"X-API-Key":["key-original"],"Content-Type":["application/json"]}"#,
            br#"{"item":1}"#.to_vec(),
            Some("application/json".into()),
        );
        entry.status_code = 200;
        entry.response_body = br#"{"ok":true}"#.to_vec();
        entry.response_size = entry.response_body.len() as u64;
        entry.response_content_type = Some("application/json".into());
        entry.response_headers = "{}".into();
        entry
    }
    async fn wait_run(storage: &TrafficStorage, workspace: &str, id: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(run) = storage.get_scan_run(workspace, id).unwrap() {
                    return run;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("Automatic run did not finish")
    }
    #[tokio::test]
    async fn requests_without_credentials_skip_noauthen_and_send_only_cors() {
        let received = Arc::new(std::sync::Mutex::new(0usize));
        let seen = received.clone();
        let app = Router::new().route("/api/test", any(move || {
            let seen = seen.clone();
            async move { *seen.lock().unwrap() += 1; (StatusCode::OK, "{}") }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut entry = captured(&format!("http://{addr}/api/test"));
        entry.request_headers = r#"{"Content-Type":["application/json"]}"#.into();
        let storage = TrafficStorage::new(":memory:", 1000000).unwrap();
        let intercept = Intercept::new(storage.clone());
        let (state, _runtime) = start(storage, intercept.clone());
        let run = audit_api(&entry, "id", &state, &intercept).await.unwrap();
        assert_eq!(*received.lock().unwrap(), 1);
        assert!(run["findings"].as_array().unwrap().iter().all(|f| f["checkId"] != "noauthen"));
        let noauthen = run["checks"].as_array().unwrap().iter().find(|c| c["checkId"] == "noauthen").unwrap();
        assert_eq!(noauthen["status"], "passed");
    }
    #[test]
    fn removes_case_insensitive_credentials_without_changing_other_query_values() {
        let mut request = request(&captured(
            "http://localhost/api?access_token=private&item=a%2Fb&item=2",
        ))
        .unwrap();
        request["headers"]["AUTHORIZATION"] = json!("second token");
        let (clean, removed) = anonymous(&request);
        assert!(!clean["headers"]
            .as_object()
            .unwrap()
            .keys()
            .any(|key| credential_header(&key.to_ascii_lowercase())));
        assert!(removed.iter().any(|v| v.contains("access_token")));
        let url = reqwest::Url::parse(clean["url"].as_str().unwrap()).unwrap();
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![("item".into(), "a/b".into()), ("item".into(), "2".into())]
        );
        assert_eq!(clean["body"], request["body"]);
    }
    #[test]
    fn api_identity_ignores_credentials_but_keeps_request_semantics() {
        let first = request(&captured("http://localhost/api?token=first&item=1")).unwrap();
        let mut second = first.clone();
        second["url"] = json!("http://localhost/api?token=second&item=1");
        second["headers"]["authorization"] = json!("Bearer second");
        second["headers"]["cookie"] = json!("sid=second");
        assert_eq!(api_id(&first), api_id(&second));
        for (field, value) in [("body", "{\"item\":2}"), ("method", "PUT"), ("url", "http://localhost/api?item=2")] {
            let mut changed = first.clone(); changed[field] = json!(value);
            assert_ne!(api_id(&first), api_id(&changed));
        }
        second["headers"]["content-type"] = json!("text/plain");
        assert_ne!(api_id(&first), api_id(&second));
    }
    #[test]
    fn forbidden_identity_preserves_authentication_context() {
        let first=request(&captured("http://localhost/api/test")).unwrap();
        let mut second=first.clone();second["headers"]["authorization"]=json!("Bearer other-user");
        assert_ne!(forbidden_id(&first),forbidden_id(&second));
        assert_eq!(api_id(&first),api_id(&second));
    }
    #[tokio::test]
    async fn forbidden_api_is_audited_with_controls_deduplicated_and_workspace_scoped() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr=listener.local_addr().unwrap();
        let calls=Arc::new(AtomicUsize::new(0));let recorded=calls.clone();
        let app=Router::new().route("/api/test",any(move |headers:HeaderMap,body:String| {
            let calls=recorded.clone();async move {
                calls.fetch_add(1,Ordering::Relaxed);
                if let Some(auth)=headers.get("authorization") { assert_eq!(auth,"Bearer original"); }
                assert_eq!(body,r#"{"item":1}"#);
                if headers.get("x-real-ip").is_some_and(|v|v=="127.0.0.1") {
                    (StatusCode::OK,Json(json!({"user":"private","id":1})))
                } else { (StatusCode::FORBIDDEN,Json(json!({"error":"forbidden"}))) }
            }
        }));
        let server=tokio::spawn(async move {axum::serve(listener,app).await.unwrap();});
        let storage=TrafficStorage::new(":memory:",1000000).unwrap();
        let intercept=Intercept::new(storage.clone());
        let (_,runtime)=start(storage.clone(),intercept.clone());
        let mut entry=captured(&format!("http://{addr}/api/test"));
        entry.status_code=403;entry.response_body=br#"{"error":"forbidden"}"#.to_vec();entry.response_size=entry.response_body.len() as u64;
        let key=forbidden_id(&request(&entry).unwrap());
        // Old successful NoAuthen/CORS audits must not suppress the new 403 check.
        let original=request(&entry).unwrap();
        let legacy=run(&entry,"auto-previous",&original,vec![observed(&entry,&original)],vec![],vec![json!({"checkId":"noauthen","status":"passed","findingIds":[]}),json!({"checkId":"cors","status":"passed","findingIds":[]})],2,"active");
        storage.put_scan_run(TEMP_WORKSPACE_ID,"auto-previous",&legacy).unwrap();
        storage.insert(&entry).unwrap();storage.insert(&entry).unwrap();
        let result=wait_run(&storage,TEMP_WORKSPACE_ID,&key).await;
        super::super::scan::validate_run(&key,&result).unwrap();
        assert_eq!(result["findings"].as_array().unwrap().len(),1);
        assert_eq!(result["findings"][0]["checkId"],"403-bypass");
        assert_eq!(result["findings"][0]["evidenceIds"].as_array().unwrap().len(),7);
        assert_eq!(result["sent"],10);
        assert!(storage.has_completed_automatic_check(TEMP_WORKSPACE_ID,&key,"403-bypass").unwrap());
        drop(runtime);
        let (_, _restarted)=start(storage.clone(),intercept);
        let mut duplicate=entry.clone();duplicate.id=uuid::Uuid::new_v4().to_string();storage.insert(&duplicate).unwrap();
        sleep(Duration::from_millis(800)).await;
        assert_eq!(calls.load(Ordering::Relaxed),10);
        let other=storage.create_workspace("403 other workspace").unwrap().id;
        storage.set_active_workspace(&other).unwrap();
        duplicate.id=uuid::Uuid::new_v4().to_string();storage.insert(&duplicate).unwrap();
        wait_run(&storage,&other,&key).await;
        assert_eq!(calls.load(Ordering::Relaxed),22);
        server.abort();
    }
    #[tokio::test]
    async fn forbidden_successful_retry_prevents_further_capture_audits() {
        let storage=TrafficStorage::new(":memory:",1000000).unwrap();
        let mut entry=captured("http://127.0.0.1:1/api/test");entry.status_code=403;
        let original=request(&entry).unwrap();let key=forbidden_id(&original);
        for (id,status) in [(key.as_str(),"inconclusive"),("auto-retry-fixture","passed")] {
            let mut value=run(&entry,id,&original,vec![observed(&entry,&original)],vec![],vec![json!({"checkId":"403-bypass","status":status,"message":"fixture","findingIds":[]})],0,"active");
            value["auditKey"]=json!(key);
            storage.put_scan_run(TEMP_WORKSPACE_ID,id,&value).unwrap();
        }
        let intercept=Intercept::new(storage.clone());let (state,_runtime)=start(storage.clone(),intercept);
        storage.insert(&entry).unwrap();sleep(Duration::from_millis(700)).await;
        assert_eq!(state.0.active.load(Ordering::Relaxed),0);
        assert_eq!(state.0.completed.load(Ordering::Relaxed),0);
        assert_eq!(storage.list_scan_runs(TEMP_WORKSPACE_ID,0).unwrap().len(),2);
    }
    #[tokio::test]
    async fn forbidden_html_and_json_error_success_pages_are_not_bypass_findings() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
        let app=Router::new().route("/api/test",any(|headers:HeaderMap|async move {
            if headers.contains_key("x-real-ip") {(StatusCode::OK,"<html>Login</html>")}
            else if headers.contains_key("x-client-ip") {(StatusCode::OK,r#"{"error":"access denied"}"#)}
            else {(StatusCode::FORBIDDEN,r#"{"error":"forbidden"}"#)}
        }));
        let server=tokio::spawn(async move {axum::serve(listener,app).await.unwrap();});
        let storage=TrafficStorage::new(":memory:",1000000).unwrap();let intercept=Intercept::new(storage.clone());let (_, _runtime)=start(storage.clone(),intercept);
        let mut entry=captured(&format!("http://{addr}/api/test"));entry.status_code=403;entry.response_body=br#"{"error":"forbidden"}"#.to_vec();entry.response_size=entry.response_body.len() as u64;
        let key=forbidden_id(&request(&entry).unwrap());storage.insert(&entry).unwrap();
        let result=wait_run(&storage,TEMP_WORKSPACE_ID,&key).await;
        assert!(result["findings"].as_array().unwrap().is_empty());assert_eq!(result["checks"][0]["status"],"passed");
        server.abort();
    }
    #[tokio::test]
    async fn recognizes_legacy_completed_reports_without_sending_again() {
        let storage = TrafficStorage::new(":memory:", 1000000).unwrap();
        let entry = captured("http://127.0.0.1:1/api/test");
        let original = request(&entry).unwrap();
        let legacy = run(&entry, "auto-old-capture", &original, vec![observed(&entry, &original)], vec![], vec![
            json!({"checkId":"noauthen","status":"passed","findingIds":[]}),
            json!({"checkId":"cors","status":"passed","findingIds":[]})], 2, "active");
        storage.put_scan_run(TEMP_WORKSPACE_ID, "auto-old-capture", &legacy).unwrap();
        let intercept = Intercept::new(storage.clone());
        let (state, _runtime) = start(storage.clone(), intercept);
        storage.insert(&entry).unwrap();
        sleep(Duration::from_millis(1400)).await;
        assert_eq!(state.0.active.load(Ordering::Relaxed), 0);
        assert_eq!(state.0.completed.load(Ordering::Relaxed), 0);
        assert!(storage.get_scan_run(TEMP_WORKSPACE_ID, &api_id(&original)).unwrap().is_none());
        assert_eq!(storage.list_scan_runs(TEMP_WORKSPACE_ID, 0).unwrap().len(), 1);
        let other = storage.create_workspace("Other audit workspace").unwrap().id;
        storage.set_active_workspace(&other).unwrap();
        storage.insert(&captured("http://127.0.0.1:1/api/test")).unwrap();
        let own_run = wait_run(&storage, &other, &api_id(&original)).await;
        assert_eq!(own_run["sent"], 2);
        assert_eq!(storage.list_scan_runs(TEMP_WORKSPACE_ID, 0).unwrap().len(), 1);
    }
    #[tokio::test]
    async fn incomplete_audits_can_retry_without_overwriting_old_evidence() {
        let storage = TrafficStorage::new(":memory:", 1000000).unwrap();
        let entry = captured("http://127.0.0.1:1/api/test");
        let key = api_id(&request(&entry).unwrap());
        let intercept = Intercept::new(storage.clone());
        let (_, _runtime) = start(storage.clone(), intercept);
        storage.insert(&entry).unwrap();
        let first = wait_run(&storage, TEMP_WORKSPACE_ID, &key).await;
        assert!(!complete_api(&first));
        let retry = captured("http://127.0.0.1:1/api/test");
        let retry_id = digest_id("auto-retry-", format!("{key}:{}", retry.id).as_bytes());
        storage.insert(&retry).unwrap();
        let second = wait_run(&storage, TEMP_WORKSPACE_ID, &retry_id).await;
        super::super::scan::validate_run(&retry_id, &second).unwrap();
        assert_eq!(storage.get_scan_run(TEMP_WORKSPACE_ID, &key).unwrap().unwrap(), first);
    }
    #[tokio::test]
    async fn audits_captures_once_preserves_post_and_records_auth_and_cors_evidence() {
        let received = Arc::new(std::sync::Mutex::new(vec![]));
        let output = received.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/test",
            any(move |headers: HeaderMap, body: String| {
                let output = output.clone();
                async move {
                    output.lock().unwrap().push((headers.clone(), body));
                    (
                        [
                            ("access-control-allow-origin", "https://evil.com"),
                            ("access-control-allow-credentials", "true"),
                        ],
                        Json(json!({"ok":true})),
                    )
                }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let storage = TrafficStorage::new(":memory:", 1000000).unwrap();
        let workspace = storage.create_workspace("Audit").unwrap().id;
        storage.set_active_workspace(&workspace).unwrap();
        let intercept = Intercept::new(storage.clone());
        let (_state, runtime) = start(storage.clone(), intercept.clone());
        let mut entry = captured(&format!("http://{addr}/api/test"));
        entry.status_code = 0;
        storage.insert(&entry).unwrap();
        sleep(Duration::from_millis(30)).await;
        assert!(received.lock().unwrap().is_empty());
        entry.status_code = 200;
        storage.insert(&entry).unwrap();
        storage.insert(&entry).unwrap();
        let duplicate = captured(&format!("http://{addr}/api/test"));
        storage.insert(&duplicate).unwrap();
        let run = wait_run(&storage, &workspace, &api_id(&request(&entry).unwrap())).await;
        drop(runtime);
        let (_, _restarted) = start(storage.clone(), intercept.clone());
        storage.insert(&captured(&format!("http://{addr}/api/test"))).unwrap();
        sleep(Duration::from_millis(1200)).await;
        super::super::scan::validate_run(run["id"].as_str().unwrap(), &run).unwrap();
        assert_eq!(run["sent"], 2);
        assert_eq!(run["findings"].as_array().unwrap().len(), 2);
        assert_eq!(run["findings"][0]["checkId"], "noauthen");
        assert_eq!(run["findings"][0]["status"], "needs_review");
        let calls = received.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for name in ["authorization", "cookie", "x-api-key"] {
            assert!(!calls[0].0.contains_key(name));
        }
        assert_eq!(calls[0].1, r#"{"item":1}"#);
        assert_eq!(calls[1].0["origin"], "https://evil.com");
        assert_eq!(calls[1].0["authorization"], "Bearer original");
        assert_eq!(
            storage
                .count(&proxy_core::TrafficFilter {
                    workspace: Some(&workspace),
                    ..Default::default()
                })
                .unwrap(),
            3
        );
        assert_eq!(storage.list_scan_runs(&workspace, 0).unwrap().len(), 1);
        server.abort();
    }
    #[tokio::test]
    async fn rejected_auth_and_redirects_never_become_noauth_findings_and_wildcard_cors_is_reported(
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/api/protected", any(|| async { StatusCode::UNAUTHORIZED }))
            .route(
                "/api/redirect",
                any(|| async { (StatusCode::FOUND, [("location", "/api/open")]) }),
            )
            .route(
                "/api/open",
                any(|| async { ([("access-control-allow-origin", "*")], "public") }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let storage = TrafficStorage::new(":memory:", 1000000).unwrap();
        let intercept = Intercept::new(storage.clone());
        let (_state, _runtime) = start(storage.clone(), intercept);
        for path in ["protected", "redirect", "open"] {
            let entry = captured(&format!("http://{addr}/api/{path}"));
            storage.insert(&entry).unwrap();
            let run = wait_run(&storage, TEMP_WORKSPACE_ID, &api_id(&request(&entry).unwrap())).await;
            let findings = run["findings"].as_array().unwrap();
            if path == "open" {
                assert_eq!(findings.len(), 2);
                assert_eq!(findings[1]["severity"], "low");
            } else {
                assert!(findings.is_empty(), "{run}");
            }
            assert_eq!(
                run["evidence"][1]["response"]["status"],
                if path == "protected" {
                    401
                } else if path == "redirect" {
                    302
                } else {
                    200
                }
            );
        }
        server.abort();
    }
    #[tokio::test]
    async fn scope_pause_and_replay_sources_do_not_schedule_probes() {
        let storage = TrafficStorage::new(":memory:", 1000000).unwrap();
        let intercept = Intercept::new(storage.clone());
        intercept
            .update_scope(ScopeSettings {
                enabled: true,
                domains: vec!["allowed.test".into()],
            })
            .unwrap();
        let (state, _runtime) = start(storage.clone(), intercept);
        let entry = captured("http://127.0.0.1:1/api/test");
        storage.insert(&entry).unwrap();
        sleep(Duration::from_millis(100)).await;
        assert_eq!(state.0.active.load(Ordering::Relaxed), 0);
        assert!(storage
            .list_scan_runs(TEMP_WORKSPACE_ID, 0)
            .unwrap()
            .is_empty());
        state.0.enabled.store(false, Ordering::Relaxed);
        storage
            .insert(&captured("http://127.0.0.1:1/api/test"))
            .unwrap();
        let mut replay = captured("http://127.0.0.1:1/api/test");
        replay.source = "replay".into();
        assert!(!eligible(&replay));
        replay.source = "proxy".into();
        replay.status_code = 101;
        assert!(!eligible(&replay));
        sleep(Duration::from_millis(100)).await;
        assert!(storage
            .list_scan_runs(TEMP_WORKSPACE_ID, 0)
            .unwrap()
            .is_empty());
    }
}
