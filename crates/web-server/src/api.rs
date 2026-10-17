/// REST API route handlers for traffic data.
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::Extension;
use axum::http::StatusCode;
use axum::response::Json;
use proxy_core::{
    HeldItem, Intercept, InterceptAction, InterceptEdit, InterceptSettings, ResolveError, SettingsUpdate, TrafficFilter,
    SessionInfo, TrafficEntry, TrafficStorage, Workspace, WorkspaceError, pairs_to_json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Query parameters for listing traffic.
#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub search: Option<String>,
    /// Restrict to one workspace id; omit for all workspaces.
    pub workspace: Option<String>,
}

/// Optional workspace scope for stats, clear and export.
#[derive(Debug, Deserialize)]
pub struct WorkspaceParam {
    pub workspace: Option<String>,
}

/// Envelope for list responses.
#[derive(Serialize)]
pub struct ListResponse<T> {
    pub data: Vec<T>,
    pub total: u64,
    pub limit: usize,
    pub offset: usize,
}

/// `GET /api/traffic` — list captured traffic with optional filters.
pub async fn list_traffic(
    State(storage): State<Arc<TrafficStorage>>,
    Query(params): Query<ListParams>,
) -> Result<Json<ListResponse<proxy_core::TrafficEntry>>, StatusCode> {
    let limit = params.limit.unwrap_or(200).min(1000);
    let offset = params.offset.unwrap_or(0);

    let filter = TrafficFilter {
        host: params.host.as_deref(),
        method: params.method.as_deref(),
        status: params.status,
        search: params.search.as_deref(),
        workspace: params.workspace.as_deref(),
    };
    let entries = storage.list(limit, offset, &filter).map_err(|e| {
        tracing::error!("list_traffic error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Count with the same filter so `total` matches what the client can page through.
    let total = storage.count(&filter).unwrap_or(0);

    Ok(Json(ListResponse {
        data: entries,
        total,
        limit,
        offset,
    }))
}

/// `GET /api/traffic/:id` — get a single traffic entry by ID.
pub async fn get_traffic(
    State(storage): State<Arc<TrafficStorage>>,
    Path(id): Path<String>,
) -> Result<Json<proxy_core::TrafficEntry>, StatusCode> {
    let entry = storage.get(&id).map_err(|e| {
        tracing::error!("get_traffic error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match entry {
        Some(e) => Ok(Json(e)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// `GET /api/stats` — get traffic statistics.
pub async fn get_stats(
    State(storage): State<Arc<TrafficStorage>>,
    Query(p): Query<WorkspaceParam>,
) -> Result<Json<proxy_core::TrafficStats>, StatusCode> {
    let stats = storage.stats(p.workspace.as_deref()).map_err(|e| {
        tracing::error!("get_stats error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(stats))
}

/// `DELETE /api/traffic` — clear all traffic entries.
pub async fn clear_traffic(
    State(storage): State<Arc<TrafficStorage>>,
    Query(p): Query<WorkspaceParam>,
) -> Result<StatusCode, StatusCode> {
    storage.clear(p.workspace.as_deref()).map_err(|e| {
        tracing::error!("clear_traffic error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/traffic/export` — export all traffic as JSON array.
pub async fn export_traffic(
    State(storage): State<Arc<TrafficStorage>>,
    Query(p): Query<WorkspaceParam>,
) -> Result<Json<Vec<proxy_core::TrafficEntry>>, StatusCode> {
    let filter = TrafficFilter { workspace: p.workspace.as_deref(), ..Default::default() };
    let entries = storage
        .list(10000, 0, &filter)
        .map_err(|e| {
            tracing::error!("export_traffic error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(entries))
}

// ── Workspaces ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WorkspaceBody {
    pub name: String,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

type ApiError = (StatusCode, Json<ErrorBody>);

fn workspace_error(e: WorkspaceError) -> ApiError {
    let status = match &e {
        WorkspaceError::InvalidName => StatusCode::BAD_REQUEST,
        WorkspaceError::NameTaken => StatusCode::CONFLICT,
        WorkspaceError::NotFound => StatusCode::NOT_FOUND,
        WorkspaceError::Protected => StatusCode::CONFLICT,
        WorkspaceError::Other(err) => {
            tracing::error!("workspace error: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    (status, Json(ErrorBody { error: e.to_string() }))
}

/// `GET /api/workspaces` — list workspaces with request counts.
pub async fn list_workspaces(
    State(storage): State<Arc<TrafficStorage>>,
) -> Result<Json<Vec<Workspace>>, ApiError> {
    storage.list_workspaces().map(Json).map_err(|e| workspace_error(WorkspaceError::Other(e)))
}

/// `POST /api/workspaces` — create a workspace.
pub async fn create_workspace(
    State(storage): State<Arc<TrafficStorage>>,
    Json(body): Json<WorkspaceBody>,
) -> Result<(StatusCode, Json<Workspace>), ApiError> {
    storage.create_workspace(&body.name).map(|w| (StatusCode::CREATED, Json(w))).map_err(workspace_error)
}

/// `PATCH /api/workspaces/:id` — rename a workspace.
pub async fn rename_workspace(
    State(storage): State<Arc<TrafficStorage>>,
    Path(id): Path<String>,
    Json(body): Json<WorkspaceBody>,
) -> Result<StatusCode, ApiError> {
    storage.rename_workspace(&id, &body.name).map(|_| StatusCode::NO_CONTENT).map_err(workspace_error)
}

/// `DELETE /api/workspaces/:id` — delete a workspace and its traffic.
pub async fn delete_workspace(
    State(storage): State<Arc<TrafficStorage>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    storage.delete_workspace(&id).map(|_| StatusCode::NO_CONTENT).map_err(workspace_error)
}

/// `POST /api/workspaces/:id/activate` — capture new traffic into this workspace.
pub async fn activate_workspace(
    State(storage): State<Arc<TrafficStorage>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    storage.set_active_workspace(&id).map(|_| StatusCode::NO_CONTENT).map_err(workspace_error)
}

/// `GET /api/info` — details the UI shows in the MCP setup docs.
pub async fn get_info() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "executable": std::env::current_exe().ok().map(|p| p.display().to_string()),
    }))
}

// ── Intercept ───────────────────────────────────────────────────

#[derive(Serialize)]
pub struct InterceptState {
    pub scope: proxy_core::ScopeSettings,
    pub settings: InterceptSettings,
    pub held: Vec<HeldItem>,
}

fn resolve_error(e: ResolveError) -> ApiError {
    let status = match &e {
        ResolveError::NotFound => StatusCode::NOT_FOUND,
        ResolveError::Invalid(_) => StatusCode::BAD_REQUEST,
    };
    (status, Json(ErrorBody { error: e.to_string() }))
}

/// `GET /api/intercept` — current settings and everything that is held right now.
pub async fn get_intercept(Extension(intercept): Extension<Arc<Intercept>>) -> Json<InterceptState> {
    Json(InterceptState { scope: intercept.scope(), settings: intercept.settings(), held: intercept.list() })
}

/// `PUT /api/intercept/settings` — switch request/response interception on or off.
pub async fn update_intercept_settings(
    Extension(intercept): Extension<Arc<Intercept>>,
    Json(update): Json<SettingsUpdate>,
) -> Json<InterceptSettings> {
    Json(intercept.update_settings(update))
}

pub async fn update_scope(
    Extension(intercept): Extension<Arc<Intercept>>,
    Json(scope): Json<proxy_core::ScopeSettings>,
) -> Result<Json<proxy_core::ScopeSettings>, ApiError> {
    intercept.update_scope(scope).map(Json).map_err(|message|bad_request(&message))
}

/// `POST /api/intercept/:id/forward` — forward a held item. The body is an optional JSON
/// edit (`method`, `path`, `status`, `headers`, `body`); an empty body forwards it unchanged.
/// A malformed edit is rejected rather than ignored, and the item stays held.
pub async fn forward_held(
    Extension(intercept): Extension<Arc<Intercept>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let edit = if body.iter().all(u8::is_ascii_whitespace) {
        None
    } else {
        Some(serde_json::from_slice::<InterceptEdit>(&body).map_err(|e| {
            (StatusCode::BAD_REQUEST, Json(ErrorBody { error: format!("invalid edit: {e}") }))
        })?)
    };
    intercept.resolve(&id, InterceptAction::Forward(edit)).map(|_| StatusCode::NO_CONTENT).map_err(resolve_error)
}

/// `POST /api/intercept/:id/drop` — drop a held item; the client receives a 502.
pub async fn drop_held(
    Extension(intercept): Extension<Arc<Intercept>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    intercept.resolve(&id, InterceptAction::Drop).map(|_| StatusCode::NO_CONTENT).map_err(resolve_error)
}

/// `POST /api/intercept/forward-all` — forward everything that is held, unchanged.
pub async fn forward_all_held(Extension(intercept): Extension<Arc<Intercept>>) -> StatusCode {
    intercept.forward_all();
    StatusCode::NO_CONTENT
}

// ── Session & saved requests ────────────────────────────────────

/// `GET /api/session` — whether a workspace has been chosen since the tool started.
pub async fn get_session(State(storage): State<Arc<TrafficStorage>>) -> Result<Json<SessionInfo>, ApiError> {
    storage.session().map(Json).map_err(|e| workspace_error(WorkspaceError::Other(e)))
}

/// `POST /api/session/temporary` — continue without a workspace. Requests are kept in memory
/// only and are lost when the tool exits.
pub async fn use_temporary_session(State(storage): State<Arc<TrafficStorage>>) -> StatusCode {
    storage.use_temporary();
    StatusCode::NO_CONTENT
}

/// A request/response pair sent from the Replay tool, to be stored like captured traffic.
#[derive(Deserialize)]
pub struct SaveTraffic {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub request_headers: Vec<(String, String)>,
    #[serde(default)]
    pub request_body: String,
    #[serde(default)]
    pub status_code: u16,
    #[serde(default)]
    pub response_headers: Vec<(String, String)>,
    #[serde(default)]
    pub response_body: String,
    #[serde(default)]
    pub duration_ms: u64,
    pub error: Option<String>,
}

const MAX_HEADERS: usize = 200;
const MAX_HEADER_LEN: usize = 8192;

fn bad_request(msg: &str) -> ApiError {
    (StatusCode::BAD_REQUEST, Json(ErrorBody { error: msg.to_string() }))
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
}

/// `POST /api/traffic` — store a request sent from Replay in the current workspace
/// (or in memory if none is chosen), marked with `source: "replay"`.
pub async fn save_traffic(
    State(storage): State<Arc<TrafficStorage>>,
    Json(body): Json<SaveTraffic>,
) -> Result<(StatusCode, Json<TrafficEntry>), ApiError> {
    if body.method.is_empty() || body.method.len() > 16 || !body.method.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(bad_request("invalid method"));
    }
    if body.url.len() > 4096 {
        return Err(bad_request("url is too long"));
    }
    let uri: axum::http::Uri = body.url.parse().map_err(|_| bad_request("invalid url"))?;
    let scheme = uri.scheme_str().filter(|s| matches!(*s, "http" | "https")).ok_or_else(|| bad_request("url must be http or https"))?;
    let host = uri.host().ok_or_else(|| bad_request("url has no host"))?;
    if body.request_headers.len() > MAX_HEADERS
        || body.response_headers.len() > MAX_HEADERS
        || body.request_headers.iter().chain(&body.response_headers).any(|(n, v)| n.len() > MAX_HEADER_LEN || v.len() > MAX_HEADER_LEN)
    {
        return Err(bad_request("too many or too large headers"));
    }

    let mut entry = TrafficEntry::new_request(
        &body.method.to_ascii_uppercase(),
        &body.url,
        host,
        uri.path(),
        scheme,
        &pairs_to_json(&body.request_headers),
        body.request_body.into_bytes(),
        header_value(&body.request_headers, "content-type"),
    );
    entry.status_code = body.status_code;
    entry.response_headers = pairs_to_json(&body.response_headers);
    entry.response_content_type = header_value(&body.response_headers, "content-type");
    entry.response_size = body.response_body.len() as u64;
    entry.response_body = body.response_body.into_bytes();
    entry.duration_ms = body.duration_ms;
    entry.error = body.error;
    entry.source = "replay".to_string();

    storage.insert(&entry).map_err(|e| workspace_error(WorkspaceError::Other(e)))?;
    // Return what was stored (it now carries its workspace).
    let stored = storage
        .get(&entry.id)
        .map_err(|e| workspace_error(WorkspaceError::Other(e)))?
        .unwrap_or(entry);
    Ok((StatusCode::CREATED, Json(stored)))
}

// ── Replay tabs ─────────────────────────────────────────────────

/// Largest stored Replay document; a guard against runaway clients, far above real use.
const MAX_REPLAY_DOC: usize = 5 * 1024 * 1024;
const MAX_REPLAY_TABS: usize = 200;

/// `GET /api/workspaces/:id/replay` — the saved Replay tabs of a workspace (empty if none yet).
pub async fn get_replay_tabs(
    State(storage): State<Arc<TrafficStorage>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let doc = storage.get_replay_tabs(&id).map_err(workspace_error)?;
    let value = doc
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_else(|| serde_json::json!({ "tabs": [], "active": null }));
    Ok(Json(value))
}

/// `PUT /api/workspaces/:id/replay` — replace the saved Replay tabs of a workspace.
/// The body must be a JSON object with a `tabs` array.
pub async fn put_replay_tabs(
    State(storage): State<Arc<TrafficStorage>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let _guard = crate::replay::WRITE_LOCK.lock().await;
    if body.len() > MAX_REPLAY_DOC {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, Json(ErrorBody { error: "replay tabs are too large".into() })));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| bad_request(&format!("invalid JSON: {e}")))?;
    match value.get("tabs").and_then(|t| t.as_array()) {
        Some(tabs) if tabs.len() <= MAX_REPLAY_TABS => {}
        Some(_) => return Err(bad_request("too many tabs")),
        None => return Err(bad_request("expected an object with a \"tabs\" array")),
    }
    crate::replay::validate_variables(&value["variables"]).map_err(|(_,body)|bad_request(body.0["error"].as_str().unwrap_or("Invalid variables")))?;
    storage
        .put_replay_tabs(&id, &value.to_string())
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(workspace_error)
}


#[derive(Deserialize)]
pub struct HistoryParams {
    pub bookmarked: Option<bool>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
    pub ascending: Option<bool>,
    pub workspace: Option<String>,
    pub search: Option<String>,
    pub method: Option<String>,
    pub status_class: Option<u16>,
    /// JSON array of exact hostnames.
    pub domains: Option<String>,
}

#[derive(Serialize)]
pub struct HistoryPage {
    summary: bool,
    data: Vec<TrafficEntry>,
    total: u64,
    next_cursor: Option<String>,
}

pub async fn history_page(State(storage): State<Arc<TrafficStorage>>, Query(p): Query<HistoryParams>) -> Result<Json<HistoryPage>, StatusCode> {
    let limit = p.limit.unwrap_or(100).clamp(1, 200);
    let cursor: Option<(String, String)> = p.cursor.as_deref().map(serde_json::from_str).transpose().map_err(|_| StatusCode::BAD_REQUEST)?;
    let domains: Vec<String> = p.domains.as_deref().map(serde_json::from_str).transpose().map_err(|_| StatusCode::BAD_REQUEST)?.unwrap_or_default();
    if domains.len() > 100 || p.status_class.is_some_and(|c| !(1..=5).contains(&c)) { return Err(StatusCode::BAD_REQUEST); }
    let filter = TrafficFilter { workspace: p.workspace.as_deref(), search: p.search.as_deref(), method: p.method.as_deref(), ..Default::default() };
    let (mut data, total) = storage.history_page(limit + 1, &filter, cursor.as_ref().map(|(t,id)| (t.as_str(),id.as_str())), p.ascending.unwrap_or(false), &domains, p.status_class, p.bookmarked.unwrap_or(false)).map_err(|e| { tracing::error!("history page: {e}"); StatusCode::INTERNAL_SERVER_ERROR })?;
    let more = data.len() > limit;
    data.truncate(limit);
    let next_cursor = if more { data.last().map(|e| serde_json::to_string(&(e.timestamp.to_rfc3339(), &e.id)).unwrap()) } else { None };
    Ok(Json(HistoryPage { summary: true, data, total, next_cursor }))
}


#[derive(Deserialize)]
pub struct AnnotationPatch { bookmarked: Option<bool>, notes: Option<String> }
pub async fn annotate_traffic(State(storage): State<Arc<TrafficStorage>>, Path(id): Path<String>, Json(p): Json<AnnotationPatch>) -> Result<Json<serde_json::Value>, ApiError> {
    if p.notes.as_ref().is_some_and(|n| n.len() > 16_000) { return Err(bad_request("Notes exceed 16 KB")); }
    let result = storage.annotate(&id,p.bookmarked,p.notes.as_deref()).map_err(|e| bad_request(&e.to_string()))?.ok_or_else(|| (StatusCode::NOT_FOUND,Json(ErrorBody { error:"Traffic not found".into() })))?;
    Ok(Json(serde_json::json!({"bookmarked":result.0,"notes":result.1})))
}

pub async fn delete_traffic(State(storage): State<Arc<TrafficStorage>>, Path(id): Path<String>) -> Result<StatusCode, StatusCode> {
    match storage.delete(&id).map_err(|e| { tracing::error!("delete_traffic error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err(StatusCode::NOT_FOUND),
    }
}
