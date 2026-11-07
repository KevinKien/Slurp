//! Remote capture: the server side of `slurp client`, plus management of capture clients.
//!
//! A capture client authenticates with its own token, which is bound to one workspace and can only
//! upload traffic there. It cannot read anything and is rejected by every other endpoint.
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    Json,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use proxy_core::{CaptureClient, ClientIdentity, IngestError, TrafficEntry, TrafficStorage, WorkspaceError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use std::sync::Arc;

pub const PROTOCOL: u32 = 1;
const MAX_ENTRIES: usize = 500;
const MAX_DECODED: u64 = 128 * 1024 * 1024;
pub const TOKEN_PREFIX: &str = "slurp_c_";

type Error = (StatusCode, Json<Value>);

fn fail(status: StatusCode, message: impl ToString) -> Error {
    (status, Json(json!({ "error": message.to_string() })))
}

/// New random token. It is shown once and only its hash is stored.
pub fn new_token() -> String {
    format!("{TOKEN_PREFIX}{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}

pub fn hash_token(token: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A traffic entry as sent over the wire: identical to `TrafficEntry` except that bodies are base64.
#[derive(Debug, Serialize, Deserialize)]
pub struct WireEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub scheme: String,
    pub request_headers: String,
    pub request_body: String,
    pub request_content_type: Option<String>,
    pub status_code: u16,
    pub response_headers: String,
    pub response_body: String,
    pub response_content_type: Option<String>,
    pub duration_ms: u64,
    pub request_size: u64,
    pub response_size: u64,
    pub error: Option<String>,
}

impl From<&TrafficEntry> for WireEntry {
    fn from(e: &TrafficEntry) -> Self {
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        Self {
            id: e.id.clone(),
            timestamp: e.timestamp,
            method: e.method.clone(),
            url: e.url.clone(),
            host: e.host.clone(),
            path: e.path.clone(),
            scheme: e.scheme.clone(),
            request_headers: e.request_headers.clone(),
            request_body: b64(&e.request_body),
            request_content_type: e.request_content_type.clone(),
            status_code: e.status_code,
            response_headers: e.response_headers.clone(),
            response_body: b64(&e.response_body),
            response_content_type: e.response_content_type.clone(),
            duration_ms: e.duration_ms,
            request_size: e.request_size,
            response_size: e.response_size,
            error: e.error.clone(),
        }
    }
}

impl WireEntry {
    fn into_entry(self) -> Result<TrafficEntry, String> {
        let decode = |text: &str| base64::engine::general_purpose::STANDARD.decode(text).map_err(|_| "body is not valid base64".to_string());
        if self.id.is_empty() || self.id.len() > 100 {
            return Err("invalid entry id".into());
        }
        let mut entry = TrafficEntry::new_request(
            &self.method,
            &self.url,
            &self.host,
            &self.path,
            &self.scheme,
            &self.request_headers,
            decode(&self.request_body)?,
            self.request_content_type.clone(),
        );
        entry.id = self.id;
        entry.timestamp = self.timestamp;
        entry.status_code = self.status_code;
        entry.response_headers = self.response_headers;
        entry.response_body = decode(&self.response_body)?;
        entry.response_content_type = self.response_content_type;
        entry.duration_ms = self.duration_ms;
        entry.request_size = self.request_size;
        entry.response_size = self.response_size;
        entry.error = self.error;
        Ok(entry)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Batch {
    pub protocol: u32,
    pub entries: Vec<WireEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchResult {
    pub accepted: usize,
    pub rejected: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hello {
    pub protocol: u32,
    pub server_version: String,
    pub client: String,
    pub workspace: String,
}

fn authenticate(storage: &TrafficStorage, headers: &HeaderMap) -> Result<ClientIdentity, Error> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| t.starts_with(TOKEN_PREFIX))
        .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "missing capture token"))?;
    match storage.authenticate_capture_client(&hash_token(token)) {
        Ok(Some(client)) => Ok(client),
        Ok(None) => Err(fail(StatusCode::UNAUTHORIZED, "capture token is invalid or was revoked")),
        Err(e) => {
            tracing::error!("capture client lookup failed: {e:#}");
            Err(fail(StatusCode::INTERNAL_SERVER_ERROR, "lookup failed"))
        }
    }
}

/// `GET /api/ingest/hello` — lets a client confirm its token and see where it uploads to.
pub async fn hello(State(storage): State<Arc<TrafficStorage>>, headers: HeaderMap) -> Result<Json<Hello>, Error> {
    let client = authenticate(&storage, &headers)?;
    let workspace = storage
        .list_workspaces()
        .ok()
        .and_then(|all| all.into_iter().find(|w| w.id == client.workspace_id))
        .map(|w| w.name)
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "the workspace of this client no longer exists"))?;
    Ok(Json(Hello { protocol: PROTOCOL, server_version: env!("CARGO_PKG_VERSION").into(), client: client.name, workspace }))
}

fn decode_body(headers: &HeaderMap, body: &Bytes) -> Result<Vec<u8>, Error> {
    match headers.get(header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()) {
        None | Some("identity") => Ok(body.to_vec()),
        Some("gzip") => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(body.as_ref())
                .take(MAX_DECODED + 1)
                .read_to_end(&mut out)
                .map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid gzip body"))?;
            if out.len() as u64 > MAX_DECODED {
                return Err(fail(StatusCode::PAYLOAD_TOO_LARGE, "batch is too large"));
            }
            Ok(out)
        }
        Some(_) => Err(fail(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported Content-Encoding")),
    }
}

/// `POST /api/ingest/batch` — store uploaded traffic in the client's workspace.
pub async fn batch(State(storage): State<Arc<TrafficStorage>>, headers: HeaderMap, body: Bytes) -> Result<Json<BatchResult>, Error> {
    let client = authenticate(&storage, &headers)?;
    let raw = decode_body(&headers, &body)?;
    let batch: Batch = serde_json::from_slice(&raw).map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid batch"))?;
    if batch.protocol != PROTOCOL {
        return Err(fail(StatusCode::BAD_REQUEST, format!("unsupported protocol {}; this server speaks {PROTOCOL}", batch.protocol)));
    }
    if batch.entries.len() > MAX_ENTRIES {
        return Err(fail(StatusCode::PAYLOAD_TOO_LARGE, format!("at most {MAX_ENTRIES} entries per batch")));
    }
    tokio::task::spawn_blocking(move || {
        let (mut accepted, mut rejected) = (0, 0);
        for wire in batch.entries {
            let Ok(entry) = wire.into_entry() else {
                rejected += 1;
                continue;
            };
            match storage.ingest_entry(&entry, &client) {
                Ok(()) => accepted += 1,
                Err(IngestError::Conflict) => rejected += 1,
                Err(IngestError::NotFound) => return Err(fail(StatusCode::NOT_FOUND, "the workspace of this client no longer exists")),
                Err(IngestError::Other(e)) => {
                    tracing::error!("ingest failed: {e:#}");
                    return Err(fail(StatusCode::INTERNAL_SERVER_ERROR, "could not store traffic"));
                }
            }
        }
        Ok(Json(BatchResult { accepted, rejected }))
    })
    .await
    .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "ingest failed"))?
}

// ---- management (admin token) ----

#[derive(Deserialize)]
pub struct NewClient {
    pub name: String,
    pub workspace_id: String,
}

fn workspace_error(e: WorkspaceError) -> Error {
    match e {
        WorkspaceError::InvalidName => fail(StatusCode::BAD_REQUEST, "client name must be 1-40 characters without commas"),
        WorkspaceError::NameTaken => fail(StatusCode::CONFLICT, "a client with this name already exists"),
        WorkspaceError::NotFound => fail(StatusCode::NOT_FOUND, "workspace not found"),
        WorkspaceError::Protected => fail(StatusCode::CONFLICT, "not allowed"),
        WorkspaceError::Other(err) => {
            tracing::error!("capture client error: {err:#}");
            fail(StatusCode::INTERNAL_SERVER_ERROR, "capture client error")
        }
    }
}

/// `GET /api/capture-clients`
pub async fn list_clients(State(storage): State<Arc<TrafficStorage>>) -> Result<Json<Vec<CaptureClient>>, Error> {
    storage.list_capture_clients().map(Json).map_err(|e| workspace_error(WorkspaceError::Other(e)))
}

/// `POST /api/capture-clients` — register a client and return its token (shown only this once).
pub async fn create_client(State(storage): State<Arc<TrafficStorage>>, Json(body): Json<NewClient>) -> Result<(StatusCode, Json<Value>), Error> {
    let token = new_token();
    let client = storage.create_capture_client(&body.name, &body.workspace_id, &hash_token(&token)).map_err(workspace_error)?;
    Ok((StatusCode::CREATED, Json(json!({ "client": client, "token": token }))))
}

/// `DELETE /api/capture-clients/:id` — revoke a client.
pub async fn delete_client(State(storage): State<Arc<TrafficStorage>>, Path(id): Path<String>) -> Result<StatusCode, Error> {
    match storage.delete_capture_client(&id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(fail(StatusCode::NOT_FOUND, "client not found")),
        Err(e) => Err(workspace_error(WorkspaceError::Other(e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_prefixed_unique_and_hash_deterministically() {
        let (a, b) = (new_token(), new_token());
        assert!(a.starts_with(TOKEN_PREFIX) && a.len() == TOKEN_PREFIX.len() + 64);
        assert_ne!(a, b);
        assert_eq!(hash_token(&a), hash_token(&a));
        assert_ne!(hash_token(&a), hash_token(&b));
        assert_eq!(hash_token(&a).len(), 64);
    }

    #[test]
    fn wire_entries_round_trip_binary_bodies() {
        let mut entry = TrafficEntry::new_request("GET", "https://x/a", "x", "/a", "https", "{}", vec![0, 255, 1], None);
        entry.response_body = vec![9, 0, 9];
        let back = WireEntry::from(&entry).into_entry().unwrap();
        assert_eq!(back.request_body, vec![0, 255, 1]);
        assert_eq!(back.response_body, vec![9, 0, 9]);
        assert_eq!(back.id, entry.id);
    }
}
