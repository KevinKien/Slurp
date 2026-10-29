//! `.slurp` workspace export and import.
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures_util::StreamExt;
use proxy_core::{ArchiveError, ExportOptions, TrafficStorage};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Seek, SeekFrom};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Largest `.slurp` file accepted for import.
const MAX_IMPORT_BYTES: u64 = 8 * 1024 * 1024 * 1024;

type Error = (StatusCode, Json<Value>);

fn fail(status: StatusCode, message: impl ToString) -> Error {
    (status, Json(json!({ "error": message.to_string() })))
}

fn archive_error(e: ArchiveError) -> Error {
    match e {
        ArchiveError::Invalid(message) => fail(StatusCode::BAD_REQUEST, message),
        ArchiveError::NotFound => fail(StatusCode::NOT_FOUND, "workspace not found"),
        ArchiveError::Other(err) => {
            tracing::error!("workspace archive error: {err:#}");
            fail(StatusCode::INTERNAL_SERVER_ERROR, "workspace archive failed")
        }
    }
}

fn join_error(e: tokio::task::JoinError) -> Error {
    tracing::error!("workspace archive task failed: {e}");
    fail(StatusCode::INTERNAL_SERVER_ERROR, "workspace archive failed")
}

#[derive(Debug, Deserialize)]
pub struct ExportParams {
    pub profiles: Option<bool>,
    pub intruder: Option<bool>,
    pub redact: Option<bool>,
}

fn file_stem(name: &str) -> String {
    let stem: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    let stem = stem.trim_matches('-');
    if stem.is_empty() { "workspace".into() } else { stem.chars().take(60).collect() }
}

/// `GET /api/workspaces/:id/export` — download a workspace as a `.slurp` file.
pub async fn export(
    State(storage): State<Arc<TrafficStorage>>,
    Path(id): Path<String>,
    Query(params): Query<ExportParams>,
) -> Result<Response, Error> {
    let name = storage
        .list_workspaces()
        .map_err(|e| archive_error(e.into()))?
        .into_iter()
        .find(|w| w.id == id)
        .map(|w| w.name)
        .ok_or_else(|| archive_error(ArchiveError::NotFound))?;
    let options = ExportOptions {
        include_profiles: params.profiles.unwrap_or(true),
        include_intruder: params.intruder.unwrap_or(true),
        redact_secrets: params.redact.unwrap_or(false),
    };
    // An unnamed temporary file is deleted automatically, including on Windows.
    let file = tokio::task::spawn_blocking(move || -> Result<std::fs::File, ArchiveError> {
        let mut file = tempfile::tempfile()?;
        storage.export_workspace(&id, options, &mut file)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    })
    .await
    .map_err(join_error)?
    .map_err(archive_error)?;
    let length = file.metadata().map(|m| m.len()).ok();
    let file = tokio::fs::File::from_std(file);
    let stream = futures_util::stream::unfold(file, |mut file| async move {
        let mut buffer = vec![0u8; 64 * 1024];
        match file.read(&mut buffer).await {
            Ok(0) => None,
            Ok(n) => {
                buffer.truncate(n);
                Some((Ok::<_, std::io::Error>(axum::body::Bytes::from(buffer)), file))
            }
            Err(e) => Some((Err(e), file)),
        }
    });
    let mut response = Response::new(Body::from_stream(stream));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}.slurp\"", file_stem(&name)).parse().unwrap(),
    );
    if let Some(length) = length {
        headers.insert(header::CONTENT_LENGTH, length.into());
    }
    Ok(response)
}

/// `POST /api/workspaces/import` — body is a `.slurp` file; creates a new workspace from it.
pub async fn import(State(storage): State<Arc<TrafficStorage>>, body: Body) -> Result<Response, Error> {
    let mut file = tokio::fs::File::from_std(tempfile::tempfile().map_err(|e| archive_error(e.into()))?);
    let mut received = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| fail(StatusCode::BAD_REQUEST, "upload interrupted"))?;
        received += chunk.len() as u64;
        if received > MAX_IMPORT_BYTES {
            return Err(fail(StatusCode::PAYLOAD_TOO_LARGE, "file is too large to import"));
        }
        file.write_all(&chunk).await.map_err(|e| archive_error(e.into()))?;
    }
    file.flush().await.map_err(|e| archive_error(e.into()))?;
    let file = file.into_std().await;
    let summary = tokio::task::spawn_blocking(move || -> Result<proxy_core::ImportSummary, ArchiveError> {
        let mut file = file;
        file.seek(SeekFrom::Start(0))?;
        let summary = storage.import_workspace(file)?;
        // Documents saved through the API are validated; imported ones must meet the same bar.
        let (_, profiles) = storage.get_auth_profiles(&summary.workspace.id).map_err(|e| ArchiveError::Other(e.into()))?;
        let valid = serde_json::from_str::<Value>(&profiles).ok().is_some_and(|doc| crate::security::validate_profiles(&doc).is_ok());
        if !valid {
            let _ = storage.delete_workspace(&summary.workspace.id);
            return Err(ArchiveError::Invalid("the file contains invalid authentication profiles".into()));
        }
        Ok(summary)
    })
    .await
    .map_err(join_error)?
    .map_err(archive_error)?;
    Ok((StatusCode::CREATED, Json(summary)).into_response())
}
