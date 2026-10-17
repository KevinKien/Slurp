//! Workspace-scoped authentication profiles and immutable authorization matrix evidence.
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use proxy_core::{TrafficStorage, WorkspaceError};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
type Error = (StatusCode, Json<Value>);
fn bad(message: impl ToString) -> Error {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":message.to_string()})),
    )
}
fn storage_error(error: WorkspaceError) -> Error {
    (
        if matches!(error, WorkspaceError::NotFound) {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        },
        Json(json!({"error":error.to_string()})),
    )
}
fn text(value: &Value, max: usize) -> bool {
    value
        .as_str()
        .is_some_and(|v| !v.trim().is_empty() && v.len() <= max)
}
pub fn validate_profiles(doc: &Value) -> Result<(), Error> {
    if doc.to_string().len() > 2_000_000 {
        return Err(bad("Profiles exceed 2 MB"));
    }
    let profiles = doc["profiles"]
        .as_array()
        .filter(|v| v.len() <= 30)
        .ok_or_else(|| bad("Up to 30 profiles"))?;
    let mut ids = std::collections::HashSet::new();
    for profile in profiles {
        if profile["id"].as_str() == Some("@anonymous")
            || !text(&profile["id"], 100)
            || !text(&profile["name"], 800)
            || !ids.insert(profile["id"].as_str().unwrap())
        {
            return Err(bad("Invalid profile ID/name"));
        }
        let origins = profile["origins"]
            .as_array()
            .filter(|v| v.len() <= 20)
            .ok_or_else(|| bad("Up to 20 origins"))?;
        for origin in origins {
            let origin = origin.as_str().ok_or_else(|| bad("Invalid origin"))?;
            let url = reqwest::Url::parse(origin).map_err(bad)?;
            if !["http", "https"].contains(&url.scheme())
                || !url.username().is_empty()
                || url.password().is_some()
                || url.origin().ascii_serialization() != origin
            {
                return Err(bad("Expected an HTTP(S) origin"));
            }
        }
        crate::replay::validate_variables(&profile["variables"])?;
        if !profile["variables"].is_object() || profile["variables"].to_string().len() > 256_000 {
            return Err(bad("Invalid profile variables"));
        }
        let headers = profile["headers"]
            .as_object()
            .filter(|h| h.len() <= 50)
            .ok_or_else(|| bad("Up to 50 profile headers"))?;
        let mut seen = std::collections::HashSet::new();
        for (name, value) in headers {
            let lower = name.to_lowercase();
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(bad)?;
            let value = value
                .as_str()
                .filter(|v| v.len() <= 8192)
                .ok_or_else(|| bad("Invalid profile header"))?;
            reqwest::header::HeaderValue::from_str(value).map_err(bad)?;
            if !seen.insert(lower.clone())
                || [
                    "cookie",
                    "host",
                    "content-length",
                    "connection",
                    "transfer-encoding",
                ]
                .contains(&lower.as_str())
                || lower.starts_with("proxy-")
            {
                return Err(bad("Unsupported or duplicate profile header"));
            }
        }
        let cookies = profile["cookies"]
            .as_array()
            .filter(|c| c.len() <= 100)
            .ok_or_else(|| bad("Up to 100 cookies"))?;
        for cookie in cookies {
            if !text(&cookie["name"], 4096)
                || cookie["value"].as_str().is_none_or(|v| {
                    v.len() > 4096
                        || v.chars()
                            .any(|c| c.is_ascii_control() || c == ' ' || c == ';' || c == ',')
                })
                || !text(&cookie["domain"], 253)
                || cookie["path"].as_str().is_none_or(|s| {
                    !s.starts_with('/') || s.len() > 4096 || s.contains(['\r', '\n', '\0'])
                })
                || !cookie["hostOnly"].is_boolean()
                || !cookie["secure"].is_boolean()
                || !cookie["httpOnly"].is_boolean()
                || !cookie["created"].is_number()
                || (!cookie["expires"].is_null() && !cookie["expires"].is_number())
                || cookie["sameSite"].as_str().is_none()
            {
                return Err(bad("Invalid cookie"));
            }
        }
    }
    if !doc["active"].is_null() && !doc["active"].as_str().is_some_and(|id| ids.contains(id)) {
        return Err(bad("Selected profile does not exist"));
    }
    Ok(())
}
pub async fn get_profiles(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
) -> Result<Json<Value>, Error> {
    let (revision, data) = storage
        .get_auth_profiles(&workspace)
        .map_err(storage_error)?;
    Ok(Json(
        json!({"revision":revision,"document":serde_json::from_str::<Value>(&data).map_err(bad)?}),
    ))
}
#[derive(Deserialize)]
pub struct Update {
    revision: u64,
    document: Value,
}
pub async fn put_profiles(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
    Json(update): Json<Update>,
) -> Result<Json<Value>, Error> {
    validate_profiles(&update.document)?;
    let revision=storage.put_auth_profiles(&workspace,update.revision,&update.document.to_string()).map_err(storage_error)?
        .ok_or_else(||(StatusCode::CONFLICT,Json(json!({"error":"Profiles changed in another browser. Reload profiles before saving."}))))?;
    Ok(Json(json!({"revision":revision})))
}
pub async fn save_matrix(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
    Json(run): Json<Value>,
) -> Result<Json<Value>, Error> {
    if id.len() > 100
        || id.is_empty()
        || run["id"].as_str() != Some(&id)
        || run.to_string().len() > 12_000_000
        || !matches!(
            run["status"].as_str(),
            Some("completed" | "stopped" | "failed")
        )
        || !text(&run["startedAt"], 100)
        || run["results"].as_array().is_none_or(|r| r.len() > 200)
    {
        return Err(bad("Invalid matrix run or exceeds 12 MB / 200 cells"));
    }
    for cell in run["results"].as_array().unwrap() {
        if let Some(request) = cell.get("request") {
            crate::replay::validate_request(request)?;
        }
        if let Some(response) = cell.get("response") {
            if !response["status"].is_number()
                || !response["responseHeaders"].is_object()
                || !response["responseBody"].is_string()
            {
                return Err(bad("Invalid response"));
            }
        }
    }
    storage
        .put_matrix_run(&workspace, &id, &run)
        .map_err(storage_error)?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
pub struct Page {
    offset: Option<usize>,
}
pub async fn list_matrix(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
    Query(page): Query<Page>,
) -> Result<Json<Value>, Error> {
    storage
        .get_auth_profiles(&workspace)
        .map_err(storage_error)?;
    let data = storage
        .list_matrix_runs(&workspace, page.offset.unwrap_or(0))
        .map_err(bad)?;
    Ok(Json(json!({"has_more":data.len()==50,"data":data})))
}
pub async fn get_matrix(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    let run = storage
        .get_matrix_run(&workspace, &id)
        .map_err(bad)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"Matrix run not found"})),
            )
        })?;
    Ok(Json(run))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document() -> Value {
        json!({"active":"a","profiles":[{"id":"a","name":"User A","origins":["https://example.com"],"variables":{"token":"a"},"headers":{"Authorization":"Bearer {{token}}"},"cookies":[]}]})
    }
    #[tokio::test]
    async fn profiles_are_versioned_workspace_scoped_and_survive_reopen() {
        let path = std::env::temp_dir().join(format!(
            "httpdebugger-profiles-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let workspace;
        {
            let storage = TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
            workspace = storage.create_workspace("Profiles").unwrap().id;
            let saved = put_profiles(
                State(storage.clone()),
                Path(workspace.clone()),
                Json(Update {
                    revision: 0,
                    document: document(),
                }),
            )
            .await
            .unwrap()
            .0;
            assert_eq!(saved["revision"], 1);
            assert_eq!(
                get_profiles(State(storage.clone()), Path("default".into()))
                    .await
                    .unwrap()
                    .0["document"]["profiles"],
                json!([])
            );
            assert_eq!(
                put_profiles(
                    State(storage.clone()),
                    Path(workspace.clone()),
                    Json(Update {
                        revision: 0,
                        document: document()
                    })
                )
                .await
                .unwrap_err()
                .0,
                StatusCode::CONFLICT
            );
            assert_eq!(
                get_profiles(State(storage), Path(workspace.clone()))
                    .await
                    .unwrap()
                    .0["document"],
                document()
            );
        }
        {
            let storage = TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
            assert_eq!(
                get_profiles(State(storage.clone()), Path(workspace.clone()))
                    .await
                    .unwrap()
                    .0["document"],
                document()
            );
            storage.delete_workspace(&workspace).unwrap();
            assert_eq!(
                get_profiles(State(storage), Path(workspace))
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::NOT_FOUND
            );
        }
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn validates_scope_and_credentials() {
        assert!(validate_profiles(&document()).is_ok());
        let mut bad_doc = document();
        bad_doc["profiles"][0]["origins"] = json!(["https://example.com/path"]);
        assert!(validate_profiles(&bad_doc).is_err());
        let mut bad_doc = document();
        bad_doc["profiles"][0]["headers"] = json!({"Cookie":"a=1"});
        assert!(validate_profiles(&bad_doc).is_err());
        let mut bad_doc = document();
        bad_doc["profiles"][0]["headers"] = json!({"Authorization":"Bearer a\r\nInjected: yes"});
        assert!(validate_profiles(&bad_doc).is_err());
        let mut bad_doc = document();
        bad_doc["profiles"][0]["variables"] = json!({"bad key":"value"});
        assert!(validate_profiles(&bad_doc).is_err());
    }
    #[tokio::test]
    async fn matrix_evidence_is_immutable_scoped_and_deleted_with_workspace() {
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let workspace = storage.create_workspace("Matrix").unwrap().id;
        let run = json!({"id":"run","startedAt":"2026-10-16T00:00:00Z","status":"completed","results":[]});
        save_matrix(
            State(storage.clone()),
            Path((workspace.clone(), "run".into())),
            Json(run.clone()),
        )
        .await
        .unwrap();
        save_matrix(
            State(storage.clone()),
            Path((workspace.clone(), "run".into())),
            Json(run.clone()),
        )
        .await
        .unwrap();
        assert!(get_matrix(
            State(storage.clone()),
            Path(("default".into(), "run".into()))
        )
        .await
        .is_err());
        let mut changed = run.clone();
        changed["status"] = json!("stopped");
        assert!(save_matrix(
            State(storage.clone()),
            Path((workspace.clone(), "run".into())),
            Json(changed)
        )
        .await
        .is_err());
        let page = list_matrix(
            State(storage.clone()),
            Path(workspace.clone()),
            Query(Page { offset: None }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(page["data"][0]["cells"], 0);
        assert!(page["data"][0].get("results").is_none());
        assert_eq!(
            get_matrix(
                State(storage.clone()),
                Path((workspace.clone(), "run".into()))
            )
            .await
            .unwrap()
            .0,
            run
        );
        storage.delete_workspace(&workspace).unwrap();
        assert!(get_matrix(State(storage), Path((workspace, "run".into())))
            .await
            .is_err());
    }
}
