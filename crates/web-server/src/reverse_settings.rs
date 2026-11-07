//! Settings → reverse proxies: listeners that forward to one fixed upstream.
use axum::{extract::Path, http::StatusCode, Json};
use proxy_core::reverse::{self, NewRule, ReverseError, RuleStatus};
use serde::Deserialize;
use serde_json::{json, Value};

type Error = (StatusCode, Json<Value>);

fn error(e: ReverseError) -> Error {
    let status = match &e {
        ReverseError::Invalid(_) => StatusCode::BAD_REQUEST,
        ReverseError::NotFound => StatusCode::NOT_FOUND,
        ReverseError::Conflict(_) => StatusCode::CONFLICT,
        ReverseError::Other(err) => {
            tracing::error!("reverse proxy error: {err:#}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "could not update reverse proxies" })));
        }
    };
    (status, Json(json!({ "error": e.to_string() })))
}

fn manager() -> Result<std::sync::Arc<reverse::ReverseProxies>, Error> {
    reverse::installed().ok_or((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "this Slurp instance runs no proxy, so it has no reverse proxies" }))))
}

/// `GET /api/settings/reverse-proxies` — `available` is false when this instance runs no proxy.
pub async fn list() -> Json<Value> {
    match reverse::installed() {
        Some(manager) => Json(json!({ "available": true, "rules": manager.list().await })),
        None => Json(json!({ "available": false, "rules": [] })),
    }
}

/// `POST /api/settings/reverse-proxies`
pub async fn add(Json(body): Json<NewRule>) -> Result<(StatusCode, Json<RuleStatus>), Error> {
    manager()?.add(body).await.map(|rule| (StatusCode::CREATED, Json(rule))).map_err(error)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enabled {
    enabled: bool,
}

/// `PATCH /api/settings/reverse-proxies/:id` — start or stop a saved reverse proxy.
pub async fn set_enabled(Path(id): Path<String>, Json(body): Json<Enabled>) -> Result<Json<RuleStatus>, Error> {
    manager()?.set_enabled(&id, body.enabled).await.map(Json).map_err(error)
}

/// `DELETE /api/settings/reverse-proxies/:id`
pub async fn remove(Path(id): Path<String>) -> Result<StatusCode, Error> {
    manager()?.remove(&id).await.map(|_| StatusCode::NO_CONTENT).map_err(error)
}
