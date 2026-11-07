//! Settings → trusted upstream CAs: servers with a private CA are trusted through that CA instead
//! of turning certificate verification off.
use axum::{extract::Path, http::StatusCode, Json};
use proxy_core::trust::{self, TrustError, TrustStatus, TrustedCa};
use serde::Deserialize;
use serde_json::{json, Value};

type Error = (StatusCode, Json<Value>);

fn error(e: TrustError) -> Error {
    let status = match &e {
        TrustError::Invalid(_) => StatusCode::BAD_REQUEST,
        TrustError::Exists => StatusCode::CONFLICT,
        TrustError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        TrustError::Other(err) => {
            tracing::error!("trusted CA error: {err:#}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "could not update trusted CAs" })));
        }
    };
    (status, Json(json!({ "error": e.to_string() })))
}

/// `GET /api/settings/upstream-trust`
pub async fn get() -> Json<TrustStatus> {
    Json(trust::status())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewCa {
    name: String,
    pem: String,
}

/// `POST /api/settings/upstream-trust/cas` — trust the certificate(s) in a PEM file.
pub async fn add(Json(body): Json<NewCa>) -> Result<(StatusCode, Json<Vec<TrustedCa>>), Error> {
    trust::add_pem(&body.name, body.pem.as_bytes()).map(|added| (StatusCode::CREATED, Json(added))).map_err(error)
}

/// `DELETE /api/settings/upstream-trust/cas/:name`
pub async fn remove(Path(name): Path<String>) -> Result<StatusCode, Error> {
    match trust::remove(&name).map_err(error)? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err((StatusCode::NOT_FOUND, Json(json!({ "error": "trusted CA not found (CAs from SLURP_UPSTREAM_CA_FILE cannot be removed here)" })))),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct System {
    system: bool,
}

/// `PUT /api/settings/upstream-trust` — also trust the operating system's certificate store.
pub async fn set_system(Json(body): Json<System>) -> Result<Json<TrustStatus>, Error> {
    if !body.system && trust::status().system_locked {
        return Err((StatusCode::CONFLICT, Json(json!({ "error": "SLURP_UPSTREAM_TRUST_SYSTEM is set and keeps the system store trusted" }))));
    }
    trust::set_system(body.system).map_err(error)?;
    Ok(Json(trust::status()))
}
