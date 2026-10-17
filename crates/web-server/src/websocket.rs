use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use proxy_core::{
    websocket::{Connection, Frame},
    TrafficStorage,
};
use serde::Deserialize;
use std::sync::Arc;
#[derive(Deserialize)]
pub struct Params {
    workspace: Option<String>,
    before: Option<String>,
    after: Option<i64>,
    limit: Option<usize>,
}
pub async fn connections(
    State(s): State<Arc<TrafficStorage>>,
    Query(p): Query<Params>,
) -> Result<Json<Vec<Connection>>, StatusCode> {
    s.websocket_connections(
        p.workspace.as_deref(),
        p.before.as_deref(),
        p.limit.unwrap_or(100),
    )
    .map(Json)
    .map_err(|e| {
        tracing::error!("{e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}
pub async fn frames(
    State(s): State<Arc<TrafficStorage>>,
    Path(id): Path<String>,
    Query(p): Query<Params>,
) -> Result<Json<Vec<Frame>>, StatusCode> {
    s.websocket_frames(
        p.workspace.as_deref(),
        &id,
        p.after.unwrap_or(0),
        p.limit.unwrap_or(100),
    )
    .map(Json)
    .map_err(|e| {
        tracing::error!("{e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}
