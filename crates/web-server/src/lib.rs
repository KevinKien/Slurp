/// Web server providing REST API and WebSocket for the curl-cozy frontend.
pub mod api;
pub mod access;
pub mod certificate;
pub mod intruder;
pub mod scan;
mod scan_browser;
mod scan_protocol;
mod scan_dependencies;
mod oast;
pub mod auto_audit;
mod forbidden_audit;
mod crlf_audit;
mod host_audit;
mod js_audit;
pub mod security;
pub mod proxy_settings;
pub mod flows;
pub mod origin;
pub mod replay;
pub mod http_sender;
mod http_target;
pub mod ui;
pub mod ws;
pub mod websocket;
pub mod websocket_replay;

use anyhow::Result;
use axum::routing::{get, post, put};
use axum::{Extension, Router};
use proxy_core::{Intercept, TrafficStorage};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

/// Start the web server on the given address.
///
/// This serves:
/// - REST API at `/api/traffic`, `/api/stats`, `/api/workspaces`, `/api/session`, `/api/intercept`
/// - WebSocket at `/api/ws`
///
/// Browsers may only reach it from pages served on this machine (see `origin`).
pub async fn start(addr: SocketAddr, storage: Arc<TrafficStorage>, intercept: Arc<Intercept>, proxy_control: proxy_core::ProxyControl, certificate: certificate::PublicCaCertificate) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let home=std::env::var_os(if cfg!(windows){"USERPROFILE"}else{"HOME"}).ok_or_else(||anyhow::anyhow!("Home directory not set"))?;
    let access=access::ApiAccess::load(&std::path::PathBuf::from(home).join(".slurp"))?;
    serve(listener, storage, intercept, proxy_control, certificate, access).await
}

/// Serve an already-bound listener so the CLI can fail before reporting readiness.
pub async fn serve(listener: tokio::net::TcpListener, storage: Arc<TrafficStorage>, intercept: Arc<Intercept>, proxy_control: proxy_core::ProxyControl, certificate: certificate::PublicCaCertificate, access: access::ApiAccess) -> Result<()> {
    let (audit, _audit_runtime) = auto_audit::start(storage.clone(), intercept.clone());
    let (oast, _oast_runtime) = oast::start().await;
    let origins = origin::AllowedOrigins::from_env(listener.local_addr()?);
    let cors = CorsLayer::new()
        .allow_origin(origins.cors_predicate())
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/scan/browser", post(scan_browser::render))
        .route("/api/scan/protocol", post(scan_protocol::probe))
        .route("/api/scan/host-header", post(host_audit::probe))
        .route("/api/scan/dependencies", post(scan_dependencies::lookup))
        .route("/api/scan/oast", get(oast::status))
        .route("/api/scan/oast/probes", post(oast::issue))
        .route("/api/scan/oast/keys", post(oast::issue_key))
        .route("/api/scan/oast/probes/:id", get(oast::poll))
        .route("/api/scan/automatic", get(auto_audit::status).put(auto_audit::settings))
        .route("/api/ca.crt", get(certificate::download))
        .route("/api/websockets", get(websocket::connections))
        .route("/api/websockets/:id/frames", get(websocket::frames))
        .route("/api/replay/websocket", get(websocket_replay::handler))
        .route("/api/replay/send", post(http_sender::send))
        .route("/api/settings/proxy/interfaces", get(proxy_settings::interfaces))
        .route("/api/settings/proxy", get(proxy_settings::get).put(proxy_settings::update))
        // REST endpoints
        .route("/api/traffic", get(api::list_traffic).delete(api::clear_traffic).post(api::save_traffic))
        .route("/api/history", get(api::history_page))
        .route("/api/traffic/export", get(api::export_traffic))
        .route("/api/traffic/:id", get(api::get_traffic).delete(api::delete_traffic))
        .route("/api/traffic/:id/annotation", axum::routing::patch(api::annotate_traffic))
        .route("/api/stats", get(api::get_stats))
        .route("/api/info", get(api::get_info))
        .route("/api/workspaces/:id/profiles", get(security::get_profiles).put(security::put_profiles))
        .route("/api/workspaces/:id/matrix-runs", get(security::list_matrix))
        .route("/api/workspaces/:id/matrix-runs/:run", get(security::get_matrix).put(security::save_matrix))
        .route("/api/workspaces/:id/intruder", get(intruder::get_document).put(intruder::put_document))
        .route("/api/workspaces/:id/intruder-sources", get(intruder::list_sources).post(intruder::create_source))
        .route("/api/workspaces/:id/intruder-sources/:source", get(intruder::payload_page).delete(intruder::delete_source))
        .route("/api/workspaces/:id/intruder-sources/:source/append", post(intruder::append_source))
        .route("/api/workspaces/:id/intruder-sources/:source/finalize", post(intruder::finalize_source))
        .route("/api/workspaces/:id/intruder-runs", get(intruder::list_runs))
        .route("/api/workspaces/:id/intruder-runs/:run", get(intruder::get_run).put(intruder::put_run).delete(intruder::delete_run))
        .route("/api/workspaces/:id/intruder-runs/:run/results", get(intruder::list_results))
        .route("/api/workspaces/:id/intruder-runs/:run/results/:index", get(intruder::get_result).put(intruder::put_result))
        .route("/api/workspaces/:id/scan-findings",get(scan::list_findings))
        .route("/api/workspaces/:id/scan-runs",get(scan::list_runs))
        .route("/api/workspaces/:id/scan-runs/:run",get(scan::get_run).put(scan::put_run).delete(scan::delete_run))
        // Workspaces
        .route("/api/workspaces", get(api::list_workspaces).post(api::create_workspace))
        .route(
            "/api/workspaces/:id",
            axum::routing::patch(api::rename_workspace).delete(api::delete_workspace),
        )
        .route("/api/workspaces/:id/activate", post(api::activate_workspace))
        .route("/api/workspaces/:id/replay", get(api::get_replay_tabs).put(api::put_replay_tabs))
        .route("/api/workspaces/:id/replay/tabs", post(replay::create))
        .route("/api/workspaces/:id/replay/tabs/:tab", axum::routing::patch(replay::edit))
        .route("/api/workspaces/:id/replay/tabs/:tab/send", post(replay::send))
        .route("/api/workspaces/:id/replay/tabs/:tab/runs", get(replay::list_runs).post(replay::save_run))
        .route("/api/workspaces/:id/replay/tabs/:tab/runs/:run", get(replay::get_run))
        .route("/api/workspaces/:id/flows", get(flows::get_document).put(flows::put_document))
        .route("/api/workspaces/:id/flow-runs", get(flows::list_runs))
        .route("/api/workspaces/:id/flow-runs/:run", get(flows::get_run).put(flows::put_run))
        // Session: has a workspace been chosen since the tool started?
        .route("/api/session", get(api::get_session))
        .route("/api/session/temporary", post(api::use_temporary_session))
        // Intercept
        .route("/api/intercept", get(api::get_intercept))
        .route("/api/intercept/settings", put(api::update_intercept_settings))
        .route("/api/intercept/scope", put(api::update_scope))
        .route("/api/intercept/forward-all", post(api::forward_all_held))
        .route("/api/intercept/:id/forward", post(api::forward_held))
        .route("/api/intercept/:id/drop", post(api::drop_held))
        // WebSocket
        .route("/api/ws", get(ws::ws_handler))
        .fallback(ui::serve)
        .layer(axum::middleware::from_fn_with_state(access, access::guard))
        // Replay saves carry whole response bodies (up to 2 MB, more once JSON-escaped)
        .layer(axum::extract::DefaultBodyLimit::max(32 * 1024 * 1024))
        // CORS (headers for allowed origins), then the guard that rejects the rest
        .layer(cors)
        .layer(axum::middleware::from_fn_with_state(origins, origin::guard))
        // Shared state
        .layer(Extension(intercept))
        .layer(Extension(proxy_control))
        .layer(Extension(certificate))
        .layer(Extension(audit))
        .layer(Extension(oast))
        .with_state(storage);

    info!("🌐 Web server listening on http://{}", listener.local_addr()?);

    axum::serve(listener, app).await?;

    Ok(())
}
