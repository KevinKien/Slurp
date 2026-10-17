//! Serves the existing UI and docs without a Node runtime. API misses never return HTML.
use axum::{
    http::{header, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));
fn asset_path(path: &str) -> Option<&str> {
    if path.contains('\\') || path.contains('%') || path.split('/').any(|s| s == "." || s == "..") {
        return None;
    }
    let path = path.trim_start_matches('/');
    if [
        "",
        "dashboard",
        "intercept",
        "replay",
        "intruder",
        "flows",
        "profiles",
        "matrix",
        "workspaces",
        "scope",
        "tools",
        "mcp",
        "settings",
    ]
    .contains(&path.trim_end_matches('/'))
    {
        Some("index.html")
    } else if path.starts_with("assets/")
        || path.starts_with("docs/")
        || ["favicon.svg", "favicon.ico", "robots.txt"].contains(&path)
    {
        Some(path)
    } else {
        None
    }
}
fn mime(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "json" | "map" => "application/json",
        "png" => "image/png",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
pub async fn serve(method: Method, uri: Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let Some(path) = asset_path(uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let bytes = if cfg!(feature = "embedded-ui") {
        ASSETS
            .iter()
            .find(|(name, _)| *name == path)
            .map(|(_, bytes)| bytes.to_vec())
    } else {
        let root = std::env::var_os("SLURP_UI_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../curl-cozy/dist-rust")
            });
        tokio::fs::read(root.join(path)).await.ok()
    };
    match bytes {
        Some(bytes) => {
            let length = bytes.len();
            (
                [
                    (header::CONTENT_TYPE, mime(path).to_string()),
                    (header::CACHE_CONTROL, "no-cache".into()),
                    (header::CONTENT_LENGTH, length.to_string()),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff".into()),
                ],
                if method == Method::HEAD {
                    Vec::new()
                } else {
                    bytes
                },
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fallback_only_serves_known_ui_paths() {
        for path in ["/dashboard", "/replay/", "/"] {
            assert_eq!(asset_path(path), Some("index.html"));
        }
        for path in [
            "/api/missing",
            "/assets/../ca.key",
            "/assets/%2e%2e/ca.key",
            "/.slurp/ca.key",
        ] {
            assert_eq!(asset_path(path), None);
        }
        assert_eq!(asset_path("/docs/scan.html"), Some("docs/scan.html"));
        assert_eq!(mime("engine.wasm"), "application/wasm");
    }
    #[cfg(feature = "embedded-ui")]
    #[tokio::test]
    async fn embedded_routes_docs_wasm_and_head_work_without_disk_assets() {
        for path in ["/dashboard", "/replay", "/docs/scan.html", "/favicon.svg"] {
            let response = serve(Method::GET, path.parse().unwrap()).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let bytes = axum::body::to_bytes(response.into_body(), 8_000_000).await.unwrap();
            assert!(!bytes.is_empty());
        }
        let wasm = ASSETS.iter().find(|(path, _)| path.ends_with(".wasm")).unwrap();
        let response = serve(Method::GET, format!("/{}", wasm.0).parse().unwrap()).await;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/wasm");
        let head = serve(Method::HEAD, "/dashboard".parse().unwrap()).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert!(axum::body::to_bytes(head.into_body(), 100).await.unwrap().is_empty());
        assert_eq!(serve(Method::GET, "/api/unknown".parse().unwrap()).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(serve(Method::POST, "/dashboard".parse().unwrap()).await.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

}
