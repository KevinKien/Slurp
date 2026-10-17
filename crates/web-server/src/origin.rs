/// Browser origin checks for the local API.
///
/// The API exposes captured traffic and, with intercept, live requests holding tokens and
/// cookies. Without a check, any website open in the user's browser could read it with
/// `fetch("http://127.0.0.1:5174/...")` or a WebSocket. Browsers always send `Origin` on
/// cross-origin requests and WebSocket handshakes, so rejecting foreign origins closes that
/// off. Requests without an `Origin` (curl, the MCP server, scripts) are unaffected.
///
/// Allowed: pages served from `localhost`, `127.0.0.1` or `[::1]` on any port, plus any exact
/// origins listed in `SLURP_ALLOWED_ORIGINS` (legacy `HTTPDEBUGGER_ALLOWED_ORIGINS` is also accepted) (comma separated).
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use tower_http::cors::AllowOrigin;

#[derive(Clone, Default)]
pub struct AllowedOrigins {
    extra: Arc<Vec<String>>,
}

impl AllowedOrigins {
    pub fn new(extra: Vec<String>) -> Self {
        Self { extra: Arc::new(extra) }
    }

    pub fn from_env() -> Self {
        let raw = std::env::var("SLURP_ALLOWED_ORIGINS")
            .or_else(|_| std::env::var("HTTPDEBUGGER_ALLOWED_ORIGINS"))
            .unwrap_or_default();
        Self::new(
            raw.split(',')
                .map(|o| o.trim().trim_end_matches('/').to_string())
                .filter(|o| !o.is_empty())
                .collect(),
        )
    }

    pub fn is_allowed(&self, origin: &str) -> bool {
        is_loopback_origin(origin) || self.extra.iter().any(|o| o == origin)
    }

    /// CORS: only echo an allow-origin header for permitted origins.
    pub fn cors_predicate(&self) -> AllowOrigin {
        let this = self.clone();
        AllowOrigin::predicate(move |origin: &HeaderValue, _| origin.to_str().is_ok_and(|o| this.is_allowed(o)))
    }
}

/// `http(s)://localhost|127.0.0.1|[::1][:port]` and nothing else (no paths, userinfo, or look-alike hosts).
fn is_loopback_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")) else {
        return false;
    };
    let (host, port) = match rest.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((host, after)) => (format!("[{host}]"), after.strip_prefix(':')),
            None => return false,
        },
        None => match rest.split_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (rest.to_string(), None),
        },
    };
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
    port_ok && matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
}

/// Reject requests whose `Origin` is not allowed.
pub async fn guard(State(allowed): State<AllowedOrigins>, req: Request, next: Next) -> Response {
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        if !origin.to_str().is_ok_and(|o| allowed.is_allowed(o)) {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_local_pages() {
        let a = AllowedOrigins::default();
        for o in [
            "http://localhost",
            "http://localhost:5173",
            "http://127.0.0.1:5174",
            "https://localhost:3000",
            "http://[::1]:5173",
        ] {
            assert!(a.is_allowed(o), "{o} should be allowed");
        }
    }

    #[test]
    fn rejects_everything_else() {
        let a = AllowedOrigins::default();
        for o in [
            "null",
            "",
            "https://evil.example",
            "http://localhost.evil.example",
            "http://evil.example/localhost",
            "http://127.0.0.1.evil.example",
            "http://localhost@evil.example",
            "http://localhost:80/path",
            "http://localhost:abc",
            "http://localhost:",
            "ftp://localhost",
            "http://[::1",
            "http://0.0.0.0:5174",
        ] {
            assert!(!a.is_allowed(o), "{o:?} should be rejected");
        }
    }

    #[test]
    fn extra_origins_must_match_exactly() {
        let a = AllowedOrigins::new(vec!["https://dev.mycorp.test".into()]);
        assert!(a.is_allowed("https://dev.mycorp.test"));
        assert!(!a.is_allowed("https://dev.mycorp.test.evil.example"));
        assert!(!a.is_allowed("http://dev.mycorp.test"));
    }
}
