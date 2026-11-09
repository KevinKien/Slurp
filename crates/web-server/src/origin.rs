//! Exact UI origin and management Host validation. Non-browser clients still need API credentials.
use axum::{extract::{Request,State},http::{header,HeaderValue,StatusCode},middleware::Next,response::{IntoResponse,Response}};
use std::{net::SocketAddr,sync::Arc};
use tower_http::cors::AllowOrigin;
#[derive(Clone)] pub struct AllowedOrigins { origins:Arc<Vec<String>>, hosts:Arc<Vec<String>> }
impl Default for AllowedOrigins { fn default()->Self {Self::new(vec![])} }
impl AllowedOrigins {
    pub fn new(extra:Vec<String>)->Self {Self::at("127.0.0.1:5174".parse().unwrap(),extra)}
    pub fn at(address:SocketAddr,extra:Vec<String>)->Self {
        let mut local=vec![format!("http://{address}")];
        if address.ip().is_loopback() || address.ip().is_unspecified() {
            local=vec![format!("http://localhost:{}",address.port()),format!("http://127.0.0.1:{}",address.port()),format!("http://[::1]:{}",address.port())];
        }
        let hosts=local.iter().filter_map(|o|o.strip_prefix("http://").map(str::to_owned)).collect();
        let mut origins=local;origins.extend(extra.into_iter().filter(|o|reqwest::Url::parse(o).is_ok_and(|url|["http","https"].contains(&url.scheme())&&url.username().is_empty()&&url.password().is_none()&&url.origin().ascii_serialization()==*o)));
        Self{origins:Arc::new(origins),hosts:Arc::new(hosts)}
    }
    pub fn from_env(address:SocketAddr)->Self {
        let raw=std::env::var("SLURP_ALLOWED_ORIGINS").or_else(|_|std::env::var("HTTPDEBUGGER_ALLOWED_ORIGINS")).unwrap_or_default();
        let allowed=Self::at(address,raw.split(',').map(|s|s.trim().trim_end_matches('/').to_owned()).filter(|s|!s.is_empty()).collect());
        match std::env::var("SLURP_PUBLIC_URL") { Ok(url) if !url.trim().is_empty() => allowed.with_public_url(url.trim()), _ => allowed }
    }
    /// Also accept the address clients and browsers use to reach a server behind a reverse proxy.
    pub fn with_public_url(self,url:&str)->Self {
        let Ok(url)=reqwest::Url::parse(url) else {return self};
        let Some(host)=url.host_str().filter(|_|["http","https"].contains(&url.scheme())&&url.username().is_empty()&&url.password().is_none()) else {return self};
        let authority=match url.port() { Some(port)=>format!("{host}:{port}"), None=>host.to_owned() };
        let (mut origins,mut hosts)=((*self.origins).clone(),(*self.hosts).clone());
        origins.push(url.origin().ascii_serialization());
        hosts.push(authority.to_ascii_lowercase());
        // Cloudflare and some reverse proxies preserve the default port in Host.
        if url.port().is_none() {
            let default_port = if url.scheme() == "https" { 443 } else { 80 };
            hosts.push(format!("{}:{default_port}", host.to_ascii_lowercase()));
        }
        Self{origins:Arc::new(origins),hosts:Arc::new(hosts)}
    }
    pub fn is_allowed(&self,origin:&str)->bool {self.origins.iter().any(|v|v==origin)}
    pub fn cors_predicate(&self)->AllowOrigin {let this=self.clone();AllowOrigin::predicate(move|origin:&HeaderValue,_|origin.to_str().is_ok_and(|o|this.is_allowed(o)))}
}
fn normalise_host(value:&str)->String { value.trim().trim_end_matches('.').to_ascii_lowercase() }
pub async fn guard(State(allowed):State<AllowedOrigins>,request:Request,next:Next)->Response {
    let host=request.headers().get(header::HOST).and_then(|v|v.to_str().ok()).map(normalise_host);
    // Cloudflare Tunnel can forward the public name in X-Forwarded-Host when an
    // origin Host is supplied by the tunnel. Accept only the explicitly allowed host.
    let forwarded=request.headers().get("x-forwarded-host").and_then(|v|v.to_str().ok())
        .and_then(|v|v.split(',').next()).map(normalise_host);
    let allowed_host=host.as_deref().filter(|h|allowed.hosts.iter().any(|v|v.eq_ignore_ascii_case(h)))
        .or_else(|| forwarded.as_deref().filter(|h|allowed.hosts.iter().any(|v|v.eq_ignore_ascii_case(h))));
    if allowed_host.is_none() {
        tracing::warn!(host=?host, x_forwarded_host=?forwarded, "rejected management request host");
        return (StatusCode::FORBIDDEN,"host not allowed").into_response();
    }
    if let Some(origin)=request.headers().get(header::ORIGIN) {
        if !origin.to_str().is_ok_and(|o|allowed.is_allowed(o)){return (StatusCode::FORBIDDEN,"origin not allowed").into_response();}
    }
    next.run(request).await
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn public_url_adds_its_origin_and_host() {
        let allowed=AllowedOrigins::default().with_public_url("https://slurp.example.com");
        assert!(allowed.is_allowed("https://slurp.example.com"));assert!(allowed.hosts.iter().any(|h|h=="slurp.example.com"));
        assert!(!allowed.is_allowed("http://slurp.example.com"));
        let with_port=AllowedOrigins::default().with_public_url("https://slurp.example.com:8443");assert!(with_port.hosts.iter().any(|h|h=="slurp.example.com:8443"));
        let ignored=AllowedOrigins::default().with_public_url("ftp://x");assert!(!ignored.is_allowed("ftp://x"));
    }
    #[test] fn permits_only_exact_ui_origins_and_explicit_development_origins() {
        let allowed=AllowedOrigins::default();assert!(allowed.is_allowed("http://127.0.0.1:5174"));assert!(allowed.is_allowed("http://localhost:5174"));
        for origin in ["http://localhost:45678","http://localhost:5173","https://evil.example","null","http://localhost:5174/path","http://localhost.evil:5174"] {assert!(!allowed.is_allowed(origin),"{origin}");}
        let allowed=AllowedOrigins::new(vec!["http://localhost:5173".into()]);assert!(allowed.is_allowed("http://localhost:5173"));assert!(!allowed.hosts.contains(&"localhost:5173".into()));
    }
}
