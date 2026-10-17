/// HTTP/HTTPS proxy server.
///
/// Handles two types of requests:
/// 1. Plain HTTP — forward, capture traffic
/// 2. HTTPS CONNECT — establish TLS tunnel with MITM, decrypt + capture
///
/// Both end up in `proxy_request`, which can hold the request and the response in the
/// interceptor so a user can review or edit them before they continue.
use crate::ca::CertificateAuthority;
use crate::intercept::{HoldContext, Intercept, RequestParts, ResponseParts};
use crate::storage::{pairs_to_json, TrafficEntry, TrafficStorage};
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

/// Configuration for the proxy server.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to bind the proxy to
    pub listen_addr: SocketAddr,
    /// Maximum body size to capture (bytes). Bodies are always forwarded in full;
    /// storage truncates what it records.
    pub max_body_size: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8888".parse().unwrap(),
            max_body_size: 10 * 1024 * 1024, // 10 MB
        }
    }
}

/// What every connection handler needs.
#[derive(Clone)]
struct Shared {
    storage: Arc<TrafficStorage>,
    intercept: Arc<Intercept>,
    upstream_tls: Arc<rustls::ClientConfig>,
}

/// The main proxy server.
pub struct ProxyServer {
    config: ProxyConfig,
    ca: Arc<CertificateAuthority>,
    shared: Shared,
}

impl ProxyServer {
    pub fn new(
        config: ProxyConfig,
        ca: Arc<CertificateAuthority>,
        storage: Arc<TrafficStorage>,
        intercept: Arc<Intercept>,
    ) -> Self {
        Self {
            config,
            ca,
            shared: Shared { storage, intercept, upstream_tls: client_tls_config() },
        }
    }

    /// Switch listeners without cancelling existing HTTP connections or CONNECT tunnels.
    pub async fn run_managed(&self, mut managed: crate::ProxyListener) -> Result<()> {
        loop {
            tokio::select! {
                Some(change) = managed.changes.recv() => {
                    let result = managed.change(change.address).await;
                    let _ = change.reply.send(result);
                }
                accepted = async {
                    match managed.listener.as_ref() {
                        Some(listener) => listener.accept().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let (stream, client_addr) = accepted?;
                    let ca = self.ca.clone();
                    let shared = self.shared.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, ca, shared).await {
                            debug!("Connection from {} error: {}", client_addr, e);
                        }
                    });
                }
            }
        }
    }

    /// Start the proxy server. This runs forever.
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", self.config.listen_addr))?;

        info!("🚀 Proxy listening on {}", self.config.listen_addr);

        loop {
            let (stream, client_addr) = listener.accept().await?;
            let ca = self.ca.clone();
            let shared = self.shared.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, ca, shared).await {
                    debug!("Connection from {} error: {}", client_addr, e);
                }
            });
        }
    }
}

/// Handle a single client connection.
///
/// We use hyper's HTTP/1.1 server to parse the incoming request.
/// If it's CONNECT, we do MITM. Otherwise, we forward as HTTP.
async fn handle_client(stream: TcpStream, ca: Arc<CertificateAuthority>, shared: Shared) -> Result<()> {
    let io = TokioIo::new(stream);

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let ca = ca.clone();
                let shared = shared.clone();
                async move {
                    if req.method() == Method::CONNECT {
                        handle_connect(req, ca, shared).await
                    } else {
                        handle_http(req, shared).await
                    }
                }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| anyhow::anyhow!("HTTP serve error: {}", e))?;

    Ok(())
}

/// Handle a plain HTTP request (no TLS). The client sends an absolute-form URI to the proxy.
async fn handle_http(req: Request<Incoming>, shared: Shared) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let uri = req.uri().clone();
    let Some(host) = uri.host() else {
        return Ok(error_response(400, "Proxy requests must use an absolute URL"));
    };
    let https = matches!(uri.scheme_str(), Some("https" | "wss"));
    let target = Target {
        https,
        host: host.to_string(),
        port: uri.port_u16().unwrap_or(if https { 443 } else { 80 }),
    };
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();
    proxy_request(req, target, path_and_query, &shared).await
}

/// Handle HTTPS CONNECT — this is where the MITM magic happens.
///
/// Flow:
/// 1. Client sends CONNECT host:port
/// 2. We respond 200 OK
/// 3. Client upgrades the connection to TLS
/// 4. We present our fake cert (signed by our CA) to the client
/// 5. For each decrypted request we connect to the real server with TLS and relay it
async fn handle_connect(
    req: Request<Incoming>,
    ca: Arc<CertificateAuthority>,
    shared: Shared,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let connect_host = req.uri().authority().map(|a| a.to_string()).unwrap_or_default();

    // Parse host:port
    let (host, port) = parse_host_port(&connect_host);

    info!("🔒 CONNECT {}:{}", host, port);

    // We need to respond with 200 first, then upgrade the connection
    tokio::spawn(async move {
        // Wait for the upgrade
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if let Err(e) = handle_https_mitm(io, &host, port, ca, shared).await {
                    debug!("MITM error for {}:{}: {}", host, port, e);
                }
            }
            Err(e) => {
                error!("Upgrade failed for {}: {}", connect_host, e);
            }
        }
    });

    // Respond 200 to tell the client the tunnel is established
    Ok(Response::new(Full::new(Bytes::new())))
}

/// Perform MITM on an upgraded HTTPS connection.
///
/// 1. Accept TLS from client using our fake cert
/// 2. Run an HTTP server on the client side, relaying each request to the real server
async fn handle_https_mitm<IO>(
    client_io: IO,
    host: &str,
    port: u16,
    ca: Arc<CertificateAuthority>,
    shared: Shared,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 1. Get the TLS config for this domain (generate cert on the fly)
    let server_config = ca
        .get_server_config(host)
        .with_context(|| format!("Failed to get cert for {}", host))?;

    let tls_acceptor = TlsAcceptor::from(server_config);

    // 2. Do TLS handshake with the client (we are the "server")
    let client_tls = tls_acceptor
        .accept(client_io)
        .await
        .with_context(|| format!("TLS handshake failed with client for {}", host))?;

    let client_io = TokioIo::new(client_tls);

    // 3. Now serve HTTP requests from the client over the TLS connection
    let host = host.to_string();

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            client_io,
            service_fn(move |req: Request<Incoming>| {
                let target = Target { https: true, host: host.clone(), port };
                let shared = shared.clone();
                async move {
                    let path_and_query = req
                        .uri()
                        .path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or("/")
                        .to_string();
                    proxy_request(req, target, path_and_query, &shared).await
                }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| anyhow::anyhow!("HTTPS serve error: {}", e))?;

    Ok(())
}

/// Where a proxied request is going.
#[derive(Clone)]
struct Target {
    https: bool,
    host: String,
    port: u16,
}

impl Target {
    fn scheme(&self) -> &'static str {
        if self.https {
            "https"
        } else {
            "http"
        }
    }

    /// `host`, or `host:port` when the port is not the scheme default.
    fn authority(&self) -> String {
        let default = if self.https { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn url(&self, path_and_query: &str) -> String {
        format!("{}://{}{}", self.scheme(), self.authority(), path_and_query)
    }
}

/// Relay one request to its destination and return the response, capturing both.
///
/// Interception happens twice: the request can be held before it is sent upstream, and the
/// response can be held before it is returned to the client. What is recorded in history is
/// what was actually sent and received (i.e. after any edits).
async fn proxy_request(
    mut req: Request<Incoming>,
    target: Target,
    path_and_query: String,
    shared: &Shared,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start = Instant::now();

    let websocket = req.method() == Method::GET
        && req.headers().get("upgrade").and_then(|v|v.to_str().ok()).is_some_and(|v|v.eq_ignore_ascii_case("websocket"))
        && req.headers().get_all("connection").iter().filter_map(|v|v.to_str().ok()).any(|v|v.split(',').any(|t|t.trim().eq_ignore_ascii_case("upgrade")));
    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));
    let method = req.method().to_string();
    let headers = headers_to_pairs(req.headers());
    let body = match read_body(req.into_body()).await {
        Ok(b) => b,
        Err(_) => return Ok(error_response(502, "Failed to read request body")),
    };

    // ── Request interception ──
    let ctx = HoldContext {
        request: None,
        scheme: target.scheme().to_string(),
        host: target.host.clone(),
        url: target.url(&path_and_query),
        method: method.clone(),
        path: path_and_query.clone(),
    };
    let original = RequestParts { method, path: path_and_query, headers, body };
    let Some(request) = shared.intercept.hold_request(&ctx, original.clone()).await else {
        record(shared, &target, &original, None, Some("Dropped by interceptor".into()), start);
        return Ok(error_response(502, "Request dropped by interceptor"));
    };
    let ctx = HoldContext {
        request: Some(request.clone()),
        url: target.url(&request.path),
        method: request.method.clone(),
        path: request.path.clone(),
        ..ctx
    };

    // ── Send upstream ──
    let mut upstream_req = match build_upstream_request(&request, &target.authority()) {
        Ok(r) => r,
        Err(e) => {
            record(shared, &target, &request, None, Some(format!("Invalid request: {e}")), start);
            return Ok(error_response(400, &format!("Invalid request: {e}")));
        }
    };
    if websocket {
        upstream_req.headers_mut().insert("connection", HeaderValue::from_static("Upgrade"));
        upstream_req.headers_mut().insert("upgrade", HeaderValue::from_static("websocket"));
    }
    let mut upstream_res = match send_upstream(&target, upstream_req, shared.upstream_tls.clone()).await {
        Ok(r) => r,
        Err(e) => {
            record(shared, &target, &request, None, Some(e.clone()), start);
            return Ok(error_response(502, &e));
        }
    };

    if websocket && upstream_res.status() == StatusCode::SWITCHING_PROTOCOLS {
        let server_upgrade = hyper::upgrade::on(&mut upstream_res);
        let response = ResponseParts { status:101, headers:headers_to_pairs(upstream_res.headers()), body:vec![] };
        let Some(response)=shared.intercept.hold_response(&ctx,response).await else {
            record(shared,&target,&request,None,Some("WebSocket handshake dropped by interceptor".into()),start);
            return Ok(error_response(502,"WebSocket handshake dropped by interceptor"));
        };
        if response.status!=101 {
            record(shared,&target,&request,Some(&response),None,start);
            return Ok(build_client_response(response));
        }
        record(shared, &target, &request, Some(&response), None, start);
        let capture = if shared.intercept.scope().matches(&target.host) {
            let url = format!("{}://{}{}", if target.https {"wss"} else {"ws"}, target.authority(), request.path);
            match shared.storage.open_websocket(&url,&target.host) {Ok(c)=>{
                let headers:std::collections::HashMap<_,_>=request.headers.iter().cloned().collect();
                let data=serde_json::json!({"method":"GET","url":url,"headers":headers,"body":""});
                if let Err(e)=shared.storage.set_websocket_request(&c.1,&c.0,&data) {error!("WebSocket request capture: {e}");}
                Some(c)
            },Err(e)=>{error!("WebSocket capture: {e}");None}}
        } else {None};
        let mut res = build_client_response(response);
        res.headers_mut().insert("connection", HeaderValue::from_static("Upgrade"));
        res.headers_mut().insert("upgrade", HeaderValue::from_static("websocket"));
        tokio::spawn(crate::websocket::relay(client_upgrade.unwrap(), server_upgrade, shared.storage.clone(),capture,shared.intercept.clone(),HoldContext{scheme:if target.https{"wss"}else{"ws"}.into(),url:format!("{}://{}{}",if target.https{"wss"}else{"ws"},target.authority(),request.path),..ctx}));
        return Ok(res);
    }
    let (head, res_body) = upstream_res.into_parts();
    let upstream_status = head.status.as_u16();
    let res_body = read_body(res_body).await.unwrap_or_default();
    let response = ResponseParts {
        status: upstream_status,
        headers: headers_to_pairs(&head.headers),
        body: res_body,
    };

    // ── Response interception ──
    let Some(response) = shared.intercept.hold_response(&ctx, response).await else {
        record(
            shared,
            &target,
            &request,
            None,
            Some(format!("Response dropped by interceptor (upstream returned {upstream_status})")),
            start,
        );
        return Ok(error_response(502, "Response dropped by interceptor"));
    };

    let entry = record(shared, &target, &request, Some(&response), None, start);
    info!(
        "{} {} {} {} {}ms",
        request.method, entry.url, response.status, entry.response_size, entry.duration_ms
    );

    Ok(build_client_response(response))
}

/// Store one request/response pair (or a failed request) in history.
fn record(
    shared: &Shared,
    target: &Target,
    request: &RequestParts,
    response: Option<&ResponseParts>,
    error: Option<String>,
    start: Instant,
) -> TrafficEntry {
    let path = request.path.split('?').next().unwrap_or("/");
    let mut entry = TrafficEntry::new_request(
        &request.method,
        &target.url(&request.path),
        &target.host,
        path,
        target.scheme(),
        &pairs_to_json(&request.headers),
        request.body.clone(),
        header_value(&request.headers, "content-type"),
    );
    if let Some(res) = response {
        entry.status_code = res.status;
        entry.response_headers = pairs_to_json(&res.headers);
        entry.response_content_type = header_value(&res.headers, "content-type");
        entry.response_size = res.body.len() as u64;
        entry.response_body = res.body.clone();
    }
    entry.error = error;
    entry.duration_ms = start.elapsed().as_millis() as u64;
    let _ = shared.storage.insert(&entry);
    entry
}

/// Connect to the destination (with TLS for https) and send one request.
async fn send_upstream(target: &Target, req: Request<Full<Bytes>>, tls_config: Arc<rustls::ClientConfig>) -> Result<Response<Incoming>, String> {
    let addr = format!("{}:{}", target.host, target.port);
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("Connection failed: {e}"))?;

    if target.https {
        let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(|e| format!("Invalid server name: {e}"))?;
        let tls = tokio_rustls::TlsConnector::from(tls_config)
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("TLS handshake failed: {e}"))?;
        send_over(tls, req).await
    } else {
        send_over(tcp, req).await
    }
}

/// Run an HTTP/1.1 exchange over an established connection.
async fn send_over<T>(io: T, req: Request<Full<Bytes>>) -> Result<Response<Incoming>, String>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .title_case_headers(true)
        .handshake(TokioIo::new(io))
        .await
        .map_err(|e| format!("Handshake error: {e}"))?;

    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            debug!("Upstream connection error: {}", e);
        }
    });

    sender
        .send_request(req)
        .await
        .map_err(|e| format!("Upstream error: {e}"))
}

/// TLS settings for talking to real servers, built once.
fn client_tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// Headers that describe a single connection and must not be relayed, plus the ones the
/// proxy recomputes itself (`content-length`, from the buffered body).
fn is_hop_by_hop(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

/// Build the request to send upstream from the (possibly edited) parts.
///
/// `accept-encoding` and `expect` are dropped: responses then arrive uncompressed so they can
/// be captured and edited as text, and the body is already fully buffered.
fn build_upstream_request(parts: &RequestParts, default_host: &str) -> Result<Request<Full<Bytes>>, String> {
    let mut req = Request::builder()
        .method(parts.method.as_str())
        .uri(parts.path.as_str())
        .body(Full::new(Bytes::from(parts.body.clone())))
        .map_err(|e| e.to_string())?;

    let headers = req.headers_mut();
    for (name, value) in &parts.headers {
        let lower = name.to_ascii_lowercase();
        if is_hop_by_hop(&lower) || lower == "accept-encoding" || lower == "expect" {
            continue;
        }
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| format!("invalid header name \"{name}\""))?;
        let value =
            HeaderValue::from_bytes(value.as_bytes()).map_err(|_| format!("invalid value for header \"{name}\""))?;
        headers.append(name, value);
    }
    if !headers.contains_key(hyper::header::HOST) {
        headers.insert(
            hyper::header::HOST,
            HeaderValue::from_str(default_host).map_err(|e| e.to_string())?,
        );
    }
    Ok(req)
}

/// Build the response to return to the client from the (possibly edited) parts.
fn build_client_response(parts: ResponseParts) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(Bytes::from(parts.body)));
    *res.status_mut() = StatusCode::from_u16(parts.status).unwrap_or(StatusCode::BAD_GATEWAY);
    for (name, value) in &parts.headers {
        if is_hop_by_hop(&name.to_ascii_lowercase()) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_bytes(value.as_bytes())) {
            res.headers_mut().append(n, v);
        }
    }
    res
}

// ── Utility functions ──────────────────────────────────────────────

/// Read a hyper body into bytes. The whole body is kept so it can be forwarded intact;
/// only what gets stored in history is truncated (by storage).
async fn read_body(body: Incoming) -> Result<Vec<u8>> {
    let collected = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("Body read error: {}", e))?;
    Ok(collected.to_bytes().to_vec())
}

/// Headers as ordered (name, value) pairs, keeping repeated headers separate.
fn headers_to_pairs(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| (name.to_string(), String::from_utf8_lossy(value.as_bytes()).into_owned()))
        .collect()
}

/// First value of a header, matched case-insensitively.
fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Parse "host:port" string. Default port 443.
fn parse_host_port(authority: &str) -> (String, u16) {
    if let Some(idx) = authority.rfind(':') {
        let host = &authority[..idx];
        let port = authority[idx + 1..].parse().unwrap_or(443);
        (host.to_string(), port)
    } else {
        (authority.to_string(), 443)
    }
}

/// Create an error response.
fn error_response(status: u16, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap()
}

#[cfg(test)]
mod websocket_tests {
    use super::*;
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    use futures_util::{SinkExt,StreamExt};
    #[tokio::test]
    async fn proxy_upgrades_and_captures_bidirectional_websocket_traffic() {
        exchange("http", true).await;
        exchange("ws", true).await;
        exchange("http", false).await;
    }
    async fn exchange(scheme: &str, capture: bool) {
        tokio::time::timeout(std::time::Duration::from_secs(10),async {
            let storage=TrafficStorage::new(":memory:",1024).unwrap();
            let shared=Shared{storage:storage.clone(),intercept:Intercept::new(storage.clone()),upstream_tls:client_tls_config()};
            if !capture {shared.intercept.update_scope(crate::ScopeSettings{enabled:true,domains:vec!["other.example.com".into()]}).unwrap();}
            let upstream=TcpListener::bind("127.0.0.1:0").await.unwrap();let target=upstream.local_addr().unwrap();
            let server=tokio::spawn(async move {let (stream,_)=upstream.accept().await.unwrap();let mut ws=tokio_tungstenite::accept_async(stream).await.unwrap();let msg=ws.next().await.unwrap().unwrap();assert_eq!(msg.to_text().unwrap(),"hello");ws.send(tokio_tungstenite::tungstenite::Message::Text("world".into())).await.unwrap();ws.close(None).await.unwrap();});
            let proxy=TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=proxy.local_addr().unwrap();
            let dir=tempfile::tempdir().unwrap();let ca=Arc::new(CertificateAuthority::load_or_create(dir.path()).unwrap());
            let handler=tokio::spawn(async move {let (stream,_)=proxy.accept().await.unwrap();handle_client(stream,ca,shared).await.unwrap();});
            let mut client=TcpStream::connect(addr).await.unwrap();
            client.write_all(format!("GET {scheme}://{target}/socket HTTP/1.1\r\nHost: {target}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
            let mut head=Vec::new();while !head.ends_with(b"\r\n\r\n") {head.push(client.read_u8().await.unwrap());}
            let head=String::from_utf8(head).unwrap();assert!(head.starts_with("HTTP/1.1 101"),"{head}");assert!(head.to_ascii_lowercase().contains("upgrade: websocket"));
            let mut ws=tokio_tungstenite::WebSocketStream::from_raw_socket(client,tokio_tungstenite::tungstenite::protocol::Role::Client,None).await;
            ws.send(tokio_tungstenite::tungstenite::Message::Text("hello".into())).await.unwrap();
            assert_eq!(ws.next().await.unwrap().unwrap().to_text().unwrap(),"world");
            let _=ws.next().await;let _=ws.close(None).await;drop(ws);server.await.unwrap();handler.await.unwrap();
            let connections=storage.websocket_connections(Some(crate::TEMP_WORKSPACE_ID),None,100).unwrap();
            if !capture {assert!(connections.is_empty());return;}
            assert_eq!(connections.len(),1);
            let frames=storage.websocket_frames(Some(crate::TEMP_WORKSPACE_ID),&connections[0].id,0,100).unwrap();
            assert!(frames.iter().any(|f|f.direction=="client_to_server"&&f.text.as_deref()==Some("hello")));
            assert!(frames.iter().any(|f|f.direction=="server_to_client"&&f.text.as_deref()==Some("world")));
        }).await.unwrap();
    }
}

#[cfg(test)]
mod wss_tests {
    use super::*;
    use futures_util::{SinkExt,StreamExt};
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    #[tokio::test]
    async fn wss_upgrade_survives_connect_and_both_tls_connections() {
        tokio::time::timeout(std::time::Duration::from_secs(10),async {
            let dir=tempfile::tempdir().unwrap();let ca=Arc::new(CertificateAuthority::load_or_create(dir.path()).unwrap());
            let mut roots=rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(ca.ca_cert_pem())) {roots.add(cert.unwrap()).unwrap();}
            let config=Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
            let storage=TrafficStorage::new(":memory:",1024).unwrap();
            let shared=Shared{storage:storage.clone(),intercept:Intercept::new(storage.clone()),upstream_tls:config.clone()};
            let upstream=TcpListener::bind("127.0.0.1:0").await.unwrap();let port=upstream.local_addr().unwrap().port();
            let tls_server=ca.get_server_config("localhost").unwrap();
            let server=tokio::spawn(async move {let (stream,_)=upstream.accept().await.unwrap();let tls=TlsAcceptor::from(tls_server).accept(stream).await.unwrap();let mut ws=tokio_tungstenite::accept_async(tls).await.unwrap();let msg=ws.next().await.unwrap().unwrap();assert_eq!(msg.to_text().unwrap(),"secure hello");ws.send(tokio_tungstenite::tungstenite::Message::Text("secure world".into())).await.unwrap();ws.close(None).await.unwrap();});
            let proxy=TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=proxy.local_addr().unwrap();
            tokio::spawn(async move {let (stream,_)=proxy.accept().await.unwrap();handle_client(stream,ca,shared).await.unwrap();});
            let mut client=TcpStream::connect(addr).await.unwrap();client.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
            let mut head=Vec::new();while !head.ends_with(b"\r\n\r\n") {head.push(client.read_u8().await.unwrap());}assert!(String::from_utf8(head).unwrap().starts_with("HTTP/1.1 200"));
            let tls=tokio_rustls::TlsConnector::from(config).connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(),client).await.unwrap();
            let (mut ws,_)=tokio_tungstenite::client_async(format!("wss://localhost:{port}/events"),tls).await.unwrap();
            ws.send(tokio_tungstenite::tungstenite::Message::Text("secure hello".into())).await.unwrap();assert_eq!(ws.next().await.unwrap().unwrap().to_text().unwrap(),"secure world");
            let _=ws.next().await;let _=ws.close(None).await;drop(ws);server.await.unwrap();
            let connections=storage.websocket_connections(Some(crate::TEMP_WORKSPACE_ID),None,100).unwrap();assert_eq!(connections.len(),1);assert!(connections[0].url.starts_with("wss://localhost:"));
            let frames=storage.websocket_frames(Some(crate::TEMP_WORKSPACE_ID),&connections[0].id,0,100).unwrap();assert!(frames.iter().any(|f|f.text.as_deref()==Some("secure world")));
        }).await.unwrap();
    }
}
