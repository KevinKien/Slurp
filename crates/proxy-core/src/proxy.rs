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
#[cfg(test)]
use crate::storage::TrafficFilter;
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
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, OwnedSemaphorePermit};
use std::{pin::Pin, task::{Context as TaskContext, Poll}};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

/// Configuration for the proxy server.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to bind the proxy to
    pub listen_addr: SocketAddr,
    /// Maximum buffered request or response body (bytes), capped at 10 MiB.
    /// Oversized requests are rejected; oversized upstream responses return 502.
    pub max_body_size: usize,
    /// Local management API listener, protected from proxy forwarding.
    pub management_addr: Option<SocketAddr>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8888".parse().unwrap(),
            max_body_size: 10 * 1024 * 1024, // 10 MB
            management_addr: None,
        }
    }
}

/// What every connection handler needs.
#[derive(Clone)]
struct Shared {
    storage: Arc<TrafficStorage>,
    intercept: Arc<Intercept>,
    upstream_tls: Arc<rustls::ClientConfig>,
    connections: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    body_limit: usize,
    management_port: Option<u16>,
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
            config: config.clone(),
            ca,
            shared: Shared { storage, intercept, upstream_tls: client_tls_config(), connections:Arc::new(Semaphore::new(64)),requests:Arc::new(Semaphore::new(8)),body_limit:config.max_body_size.min(10*1024*1024),management_port:config.management_addr.map(|a|a.port()) },
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

// The permit travels with the socket through CONNECT and WebSocket upgrades.
struct ClientStream { stream:TcpStream, _permit:OwnedSemaphorePermit }
impl AsyncRead for ClientStream {
    fn poll_read(mut self:Pin<&mut Self>,cx:&mut TaskContext<'_>,buf:&mut tokio::io::ReadBuf<'_>)->Poll<std::io::Result<()>> {Pin::new(&mut self.stream).poll_read(cx,buf)}
}
impl AsyncWrite for ClientStream {
    fn poll_write(mut self:Pin<&mut Self>,cx:&mut TaskContext<'_>,buf:&[u8])->Poll<std::io::Result<usize>> {Pin::new(&mut self.stream).poll_write(cx,buf)}
    fn poll_flush(mut self:Pin<&mut Self>,cx:&mut TaskContext<'_>)->Poll<std::io::Result<()>> {Pin::new(&mut self.stream).poll_flush(cx)}
    fn poll_shutdown(mut self:Pin<&mut Self>,cx:&mut TaskContext<'_>)->Poll<std::io::Result<()>> {Pin::new(&mut self.stream).poll_shutdown(cx)}
}

/// Handle a single client connection.
///
/// We use hyper's HTTP/1.1 server to parse the incoming request.
/// If it's CONNECT, we do MITM. Otherwise, we forward as HTTP.
async fn handle_client(stream: TcpStream, ca: Arc<CertificateAuthority>, shared: Shared) -> Result<()> {
    let permit=shared.connections.clone().try_acquire_owned().map_err(|_|anyhow::anyhow!("Proxy connection capacity reached"))?;
    let io = TokioIo::new(ClientStream{stream,_permit:permit});

    http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
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
    let client_tls = tokio::time::timeout(Duration::from_secs(10),tls_acceptor.accept(client_io))
        .await.context("Client TLS handshake timed out")?
        .with_context(|| format!("TLS handshake failed with client for {}", host))?;

    let h2 = client_tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    let client_io = TokioIo::new(client_tls);

    // 3. Now serve HTTP requests from the client over the TLS connection
    let host = host.to_string();

    let service = service_fn(move |req: Request<Incoming>| {
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
    });

    if h2 {
        // Streams beyond the proxy's request capacity would be rejected with 503, so let the
        // client queue them instead of opening more than that many at once.
        hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .timer(hyper_util::rt::TokioTimer::new())
            .max_concurrent_streams(8)
            .serve_connection(client_io, service)
            .await
            .map_err(|e| anyhow::anyhow!("HTTP/2 serve error: {}", e))?;
    } else {
        http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(Duration::from_secs(10))
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(client_io, service)
            .with_upgrades()
            .await
            .map_err(|e| anyhow::anyhow!("HTTPS serve error: {}", e))?;
    }

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
    let _permit=match shared.requests.clone().try_acquire_owned(){Ok(permit)=>permit,Err(_)=>return Ok(error_response(503,"Proxy request capacity reached; existing held requests are preserved"))};
    let start = Instant::now();

    let websocket = req.method() == Method::GET
        && req.headers().get("upgrade").and_then(|v|v.to_str().ok()).is_some_and(|v|v.eq_ignore_ascii_case("websocket"))
        && req.headers().get_all("connection").iter().filter_map(|v|v.to_str().ok()).any(|v|v.split(',').any(|t|t.trim().eq_ignore_ascii_case("upgrade")));
    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));
    let method = req.method().to_string();
    let mut headers = headers_to_pairs(req.headers());
    // HTTP/2 carries the host in :authority; keep it visible as a Host header in history/Intercept.
    if header_value(&headers, "host").is_none() {
        let authority = req.uri().authority().map(|a| a.to_string()).unwrap_or_else(|| target.authority());
        headers.insert(0, ("host".to_string(), authority));
    }
    let body = match read_body(req.into_body(),shared.body_limit).await {
        Ok(b) => b,
        Err(error) => return Ok(error_response(413, &error.to_string())),
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
    let mut upstream_res = match tokio::time::timeout(Duration::from_secs(30),send_upstream(&target, upstream_req, shared.upstream_tls.clone(),shared.management_port,websocket)).await.unwrap_or_else(|_|Err("Upstream request timed out".into())) {
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
    let res_body = match read_body(res_body,shared.body_limit).await {
        Ok(body)=>body,
        Err(error)=>{record(shared,&target,&request,None,Some(error.to_string()),start);return Ok(error_response(502,&error.to_string()));}
    };
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
/// WebSocket upgrades need HTTP/1.1, so they skip HTTP/2 negotiation (`websocket`).
async fn send_upstream(target: &Target, req: Request<Full<Bytes>>, tls_config: Arc<rustls::ClientConfig>, management_port:Option<u16>, websocket: bool) -> Result<Response<Incoming>, String> {
    let addresses:Vec<_>=tokio::net::lookup_host((target.host.trim_matches(['[',']']),target.port)).await.map_err(|e|format!("DNS lookup failed: {e}"))?.collect();
    if management_port==Some(target.port) {
        let local:Vec<_>=if_addrs::get_if_addrs().map_err(|e|format!("Cannot validate management destination: {e}"))?.into_iter().map(|i|i.ip().to_canonical()).collect();
        if addresses.iter().any(|a|a.ip().to_canonical().is_loopback()||local.contains(&a.ip().to_canonical())) {return Err("Proxy forwarding to Slurp management API is forbidden".into());}
    }
    // Connect to the exact addresses checked above; do not perform another DNS lookup.
    let tcp=TcpStream::connect(addresses.as_slice()).await.map_err(|e|format!("Connection failed: {e}"))?;

    if target.https {
        let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(|e| format!("Invalid server name: {e}"))?;
        let tls_config = if websocket { http1_only(&tls_config) } else { tls_config };
        let tls = tokio_rustls::TlsConnector::from(tls_config)
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("TLS handshake failed: {e}"))?;
        if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
            send_over_h2(tls, req).await
        } else {
            send_over(tls, req).await
        }
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

/// Run an HTTP/2 exchange over an established TLS connection.
///
/// HTTP/2 has no Host header: the authority travels in `:authority`, so the request is rewritten
/// to absolute form with the Host value (or the URI's own authority) as that authority.
async fn send_over_h2<T>(io: T, req: Request<Full<Bytes>>) -> Result<Response<Incoming>, String>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut parts, body) = req.into_parts();
    let authority = parts
        .headers
        .remove(hyper::header::HOST)
        .and_then(|v| v.to_str().ok().map(str::to_string))
        .or_else(|| parts.uri.authority().map(|a| a.to_string()))
        .ok_or("Request has no host")?;
    let path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    parts.uri = format!("https://{authority}{path}")
        .parse()
        .map_err(|e| format!("Invalid HTTP/2 request target: {e}"))?;
    parts.version = hyper::Version::HTTP_2;

    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .timer(hyper_util::rt::TokioTimer::new())
        .handshake(TokioIo::new(io))
        .await
        .map_err(|e| format!("HTTP/2 handshake error: {e}"))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("Upstream HTTP/2 connection error: {}", e);
        }
    });

    sender
        .send_request(Request::from_parts(parts, body))
        .await
        .map_err(|e| format!("Upstream error: {e}"))
}

/// TLS settings for talking to real servers, built once. Offers HTTP/2 and HTTP/1.1.
fn client_tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone()
}

/// Same trust roots as `config`, but HTTP/1.1 only (required for WebSocket upgrades).
fn http1_only(config: &Arc<rustls::ClientConfig>) -> Arc<rustls::ClientConfig> {
    let mut config = (**config).clone();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
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

/// Bound body buffering and read time before interception or history copies are made.
async fn read_body(mut body: Incoming, limit:usize) -> Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(30),async {
        let mut bytes=Vec::new();
        while let Some(frame)=body.frame().await {
            let frame=frame?;
            if let Ok(data)=frame.into_data() {
                anyhow::ensure!(data.len()<=limit.saturating_sub(bytes.len()),"Proxy body exceeds {} byte buffering limit",limit);
                bytes.extend_from_slice(&data);
            }
        }
        Ok(bytes)
    }).await.context("Proxy body read timed out")?
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
            let shared=Shared{storage:storage.clone(),intercept:Intercept::new(storage.clone()),upstream_tls:client_tls_config(),connections:Arc::new(Semaphore::new(64)),requests:Arc::new(Semaphore::new(8)),body_limit:10*1024*1024,management_port:None};
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
            let shared=Shared{storage:storage.clone(),intercept:Intercept::new(storage.clone()),upstream_tls:config.clone(),connections:Arc::new(Semaphore::new(64)),requests:Arc::new(Semaphore::new(8)),body_limit:10*1024*1024,management_port:None};
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

#[cfg(test)]
mod resource_tests {
    use super::*;
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    async fn request(body_limit:usize,management_port:Option<u16>,target:SocketAddr,body:&[u8],capacity:usize)->String {
        let storage=TrafficStorage::new(":memory:",1024).unwrap();
        let shared=Shared{intercept:Intercept::new(storage.clone()),storage,upstream_tls:client_tls_config(),connections:Arc::new(Semaphore::new(2)),requests:Arc::new(Semaphore::new(capacity)),body_limit,management_port};
        let directory=tempfile::tempdir().unwrap();let ca=Arc::new(CertificateAuthority::load_or_create(directory.path()).unwrap());
        let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let task=tokio::spawn(async move{let (stream,_)=listener.accept().await.unwrap();let _=handle_client(stream,ca,shared).await;});
        let mut client=TcpStream::connect(address).await.unwrap();
        client.write_all(format!("POST http://{target}/test HTTP/1.1\r\nHost: {target}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();client.write_all(body).await.unwrap();
        let mut bytes=Vec::new();tokio::time::timeout(Duration::from_secs(5),client.read_to_end(&mut bytes)).await.unwrap().unwrap();task.await.unwrap();String::from_utf8(bytes).unwrap()
    }
    #[tokio::test] async fn rejects_oversized_request_before_forwarding() {
        let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let response=request(32,None,listener.local_addr().unwrap(),&[b'x';33],8).await;assert!(response.starts_with("HTTP/1.1 413"),"{response}");
        assert!(tokio::time::timeout(Duration::from_millis(50),listener.accept()).await.is_err());
    }
    #[tokio::test] async fn rejects_management_destination_before_connecting() {
        let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();let response=request(64,Some(address.port()),address,b"",8).await;assert!(response.contains("management API is forbidden"),"{response}");assert!(tokio::time::timeout(Duration::from_millis(50),listener.accept()).await.is_err());
    }
    #[tokio::test] async fn rejects_new_requests_when_buffer_capacity_is_full() {
        let response=request(64,None,"127.0.0.1:1".parse().unwrap(),b"",0).await;assert!(response.starts_with("HTTP/1.1 503"),"{response}");
    }
    #[tokio::test] async fn rejects_oversized_upstream_response() {
        let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let task=tokio::spawn(async move{let (mut stream,_)=listener.accept().await.unwrap();let mut bytes=[0u8;4096];stream.read(&mut bytes).await.unwrap();stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\nConnection: close\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").await.unwrap();});
        let response=request(32,None,address,b"",8).await;assert!(response.starts_with("HTTP/1.1 502"),"{response}");assert!(response.contains("buffering limit"));task.await.unwrap();
    }
}

#[cfg(test)]
mod http2_tests {
    use super::*;
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    use hyper_util::rt::TokioExecutor;

    /// Client -> proxy (h2 over MITM TLS) -> upstream (h2 over TLS), captured in history.
    #[tokio::test]
    async fn proxies_http2_in_both_directions_and_captures_it() {
        tokio::time::timeout(Duration::from_secs(10),async {
            let dir=tempfile::tempdir().unwrap();let ca=Arc::new(CertificateAuthority::load_or_create(dir.path()).unwrap());
            let mut roots=rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(ca.ca_cert_pem())) {roots.add(cert.unwrap()).unwrap();}
            let mut client_config=rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
            client_config.alpn_protocols=vec![b"h2".to_vec(),b"http/1.1".to_vec()];
            let config=Arc::new(client_config);
            let storage=TrafficStorage::new(":memory:",1024).unwrap();
            let shared=Shared{storage:storage.clone(),intercept:Intercept::new(storage.clone()),upstream_tls:config.clone(),connections:Arc::new(Semaphore::new(64)),requests:Arc::new(Semaphore::new(8)),body_limit:10*1024*1024,management_port:None};

            let upstream=TcpListener::bind("127.0.0.1:0").await.unwrap();let port=upstream.local_addr().unwrap().port();
            let tls_server=ca.get_server_config("localhost").unwrap();
            let server=tokio::spawn(async move {
                let (stream,_)=upstream.accept().await.unwrap();
                let tls=TlsAcceptor::from(tls_server).accept(stream).await.unwrap();
                assert_eq!(tls.get_ref().1.alpn_protocol(),Some(b"h2".as_slice()));
                let service=service_fn(|req:Request<Incoming>|async move {
                    let seen=format!("{:?} {} {}",req.version(),req.uri().authority().map(|a|a.as_str()).unwrap_or(""),req.uri().path());
                    Ok::<_,hyper::Error>(Response::new(Full::new(Bytes::from(seen))))
                });
                hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls),service).await.unwrap();
            });

            let proxy=TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=proxy.local_addr().unwrap();
            tokio::spawn(async move {let (stream,_)=proxy.accept().await.unwrap();let _=handle_client(stream,ca,shared).await;});
            let mut client=TcpStream::connect(addr).await.unwrap();client.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
            let mut head=Vec::new();while !head.ends_with(b"\r\n\r\n") {head.push(client.read_u8().await.unwrap());}assert!(String::from_utf8(head).unwrap().starts_with("HTTP/1.1 200"));
            let tls=tokio_rustls::TlsConnector::from(config).connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(),client).await.unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(),Some(b"h2".as_slice()),"proxy must offer h2 to the client");

            let (mut sender,conn)=hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(TokioIo::new(tls)).await.unwrap();
            tokio::spawn(conn);
            let request=Request::builder().uri(format!("https://localhost:{port}/h2/path?q=1")).body(Full::new(Bytes::new())).unwrap();
            let response=sender.send_request(request).await.unwrap();
            assert_eq!(response.status(),200);
            let body=response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(String::from_utf8(body.to_vec()).unwrap(),format!("HTTP/2.0 localhost:{port} /h2/path"));

            let entries=storage.list(10,0,&TrafficFilter{workspace:Some(crate::TEMP_WORKSPACE_ID),..Default::default()}).unwrap();
            assert_eq!(entries.len(),1);
            assert_eq!(entries[0].status_code,200);
            assert_eq!(entries[0].path,"/h2/path");
            assert!(entries[0].request_headers.to_ascii_lowercase().contains(&format!("localhost:{port}")),"Host recorded from :authority");
            drop(server);
        }).await.unwrap();
    }
}
