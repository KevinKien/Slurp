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
use std::sync::Arc;
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
pub(crate) struct Shared {
    storage: Arc<TrafficStorage>,
    intercept: Arc<Intercept>,
    /// `None` follows the live trust store; tests pin a fixed config.
    upstream_tls: Option<Arc<rustls::ClientConfig>>,
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
            shared: Shared { storage, intercept, upstream_tls: None, connections:Arc::new(Semaphore::new(64)),requests:Arc::new(Semaphore::new(8)),body_limit:config.max_body_size.min(10*1024*1024),management_port:config.management_addr.map(|a|a.port()) },
        }
    }

    /// Reverse proxies (fixed-upstream listeners) that capture into this server's storage.
    pub fn reverse_proxies(&self, config_path: std::path::PathBuf) -> Arc<crate::reverse::ReverseProxies> {
        crate::reverse::ReverseProxies::new(self.ca.clone(), self.shared.clone(), config_path)
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
    // SOCKS5 starts with 0x05; HTTP starts with a letter, so both share the proxy port.
    let mut first=[0u8;1];
    if let Ok(Ok(1))=tokio::time::timeout(Duration::from_secs(10),stream.peek(&mut first)).await {
        if first[0]==5 { return handle_socks(ClientStream{stream,_permit:permit},ca,shared).await; }
    }
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

/// One connection to a reverse-proxy listener: every request goes to the rule's fixed upstream.
pub(crate) async fn handle_reverse(stream: TcpStream, route: crate::reverse::Route, ca: Arc<CertificateAuthority>, shared: Shared) -> Result<()> {
    let permit = shared.connections.clone().try_acquire_owned().map_err(|_| anyhow::anyhow!("Proxy connection capacity reached"))?;
    let io = ClientStream { stream, _permit: permit };
    let target = Target { https: route.https, host: route.host.clone(), port: route.port };
    if !route.tls {
        return serve_fixed_target(io, target, route.rewrite_host, shared, false).await;
    }
    let handshake = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io);
    let start = tokio::time::timeout(Duration::from_secs(10), handshake).await.context("Client TLS handshake timed out")??;
    let name = start.client_hello().server_name().map(str::to_ascii_lowercase).unwrap_or_else(|| route.fallback_name.clone());
    let config = ca.get_server_config(&name).with_context(|| format!("Failed to get cert for {name}"))?;
    let tls = tokio::time::timeout(Duration::from_secs(10), start.into_stream(config)).await.context("Client TLS handshake timed out")??;
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    serve_fixed_target(tls, target, route.rewrite_host, shared, h2).await
}

/// Serve requests read from `io` to one destination, optionally presenting the destination's own
/// host as `Host` (what the upstream expects, rather than the address the client used).
async fn serve_fixed_target<IO>(io: IO, target: Target, rewrite_host: bool, shared: Shared, h2: bool) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |mut req: Request<Incoming>| {
        let target = target.clone();
        let shared = shared.clone();
        async move {
            if rewrite_host {
                if let Ok(value) = HeaderValue::from_str(&target.authority()) {
                    req.headers_mut().insert(hyper::header::HOST, value);
                }
            }
            let path_and_query = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();
            proxy_request(req, target, path_and_query, &shared).await
        }
    });
    let io = TokioIo::new(io);
    if h2 {
        hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .timer(hyper_util::rt::TokioTimer::new())
            .max_concurrent_streams(8)
            .serve_connection(io, service)
            .await
            .map_err(|e| anyhow::anyhow!("HTTP/2 serve error: {}", e))
    } else {
        http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(Duration::from_secs(10))
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, service)
            .with_upgrades()
            .await
            .map_err(|e| anyhow::anyhow!("HTTP serve error: {}", e))
    }
}

/// How long a SOCKS client gets to send its first bytes. Protocols where the server speaks
/// first (SSH, SMTP, databases) send nothing, and are relayed once this passes.
const SOCKS_SNIFF: Duration = Duration::from_secs(1);

/// A SOCKS5 connection: after the handshake, decrypt TLS, capture plain HTTP, or relay the rest.
async fn handle_socks(mut io: ClientStream, ca: Arc<CertificateAuthority>, shared: Shared) -> Result<()> {
    let destination = crate::socks::handshake(&mut io.stream).await?;
    let deadline = Instant::now() + SOCKS_SNIFF;
    let mut buffer = vec![0u8; 16384 + 5];
    let kind = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let seen = match tokio::time::timeout(remaining, io.stream.peek(&mut buffer)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break crate::socks::Kind::Other,
        };
        match crate::socks::classify(&buffer[..seen]) {
            crate::socks::Kind::Incomplete if Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(5)).await,
            crate::socks::Kind::Incomplete => break crate::socks::Kind::Other,
            kind => break kind,
        }
    };
    let (host, port) = (destination.host, destination.port);
    match kind {
        crate::socks::Kind::Tls(sni) => {
            // A client that resolved DNS itself sends an address; the name it asked for is in the SNI.
            let name = sni.filter(|_| destination_is_ip(&host)).unwrap_or(host);
            info!("🧦 SOCKS5 TLS {}:{}", name, port);
            handle_https_mitm(io, &name, port, ca, shared).await
        }
        crate::socks::Kind::Http => {
            info!("🧦 SOCKS5 HTTP {}:{}", host, port);
            serve_plain_http(io, host, port, shared).await
        }
        _ => {
            info!("🧦 SOCKS5 relay {}:{} (not HTTP or TLS, not captured)", host, port);
            relay(io, &host, port, shared.management_port).await
        }
    }
}

fn destination_is_ip(host: &str) -> bool {
    host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok()
}

/// Serve HTTP/1.1 requests read from `io` (origin-form) to a fixed plain-HTTP destination.
async fn serve_plain_http<IO>(io: IO, host: String, port: u16, shared: Shared) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req: Request<Incoming>| {
        let target = Target { https: false, host: host.clone(), port };
        let shared = shared.clone();
        async move {
            let path_and_query = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();
            proxy_request(req, target, path_and_query, &shared).await
        }
    });
    http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades()
        .await
        .map_err(|e| anyhow::anyhow!("HTTP serve error: {}", e))
}

/// Copy bytes both ways between the client and the destination without looking at them.
async fn relay(mut io: ClientStream, host: &str, port: u16, management_port: Option<u16>) -> Result<()> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.trim_matches(['[', ']']), port)).await?.collect();
    forbid_management(&addresses, port, management_port).map_err(|e| anyhow::anyhow!(e))?;
    let mut upstream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addresses.as_slice()))
        .await
        .map_err(|_| anyhow::anyhow!("Connection timed out"))??;
    tokio::io::copy_bidirectional(&mut io, &mut upstream).await?;
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
    let mut upstream_res = match tokio::time::timeout(Duration::from_secs(30),send_upstream(&target, upstream_req, shared.upstream_tls.clone().unwrap_or_else(client_tls_config),shared.management_port,websocket)).await.unwrap_or_else(|_|Err("Upstream request timed out".into())) {
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

/// Refuse destinations that would reach Slurp's own management API through the proxy.
fn forbid_management(addresses:&[SocketAddr],port:u16,management_port:Option<u16>)->Result<(),String>{
    if management_port==Some(port) {
        let local:Vec<_>=if_addrs::get_if_addrs().map_err(|e|format!("Cannot validate management destination: {e}"))?.into_iter().map(|i|i.ip().to_canonical()).collect();
        if addresses.iter().any(|a|a.ip().to_canonical().is_loopback()||local.contains(&a.ip().to_canonical())) {return Err("Proxy forwarding to Slurp management API is forbidden".into());}
    }
    Ok(())
}

/// Connect to the destination (with TLS for https) and send one request.
/// WebSocket upgrades need HTTP/1.1, so they skip HTTP/2 negotiation (`websocket`).
async fn send_upstream(target: &Target, req: Request<Full<Bytes>>, tls_config: Arc<rustls::ClientConfig>, management_port:Option<u16>, websocket: bool) -> Result<Response<Incoming>, String> {
    let addresses:Vec<_>=tokio::net::lookup_host((target.host.trim_matches(['[',']']),target.port)).await.map_err(|e|format!("DNS lookup failed: {e}"))?.collect();
    forbid_management(&addresses,target.port,management_port)?;
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

/// TLS settings for talking to real servers: public roots plus the CAs trusted in Settings.
fn client_tls_config() -> Arc<rustls::ClientConfig> {
    crate::trust::client_config()
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
            let shared=Shared{storage:storage.clone(),intercept:Intercept::new(storage.clone()),upstream_tls:None,connections:Arc::new(Semaphore::new(64)),requests:Arc::new(Semaphore::new(8)),body_limit:10*1024*1024,management_port:None};
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
            let shared=Shared{storage:storage.clone(),intercept:Intercept::new(storage.clone()),upstream_tls:Some(config.clone()),connections:Arc::new(Semaphore::new(64)),requests:Arc::new(Semaphore::new(8)),body_limit:10*1024*1024,management_port:None};
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
        let shared=Shared{intercept:Intercept::new(storage.clone()),storage,upstream_tls:None,connections:Arc::new(Semaphore::new(2)),requests:Arc::new(Semaphore::new(capacity)),body_limit,management_port};
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
            let shared=Shared{storage:storage.clone(),intercept:Intercept::new(storage.clone()),upstream_tls:Some(config.clone()),connections:Arc::new(Semaphore::new(64)),requests:Arc::new(Semaphore::new(8)),body_limit:10*1024*1024,management_port:None};

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

#[cfg(test)]
mod private_ca_tests {
    use super::*;
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    /// An HTTPS upstream signed by a CA that is not a public root: refused until that CA is trusted.
    #[tokio::test]
    async fn upstream_with_a_private_ca_works_only_after_the_ca_is_trusted() {
        let _guard=crate::trust::TEST_SERIAL.lock().unwrap_or_else(|e|e.into_inner());
        let data=tempfile::tempdir().unwrap();crate::trust::init(data.path().join("trusted-cas")).unwrap();
        let upstream_ca_dir=tempfile::tempdir().unwrap();let upstream_ca=CertificateAuthority::load_or_create(upstream_ca_dir.path()).unwrap();
        let mut server_config=(*upstream_ca.get_server_config("localhost").unwrap()).clone();server_config.alpn_protocols=vec![b"http/1.1".to_vec()];
        let acceptor=TlsAcceptor::from(Arc::new(server_config));
        let upstream=TcpListener::bind("127.0.0.1:0").await.unwrap();let port=upstream.local_addr().unwrap().port();
        tokio::spawn(async move{loop{let Ok((stream,_))=upstream.accept().await else{break};let acceptor=acceptor.clone();tokio::spawn(async move{
            let Ok(mut tls)=acceptor.accept(stream).await else{return};let mut buffer=[0u8;4096];let _=tls.read(&mut buffer).await;
            let _=tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").await;let _=tls.shutdown().await;});}});
        let proxy_ca_dir=tempfile::tempdir().unwrap();let proxy_ca=Arc::new(CertificateAuthority::load_or_create(proxy_ca_dir.path()).unwrap());
        let fetch=|ca:Arc<CertificateAuthority>|async move{
            let storage=TrafficStorage::new(":memory:",1024).unwrap();
            let shared=Shared{intercept:Intercept::new(storage.clone()),storage,upstream_tls:None,connections:Arc::new(Semaphore::new(4)),requests:Arc::new(Semaphore::new(4)),body_limit:1024*1024,management_port:None};
            let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
            let task=tokio::spawn(async move{let (stream,_)=listener.accept().await.unwrap();let _=handle_client(stream,ca,shared).await;});
            let mut client=TcpStream::connect(address).await.unwrap();
            client.write_all(format!("GET https://localhost:{port}/hello HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut bytes=Vec::new();tokio::time::timeout(Duration::from_secs(10),client.read_to_end(&mut bytes)).await.unwrap().unwrap();task.await.unwrap();String::from_utf8_lossy(&bytes).into_owned()
        };
        let before=fetch(proxy_ca.clone()).await;assert!(before.starts_with("HTTP/1.1 502"),"{before}");
        crate::trust::add_pem("private-upstream",upstream_ca.ca_cert_pem().as_ref()).unwrap();
        let after=fetch(proxy_ca.clone()).await;assert!(after.starts_with("HTTP/1.1 200")&&after.ends_with("hello"),"{after}");
        assert!(crate::trust::remove("private-upstream").unwrap());
        let removed=fetch(proxy_ca).await;assert!(removed.starts_with("HTTP/1.1 502"),"{removed}");
    }
}

#[cfg(test)]
mod socks_tests {
    use super::*;
    use tokio::io::{AsyncReadExt,AsyncWriteExt};

    fn shared(storage:Arc<TrafficStorage>,upstream_tls:Option<Arc<rustls::ClientConfig>>,management_port:Option<u16>)->Shared {
        Shared{intercept:Intercept::new(storage.clone()),storage,upstream_tls,connections:Arc::new(Semaphore::new(8)),requests:Arc::new(Semaphore::new(8)),body_limit:1024*1024,management_port}
    }
    /// A proxy that serves exactly one connection; returns its address.
    async fn proxy(shared:Shared,ca:Arc<CertificateAuthority>)->(SocketAddr,tokio::task::JoinHandle<()>) {
        let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        (address,tokio::spawn(async move{let (stream,_)=listener.accept().await.unwrap();let _=handle_client(stream,ca,shared).await;}))
    }
    fn new_ca()->(Arc<CertificateAuthority>,tempfile::TempDir) {let dir=tempfile::tempdir().unwrap();(Arc::new(CertificateAuthority::load_or_create(dir.path()).unwrap()),dir)}
    /// SOCKS5 greeting and CONNECT; returns the connected client and the reply code.
    async fn socks(proxy:SocketAddr,atyp:u8,address:&[u8],port:u16,command:u8)->(TcpStream,u8) {
        let mut client=TcpStream::connect(proxy).await.unwrap();
        client.write_all(&[5,1,0]).await.unwrap();let mut method=[0u8;2];client.read_exact(&mut method).await.unwrap();assert_eq!(method,[5,0]);
        let mut request=vec![5,command,0,atyp];request.extend_from_slice(address);request.extend_from_slice(&port.to_be_bytes());client.write_all(&request).await.unwrap();
        let mut answer=[0u8;10];client.read_exact(&mut answer).await.unwrap();assert_eq!(answer[0],5);(client,answer[1])
    }
    fn domain(name:&str)->Vec<u8> {let mut v=vec![name.len() as u8];v.extend_from_slice(name.as_bytes());v}
    async fn http_upstream()->(u16,tokio::task::JoinHandle<()>) {
        let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let port=listener.local_addr().unwrap().port();
        (port,tokio::spawn(async move{let (mut s,_)=listener.accept().await.unwrap();let mut b=[0u8;4096];let _=s.read(&mut b).await;let _=s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;}))
    }
    fn urls(storage:&TrafficStorage)->Vec<String> {storage.list(10,0,&TrafficFilter{workspace:Some(crate::TEMP_WORKSPACE_ID),..Default::default()}).unwrap().into_iter().map(|e|e.url).collect()}

    #[tokio::test]
    async fn socks5_plain_http_is_captured() {
        tokio::time::timeout(Duration::from_secs(10),async{
            let (port,upstream)=http_upstream().await;let storage=TrafficStorage::new(":memory:",1024).unwrap();let (ca,_d)=new_ca();
            let (address,task)=proxy(shared(storage.clone(),None,None),ca).await;
            let (mut client,code)=socks(address,3,&domain("localhost"),port,1).await;assert_eq!(code,0);
            client.write_all(format!("GET /x HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut bytes=Vec::new();client.read_to_end(&mut bytes).await.unwrap();let text=String::from_utf8_lossy(&bytes).into_owned();
            assert!(text.starts_with("HTTP/1.1 200")&&text.ends_with("ok"),"{text}");upstream.await.unwrap();let _=task.await;
            assert_eq!(urls(&storage),vec![format!("http://localhost:{port}/x")]);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn socks5_tls_to_an_ip_address_is_decrypted_using_the_sni_name() {
        tokio::time::timeout(Duration::from_secs(10),async{
            let (ca,_d)=new_ca();let mut roots=rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(ca.ca_cert_pem())) {roots.add(cert.unwrap()).unwrap();}
            let mut config=rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();config.alpn_protocols=vec![b"http/1.1".to_vec()];let config=Arc::new(config);
            let mut server=(*ca.get_server_config("localhost").unwrap()).clone();server.alpn_protocols=vec![b"http/1.1".to_vec()];let acceptor=TlsAcceptor::from(Arc::new(server));
            let upstream=TcpListener::bind("127.0.0.1:0").await.unwrap();let port=upstream.local_addr().unwrap().port();
            let server=tokio::spawn(async move{let (s,_)=upstream.accept().await.unwrap();let mut tls=acceptor.accept(s).await.unwrap();let mut b=[0u8;4096];let _=tls.read(&mut b).await;let _=tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure").await;let _=tls.shutdown().await;});
            let storage=TrafficStorage::new(":memory:",1024).unwrap();
            let (address,task)=proxy(shared(storage.clone(),Some(config.clone()),None),ca).await;
            // The client resolved DNS itself, so SOCKS carries 127.0.0.1; TLS still asks for "localhost".
            let (client,code)=socks(address,1,&[127,0,0,1],port,1).await;assert_eq!(code,0);
            let mut tls=tokio_rustls::TlsConnector::from(config).connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(),client).await.unwrap();
            tls.write_all(format!("GET /secure HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut bytes=Vec::new();let _=tls.read_to_end(&mut bytes).await;let text=String::from_utf8_lossy(&bytes).into_owned();
            assert!(text.starts_with("HTTP/1.1 200")&&text.ends_with("secure"),"{text}");server.await.unwrap();drop(tls);let _=task.await;
            assert_eq!(urls(&storage),vec![format!("https://localhost:{port}/secure")]);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn socks5_rejects_unsupported_methods_and_commands() {
        let storage=TrafficStorage::new(":memory:",1024).unwrap();let (ca,_d)=new_ca();
        let (address,task)=proxy(shared(storage.clone(),None,None),ca.clone()).await;
        let mut client=TcpStream::connect(address).await.unwrap();client.write_all(&[5,1,2]).await.unwrap();let mut answer=[0u8;2];client.read_exact(&mut answer).await.unwrap();assert_eq!(answer,[5,0xFF]);let _=task.await;
        // UDP ASSOCIATE (3) and BIND (2) are refused with "command not supported".
        for command in [3u8,2] {
            let (address,task)=proxy(shared(storage.clone(),None,None),ca.clone()).await;
            let (_client,code)=socks(address,1,&[127,0,0,1],9,command).await;assert_eq!(code,7);let _=task.await;
        }
        // An unknown address type is refused with "address type not supported".
        let (address,task)=proxy(shared(storage.clone(),None,None),ca).await;
        let mut client=TcpStream::connect(address).await.unwrap();client.write_all(&[5,1,0]).await.unwrap();let mut method=[0u8;2];client.read_exact(&mut method).await.unwrap();
        client.write_all(&[5,1,0,9,0,0]).await.unwrap();let mut answer=[0u8;10];client.read_exact(&mut answer).await.unwrap();assert_eq!(answer[1],8);let _=task.await;
        assert!(urls(&storage).is_empty());
    }

    #[tokio::test]
    async fn socks5_relays_other_protocols_unchanged_including_server_first_ones() {
        tokio::time::timeout(Duration::from_secs(15),async{
            let storage=TrafficStorage::new(":memory:",1024).unwrap();let (ca,_d)=new_ca();
            // Server speaks first (like SSH or SMTP): nothing arrives from the client at first.
            let banner=TcpListener::bind("127.0.0.1:0").await.unwrap();let banner_port=banner.local_addr().unwrap().port();
            tokio::spawn(async move{let (mut s,_)=banner.accept().await.unwrap();let _=s.write_all(b"HELLO\r\n").await;let mut b=[0u8;16];let _=s.read(&mut b).await;});
            let (address,task)=proxy(shared(storage.clone(),None,None),ca.clone()).await;
            let (mut client,code)=socks(address,3,&domain("localhost"),banner_port,1).await;assert_eq!(code,0);
            let mut hello=[0u8;7];client.read_exact(&mut hello).await.unwrap();assert_eq!(&hello,b"HELLO\r\n");drop(client);let _=task.await;
            // Client speaks first with binary data: echoed back byte for byte.
            let echo=TcpListener::bind("127.0.0.1:0").await.unwrap();let echo_port=echo.local_addr().unwrap().port();
            tokio::spawn(async move{let (mut s,_)=echo.accept().await.unwrap();let mut b=[0u8;5];s.read_exact(&mut b).await.unwrap();s.write_all(&b).await.unwrap();});
            let (address,task)=proxy(shared(storage.clone(),None,None),ca).await;
            let (mut client,_)=socks(address,1,&[127,0,0,1],echo_port,1).await;
            client.write_all(&[0,1,2,3,4]).await.unwrap();let mut back=[0u8;5];client.read_exact(&mut back).await.unwrap();assert_eq!(back,[0,1,2,3,4]);drop(client);let _=task.await;
            assert!(urls(&storage).is_empty(),"relayed traffic is not captured");
        }).await.unwrap();
    }

    #[tokio::test]
    async fn socks5_cannot_be_used_to_reach_the_management_api() {
        tokio::time::timeout(Duration::from_secs(10),async{
            let management=TcpListener::bind("127.0.0.1:0").await.unwrap();let port=management.local_addr().unwrap().port();
            let storage=TrafficStorage::new(":memory:",1024).unwrap();let (ca,_d)=new_ca();
            let (address,task)=proxy(shared(storage,None,Some(port)),ca).await;
            let (mut client,code)=socks(address,1,&[127,0,0,1],port,1).await;assert_eq!(code,0);
            client.write_all(&[0,1,2,3,4]).await.unwrap();
            let mut rest=Vec::new();let _=client.read_to_end(&mut rest).await;assert!(rest.is_empty());let _=task.await;
            assert!(tokio::time::timeout(Duration::from_millis(100),management.accept()).await.is_err(),"the proxy must not connect to the management port");
        }).await.unwrap();
    }
}

#[cfg(test)]
mod reverse_tests {
    use super::*;
    use crate::reverse::{NewRule, ReverseError, ReverseProxies};
    use tokio::io::{AsyncReadExt,AsyncWriteExt};

    fn free_port()->u16 {let l=std::net::TcpListener::bind("127.0.0.1:0").unwrap();l.local_addr().unwrap().port()}
    fn setup(upstream_tls:Option<Arc<rustls::ClientConfig>>)->(Arc<ReverseProxies>,Arc<TrafficStorage>,Arc<CertificateAuthority>,tempfile::TempDir) {
        let dir=tempfile::tempdir().unwrap();let ca=Arc::new(CertificateAuthority::load_or_create(dir.path()).unwrap());
        let storage=TrafficStorage::new(":memory:",1024).unwrap();
        let shared=Shared{intercept:Intercept::new(storage.clone()),storage:storage.clone(),upstream_tls,connections:Arc::new(Semaphore::new(16)),requests:Arc::new(Semaphore::new(8)),body_limit:1024*1024,management_port:None};
        (ReverseProxies::new(ca.clone(),shared,dir.path().join("reverse-proxies.json")),storage,ca,dir)
    }
    /// An HTTP upstream that records the raw request it receives and answers 200 "ok".
    async fn upstream()->(u16,tokio::sync::oneshot::Receiver<String>) {
        let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let port=listener.local_addr().unwrap().port();let (tx,rx)=tokio::sync::oneshot::channel();
        tokio::spawn(async move{let (mut s,_)=listener.accept().await.unwrap();let mut b=vec![0u8;8192];let n=s.read(&mut b).await.unwrap();let _=tx.send(String::from_utf8_lossy(&b[..n]).into_owned());
            let _=s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;});
        (port,rx)
    }
    fn rule(listen:u16,upstream:&str,tls:bool,rewrite_host:bool)->NewRule {NewRule{name:"api".into(),listen:format!("127.0.0.1:{listen}").parse().unwrap(),upstream:upstream.into(),tls,rewrite_host}}
    fn urls(storage:&TrafficStorage)->Vec<String> {storage.list(10,0,&TrafficFilter{workspace:Some(crate::TEMP_WORKSPACE_ID),..Default::default()}).unwrap().into_iter().map(|e|e.url).collect()}
    async fn get(port:u16,path:&str)->String {
        let mut c=TcpStream::connect(("127.0.0.1",port)).await.unwrap();
        c.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut bytes=Vec::new();tokio::time::timeout(Duration::from_secs(10),c.read_to_end(&mut bytes)).await.unwrap().unwrap();String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn requests_reach_the_fixed_upstream_with_its_host_and_are_captured() {
        tokio::time::timeout(Duration::from_secs(20),async{
            let (manager,storage,_ca,_d)=setup(None);
            let (up,seen)=upstream().await;let listen=free_port();
            manager.add(rule(listen,&format!("http://localhost:{up}"),false,true)).await.unwrap();
            let response=get(listen,"/p?x=1").await;assert!(response.starts_with("HTTP/1.1 200")&&response.ends_with("ok"),"{response}");
            let request=seen.await.unwrap();assert!(request.starts_with("GET /p?x=1 HTTP/1.1"),"{request}");assert!(request.to_ascii_lowercase().contains(&format!("host: localhost:{up}")),"{request}");
            assert_eq!(urls(&storage),vec![format!("http://localhost:{up}/p?x=1")]);
            // With Host rewriting off, the upstream sees the address the client used.
            let (up2,seen2)=upstream().await;let listen2=free_port();
            manager.add(rule(listen2,&format!("http://localhost:{up2}"),false,false)).await.unwrap();
            get(listen2,"/h").await;let request=seen2.await.unwrap();assert!(request.to_ascii_lowercase().contains(&format!("host: 127.0.0.1:{listen2}")),"{request}");
        }).await.unwrap();
    }

    #[tokio::test]
    async fn an_https_listener_serves_a_certificate_from_the_slurp_ca() {
        tokio::time::timeout(Duration::from_secs(20),async{
            let (manager,storage,ca,_d)=setup(None);
            let mut roots=rustls::RootCertStore::empty();for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(ca.ca_cert_pem())) {roots.add(cert.unwrap()).unwrap();}
            let mut client=rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();client.alpn_protocols=vec![b"http/1.1".to_vec()];
            let (up,_seen)=upstream().await;let listen=free_port();
            manager.add(rule(listen,&format!("http://localhost:{up}"),true,true)).await.unwrap();
            // The client connects by IP address, so there is no SNI: the certificate carries an IP SAN.
            let stream=TcpStream::connect(("127.0.0.1",listen)).await.unwrap();
            let mut tls=tokio_rustls::TlsConnector::from(Arc::new(client)).connect(rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),stream).await.unwrap();
            tls.write_all(format!("GET /tls HTTP/1.1\r\nHost: 127.0.0.1:{listen}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut bytes=Vec::new();let _=tls.read_to_end(&mut bytes).await;let text=String::from_utf8_lossy(&bytes).into_owned();assert!(text.starts_with("HTTP/1.1 200")&&text.ends_with("ok"),"{text}");
            assert_eq!(urls(&storage),vec![format!("http://localhost:{up}/tls")]);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn rules_are_validated_and_stopped_rules_release_their_port() {
        let (manager,_storage,_ca,_d)=setup(None);let listen=free_port();
        for bad in ["not a url","ftp://x","http://","http://u:p@x","http://x/path","http://x/?q=1","http://x:0"] {
            assert!(matches!(manager.add(rule(free_port(),bad,false,true)).await,Err(ReverseError::Invalid(_))),"{bad}");
        }
        assert!(matches!(manager.add(NewRule{name:"".into(),..rule(free_port(),"http://x",false,true)}).await,Err(ReverseError::Invalid(_))));
        assert!(matches!(manager.add(rule(listen,&format!("http://localhost:{listen}"),false,true)).await,Err(ReverseError::Conflict(_))),"forwarding to itself");
        let added=manager.add(rule(listen,"http://example.com",false,true)).await.unwrap();
        assert!(matches!(manager.add(rule(listen,"http://example.org",false,true)).await,Err(ReverseError::Conflict(_))),"address already used by a rule");
        assert!(matches!(manager.add(rule(free_port(),&format!("http://127.0.0.1:{listen}"),false,true)).await,Err(ReverseError::Conflict(_))),"upstream is another rule's listener");
        assert_eq!(manager.list().await.len(),1);
        // A port taken by something else is reported and nothing is saved.
        let taken=TcpListener::bind("127.0.0.1:0").await.unwrap();let taken_port=taken.local_addr().unwrap().port();
        assert!(matches!(manager.add(rule(taken_port,"http://example.com",false,true)).await,Err(ReverseError::Conflict(_))));
        assert_eq!(manager.list().await.len(),1);
        // Disabling releases the port; enabling takes it again; removing deletes the rule.
        assert!(manager.list().await[0].running);
        manager.set_enabled(&added.rule.id,false).await.unwrap();tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!manager.list().await[0].running);drop(TcpListener::bind(("127.0.0.1",listen)).await.unwrap());
        manager.set_enabled(&added.rule.id,true).await.unwrap();assert!(manager.list().await[0].running);
        manager.remove(&added.rule.id).await.unwrap();assert!(manager.list().await.is_empty());assert!(matches!(manager.remove(&added.rule.id).await,Err(ReverseError::NotFound)));
    }

    #[tokio::test]
    async fn rules_survive_a_restart_and_only_enabled_ones_start() {
        let (manager,_storage,ca,dir)=setup(None);let (on,off)=(free_port(),free_port());
        manager.add(rule(on,"http://example.com",false,true)).await.unwrap();
        let second=manager.add(rule(off,"http://example.org",false,true)).await.unwrap();manager.set_enabled(&second.rule.id,false).await.unwrap();
        drop(manager);tokio::time::sleep(Duration::from_millis(50)).await;
        let storage=TrafficStorage::new(":memory:",1024).unwrap();
        let shared=Shared{intercept:Intercept::new(storage.clone()),storage,upstream_tls:None,connections:Arc::new(Semaphore::new(4)),requests:Arc::new(Semaphore::new(4)),body_limit:1024,management_port:None};
        let again=ReverseProxies::new(ca,shared,dir.path().join("reverse-proxies.json"));
        assert_eq!(again.list().await.len(),2);assert!(again.list().await.iter().all(|r|!r.running));
        again.start_all().await;let status=again.list().await;
        assert!(status.iter().find(|r|r.rule.listen.port()==on).unwrap().running);assert!(!status.iter().find(|r|r.rule.listen.port()==off).unwrap().running);
    }
}
