//! Bounded self-hosted OAST collector. Callback listeners never expose the API.
use axum::{
    extract::{ConnectInfo, Path},
    http::StatusCode,
    routing::any,
    Extension, Json, Router,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    id: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_name: Option<String>,
    expires_at: String,
    events: Vec<Event>,
    #[serde(skip)]
    deadline: Instant,
}
#[derive(Clone, Serialize)]
struct Event {
    protocol: &'static str,
    timestamp: String,
    peer: String,
    detail: String,
}
#[derive(Clone)]
pub struct Collector(Arc<Inner>);
struct Inner {
    base: Option<reqwest::Url>,
    domain: Option<String>,
    dns_address: Option<std::net::Ipv4Addr>,
    error: Option<String>,
    probes: Mutex<HashMap<String, Probe>>,
}
pub struct Runtime(Vec<JoinHandle<()>>);
impl Drop for Runtime {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}
fn token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && (2..=19).contains(&value.split('.').count())
        && value.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && !p.starts_with('-')
                && !p.ends_with('-')
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
impl Collector {
    fn new(
        base: Option<reqwest::Url>,
        domain: Option<String>,
        dns_address: Option<std::net::Ipv4Addr>,
        error: Option<String>,
    ) -> Self {
        Self(Arc::new(Inner {
            base,
            domain,
            dns_address,
            error,
            probes: Mutex::new(HashMap::new()),
        }))
    }
    fn issue(&self) -> Result<Probe, &'static str> {
        let mut probes = self.0.probes.lock().unwrap();
        probes.retain(|_, p| p.deadline > Instant::now());
        let base = self
            .0
            .base
            .as_ref()
            .ok_or("OAST is not configured. Set SLURP_OAST_PUBLIC_URL and restart Slurp.")?;
        if probes.len() >= 1024 {
            return Err("OAST probe capacity reached; wait for expired probes");
        }
        let id = token();
        let dns_name = self.0.domain.as_ref().map(|d| format!("{id}.{d}"));
        let mut url = base.clone();
        if let Some(name) = &dns_name {
            url.set_host(Some(name))
                .map_err(|_| "Invalid OAST domain")?;
        }
        url.set_path(&format!(
            "{}/slurp-oast/{id}",
            base.path().trim_end_matches('/')
        ));
        let probe = Probe {
            id: id.clone(),
            url: url.to_string(),
            dns_name,
            expires_at: (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
            events: vec![],
            deadline: Instant::now() + Duration::from_secs(600),
        };
        probes.insert(id, probe.clone());
        Ok(probe)
    }
    fn poll(&self, id: &str) -> Option<Probe> {
        self.0
            .probes
            .lock()
            .unwrap()
            .get(id)
            .filter(|p| p.deadline > Instant::now())
            .cloned()
    }
    fn record(&self, id: &str, protocol: &'static str, peer: SocketAddr, detail: String) -> bool {
        let mut probes = self.0.probes.lock().unwrap();
        let Some(probe) = probes.get_mut(id).filter(|p| p.deadline > Instant::now()) else {
            return false;
        };
        if probe.events.len() < 16 {
            probe.events.push(Event {
                protocol,
                timestamp: chrono::Utc::now().to_rfc3339(),
                peer: peer.ip().to_string(),
                detail: detail.chars().take(500).collect(),
            });
        }
        true
    }
}
async fn callback(
    Extension(collector): Extension<Collector>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    request: axum::extract::Request,
) -> StatusCode {
    if request.method() == axum::http::Method::OPTIONS {
        return StatusCode::METHOD_NOT_ALLOWED;
    }
    if collector.record(
        &id,
        "http",
        peer,
        format!("{} {}", request.method(), request.uri().path()),
    ) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}
fn callback_router(collector: Collector) -> Router {
    Router::new()
        .route("/slurp-oast/:id", any(callback))
        .layer(Extension(collector))
}
// Small authoritative responder: one uncompressed question, no recursion, no
// forwarding, bounded replies. Only live random probe names are recorded.
fn dns_response(collector: &Collector, packet: &[u8], peer: SocketAddr) -> Option<Vec<u8>> {
    if packet.len() < 17 || packet.len() > 512 || packet[2] & 0xfe != 0 || packet[4..6] != [0, 1] {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let length = *packet.get(at)? as usize;
        at += 1;
        if length == 0 {
            break;
        }
        if length > 63 || labels.len() > 20 {
            return None;
        }
        let label = std::str::from_utf8(packet.get(at..at + length)?).ok()?;
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
        labels.push(label.to_ascii_lowercase());
        at += length;
    }
    let tail = packet.get(at..at + 4)?;
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    if tail[2..4] != [0, 1] {
        return None;
    }
    let domain = collector.0.domain.as_ref()?;
    let (id, rest) = labels.split_first()?;
    let known = rest.join(".") == *domain
        && id.len() == 32
        && collector.record(
            id,
            "dns",
            peer,
            format!("{} type {qtype}", labels.join(".")),
        );
    let answer = known && qtype == 1 && collector.0.dns_address.is_some();
    let mut response = packet[..at + 4].to_vec();
    response[2] = 0x84;
    response[3] = if known { 0 } else { 3 };
    response[6..12].fill(0);
    if answer {
        response[7] = 1;
    }
    if answer {
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
        response.extend_from_slice(&collector.0.dns_address.unwrap().octets());
    }
    Some(response)
}
async fn serve_dns(socket: UdpSocket, collector: Collector) {
    let mut data = [0u8; 512];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut data).await else {
            break;
        };
        if let Some(reply) = dns_response(&collector, &data[..len], peer) {
            let _ = socket.send_to(&reply, peer).await;
        }
    }
}
pub async fn start() -> (Collector, Runtime) {
    let disabled = |error: String| {
        (
            Collector::new(None, None, None, Some(error)),
            Runtime(vec![]),
        )
    };
    let Ok(raw) = std::env::var("SLURP_OAST_PUBLIC_URL") else {
        return disabled(
            "Set SLURP_OAST_PUBLIC_URL to a callback address reachable by the target.".into(),
        );
    };
    let Ok(base) = reqwest::Url::parse(&raw) else {
        return disabled("Invalid SLURP_OAST_PUBLIC_URL".into());
    };
    if super::http_target::validate(&base).is_err()
        || base.query().is_some()
        || base.fragment().is_some()
        || raw.len() > 1000
    {
        return disabled(
            "Invalid OAST public URL: expected HTTP(S) without credentials, query or fragment"
                .into(),
        );
    }
    let domain = std::env::var("SLURP_OAST_DNS_DOMAIN")
        .ok()
        .map(|s| s.trim_end_matches('.').to_ascii_lowercase());
    if domain.as_ref().is_some_and(|d| !valid_domain(d)) {
        return disabled("Invalid SLURP_OAST_DNS_DOMAIN".into());
    }
    let dns_address = match std::env::var("SLURP_OAST_DNS_ADDRESS") {
        Ok(s) => match s.parse() {
            Ok(ip) => Some(ip),
            Err(_) => return disabled("Invalid SLURP_OAST_DNS_ADDRESS: expected IPv4".into()),
        },
        Err(_) => None,
    };
    let listener = match TcpListener::bind(
        std::env::var("SLURP_OAST_LISTEN").unwrap_or("127.0.0.1:8899".into()),
    )
    .await
    {
        Ok(l) => l,
        Err(e) => return disabled(format!("OAST HTTP listener: {e}")),
    };
    let socket = if domain.is_some() {
        match UdpSocket::bind(
            std::env::var("SLURP_OAST_DNS_LISTEN").unwrap_or("127.0.0.1:5354".into()),
        )
        .await
        {
            Ok(s) => Some(s),
            Err(e) => return disabled(format!("OAST DNS listener: {e}")),
        }
    } else {
        None
    };
    let collector = Collector::new(Some(base), domain, dns_address, None);
    let router = callback_router(collector.clone());
    let mut tasks = vec![tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("OAST HTTP listener stopped: {e}");
        }
    })];
    if let Some(socket) = socket {
        tasks.push(tokio::spawn(serve_dns(socket, collector.clone())));
    }
    (collector, Runtime(tasks))
}
pub async fn status(Extension(c): Extension<Collector>) -> Json<Value> {
    Json(
        json!({"enabled":c.0.base.is_some(),"http":c.0.base.is_some(),"dns":c.0.domain.is_some(),"error":c.0.error}),
    )
}
pub async fn issue(
    Extension(c): Extension<Collector>,
) -> Result<Json<Probe>, (StatusCode, Json<Value>)> {
    c.issue()
        .map(Json)
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":e}))))
}
pub async fn poll(
    Extension(c): Extension<Collector>,
    Path(id): Path<String>,
) -> Result<Json<Probe>, StatusCode> {
    c.poll(&id).map(Json).ok_or(StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn collector() -> Collector {
        Collector::new(
            Some(reqwest::Url::parse("http://127.0.0.1:8899").unwrap()),
            Some("oast.example.test".into()),
            Some("192.0.2.10".parse().unwrap()),
            None,
        )
    }
    fn question(name: &str) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for part in name.split('.') {
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        packet
    }
    #[test]
    fn oast_correlates_only_live_probes_and_bounds_storage() {
        let c = collector();
        let a = c.issue().unwrap();
        let b = c.issue().unwrap();
        let peer = "127.0.0.1:1234".parse().unwrap();
        assert_ne!(a.id, b.id);
        assert!(a.url.contains(&format!("{}.oast.example.test", a.id)));
        assert!(!c.record("unknown", "http", peer, "GET /".into()));
        for _ in 0..32 {
            assert!(c.record(&a.id, "http", peer, "x".repeat(2000)));
        }
        assert_eq!(c.poll(&a.id).unwrap().events.len(), 16);
        assert_eq!(c.poll(&a.id).unwrap().events[0].detail.len(), 500);
        assert!(c.poll(&b.id).unwrap().events.is_empty());
        c.0.probes.lock().unwrap().get_mut(&a.id).unwrap().deadline =
            Instant::now() - Duration::from_secs(1);
        assert!(c.poll(&a.id).is_none());
        assert!(!c.record(&a.id, "http", peer, "GET /".into()));
        for _ in 0..1023 {
            c.issue().unwrap();
        }
        assert!(c.issue().is_err());
    }
    #[test]
    fn oast_dns_has_no_recursion_and_rejects_malformed_or_unrelated_names() {
        let c = collector();
        let p = c.issue().unwrap();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let packet = question(p.dns_name.as_ref().unwrap());
        let reply = dns_response(&c, &packet, peer).unwrap();
        assert_eq!(&reply[..2], &packet[..2]);
        assert_eq!(reply[2], 0x84);
        assert_eq!(reply[7], 1);
        assert_eq!(&reply[reply.len() - 4..], &[192, 0, 2, 10]);
        assert_eq!(c.poll(&p.id).unwrap().events[0].protocol, "dns");
        let unknown = dns_response(&c, &question("unknown.oast.example.test"), peer).unwrap();
        assert_eq!(unknown[3], 3);
        assert_eq!(unknown[7], 0);
        assert!(dns_response(&c, &[0; 12], peer).is_none());
        let mut bad = packet.clone();
        bad[12] = 0xc0;
        assert!(dns_response(&c, &bad, peer).is_none());
        let mut response = packet;
        response[2] = 0x80;
        assert!(dns_response(&c, &response, peer).is_none());
    }
    #[tokio::test]
    async fn oast_http_listener_is_separate_and_records_real_callbacks() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let c = Collector::new(
            Some(reqwest::Url::parse(&format!("http://{addr}")).unwrap()),
            None,
            None,
            None,
        );
        let probe = c.issue().unwrap();
        let control = c.issue().unwrap();
        let router = callback_router(c.clone());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap()
        });
        let _runtime = Runtime(vec![task]);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        assert_eq!(client.get(&probe.url).send().await.unwrap().status(), 204);
        assert_eq!(c.poll(&probe.id).unwrap().events.len(), 1);
        assert!(c.poll(&control.id).unwrap().events.is_empty());
        assert_eq!(
            client
                .get(format!("http://{addr}/api/scan/oast/probes"))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
        assert_eq!(
            client
                .get(format!("http://{addr}/slurp-oast/unknown"))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }
    #[tokio::test]
    async fn oast_shared_sender_correlates_callbacks_from_local_ssrf_fixture() {
        let callback_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let callback_addr = callback_listener.local_addr().unwrap();
        let collector = Collector::new(
            Some(reqwest::Url::parse(&format!("http://{callback_addr}")).unwrap()),
            None,
            None,
            None,
        );
        let router = callback_router(collector.clone());
        let callback_task = tokio::spawn(async move {
            axum::serve(
                callback_listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap()
        });
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target=Router::new().route("/fetch",axum::routing::get(|axum::extract::Query(query):axum::extract::Query<HashMap<String,String>>| async move {
            let url=reqwest::Url::parse(query.get("url").unwrap()).unwrap();
            let client=crate::http_target::client(&url,2000).await.unwrap();
            client.get(url).send().await.unwrap();"done"
        }));
        let target_task =
            tokio::spawn(async move { axum::serve(target_listener, target).await.unwrap() });
        let _runtime = Runtime(vec![callback_task, target_task]);
        let a = collector.issue().unwrap();
        let b = collector.issue().unwrap();
        let control = collector.issue().unwrap();
        for probe in [&a, &b] {
            let mut url = reqwest::Url::parse(&format!("http://{target_addr}/fetch")).unwrap();
            url.query_pairs_mut().append_pair("url", &probe.url);
            let response = crate::http_sender::send(Json(
                json!({"method":"GET","url":url.as_str(),"headers":{},"body":"","timeout":3000}),
            ))
            .await
            .0;
            assert_eq!(response["ok"], true);
            assert_eq!(response["status"], 200);
            assert_eq!(collector.poll(&probe.id).unwrap().events.len(), 1);
        }
        assert!(collector.poll(&control.id).unwrap().events.is_empty());
    }
    #[tokio::test]
    async fn oast_dns_listener_correlates_real_udp_queries() {
        let c = collector();
        let probe = c.issue().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let _runtime = Runtime(vec![tokio::spawn(serve_dns(socket, c.clone()))]);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&question(probe.dns_name.as_ref().unwrap()), addr)
            .await
            .unwrap();
        let mut bytes = [0u8; 512];
        let (len, peer) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(peer, addr);
        assert_eq!(bytes[7], 1);
        assert_eq!(&bytes[len - 4..len], &[192, 0, 2, 10]);
        let observed = c.poll(&probe.id).unwrap();
        assert_eq!(observed.events.len(), 1);
        assert_eq!(observed.events[0].protocol, "dns");
    }
}
