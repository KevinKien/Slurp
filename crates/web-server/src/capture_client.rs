//! `slurp client`: uploads what the local proxy captured to a Slurp server.
//!
//! The local proxy records into a spool (a local workspace). The uploader sends the oldest spooled
//! entries and removes them only after the server has accepted them, so nothing is lost when the
//! server or the network is down, and retries are safe because the server upserts by entry id.
use crate::ingest::{Batch, BatchResult, Hello, WireEntry, PROTOCOL};
use anyhow::{bail, Context, Result};
use flate2::{write::GzEncoder, Compression};
use proxy_core::{redact_json_text, TrafficEntry, TrafficStorage};
use std::sync::Arc;
use std::time::Duration;

const BATCH_ENTRIES: usize = 25;
const BATCH_BYTES: usize = 16 * 1024 * 1024;
/// Entries kept while the server is unreachable; the oldest are dropped beyond this.
const SPOOL_LIMIT: u64 = 100_000;

#[derive(Clone)]
pub struct ClientConfig {
    pub server: String,
    pub token: String,
    /// Hosts to upload; `None` uploads everything. `*.example.com` matches subdomains.
    pub scope: Option<Vec<String>>,
    pub redact: bool,
    pub allow_insecure: bool,
    /// PEM of a private CA that signed the server's certificate.
    pub ca_cert: Option<Vec<u8>>,
}

pub fn in_scope(scope: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    scope.iter().any(|pattern| {
        let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        match pattern.strip_prefix("*.") {
            Some(suffix) => host.len() > suffix.len() && host.ends_with(&format!(".{suffix}")),
            None => host == pattern,
        }
    })
}

fn endpoint(config: &ClientConfig, path: &str) -> String {
    format!("{}{path}", config.server.trim_end_matches('/'))
}

/// Refuses to send a token and traffic over plain HTTP to anything but this machine.
pub fn validate_server(config: &ClientConfig) -> Result<()> {
    let url = reqwest::Url::parse(&config.server).context("--server must be a URL such as https://slurp.example.com")?;
    let loopback = url.host_str().is_some_and(|h| h == "localhost" || h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()));
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback || config.allow_insecure => Ok(()),
        "http" => bail!("{} is plain HTTP: your token and traffic would be readable on the network. Use https:// (or pass --allow-insecure-http)", config.server),
        other => bail!("unsupported scheme {other}"),
    }
}

fn http_client(config: &ClientConfig) -> Result<reqwest::Client> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(120)).connect_timeout(Duration::from_secs(10));
    for der in proxy_core::trust::extra_certificates() {
        builder = builder.add_root_certificate(reqwest::Certificate::from_der(&der)?);
    }
    if let Some(pem) = &config.ca_cert {
        let certificates = reqwest::Certificate::from_pem_bundle(pem).context("--ca-cert is not a valid PEM certificate file")?;
        if certificates.is_empty() {
            bail!("--ca-cert contains no certificate");
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    Ok(builder.build()?)
}

/// Confirms the token and returns which workspace this client uploads to.
pub async fn hello(config: &ClientConfig) -> Result<Hello> {
    validate_server(config)?;
    let response = http_client(config)?
        .get(endpoint(config, "/api/ingest/hello"))
        .bearer_auth(&config.token)
        .send()
        .await
        .with_context(|| format!("cannot reach {}", config.server))?;
    let status = response.status();
    if !status.is_success() {
        let detail = response.json::<serde_json::Value>().await.ok().and_then(|v| v["error"].as_str().map(str::to_owned)).unwrap_or_else(|| status.to_string());
        bail!("server refused this client: {detail}");
    }
    let hello: Hello = response.json().await.context("unexpected response from server")?;
    if hello.protocol != PROTOCOL {
        bail!("server speaks protocol {}, this client speaks {PROTOCOL}; update the older one", hello.protocol);
    }
    Ok(hello)
}

fn encode(entries: &[TrafficEntry], redact: bool) -> Result<Vec<u8>> {
    let wire: Vec<WireEntry> = entries
        .iter()
        .map(|entry| {
            let mut wire = WireEntry::from(entry);
            if redact {
                wire.request_headers = redact_json_text(&wire.request_headers);
                wire.response_headers = redact_json_text(&wire.response_headers);
            }
            wire
        })
        .collect();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    serde_json::to_writer(&mut encoder, &Batch { protocol: PROTOCOL, entries: wire })?;
    Ok(encoder.finish()?)
}

enum Sent {
    Accepted(BatchResult),
    /// The server will not take this right now; try again later.
    Retry(String),
    /// Too large for one request.
    TooLarge,
}

async fn send(client: &reqwest::Client, config: &ClientConfig, entries: &[TrafficEntry]) -> Sent {
    let body = match encode(entries, config.redact) {
        Ok(body) => body,
        Err(e) => return Sent::Retry(format!("could not encode batch: {e}")),
    };
    let response = client
        .post(endpoint(config, "/api/ingest/batch"))
        .bearer_auth(&config.token)
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "gzip")
        .body(body)
        .send()
        .await;
    match response {
        Err(e) => Sent::Retry(format!("cannot reach server: {}", e.without_url())),
        Ok(r) if r.status().is_success() => match r.json::<BatchResult>().await {
            Ok(result) => Sent::Accepted(result),
            Err(_) => Sent::Retry("unexpected response from server".into()),
        },
        Ok(r) if r.status() == reqwest::StatusCode::PAYLOAD_TOO_LARGE => Sent::TooLarge,
        Ok(r) => {
            let status = r.status();
            let detail = r.json::<serde_json::Value>().await.ok().and_then(|v| v["error"].as_str().map(str::to_owned)).unwrap_or_default();
            Sent::Retry(format!("server answered {status} {detail}"))
        }
    }
}

/// Uploads the spool forever. `workspace` is the local spool workspace of `storage`.
pub async fn run_uploader(storage: Arc<TrafficStorage>, config: ClientConfig, workspace: String) -> Result<()> {
    validate_server(&config)?;
    let client = http_client(&config)?;
    let mut backoff = Duration::from_secs(1);
    let mut failing = false;
    let mut batch_limit = BATCH_ENTRIES;
    let mut idle_ticks = 0u32;
    loop {
        let pending = {
            let storage = storage.clone();
            let workspace = workspace.clone();
            tokio::task::spawn_blocking(move || storage.spooled_entries(&workspace, batch_limit)).await??
        };
        if pending.is_empty() {
            idle_ticks += 1;
            if idle_ticks % 1200 == 0 {
                // About every ten minutes: tidy what the client does not forward.
                let _ = storage.clear_websocket_history(&workspace);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }
        idle_ticks = 0;

        let mut upload: Vec<TrafficEntry> = Vec::new();
        let mut done: Vec<String> = Vec::new();
        let mut bytes = 0usize;
        for (_, entry) in pending {
            if config.scope.as_ref().is_some_and(|scope| !in_scope(scope, &entry.host)) {
                done.push(entry.id); // out of scope: never leaves this machine
                continue;
            }
            let size = entry.request_body.len() + entry.response_body.len();
            if !upload.is_empty() && bytes + size > BATCH_BYTES {
                break;
            }
            bytes += size;
            done.push(entry.id.clone());
            upload.push(entry);
        }

        if upload.is_empty() {
            storage.remove_entries(&done)?;
            continue;
        }
        match send(&client, &config, &upload).await {
            Sent::Accepted(result) => {
                storage.remove_entries(&done)?;
                if failing {
                    println!("✅ Server reachable again; uploading resumed");
                    failing = false;
                }
                backoff = Duration::from_secs(1);
                batch_limit = BATCH_ENTRIES;
                if result.rejected > 0 {
                    eprintln!("⚠️  Server rejected {} of {} requests", result.rejected, upload.len());
                }
                let _ = storage.trim_spool(&workspace, SPOOL_LIMIT);
                println!("↑ uploaded {} request(s)", result.accepted);
            }
            Sent::TooLarge if upload.len() > 1 => batch_limit = 1,
            Sent::TooLarge => {
                eprintln!("⚠️  Dropping a request too large for the server ({})", upload[0].url);
                storage.remove_entries(&done)?;
            }
            Sent::Retry(reason) => {
                if !failing {
                    eprintln!("⚠️  Upload paused: {reason}. Traffic is kept locally and retried.");
                    failing = true;
                }
                let _ = storage.trim_spool(&workspace, SPOOL_LIMIT);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_matches_exact_hosts_and_wildcard_subdomains_only() {
        let scope = vec!["api.example.com".to_string(), "*.corp.test".to_string()];
        assert!(in_scope(&scope, "api.example.com"));
        assert!(in_scope(&scope, "API.example.com."));
        assert!(in_scope(&scope, "a.corp.test"));
        assert!(!in_scope(&scope, "corp.test"));
        assert!(!in_scope(&scope, "evilcorp.test"));
        assert!(!in_scope(&scope, "example.com"));
        assert!(!in_scope(&[], "anything"));
    }

    #[test]
    fn plain_http_is_only_allowed_to_this_machine_or_explicitly() {
        let config = |server: &str, allow| ClientConfig { server: server.into(), token: "t".into(), scope: None, redact: false, allow_insecure: allow, ca_cert: None };
        assert!(validate_server(&config("https://slurp.example.com", false)).is_ok());
        assert!(validate_server(&config("http://127.0.0.1:5174", false)).is_ok());
        assert!(validate_server(&config("http://localhost:5174", false)).is_ok());
        assert!(validate_server(&config("http://slurp.example.com", false)).is_err());
        assert!(validate_server(&config("http://slurp.example.com", true)).is_ok());
        assert!(validate_server(&config("ftp://x", true)).is_err());
    }

    fn entry(host: &str) -> TrafficEntry {
        let mut e = TrafficEntry::new_request("GET", &format!("https://{host}/x"), host, "/x", "https", "{\"authorization\":[\"Bearer sekret\"],\"accept\":[\"*/*\"]}", vec![1, 2, 3], None);
        e.status_code = 200;
        e.response_body = vec![0, 255];
        e
    }

    #[tokio::test]
    async fn client_uploads_only_scoped_redacted_traffic_into_its_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let server_storage = TrafficStorage::new(dir.path().join("server.db").to_str().unwrap(), 1 << 20).unwrap();
        let workspace = server_storage.create_workspace("Remote").unwrap();
        let token = crate::ingest::new_token();
        server_storage.create_capture_client("laptop", &workspace.id, &crate::ingest::hash_token(&token)).unwrap();
        let access = crate::access::ApiAccess::load(&dir.path().join("access")).unwrap();
        let access_token = access.token().to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let intercept = proxy_core::Intercept::new(server_storage.clone());
        tokio::spawn(crate::serve(listener, server_storage.clone(), intercept, proxy_core::ProxyControl::disabled(), crate::certificate::PublicCaCertificate(Arc::from(Vec::new())), access));

        let config = ClientConfig { server: format!("http://127.0.0.1:{port}"), token: token.clone(), scope: Some(vec!["a.test".into()]), redact: true, allow_insecure: false, ca_cert: None };
        let hello = hello(&config).await.unwrap();
        assert_eq!((hello.client.as_str(), hello.workspace.as_str()), ("laptop", "Remote"));
        assert!(super::hello(&ClientConfig { token: "slurp_c_wrong".into(), ..config.clone() }).await.is_err());

        let spool = TrafficStorage::new(":memory:", 1 << 20).unwrap();
        spool.set_active_workspace("default").unwrap();
        let (kept, private) = (entry("a.test"), entry("b.test"));
        spool.insert(&kept).unwrap();
        spool.insert(&private).unwrap();
        let uploader = tokio::spawn(run_uploader(spool.clone(), config.clone(), "default".into()));
        let mut stored = None;
        for _ in 0..100 {
            stored = server_storage.get(&kept.id).unwrap();
            if stored.is_some() && spool.spool_len("default").unwrap() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        uploader.abort();
        let stored = stored.expect("entry reached the server");
        assert_eq!(stored.workspace_id, workspace.id);
        assert_eq!(stored.source, "client:laptop");
        assert_eq!(stored.request_body, vec![1, 2, 3]);
        assert_eq!(stored.response_body, vec![0, 255]);
        assert!(!stored.request_headers.contains("sekret") && stored.request_headers.contains("*/*"), "{}", stored.request_headers);
        assert!(server_storage.get(&private.id).unwrap().is_none(), "out-of-scope traffic never leaves the machine");
        assert_eq!(spool.spool_len("default").unwrap(), 0);

        // The capture token opens nothing but the ingest endpoints, and the admin token is not a capture token.
        let http = http_client(&config).unwrap();
        let read = http.get(format!("http://127.0.0.1:{port}/api/traffic")).bearer_auth(&token).send().await.unwrap();
        assert_eq!(read.status(), reqwest::StatusCode::UNAUTHORIZED);
        let admin = http.get(format!("http://127.0.0.1:{port}/api/ingest/hello")).bearer_auth(access_token).send().await.unwrap();
        assert_eq!(admin.status(), reqwest::StatusCode::UNAUTHORIZED);

        // A client cannot overwrite traffic that is not its own, and revoking stops it.
        let clash = server_storage.list_capture_clients().unwrap();
        let identity = proxy_core::ClientIdentity { id: "x".into(), name: "other".into(), workspace_id: workspace.id.clone() };
        assert!(matches!(server_storage.ingest_entry(&kept, &identity), Err(proxy_core::IngestError::Conflict)));
        assert!(server_storage.delete_capture_client(&clash[0].id).unwrap());
        assert!(super::hello(&config).await.is_err());
    }
}
