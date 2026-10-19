//! Bounded HTTP/1 framing diagnostics. No pooled sockets, embedded requests or cache writes.
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Input {
    url: String,
    variant: String,
    timeout_ms: u64,
}
fn wire(url: &reqwest::Url, variant: &str) -> Result<String, String> {
    let host = url.host_str().ok_or("Missing host")?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let target = format!(
        "{}{}",
        url.path(),
        url.query().map(|q| format!("?{q}")).unwrap_or_default()
    );
    if target.len() > 12000 || target.chars().any(|c| c.is_control() || c == ' ') {
        return Err("Invalid request target".into());
    }
    let (headers, body) = match variant {
        "control" => ("Content-Length: 5\r\n", "0\r\n\r\n"),
        "chunked" => ("Transfer-Encoding: chunked\r\n", "0\r\n\r\n"),
        "cl-te" => (
            "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
            "0\r\n\r\n",
        ),
        "te-cl" => (
            "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
            "0\r\n\r\n",
        ),
        "duplicate-cl" => ("Content-Length: 5\r\nContent-Length: 0\r\n", "0\r\n\r\n"),
        _ => return Err("Unknown framing variant".into()),
    };
    Ok(format!("GET {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept-Encoding: identity\r\nCache-Control: no-store\r\n{headers}\r\n{body}"))
}
fn complete_response(bytes: &[u8], eof: bool) -> Result<bool, String> {
    let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") else {
        return Ok(false);
    };
    let headers = std::str::from_utf8(&bytes[..end]).map_err(|_| "Invalid response headers")?;
    let body = &bytes[end + 4..];
    let fields: Vec<_> = headers
        .split("\r\n")
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .collect();
    if fields.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.trim().eq_ignore_ascii_case("chunked")
    }) {
        let mut offset = 0;
        loop {
            let Some(line) = body[offset..].windows(2).position(|b| b == b"\r\n") else {
                return Ok(false);
            };
            let raw = std::str::from_utf8(&body[offset..offset + line])
                .map_err(|_| "Invalid chunk size")?;
            let size = usize::from_str_radix(raw.split(';').next().unwrap().trim(), 16)
                .map_err(|_| "Invalid chunk size")?;
            offset += line + 2;
            if size == 0 {
                return Ok(body[offset..].starts_with(b"\r\n")
                    || body[offset..].windows(4).any(|b| b == b"\r\n\r\n"));
            }
            if size > 32000 || offset.saturating_add(size).saturating_add(2) > body.len() {
                return Ok(false);
            }
            offset += size;
            if &body[offset..offset + 2] != b"\r\n" {
                return Err("Invalid chunk terminator".into());
            }
            offset += 2;
        }
    }
    let lengths: Vec<_> = fields
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .collect();
    if let Some((_, value)) = lengths.first() {
        let size: usize = value
            .trim()
            .parse()
            .map_err(|_| "Invalid response Content-Length")?;
        if lengths.iter().any(|(_, v)| v.trim() != value.trim()) {
            return Err("Conflicting response framing".into());
        }
        return Ok(body.len() >= size);
    }
    let status = headers
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("");
    Ok(matches!(status, "204" | "304") || eof)
}
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
async fn execute(input: Input) -> Result<Value, String> {
    if input.url.len() > 12000 || !(1000..=10000).contains(&input.timeout_ms) {
        return Err("Invalid protocol probe limits".into());
    }
    let url = reqwest::Url::parse(&input.url).map_err(|e| e.to_string())?;
    crate::http_target::validate(&url)?;
    let raw_request = wire(&url, &input.variant)?;
    let start = Instant::now();
    let addresses = crate::http_target::resolve(&url).await?;
    let mut connected = None;
    for address in addresses {
        if let Ok(socket) = tokio::net::TcpStream::connect(address).await {
            connected = Some(socket);
            break;
        }
    }
    let socket = connected.ok_or("Cannot connect to target")?;
    let mut stream: Box<dyn Stream> = if url.scheme() == "https" {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = rustls::pki_types::ServerName::try_from(
            url.host_str().unwrap().trim_matches(['[', ']']).to_owned(),
        )
        .map_err(|e| e.to_string())?;
        Box::new(
            tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, socket)
                .await
                .map_err(|e| e.to_string())?,
        )
    } else {
        Box::new(socket)
    };
    stream
        .write_all(raw_request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            if !complete_response(&bytes, true)? {
                return Err("Incomplete HTTP response body".into());
            }
            break;
        }
        if bytes.len() + n > 32000 {
            return Err("Raw response exceeds 32 KB diagnostic limit".into());
        }
        bytes.extend_from_slice(&chunk[..n]);
        if complete_response(&bytes, false)? {
            break;
        }
    }
    let raw_response = String::from_utf8_lossy(&bytes).to_string();
    let status: u16 = raw_response
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1."))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .filter(|n| (100..=599).contains(n))
        .ok_or("No complete HTTP/1 response")?;
    if !raw_response.contains("\r\n\r\n") {
        return Err("Incomplete HTTP headers".into());
    }
    Ok(
        json!({"ok":true,"rawRequest":raw_request,"rawResponse":raw_response,"status":status,"duration":start.elapsed().as_millis(),"size":bytes.len()}),
    )
}
pub(crate) async fn probe(Json(input): Json<Input>) -> Json<Value> {
    static SLOTS: OnceLock<Semaphore> = OnceLock::new();
    let Ok(_permit) = SLOTS.get_or_init(|| Semaphore::new(4)).try_acquire() else {
        return Json(json!({"ok":false,"error":"Protocol probe capacity reached"}));
    };
    let timeout = input.timeout_ms.min(10000);
    let value = match tokio::time::timeout(Duration::from_millis(timeout), execute(input)).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => json!({"ok":false,"error":error}),
        Err(_) => json!({"ok":false,"error":"Protocol probe timed out; no finding established"}),
    };
    Json(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn variants_are_fixed_and_contain_no_embedded_request() {
        let url = reqwest::Url::parse("http://127.0.0.1:8088/products?q=x").unwrap();
        for variant in ["control", "chunked", "cl-te", "te-cl", "duplicate-cl"] {
            let raw = wire(&url, variant).unwrap();
            assert!(raw.starts_with("GET /products?q=x HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n"));
            assert_eq!(raw.matches("HTTP/1.1").count(), 1);
            assert!(raw.ends_with("\r\n\r\n0\r\n\r\n"));
        }
        assert!(wire(&url, "custom").is_err());
    }
    #[tokio::test]
    async fn sends_exact_wire_on_fresh_connections_and_bounds_targets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n])
                .contains("Content-Length: 0\r\nTransfer-Encoding: chunked"));
            socket
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let value = execute(Input {
            url: format!("http://{addr}/test"),
            variant: "cl-te".into(),
            timeout_ms: 1000,
        })
        .await
        .unwrap();
        assert_eq!(value["status"], 400);
        server.await.unwrap();
        assert!(execute(Input {
            url: "http://0.0.0.0/".into(),
            variant: "control".into(),
            timeout_ms: 1000
        })
        .await
        .is_err());
        assert!(execute(Input {
            url: "file:///etc/passwd".into(),
            variant: "control".into(),
            timeout_ms: 1000
        })
        .await
        .is_err());
    }
}
