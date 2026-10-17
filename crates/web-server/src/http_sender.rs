//! Stateless browser Replay sender. Callers own workspace persistence and script execution.
use axum::Json;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub(crate) fn validate(data: &Value) -> Result<(reqwest::Url, u64), String> {
    super::replay::validate_request(data).map_err(|(_, body)| {
        body.0["error"]
            .as_str()
            .unwrap_or("Invalid request")
            .to_string()
    })?;
    let url = reqwest::Url::parse(data["url"].as_str().unwrap()).map_err(|e| e.to_string())?;
    let host = url.host_str().unwrap_or("");
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || host.parse::<std::net::IpAddr>().is_ok()
        || !host.contains('.')
        || ["localhost", "local", "internal", "test", "invalid"]
            .iter()
            .any(|s| host == *s || host.ends_with(&format!(".{s}")))
    {
        return Err("Replay supports public HTTPS hosts only.".into());
    }
    let timeout = data["timeout"]
        .as_u64()
        .filter(|n| (1000..=30000).contains(n))
        .ok_or("Timeout must be between 1000 and 30000 ms")?;
    Ok((url, timeout))
}
fn allowed_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ![
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "upgrade",
        "expect",
        "forwarded",
        "keep-alive",
        "te",
        "trailer",
    ]
    .contains(&name.as_str())
        && !["proxy-", "cf-", "x-forwarded-"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
}
async fn read_response(mut response: reqwest::Response, start: Instant) -> Result<Value, String> {
    if response
        .headers()
        .get("content-encoding")
        .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err("Unsupported Content-Encoding in response".into());
    }
    let status = response.status();
    let mut headers = serde_json::Map::new();
    for name in response.headers().keys() {
        let values: Vec<_> = response
            .headers()
            .get_all(name)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect();
        headers.insert(name.to_string(), json!(values.join(", ")));
    }
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if bytes.len() + chunk.len() > 2_000_000 {
            return Err("Response exceeds the 2 MB limit.".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(
        json!({"ok":true,"status":status.as_u16(),"statusText":status.canonical_reason().unwrap_or(""),
        "duration":start.elapsed().as_millis() as u64,"size":bytes.len(),"responseHeaders":headers,
        "setCookies":cookies,"responseBody":String::from_utf8_lossy(&bytes)}),
    )
}
async fn execute(data: &Value, url: reqwest::Url, timeout: u64) -> Result<Value, String> {
    let start = Instant::now();
    let host = url.host_str().unwrap();
    let addresses: Vec<_> =
        tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, 443)))
            .await
            .map_err(|_| "DNS lookup timed out".to_string())?
            .map_err(|e| e.to_string())?
            .collect();
    if addresses.is_empty() || addresses.iter().any(|a| !super::replay::public_ip(a.ip())) {
        return Err("This host is unavailable or is not a public address.".into());
    }
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(timeout))
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(|e| e.to_string())?;
    let mut request = client.request(
        data["method"]
            .as_str()
            .unwrap()
            .parse::<reqwest::Method>()
            .map_err(|e| e.to_string())?,
        url.clone(),
    );
    for (name, value) in data["headers"].as_object().unwrap() {
        if allowed_header(name) {
            request = request.header(name, value.as_str().unwrap());
        }
    }
    if !["GET", "HEAD"].contains(&data["method"].as_str().unwrap()) {
        request = request.body(data["body"].as_str().unwrap().to_string());
    }
    read_response(request.send().await.map_err(|e| e.to_string())?, start).await
}
pub async fn send(Json(data): Json<Value>) -> Json<Value> {
    let result = match validate(&data) {
        Ok((url, timeout)) => {
            tokio::time::timeout(Duration::from_millis(timeout), execute(&data, url, timeout))
                .await
                .unwrap_or_else(|_| Err("Request timed out".into()))
        }
        Err(error) => Err(error),
    };
    Json(result.unwrap_or_else(|error| json!({"ok":false,"error":error})))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_private_schemes_credentials_and_invalid_input() {
        for url in [
            "http://example.com",
            "https://127.0.0.1",
            "https://[::1]",
            "https://example.internal",
            "https://u:p@example.com",
            "https://example.com:444",
            "https://localhost",
        ] {
            assert!(
                validate(&json!({"method":"GET","url":url,"headers":{},"body":"","timeout":1000}))
                    .is_err(),
                "{url}"
            );
        }
        let mut data = json!({"method":"POST","url":"https://example.com","headers":{},"body":"hi","timeout":1000});
        assert!(validate(&data).is_ok());
        data["timeout"] = json!(0);
        assert!(validate(&data).is_err());
        data["timeout"] = json!(1000);
        data["headers"] = json!({"x-test":"x\r\ny: z"});
        assert!(validate(&data).is_err());
        assert!(!allowed_header("X-Forwarded-For"));
        assert!(!allowed_header("HOST"));
        assert!(allowed_header("Authorization"));
        assert!(allowed_header("Cookie"));
    }
    #[tokio::test]
    async fn preserves_redirect_status_duplicate_cookies_and_caps_response_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        for oversized in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let _ = socket.read(&mut request).await;
                let body = if oversized {
                    vec![b'x'; 2_000_001]
                } else {
                    b"redirect".to_vec()
                };
                let headers=format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/must-not-follow\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
                let _ = socket.write_all(headers.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            });
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let response = client.get(format!("http://{addr}")).send().await.unwrap();
            let result = read_response(response, Instant::now()).await;
            if oversized {
                assert!(result.unwrap_err().contains("2 MB"));
            } else {
                let result = result.unwrap();
                assert_eq!(result["status"], 302);
                assert_eq!(result["responseBody"], "redirect");
                assert_eq!(result["setCookies"], json!(["a=1; Path=/", "b=2; Path=/"]));
                assert_eq!(result["size"], 8);
            }
            server.await.unwrap();
        }
    }
    #[tokio::test]
    async fn errors_keep_browser_result_contract() {
        let result = send(Json(
            json!({"method":"GET","url":"http://localhost","headers":{},"body":"","timeout":1000}),
        ))
        .await
        .0;
        assert_eq!(result["ok"], false);
        assert!(result["error"].is_string());
    }
    fn compress(kind: &str, body: &[u8]) -> Vec<u8> {
        use std::io::Write;
        match kind {
            "gzip" => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(body).unwrap();
                encoder.finish().unwrap()
            }
            "deflate" => {
                let mut encoder =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(body).unwrap();
                encoder.finish().unwrap()
            }
            "br" => {
                let mut output = Vec::new();
                {
                    let mut encoder = brotli::CompressorWriter::new(&mut output, 4096, 5, 22);
                    encoder.write_all(body).unwrap();
                }
                output
            }
            "zstd" => zstd::stream::encode_all(std::io::Cursor::new(body), 1).unwrap(),
            _ => unreachable!(),
        }
    }
    #[tokio::test]
    async fn decodes_captured_accept_encoding_and_bounds_decoded_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (kind, oversized) in [
            ("gzip", false),
            ("br", false),
            ("deflate", false),
            ("zstd", false),
            ("gzip", true),
        ] {
            let plain = if oversized {
                vec![b'x'; 2_000_001]
            } else {
                br#"{"message":"plain text response"}"#.to_vec()
            };
            let compressed = compress(kind, &plain);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 8192];
                let count = stream.read(&mut request).await.unwrap();
                assert!(String::from_utf8_lossy(&request[..count])
                    .to_lowercase()
                    .contains("accept-encoding: gzip, deflate, br, zstd"));
                let head=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",compressed.len());
                stream.write_all(head.as_bytes()).await.unwrap();
                stream.write_all(&compressed).await.unwrap();
            });
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let response = client
                .get(format!("http://{addr}/"))
                .header("Accept-Encoding", "gzip, deflate, br, zstd")
                .send()
                .await
                .unwrap();
            let result = read_response(response, Instant::now()).await;
            if oversized {
                assert!(result.unwrap_err().contains("2 MB"));
            } else {
                let result = result.unwrap();
                assert_eq!(result["responseBody"], String::from_utf8(plain).unwrap());
                assert!(result["responseHeaders"].get("content-encoding").is_none());
            }
            server.await.unwrap();
        }
    }
}
