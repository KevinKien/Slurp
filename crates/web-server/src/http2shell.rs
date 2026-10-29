//! HTTP2Shell / Node2Shell / Brotli2Shell exposure (CVE-2026-111497).
//!
//! The flaw is an out-of-bounds write in the Brotli *decoder*. This audit only checks whether a
//! server applies `Content-Encoding: br` to request bodies, which is the precondition for the
//! decoder to be reachable over HTTP. It sends the captured body unchanged with the header added:
//! an invalid Brotli stream that every decoder rejects. No crafted memory-corruption payload and no
//! exploit is used, so the probe cannot trigger the bug on a vulnerable build.
use super::auto_audit::{self as audit, AuditState};
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};
use tokio::time::{sleep, Duration, Instant};

const ADVISORY: &str = "CVE-2026-111497 (fixed in Brotli 1.0.10, 1.1.1 and 1.2.1)";
const SEND_DEADLINE: Duration = Duration::from_secs(30);

/// One probe per deployment: request-body decoding is configured per server, not per path.
pub(super) fn key(request: &Value) -> String {
    let origin = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, origin.as_bytes());
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("auto-http2shell-{hex}")
}

fn header_text(headers: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(Value::as_str)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Cookie and header values that only Brotli-capable server stacks send.
pub(super) fn stack(headers: &serde_json::Map<String, Value>) -> Option<&'static str> {
    let server = header_text(headers, "server")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let powered = header_text(headers, "x-powered-by")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if headers.contains_key("x-aspnet-version")
        || headers.contains_key("x-aspnetmvc-version")
        || server.contains("kestrel")
        || server.contains("asp.net")
    {
        return Some(".NET");
    }
    if powered.contains("express") {
        return Some("Node.js (Express)");
    }
    if server.contains("node") || server.contains("bun") || powered.contains("node") {
        return Some("Node.js/Bun");
    }
    None
}

/// Whether a `Content-Encoding` value lists the Brotli token.
fn has_brotli(value: &str) -> bool {
    value
        .split(',')
        .map(|token| token.trim().to_ascii_lowercase())
        .any(|token| token == "br")
}

fn response_brotli(headers: &serde_json::Map<String, Value>) -> bool {
    header_text(headers, "content-encoding").is_some_and(|value| has_brotli(&value))
}

fn request_brotli(headers: &serde_json::Map<String, Value>) -> bool {
    header_text(headers, "accept-encoding").is_some_and(|value| has_brotli(&value))
}

/// Only bounded request bodies that a server could plausibly decode are probed.
pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    if !matches!(entry.method.as_str(), "POST" | "PUT" | "PATCH") {
        return false;
    }
    if !(200..400).contains(&entry.status_code) || entry.request_body.is_empty() {
        return false;
    }
    if entry.request_body.len() > 65_536 {
        return false;
    }
    if entry
        .request_content_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("multipart/")
    {
        return false;
    }
    let headers = audit::headers(&entry.response_headers);
    let request_headers = audit::headers(&entry.request_headers);
    stack(&headers).is_some() || response_brotli(&headers) || request_brotli(&request_headers)
}

pub(super) async fn audit(
    entry: &TrafficEntry,
    id: &str,
    state: &AuditState,
    intercept: &Intercept,
) -> Option<Value> {
    if !state.enabled() || !intercept.scope().matches(&entry.host) {
        return None;
    }
    let start = Instant::now();
    let original = audit::request(entry)?;
    let headers = audit::headers(&entry.response_headers);
    let stack = stack(&headers);
    let baseline = entry.status_code;
    let mut evidence = vec![audit::observed(entry, &original)];

    let mut probe = original.clone();
    probe["headers"]["content-encoding"] = json!("br");
    if let Some(headers) = probe["headers"].as_object_mut() {
        for name in ["content-length", "transfer-encoding", "expect"] {
            headers.remove(name);
        }
    }
    sleep(Duration::from_millis(500)).await;
    if !state.enabled() || !intercept.scope().matches(&entry.host) {
        return None;
    }
    let remaining = SEND_DEADLINE
        .checked_sub(start.elapsed())
        .unwrap_or(Duration::from_millis(1));
    let result = tokio::time::timeout(remaining, super::http_sender::send(axum::Json(probe.clone())))
        .await
        .map(|response| response.0)
        .unwrap_or_else(|_| json!({"ok":false,"error":"HTTP2Shell probe timed out"}));
    let mut item = json!({
        "id": "http2shell-1",
        "label": "Content-Encoding: br request-body probe",
        "request": probe,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "setCookies": [],
        "duration": result["duration"].as_u64().unwrap_or(0).min(3_600_000),
        "size": result["size"].as_u64().unwrap_or(0).min(2_000_000),
        "truncated": false
    });
    let probe_status = if result["ok"] == true {
        let body = result["responseBody"].as_str().unwrap_or("");
        let mut response_headers = result["responseHeaders"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        let count = response_headers.len();
        response_headers.retain(|_, v| v.as_str().is_some_and(|s| s.len() <= 8192));
        let response_headers: serde_json::Map<_, _> = response_headers.into_iter().take(200).collect();
        item["truncated"] = json!(body.chars().count() > 32000 || response_headers.len() != count);
        item["response"] = json!({
            "status": result["status"],
            "responseHeaders": response_headers,
            "responseBody": audit::preview(body, 32000)
        });
        result["status"].as_u64().unwrap_or(0)
    } else {
        item["error"] = json!(audit::preview(
            result["error"].as_str().unwrap_or("Probe failed"),
            4000
        ));
        0
    };
    evidence.push(item);

    let mut findings = vec![];
    let mut status = "inconclusive";
    let message;
    if result["ok"] != true {
        message = "The Brotli probe did not complete; no conclusion about request-body decoding".into();
    } else if probe_status == baseline as u64 {
        message = format!(
            "Adding Content-Encoding: br did not change the response (HTTP {probe_status}); no evidence that the body was decoded"
        );
    } else if (400..600).contains(&probe_status)
        && (200..400).contains(&baseline)
        && probe_status != baseline as u64
    {
        let stack_text = stack.unwrap_or("an unidentified server stack");
        let fid = "http2shell-1".to_string();
        let mut finding = audit::finding(
            "http2shell",
            &fid,
            &format!("HTTP2Shell: {stack_text} decodes Brotli request bodies"),
            format!(
                "The captured body was resent unchanged with Content-Encoding: br added. The response changed from HTTP {baseline} to HTTP {probe_status}, so the server applied the declared encoding and rejected the body during Brotli decoding. That makes the native Brotli decoder reachable from HTTP input, which is the precondition for {ADVISORY}. Only an invalid stream was sent: this audit does not send the crafted block-switch payload and cannot corrupt memory or execute code. Patched and vulnerable builds both reject this probe, so the finding is an exposure signal, not proof of exploitability."
            ),
            vec!["observed", "http2shell-1"],
            vec![
                format!("Baseline: HTTP {baseline}"),
                format!("Content-Encoding: br probe: HTTP {probe_status}"),
                format!("Detected stack: {stack_text}"),
                format!("Advisory: {ADVISORY}; Node.js fixed in 22.23.4, 24.22.1 and 26.12.1"),
            ],
            "medium",
        );
        finding["confidence"] = json!(if stack.is_some() { "high" } else { "medium" });
        finding["verification"] = json!({
            "method": "Differential request-body probe with the captured body and Content-Encoding: br",
            "outcome": "inconclusive",
            "reason": "The status change shows the server decodes declared Brotli request bodies. Whether the bundled decoder is vulnerable depends on the runtime and library versions, which HTTP responses did not disclose."
        });
        finding["endpoint"] = original["url"].clone();
        finding["method"] = original["method"].clone();
        finding["baselineId"] = json!("observed");
        finding["remediation"] = json!("Update the runtime and any bundled Brotli library: Brotli 1.0.10, 1.1.1 and 1.2.1 contain the decoder fix; Node.js 22.23.4, 24.22.1 and 26.12.1 (or later) incorporate it. If a vulnerable decoder is reachable, disable Brotli request-body decompression for untrusted clients until the update is deployed. Verify package and container inventories, since patch status cannot be inferred from HTTP responses.");
        findings.push(finding);
        status = "findings";
        message = format!(
            "Server applied Content-Encoding: br and rejected the invalid stream (HTTP {baseline} → {probe_status})"
        );
    } else {
        message = format!(
            "Probe returned HTTP {probe_status} against a baseline of HTTP {baseline}; decoding is not established"
        );
    }
    let checks = vec![json!({
        "checkId": "http2shell",
        "status": status,
        "message": message,
        "findingIds": findings.iter().map(|f| f["id"].clone()).collect::<Vec<_>>()
    })];
    let mut run = audit::run(entry, id, &original, evidence, findings, checks, 1, "active");
    run["auditKey"] = json!(key(&original));
    run["profileName"] = json!("Automatic HTTP2Shell Brotli exposure");
    run["plan"]["maxRequests"] = json!(1);
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(status: u16, response_headers: Value, method: &str, body: &[u8]) -> TrafficEntry {
        let mut entry = TrafficEntry::new_request(
            method,
            "http://localhost/api/items",
            "localhost",
            "/api/items",
            "http",
            r#"{"content-type":["application/json"]}"#,
            body.to_vec(),
            Some("application/json".into()),
        );
        entry.status_code = status;
        entry.response_headers = response_headers.to_string();
        entry.response_body = br#"{"ok":true}"#.to_vec();
        entry.response_size = entry.response_body.len() as u64;
        entry.response_content_type = Some("application/json".into());
        entry
    }

    #[test]
    fn probes_each_origin_once_regardless_of_path() {
        let first = key(&json!({"url":"https://example.com/api/items"}));
        assert_eq!(first, key(&json!({"url":"https://example.com/login?next=/"})));
        assert_ne!(first, key(&json!({"url":"https://example.com:8443/api/items"})));
        assert!(first.starts_with("auto-http2shell-"));
    }

    #[test]
    fn detects_brotli_capable_stacks_and_encodings() {
        let headers = |value: Value| audit::headers(&value.to_string());
        assert_eq!(stack(&headers(json!({"server":["node"]}))), Some("Node.js/Bun"));
        assert_eq!(
            stack(&headers(json!({"x-powered-by":["Express"]}))),
            Some("Node.js (Express)")
        );
        assert_eq!(stack(&headers(json!({"server":["Kestrel"]}))), Some(".NET"));
        assert_eq!(
            stack(&headers(json!({"x-aspnet-version":["4.0"]}))),
            Some(".NET")
        );
        assert_eq!(stack(&headers(json!({"server":["nginx/1.27"]}))), None);
        assert!(has_brotli("gzip, br"));
        assert!(has_brotli("BR"));
        assert!(!has_brotli("gzip, deflate"));
    }

    #[test]
    fn eligibility_requires_a_bounded_body_and_a_brotli_signal() {
        assert!(eligible(&entry(200, json!({"server":["node"]}), "POST", br#"{"a":1}"#)));
        assert!(eligible(&entry(
            200,
            json!({"content-encoding":["br"]}),
            "POST",
            br#"{"a":1}"#
        )));
        assert!(!eligible(&entry(200, json!({"server":["nginx"]}), "POST", br#"{"a":1}"#)));
        assert!(!eligible(&entry(200, json!({"server":["node"]}), "GET", b"")));
        assert!(!eligible(&entry(404, json!({"server":["node"]}), "POST", br#"{"a":1}"#)));
        assert!(!eligible(&entry(200, json!({"server":["node"]}), "POST", &vec![b'a'; 65_537])));
    }

    async fn fixture(
        reject_brotli: bool,
    ) -> (
        TrafficEntry,
        std::sync::Arc<proxy_core::TrafficStorage>,
        std::sync::Arc<Intercept>,
    ) {
        use axum::{body::Bytes, http::HeaderMap, routing::post, Router};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/items",
            post(move |headers: HeaderMap, body: Bytes| async move {
                let declared = headers.contains_key("content-encoding");
                if reject_brotli && declared {
                    return (axum::http::StatusCode::BAD_REQUEST, "{\"error\":\"invalid brotli\"}");
                }
                if body.as_ref() == br#"{"item":1}"# {
                    (axum::http::StatusCode::OK, "{\"ok\":true}")
                } else {
                    (axum::http::StatusCode::BAD_REQUEST, "{\"error\":\"body\"}")
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let url = format!("http://{address}/api/items");
        let mut entry = TrafficEntry::new_request(
            "POST",
            &url,
            "127.0.0.1",
            "/api/items",
            "http",
            r#"{"content-type":["application/json"]}"#,
            br#"{"item":1}"#.to_vec(),
            Some("application/json".into()),
        );
        entry.status_code = 200;
        entry.response_headers = json!({"server":["node"],"content-type":["application/json"]}).to_string();
        entry.response_body = br#"{"ok":true}"#.to_vec();
        entry.response_size = entry.response_body.len() as u64;
        entry.response_content_type = Some("application/json".into());
        let storage = proxy_core::TrafficStorage::new(":memory:", 100_000).unwrap();
        let intercept = Intercept::new(storage.clone());
        (entry, storage, intercept)
    }

    #[tokio::test]
    async fn reports_a_reachable_brotli_request_decoder() {
        let (entry, storage, intercept) = fixture(true).await;
        let (state, _runtime) = audit::start(storage, intercept.clone());
        let run = audit(&entry, "http2shell-test", &state, &intercept)
            .await
            .unwrap();
        assert_eq!(run["sent"], 1);
        assert_eq!(run["findings"].as_array().unwrap().len(), 1);
        assert_eq!(run["findings"][0]["confidence"], "high");
        assert!(run["findings"][0]["summary"]
            .as_str()
            .unwrap()
            .contains("does not send the crafted"));
        assert_eq!(run["checks"][0]["status"], "findings");
        assert!(super::super::scan::validate_run("http2shell-test", &run).is_ok());
    }

    #[tokio::test]
    async fn ignores_a_server_that_does_not_apply_the_encoding() {
        let (entry, storage, intercept) = fixture(false).await;
        let (state, _runtime) = audit::start(storage, intercept.clone());
        let run = audit(&entry, "http2shell-none", &state, &intercept)
            .await
            .unwrap();
        assert!(run["findings"].as_array().unwrap().is_empty());
        assert_eq!(run["checks"][0]["status"], "inconclusive");
        assert!(super::super::scan::validate_run("http2shell-none", &run).is_ok());
    }
}
