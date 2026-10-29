//! React2Shell (CVE-2025-55182) exposure: is a React Server Components endpoint reachable?
//!
//! Safe by construction. The probe is a normal `GET` with `RSC: 1`, which is exactly what a Next.js
//! client sends during navigation. It contains no Server Function payload, no Flight chunk and no
//! exploit sequence, so it cannot deserialize attacker data or execute code. A positive result means
//! RSC is enabled, which the vendor advisory describes as the exposure condition; patch status must
//! still come from the React and Next.js versions in the deployment.
use super::auto_audit::{self as audit, AuditState};
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};
use tokio::time::{sleep, Duration, Instant};

const ADVISORY: &str = "CVE-2025-55182 (React Server Components deserialization; CVSS 10.0)";
const SEND_DEADLINE: Duration = Duration::from_secs(30);

/// One audit per origin: RSC support is a deployment property.
pub(super) fn key(request: &Value) -> String {
    let origin = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, origin.as_bytes());
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("auto-react2shell-{hex}")
}

fn header_text(headers: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(Value::as_str)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn is_rsc_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("text/x-component")
}

/// Flight rows start with a numeric id and a colon, such as `0:{"a":"$@1"}`.
fn looks_like_flight(body: &str) -> bool {
    let head = body.trim_start();
    let digits = head.chars().take_while(char::is_ascii_digit).count();
    digits > 0
        && digits <= 6
        && head.chars().nth(digits) == Some(':')
        && head.contains('"')
}

/// Next.js and React Router RSC markers in a captured response.
pub(super) fn nextjs_markers(
    entry: &TrafficEntry,
    headers: &serde_json::Map<String, Value>,
) -> Vec<&'static str> {
    let mut markers = vec![];
    if header_text(headers, "x-powered-by")
        .is_some_and(|value| value.to_ascii_lowercase().contains("next.js"))
    {
        markers.push("header: x-powered-by Next.js");
    }
    if headers
        .keys()
        .any(|name| name.starts_with("x-nextjs") || name.starts_with("x-vercel-"))
    {
        markers.push("header: x-nextjs-*");
    }
    if header_text(headers, "content-type").is_some_and(|value| is_rsc_type(&value)) {
        markers.push("header: text/x-component response");
    }
    if header_text(headers, "vary").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("rsc"))
    }) {
        markers.push("header: Vary: RSC");
    }
    if entry
        .response_content_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("text/x-component")
    {
        markers.push("header: text/x-component response");
    }
    let sample = String::from_utf8_lossy(&entry.response_body[..entry.response_body.len().min(65_536)]);
    if sample.contains("self.__next_f.push") {
        markers.push("body: Next.js App Router flight data");
    } else if sample.contains("__NEXT_DATA__") {
        markers.push("body: __NEXT_DATA__");
    }
    if sample.contains("/_next/static/") {
        markers.push("body: /_next/static assets");
    }
    markers.sort_unstable();
    markers.dedup();
    markers
}

fn request_rsc(headers: &serde_json::Map<String, Value>) -> bool {
    header_text(headers, "rsc").is_some_and(|value| value == "1")
        || header_text(headers, "next-action").is_some()
        || header_text(headers, "next-router-state-tree").is_some()
}

pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    if entry.method != "GET" || !(200..400).contains(&entry.status_code) {
        return false;
    }
    let response = audit::headers(&entry.response_headers);
    let request = audit::headers(&entry.request_headers);
    request_rsc(&request) || !nextjs_markers(entry, &response).is_empty()
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
    let response_headers = audit::headers(&entry.response_headers);
    let markers = nextjs_markers(entry, &response_headers);
    let captured_body = String::from_utf8_lossy(&entry.response_body[..entry.response_body.len().min(65_536)]);
    let captured_flight = is_rsc_type(
        entry.response_content_type.as_deref().unwrap_or(""),
    ) || looks_like_flight(&captured_body);
    let mut evidence = vec![audit::observed(entry, &original)];
    let mut sent = 0;

    // A captured RSC response is already conclusive; otherwise send one ordinary RSC navigation.
    let (reachable, detail, status_line) = if captured_flight {
        (true, "captured response is Flight data".to_string(), None)
    } else {
        let mut probe = original.clone();
        probe["headers"]["rsc"] = json!("1");
        probe["headers"]["accept"] = json!("text/x-component");
        probe["headers"]["cache-control"] = json!("no-store");
        if let Some(headers) = probe["headers"].as_object_mut() {
            for name in ["content-length", "transfer-encoding", "expect", "content-type"] {
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
            .unwrap_or_else(|_| json!({"ok":false,"error":"React2Shell probe timed out"}));
        sent = 1;
        let mut item = json!({
            "id": "react2shell-1",
            "label": "RSC: 1 navigation probe",
            "request": probe,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "setCookies": [],
            "duration": result["duration"].as_u64().unwrap_or(0).min(3_600_000),
            "size": result["size"].as_u64().unwrap_or(0).min(2_000_000),
            "truncated": false
        });
        let mut detail = String::new();
        let mut reachable = false;
        let mut status_line = None;
        if result["ok"] == true {
            let body = result["responseBody"].as_str().unwrap_or("");
            let content_type = result["responseHeaders"]["content-type"]
                .as_str()
                .unwrap_or("");
            let mut response_headers = result["responseHeaders"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            let count = response_headers.len();
            response_headers.retain(|_, v| v.as_str().is_some_and(|s| s.len() <= 8192));
            let response_headers: serde_json::Map<_, _> =
                response_headers.into_iter().take(200).collect();
            item["truncated"] = json!(body.chars().count() > 32000 || response_headers.len() != count);
            item["response"] = json!({
                "status": result["status"],
                "responseHeaders": { "content-type": content_type },
                "responseBody": audit::preview(body, 32000)
            });
            reachable = is_rsc_type(content_type) || looks_like_flight(body);
            let status = result["status"].as_u64().unwrap_or(0);
            detail = if is_rsc_type(content_type) {
                format!("server answered with {content_type} (HTTP {status})")
            } else if looks_like_flight(body) {
                format!("server answered with Flight rows (HTTP {status})")
            } else {
                format!("server answered with HTML instead of Flight data (HTTP {status})")
            };
            status_line = Some(format!(
                "RSC probe: HTTP {status}; Content-Type: {}",
                if content_type.is_empty() { "(none)" } else { content_type }
            ));
        } else {
            item["error"] = json!(audit::preview(
                result["error"].as_str().unwrap_or("Probe failed"),
                4000
            ));
            detail = "RSC probe did not complete".into();
        }
        evidence.push(item);
        (reachable, detail, status_line)
    };

    let mut findings = vec![];
    let (status, check_message);
    if reachable {
        let marker_text = if markers.is_empty() {
            "the RSC probe only".to_string()
        } else {
            markers.join("; ")
        };
        let fid = "react2shell-1".to_string();
        let mut excerpt = vec![
            format!("Evidence: {marker_text}"),
            format!("Observation: {detail}"),
            format!("Advisory: {ADVISORY}"),
            "Vulnerable React: 19.0.0, 19.1.0, 19.1.1, 19.2.0 (fixed 19.0.1, 19.1.2, 19.2.1)".to_string(),
            "Patch Next.js per branch: 14.2.35, 15.0.8, 15.1.12, 15.2.9, 15.3.9, 15.4.11, 15.5.10, 16.0.11, 16.1.5".to_string(),
        ];
        if let Some(line) = &status_line {
            excerpt.push(line.clone());
        }
        let mut finding = audit::finding(
            "react2shell",
            &fid,
            "React2Shell: React Server Components endpoint is reachable",
            format!(
                "The deployment answers React Server Components navigation ({detail}). The vendor advisory states that an application can be affected by {ADVISORY} even when it does not implement Server Function endpoints, provided it supports RSC; unauthenticated deserialization of a crafted Server Function request is the attack path. This audit sent only an ordinary `RSC: 1` GET with no Server Function payload, so it proves exposure, not exploitability. Confirm the React and Next.js versions in the deployment; HTTP responses did not disclose them."
            ),
            vec!["observed"],
            excerpt,
            "high",
        );
        finding["confidence"] = json!(if markers.is_empty() { "medium" } else { "high" });
        finding["verification"] = json!({
            "method": "Ordinary RSC navigation request; no deserialization payload",
            "outcome": "inconclusive",
            "reason": "RSC support is confirmed from the response, but the vulnerable React deserializer version cannot be determined from HTTP. Exploitability requires a crafted Server Function request, which this audit does not send."
        });
        finding["endpoint"] = original["url"].clone();
        finding["method"] = original["method"].clone();
        finding["remediation"] = json!("Upgrade react-server-dom-webpack, react-server-dom-parcel and react-server-dom-turbopack to 19.0.1, 19.1.2 or 19.2.1 (or later), and Next.js to a patched release for the branch in use (14.2.35, 15.0.8, 15.1.12, 15.2.9, 15.3.9, 15.4.11, 15.5.10, 16.0.11, 16.1.5). Verify the installed package versions and rebuild; WAF rules are not a substitute for the update.");
        findings.push(finding);
        status = "findings";
        check_message = format!("React Server Components reachable: {detail}");
    } else {
        status = "inconclusive";
        check_message = format!(
            "No React Server Components endpoint was confirmed: {detail}. Pages Router or a non-React stack is not affected by this advisory."
        );
    }
    let checks = vec![json!({
        "checkId": "react2shell",
        "status": status,
        "message": check_message,
        "findingIds": findings.iter().map(|f| f["id"].clone()).collect::<Vec<_>>()
    })];
    let mode = if sent > 0 { "active" } else { "passive" };
    let mut run = audit::run(entry, id, &original, evidence, findings, checks, sent, mode);
    run["auditKey"] = json!(key(&original));
    run["profileName"] = json!("Automatic React2Shell RSC exposure");
    run["plan"]["maxRequests"] = json!(sent);
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(response_headers: Value, body: &str, content_type: &str) -> TrafficEntry {
        let mut entry = TrafficEntry::new_request(
            "GET",
            "http://localhost/page",
            "localhost",
            "/page",
            "http",
            "{}",
            vec![],
            None,
        );
        entry.status_code = 200;
        entry.response_headers = response_headers.to_string();
        entry.response_body = body.as_bytes().to_vec();
        entry.response_size = entry.response_body.len() as u64;
        entry.response_content_type = Some(content_type.into());
        entry
    }

    #[test]
    fn detects_nextjs_and_rsc_markers() {
        let headers = |value: Value| audit::headers(&value.to_string());
        assert!(nextjs_markers(
            &entry(json!({"content-type":["text/html"]}), "<p>hi</p>", "text/html"),
            &headers(json!({"content-type":["text/html"]}))
        )
        .is_empty());
        assert!(nextjs_markers(
            &entry(json!({}), "<script>self.__next_f.push([1,\"x\"])</script>", "text/html"),
            &headers(json!({}))
        )
        .iter()
        .any(|marker| marker.contains("flight")));
        assert!(nextjs_markers(
            &entry(json!({"x-powered-by":["Next.js"]}), "", "text/html"),
            &headers(json!({"x-powered-by":["Next.js"]}))
        )
        .iter()
        .any(|marker| marker.contains("Next.js")));
        assert!(nextjs_markers(
            &entry(json!({"content-type":["text/x-component"]}), "", "text/x-component"),
            &headers(json!({"content-type":["text/x-component"]}))
        )
        .iter()
        .any(|marker| marker.contains("x-component")));
    }

    #[test]
    fn recognises_flight_rows_and_plain_html() {
        assert!(looks_like_flight("0:{\"a\":\"$@1\"}\n1:[\"$\",\"div\",null,{}]"));
        assert!(!looks_like_flight("<html><body>app</body></html>"));
        assert!(!looks_like_flight("0:no quotes here"));
        assert!(is_rsc_type("text/x-component; charset=utf-8"));
        assert!(!is_rsc_type("text/html"));
    }

    #[test]
    fn eligibility_needs_an_rsc_or_nextjs_signal() {
        assert!(eligible(&entry(
            json!({"x-powered-by":["Next.js"]}),
            "",
            "text/html"
        )));
        assert!(!eligible(&entry(
            json!({"server":["nginx"]}),
            "<html>plain</html>",
            "text/html"
        )));
        let mut post = entry(json!({"x-powered-by":["Next.js"]}), "", "text/html");
        post.method = "POST".into();
        assert!(!eligible(&post));
        let mut missing = entry(json!({"x-powered-by":["Next.js"]}), "", "text/html");
        missing.status_code = 500;
        assert!(!eligible(&missing));
    }

    #[test]
    fn audits_each_origin_once_regardless_of_path() {
        let first = key(&json!({"url":"https://app.example/page"}));
        assert_eq!(first, key(&json!({"url":"https://app.example/other?x=1"})));
        assert_ne!(first, key(&json!({"url":"https://app.example:8443/page"})));
        assert!(first.starts_with("auto-react2shell-"));
    }

    async fn fixture(answer_flight: bool) -> (TrafficEntry, std::sync::Arc<proxy_core::TrafficStorage>, std::sync::Arc<Intercept>) {
        use axum::{http::HeaderMap, routing::get, Router};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/page",
            get(move |headers: HeaderMap| async move {
                let rsc = headers
                    .get("rsc")
                    .and_then(|value| value.to_str().ok())
                    == Some("1");
                if answer_flight && rsc {
                    (
                        axum::http::StatusCode::OK,
                        [("content-type", "text/x-component")],
                        "0:{\"a\":\"$@1\"}".to_string(),
                    )
                } else {
                    (
                        axum::http::StatusCode::OK,
                        [("content-type", "text/html")],
                        "<html><body>app</body></html>".to_string(),
                    )
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut entry = TrafficEntry::new_request(
            "GET",
            &format!("http://{address}/page"),
            "127.0.0.1",
            "/page",
            "http",
            "{}",
            vec![],
            None,
        );
        entry.status_code = 200;
        entry.response_headers = json!({"server":["node"],"content-type":["text/html"]}).to_string();
        entry.response_body = b"<html><script>self.__next_f.push([1,\"x\"])</script></html>".to_vec();
        entry.response_size = entry.response_body.len() as u64;
        entry.response_content_type = Some("text/html".into());
        let storage = proxy_core::TrafficStorage::new(":memory:", 100_000).unwrap();
        let intercept = Intercept::new(storage.clone());
        (entry, storage, intercept)
    }

    #[tokio::test]
    async fn reports_reachable_rsc_with_a_safe_navigation_probe() {
        let (entry, storage, intercept) = fixture(true).await;
        let (state, _runtime) = audit::start(storage, intercept.clone());
        let run = audit(&entry, "react-test", &state, &intercept).await.unwrap();
        assert_eq!(run["sent"], 1);
        assert_eq!(run["plan"]["mode"], "active");
        assert_eq!(run["findings"].as_array().unwrap().len(), 1);
        assert_eq!(run["findings"][0]["severity"], "high");
        assert!(run["findings"][0]["summary"]
            .as_str()
            .unwrap()
            .contains("no Server Function payload"));
        assert_eq!(run["checks"][0]["status"], "findings");
        assert!(super::super::scan::validate_run("react-test", &run).is_ok());
    }

    #[tokio::test]
    async fn does_not_report_a_server_without_rsc() {
        let (entry, storage, intercept) = fixture(false).await;
        let (state, _runtime) = audit::start(storage, intercept.clone());
        let run = audit(&entry, "react-none", &state, &intercept).await.unwrap();
        assert!(run["findings"].as_array().unwrap().is_empty());
        assert_eq!(run["checks"][0]["status"], "inconclusive");
        assert!(super::super::scan::validate_run("react-none", &run).is_ok());
    }
}
