//! CVE-2026-119202: `@hapi/content` parses a `Content-Disposition` parameter name with a
//! quadratic-time regular expression when a long token has no `=`.
//!
//! The audit uses a timing differential only: the captured multipart request is replayed with a
//! bounded 16 KB / 32 KB token appended to the first part's `Content-Disposition` parameters.
//! Patched parsers stay linear; affected versions grow super-linearly. No 1 MB token, concurrency,
//! repeated flood or malformed request is used, so the probe does not attempt an outage.
use super::auto_audit::{self as audit, AuditState};
use axum::Json;
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};
use tokio::time::{sleep, Duration, Instant};

const ADVISORY: &str = "CVE-2026-119202 (GHSA-8494-f6mr-cjpv; @hapi/content Content-Disposition quadratic parsing)";
const MAX_SENDS: usize = 5;
const SEND_DEADLINE: Duration = Duration::from_secs(45);

pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    if !matches!(entry.method.as_str(), "POST" | "PUT" | "PATCH") {
        return false;
    }
    if !(200..400).contains(&entry.status_code)
        || entry.request_body.is_empty()
        || entry.request_body.len() > 512_000
    {
        return false;
    }
    if !entry
        .request_content_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("multipart/form-data")
    {
        return false;
    }
    let Ok(body) = std::str::from_utf8(&entry.request_body) else {
        return false;
    };
    body.to_ascii_lowercase().contains("content-disposition:")
        && body.to_ascii_lowercase().contains("form-data")
}

pub(super) fn key(request: &Value) -> String {
    let url = reqwest::Url::parse(request["url"].as_str().unwrap_or_default()).ok();
    let identity = url
        .as_ref()
        .map(|url| format!("{}|{}", url.origin().ascii_serialization(), url.path()))
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, identity.as_bytes());
    let hex: String = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    format!("auto-hapi-content-{hex}")
}

/// Append a long parameter token without `=` to the first `Content-Disposition` line.
fn mutate_body(body: &str, token_len: usize) -> Option<String> {
    let lowered = body.to_ascii_lowercase();
    let start = lowered.find("content-disposition:")?;
    let line_end = body[start..].find("\r\n").map(|offset| start + offset)?;
    let line = &body[start..line_end];
    if !line.to_ascii_lowercase().contains("form-data") {
        return None;
    }
    let mut out = String::with_capacity(body.len() + token_len + 2);
    out.push_str(&body[..line_end]);
    out.push_str("; ");
    out.extend(std::iter::repeat_n('a', token_len));
    out.push_str(&body[line_end..]);
    Some(out)
}

/// Quadratic growth is visible only when the large-token probe is clearly slower than both the
/// baseline and the half-size token. Absolute floors reject noisy microsecond differences.
fn verdict(baseline_ms: u64, half_ms: u64, full_ms: u64) -> bool {
    full_ms >= baseline_ms.saturating_add(150)
        && half_ms >= baseline_ms.saturating_add(40)
        && full_ms >= half_ms.saturating_mul(2)
}

fn header_text(headers: &Value, name: &str) -> Option<String> {
    headers
        .as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_string)
}

async fn send(request: &Value) -> (Value, u64) {
    sleep(Duration::from_millis(500)).await;
    let result = super::http_sender::send(Json(request.clone())).await.0;
    let duration = result["duration"].as_u64().unwrap_or(0);
    (result, duration)
}

fn evidence_item(id: &str, label: &str, request: &Value, result: &Value) -> Value {
    let mut item = json!({
        "id": id,
        "label": label,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "request": request,
        "setCookies": [],
        "duration": result["duration"].as_u64().unwrap_or(0).min(3_600_000),
        "size": result["size"].as_u64().unwrap_or(0).min(2_000_000),
        "truncated": false,
    });
    if result["ok"] == true {
        let body = result["responseBody"].as_str().unwrap_or_default();
        let mut headers = result["responseHeaders"].as_object().cloned().unwrap_or_default();
        let count = headers.len();
        headers.retain(|_, value| value.as_str().is_some_and(|text| text.len() <= 8192));
        let headers: serde_json::Map<_, _> = headers.into_iter().take(200).collect();
        item["truncated"] = json!(body.chars().count() > 32000 || headers.len() != count);
        item["response"] = json!({
            "status": result["status"],
            "responseHeaders": headers,
            "responseBody": audit::preview(body, 32000),
        });
    } else {
        item["error"] = json!(audit::preview(
            result["error"].as_str().unwrap_or("Request failed"),
            4000
        ));
    }
    item
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
    let original = audit::request(entry)?;
    let body = original["body"].as_str()?.to_string();
    let small = mutate_body(&body, 16_384)?;
    let large = mutate_body(&body, 32_768)?;
    let small_request = {
        let mut value = original.clone();
        value["body"] = json!(small);
        value
    };
    let large_request = {
        let mut value = original.clone();
        value["body"] = json!(large);
        value
    };
    let mut evidence = vec![audit::observed(entry, &original)];
    let mut sent = 0;
    let start = Instant::now();
    if start.elapsed() >= SEND_DEADLINE {
        return None;
    }
    let (baseline, baseline_ms) = send(&original).await;
    sent += 1;
    evidence.push(evidence_item("hapi-baseline", "Multipart baseline", &original, &baseline));
    if baseline["ok"] != true
        || !(200..300).contains(&baseline["status"].as_u64().unwrap_or(0))
    {
        return None;
    }
    let (half, half_ms) = send(&small_request).await;
    sent += 1;
    evidence.push(evidence_item("hapi-16k", "16 KB parameter token", &small_request, &half));
    let (full, full_ms) = send(&large_request).await;
    sent += 1;
    evidence.push(evidence_item("hapi-32k", "32 KB parameter token", &large_request, &full));
    let (full_repeat, full_repeat_ms) = send(&large_request).await;
    sent += 1;
    evidence.push(evidence_item("hapi-32k-repeat", "32 KB parameter token repeat", &large_request, &full_repeat));
    let (restore, _) = send(&original).await;
    sent += 1;
    evidence.push(evidence_item("hapi-restore", "Original multipart restore", &original, &restore));

    let stable = half["ok"] == true
        && full["ok"] == true
        && full_repeat["ok"] == true
        && (200..300).contains(&half["status"].as_u64().unwrap_or(0))
        && (200..300).contains(&full["status"].as_u64().unwrap_or(0))
        && (200..300).contains(&full_repeat["status"].as_u64().unwrap_or(0));
    let slow_full = full_ms.min(full_repeat_ms);
    let findings = if stable && verdict(baseline_ms, half_ms, slow_full) {
        vec![json!({
            "id": "hapi-content-timing",
            "fingerprint": "hapi-content:Content-Disposition-quadratic",
            "checkId": "hapi-content",
            "title": "Timing pattern consistent with CVE-2026-119202 (@hapi/content)",
            "summary": format!(
                "A multipart request with a long Content-Disposition parameter name but no '=' grew super-linearly: baseline {baseline_ms} ms, 16 KB {half_ms} ms, 32 KB {full_ms}/{full_repeat_ms} ms. Affected @hapi/content versions (<= 6.0.2 and content 3.0.6-4.0.6) parse this header in quadratic time, so one unauthenticated upload can block the Node.js event loop. Patched 6.0.3 is linear. Timing can be influenced by load and proxies; confirm the dependency version before reporting."
            ),
            "severity": "high",
            "confidence": "medium",
            "status": "needs_review",
            "evidenceIds": ["observed", "hapi-baseline", "hapi-16k", "hapi-32k", "hapi-32k-repeat", "hapi-restore"],
            "excerpts": [
                format!("Baseline: {baseline_ms} ms"),
                format!("16 KB token: {half_ms} ms"),
                format!("32 KB tokens: {full_ms} ms and {full_repeat_ms} ms"),
            ],
            "remediation": "Upgrade @hapi/content to 6.0.3 or later (or content to a patched release), and lower payload.maxBytes on multipart routes until the upgrade is deployed.",
            "verification": {
                "method": "bounded timing differential on a captured multipart request",
                "outcome": "inconclusive",
                "reason": "Timing is consistent with the advisory but does not prove the installed dependency version; confirm the lockfile and patch level."
            }
        })]
    } else {
        vec![]
    };
    let status = if !findings.is_empty() {
        "findings"
    } else if !stable {
        "inconclusive"
    } else {
        "passed"
    };
    let checks = vec![json!({
        "checkId": "hapi-content",
        "status": status,
        "message": if findings.is_empty() && status == "passed" {
            "No super-linear Content-Disposition parsing was observed at 16 KB and 32 KB."
        } else if findings.is_empty() {
            "The multipart probes did not complete successfully; no timing conclusion."
        } else {
            "Bounded 16 KB/32 KB timing differential is consistent with the advisory."
        },
        "findingIds": findings.iter().map(|finding| finding["id"].clone()).collect::<Vec<_>>()
    })];
    let mut run = audit::run(entry, id, &original, evidence, findings, checks, sent, "active");
    run["auditKey"] = json!(key(&original));
    run["profileName"] = json!("Automatic @hapi/content audit");
    run["plan"]["maxRequests"] = json!(MAX_SENDS);
    let _ = ADVISORY;
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_token_to_first_disposition_line() {
        let body = "--x\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Type: text/plain\r\n\r\nv\r\n--x--\r\n";
        let out = mutate_body(body, 8).unwrap();
        assert!(out.contains("Content-Disposition: form-data; name=\"f\"; aaaaaaaa\r\n"));
        assert!(out.contains("\r\n\r\nv\r\n--x--\r\n"));
        assert_eq!(mutate_body("no multipart", 8), None);
    }

    #[test]
    fn timing_verdict_requires_super_linear_growth() {
        assert!(verdict(10, 100, 380));
        assert!(!verdict(10, 12, 15));
        assert!(!verdict(500, 520, 600));
    }

    #[test]
    fn eligibility_requires_multipart_text() {
        let storage = proxy_core::TrafficStorage::new(":memory:", 100_000).unwrap();
        let _ = storage;
        let mut entry = TrafficEntry::new_request(
            "POST",
            "http://example.test/upload",
            "example.test",
            "/upload",
            "http",
            r#"{"content-type":["multipart/form-data; boundary=x"]}"#,
            b"--x\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--x--\r\n".to_vec(),
            None,
        );
        entry.status_code = 200;
        entry.request_content_type = Some("multipart/form-data; boundary=x".into());
        assert!(eligible(&entry));
        entry.method = "GET".into();
        assert!(!eligible(&entry));
    }
}
