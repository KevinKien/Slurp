//! CVE-2026-119200 / GHSA-9v7c-q64q-vv33: Nuxt 4.6.0–4.6.2 page-router dot-segment
//! resolution bypasses `server/middleware` path checks and server route rules.
//!
//! The audit replays the captured page with percent-encoded dot segments. A page that was denied
//! or redirected at its literal path but renders at an encoded dot-segment path is consistent with
//! the advisory. Requests are GET only, identical headers, no exploit payload and no write.
use super::auto_audit::{self as audit, AuditState};
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};
use tokio::time::{sleep, Duration, Instant};

const ADVISORY: &str = "CVE-2026-119200 (GHSA-9v7c-q64q-vv33; Nuxt page dot-segment path bypass)";
const MAX_SENDS: usize = 4;
const SEND_DEADLINE: Duration = Duration::from_secs(30);

fn header(headers: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_string)
}

pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    if entry.method != "GET"
        || !entry.url.starts_with("http://")
        || !(200..500).contains(&entry.status_code)
    {
        return false;
    }
    if entry.url.len() > 4096 {
        return false;
    }
    let headers = audit::headers(&entry.response_headers);
    if header(&headers, "x-powered-by")
        .is_some_and(|value| value.to_ascii_lowercase().contains("nuxt"))
    {
        return true;
    }
    let body = String::from_utf8_lossy(&entry.response_body);
    body.contains("__NUXT__") || body.contains("/_nuxt/")
}

pub(super) fn key(request: &Value) -> String {
    let url = reqwest::Url::parse(request["url"].as_str().unwrap_or_default()).ok();
    let identity = url
        .as_ref()
        .map(|url| format!("{}|{}", url.origin().ascii_serialization(), url.path()))
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, identity.as_bytes());
    let hex: String = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    format!("auto-nuxt-dot-{hex}")
}

fn variants(path: &str) -> Vec<String> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return vec![];
    }
    vec![
        format!("/%2e/{trimmed}"),
        format!("/.%2e/{trimmed}"),
        format!("/x/%2e%2e/{trimmed}"),
    ]
}

fn variant_request(original: &Value, variant: &str) -> Option<Value> {
    let raw = original["url"].as_str()?;
    let (base, query) = raw.split_once('?').unwrap_or((raw, ""));
    let origin = reqwest::Url::parse(base).ok()?.origin().ascii_serialization();
    let mut request = original.clone();
    request["url"] = json!(format!(
        "{origin}{variant}{}",
        if query.is_empty() { String::new() } else { format!("?{query}") }
    ));
    Some(request)
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

/// reqwest/url normalises percent-encoded dot segments before sending, which hides exactly the
/// mismatch this advisory is about. HTTP/1.1 probes therefore use a raw socket and the exact target
/// path. HTTPS is skipped rather than silently normalised.
async fn raw_get(request: &Value, target: &str) -> Option<Value> {
    let url = reqwest::Url::parse(request["url"].as_str()?).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let host = url.host_str()?.to_string();
    let port = url.port_or_known_default()?;
    let authority = format!("{host}:{port}");
    let target = match url.query() {
        Some(query) => format!("{target}?{query}"),
        None => target.to_string(),
    };
    if target.len() > 4096 || target.chars().any(|character| character.is_control()) {
        return None;
    }
    let mut headers = String::new();
    if let Some(map) = request["headers"].as_object() {
        for (name, value) in map {
            if ["host", "connection", "content-length", "transfer-encoding", "accept-encoding"]
                .iter()
                .any(|blocked| name.eq_ignore_ascii_case(blocked))
            {
                continue;
            }
            if let Some(value) = value.as_str() {
                if !value.contains(['\r', '\n']) && value.len() <= 8192 {
                    headers.push_str(&format!("{name}: {value}\r\n"));
                }
            }
        }
    }
    let start = Instant::now();
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => return None,
    };
    let wire = format!(
        "GET {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept-Encoding: identity\r\n{headers}\r\n"
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if tokio::time::timeout(Duration::from_secs(5), stream.write_all(wire.as_bytes()))
        .await
        .ok()?
        .is_err()
    {
        return None;
    }
    let mut bytes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let mut chunk = [0u8; 8192];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(count)) => {
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.len() > 2_000_000 {
                    break;
                }
            }
            _ => break,
        }
    }
    let end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&bytes[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    let mut response_headers = serde_json::Map::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            response_headers.insert(name.trim().to_ascii_lowercase(), json!(value.trim()));
        }
    }
    let mut body = bytes[end + 4..].to_vec();
    if response_headers
        .get("transfer-encoding")
        .and_then(Value::as_str)
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        let mut decoded = Vec::new();
        let mut offset = 0;
        while offset < body.len() {
            let Some(line_end) = body[offset..].windows(2).position(|window| window == b"\r\n")
            else {
                break;
            };
            let raw_size = std::str::from_utf8(&body[offset..offset + line_end]).ok()?;
            let size = usize::from_str_radix(raw_size.split(';').next()?.trim(), 16).ok()?;
            offset += line_end + 2;
            if size == 0 || offset + size > body.len() {
                break;
            }
            decoded.extend_from_slice(&body[offset..offset + size]);
            offset += size + 2;
        }
        body = decoded;
    }
    Some(json!({
        "ok": true,
        "status": status,
        "responseHeaders": response_headers,
        "responseBody": String::from_utf8_lossy(&body),
        "duration": start.elapsed().as_millis() as u64,
        "size": body.len(),
    }))
}

async fn send(request: &Value, target: &str) -> Option<Value> {
    sleep(Duration::from_millis(500)).await;
    raw_get(request, target).await
}

fn security_headers(result: &Value) -> Vec<&'static str> {
    let Some(headers) = result["responseHeaders"].as_object() else {
        return vec![];
    };
    ["content-security-policy", "x-frame-options", "strict-transport-security", "referrer-policy"]
        .into_iter()
        .filter(|name| header(headers, name).is_some_and(|value| !value.trim().is_empty()))
        .collect()
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
    let path = reqwest::Url::parse(entry.url.as_str())
        .ok()
        .map(|url| url.path().to_string())?;
    let variants = variants(&path);
    if variants.is_empty() {
        return None;
    }
    let start = Instant::now();
    let mut evidence = vec![audit::observed(entry, &original)];
    let mut sent = 0;
    let baseline = send(&original, &path).await?;
    sent += 1;
    evidence.push(evidence_item("nuxt-baseline", "Literal path baseline", &original, &baseline));
    if baseline["ok"] != true {
        return None;
    }
    let baseline_status = baseline["status"].as_u64().unwrap_or(0);
    let denied = matches!(baseline_status, 401 | 403) || (300..400).contains(&baseline_status);
    let baseline_headers = security_headers(&baseline);
    let mut finding = None;
    for (index, variant) in variants.iter().enumerate() {
        if sent >= MAX_SENDS || start.elapsed() >= SEND_DEADLINE {
            break;
        }
        let request = variant_request(&original, variant)?;
        let Some(result) = send(&request, variant).await else {
            continue;
        };
        sent += 1;
        evidence.push(evidence_item(
            &format!("nuxt-variant-{index}"),
            "Percent-encoded dot-segment variant",
            &request,
            &result,
        ));
        if result["ok"] != true || result["status"].as_u64().unwrap_or(0) != 200 {
            continue;
        }
        let body = result["responseBody"].as_str().unwrap_or_default();
        let nuxt = body.contains("__NUXT__") || body.contains("/_nuxt/");
        if denied && nuxt {
            finding = Some(json!({
                "id": "nuxt-dot-segment-bypass",
                "fingerprint": "nuxt-dot-segments:page-bypass",
                "checkId": "nuxt-dot-segments",
                "title": "Dot-segment path renders a denied Nuxt page (CVE-2026-119200)",
                "summary": format!(
                    "The literal page path returned HTTP {baseline_status}, but {variant} returned 200 and Nuxt page markers. Nuxt 4.6.0–4.6.2 resolve dot segments in the page router before rendering while server middleware and route rules see the unresolved path, so path-based auth, redirects and header rules can be skipped. This is consistent with the advisory; confirm the Nuxt version and the middleware that keyed on the path."
                ),
                "severity": "high",
                "confidence": "high",
                "status": "needs_review",
                "evidenceIds": ["observed", "nuxt-baseline", format!("nuxt-variant-{index}")],
                "excerpts": [
                    format!("Literal path: {path} -> HTTP {baseline_status}"),
                    format!("Dot-segment path: {variant} -> HTTP 200 with Nuxt markers"),
                ],
                "remediation": "Upgrade nuxt and @nuxt/nitro-server to 4.6.3 or later, or reject dot segments in the first server middleware before other path checks.",
                "verification": {
                    "method": "literal versus percent-encoded dot-segment page request",
                    "outcome": "inconclusive",
                    "reason": "The response difference is consistent with the advisory but does not prove the installed Nuxt version; confirm the lockfile."
                }
            }));
            break;
        }
        if baseline_status == 200 && !denied {
            let variant_headers = security_headers(&result);
            let missing: Vec<&str> = baseline_headers
                .iter()
                .copied()
                .filter(|name| !variant_headers.contains(name))
                .collect();
            if !missing.is_empty() && nuxt {
                finding = Some(json!({
                    "id": "nuxt-dot-segment-headers",
                    "fingerprint": "nuxt-dot-segments:route-rule-headers",
                    "checkId": "nuxt-dot-segments",
                    "title": "Dot-segment path skips Nuxt route-rule headers",
                    "summary": format!(
                        "The literal page carried security headers ({}) but {variant} returned 200 without them. Nuxt server route rules for headers/redirects can be skipped when the page router resolves dot segments first; confirm the Nuxt version and the route rules involved.",
                        baseline_headers.join(", ")
                    ),
                    "severity": "medium",
                    "confidence": "medium",
                    "status": "needs_review",
                    "evidenceIds": ["observed", "nuxt-baseline", format!("nuxt-variant-{index}")],
                    "excerpts": [
                        format!("Baseline headers: {}", baseline_headers.join(", ")),
                        format!("Missing on {variant}: {}", missing.join(", ")),
                    ],
                    "remediation": "Upgrade nuxt and @nuxt/nitro-server to 4.6.3 or later, or normalise/reject dot segments before route rules.",
                    "verification": {
                        "method": "literal versus percent-encoded dot-segment page request",
                        "outcome": "inconclusive",
                        "reason": "Header differences can have other causes; version and route-rule configuration require confirmation."
                    }
                }));
                break;
            }
        }
    }
    let findings: Vec<Value> = finding.into_iter().collect();
    let checks = vec![json!({
        "checkId": "nuxt-dot-segments",
        "status": if !findings.is_empty() { "findings" } else { "passed" },
        "message": if findings.is_empty() {
            "No dot-segment page bypass or skipped route-rule header was observed."
        } else {
            "Percent-encoded dot-segment behavior is consistent with the Nuxt advisory."
        },
        "findingIds": findings.iter().map(|finding| finding["id"].clone()).collect::<Vec<_>>()
    })];
    let mut run = audit::run(entry, id, &original, evidence, findings, checks, sent, "active");
    run["auditKey"] = json!(key(&original));
    run["profileName"] = json!("Automatic Nuxt dot-segment audit");
    run["plan"]["maxRequests"] = json!(MAX_SENDS);
    let _ = ADVISORY;
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_encoded_dot_segment_variants() {
        assert_eq!(
            variants("/admin"),
            vec!["/%2e/admin", "/.%2e/admin", "/x/%2e%2e/admin"]
        );
        assert!(variants("/").is_empty());
    }

    #[test]
    fn variant_request_preserves_query_and_origin() {
        let original = json!({"url":"https://app.test/admin?tab=1"});
        let request = variant_request(&original, "/%2e/admin").unwrap();
        assert_eq!(request["url"], "https://app.test/%2e/admin?tab=1");
    }

    #[test]
    fn security_header_detection_is_case_insensitive() {
        let result = json!({"responseHeaders":{"Content-Security-Policy":"default-src 'self'","X-Frame-Options":"DENY"}});
        assert_eq!(security_headers(&result).len(), 2);
    }
}
