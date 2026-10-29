//! PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure from captured responses.
//! Passive only: the PHP version already disclosed by the server is compared with the fixed
//! releases. No request is sent and no exploit is attempted.
use super::auto_audit::{self as audit, AuditState};
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};

const ADVISORY: &str = "CVE-2026-109618 (RCE via OOM corruption) and CVE-2026-109619 (RCE via stale global state)";

/// One audit per deployment: the PHP release is a host property, not a per-path property.
pub(super) fn key(request: &Value) -> String {
    let origin = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, origin.as_bytes());
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("auto-php2shell-{hex}")
}

fn header_text(headers: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
}

/// PHP session cookies identify a PHP runtime even when `expose_php` hides the version.
fn php_session(headers: &serde_json::Map<String, Value>) -> bool {
    header_text(headers, "set-cookie")
        .is_some_and(|value| value.to_ascii_lowercase().contains("phpsessid"))
}

fn mentions_php(headers: &serde_json::Map<String, Value>) -> bool {
    ["x-powered-by", "server", "via"].iter().any(|name| {
        header_text(headers, name)
            .is_some_and(|value| value.to_ascii_lowercase().contains("php"))
    })
}

pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    let headers = audit::headers(&entry.response_headers);
    mentions_php(&headers) || php_session(&headers)
}

/// Parse a `PHP` version marker from arbitrary text: `PHP/8.4.26`, `PHP 8.5`, `php-8.4.26`.
pub(super) fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    while let Some(position) = lower[from..].find("php") {
        let mut start = from + position + 3;
        while let Some(character) = text.get(start..).and_then(|tail| tail.chars().next()) {
            if matches!(character, '/' | '-' | ':' | '_') || character.is_whitespace() {
                start += character.len_utf8();
            } else {
                break;
            }
        }
        let mut numbers: Vec<u32> = vec![];
        let mut current = String::new();
        for character in text[start..].chars().take(24) {
            if character.is_ascii_digit() {
                current.push(character);
            } else if character == '.' && !current.is_empty() {
                if let Ok(value) = current.parse() {
                    numbers.push(value);
                }
                current.clear();
            } else {
                break;
            }
        }
        if let Ok(value) = current.parse() {
            numbers.push(value);
        }
        if numbers.len() >= 2 {
            return Some((numbers[0], numbers[1], numbers.get(2).copied().unwrap_or(0)));
        }
        from = from + position + 3;
    }
    None
}

/// Fixed release for a branch, when that branch is still supported.
pub(super) fn fixed_release(version: (u32, u32, u32)) -> Option<(u32, u32, u32)> {
    match (version.0, version.1) {
        (8, 2) => Some((8, 2, 35)),
        (8, 3) => Some((8, 3, 36)),
        (8, 4) => Some((8, 4, 27)),
        (8, 5) => Some((8, 5, 12)),
        _ => None,
    }
}

pub(super) enum Assessment {
    /// Affected branch. `fixed` is `None` when the branch is end-of-life and receives no fix.
    Vulnerable { fixed: Option<(u32, u32, u32)> },
    Patched { fixed: (u32, u32, u32) },
    Unknown,
}

pub(super) fn assess(version: (u32, u32, u32)) -> Assessment {
    if version < (8, 2, 0) {
        // PHP 5.4 and later are affected by at least one of the two flaws; older branches are EOL.
        return Assessment::Vulnerable { fixed: None };
    }
    match fixed_release(version) {
        Some(fixed) if version < fixed => Assessment::Vulnerable { fixed: Some(fixed) },
        Some(fixed) => Assessment::Patched { fixed },
        None => Assessment::Unknown,
    }
}

fn version_text(version: (u32, u32, u32)) -> String {
    format!("{}.{}.{}", version.0, version.1, version.2)
}

/// Read the first PHP version disclosed by headers, then by the response body.
fn disclosed_version(
    entry: &TrafficEntry,
    headers: &serde_json::Map<String, Value>,
) -> Option<((u32, u32, u32), String, bool)> {
    for name in ["x-powered-by", "server", "via"] {
        if let Some(value) = header_text(headers, name) {
            if let Some(version) = parse_version(&value) {
                return Some((version, format!("{name}: {value}"), true));
            }
        }
    }
    let sample = &entry.response_body[..entry.response_body.len().min(65_536)];
    let body = String::from_utf8_lossy(sample);
    parse_version(&body).map(|version| {
        let marker = body
            .to_ascii_lowercase()
            .find("php/")
            .map(|index| audit::preview(&body[index.min(body.len())..], 120))
            .unwrap_or_default();
        (version, format!("response body: {marker}"), false)
    })
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
    let headers = audit::headers(&entry.response_headers);
    let evidence = vec![audit::observed(entry, &original)];
    let mut findings = vec![];
    let mut status = "inconclusive";
    let message: String;
    match disclosed_version(entry, &headers) {
        Some((version, source, from_header)) => {
            let text = version_text(version);
            match assess(version) {
                Assessment::Vulnerable { fixed } => {
                    let fixed_text = fixed
                        .map(version_text)
                        .unwrap_or_else(|| "no fixed release (end-of-life branch)".to_string());
                    let fid = "php2shell-1".to_string();
                    let mut finding = audit::finding(
                        "php2shell",
                        &fid,
                        &format!("PHP2Shell: PHP {text} is affected"),
                        format!(
                            "The server disclosed PHP {text} ({source}). That release is before the fixed builds for {ADVISORY}, so the deployment is in the affected range. This is version-based exposure evidence, not a proof of remote code execution: reachability still depends on request processing and on the vulnerable paths actually being used. The audit sent no request and attempted no exploit."
                        ),
                        vec!["observed"],
                        vec![
                            source.clone(),
                            format!("Assessed PHP {text}; fixed release: {fixed_text}"),
                            format!("Advisory: {ADVISORY}"),
                        ],
                        "critical",
                    );
                    finding["confidence"] = json!(if from_header { "high" } else { "medium" });
                    finding["verification"] = json!({
                        "method": "Passive comparison of a disclosed PHP version with the advisory fixed releases",
                        "outcome": "inconclusive",
                        "reason": "Version disclosure places the deployment in the affected range. Confirming exploitability requires the vulnerable request paths and a controlled test of the target, which this audit does not perform."
                    });
                    finding["endpoint"] = original["url"].clone();
                    finding["method"] = original["method"].clone();
                    finding["remediation"] = json!("Update to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or later) for the branch in use. Move end-of-life branches to a supported release. If an update is not immediately possible, restrict access to the application and follow the PHP project advisories for the available mitigations.");
                    findings.push(finding);
                    status = "findings";
                    message = format!("PHP {text} is in the affected range for PHP2Shell");
                }
                Assessment::Patched { fixed } => {
                    status = "passed";
                    message = format!(
                        "PHP {text} is at or after the fixed release {} for its branch",
                        version_text(fixed)
                    );
                }
                Assessment::Unknown => {
                    message = format!(
                        "PHP {text} was disclosed, but no fixed release is recorded for that branch; update to a supported branch"
                    );
                }
            }
        }
        None if php_session(&headers) => {
            message = "A PHP session cookie was observed, but the PHP version is not disclosed; confirm the release from the server inventory".into();
        }
        None => {
            message = "PHP was mentioned in a response header without a parseable version; confirm the release from the server inventory".into();
        }
    }
    let checks = vec![json!({
        "checkId": "php2shell",
        "status": status,
        "message": message,
        "findingIds": findings.iter().map(|f| f["id"].clone()).collect::<Vec<_>>()
    })];
    let mut run = audit::run(entry, id, &original, evidence, findings, checks, 0, "passive");
    run["auditKey"] = json!(key(&original));
    run["profileName"] = json!("Automatic PHP2Shell version exposure");
    run["plan"]["maxRequests"] = json!(0);
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_disclosed_php_versions() {
        assert_eq!(parse_version("PHP/8.4.26"), Some((8, 4, 26)));
        assert_eq!(parse_version("x-powered-by: php/8.3.36-1+deb12u1"), Some((8, 3, 36)));
        assert_eq!(parse_version("PHP 8.5"), Some((8, 5, 0)));
        assert_eq!(parse_version("PHP/8"), None);
        assert_eq!(parse_version("no version here"), None);
        assert_eq!(parse_version("PHP/"), None);
    }

    #[test]
    fn compares_against_each_fixed_release() {
        for (version, vulnerable) in [
            ((8, 4, 26), true),
            ((8, 4, 27), false),
            ((8, 5, 11), true),
            ((8, 5, 12), false),
            ((8, 2, 34), true),
            ((8, 2, 35), false),
            ((8, 3, 35), true),
            ((8, 3, 36), false),
            ((8, 1, 99), true),
            ((7, 4, 33), true),
            ((5, 6, 40), true),
            ((8, 6, 0), false),
        ] {
            let assessment = assess(version);
            assert_eq!(
                matches!(assessment, Assessment::Vulnerable { .. }),
                vulnerable,
                "PHP {}.{}.{}",
                version.0,
                version.1,
                version.2
            );
        }
        assert!(matches!(assess((8, 6, 0)), Assessment::Unknown));
        assert!(matches!(assess((9, 0, 0)), Assessment::Unknown));
    }

    #[test]
    fn audits_each_origin_once_regardless_of_path() {
        let first = key(&json!({"url":"https://example.com/a"}));
        let same = key(&json!({"url":"https://example.com/b?x=1"}));
        let other_host = key(&json!({"url":"https://other.example/a"}));
        let other_scheme = key(&json!({"url":"http://example.com/a"}));
        assert_eq!(first, same);
        assert_ne!(first, other_host);
        assert_ne!(first, other_scheme);
        assert_ne!(first, key(&json!({"url":"https://example.com:8443/a"})));
        assert!(first.starts_with("auto-php2shell-"));
    }

    fn entry(response_headers: Value, body: &str) -> TrafficEntry {
        let mut entry = TrafficEntry::new_request(
            "GET",
            "http://localhost/index.php",
            "localhost",
            "/index.php",
            "http",
            "{}",
            vec![],
            None,
        );
        entry.status_code = 200;
        entry.response_headers = response_headers.to_string();
        entry.response_body = body.as_bytes().to_vec();
        entry.response_size = entry.response_body.len() as u64;
        entry.response_content_type = Some("text/html".into());
        entry
    }

    #[test]
    fn eligibility_needs_a_php_signal() {
        assert!(eligible(&entry(json!({"x-powered-by":["PHP/8.4.26"]}), "")));
        assert!(eligible(&entry(json!({"server":["Apache/2.4 (PHP/8.4.26)"]}), "")));
        assert!(eligible(&entry(json!({"set-cookie":["PHPSESSID=abc; path=/"]}), "")));
        assert!(!eligible(&entry(json!({"server":["nginx/1.27"]}), "")));
    }

    #[tokio::test]
    async fn reports_vulnerable_and_patched_releases_with_valid_runs() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let storage = proxy_core::TrafficStorage::new(":memory:", 100_000).unwrap();
        let intercept = Intercept::new(storage.clone());
        let (state, _runtime) = audit::start(storage.clone(), intercept.clone());

        let vulnerable = entry(json!({"x-powered-by":["PHP/8.4.26"]}), "");
        let run = audit(&vulnerable, "php-vuln", &state, &intercept).await.unwrap();
        assert_eq!(run["sent"], 0);
        assert_eq!(run["plan"]["mode"], "passive");
        assert_eq!(run["findings"].as_array().unwrap().len(), 1);
        assert_eq!(run["findings"][0]["severity"], "critical");
        assert_eq!(run["findings"][0]["confidence"], "high");
        assert_eq!(run["checks"][0]["status"], "findings");
        assert!(super::super::scan::validate_run("php-vuln", &run).is_ok());

        let patched = entry(json!({"x-powered-by":["PHP/8.4.27"]}), "");
        let run = audit(&patched, "php-ok", &state, &intercept).await.unwrap();
        assert!(run["findings"].as_array().unwrap().is_empty());
        assert_eq!(run["checks"][0]["status"], "passed");
        assert!(super::super::scan::validate_run("php-ok", &run).is_ok());

        let hidden = entry(json!({"set-cookie":["PHPSESSID=abc"]}), "");
        let run = audit(&hidden, "php-hidden", &state, &intercept).await.unwrap();
        assert_eq!(run["checks"][0]["status"], "inconclusive");
        assert!(super::super::scan::validate_run("php-hidden", &run).is_ok());
    }
}
