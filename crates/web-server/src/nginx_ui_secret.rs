//! CVE-2026-107807 / GHSA-pvgv-gcp7-v38g: nginx-ui accepts its master `Node.Secret` as the
//! `node_secret` URL query parameter, exposing a full authentication bypass in access logs,
//! proxy logs, browser history, Referer headers and cluster URLs. The audit is passive and only
//! inspects captured traffic; it never validates the secret or sends a request.
use super::auto_audit::{self as audit, AuditState};
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};

const ADVISORY: &str = "CVE-2026-107807 (GHSA-pvgv-gcp7-v38g; nginx-ui node_secret query exposure)";

fn has_query_secret(url: &str) -> bool {
    reqwest::Url::parse(url).ok().is_some_and(|url| {
        url.query_pairs()
            .any(|(name, _)| name.eq_ignore_ascii_case("node_secret"))
    })
}

fn referer_leaks(entry: &TrafficEntry) -> bool {
    audit::headers(&entry.request_headers)
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("referer"))
        .and_then(|(_, value)| value.as_str())
        .is_some_and(has_query_secret)
}

pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    has_query_secret(&entry.url) || referer_leaks(entry)
}

pub(super) fn key(request: &Value) -> String {
    let url = reqwest::Url::parse(request["url"].as_str().unwrap_or_default()).ok();
    let identity = url
        .as_ref()
        .map(|url| format!("{}|{}", url.origin().ascii_serialization(), url.path()))
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, identity.as_bytes());
    let hex: String = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    format!("auto-nginx-ui-secret-{hex}")
}

fn redact_url(raw: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(raw) else {
        return "[unparsable URL redacted]".into();
    };
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| {
            if name.eq_ignore_ascii_case("node_secret") {
                (name.into_owned(), "[redacted]".into())
            } else {
                (name.into_owned(), value.into_owned())
            }
        })
        .collect();
    url.query_pairs_mut().clear().extend_pairs(pairs);
    url.to_string()
}

fn redact_request(request: &Value) -> Value {
    let mut request = request.clone();
    request["url"] = json!(redact_url(request["url"].as_str().unwrap_or_default()));
    if let Some(headers) = request["headers"].as_object_mut() {
        for (name, value) in headers.iter_mut() {
            if name.eq_ignore_ascii_case("referer")
                && value.as_str().is_some_and(has_query_secret)
            {
                *value = json!("[redacted Referer containing node_secret]");
            }
        }
    }
    request
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
    if !has_query_secret(original["url"].as_str().unwrap_or_default()) && !referer_leaks(entry) {
        return None;
    }
    let request = redact_request(&original);
    let finding = json!({
        "id": "nginx-ui-node-secret-query",
        "fingerprint": "nginx-ui:node_secret-query",
        "checkId": "nginx-ui-node-secret",
        "title": "nginx-ui Node Secret is exposed in a URL query parameter (CVE-2026-107807)",
        "summary": "A captured request carries the nginx-ui node_secret credential in its URL query string or Referer. nginx-ui accepts this master secret as a full authentication bypass for HTTP and WebSocket APIs, and query strings are recorded in access/proxy logs, browser history and third-party Referer headers. The value is redacted here; rotate the secret and remove query-string support. No request was sent and the secret's validity was not tested.",
        "severity": "high",
        "confidence": "high",
        "status": "needs_review",
        "evidenceIds": ["observed"],
        "excerpts": [
            "node_secret query parameter observed (value redacted)",
            if referer_leaks(entry) {
                "Referer also contains node_secret (value redacted)"
            } else {
                "No node_secret was found in the Referer"
            },
        ],
        "remediation": "Upgrade nginx-ui to a build that accepts node secrets only through a header, remove node_secret from cluster URLs and app.ini/environment configuration, rotate the current Node.Secret, encrypt node tokens at rest and restrict log access.",
        "verification": {
            "method": "captured URL and Referer inspection; no request or authentication attempt",
            "outcome": "confirmed",
            "reason": "The credential is directly observed in the query or Referer; its validity and nginx-ui version still require confirmation."
        }
    });
    let checks = vec![json!({
        "checkId": "nginx-ui-node-secret",
        "status": "findings",
        "message": "node_secret was observed in a URL query or Referer; value redacted.",
        "findingIds": ["nginx-ui-node-secret-query"]
    })];
    let evidence = vec![audit::observed(entry, &request)];
    let mut run = audit::run(entry, id, &request, evidence, vec![finding], checks, 0, "passive");
    run["auditKey"] = json!(key(&request));
    run["profileName"] = json!("Automatic nginx-ui node_secret exposure audit");
    let _ = ADVISORY;
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_redacts_query_secret() {
        assert!(has_query_secret("http://example.test/api/settings?node_secret=abc&x=1"));
        assert!(!has_query_secret("http://example.test/api/settings?x=1"));
        assert_eq!(
            redact_url("http://example.test/api/settings?node_secret=abc&x=1"),
            "http://example.test/api/settings?node_secret=%5Bredacted%5D&x=1"
        );
    }

    #[test]
    fn eligibility_accepts_query_or_referer() {
        let mut entry = TrafficEntry::new_request(
            "GET",
            "http://example.test/api/settings?node_secret=abc",
            "example.test",
            "/api/settings",
            "http",
            "{}",
            vec![],
            None,
        );
        assert!(eligible(&entry));
        entry.url = "http://example.test/api/settings".into();
        assert!(!eligible(&entry));
    }
}
