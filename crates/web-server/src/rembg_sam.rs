//! CVE-2026-115924 / GHSA-qr6x-7v33-6qmg: rembg `< 2.0.82` exposes `/api/remove` and trusts
//! `extras.sam_model` in file names and GitHub URLs. Exploitation requires an attacker-controlled
//! ONNX graph, two priming requests and decoding file bytes out of a returned PNG, so this audit is
//! passive: it flags the reachable endpoint and any captured `sam_model` input, and never uploads a
//! model, traverses a path, fetches a URL or attempts file disclosure.
use super::auto_audit::{self as audit, AuditState};
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};

const ADVISORY: &str = "CVE-2026-115924 (GHSA-qr6x-7v33-6qmg; rembg SAM model injection)";

pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    if entry.method != "POST" {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(&entry.url) else {
        return false;
    };
    url.path().trim_end_matches('/') == "/api/remove"
}

pub(super) fn key(request: &Value) -> String {
    let url = reqwest::Url::parse(request["url"].as_str().unwrap_or_default()).ok();
    let identity = url
        .as_ref()
        .map(|url| format!("{}|{}", url.origin().ascii_serialization(), url.path()))
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, identity.as_bytes());
    let hex: String = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    format!("auto-rembg-sam-{hex}")
}

fn captured_model(body: &str) -> bool {
    body.to_ascii_lowercase().contains("sam_model")
}

fn model_syntax(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    ["../", "%2e", "%2f", "http://", "https://", "#"]
        .iter()
        .any(|marker| lower.contains(marker))
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
    let request = audit::request(entry)?;
    let body = String::from_utf8_lossy(&entry.request_body);
    let supplied = captured_model(&body);
    let suspicious = supplied && model_syntax(&body);
    let evidence = vec![audit::observed(entry, &request)];
    let title = if suspicious {
        "Rembg SAM model injection with path/URL syntax in a captured request (CVE-2026-115924)"
    } else if supplied {
        "Rembg SAM model injection surface with a captured sam_model (CVE-2026-115924)"
    } else {
        "Unauthenticated rembg /api/remove SAM model injection surface (CVE-2026-115924)"
    };
    let summary = if suspicious {
        "A captured request to rembg /api/remove contains a sam_model value with path, URL or fragment syntax. rembg < 2.0.82 inserts that value into SAM filenames and GitHub URLs; a crafted ONNX graph can read local files as external tensor data and return them encoded in a PNG. No exploit request was sent and the value is not repeated in this finding. Confirm the rembg version and whether the endpoint is reachable without authentication."
    } else if supplied {
        "A captured request supplies extras.sam_model to rembg /api/remove. Versions before 2.0.82 accept this unauthenticated model selector and use it in filenames and download URLs. No exploit request was sent; confirm the rembg version and whether the endpoint is reachable without authentication."
    } else {
        "The captured request reaches rembg's unauthenticated /api/remove endpoint. rembg < 2.0.82 trusts extras.sam_model, which can lead to path traversal and local-file disclosure through a malicious ONNX graph. No exploit request was sent; this is an exposure finding that requires version confirmation."
    };
    let finding = json!({
        "id": "rembg-sam-exposure",
        "fingerprint": if suspicious {
            "rembg-sam:captured-model-syntax"
        } else if supplied {
            "rembg-sam:captured-model"
        } else {
            "rembg-sam:endpoint"
        },
        "checkId": "rembg-sam-injection",
        "title": title,
        "summary": summary,
        "severity": if suspicious { "high" } else { "medium" },
        "confidence": if supplied { "high" } else { "medium" },
        "status": "needs_review",
        "evidenceIds": ["observed"],
        "excerpts": [
            "Endpoint: POST /api/remove",
            if supplied {
                "Captured extras.sam_model present (value redacted)"
            } else {
                "No sam_model was present in the captured request"
            },
        ],
        "remediation": "Upgrade rembg to 2.0.82 or later, allow only fixed SAM identifiers mapped server-side to fixed filenames/URLs with pinned hashes, reject path and URL syntax, enforce cache containment, and run the container as a non-root user with a read-only root filesystem.",
        "verification": {
            "method": "captured request inspection; no exploit request",
            "outcome": "inconclusive",
            "reason": "The endpoint and optional sam_model are observed, but the rembg version and local-file impact require confirmation."
        }
    });
    let checks = vec![json!({
        "checkId": "rembg-sam-injection",
        "status": "findings",
        "message": if suspicious {
            "Captured sam_model contains path/URL/fragment syntax; version confirmation required."
        } else if supplied {
            "Captured request supplies sam_model; version confirmation required."
        } else {
            "Unauthenticated /api/remove exposure observed; version confirmation required."
        },
        "findingIds": ["rembg-sam-exposure"]
    })];
    let mut run = audit::run(entry, id, &request, evidence, vec![finding], checks, 0, "passive");
    run["auditKey"] = json!(key(&request));
    run["profileName"] = json!("Automatic rembg SAM exposure audit");
    let _ = ADVISORY;
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligibility_is_exact_remove_endpoint() {
        let mut entry = TrafficEntry::new_request(
            "POST",
            "http://example.test/api/remove",
            "example.test",
            "/api/remove",
            "http",
            "{}",
            b"x".to_vec(),
            None,
        );
        assert!(eligible(&entry));
        entry.url = "http://example.test/api/other".into();
        assert!(!eligible(&entry));
    }

    #[test]
    fn detects_model_and_syntax() {
        assert!(captured_model("name=\"extras\" {\"sam_model\":\"x\"}"));
        assert!(model_syntax("sam_model=../../flag#http://x"));
        assert!(!captured_model("name=\"image\""));
    }
}
