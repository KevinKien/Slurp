//! Host overrides remain pinned to the original URL; no attacker destination is contacted.
use super::auto_audit::{self as audit, AuditState};
use axum::Json;
use proxy_core::{Intercept, TrafficEntry};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::time::{sleep, Duration, Instant};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    request: Value,
    header: String,
    host: String,
}
pub(crate) async fn probe(Json(input): Json<Input>) -> Json<Value> {
    Json(super::http_sender::send_host(input.request, &input.header, &input.host).await)
}
pub(super) fn key(request: &Value) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, request.to_string().as_bytes());
    format!(
        "auto-host-{}",
        digest
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    entry.method == "GET"
        && (audit::headers(&entry.response_headers)
            .get("location")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
            || entry
                .response_content_type
                .as_deref()
                .unwrap_or("")
                .contains("html")
                && String::from_utf8_lossy(
                    &entry.response_body[..entry.response_body.len().min(256000)],
                )
                .contains(&format!("://{}", entry.host)))
}
fn location(value: &Value) -> Option<String> {
    if value["ok"] != true {
        return None;
    }
    value["responseHeaders"]
        .as_object()?
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))?
        .1
        .as_str()
        .map(str::to_string)
}
fn sink(value: &Value, host: &str) -> Option<String> {
    let raw = location(value)?;
    let raw = if raw.starts_with("//") {
        format!("https:{raw}")
    } else {
        raw
    };
    let url = reqwest::Url::parse(&raw).ok()?;
    if !["http", "https"].contains(&url.scheme())
        || url.host_str() != Some(host)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    Some(format!(
        "{}{}",
        url.path(),
        url.query().map(|q| format!("?{q}")).unwrap_or_default()
    ))
}
fn prepare(request: &Value) -> Value {
    let mut r = request.clone();
    r["headers"].as_object_mut().unwrap().retain(|k, _| {
        !matches!(
            k.to_ascii_lowercase().as_str(),
            "cache-control" | "pragma" | "host" | "x-forwarded-host"
        )
    });
    r["headers"]["cache-control"] = json!("no-store");
    r["headers"]["pragma"] = json!("no-cache");
    r
}
struct Runner<'a> {
    entry: &'a TrafficEntry,
    state: &'a AuditState,
    intercept: &'a Intercept,
    start: Instant,
    evidence: Vec<Value>,
    sent: usize,
}
impl Runner<'_> {
    async fn send(
        &mut self,
        request: &Value,
        header: Option<(&str, &str)>,
        label: &str,
    ) -> Option<Value> {
        if !self.state.enabled()
            || !self.intercept.scope().matches(&self.entry.host)
            || self.start.elapsed() >= Duration::from_secs(45)
            || self.sent >= 12
        {
            return None;
        }
        sleep(Duration::from_millis(500)).await;
        if !self.state.enabled() || !self.intercept.scope().matches(&self.entry.host) {
            return None;
        }
        let mut wire = request.clone();
        if let Some((name, value)) = header {
            wire["headers"][name] = json!(value);
        }
        let remaining = Duration::from_secs(45).checked_sub(self.start.elapsed())?;
        let result = tokio::time::timeout(remaining, async {
            match header {
                Some((n, h)) => super::http_sender::send_host(wire.clone(), n, h).await,
                None => super::http_sender::send(Json(wire.clone())).await.0,
            }
        })
        .await
        .unwrap_or_else(|_| json!({"ok":false,"error":"Host audit timed out"}));
        self.sent += 1;
        let mut e = json!({"id":format!("host-{}",self.sent),"label":label,"request":wire,"timestamp":chrono::Utc::now().to_rfc3339(),"duration":result["duration"].as_u64().unwrap_or(0).min(3600000),"size":result["size"].as_u64().unwrap_or(0).min(2000000),"setCookies":[],"truncated":false});
        if result["ok"] == true {
            let body = result["responseBody"].as_str().unwrap_or("");
            let mut headers = result["responseHeaders"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            let count = headers.len();
            headers.retain(|_, v| v.as_str().is_some_and(|s| s.len() <= 8192));
            let headers: serde_json::Map<_, _> = headers.into_iter().take(200).collect();
            e["truncated"] = json!(body.chars().count() > 32000 || headers.len() != count);
            e["response"] = json!({"status":result["status"],"responseHeaders":headers,"responseBody":audit::preview(body,32000)});
        } else {
            e["error"] = json!(audit::preview(
                result["error"].as_str().unwrap_or("Request failed"),
                4000
            ));
        }
        self.evidence.push(e);
        Some(result)
    }
    fn last(&self) -> String {
        self.evidence.last().unwrap()["id"].as_str().unwrap().into()
    }
}
pub(super) async fn audit(
    entry: &TrafficEntry,
    id: &str,
    state: &AuditState,
    intercept: &Intercept,
) -> Option<Value> {
    let original = audit::request(entry)?;
    let request = prepare(&original);
    let mut runner = Runner {
        entry,
        state,
        intercept,
        start: Instant::now(),
        evidence: vec![audit::observed(entry, &original)],
        sent: 0,
    };
    let baseline = runner
        .send(&request, None, "Host header original control")
        .await?;
    let baseline_id = runner.last();
    let mut findings = vec![];
    let mut complete = baseline["ok"] == true;
    if complete {
        for name in ["host", "x-forwarded-host"] {
            let mut refs = vec!["observed".to_string(), baseline_id.clone()];
            let mut shape = None;
            let mut matched = true;
            let mut markers = vec![];
            for _ in 0..2 {
                let host = format!("slurp-{}.invalid", uuid::Uuid::new_v4().simple());
                let Some(result) = runner
                    .send(
                        &request,
                        Some((name, &host)),
                        "Host header independent host probe",
                    )
                    .await
                else {
                    complete = false;
                    matched = false;
                    break;
                };
                refs.push(runner.last());
                if result["ok"] != true {
                    complete = false;
                    matched = false;
                    break;
                }
                let mut control_request = request.clone();
                control_request["headers"]["X-Slurp-Host-Control"] = json!(host);
                let Some(control) = runner
                    .send(&control_request, None, "Unused host marker control")
                    .await
                else {
                    complete = false;
                    matched = false;
                    break;
                };
                refs.push(runner.last());
                if control["ok"] != true {
                    complete = false;
                    matched = false;
                    break;
                }
                if sink(&control, &host).is_some() {
                    matched = false;
                    break;
                }
                let Some(found) = sink(&result, &host) else {
                    matched = false;
                    break;
                };
                if shape.as_ref().is_some_and(|s| s != &found) {
                    matched = false;
                    break;
                }
                shape = Some(found);
                markers.push(host);
            }
            if matched {
                let Some(restored) = runner
                    .send(&request, None, "Host header restored original control")
                    .await
                else {
                    complete = false;
                    break;
                };
                refs.push(runner.last());
                if restored["ok"] != true
                    || baseline["status"] != restored["status"]
                    || location(&baseline) != location(&restored)
                {
                    complete = false;
                    continue;
                }
                let fid = format!("host-{}", findings.len() + 1);
                let references: Vec<&str> = refs.iter().map(String::as_str).collect();
                let mut f=audit::finding("host-header",&fid,&format!("Host header injection via {name}"),"Two independent untrusted host values changed the absolute Location destination to their own hostname with the same path/query. Original and restored controls matched. The connection remained pinned to the original URL. This establishes redirect generation from an untrusted host, not password-reset poisoning, cache poisoning or server-side request forgery.".into(),references,markers,"medium");
                f["endpoint"] = original["url"].clone();
                f["method"] = original["method"].clone();
                f["baselineId"] = json!(baseline_id);
                findings.push(f);
            }
        }
    }
    let checks = vec![
        json!({"checkId":"host-header","status":if !findings.is_empty(){"findings"}else if complete{"passed"}else{"inconclusive"},"message":"Bounded Host/X-Forwarded-Host redirect checks; transport failures are inconclusive","findingIds":findings.iter().map(|f|f["id"].clone()).collect::<Vec<_>>()}),
    ];
    let mut run = audit::run(
        entry,
        id,
        &original,
        runner.evidence,
        findings,
        checks,
        runner.sent,
        "active",
    );
    run["auditKey"] = json!(key(&original));
    run["profileName"] = json!("Automatic Host header injection");
    run["plan"]["maxRequests"] = json!(12);
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_real_matching_redirect_destinations_count() {
        for location in [
            "https://slurp-a.invalid/path?x=1",
            "//slurp-a.invalid/path?x=1",
        ] {
            assert_eq!(
                sink(
                    &json!({"ok":true,"responseHeaders":{"Location":location}}),
                    "slurp-a.invalid"
                ),
                Some("/path?x=1".into())
            );
        }
        for location in [
            "/slurp-a.invalid",
            "https://slurp-a.invalid.evil.com/path",
            "https://slurp-a.invalid@other.invalid",
            "https://user@slurp-a.invalid/",
        ] {
            assert_eq!(
                sink(
                    &json!({"ok":true,"responseHeaders":{"location":location}}),
                    "slurp-a.invalid"
                ),
                None
            );
        }
        assert_eq!(
            sink(
                &json!({"ok":true,"responseHeaders":{},"responseBody":"https://slurp-a.invalid/"}),
                "slurp-a.invalid"
            ),
            None
        );
    }
    #[tokio::test]
    async fn verifies_host_and_forwarding_redirects_with_negative_controls() {
        use axum::{http::HeaderMap, routing::get, Router};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/page",
            get(|h: HeaderMap| async move {
                let host = h
                    .get("x-forwarded-host")
                    .unwrap_or(&h["host"])
                    .to_str()
                    .unwrap();
                (
                    axum::http::StatusCode::FOUND,
                    [("location", format!("http://{host}/login"))],
                )
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let url = format!("http://{addr}/page");
        let mut entry = TrafficEntry::new_request(
            "GET",
            &url,
            "127.0.0.1",
            "/page",
            "http",
            "{}",
            vec![],
            None,
        );
        entry.status_code = 302;
        entry.response_headers = json!({"location":format!("http://{addr}/login")}).to_string();
        assert!(eligible(&entry));
        let storage = proxy_core::TrafficStorage::new(":memory:", 100000).unwrap();
        let intercept = Intercept::new(storage.clone());
        let (state, _runtime) = audit::start(storage, intercept.clone());
        let run = audit(&entry, "host-test", &state, &intercept)
            .await
            .unwrap();
        assert_eq!(run["findings"].as_array().unwrap().len(), 2);
        assert_eq!(run["sent"], 11);
        server.abort();
    }
    #[test]
    fn authentication_context_changes_dedup_key() {
        assert_ne!(
            key(&json!({"headers":{"Authorization":"a"}})),
            key(&json!({"headers":{"Authorization":"b"}}))
        );
    }
}
