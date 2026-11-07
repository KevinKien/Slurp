//! Automatic OAuth authorize audit from captured traffic.
//!
//! Bounded and non-destructive: only GET authorize requests are considered, the authorization
//! server is contacted (never the attacker destination), no code or token is used and no account
//! registration is attempted. The callback-host fingerprint is limited to the same site to avoid
//! scanning unrelated third parties.
use super::auto_audit::{self as audit, AuditState};
use axum::Json;
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::time::{sleep, Duration, Instant};

const SEND_DEADLINE: Duration = Duration::from_secs(45);
const MAX_SENDS: usize = 12;

struct Runner<'a> {
    entry: &'a TrafficEntry,
    state: &'a AuditState,
    intercept: &'a Intercept,
    start: Instant,
    evidence: Vec<Value>,
    sent: usize,
}

impl Runner<'_> {
    async fn send(&mut self, request: &Value, label: &str) -> Option<Value> {
        if self.sent >= MAX_SENDS
            || !self.state.enabled()
            || !self.intercept.scope().matches(&self.entry.host)
            || self.start.elapsed() >= SEND_DEADLINE
        {
            return None;
        }
        sleep(Duration::from_millis(500)).await;
        if !self.state.enabled()
            || !self.intercept.scope().matches(&self.entry.host)
            || self.start.elapsed() >= SEND_DEADLINE
        {
            return None;
        }
        let remaining = SEND_DEADLINE
            .checked_sub(self.start.elapsed())
            .unwrap_or(Duration::from_millis(1));
        let result =
            match tokio::time::timeout(remaining, super::http_sender::send(Json(request.clone())))
                .await
            {
                Ok(value) => value.0,
                Err(_) => json!({"ok":false,"error":"Automatic OAuth audit deadline reached"}),
            };
        self.sent += 1;
        let mut item = json!({
            "id": format!("oauth-{}", self.sent),
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
            let mut headers = result["responseHeaders"]
                .as_object()
                .cloned()
                .unwrap_or_default();
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
        self.evidence.push(item);
        Some(result)
    }

    fn last(&self) -> &Value {
        self.evidence.last().unwrap()
    }
}

fn header_value(result: &Value, name: &str) -> Option<String> {
    result["responseHeaders"]
        .as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_string)
}

fn location_host(result: &Value, base: &str) -> Option<String> {
    let raw = header_value(result, "location")?;
    let parsed = reqwest::Url::parse(&raw)
        .or_else(|_| reqwest::Url::parse(base).and_then(|url| url.join(&raw)))
        .ok()?;
    parsed.host_str().map(|host| host.to_ascii_lowercase())
}

fn set_query(request: &Value, name: &str, value: &str) -> Option<Value> {
    let mut out = request.clone();
    let mut url = reqwest::Url::parse(request["url"].as_str()?).ok()?;
    let mut found = false;
    let mut segments: Vec<String> = url
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let raw_name = segment.split('=').next().unwrap_or(segment);
            if raw_name == name {
                found = true;
                format!("{raw_name}={}", encode(value))
            } else {
                segment.to_string()
            }
        })
        .collect();
    if !found {
        segments.push(format!("{name}={}", encode(value)));
    }
    url.set_query(Some(&segments.join("&")));
    out["url"] = json!(url.as_str());
    Some(out)
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b' ' => out.push_str("%20"),
            b'#' => out.push_str("%23"),
            b'&' => out.push_str("%26"),
            b'+' => out.push_str("%2B"),
            byte => out.push(byte as char),
        }
    }
    out
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut values = Vec::new();
    for byte in input.bytes() {
        let Some(value) = TABLE.iter().position(|item| *item == byte) else {
            if byte == b'=' {
                continue;
            }
            return None;
        };
        values.push(value as u32);
    }
    let mut out = Vec::new();
    for chunk in values.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let mut triple = chunk[0] << 18;
        triple |= chunk[1] << 12;
        if chunk.len() > 2 {
            triple |= chunk[2] << 6;
        }
        if chunk.len() > 3 {
            triple |= chunk[3];
        }
        out.push((triple >> 16) as u8);
        if chunk.len() > 2 {
            out.push((triple >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(triple as u8);
        }
    }
    Some(out)
}

fn id_token_claims(body: &str) -> Option<Value> {
    let index = body.find("\"id_token\"")?;
    let rest = &body[index..];
    let rest = &rest[rest.find(':')? + 1..];
    let start = rest.find('"')? + 1;
    let token = &rest[start..];
    let payload = token[..token.find('"')?].split('.').nth(1)?;
    let decoded = b64url_decode(payload)?;
    serde_json::from_str(&String::from_utf8_lossy(&decoded)).ok()
}

/// Same registrable domain heuristic: the last two labels match and both hosts have at least two.
fn same_site(a: &str, b: &str) -> bool {
    let left: Vec<&str> = a.split('.').collect();
    let right: Vec<&str> = b.split('.').collect();
    left.len() >= 2 && right.len() >= 2 && left[left.len() - 2..] == right[right.len() - 2..]
}

pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    if entry.method != "GET" || !(200..500).contains(&entry.status_code) {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(&entry.url) else {
        return false;
    };
    let mut client = false;
    let mut redirect = false;
    let mut authorize = url.path().to_ascii_lowercase().contains("authorize");
    for (name, _) in url.query_pairs() {
        match name.as_ref() {
            "client_id" => client = true,
            "redirect_uri" => redirect = true,
            "response_type" => authorize = true,
            _ => {}
        }
    }
    client && redirect && authorize
}

pub(super) fn key(request: &Value) -> String {
    let client = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())
        .ok()
        .map(|url| {
            let client = url
                .query_pairs()
                .find(|(name, _)| name == "client_id")
                .map(|(_, value)| value.to_string())
                .unwrap_or_default();
            format!("{}|{client}", url.origin().ascii_serialization())
        })
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, client.as_bytes());
    let hex: String = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    format!("auto-oauth-{hex}")
}

fn finding(
    id: &str,
    title: &str,
    summary: &str,
    evidence: Vec<String>,
    excerpts: Vec<String>,
    severity: &str,
) -> Value {
    json!({
        "id": id,
        "fingerprint": format!("oauth-redirect:{id}"),
        "checkId": "oauth-redirect",
        "title": title,
        "summary": summary,
        "severity": severity,
        "confidence": "high",
        "status": "needs_review",
        "evidenceIds": evidence,
        "excerpts": excerpts,
        "remediation": "Validate redirect_uri against an exact allowlist per client, require and verify state and nonce, escape all values in form_post responses, remove unclaimed callback hosts and require email_verified before linking accounts.",
        "verification": {
            "method": "automatic OAuth authorize differential with a fresh captured baseline",
            "outcome": "inconclusive",
            "reason": "The observed behavior requires contextual confirmation. No authorization code or token was used and no account registration was attempted."
        }
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
    let url = reqwest::Url::parse(original["url"].as_str()?).ok()?;
    let params: HashMap<String, String> = url
        .query_pairs()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let redirect = params.get("redirect_uri")?.clone();
    let redirect_url = reqwest::Url::parse(&redirect).ok();
    let redirect_host = redirect_url
        .as_ref()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
        .unwrap_or_default();
    let mut runner = Runner {
        entry,
        state,
        intercept,
        start: Instant::now(),
        evidence: vec![audit::observed(entry, &original)],
        sent: 0,
    };
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let attacker = format!("slurp-{}.invalid", &nonce[..8]);
    let marker = format!("slurp-{}", &nonce[8..16]);
    let mut findings = vec![];
    let mut incomplete = false;

    let accepted = |result: &Value| {
        location_host(result, url.as_str()).is_some_and(|host| {
            host == attacker || host.ends_with(&format!(".{attacker}"))
        })
    };

    if let Some(candidate) = set_query(&original, "redirect_uri", &format!("https://{attacker}/callback"))
    {
        let first = runner.send(&candidate, "OAuth redirect attacker origin").await;
        let first_id = runner.last()["id"].as_str().unwrap_or_default().to_string();
        let repeat = runner.send(&candidate, "OAuth redirect attacker origin repeat").await;
        let repeat_id = runner.last()["id"].as_str().unwrap_or_default().to_string();
        match (first, repeat) {
            (Some(first), Some(repeat)) if accepted(&first) && accepted(&repeat) => {
                findings.push(finding(
                    "redirect-attacker-origin",
                    "OAuth redirect_uri accepts an attacker-controlled origin",
                    "The authorization endpoint redirected to an origin the captured client does not own, twice and with the same destination. If codes or tokens are issued to that redirect_uri an attacker can receive them; this audit used no code or token.",
                    vec!["observed".into(), first_id, repeat_id],
                    vec![format!("redirect_uri: https://{attacker}/callback")],
                    "high",
                ));
            }
            (Some(_), Some(_)) => {
                // Plain origin rejected; try prefix/suffix validator bypasses.
                for (label, value) in [
                    (
                        "userinfo",
                        format!("https://{redirect_host}@{attacker}/callback"),
                    ),
                    (
                        "suffix",
                        format!("https://{redirect_host}.{attacker}/callback"),
                    ),
                    ("protocol-relative", format!("//{attacker}/callback")),
                ] {
                    if runner.sent + 2 > MAX_SENDS {
                        incomplete = true;
                        break;
                    }
                    let Some(candidate) = set_query(&original, "redirect_uri", &value) else {
                        continue;
                    };
                    let Some(probe) = runner.send(&candidate, "OAuth redirect_uri bypass").await else {
                        incomplete = true;
                        break;
                    };
                    let probe_id = runner.last()["id"].as_str().unwrap_or_default().to_string();
                    if !accepted(&probe) {
                        continue;
                    }
                    let Some(_repeat) = runner.send(&candidate, "OAuth redirect_uri bypass repeat").await
                    else {
                        incomplete = true;
                        break;
                    };
                    let repeat_id = runner.last()["id"].as_str().unwrap_or_default().to_string();
                    findings.push(finding(
                        &format!("redirect-bypass-{label}"),
                        &format!("redirect_uri bypass accepted: {label}"),
                        "The authorization endpoint rejected a plain attacker origin but redirected to the attacker host for a crafted redirect_uri containing the legitimate host, twice and with the same destination. This indicates prefix or suffix validation instead of exact allowlisting; no code or token was used.",
                        vec!["observed".into(), probe_id, repeat_id],
                        vec![format!("redirect_uri: {value}")],
                        "high",
                    ));
                    break;
                }
            }
            _ => incomplete = true,
        }
    } else {
        incomplete = true;
    }

    if !params.contains_key("state") {
        findings.push(finding(
            "missing-state",
            "OAuth authorize request omits state",
            "The captured authorization request has no state parameter, so the authorization response is not bound to the initiating session. This enables login CSRF and makes mix-up attacks easier when several identity providers are trusted; server-side enforcement cannot be proven without a second provider.",
            vec!["observed".into()],
            vec!["No state parameter in the authorize request".into()],
            "low",
        ));
    }
    let response_type = params.get("response_type").cloned().unwrap_or_default();
    if !params.contains_key("nonce") && response_type.contains("token") {
        findings.push(finding(
            "missing-nonce",
            "OAuth authorize request omits nonce",
            "The request can return tokens but carries no nonce, which weakens ID-token replay and mix-up defenses.",
            vec!["observed".into()],
            vec![format!("response_type: {response_type}")],
            "low",
        ));
    }

    let Some(form_request) = set_query(&original, "response_mode", "form_post")
        .and_then(|value| set_query(&value, "state", &format!("\"><{marker}>")))
    else {
        incomplete = true;
        return finish(runner, id, original, findings, incomplete);
    };
    if let (Some(first), Some(_repeat)) = (
        runner.send(&form_request, "OAuth form_post injection").await,
        runner.send(&form_request, "OAuth form_post injection repeat").await,
    ) {
        let first_id = runner.evidence[runner.evidence.len() - 2]["id"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let repeat_id = runner.last()["id"].as_str().unwrap_or_default().to_string();
        let body = first["responseBody"].as_str().unwrap_or_default();
        if first["ok"] == true
            && body.contains(&format!("<{marker}>"))
            && body.to_ascii_lowercase().contains("<form")
        {
            findings.push(finding(
                "form-post-injection",
                "OAuth form_post response reflects unescaped state",
                "With response_mode=form_post an injected state value appeared as a raw tag in a form response. A raw tag on an auto-submitting identity-provider page can execute script where authorization codes are processed; no script was executed by this audit.",
                vec!["observed".into(), first_id, repeat_id],
                vec![format!("Injected marker: <{marker}>")],
                "medium",
            ));
        }
    } else {
        incomplete = true;
    }

    if !redirect_host.is_empty()
        && redirect_host != url.host_str().unwrap_or_default()
        && same_site(&redirect_host, url.host_str().unwrap_or_default())
        && runner.sent < MAX_SENDS
    {
        let callback = json!({
            "method": "GET",
            "url": format!("https://{redirect_host}/"),
            "headers": {"accept": "text/html"},
            "body": ""
        });
        if let Some(result) = runner.send(&callback, "OAuth callback host fingerprint").await {
            if result["ok"] == true {
                let callback_id = runner.last()["id"].as_str().unwrap_or_default().to_string();
                let body = result["responseBody"].as_str().unwrap_or_default();
                for fingerprint in [
                    "NoSuchBucket",
                    "There isn't a GitHub Pages site here",
                    "This domain is not configured",
                    "no such app",
                    "Fastly error: unknown domain",
                    "The specified bucket does not exist",
                ] {
                    if body.contains(fingerprint) {
                        findings.push(finding(
                            "callback-unclaimed",
                            "OAuth callback host appears unclaimed",
                            "The registered callback host returned a provider placeholder page. If the host can be claimed, authorization codes or tokens sent to it can be intercepted; confirm DNS and ownership before reporting.",
                            vec!["observed".into(), callback_id],
                            vec![
                                format!("Callback host: {redirect_host}"),
                                format!("Fingerprint: {fingerprint}"),
                            ],
                            "medium",
                        ));
                        break;
                    }
                }
            }
        }
    }

    if let Some(claims) = id_token_claims(&String::from_utf8_lossy(&entry.response_body)) {
        let verified = claims["email_verified"] == json!(true)
            || claims["email_verified"] == json!("true");
        if claims["email"].is_string() && !verified {
            findings.push(finding(
                "unverified-email",
                "ID token carries an unverified email",
                "The captured ID token contains an email address without email_verified=true. Applications that link accounts by email could let an attacker register the address first and inherit the account after SSO; this audit attempted no registration.",
                vec!["observed".into()],
                vec![format!(
                    "email_verified={}",
                    claims["email_verified"]
                )],
                "medium",
            ));
        }
    }

    finish(runner, id, original, findings, incomplete)
}

fn finish(
    runner: Runner<'_>,
    id: &str,
    original: Value,
    findings: Vec<Value>,
    incomplete: bool,
) -> Option<Value> {
    let status = if !findings.is_empty() {
        "findings"
    } else if incomplete {
        "inconclusive"
    } else {
        "passed"
    };
    let message = if !findings.is_empty() {
        "Automatic OAuth authorize controls produced findings; review each redirect and form_post observation."
    } else if incomplete {
        "OAuth authorize evidence was incomplete or the request budget was reached."
    } else {
        "No attacker redirect, state/nonce omission, form_post injection or unclaimed callback was observed."
    };
    let checks = vec![json!({
        "checkId": "oauth-redirect",
        "status": status,
        "message": message,
        "findingIds": findings.iter().map(|finding| finding["id"].clone()).collect::<Vec<_>>()
    })];
    let sent = runner.sent;
    let mut run = audit::run(
        runner.entry,
        id,
        &original,
        runner.evidence,
        findings,
        checks,
        sent,
        "active",
    );
    run["auditKey"] = json!(key(&original));
    run["profileName"] = json!("Automatic OAuth authorize audit");
    run["plan"]["maxRequests"] = json!(MAX_SENDS);
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use std::net::SocketAddr;

    fn entry(address: SocketAddr, state: bool) -> TrafficEntry {
        let state = if state { "&state=xyz" } else { "" };
        let url = format!(
            "http://{address}/oauth/authorize?client_id=app&response_type=code&redirect_uri=http%3A%2F%2F{address}%2Fcb{state}"
        );
        let mut entry = TrafficEntry::new_request(
            "GET",
            &url,
            "127.0.0.1",
            "/oauth/authorize",
            "http",
            "{}",
            vec![],
            None,
        );
        entry.status_code = 302;
        entry.response_headers = json!({"location": [format!("http://{address}/cb?code=x")]}).to_string();
        entry.response_body = vec![];
        entry.response_size = 0;
        entry
    }

    async fn idp(strict: bool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/oauth/authorize",
            get(move |Query(params): Query<HashMap<String, String>>| async move {
                let redirect = params.get("redirect_uri").cloned().unwrap_or_default();
                if params.get("response_mode").map(String::as_str) == Some("form_post") {
                    let state = params.get("state").cloned().unwrap_or_default();
                    let body = if strict {
                        format!(
                            "<form method=\"post\"><input name=\"state\" value=\"{}\"></form>",
                            state.replace('<', "&lt;").replace('>', "&gt;")
                        )
                    } else {
                        format!("<form method=\"post\"><input name=\"state\" value=\"{state}\"></form>")
                    };
                    let mut headers = HeaderMap::new();
                    headers.insert("content-type", "text/html".parse().unwrap());
                    return (StatusCode::OK, headers, body);
                }
                if strict && redirect.contains(".invalid") {
                    return (StatusCode::BAD_REQUEST, HeaderMap::new(), "invalid".to_string());
                }
                let mut headers = HeaderMap::new();
                if let Ok(value) = redirect.parse() {
                    headers.insert("location", value);
                }
                (StatusCode::FOUND, headers, String::new())
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (address, server)
    }

    #[test]
    fn eligibility_requires_an_authorize_request() {
        let address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(eligible(&entry(address, true)));
        assert!(eligible(&entry(address, false)));
        let mut other = entry(address, true);
        other.method = "POST".into();
        assert!(!eligible(&other));
        other.method = "GET".into();
        other.url = other.url.replace("client_id=app&", "");
        assert!(!eligible(&other));
    }

    #[test]
    fn key_is_stable_per_origin_and_client() {
        let first = json!({"url": "https://idp.test/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&response_type=code"});
        let same = json!({"url": "https://idp.test/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Fother.test%2Fcb&state=1&response_type=code"});
        let other = json!({"url": "https://idp.test/oauth/authorize?client_id=other&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&response_type=code"});
        assert_eq!(key(&first), key(&same));
        assert_ne!(key(&first), key(&other));
        assert!(key(&first).starts_with("auto-oauth-"));
    }

    #[tokio::test]
    async fn reports_attacker_redirect_and_form_post_injection() {
        let (address, server) = idp(false).await;
        let storage = proxy_core::TrafficStorage::new(":memory:", 100_000).unwrap();
        let intercept = Intercept::new(storage.clone());
        let (state, _runtime) = audit::start(storage.clone(), intercept.clone());
        let entry = entry(address, true);
        let run = audit(&entry, "oauth-test", &state, &intercept)
            .await
            .unwrap();
        super::super::scan::validate_run("oauth-test", &run).unwrap();
        assert_eq!(run["plan"]["mode"], "active");
        assert_eq!(run["checks"][0]["checkId"], "oauth-redirect");
        assert_eq!(run["checks"][0]["status"], "findings");
        let findings = run["findings"].as_array().unwrap();
        assert!(findings.iter().any(|f| f["id"] == "redirect-attacker-origin"));
        assert!(findings.iter().any(|f| f["id"] == "form-post-injection"));
        assert_eq!(run["sent"], 4);
        server.abort();
    }

    #[tokio::test]
    async fn strict_server_passes_and_missing_state_is_reported() {
        let (address, server) = idp(true).await;
        let storage = proxy_core::TrafficStorage::new(":memory:", 100_000).unwrap();
        let intercept = Intercept::new(storage.clone());
        let (state, _runtime) = audit::start(storage.clone(), intercept.clone());
        let strict = audit(&entry(address, true), "oauth-strict", &state, &intercept)
            .await
            .unwrap();
        super::super::scan::validate_run("oauth-strict", &strict).unwrap();
        assert!(strict["findings"].as_array().unwrap().is_empty());
        assert_eq!(strict["checks"][0]["status"], "passed");
        let missing = audit(&entry(address, false), "oauth-state", &state, &intercept)
            .await
            .unwrap();
        super::super::scan::validate_run("oauth-state", &missing).unwrap();
        assert!(missing["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "missing-state"));
        server.abort();
    }
}
