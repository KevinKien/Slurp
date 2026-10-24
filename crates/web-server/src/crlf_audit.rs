//! Automatic CRLF response-header injection checks.
use super::auto_audit::{self as audit, AuditState};
use axum::Json;
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};
use tokio::time::{sleep, Duration, Instant};
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
        if self.sent >= 34
            || !self.state.enabled()
            || !self.intercept.scope().matches(&self.entry.host)
            || self.start.elapsed() >= Duration::from_secs(60)
        {
            return None;
        }
        sleep(Duration::from_millis(500)).await;
        if !self.state.enabled() || !self.intercept.scope().matches(&self.entry.host) {
            return None;
        }
        let remaining = Duration::from_secs(60).checked_sub(self.start.elapsed())?;
        if remaining < Duration::from_secs(1) {
            return None;
        }
        let result =
            match tokio::time::timeout(remaining, super::http_sender::send(Json(request.clone())))
                .await
            {
                Ok(value) => value.0,
                Err(_) => json!({"ok":false,"error":"Automatic CRLF audit duration limit reached"}),
            };
        self.sent += 1;
        let mut item = json!({"id":format!("crlf-{}",self.sent),"label":label,"timestamp":chrono::Utc::now().to_rfc3339(),"request":request,"setCookies":[],"duration":result["duration"].as_u64().unwrap_or(0).min(3600000),"size":result["size"].as_u64().unwrap_or(0),"truncated":false});
        if result["ok"] == true {
            let body = result["responseBody"].as_str().unwrap_or("");
            let mut headers = result["responseHeaders"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            let count = headers.len();
            headers.retain(|_, v| v.as_str().is_some_and(|s| s.len() <= 8192));
            let headers: serde_json::Map<_, _> = headers.into_iter().take(200).collect();
            item["truncated"] = json!(body.chars().count() > 32000 || headers.len() != count);
            item["response"] = json!({"status":result["status"],"responseHeaders":headers,"responseBody":audit::preview(body,32000)});
        } else {
            item["error"] = json!(audit::preview(
                result["error"].as_str().unwrap_or("Request failed"),
                4000
            ));
        }
        self.evidence.push(item);
        Some(result)
    }
    fn last_id(&self) -> String {
        self.evidence.last().unwrap()["id"].as_str().unwrap().into()
    }
}
#[derive(Clone, Debug)]
enum Slot {
    Query(usize),
    Form(usize),
    Json(String),
}
fn part(raw: &str) -> Option<(String, String)> {
    let mut url = reqwest::Url::parse("http://localhost/").ok()?;
    url.set_query(Some(raw));
    url.query_pairs()
        .next()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
}
fn changed(raw: &str, suffix: &str) -> Option<String> {
    let (_, value) = part(raw)?;
    let name = raw.split('=').next()?;
    let mut url = reqwest::Url::parse("http://localhost/").ok()?;
    url.query_pairs_mut()
        .append_pair("v", &format!("{value}{suffix}"));
    Some(format!("{name}={}", url.query()?.strip_prefix("v=")?))
}
fn slots(request: &Value) -> Vec<Slot> {
    let mut out = Vec::new();
    if let Some(url) = request["url"]
        .as_str()
        .and_then(|s| reqwest::Url::parse(s).ok())
    {
        for (i, raw) in url.query().unwrap_or("").split('&').enumerate() {
            let Some((name, value)) = part(raw) else {
                continue;
            };
            if !name.is_empty() && value.len() <= 512 && !credential(&name) {
                out.push(Slot::Query(i));
            }
            if out.len() >= 4 {
                return out;
            }
        }
    }
    let mime = request["headers"]
        .as_object()
        .and_then(|h| {
            h.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        })
        .and_then(|(_, v)| v.as_str())
        .unwrap_or("");
    let body = request["body"].as_str().unwrap_or("");
    if body.len() > 16000 {
        return out;
    }
    if mime
        .to_ascii_lowercase()
        .starts_with("application/x-www-form-urlencoded")
    {
        for (i, part) in body.split('&').enumerate() {
            let Some((name, value)) = self::part(part) else {
                continue;
            };
            if !name.is_empty() && value.len() <= 512 && !credential(&name) {
                out.push(Slot::Form(i));
            }
            if out.len() >= 4 {
                break;
            }
        }
    } else if mime.to_ascii_lowercase().contains("json") {
        fn walk(value: &Value, path: String, depth: usize, out: &mut Vec<Slot>) {
            if depth > 8 || out.len() >= 4 {
                return;
            }
            match value {
                Value::String(s)
                    if !path.is_empty()
                        && s.len() <= 512
                        && !path.rsplit('/').next().is_some_and(credential) =>
                {
                    out.push(Slot::Json(path))
                }
                Value::Object(map) => {
                    for (key, v) in map {
                        walk(
                            v,
                            format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                            depth + 1,
                            out,
                        );
                    }
                }
                Value::Array(list) => {
                    for (i, v) in list.iter().take(100).enumerate() {
                        walk(v, format!("{path}/{i}"), depth + 1, out);
                    }
                }
                _ => {}
            }
        }
        if let Ok(value) = serde_json::from_str::<Value>(body) {
            walk(&value, String::new(), 0, &mut out);
        }
    }
    out.truncate(4);
    out
}
fn credential(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("token")
        || n.contains("password")
        || n.contains("secret")
        || matches!(
            n.as_str(),
            "authorization" | "cookie" | "api_key" | "apikey"
        )
}
pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    audit::request(entry).is_some_and(|r| !slots(&r).is_empty())
}
pub(super) fn key(request: &Value) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, request.to_string().as_bytes());
    format!(
        "auto-crlf-{}",
        digest
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
fn mutate(request: &Value, slot: &Slot, suffix: &str) -> Option<Value> {
    let mut out = request.clone();
    match slot {
        Slot::Query(index) => {
            let mut url = reqwest::Url::parse(request["url"].as_str()?).ok()?;
            let mut parts: Vec<String> = url.query()?.split('&').map(str::to_string).collect();
            parts[*index] = changed(parts.get(*index)?, suffix)?;
            url.set_query(Some(&parts.join("&")));
            out["url"] = json!(url.as_str());
        }
        Slot::Form(index) => {
            let body = request["body"].as_str()?;
            let mut segments: Vec<String> = body.split('&').map(str::to_string).collect();
            segments[*index] = changed(segments.get(*index)?, suffix)?;
            out["body"] = json!(segments.join("&"));
        }
        Slot::Json(pointer) => {
            let mut value: Value = serde_json::from_str(request["body"].as_str()?).ok()?;
            let field = value.pointer_mut(pointer)?;
            *field = json!(format!("{}{suffix}", field.as_str()?));
            out["body"] = json!(value.to_string());
        }
    }
    Some(out)
}
fn header<'a>(result: &'a Value, name: &str) -> Option<&'a str> {
    if result["ok"] != true {
        return None;
    }
    result["responseHeaders"]
        .as_object()?
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))?
        .1
        .as_str()
}
pub(super) async fn audit(
    entry: &TrafficEntry,
    id: &str,
    state: &AuditState,
    intercept: &Intercept,
) -> Option<Value> {
    let original = audit::request(entry)?;
    let candidates = slots(&original);
    if candidates.is_empty() {
        return None;
    }
    let mut runner = Runner {
        entry,
        state,
        intercept,
        start: Instant::now(),
        evidence: vec![audit::observed(entry, &original)],
        sent: 0,
    };
    let mut findings = vec![];
    let mut complete = true;
    let baseline = runner
        .send(&original, "CRLF original header control")
        .await?;
    if baseline["ok"] != true || header(&baseline, "x-slurp-crlf").is_some() {
        complete = false;
    }
    let baseline_id = runner.last_id();
    if complete {
        'slots: for slot in candidates {
            for encoded in [false, true] {
                let mut evidence = vec!["observed".to_string(), baseline_id.clone()];
                let mut markers = vec![];
                let mut matched = true;
                for _ in 0..2 {
                    let marker = uuid::Uuid::new_v4().simple().to_string();
                    let line = if encoded { "%0d%0a" } else { "\r\n" };
                    let probe = mutate(&original, &slot, &format!("{line}X-Slurp-Crlf: {marker}"))?;
                    let control = mutate(&original, &slot, &format!(" X-Slurp-Crlf: {marker}"))?;
                    let Some(a) = runner.send(&probe, "CRLF encoded line-break probe").await else {
                        complete = false;
                        break 'slots;
                    };
                    evidence.push(runner.last_id());
                    let Some(b) = runner
                        .send(&control, "CRLF plain-text negative control")
                        .await
                    else {
                        complete = false;
                        break 'slots;
                    };
                    evidence.push(runner.last_id());
                    if a["ok"] != true || b["ok"] != true {
                        complete = false;
                        matched = false;
                        break;
                    }
                    if header(&a, "x-slurp-crlf").map(str::trim) != Some(marker.as_str())
                        || header(&b, "x-slurp-crlf").is_some()
                    {
                        matched = false;
                        break;
                    }
                    markers.push(marker);
                }
                if !matched {
                    continue;
                }
                let Some(restored) = runner
                    .send(&original, "CRLF restored original header control")
                    .await
                else {
                    complete = false;
                    break 'slots;
                };
                evidence.push(runner.last_id());
                if restored["ok"] != true || header(&restored, "x-slurp-crlf").is_some() {
                    complete = false;
                    continue;
                }
                let finding_id = format!("crlf-{}", findings.len() + 1);
                let refs: Vec<&str> = evidence.iter().map(String::as_str).collect();
                let mut f=audit::finding("header-injection",&finding_id,"CRLF injection: input created a response header",
                    format!("Two independent markers became actual X-Slurp-Crlf response headers for {slot:?} using {} line breaks. Plain-text controls and the restored original did not produce that header. Body reflection is ignored; response splitting and downstream impact are not established.",if encoded{"percent-encoded"}else{"CRLF"}),refs,markers,"medium");
                f["endpoint"] = original["url"].clone();
                f["method"] = original["method"].clone();
                f["baselineId"] = json!(baseline_id);
                f["parameter"] = match &slot {
                    Slot::Json(pointer) => json!({"kind":"json","pointer":pointer}),
                    Slot::Query(index) | Slot::Form(index) => {
                        let raw = if matches!(slot, Slot::Query(_)) {
                            reqwest::Url::parse(original["url"].as_str()?)
                                .ok()?
                                .query()?
                                .to_string()
                        } else {
                            original["body"].as_str()?.to_string()
                        };
                        let name = part(raw.split('&').nth(*index)?)?.0;
                        let occurrence = raw
                            .split('&')
                            .take(*index)
                            .filter(|raw| part(raw).is_some_and(|(n, _)| n == name))
                            .count();
                        json!({"kind":if matches!(slot,Slot::Query(_)){"query"}else{"form"},"name":name,"occurrence":occurrence})
                    }
                };
                findings.push(f);
                break;
            }
        }
    }
    let checks = vec![
        json!({"checkId":"header-injection","status":if !findings.is_empty(){"findings"}else if complete{"passed"}else{"inconclusive"},"message":if complete{"Bounded CRLF response-header controls completed"}else{"CRLF audit incomplete: scope/pause, time limit, transport error or unstable controls"},"findingIds":findings.iter().map(|f|f["id"].clone()).collect::<Vec<_>>()}),
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
    run["profileName"] = json!("Automatic CRLF injection");
    run["plan"]["maxRequests"] = json!(34);
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::Query,
        http::{HeaderMap, HeaderValue},
        routing::get,
        Router,
    };
    use proxy_core::TrafficStorage;
    use std::collections::HashMap;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    fn entry(url: &str) -> TrafficEntry {
        let mut e =
            TrafficEntry::new_request("GET", url, "127.0.0.1", "/page", "http", "{}", vec![], None);
        e.status_code = 200;
        e.response_headers = "{}".into();
        e.response_body = b"captured".to_vec();
        e.response_size = 8;
        e.response_content_type = Some("text/html".into());
        e
    }
    async fn target(mode: &'static str) -> (String, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let record = calls.clone();
        let app = Router::new().route(
            "/page",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let record = record.clone();
                async move {
                    record.fetch_add(1, Ordering::Relaxed);
                    let q = query.get("q").cloned().unwrap_or_default();
                    let allows_header =
                        mode == "vulnerable" || (mode == "double" && q.contains("%0d%0a"));
                    let q = if mode == "double" {
                        q.replace("%0d%0a", "\r\n")
                    } else {
                        q
                    };
                    let mut headers = HeaderMap::new();
                    if allows_header && q.contains("\r\nX-Slurp-Crlf: ") || mode == "blanket" {
                        if let Some(marker) = q.split("X-Slurp-Crlf: ").nth(1) {
                            headers.insert("x-slurp-crlf", HeaderValue::from_str(marker).unwrap());
                        }
                    }
                    (headers, q)
                }
            }),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/page?q=hello"), task, calls)
    }
    #[test]
    fn bounded_candidates_and_mutations_preserve_other_encoded_fields() {
        let r = json!({"method":"POST","url":"http://localhost/page?x=a%2Fb&&x=second&token=secret","headers":{"content-type":"application/x-www-form-urlencoded"},"body":"keep=a%2Fb&&name=b&name=c"});
        let mutated = mutate(&r, &Slot::Query(2), "\r\nX-Test: ok").unwrap();
        assert!(mutated["url"]
            .as_str()
            .unwrap()
            .contains("x=a%2Fb&&x=second%0D%0AX-Test%3A+ok&token=secret"));
        let mutated = mutate(&r, &Slot::Form(2), "\r\nX-Test: ok").unwrap();
        assert_eq!(
            mutated["body"],
            "keep=a%2Fb&&name=b%0D%0AX-Test%3A+ok&name=c"
        );
        assert_eq!(slots(&r).len(), 4);
        let j = json!({"url":"http://localhost/page","headers":{"content-type":"application/json"},"body":"{\"nested\":{\"redirect\":\"/home\"},\"quantity\":5,\"token\":\"secret\"}"});
        assert_eq!(slots(&j).len(), 1);
        let out = mutate(&j, &slots(&j)[0], "\r\nX-Test: ok").unwrap();
        let body: Value = serde_json::from_str(out["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["nested"]["redirect"], "/home\r\nX-Test: ok");
        assert_eq!(body["quantity"], 5);
        let mut other = j.clone();
        other["headers"]["authorization"] = json!("other user");
        assert_ne!(key(&j), key(&other));
    }
    #[tokio::test]
    async fn detects_actual_header_with_controls_and_saves_once_per_workspace() {
        let (url, server, calls) = target("vulnerable").await;
        let storage = TrafficStorage::new(":memory:", 100000).unwrap();
        let workspace = storage.create_workspace("CRLF").unwrap().id;
        storage.set_active_workspace(&workspace).unwrap();
        let intercept = Intercept::new(storage.clone());
        let (_state, runtime) = audit::start(storage.clone(), intercept.clone());
        let e = entry(&url);
        let id = key(&audit::request(&e).unwrap());
        storage.insert(&e).unwrap();
        storage.insert(&entry(&url)).unwrap();
        let run = tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if let Some(run) = storage.get_scan_run(&workspace, &id).unwrap() {
                    break run;
                }
                sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .unwrap();
        super::super::scan::validate_run(&id, &run).unwrap();
        assert_eq!(run["findings"].as_array().unwrap().len(), 1);
        assert_eq!(run["checks"][0]["status"], "findings");
        assert_eq!(run["findings"][0]["parameter"]["name"], "q");
        assert_eq!(run["sent"], 6);
        let sent = calls.load(Ordering::Relaxed);
        drop(runtime);
        let (_state, _runtime) = audit::start(storage.clone(), intercept);
        storage.insert(&entry(&url)).unwrap();
        sleep(Duration::from_millis(800)).await;
        assert_eq!(calls.load(Ordering::Relaxed), sent);
        assert_eq!(storage.list_scan_runs(&workspace, 0).unwrap().len(), 1);
        assert!(storage
            .has_completed_automatic_check(&workspace, &id, "header-injection")
            .unwrap());
        let other = storage.create_workspace("Other").unwrap().id;
        assert!(!storage
            .has_completed_automatic_check(&other, &id, "header-injection")
            .unwrap());
        server.abort();
    }
    #[tokio::test]
    async fn encoded_variant_is_verified_and_out_of_scope_requests_never_send() {
        let (url, server, calls) = target("double").await;
        let storage = TrafficStorage::new(":memory:", 100000).unwrap();
        let intercept = Intercept::new(storage.clone());
        let (state, _runtime) = audit::start(storage, intercept.clone());
        let e = entry(&url);
        intercept
            .update_scope(proxy_core::ScopeSettings {
                enabled: true,
                domains: vec!["other.test".into()],
            })
            .unwrap();
        assert!(audit(&e, "outside", &state, &intercept).await.is_none());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        intercept
            .update_scope(proxy_core::ScopeSettings {
                enabled: false,
                domains: vec![],
            })
            .unwrap();
        let run = audit(&e, "encoded", &state, &intercept).await.unwrap();
        assert_eq!(run["sent"], 8);
        assert_eq!(run["findings"].as_array().unwrap().len(), 1);
        super::super::scan::validate_run("encoded", &run).unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn body_reflection_or_header_echo_without_crlf_never_creates_a_finding() {
        for mode in ["body", "blanket"] {
            let (url, server, _) = target(mode).await;
            let storage = TrafficStorage::new(":memory:", 100000).unwrap();
            let intercept = Intercept::new(storage.clone());
            let (state, _runtime) = audit::start(storage, intercept.clone());
            let e = entry(&url);
            let run = audit(&e, "negative-crlf", &state, &intercept)
                .await
                .unwrap();
            assert!(run["findings"].as_array().unwrap().is_empty());
            super::super::scan::validate_run("negative-crlf", &run).unwrap();
            server.abort();
        }
    }
}
