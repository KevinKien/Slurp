//! Automatic, same-endpoint header-based 403 bypass differentials.
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
        if !self.state.enabled()
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
                Err(_) => json!({"ok":false,"error":"Automatic 403 audit duration limit reached"}),
            };
        self.sent += 1;
        let mut item = json!({"id":format!("403-{}",self.sent),"label":label,"timestamp":chrono::Utc::now().to_rfc3339(),"request":request,"setCookies":[],"duration":result["duration"].as_u64().unwrap_or(0).min(3600000),"size":result["size"].as_u64().unwrap_or(0),"truncated":false});
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
fn normalized(value: &Value) -> Option<Value> {
    if value["ok"] != true {
        return None;
    }
    let body = value["responseBody"].as_str()?;
    if body.len() > 128000 {
        return None;
    }
    Some(serde_json::from_str(body).unwrap_or_else(|_| json!(body)))
}
fn denied(value: &Value) -> bool {
    value["ok"] == true && value["status"] == 403
}
fn same(a: &Value, b: &Value) -> bool {
    normalized(a).is_some() && normalized(a) == normalized(b) && a["status"] == b["status"]
}
fn api_success(value: &Value) -> bool {
    if value["ok"] != true || value["status"] != 200 {
        return false;
    }
    let Some(body) = value["responseBody"].as_str() else {
        return false;
    };
    if body.len() > 128000 {
        return false;
    }
    let Ok(json) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let Some(object) = json.as_object().filter(|o| !o.is_empty()) else {
        return json.as_array().is_some_and(|a| !a.is_empty());
    };
    if object.contains_key("error")
        || object.contains_key("errors")
        || object.get("success") == Some(&json!(false))
        || object.get("ok") == Some(&json!(false))
    {
        return false;
    }
    if ["status", "code", "statusCode"].iter().any(|key| {
        object.get(*key).is_some_and(|v| {
            v == &json!(401)
                || v == &json!(403)
                || v.as_str().is_some_and(|s| {
                    [
                        "401",
                        "403",
                        "error",
                        "forbidden",
                        "unauthorized",
                        "denied",
                        "failed",
                    ]
                    .contains(&s.to_ascii_lowercase().as_str())
                })
        })
    }) || object.get("data").is_some_and(Value::is_null)
    {
        return false;
    }
    if object
        .keys()
        .all(|key| ["message", "status", "code", "detail", "success", "ok"].contains(&key.as_str()))
    {
        return false;
    }
    true
}
fn header(request: &Value, name: &str, value: &str) -> Value {
    let mut request = request.clone();
    request["headers"]
        .as_object_mut()
        .unwrap()
        .retain(|k, _| !k.eq_ignore_ascii_case(name));
    request["headers"][name] = json!(value);
    request
}
pub(super) async fn audit(
    entry: &TrafficEntry,
    id: &str,
    state: &AuditState,
    intercept: &Intercept,
) -> Option<Value> {
    let original = audit::request(entry)?;
    let mut runner = Runner {
        entry,
        state,
        intercept,
        start: Instant::now(),
        evidence: vec![audit::observed(entry, &original)],
        sent: 0,
    };
    let mut findings = vec![];
    let mut completed = true;
    let captured_body = String::from_utf8(entry.response_body.clone()).ok();
    let captured =
        captured_body.map(|body| json!({"ok":true,"status":entry.status_code,"responseBody":body}));
    let first = runner.send(&original, "403 original denial control").await;
    let first_id = runner.last_id();
    let second = runner.send(&original, "403 repeated original denial").await;
    let second_id = runner.last_id();
    let stable = match (&first, &second, &captured) {
        (Some(a), Some(b), Some(c)) => {
            denied(a)
                && denied(b)
                && same(a, b)
                && same(a, c)
                && entry.response_size <= entry.response_body.len() as u64
        }
        _ => false,
    };
    if stable {
        let url = reqwest::Url::parse(original["url"].as_str()?).ok()?;
        let path = format!(
            "{}{}",
            url.path(),
            url.query().map(|s| format!("?{s}")).unwrap_or_default()
        );
        let root = format!("{}/", url.origin().ascii_serialization());
        let marker = uuid::Uuid::new_v4().simple().to_string();
        let missing = format!("/slurp-missing-{marker}");
        let evil = format!("https://{marker}.invalid/");
        let variants = [
            ("x-real-ip", "127.0.0.1", "192.0.2.123"),
            ("x-client-ip", "127.0.0.1", "192.0.2.123"),
            ("referer", root.as_str(), evil.as_str()),
            ("x-original-url", path.as_str(), missing.as_str()),
            ("x-rewrite-url", path.as_str(), missing.as_str()),
        ];
        for (name, allowed, rejected) in variants {
            let positive = header(&original, name, allowed);
            let negative = header(&original, name, rejected);
            let Some(a) = runner
                .send(&positive, &format!("403 bypass candidate: {name}"))
                .await
            else {
                completed = false;
                break;
            };
            let a_id = runner.last_id();
            if a["ok"] != true {
                completed = false;
                continue;
            }
            // Status 200 alone, HTML/login pages, empty replies and JSON errors are insufficient.
            if !api_success(&a) {
                continue;
            }
            let Some(b) = runner
                .send(&negative, &format!("403 negative header control: {name}"))
                .await
            else {
                completed = false;
                break;
            };
            let b_id = runner.last_id();
            let Some(c) = runner
                .send(&positive, &format!("403 bypass repeat: {name}"))
                .await
            else {
                completed = false;
                break;
            };
            let c_id = runner.last_id();
            let Some(d) = runner.send(&original, "403 restored original denial").await else {
                completed = false;
                break;
            };
            let d_id = runner.last_id();
            if [b.clone(), c.clone(), d.clone()]
                .iter()
                .any(|r| r["ok"] != true)
            {
                completed = false;
                continue;
            }
            if ![401, 403, 404].iter().any(|code| b["status"] == *code)
                || !api_success(&c)
                || !same(&a, &c)
                || !same(&d, first.as_ref().unwrap())
            {
                continue;
            }
            let finding_id = format!("403-{name}");
            let mut finding=audit::finding("403-bypass",&finding_id,&format!("Possible 403 access-control bypass via {name}"),
                "A single header repeatedly changed a stable 403 into a nonempty JSON API response. A negative header control remained denied/missing, and the unmodified request restored the original denial. Credentials, endpoint, method and body were preserved. Confirm that the returned data/functionality is protected and the header is not intentionally supported.".into(),
                vec!["observed",&first_id,&second_id,&a_id,&b_id,&c_id,&d_id],vec![format!("{name}: {allowed}"),format!("Negative control: {rejected}"),"Captured/original/restore: 403; candidate/repeat: 200 JSON".into()],"medium");
            finding["verification"]["method"]=json!("Stable repeated denial, repeated single-header mutation, negative header control and restored original denial");
            findings.push(finding);
        }
    } else {
        completed = false;
    }
    let check = json!({"checkId":"403-bypass","status":if !findings.is_empty(){"findings"}else if completed{"passed"}else{"inconclusive"},"message":if completed{"Automatic same-endpoint 403 header controls completed; path/method and forwarded-header attacks were not tested"}else{"Unstable denial, incomplete evidence, scope/pause or duration limits; not a clean scan result"},"findingIds":findings.iter().map(|f|f["id"].clone()).collect::<Vec<_>>()});
    let mut run = audit::run(
        entry,
        id,
        &original,
        runner.evidence,
        findings,
        vec![check],
        runner.sent,
        "active",
    );
    run["auditKey"] = json!(audit::forbidden_id(&original));
    run["profileName"] = json!("Automatic 403 bypass");
    run["plan"]["maxRequests"] = json!(22);
    Some(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn success_requires_api_data_not_error_envelopes_or_login_pages() {
        for body in [r#"{"data":{"account":1}}"#, r#"[{"id":1}]"#] {
            assert!(api_success(
                &json!({"ok":true,"status":200,"responseBody":body})
            ));
        }
        for body in [
            "<html>Login</html>",
            "",
            "[]",
            "{}",
            r#"{"status":403,"data":null}"#,
            r#"{"status":"forbidden","payload":"denied"}"#,
            r#"{"error":"denied"}"#,
            r#"{"success":false,"data":{"x":1}}"#,
            r#"{"message":"login required"}"#,
        ] {
            assert!(!api_success(
                &json!({"ok":true,"status":200,"responseBody":body})
            ));
        }
    }
}
