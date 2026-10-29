//! Local, workspace-scoped immutable scan evidence. Scans execute through the existing Replay sender.
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use proxy_core::{TrafficStorage, WorkspaceError};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc};
type Error = (StatusCode, Json<Value>);
fn bad(message: impl ToString) -> Error {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":message.to_string()})),
    )
}
fn storage_error(error: WorkspaceError) -> Error {
    (
        match error {
            WorkspaceError::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::CONFLICT,
        },
        Json(json!({"error":error.to_string()})),
    )
}
fn text(value: &Value, max: usize) -> bool {
    value
        .as_str()
        .is_some_and(|s| !s.is_empty() && s.len() <= max)
}
fn number(value: &Value, max: u64) -> bool {
    value.as_u64().is_some_and(|n| n <= max)
}
fn strings(value: &Value, count: usize, len: usize) -> bool {
    value.as_array().is_some_and(|v| {
        v.len() <= count && v.iter().all(|s| s.as_str().is_some_and(|s| s.len() <= len))
    })
}
fn script_urls(value: &Value) -> bool {
    value.as_array().is_some_and(|urls| {
        urls.len() <= 16 && urls.iter().all(|v| {
            v.as_str().is_some_and(|s| {
                s.len() <= 4096 && reqwest::Url::parse(s).is_ok_and(|url| {
                    super::http_target::validate(&url).is_ok() && url.fragment().is_none()
                })
            })
        })
    })
}
fn check_id(value: &Value) -> bool {
    matches!(
        value.as_str(),
        Some(
            "parameter-hints" | "hidden-parameters" | "business-negative" | "business-dates" | "jwt-jwk" | "jwt-jku" | "jwt-x5u" | "jwt-kid" | "cookie-flags"
                | "403-bypass" | "dependency-audit" | "jwt-weak-secret" | "nosql-injection" | "nosql-operators" | "jwt-confusion" | "jwt-signature" | "graphql-introspection" | "graphql-batching" | "http-framing"
                | "browser-xss" | "dom-xss" | "dom-interaction" | "oast-ssrf" | "oast-xxe"
                | "error-disclosure"
                | "security-headers"
                | "reflection"
                | "input-errors"
                | "cors" | "cors-trust"
                | "noauthen"
                | "js-endpoints"
                | "js-secrets"
                | "sql-boolean" | "sql-time" | "header-injection" | "host-header" | "auth-access" | "referer-access" | "client-ip" | "url-override" | "http-methods"
                | "command-injection" | "code-injection" | "el-injection" | "ldap-injection" | "xpath-injection" | "xml-injection" | "xml-entity" | "xxe" | "xml-injection-body" | "xml-entity-body" | "xxe-body"
                | "cookie-audit" | "disclosure-audit" | "policy-audit"
                | "php2shell" | "http2shell" | "react2shell"
                | "passive-audit" | "sql-injection" | "ssti" | "path-traversal" | "open-redirect"
        )
    )
}
pub fn validate_run(id: &str, run: &Value) -> Result<(), Error> {
    if id.is_empty()
        || id.len() > 100
        || run["id"].as_str() != Some(id)
        || run["version"] != 1
        || !text(&run["startedAt"], 100)
        || !text(&run["finishedAt"], 100)
        || !matches!(
            run["status"].as_str(),
            Some("completed" | "stopped" | "failed")
        )
        || !number(&run["sent"], 9_007_199_254_740_991)
        || run.to_string().len() > 12_000_000
    {
        return Err(bad(
            "Invalid or unfinished scan run (maximum 12 MB)",
        ));
    }
    crate::replay::validate_request(&run["plan"]["request"])?;
    if let Some(key) = run["plan"].get("jwtPublicKey") {
        if !key.as_str().is_some_and(|s| s.len() <= 16000 && !s.contains("PRIVATE KEY")) {
            return Err(bad("JWT key must be a public PEM, at most 16 KB"));
        }
    }
    if !matches!(run["plan"]["mode"].as_str(), Some("passive" | "active" | "both")) {
        return Err(bad("Invalid scan mode"));
    }
    let crawl = run["plan"]["crawlBeforeScan"] == true;
    if let Some(enabled) = run["plan"].get("crawlBeforeScan") {
        if !enabled.is_boolean() { return Err(bad("Invalid crawl option")); }
    }
    let mut crawl_limit = 20;
    if let Some(options) = run["plan"].get("crawlOptions") {
        if !options["maxUrls"].as_u64().is_some_and(|n| (1..=50).contains(&n))
            || !number(&options["maxDepth"], 5) { return Err(bad("Invalid crawl limits")); }
        crawl_limit = options["maxUrls"].as_u64().unwrap();
    }
    if crawl && run["plan"]["allowSending"] != true { return Err(bad("Crawling requires sending permission")); }
    if let Some(progress) = run.get("crawl") {
        if !crawl || !matches!(progress["phase"].as_str(), Some("crawling" | "scanning" | "completed"))
            || !number(&progress["fetched"], crawl_limit) || !number(&progress["queued"], crawl_limit)
            || !strings(&progress["urls"], crawl_limit as usize, 4096) { return Err(bad("Invalid crawl progress")); }
    }
    if run["plan"]["mode"] == "passive"
        && (run["sent"].as_u64().unwrap_or(u64::MAX) > if crawl { crawl_limit + 1 } else { 1 }
            || (run["sent"].as_u64().unwrap_or(0) > 0 && run["plan"]["allowSending"] != true))
    {
        return Err(bad("Passive scans may only fetch their response or an explicitly enabled bounded crawl"));
    }
    let evidence = run["evidence"]
        .as_array()
        .ok_or_else(|| bad("Invalid evidence list"))?;
    let mut ids = HashSet::new();
    for e in evidence {
        if !text(&e["id"], 100)
            || !ids.insert(e["id"].as_str().unwrap())
            || !text(&e["label"], 200)
            || !text(&e["timestamp"], 100)
            || !e["truncated"].is_boolean()
            || !number(&e["size"], 2_000_000)
            || e["duration"]
                .as_f64()
                .is_none_or(|n| !n.is_finite() || !(0.0..=3_600_000.0).contains(&n))
            || !strings(&e["setCookies"], 1000, 16384)
        {
            return Err(bad("Invalid scan evidence"));
        }
        crate::replay::validate_request(&e["request"])?;
        for (field, limit) in [("rawRequest",16000),("rawResponse",32000)] {
            if let Some(raw) = e.get(field) { if !text(raw,limit) { return Err(bad("Invalid raw protocol evidence")); } }
        }
        if let Some(browser) = e.get("browser") {
            let valid = browser.as_array().is_some_and(|observations| {
                observations.len() <= 500 && observations.iter().all(|o| {
                    o["executed"].is_boolean() && text(&o["marker"], 100)
                        && text(&o["url"], 12000) && text(&o["browser"], 200)
                        && strings(&o["sinks"], 12, 100)
                        && o.get("interactions").is_none_or(|v|strings(v,16,800))
                        && strings(&o["cspViolations"], 6, 2000)
                        && o.get("requestedScripts").is_none_or(|v| script_urls(v))
                        && number(&o["blockedRequests"], 9_007_199_254_740_991)
                        && o.get("sinkTraces").is_none_or(|v| v.as_array().is_some_and(|traces| {
                            traces.len() <= 12 && traces.iter().all(|t| text(&t["sink"],100)
                                && t["value"].as_str().is_some_and(|s|s.len()<=2000)
                                && t["stack"].as_str().is_some_and(|s|s.len()<=6000))
                        }))
                })
            });
            if !valid { return Err(bad("Invalid browser evidence")); }
        }
        if let Some(probes) = e.get("oast") {
            if !probes.as_array().is_some_and(|probes|probes.len()<=4 && probes.iter().all(|p| {
                text(&p["id"],100) && text(&p["url"],4096) && text(&p["expiresAt"],100)
                    && p.get("dnsName").is_none_or(|v|text(v,253))
                    && p["events"].as_array().is_some_and(|events|events.len()<=16 && events.iter().all(|v| {
                        matches!(v["protocol"].as_str(),Some("http"|"dns")) && text(&v["timestamp"],100) && text(&v["peer"],100) && text(&v["detail"],2000)
                    }))
            })) { return Err(bad("Invalid OAST evidence")); }
        }
        if let Some(response) = e.get("response") {
            if response["status"]
                .as_u64()
                .is_none_or(|s| !(100..=599).contains(&s))
                || response["responseBody"]
                    .as_str()
                    .is_none_or(|s| s.len() > 128000)
                || response["responseHeaders"]
                    .as_object()
                    .is_none_or(|h| h.len() > 200 || h.values().any(|v| !v.is_string()))
            {
                return Err(bad("Invalid response preview"));
            }
        } else if !text(&e["error"], 10000) {
            return Err(bad("Expected a response or error"));
        }
    }
    let refs = |value: &Value| {
        value.as_array().is_some_and(|v| {
            v.len() <= evidence.len()
                && v.iter()
                    .all(|id| id.as_str().is_some_and(|id| ids.contains(id)))
        })
    };
    if !refs(&run["baselineIds"]) {
        return Err(bad("Unknown baseline evidence reference"));
    }
    if let Some(audits) = run.get("domAudits") {
        let valid = audits.as_array().is_some_and(|audits| audits.len() <= 10 && audits.iter().all(|a| {
            text(&a["id"],100) && text(&a["url"],12000) && strings(&a["notes"],40,4000)
                && a.get("runtimeScripts").is_none_or(|v| script_urls(v))
                && a["scripts"].as_array().is_some_and(|scripts| scripts.len()<=116 && scripts.iter().all(|s| {
                    text(&s["url"],12000) && s["evidenceId"].as_str().is_some_and(|id|ids.contains(id))
                        && strings(&s["sources"],30,4000) && strings(&s["sinks"],30,4000) && s["parsed"].is_boolean()
                }))
                && a["candidates"].as_array().is_some_and(|candidates| candidates.len()<=40 && candidates.iter().all(|c| {
                    text(&c["id"],100) && text(&c["script"],12000) && text(&c["sink"],4000)
                        && number(&c["line"],1_000_000) && number(&c["column"],1_000_000)
                        && text(&c["excerpt"],4000) && strings(&c["families"],10,100)
                        && matches!(c["context"].as_str(),Some("html"|"script"|"url"))
                        && matches!(c["source"]["kind"].as_str(),Some("fragment"|"query"|"url"|"input"|"unsupported"))
                        && text(&c["source"]["label"],4000) && c["source"]["decoded"].is_boolean() && c["source"]["base64"].is_boolean()
                        && c["source"].get("name").is_none_or(|v|v.as_str().is_some_and(|s|s.len()<=1000))
                }))
        }));
        if !valid { return Err(bad("Invalid DOM script audit")); }
    }
    let findings = run["findings"]
        .as_array()
        .filter(|v| v.len() <= if crawl { 5000 } else { 500 })
        .ok_or_else(|| bad("Invalid findings"))?;
    let mut finding_ids = HashSet::new();
    let mut fingerprints = HashSet::new();
    for finding in findings {
        if let Some(endpoint) = finding.get("endpoint") {
            if !text(endpoint, 12000) || !reqwest::Url::parse(endpoint.as_str().unwrap()).is_ok_and(|url| super::http_target::validate(&url).is_ok()) { return Err(bad("Invalid finding endpoint")); }
        }
        if finding.get("method").is_some_and(|v| !text(v, 16)) { return Err(bad("Invalid finding method")); }
        if finding.get("baselineId").is_some_and(|v| !v.as_str().is_some_and(|id| ids.contains(id))) { return Err(bad("Invalid finding baseline reference")); }

        if !text(&finding["id"], 100)
            || !finding_ids.insert(finding["id"].as_str().unwrap())
            || !text(&finding["fingerprint"], 12000)
            || !fingerprints.insert(finding["fingerprint"].as_str().unwrap())
            || !check_id(&finding["checkId"])
            || !text(&finding["title"], 1000)
            || !text(&finding["summary"], 10000)
            || !text(&finding["remediation"], 10000)
            || !matches!(
                finding["severity"].as_str(),
                Some("info" | "low" | "medium" | "high" | "critical")
            )
            || !matches!(
                finding["confidence"].as_str(),
                Some("low" | "medium" | "high")
            )
            || !matches!(
                finding["status"].as_str(),
                Some("suspected" | "verified" | "needs_review" | "false_positive")
            )
            || !refs(&finding["evidenceIds"])
            || finding["evidenceIds"].as_array().unwrap().is_empty()
            || !strings(&finding["excerpts"], 20, 4000)
            || !text(&finding["verification"]["method"], 2000)
            || !text(&finding["verification"]["reason"], 10000)
            || !matches!(
                finding["verification"]["outcome"].as_str(),
                Some("confirmed" | "inconclusive" | "not_performed")
            )
        {
            return Err(bad("Invalid finding or missing evidence"));
        }
        if finding["status"] == "verified"
            && (finding["verification"]["outcome"] != "confirmed"
                || finding["confidence"] != "high")
        {
            return Err(bad(
                "Verified findings need a confirmed verification and high confidence",
            ));
        }
    }
    let checks = run["checks"]
        .as_array()
        .filter(|v| v.len() <= if crawl { 10000 } else { 1000 })
        .ok_or_else(|| bad("Invalid check results"))?;
    for check in checks {
        if !check_id(&check["checkId"])
            || !matches!(
                check["status"].as_str(),
                Some("passed" | "findings" | "inconclusive" | "skipped")
            )
            || !text(&check["message"], 10000)
            || check["findingIds"].as_array().is_none_or(|v| {
                v.iter()
                    .any(|id| id.as_str().is_none_or(|s| !finding_ids.contains(s)))
            })
        {
            return Err(bad("Invalid check result references"));
        }
    }
    Ok(())
}
pub async fn put_run(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
    Json(run): Json<Value>,
) -> Result<Json<Value>, Error> {
    validate_run(&id, &run)?;
    storage
        .put_scan_run(&workspace, &id, &run)
        .map_err(storage_error)?;
    Ok(Json(json!({"ok":true})))
}
pub async fn get_run(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        storage
            .get_scan_run(&workspace, &id)
            .map_err(bad)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error":"Scan run not found"})),
                )
            })?,
    ))
}
#[derive(Deserialize)]
pub struct Page {
    offset: Option<usize>,
}
pub async fn list_runs(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
    Query(page): Query<Page>,
) -> Result<Json<Value>, Error> {
    if workspace != proxy_core::storage::TEMP_WORKSPACE_ID {
        storage.get_intruder_document(&workspace).map_err(storage_error)?;
    }
    let offset = page.offset.unwrap_or(0);
    if offset > 1_000_000 {
        return Err(bad("Invalid pagination offset"));
    }
    let data = storage.list_scan_runs(&workspace, offset).map_err(bad)?;
    Ok(Json(json!({"has_more":data.len()==50,"data":data})))
}
pub async fn delete_run(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    storage
        .delete_scan_run(&workspace, &id)
        .map_err(storage_error)?;
    Ok(Json(json!({"ok":true})))
}

#[derive(Deserialize)]
pub struct FindingQuery {
    offset: Option<usize>,
    q: Option<String>,
    status: Option<String>,
    severity: Option<String>,
}
pub async fn list_findings(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
    Query(query): Query<FindingQuery>,
) -> Result<Json<Value>, Error> {
    if workspace != proxy_core::storage::TEMP_WORKSPACE_ID {
        storage.get_intruder_document(&workspace).map_err(storage_error)?;
    }
    let offset = query.offset.unwrap_or(0);
    let q = query.q.unwrap_or_default();
    let status = query.status.unwrap_or_default();
    let severity = query.severity.unwrap_or_default();
    if offset > 1_000_000
        || q.len() > 1000
        || !matches!(
            status.as_str(),
            "" | "suspected" | "verified" | "needs_review" | "false_positive"
        )
        || !matches!(
            severity.as_str(),
            "" | "info" | "low" | "medium" | "high" | "critical"
        )
    {
        return Err(bad("Invalid finding filters"));
    }
    let (total, data) = storage
        .list_scan_findings(&workspace, offset, &q, &status, &severity)
        .map_err(bad)?;
    Ok(Json(
        json!({"total":total,"has_more":offset+data.len()<total,"data":data}),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn run() -> Value {
        json!({"version":1,"id":"scan-1","startedAt":"2026-10-16T00:00:00Z","finishedAt":"2026-10-16T00:00:01Z","status":"completed","sent":0,"plan":{"mode":"passive","request":{"method":"GET","url":"https://example.com/items","headers":{},"body":""}},"baselineIds":["e1"],"evidence":[{"id":"e1","label":"Observed response","timestamp":"2026-10-16T00:00:00Z","request":{"method":"GET","url":"https://example.com/items","headers":{},"body":""},"truncated":false,"size":2,"duration":1,"setCookies":[],"response":{"status":200,"responseHeaders":{},"responseBody":"ok"}}],"findings":[{"id":"f1","fingerprint":"cookie-flags:sid:secure","checkId":"cookie-flags","title":"Cookie lacks Secure","severity":"low","confidence":"high","status":"verified","summary":"Missing attribute observed","evidenceIds":["e1"],"excerpts":["sid=<redacted>"],"remediation":"Set Secure","verification":{"method":"response inspection","outcome":"confirmed","reason":"Observed directly"}}],"checks":[{"checkId":"cookie-flags","status":"findings","message":"Observed missing flag","findingIds":["f1"]}]})
    }
    #[test]
    fn passive_scan_can_save_one_authorized_response_fetch() {
        let mut value = run();
        value["sent"] = json!(1);
        assert!(validate_run("scan-1", &value).is_err());
        value["plan"]["allowSending"] = json!(true);
        validate_run("scan-1", &value).unwrap();
        value["sent"] = json!(2);
        assert!(validate_run("scan-1", &value).is_err());
    }
    #[test]
    fn passive_crawl_requires_opt_in_and_bounded_progress() {
        let mut value = run();
        value["sent"] = json!(3);
        value["plan"]["crawlBeforeScan"] = json!(true);
        value["plan"]["crawlOptions"] = json!({"maxUrls": 3, "maxDepth": 1});
        assert!(validate_run("scan-1", &value).is_err());
        value["plan"]["allowSending"] = json!(true);
        value["crawl"] = json!({"phase":"completed","fetched":3,"queued":3,"urls":["https://example.com/items"]});
        validate_run("scan-1", &value).unwrap();
        value["sent"] = json!(5);
        assert!(validate_run("scan-1", &value).is_err());
        value["sent"] = json!(3);
        value["crawl"]["fetched"] = json!(4);
        assert!(validate_run("scan-1", &value).is_err());
        value["crawl"]["fetched"] = json!(3);
        value["plan"]["crawlOptions"]["maxUrls"] = json!(51);
        assert!(validate_run("scan-1", &value).is_err());
    }
    #[test]
    fn accepts_new_passive_modules_and_preserves_policy_snapshot() {
        for check in ["cookie-audit", "disclosure-audit", "policy-audit"] {
            let mut value=run();
            value["checks"][0]["checkId"]=json!(check);
            value["findings"][0]["checkId"]=json!(check);
            value["plan"]["policy"]=json!({"maxImpact":"passive","allowIntrusive":false,"includeExperimental":false,"maxDurationMs":300000,"requestTimeoutMs":15000});
            validate_run("scan-1", &value).unwrap();
        }
    }
    #[test]
    fn accepts_phase_four_injection_evidence() {
        for check in ["command-injection", "code-injection", "el-injection", "ldap-injection", "xpath-injection", "xml-injection", "xml-entity", "xxe", "xml-injection-body", "xml-entity-body", "xxe-body"] {
            let mut value = run();
            value["plan"]["mode"] = json!("active");
            value["checks"][0]["checkId"] = json!(check);
            value["findings"][0]["checkId"] = json!(check);
            value["findings"][0]["status"] = json!("needs_review");
            validate_run("scan-1", &value).unwrap();
        }
    }
    #[test]
    fn validates_new_security_checks_and_bounded_raw_evidence() {
        for id in ["parameter-hints","hidden-parameters","business-negative","business-dates","jwt-jwk","jwt-jku","jwt-x5u","jwt-kid","jwt-confusion","cors-trust","jwt-weak-secret","nosql-injection","nosql-operators","jwt-signature","graphql-introspection","graphql-batching","http-framing","dependency-audit"] {
            let mut value=run();
            value["checks"][0]["checkId"]=json!(id);
            value["findings"][0]["checkId"]=json!(id);
            value["evidence"][0]["rawRequest"]=json!("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
            value["evidence"][0]["rawResponse"]=json!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            validate_run("scan-1",&value).unwrap();
            value["evidence"][0]["rawRequest"]=json!("x".repeat(16001));
            assert!(validate_run("scan-1",&value).is_err());
        }
    }
    #[test]
    fn rejects_private_and_oversized_jwt_public_keys() {
        let mut value = run();
        for key in [json!("-----BEGIN PRIVATE KEY-----"), json!("x".repeat(16001)), json!(42)] {
            value["plan"]["jwtPublicKey"] = key;
            assert!(validate_run("scan-1", &value).is_err());
        }
        value["plan"]["jwtPublicKey"] = json!("");
        validate_run("scan-1", &value).unwrap();
    }
    #[test]
    fn validates_phase_five_browser_evidence() {
        for id in ["browser-xss", "dom-xss"] {
            let mut value = run();
            value["plan"]["mode"] = json!("active");
            value["checks"][0]["checkId"] = json!(id);
            value["findings"][0]["checkId"] = json!(id);
            value["evidence"][0]["browser"] = json!([{
                "executed":true,"marker":"slurpMarker12345678","url":"https://example.com/items#payload",
                "sinks":["innerHTML"],"cspViolations":[],"blockedRequests":2,"browser":"Chrome/fixture"
            }]);
            validate_run("scan-1", &value).unwrap();
            value["evidence"][0]["browser"][0]["executed"] = json!("yes");
            assert!(validate_run("scan-1", &value).is_err());
        }
    }
    #[test]
    fn validates_dom_audit_and_runtime_trace_references() {
        let mut value=run();
        value["domAudits"]=json!([{"id":"audit-1","url":"https://example.com/items","notes":[],"scripts":[{
            "url":"https://example.com/app.js","evidenceId":"e1","sources":["location.hash"],"sinks":["innerHTML"],"parsed":true
        }],"candidates":[{"id":"candidate-1","script":"https://example.com/app.js","line":1,"column":1,"sink":"innerHTML","context":"html","excerpt":"el.innerHTML=location.hash","families":["html-element"],"source":{"kind":"fragment","label":"location.hash","decoded":true,"base64":false}}]}]);
        value["evidence"][0]["browser"]=json!([{"executed":true,"marker":"slurp1234567890123456","url":"https://example.com/items#x","sinks":["innerHTML"],"cspViolations":[],"blockedRequests":0,"browser":"Chrome/fixture","sinkTraces":[{"sink":"innerHTML","value":"marker","stack":"https://example.com/app.js:1"}]}]);
        validate_run("scan-1", &value).unwrap();
        value["domAudits"][0]["scripts"][0]["evidenceId"]=json!("missing");
        assert!(validate_run("scan-1", &value).is_err());
        value["domAudits"][0]["scripts"][0]["evidenceId"]=json!("e1");
        value["evidence"][0]["browser"][0]["sinkTraces"][0]["value"]=json!("x".repeat(2001));
        assert!(validate_run("scan-1", &value).is_err());
    }
    #[test]
    fn validates_runtime_dependency_evidence() {
        let mut value = run();
        value["evidence"][0]["browser"] = json!([{
            "executed":false,"marker":"slurpMarker12345678","url":"https://example.com/items",
            "sinks":[],"cspViolations":[],"blockedRequests":1,"browser":"Chrome/fixture",
            "requestedScripts":["https://example.com/lazy.js"]
        }]);
        value["domAudits"] = json!([{"id":"audit-1","url":"https://example.com/items","notes":[],"scripts":[],"candidates":[],"runtimeScripts":["https://example.com/lazy.js"]}]);
        validate_run("scan-1", &value).unwrap();
        for invalid in [json!(["file:///etc/passwd"]),json!(["https://user:secret@example.com/app.js"]),json!(vec!["https://example.com/app.js";17])] {
            value["evidence"][0]["browser"][0]["requestedScripts"] = invalid;
            assert!(validate_run("scan-1", &value).is_err());
        }
        value["evidence"][0]["browser"][0]["requestedScripts"] = json!([]);
        value["domAudits"][0]["runtimeScripts"] = json!(["javascript:alert(1)"]);
        assert!(validate_run("scan-1", &value).is_err());
    }
    #[test]
    fn validates_interaction_and_oast_evidence() {
        let mut value=run();
        for check in ["dom-interaction","oast-ssrf","oast-xxe"] {
            value["plan"]["checks"]=json!([check]);
            value["plan"]["mode"]=json!("active");
            value["checks"][0]["checkId"]=json!(check);
            value["findings"][0]["checkId"]=json!(check);
            validate_run("scan-1",&value).unwrap();
        }
        value["evidence"][0]["oast"]=json!([{"id":"probe-1","url":"http://oast.example.test/slurp-oast/probe-1","expiresAt":"2026-10-19T00:10:00Z","events":[{"protocol":"http","timestamp":"2026-10-19T00:00:00Z","peer":"127.0.0.1","detail":"GET /slurp-oast/probe-1"}]}]);
        value["evidence"][0]["browser"]=json!([{"executed":true,"marker":"slurpMarker12345678","url":"https://example.com/items","sinks":[],"cspViolations":[],"blockedRequests":0,"browser":"Chrome/fixture","interactions":["fill/input/change INPUT#search"]}]);
        validate_run("scan-1",&value).unwrap();
        value["evidence"][0]["oast"][0]["events"][0]["protocol"]=json!("invalid");
        assert!(validate_run("scan-1",&value).is_err());
        value["evidence"][0]["oast"][0]["events"][0]["protocol"]=json!("dns");
        value["evidence"][0]["browser"][0]["interactions"]=json!(vec!["click";17]);
        assert!(validate_run("scan-1",&value).is_err());
    }
    #[test]
    fn accepts_runs_beyond_the_old_request_and_result_limits() {
        let mut value = run();
        value["plan"]["mode"] = json!("active");
        value["sent"] = json!(130);
        let template = value["evidence"][0].clone();
        value["evidence"] = json!((1..=130).map(|i| {
            let mut item = template.clone();
            item["id"] = json!(format!("e{i}"));
            item
        }).collect::<Vec<_>>());
        let check = value["checks"][0].clone();
        value["checks"] = json!(vec![check; 150]);
        validate_run("scan-1", &value).unwrap();
    }
    #[tokio::test]
    async fn dashboard_findings_are_scoped_filtered_and_paginated() {
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let workspace = storage.create_workspace("Dashboard").unwrap().id;
        let mut value = run();
        let template = value["findings"][0].clone();
        value["findings"] = json!((0..105)
            .map(|i| {
                let mut f = template.clone();
                f["id"] = json!(format!("f{i}"));
                f["fingerprint"] = json!(format!("key{i}"));
                f["title"] = json!(format!("Cookie observation {i}"));
                f
            })
            .collect::<Vec<_>>());
        put_run(
            State(storage.clone()),
            Path((workspace.clone(), "scan-1".into())),
            Json(value),
        )
        .await
        .unwrap();
        let (total, first) = storage
            .list_scan_findings(&workspace, 0, "", "verified", "low")
            .unwrap();
        assert_eq!(total, 105);
        assert_eq!(first.len(), 100);
        assert_eq!(first[0]["runId"], "scan-1");
        assert_eq!(first[0]["url"], "https://example.com/items");
        assert!(first[0].get("evidence").is_none());
        assert_eq!(
            storage
                .list_scan_findings(&workspace, 100, "", "", "")
                .unwrap()
                .1
                .len(),
            5
        );
        assert_eq!(
            storage
                .list_scan_findings(&workspace, 0, "Cookie observation 104", "", "")
                .unwrap()
                .0,
            1
        );
        assert_eq!(
            storage
                .list_scan_findings(&workspace, 0, "", "suspected", "")
                .unwrap()
                .0,
            0
        );
        assert_eq!(
            storage
                .list_scan_findings("default", 0, "", "", "")
                .unwrap()
                .0,
            0
        );
        let summaries = storage.list_scan_runs(&workspace, 0).unwrap();
        assert_eq!(summaries[0]["url"], "https://example.com/items");
        assert!(summaries[0].get("evidence").is_none());
        let bad = list_findings(
            State(storage.clone()),
            Path(workspace.clone()),
            Query(FindingQuery {
                offset: None,
                q: None,
                status: Some("invalid".into()),
                severity: None,
            }),
        )
        .await;
        assert_eq!(bad.unwrap_err().0, StatusCode::BAD_REQUEST);
        storage.delete_scan_run(&workspace, "scan-1").unwrap();
        assert_eq!(
            storage
                .list_scan_findings(&workspace, 0, "", "", "")
                .unwrap()
                .0,
            0
        );
    }
    #[tokio::test]
    async fn crawled_finding_endpoint_is_searchable_and_preserved() {
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let workspace = storage.create_workspace("Crawl").unwrap().id;
        let mut value = run();
        value["findings"][0]["endpoint"] = json!("https://example.com/discovered");
        value["findings"][0]["method"] = json!("GET");
        value["findings"][0]["baselineId"] = json!("e1");
        let _ = put_run(State(storage.clone()), Path((workspace.clone(), "scan-1".into())), Json(value.clone())).await.unwrap();
        let (total, rows) = storage.list_scan_findings(&workspace, 0, "discovered", "", "").unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0]["url"], "https://example.com/discovered");
        assert_eq!(rows[0]["method"], "GET");
        value["findings"][0]["baselineId"] = json!("missing");
        assert!(validate_run("scan-1", &value).is_err());
    }
    #[test]
    fn rejects_unsupported_verification_and_dangling_evidence() {
        let mut value = run();
        assert!(validate_run("scan-1", &value).is_ok());
        value["findings"][0]["verification"]["outcome"] = json!("inconclusive");
        assert!(validate_run("scan-1", &value).is_err());
        value = run();
        value["findings"][0]["evidenceIds"] = json!(["missing"]);
        assert!(validate_run("scan-1", &value).is_err());
        value = run();
        value["sent"] = json!(1);
        assert!(validate_run("scan-1", &value).is_err());
        value = run();
        value["status"] = json!("running");
        assert!(validate_run("scan-1", &value).is_err());
    }
    #[tokio::test]
    async fn evidence_survives_reopen_is_scoped_immutable_and_deleted() {
        let path = std::env::temp_dir().join(format!(
            "scan-evidence-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let workspace;
        {
            let s = TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
            workspace = s.create_workspace("Scans").unwrap().id;
            put_run(
                State(s.clone()),
                Path((workspace.clone(), "scan-1".into())),
                Json(run()),
            )
            .await
            .unwrap();
            put_run(
                State(s.clone()),
                Path((workspace.clone(), "scan-1".into())),
                Json(run()),
            )
            .await
            .unwrap();
            assert!(
                get_run(State(s.clone()), Path(("default".into(), "scan-1".into())))
                    .await
                    .is_err()
            );
            let mut changed = run();
            changed["status"] = json!("stopped");
            assert!(put_run(
                State(s.clone()),
                Path((workspace.clone(), "scan-1".into())),
                Json(changed)
            )
            .await
            .is_err());
            assert_eq!(s.list_scan_runs(&workspace, 0).unwrap()[0]["findings"], 1);
            assert!(s.list_scan_runs(&workspace, 0).unwrap()[0]
                .get("evidence")
                .is_none());
            assert!(s.put_scan_run("missing", "scan-1", &run()).is_err());
        }
        {
            let s = TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
            assert_eq!(
                s.get_scan_run(&workspace, "scan-1").unwrap().unwrap(),
                run()
            );
            s.delete_scan_run("default", "scan-1").unwrap();
            assert!(s.get_scan_run(&workspace, "scan-1").unwrap().is_some());
            s.delete_scan_run(&workspace, "scan-1").unwrap();
            assert!(s.get_scan_run(&workspace, "scan-1").unwrap().is_none());
            s.put_scan_run(&workspace, "scan-1", &run()).unwrap();
            s.delete_workspace(&workspace).unwrap();
            assert!(s.get_scan_run(&workspace, "scan-1").unwrap().is_none());
        }
        let _ = std::fs::remove_file(path);
    }
}
