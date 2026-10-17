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
fn check_id(value: &Value) -> bool {
    matches!(
        value.as_str(),
        Some(
            "cookie-flags"
                | "error-disclosure"
                | "security-headers"
                | "reflection"
                | "input-errors"
                | "cors"
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
        || !number(&run["sent"], 100)
        || run.to_string().len() > 12_000_000
    {
        return Err(bad(
            "Invalid or unfinished scan run (maximum 12 MB / 100 requests)",
        ));
    }
    crate::replay::validate_request(&run["plan"]["request"])?;
    if !matches!(run["plan"]["mode"].as_str(), Some("passive" | "active")) {
        return Err(bad("Invalid scan mode"));
    }
    if run["plan"]["mode"] == "passive" && run["sent"] != 0 {
        return Err(bad("Passive scans cannot send requests"));
    }
    let evidence = run["evidence"]
        .as_array()
        .filter(|v| v.len() <= 101)
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
            v.len() <= 101
                && v.iter()
                    .all(|id| id.as_str().is_some_and(|id| ids.contains(id)))
        })
    };
    if !refs(&run["baselineIds"]) {
        return Err(bad("Unknown baseline evidence reference"));
    }
    let findings = run["findings"]
        .as_array()
        .filter(|v| v.len() <= 500)
        .ok_or_else(|| bad("Invalid findings"))?;
    let mut finding_ids = HashSet::new();
    let mut fingerprints = HashSet::new();
    for finding in findings {
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
        .filter(|v| v.len() <= 100)
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
    storage
        .get_intruder_document(&workspace)
        .map_err(storage_error)?;
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
    storage
        .get_intruder_document(&workspace)
        .map_err(storage_error)?;
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
