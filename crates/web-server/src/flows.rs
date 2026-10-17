//! Browser-driven flows: workspace-scoped definitions and execution checkpoints.
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use proxy_core::{TrafficStorage, WorkspaceError};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
type Error = (StatusCode, Json<Value>);
fn bad(message: impl ToString) -> Error {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":message.to_string()})),
    )
}
fn storage_error(error: WorkspaceError) -> Error {
    let status = if matches!(error, WorkspaceError::NotFound) {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (status, Json(json!({"error":error.to_string()})))
}
fn id(value: &Value) -> Result<(), Error> {
    if value.as_str().is_none_or(|s| s.is_empty() || s.len() > 100) {
        return Err(bad("Invalid flow/step ID"));
    }
    Ok(())
}
fn variables(value: &Value) -> Result<(), Error> {
    if !value.is_object() {
        return Err(bad("Flow variables must be an object"));
    }
    crate::replay::validate_variables(value)?;
    if value.to_string().len() > 256_000 {
        return Err(bad("Flow variables exceed 256 KB"));
    }
    Ok(())
}
fn validate_flow(flow: &Value) -> Result<(), Error> {
    if flow.to_string().len() > 5_000_000 {
        return Err(bad("Flow snapshot exceeds 5 MB"));
    }
    id(&flow["id"])?;
    if flow["name"]
        .as_str()
        .is_none_or(|s| s.trim().is_empty() || s.chars().count() > 200)
    {
        return Err(bad("Flow name must contain 1–200 characters"));
    }
    variables(&flow["variables"])?;
    let steps = flow["steps"]
        .as_array()
        .filter(|s| s.len() <= 50)
        .ok_or_else(|| bad("A flow supports at most 50 steps"))?;
    let mut ids = std::collections::HashSet::new();
    for step in steps {
        id(&step["id"])?;
        if !ids.insert(step["id"].as_str().unwrap()) {
            return Err(bad("Duplicate step ID"));
        }
        if step["name"]
            .as_str()
            .is_none_or(|s| s.trim().is_empty() || s.chars().count() > 200)
        {
            return Err(bad("Invalid step name"));
        }
        let mut request = step["request"].clone();
        if request["url"].as_str() == Some("") {
            request["url"] = json!("https://example.com");
        }
        crate::replay::validate_request(&request)?;
        if step["afterResponse"]
            .as_str()
            .is_none_or(|s| s.chars().count() > 32000)
        {
            return Err(bad("Invalid after-response script"));
        }
        if !matches!(step["onFailure"].as_str(), Some("stop" | "continue")) {
            return Err(bad("Invalid failure behavior"));
        }
        if !step["enabled"].is_boolean()
            || !step["pauseBefore"].is_boolean()
            || step["pauseMessage"]
                .as_str()
                .is_none_or(|s| s.chars().count() > 2000)
        {
            return Err(bad("Invalid step settings"));
        }
        let status = step["expectedStatus"]
            .as_str()
            .ok_or_else(|| bad("Expected status is required"))?;
        if !status.is_empty()
            && !status.split(',').all(|part| {
                let b = part.trim().as_bytes();
                b.len() == 3
                    && (b'1'..=b'5').contains(&b[0])
                    && (&b[1..] == b"xx" || b[1..].iter().all(u8::is_ascii_digit))
            })
        {
            return Err(bad("Invalid expected HTTP status"));
        }

        for key in ["extractors", "assertions"] {
            if step[key].as_array().is_none_or(|a| a.len() > 20) {
                return Err(bad("At most 20 extractors/assertions per step"));
            }
        }
        for extractor in step["extractors"].as_array().unwrap() {
            let name = extractor["variable"]
                .as_str()
                .ok_or_else(|| bad("Extractor variable is required"))?;
            crate::replay::validate_variables(&json!({(name):""}))?;
            if !matches!(
                extractor["source"].as_str(),
                Some("json" | "header" | "text")
            ) || extractor["path"]
                .as_str()
                .is_none_or(|s| s.chars().count() > 500)
            {
                return Err(bad("Invalid extractor"));
            }
        }
        for assertion in step["assertions"].as_array().unwrap() {
            if !matches!(
                assertion["operator"].as_str(),
                Some("exists" | "equals" | "contains")
            ) || assertion["path"]
                .as_str()
                .is_none_or(|s| s.chars().count() > 500)
                || assertion["expected"]
                    .as_str()
                    .is_none_or(|s| s.chars().count() > 64000)
            {
                return Err(bad("Invalid JSON assertion"));
            }
        }
    }
    Ok(())
}
fn parse(body: Bytes, max: usize) -> Result<Value, Error> {
    if body.len() > max {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error":"Flow data exceeds the size limit"})),
        ));
    }
    serde_json::from_slice(&body).map_err(bad)
}
pub async fn get_document(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
) -> Result<Json<Value>, Error> {
    let doc = storage
        .get_flow_document(&workspace)
        .map_err(storage_error)?;
    Ok(Json(
        doc.and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(json!({"flows":[],"active":null})),
    ))
}
pub async fn put_document(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
    body: Bytes,
) -> Result<StatusCode, Error> {
    let doc = parse(body, 5 * 1024 * 1024)?;
    let flows = doc["flows"]
        .as_array()
        .filter(|f| f.len() <= 50)
        .ok_or_else(|| bad("A workspace supports at most 50 flows"))?;
    let mut ids = std::collections::HashSet::new();
    for flow in flows {
        validate_flow(flow)?;
        if !ids.insert(flow["id"].as_str().unwrap()) {
            return Err(bad("Duplicate flow ID"));
        }
    }
    storage
        .put_flow_document(&workspace, &doc.to_string())
        .map_err(storage_error)?;
    Ok(StatusCode::NO_CONTENT)
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
        .get_flow_document(&workspace)
        .map_err(storage_error)?;
    let data = storage
        .list_flow_runs(&workspace, page.offset.unwrap_or(0))
        .map_err(bad)?;
    let more = data.len() == 50;
    Ok(Json(json!({"data":data,"has_more":more})))
}
pub async fn get_run(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, run)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    let data = storage
        .get_flow_run(&workspace, &run)
        .map_err(bad)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"Flow run not found"})),
            )
        })?;
    Ok(Json(data))
}
pub async fn put_run(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, run)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode, Error> {
    let data = parse(body, 32 * 1024 * 1024)?;
    id(&data["id"])?;
    if data["id"].as_str() != Some(run.as_str()) {
        return Err(bad("Run ID mismatch"));
    }
    validate_flow(&data["flow"])?;
    variables(&data["variables"])?;
    variables(&data["initialVariables"])?;
    if data["startedAt"]
        .as_str()
        .is_none_or(|s| s.is_empty() || s.len() > 40)
    {
        return Err(bad("Invalid start timestamp"));
    }
    if !matches!(
        data["status"].as_str(),
        Some("running" | "paused" | "passed" | "failed" | "stopped")
    ) {
        return Err(bad("Invalid run status"));
    }
    if data["results"].as_array().is_none_or(|s| s.len() > 50) {
        return Err(bad("Invalid step results"));
    }
    let count = data["flow"]["steps"].as_array().unwrap().len() as u64;
    for field in ["startIndex", "nextIndex", "endIndex"] {
        if data[field].as_u64().is_none_or(|n| n > count) {
            return Err(bad("Invalid run step range"));
        }
    }
    if data["duration"].as_u64().is_none() {
        return Err(bad("Invalid run duration"));
    }
    if !data["sendingIndex"].is_null() && data["sendingIndex"].as_u64().is_none_or(|n| n >= count) {
        return Err(bad("Invalid in-flight step"));
    }
    let mut indexes = std::collections::HashSet::new();
    for result in data["results"].as_array().unwrap() {
        let index = result["index"]
            .as_u64()
            .filter(|n| *n < count)
            .ok_or_else(|| bad("Invalid result index"))?;
        if !indexes.insert(index) || result["stepId"] != data["flow"]["steps"][index as usize]["id"]
        {
            return Err(bad("Step result does not match snapshot"));
        }
        if !matches!(
            result["status"].as_str(),
            Some("passed" | "failed" | "skipped")
        ) || result["duration"].as_u64().is_none()
        {
            return Err(bad("Invalid step result"));
        }
        variables(&result["variablesBefore"])?;
        variables(&result["variablesAfter"])?;
        if let Some(request) = result.get("request") {
            crate::replay::validate_request(request)?;
        }
        if let Some(response) = result.get("response") {
            if response["responseBody"]
                .as_str()
                .is_none_or(|s| s.chars().count() > 2_000_000)
                || !response["responseHeaders"].is_object()
                || response["status"]
                    .as_u64()
                    .is_none_or(|s| !(100..=599).contains(&s))
            {
                return Err(bad("Invalid recorded response"));
            }
        }
    }

    if let Some(existing) = storage.get_flow_run(&workspace, &run).map_err(bad)? {
        if existing["startedAt"] != data["startedAt"] || existing["flow"] != data["flow"] {
            return Err(bad("Run snapshot cannot be replaced"));
        }
        if existing["finishedAt"].is_string() && existing != data {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({"error":"Finished run history is immutable"})),
            ));
        }
    }
    storage
        .put_flow_run(&workspace, &run, &data)
        .map_err(storage_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn flow() -> Value {
        json!({"id":"flow-1","name":"Login","variables":{},"steps":[{"id":"step-1","name":"Login","request":{"method":"POST","url":"","headers":{},"body":""},"enabled":true,"pauseBefore":false,"pauseMessage":"","expectedStatus":"2xx","onFailure":"stop","extractors":[],"assertions":[],"afterResponse":""}]})
    }
    fn run() -> Value {
        json!({"id":"run-1","flow":flow(),"startedAt":"2026-10-16T00:00:00Z","status":"running","initialVariables":{},"variables":{},"results":[],"nextIndex":0,"endIndex":1,"startIndex":0,"sendingIndex":null,"duration":0,"message":""})
    }
    #[tokio::test]
    async fn definitions_and_runs_are_workspace_scoped_and_history_survives_definition_edits() {
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let other = storage.create_workspace("Other").unwrap();
        let doc = json!({"flows":[flow()],"active":"flow-1"});
        put_document(
            State(storage.clone()),
            Path("default".into()),
            Bytes::from(doc.to_string()),
        )
        .await
        .unwrap();
        assert_eq!(
            get_document(State(storage.clone()), Path("default".into()))
                .await
                .unwrap()
                .0,
            doc
        );
        assert_eq!(
            get_document(State(storage.clone()), Path(other.id.clone()))
                .await
                .unwrap()
                .0["flows"],
            json!([])
        );
        put_run(
            State(storage.clone()),
            Path(("default".into(), "run-1".into())),
            Bytes::from(run().to_string()),
        )
        .await
        .unwrap();
        assert_eq!(
            get_run(State(storage.clone()), Path((other.id, "run-1".into())))
                .await
                .unwrap_err()
                .0,
            StatusCode::NOT_FOUND
        );
        put_document(
            State(storage.clone()),
            Path("default".into()),
            Bytes::from(json!({"flows":[],"active":null}).to_string()),
        )
        .await
        .unwrap();
        assert_eq!(
            get_run(
                State(storage.clone()),
                Path(("default".into(), "run-1".into()))
            )
            .await
            .unwrap()
            .0["flow"]["name"],
            "Login"
        );
        let summaries = list_runs(
            State(storage),
            Path("default".into()),
            Query(Page { offset: None }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summaries["data"][0]["name"], "Login");
        assert!(summaries["data"][0].get("variables").is_none());
    }
    #[tokio::test]
    async fn checkpoints_can_finish_but_final_snapshots_are_immutable() {
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let initial = run();
        put_run(
            State(storage.clone()),
            Path(("default".into(), "run-1".into())),
            Bytes::from(initial.to_string()),
        )
        .await
        .unwrap();
        let mut finished = initial.clone();
        finished["status"] = json!("passed");
        finished["finishedAt"] = json!("2026-10-16T00:01:00Z");
        put_run(
            State(storage.clone()),
            Path(("default".into(), "run-1".into())),
            Bytes::from(finished.to_string()),
        )
        .await
        .unwrap();
        assert_eq!(
            put_run(
                State(storage.clone()),
                Path(("default".into(), "run-1".into())),
                Bytes::from(initial.to_string())
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::CONFLICT
        );
        put_run(
            State(storage),
            Path(("default".into(), "run-1".into())),
            Bytes::from(finished.to_string()),
        )
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn malformed_documents_and_variables_are_rejected() {
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let mut invalid = flow();
        invalid["variables"] = json!({"bad name":"value"});
        assert!(put_document(
            State(storage.clone()),
            Path("default".into()),
            Bytes::from(json!({"flows":[invalid]}).to_string())
        )
        .await
        .is_err());
        assert!(put_document(
            State(storage.clone()),
            Path("missing".into()),
            Bytes::from(json!({"flows":[]}).to_string())
        )
        .await
        .is_err());
        let mut invalid = run();
        invalid["id"] = json!("different");
        assert!(put_run(
            State(storage),
            Path(("default".into(), "run-1".into())),
            Bytes::from(invalid.to_string())
        )
        .await
        .is_err());
    }
}
