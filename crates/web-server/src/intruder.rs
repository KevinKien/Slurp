//! Intruder payload files and evidence are stored locally and scoped to a workspace.
//! Execution remains browser-driven through the existing public HTTPS Replay sender.
use axum::{
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
    (
        if matches!(error, WorkspaceError::NotFound) {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::CONFLICT
        },
        Json(json!({"error":error.to_string()})),
    )
}
fn not_found() -> Error {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error":"Intruder item not found"})),
    )
}
fn text(value: &Value, max: usize) -> bool {
    value.as_str().is_some_and(|s| s.len() <= max)
}
fn bounded(value: &Value, min: u64, max: u64) -> bool {
    value.as_u64().is_some_and(|n| n >= min && n <= max)
}
pub fn validate_config(config: &Value) -> Result<(), Error> {
    if config.to_string().len() > 2_000_000 {
        return Err(bad("Intruder configuration exceeds 2 MB"));
    }
    let mut request = config["request"].clone();
    if request["url"].as_str() == Some("") {
        request["url"] = json!("https://example.com");
    }
    crate::replay::validate_request(&request)?;
    if !matches!(
        config["encoding"].as_str(),
        Some("none" | "url" | "base64" | "hex" | "html")
    ) || !bounded(&config["concurrency"], 1, 10)
        || !bounded(&config["rate"], 1, 100)
        || !bounded(&config["delay"], 0, 60000)
        || !bounded(&config["limit"], 1, 100000)
        || !bounded(&config["start"], 0, 999999)
        || !text(&config["matchText"], 2000)
    {
        return Err(bad("Invalid Intruder controls"));
    }
    match config["source"]["kind"].as_str() {
        Some("list") => {
            let values = config["source"]["values"]
                .as_array()
                .filter(|v| v.len() <= 10000)
                .ok_or_else(|| bad("Up to 10,000 manual payloads"))?;
            if values.iter().any(|v| !text(v, 16384)) {
                return Err(bad("Payload exceeds 16 KB"));
            }
        }
        Some("numbers") => {
            for field in ["from", "to", "step"] {
                let s = config["source"][field]
                    .as_str()
                    .filter(|s| s.len() <= 22)
                    .ok_or_else(|| bad("Invalid number range"))?;
                if s.parse::<i64>().is_err() {
                    return Err(bad("Number range must use signed 64-bit integers"));
                }
            }
            let from = config["source"]["from"]
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap() as i128;
            let to = config["source"]["to"]
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap() as i128;
            let step = config["source"]["step"]
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap() as i128;
            if step == 0
                || (to > from && step < 0)
                || (to < from && step > 0)
                || (to - from) / step + 1 > 1_000_000
            {
                return Err(bad(
                    "Invalid range direction, zero step or more than 1 million payloads",
                ));
            }
            if !bounded(&config["source"]["pad"], 0, 32) {
                return Err(bad("Invalid number padding"));
            }
        }
        Some("file") => {
            if !text(&config["source"]["id"], 100)
                || !bounded(&config["source"]["count"], 1, 1000000)
            {
                return Err(bad("Invalid payload file"));
            }
        }
        _ => return Err(bad("Invalid payload source")),
    }
    Ok(())
}
#[derive(Deserialize)]
pub struct DocumentUpdate {
    revision: u64,
    document: Value,
}
pub async fn get_document(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
) -> Result<Json<Value>, Error> {
    let (revision, data) = storage
        .get_intruder_document(&workspace)
        .map_err(storage_error)?;
    Ok(Json(
        json!({"revision":revision,"document":data.map(|s|serde_json::from_str::<Value>(&s)).transpose().map_err(bad)?}),
    ))
}
pub async fn put_document(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
    Json(update): Json<DocumentUpdate>,
) -> Result<Json<Value>, Error> {
    validate_config(&update.document)?;
    let revision=storage.put_intruder_document(&workspace,update.revision,&update.document.to_string()).map_err(storage_error)?.ok_or_else(||(StatusCode::CONFLICT,Json(json!({"error":"Intruder configuration changed in another browser. Reload before saving."}))))?;
    Ok(Json(json!({"revision":revision})))
}
#[derive(Deserialize)]
pub struct SourceCreate {
    name: String,
}
pub async fn create_source(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
    Json(input): Json<SourceCreate>,
) -> Result<Json<Value>, Error> {
    if input.name.trim().is_empty() || input.name.len() > 300 {
        return Err(bad("File name is required (up to 300 bytes)"));
    }
    Ok(Json(
        json!({"id":storage.create_intruder_source(&workspace,&input.name).map_err(storage_error)?}),
    ))
}
pub async fn list_sources(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
) -> Result<Json<Value>, Error> {
    storage
        .get_intruder_document(&workspace)
        .map_err(storage_error)?;
    Ok(Json(
        json!({"data":storage.list_intruder_sources(&workspace).map_err(bad)?}),
    ))
}
#[derive(Deserialize)]
pub struct Append {
    offset: usize,
    values: Vec<String>,
}
pub async fn append_source(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
    Json(input): Json<Append>,
) -> Result<Json<Value>, Error> {
    if input.values.is_empty()
        || input.values.len() > 256
        || input.values.iter().any(|s| s.len() > 16384)
        || input.values.iter().map(|s| s.len()).sum::<usize>() > 1_000_000
    {
        return Err(bad(
            "Upload 1–256 payloads, up to 1 MB per batch and 16 KB per payload",
        ));
    }
    Ok(Json(
        json!({"count":storage.append_intruder_payloads(&workspace,&id,input.offset,&input.values).map_err(storage_error)?}),
    ))
}
pub async fn finalize_source(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    storage
        .finalize_intruder_source(&workspace, &id)
        .map_err(storage_error)?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
pub struct Page {
    offset: Option<usize>,
}
pub async fn payload_page(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
    Query(query): Query<Page>,
) -> Result<Json<Value>, Error> {
    let offset = query.offset.unwrap_or(0);
    if offset > 1000000 {
        return Err(bad("Invalid payload offset"));
    }
    Ok(Json(
        json!({"values":storage.intruder_payload_page(&workspace,&id,offset).map_err(storage_error)?}),
    ))
}
pub async fn delete_source(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    storage
        .delete_intruder_source(&workspace, &id)
        .map_err(storage_error)?;
    Ok(Json(json!({"ok":true})))
}
pub async fn put_run(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
    Json(run): Json<Value>,
) -> Result<Json<Value>, Error> {
    if id.is_empty()
        || id.len() > 100
        || run["id"].as_str() != Some(&id)
        || !text(&run["startedAt"], 100)
        || !bounded(&run["count"], 1, 100000)
        || !matches!(
            run["status"].as_str(),
            Some("running" | "paused" | "completed" | "stopped" | "failed")
        )
        || run.to_string().len() > 2_200_000
    {
        return Err(bad("Invalid Intruder run"));
    }
    validate_config(&run["config"])?;
    storage
        .put_intruder_run(&workspace, &id, &run)
        .map_err(storage_error)?;
    Ok(Json(json!({"ok":true})))
}
pub async fn get_run(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        storage
            .get_intruder_run(&workspace, &id)
            .map_err(bad)?
            .ok_or_else(not_found)?,
    ))
}
pub async fn list_runs(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
    Query(page): Query<Page>,
) -> Result<Json<Value>, Error> {
    storage
        .get_intruder_document(&workspace)
        .map_err(storage_error)?;
    let data = storage
        .list_intruder_runs(&workspace, page.offset.unwrap_or(0))
        .map_err(bad)?;
    Ok(Json(json!({"has_more":data.len()==50,"data":data})))
}
pub async fn put_result(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, run, index)): Path<(String, String, usize)>,
    Json(result): Json<Value>,
) -> Result<Json<Value>, Error> {
    if result["index"].as_u64() != Some(index as u64)
        || !text(&result["payload"], 16384)
        || !bounded(&result["payloadIndex"], 0, 999999)
        || result.to_string().len() > 3_000_000
        || !bounded(&result["duration"], 0, 3600000)
        || !bounded(&result["size"], 0, 2_000_000)
        || !result["matched"].is_boolean()
    {
        return Err(bad("Invalid Intruder result"));
    }
    if let Some(request) = result.get("request") {
        crate::replay::validate_request(request)?;
    }
    if let Some(response) = result.get("response") {
        if !bounded(&response["status"], 100, 599)
            || !response["responseHeaders"].is_object()
            || !text(&response["responseBody"], 200000)
        {
            return Err(bad("Invalid response preview"));
        }
    }
    if result.get("response").is_none() && !result["error"].is_string() {
        return Err(bad("Expected a response or error"));
    }
    storage
        .put_intruder_result(&workspace, &run, index, &result)
        .map_err(storage_error)?;
    Ok(Json(json!({"ok":true})))
}
pub async fn get_result(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, run, index)): Path<(String, String, usize)>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        storage
            .get_intruder_result(&workspace, &run, index)
            .map_err(bad)?
            .ok_or_else(not_found)?,
    ))
}
#[derive(Deserialize)]
pub struct ResultsQuery {
    offset: Option<usize>,
    q: Option<String>,
    status: Option<u16>,
    matched: Option<bool>,
    errors: Option<bool>,
    sort: Option<String>,
    descending: Option<bool>,
}
pub async fn list_results(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, run)): Path<(String, String)>,
    Query(query): Query<ResultsQuery>,
) -> Result<Json<Value>, Error> {
    let offset = query.offset.unwrap_or(0);
    let q = query.q.unwrap_or_default();
    if offset > 100000 || q.len() > 2000 {
        return Err(bad("Invalid result query"));
    }
    let (total, data) = storage
        .list_intruder_results(
            &workspace,
            &run,
            offset,
            &q,
            query.status.unwrap_or(0),
            query.matched.unwrap_or(false),
            query.errors.unwrap_or(false),
            query.sort.as_deref().unwrap_or("index"),
            query.descending.unwrap_or(false),
        )
        .map_err(bad)?;
    Ok(Json(
        json!({"total":total,"data":data,"has_more":offset+data.len()<total}),
    ))
}
pub async fn delete_run(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    storage
        .delete_intruder_run(&workspace, &id)
        .map_err(storage_error)?;
    Ok(Json(json!({"ok":true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Value {
        json!({"request":{"method":"GET","url":"https://example.com/§x§","headers":{},"body":""},"encoding":"none","concurrency":1,"rate":5,"delay":0,"limit":1000,"start":0,"matchText":"","source":{"kind":"numbers","from":"1","to":"100","step":"1","pad":0}})
    }
    #[test]
    fn validates_lazy_ranges_and_controls() {
        let mut c = config();
        assert!(validate_config(&c).is_ok());
        for step in ["0", "-1", "9223372036854775808"] {
            c["source"]["step"] = json!(step);
            assert!(validate_config(&c).is_err());
        }
        c = config();
        c["source"]["to"] = json!("1000001");
        assert!(validate_config(&c).is_err());
        c = config();
        c["source"]["from"] = json!("9223372036854775807");
        c["source"]["to"] = json!("9223372036854775805");
        c["source"]["step"] = json!("-1");
        assert!(validate_config(&c).is_ok());
        c["concurrency"] = json!(11);
        assert!(validate_config(&c).is_err());
    }
    #[test]
    fn accepts_empty_draft_but_rejects_oversize_payloads() {
        let mut c = config();
        c["request"]["url"] = json!("");
        c["source"] = json!({"kind":"list","values":[]});
        assert!(validate_config(&c).is_ok());
        c["source"]["values"] = json!(["x".repeat(16385)]);
        assert!(validate_config(&c).is_err());
    }
}
