//! Saved Replay operations shared by MCP clients. Sending does not change the capture workspace.
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use proxy_core::{pairs_to_json, TrafficEntry, TrafficEvent, TrafficStorage};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::Instant,
};

pub static WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type Error = (StatusCode, Json<Value>);
fn bad(message: impl ToString) -> Error {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":message.to_string()})),
    )
}
fn load(storage: &TrafficStorage, workspace: &str) -> Result<Value, Error> {
    let doc = storage.get_replay_tabs(workspace).map_err(bad)?;
    Ok(doc
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(json!({"tabs":[],"active":null})))
}
fn save(storage: &TrafficStorage, workspace: &str, doc: &Value) -> Result<(), Error> {
    if doc.to_string().len() > 5 * 1024 * 1024 {
        return Err(bad("Replay document exceeds 5 MB"));
    }
    storage
        .put_replay_tabs(workspace, &doc.to_string())
        .map_err(bad)?;
    storage.publish(TrafficEvent::ReplayChanged {
        workspace_id: workspace.into(),
        document: doc.clone(),
    });
    Ok(())
}
pub(crate) fn validate_request(request: &Value) -> Result<(), Error> {
    let method = request["method"]
        .as_str()
        .ok_or_else(|| bad("method required"))?;
    if !["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"].contains(&method) {
        return Err(bad("Unsupported method"));
    }
    let url = request["url"].as_str().ok_or_else(|| bad("url required"))?;
    if url.len() > 4096 {
        return Err(bad("URL too long"));
    }
    if !url.contains("{{") {
    let parsed = reqwest::Url::parse(url).map_err(bad)?;
    if !["http", "https"].contains(&parsed.scheme())
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(bad("Expected HTTP(S) URL without credentials"));
    }
    }
    if request["body"].as_str().is_none_or(|s| s.len() > 1_000_000) {
        return Err(bad("Body must be text, at most 1 MB"));
    }
    let headers = request["headers"]
        .as_object()
        .ok_or_else(|| bad("headers must be an object"))?;
    if headers.len() > 200 {
        return Err(bad("Too many headers"));
    }
    for (name, value) in headers {
        let value = value
            .as_str()
            .ok_or_else(|| bad("Header values must be strings"))?;
        if name.len() > 8192 || value.len() > 8192 {
            return Err(bad("Header too long"));
        }
        if !name.contains("{{") { reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(bad)?; }
        if !value.contains("{{") { reqwest::header::HeaderValue::from_str(value).map_err(bad)?; }
    }
    Ok(())
}
fn name(value: &Value) -> Result<String, Error> {
    let text = value
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 200)
        .ok_or_else(|| bad("name must contain 1–200 bytes"))?;
    Ok(text.into())
}
pub async fn create(
    State(storage): State<Arc<TrafficStorage>>,
    Path(workspace): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Error> {
    let _guard = WRITE_LOCK.lock().await;
    let mut doc = load(&storage, &workspace)?;
    let mut request =
        json!({"method":"GET","url":"https://httpbin.org/get","headers":{},"body":""});
    if let Some(id) = body["traffic_id"].as_str() {
        let entry = storage
            .get(id)
            .map_err(bad)?
            .ok_or_else(|| bad("Traffic not found"))?;
        let mut headers = serde_json::Map::new();
        let pairs: Value = serde_json::from_str(&entry.request_headers).map_err(bad)?;
        if let Some(pairs) = pairs.as_array() {
            for pair in pairs {
                if let (Some(k), Some(v)) = (pair[0].as_str(), pair[1].as_str()) {
                    headers.insert(k.into(), json!(v));
                }
            }
        } else if let Some(object) = pairs.as_object() {
            for (key, value) in object {
                let text = if let Some(values) = value.as_array() {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    value.as_str().unwrap_or("").to_string()
                };
                headers.insert(key.clone(), json!(text));
            }
        }
        request = json!({"method":entry.method,"url":entry.url,"headers":headers,"body":String::from_utf8(entry.request_body).map_err(|_|bad("Binary request cannot be edited as text"))?});
    }
    if let Some(patch) = body.get("request") {
        merge_request(&mut request, patch)?;
    }
    validate_request(&request)?;
    let tabs = doc["tabs"]
        .as_array_mut()
        .ok_or_else(|| bad("Invalid saved Replay document"))?;
    if tabs.len() >= 100 {
        return Err(bad("Maximum 100 Replay tabs"));
    }
    let id = tabs
        .iter()
        .filter_map(|t| t["id"].as_u64())
        .max()
        .unwrap_or(0).max(storage.max_replay_tab_id(&workspace).map_err(bad)?)
        + 1;
    let title = match body.get("name") {
        Some(value) => name(value)?,
        None => reqwest::Url::parse(request["url"].as_str().unwrap()).map(|u|u.path().to_string()).unwrap_or_else(|_|"Untitled request".into()),
    };
    let tab = json!({"id":id,"name":title,"customName":true,"request":request});
    tabs.push(tab.clone());
    doc["active"] = json!(id);
    save(&storage, &workspace, &doc)?;
    Ok(Json(tab))
}
fn merge_request(request: &mut Value, patch: &Value) -> Result<(), Error> {
    let patch = patch
        .as_object()
        .ok_or_else(|| bad("request must be an object"))?;
    for (k, v) in patch {
        if !["method", "url", "headers", "body"].contains(&k.as_str()) {
            return Err(bad("Unknown request field"));
        }
        request[k] = v.clone();
    }
    Ok(())
}
pub async fn edit(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, u64)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Error> {
    let _guard = WRITE_LOCK.lock().await;
    let mut doc = load(&storage, &workspace)?;
    let tab = doc["tabs"]
        .as_array_mut()
        .and_then(|tabs| tabs.iter_mut().find(|t| t["id"].as_u64() == Some(id)))
        .ok_or_else(|| bad("Replay tab not found"))?;
    if let Some(value) = body.get("name") {
        tab["name"] = json!(name(value)?);
        tab["customName"] = json!(true);
    }
    if let Some(patch) = body.get("request") {
        merge_request(&mut tab["request"], patch)?;
    }
    validate_request(&tab["request"])?;
    let result = tab.clone();
    save(&storage, &workspace, &doc)?;
    Ok(Json(result))
}

// WebSocket Replay retains its public-address policy. HTTP uses http_target.
pub(crate) fn public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_broadcast()
                && !v.is_documentation()
                && v.octets()[0] != 0
                && v.octets()[0] < 240
                && !(v.octets()[0] == 100 && (64..=127).contains(&v.octets()[1]))
                && !(v.octets()[0] == 198 && (18..=19).contains(&v.octets()[1]))
        }
        std::net::IpAddr::V6(v) => {
            (v.segments()[0] & 0xe000) == 0x2000
                && !(v.segments()[0] == 0x2001 && v.segments()[1] == 0xdb8)
        }
    }
}
pub async fn send(
    State(storage): State<Arc<TrafficStorage>>,
    Path((workspace, id)): Path<(String, u64)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Error> {
    let doc = load(&storage, &workspace)?;
    let tab = doc["tabs"]
        .as_array()
        .and_then(|tabs| tabs.iter().find(|t| t["id"].as_u64() == Some(id)))
        .ok_or_else(|| bad("Replay tab not found"))?;
    let template = tab["request"].clone();
    let resolved = resolve_request(&template, &doc["variables"])?;
    let request = &resolved;
    validate_request(request)?;
    let url = reqwest::Url::parse(request["url"].as_str().unwrap()).map_err(bad)?;
    super::http_target::validate(&url).map_err(bad)?;
    let host = url.host_str().unwrap();
    let timeout = body["timeout_ms"]
        .as_u64()
        .unwrap_or(15000)
        .clamp(1000, 30000);
    let start = Instant::now();
    let client = super::http_target::client(&url, timeout).await.map_err(bad)?;
    let mut outgoing = client.request(
        request["method"]
            .as_str()
            .unwrap()
            .parse::<reqwest::Method>()
            .map_err(bad)?,
        url.clone(),
    );
    let mut sent_headers = vec![];
    for (key, value) in request["headers"].as_object().unwrap() {
        let lower = key.to_ascii_lowercase();
        if [
            "host",
            "connection",
            "content-length",
            "transfer-encoding",
            "upgrade",
            "expect",
        ]
        .contains(&lower.as_str())
            || lower.starts_with("proxy-")
        {
            continue;
        }
        let value = value.as_str().unwrap();
        outgoing = outgoing.header(key, value);
        sent_headers.push((key.clone(), value.to_string()));
    }
    let payload = if ["GET", "HEAD"].contains(&request["method"].as_str().unwrap()) {
        ""
    } else {
        request["body"].as_str().unwrap()
    };
    let mut entry = TrafficEntry::new_request(
        request["method"].as_str().unwrap(),
        url.as_str(),
        host,
        url.path(),
        url.scheme(),
        &pairs_to_json(&sent_headers),
        payload.as_bytes().to_vec(),
        None,
    );
    entry.source = "replay".into();
    entry.workspace_id = workspace.clone();
    let outcome: Result<(), String> = async {
        let mut response = outgoing
            .body(payload.to_string())
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if response.headers().get("content-encoding").is_some_and(|v|!v.as_bytes().eq_ignore_ascii_case(b"identity")) {return Err("Unsupported Content-Encoding in response".into());}
        entry.status_code = response.status().as_u16();
        let headers: Vec<_> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        entry.response_headers = pairs_to_json(&headers);
        entry.response_content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if entry.response_body.len() + chunk.len() > 2_000_000 {
                return Err("Response exceeds 2 MB".into());
            }
            entry.response_body.extend_from_slice(&chunk);
        }
        Ok(())
    }
    .await;
    entry.error = outcome.err();
    entry.response_size = entry.response_body.len() as u64;
    entry.duration_ms = start.elapsed().as_millis() as u64;
    storage
        .insert_in_workspace(&entry, &workspace)
        .map_err(bad)?;
    let response_headers: Value = serde_json::from_str(&entry.response_headers).unwrap_or(json!({}));
    let mut flat = serde_json::Map::new();
    if let Some(headers) = response_headers.as_object() {
        for (k,v) in headers { flat.insert(k.clone(),json!(v.as_array().map(|a|a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default())); }
    }
    let run = json!({"template":template,"request":resolved,"duration":entry.duration_ms,"error":entry.error,
        "response":if entry.error.is_none() { json!({"id":0,"method":entry.method,"url":entry.url,"headers":{},"body":"","status":entry.status_code,"statusText":entry.status_code.to_string(),"timestamp":entry.timestamp,"duration":entry.duration_ms,"size":entry.response_size,"responseHeaders":flat,"responseBody":String::from_utf8_lossy(&entry.response_body)}) } else { Value::Null }});
    storage.add_replay_run(&workspace,id,run).map_err(bad)?;
    storage.publish(TrafficEvent::ReplayResult {
        workspace_id: workspace,
        tab_id: id,
        entry: entry.clone(),
    });
    Ok(Json(serde_json::to_value(entry).map_err(bad)?))
}

pub fn validate_variables(value: &Value) -> Result<(), Error> {
    if value.is_null() { return Ok(()); }
    let variables = value.as_object().ok_or_else(||bad("variables must be an object"))?;
    if variables.len()>100 { return Err(bad("Maximum 100 variables")); }
    for (key,value) in variables {
        if key.is_empty() || key.len()>100 || !key.bytes().enumerate().all(|(i,c)|c.is_ascii_alphabetic()||c==b'_'||i>0&&(c.is_ascii_digit()||c==b'.'||c==b'-')) { return Err(bad("Invalid variable name")); }
        if value.as_str().is_none_or(|v|v.len()>64_000) { return Err(bad("Variable value must be text, at most 64 KB")); }
    }
    Ok(())
}
fn interpolate(text: &str, variables: &Value) -> Result<String, Error> {
    let mut result=String::new(); let mut remaining=text;
    while let Some(start)=remaining.find("{{") {
        result.push_str(&remaining[..start]);
        let rest=&remaining[start+2..];
        let end=rest.find("}}").ok_or_else(||bad("Unclosed variable placeholder"))?;
        let key=rest[..end].trim();
        result.push_str(variables.get(key).and_then(Value::as_str).ok_or_else(||bad(format!("Missing variable: {key}")))?);
        if result.len()>2_000_000 { return Err(bad("Resolved value too large")); }
        remaining=&rest[end+2..];
    }
    result.push_str(remaining); Ok(result)
}
fn resolve_request(template: &Value, variables: &Value) -> Result<Value, Error> {
    validate_variables(variables)?;
    validate_request(template)?;
    let mut request=template.clone();
    for field in ["url","body"] { request[field]=json!(interpolate(template[field].as_str().unwrap(),variables)?); }
    let mut headers=serde_json::Map::new();
    for (key,value) in template["headers"].as_object().unwrap() {
        let key=interpolate(key,variables)?; let value=interpolate(value.as_str().unwrap(),variables)?;
        reqwest::header::HeaderName::from_bytes(key.as_bytes()).map_err(bad)?;
        reqwest::header::HeaderValue::from_str(&value).map_err(bad)?;
        if headers.keys().any(|k|k.eq_ignore_ascii_case(&key)) { return Err(bad("Duplicate resolved header")); }
        headers.insert(key,json!(value));
    }
    request["headers"]=json!(headers);
    // Variable values are inserted literally once, then the same destination checks apply.
    let url=reqwest::Url::parse(request["url"].as_str().unwrap()).map_err(bad)?;
    if !["http","https"].contains(&url.scheme()) || !url.username().is_empty() || url.password().is_some() { return Err(bad("Expected HTTP(S) URL without credentials")); }
    validate_request(&request)?; Ok(request)
}

#[derive(serde::Deserialize)]
pub struct RunsQuery { offset: Option<usize> }
pub async fn list_runs(State(storage):State<Arc<TrafficStorage>>,Path((workspace,tab)):Path<(String,u64)>,Query(query):Query<RunsQuery>) -> Result<Json<Value>,Error> {
    let runs=storage.list_replay_runs(&workspace,tab,query.offset.unwrap_or(0)).map_err(bad)?;
    Ok(Json(json!({"data":runs,"has_more":runs.len()==50})))
}
pub async fn get_run(State(storage):State<Arc<TrafficStorage>>,Path((workspace,tab,id)):Path<(String,u64,String)>) -> Result<Json<Value>,Error> {
    let run=storage.get_replay_run(&workspace,tab,&id).map_err(bad)?.ok_or_else(||(StatusCode::NOT_FOUND,Json(json!({"error":"Run not found"}))))?;
    Ok(Json(run))
}
pub async fn save_run(State(storage):State<Arc<TrafficStorage>>,Path((workspace,tab)):Path<(String,u64)>,Json(run):Json<Value>) -> Result<Json<Value>,Error> {
    if run.to_string().len()>12*1024*1024 { return Err(bad("Run exceeds 12 MB")); }
    validate_request(&run["request"])?;
    validate_request(&run["template"])?;
    if run["response"].is_null()&&run["error"].as_str().is_none() { return Err(bad("Expected response or error")); }
    if !run["response"].is_null() && (run["response"]["responseBody"].as_str().is_none() || run["response"]["status"].as_u64().is_none() || !run["response"]["responseHeaders"].is_object()) { return Err(bad("Invalid response snapshot")); }
    Ok(Json(storage.add_replay_run(&workspace,tab,run).map_err(bad)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolves_templates_and_rejects_missing_variables_and_header_injection() {
        let template=json!({"method":"POST","url":"{{base_url}}/users/{{id}}","headers":{"Authorization":"Bearer {{token}}"},"body":"{{payload}}"});
        let vars=json!({"base_url":"https://example.com","id":"42","token":"secret","payload":"$& {{token}}"});
        let request=resolve_request(&template,&vars).unwrap();assert_eq!(request["url"],"https://example.com/users/42");assert_eq!(request["body"],"$& {{token}}");assert_eq!(request["headers"]["Authorization"],"Bearer secret");assert_eq!(template["url"],"{{base_url}}/users/{{id}}");
        assert!(resolve_request(&template,&json!({})).is_err());
        let mut injected=vars;injected["token"]=json!("x\r\nInjected: yes");assert!(resolve_request(&template,&injected).is_err());
        assert!(validate_variables(&json!({"bad name":"value"})).is_err());
    }

    #[tokio::test]
    async fn saved_replay_sends_local_http_and_records_actual_scheme() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/login", axum::routing::post(|body: String| async move { body }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let workspace = storage.create_workspace("Local Replay").unwrap();
        let tab = create(State(storage.clone()), Path(workspace.id.clone()), Json(json!({
            "request":{"method":"POST","url":format!("http://{address}/login"),"headers":{},"body":"local payload"}
        }))).await.unwrap().0;
        let result = send(State(storage.clone()), Path((workspace.id.clone(), tab["id"].as_u64().unwrap())), Json(json!({"timeout_ms":2000}))).await.unwrap().0;
        assert_eq!(result["status_code"], 200, "{result}");
        assert_eq!(result["response_body"], json!(b"local payload".to_vec()));
        assert_eq!(result["scheme"], "http");
        server.abort();
    }

    #[tokio::test]
    async fn sends_history_endpoints_preserve_snapshot_and_scope() {
        let storage=TrafficStorage::new(":memory:",1024).unwrap();
        let template=json!({"method":"GET","url":"https://example.com","headers":{},"body":""});
        let run=save_run(State(storage.clone()),Path(("default".into(),5)),Json(json!({"template":template,"request":template,"response":{"status":200,"responseBody":"payload","responseHeaders":{}},"duration":3}))).await.unwrap().0;
        let id=run["id"].as_str().unwrap().to_string();
        assert_eq!(get_run(State(storage.clone()),Path(("default".into(),5,id.clone()))).await.unwrap().0["response"]["responseBody"],"payload");
        assert!(get_run(State(storage.clone()),Path(("default".into(),6,id))).await.is_err());
        let list=list_runs(State(storage.clone()),Path(("default".into(),5)),Query(RunsQuery{offset:None})).await.unwrap().0;
        assert_eq!(list["data"].as_array().unwrap().len(),1);assert!(list["data"][0].get("response").is_none());
        let created=create(State(storage),Path("default".into()),Json(json!({}))).await.unwrap().0;assert_eq!(created["id"],6);
    }

    #[tokio::test]
    async fn create_edit_rename_preserve_other_tabs_and_workspace() {
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let workspace = storage.create_workspace("MCP tests").unwrap();
        let other = storage.create_workspace("Capture").unwrap();
        storage.set_active_workspace(&other.id).unwrap();
        let entry = TrafficEntry::new_request(
            "POST",
            "https://example.com/api",
            "example.com",
            "/api",
            "https",
            &pairs_to_json(&[("Content-Type".into(), "application/json".into())]),
            b"{\"a\":1}".to_vec(),
            Some("application/json".into()),
        );
        storage.insert(&entry).unwrap();
        let first = create(
            State(storage.clone()),
            Path(workspace.id.clone()),
            Json(json!({"traffic_id":entry.id,"name":"Copied"})),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(first["request"]["body"], "{\"a\":1}");
        assert_eq!(
            first["request"]["headers"]["content-type"],
            "application/json"
        );
        let _ = create(
            State(storage.clone()),
            Path(workspace.id.clone()),
            Json(json!({"name":"Other"})),
        )
        .await
        .unwrap();
        let _ = edit(
            State(storage.clone()),
            Path((workspace.id.clone(), 1)),
            Json(json!({"name":"Renamed","request":{"body":"changed"}})),
        )
        .await
        .unwrap();
        let doc = load(&storage, &workspace.id).unwrap();
        assert_eq!(doc["tabs"][0]["name"], "Renamed");
        assert_eq!(doc["tabs"][0]["customName"], true);
        assert_eq!(doc["tabs"][0]["request"]["body"], "changed");
        assert_eq!(doc["tabs"][0]["request"]["url"], "https://example.com/api");
        assert_eq!(doc["tabs"][1]["name"], "Other");
        assert_eq!(
            storage.session().unwrap().workspace_id,
            Some(other.id.clone())
        );
        let mut response = entry.clone();
        response.id = "replay-result".into();
        response.source = "replay".into();
        storage
            .insert_in_workspace(&response, &workspace.id)
            .unwrap();
        assert_eq!(
            storage.get("replay-result").unwrap().unwrap().workspace_id,
            workspace.id
        );
        assert_eq!(storage.session().unwrap().workspace_id, Some(other.id));
    }
    #[tokio::test]
    async fn invalid_edits_do_not_change_saved_tabs() {
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let _ = create(
            State(storage.clone()),
            Path("default".into()),
            Json(json!({"request":{"url":"http://127.0.0.1:1/"}})),
        )
        .await
        .unwrap();
        let before = load(&storage, "default").unwrap();
        assert!(edit(
            State(storage.clone()),
            Path(("default".into(), 1)),
            Json(json!({"request":{"headers":{"X-Test":"bad\r\nInjected: true"}}}))
        )
        .await
        .is_err());
        assert_eq!(load(&storage, "default").unwrap(), before);
    }
    #[test]
    fn excludes_private_and_reserved_addresses() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "198.18.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fd00::1",
            "2001:db8::1",
        ] {
            assert!(!public_ip(address.parse().unwrap()), "{address}");
        }
        assert!(public_ip("1.1.1.1".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}
