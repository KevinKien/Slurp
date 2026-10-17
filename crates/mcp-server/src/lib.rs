/// MCP (Model Context Protocol) server exposing captured traffic to AI clients.
///
/// Speaks newline-delimited JSON-RPC 2.0 over stdio and reads data from the
/// REST API of a running `Slurp` instance, so it never contends with the
/// proxy for the SQLite file. stdout carries protocol messages only.
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const SERVER_NAME: &str = "slurp";
const DEFAULT_PROTOCOL: &str = "2025-06-18";
const SUPPORTED_PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
/// Default cap for body text returned to the model.
const DEFAULT_MAX_BODY: usize = 4096;
const MAX_LIST_LIMIT: u64 = 200;

/// Client for the Slurp REST API.
pub struct Backend {
    http: reqwest::Client,
    base: String,
}

impl Backend {
    pub fn new(api_base: &str) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        Self {
            http: {
                let home=std::env::var_os(if cfg!(windows){"USERPROFILE"}else{"HOME"});
                let token=std::env::var("SLURP_API_TOKEN").ok().or_else(||home.and_then(|h|std::fs::read_to_string(std::path::PathBuf::from(h).join(".slurp/api-token")).ok()));
                let mut headers=reqwest::header::HeaderMap::new();
                if let Some(token)=token.filter(|v|v.len()==64&&v.bytes().all(|b|b.is_ascii_hexdigit())) {
                    let mut value=reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).unwrap();value.set_sensitive(true);headers.insert(reqwest::header::AUTHORIZATION,value);
                }
                reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(35)).default_headers(headers).build().expect("MCP HTTP client")
            },
            base: api_base.trim_end_matches('/').to_string(),
        }
    }

    async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value> {
        let res = self.http.get(format!("{}{}", self.base, path)).query(query).send().await
            .map_err(|e| anyhow!("cannot reach Slurp API at {} ({e}); is the proxy running?", self.base))?;
        if !res.status().is_success() {
            return Err(anyhow!("API returned {}", res.status()));
        }
        Ok(res.json().await?)
    }

    async fn write(&self, method: reqwest::Method, path: &str, body: &Value) -> Result<Value> {
        let res = self.http.request(method, format!("{}{}", self.base, path)).json(body).send().await?;
        let status = res.status();
        let value: Value = res.json().await?;
        if !status.is_success() { return Err(anyhow!("API {status}: {}", value["error"])); }
        Ok(value)
    }

    /// Resolve a workspace given by name or id (case-insensitive name) to its id.
    async fn resolve_workspace(&self, name_or_id: &str) -> Result<String> {
        let list = self.get("/api/workspaces", &[]).await?;
        let wanted = name_or_id.trim();
        // The in-memory session is not a saved workspace, so it is not in the list.
        if wanted.eq_ignore_ascii_case("temporary") {
            return Ok("temporary".to_string());
        }
        let found = list.as_array().into_iter().flatten().find(|w| {
            w["id"].as_str() == Some(wanted)
                || w["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(wanted))
        });
        match found {
            Some(w) => Ok(w["id"].as_str().unwrap_or_default().to_string()),
            None => {
                let names: Vec<&str> = list.as_array().into_iter().flatten().filter_map(|w| w["name"].as_str()).collect();
                Err(anyhow!("workspace '{wanted}' not found. Available: {}", names.join(", ")))
            }
        }
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let res = self.http.delete(format!("{}{}", self.base, path)).send().await
            .map_err(|e| anyhow!("cannot reach Slurp API at {} ({e}); is the proxy running?", self.base))?;
        if !res.status().is_success() {
            return Err(anyhow!("API returned {}", res.status()));
        }
        Ok(())
    }
}

/// Run the MCP server on stdin/stdout until EOF.
pub async fn run_stdio(api_base: &str) -> Result<()> {
    let backend = Backend::new(api_base);
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle_message(&backend, msg).await,
            Err(e) => Some(error_response(Value::Null, -32700, &format!("parse error: {e}"))),
        };
        if let Some(reply) = reply {
            out.write_all(reply.to_string().as_bytes()).await?;
            out.write_all(b"\n").await?;
            out.flush().await?;
        }
    }
    Ok(())
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Handle one JSON-RPC message. Returns `None` for notifications.
pub async fn handle_message(backend: &Backend, msg: Value) -> Option<Value> {
    let method = msg.get("method").and_then(Value::as_str)?;
    // Notifications carry no id and must not be answered.
    let id = msg.get("id").cloned()?;
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    let result = match method {
        "initialize" => {
            let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
            let version = SUPPORTED_PROTOCOLS.iter().find(|v| **v == requested).copied().unwrap_or(DEFAULT_PROTOCOL);
            json!({
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Inspect HTTP traffic captured by the Slurp proxy. Start with search_history or list_traffic, then get_traffic for headers and bodies. Use list_replay/create_replay/edit_replay/rename_replay/send_replay to manage saved workspace Replay tabs."
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools": tool_definitions()}),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match call_tool(backend, name, &args).await {
                Ok(text) => json!({"content": [{"type": "text", "text": text}]}),
                Err(e) => json!({"content": [{"type": "text", "text": e.to_string()}], "isError": true}),
            }
        }
        _ => return Some(error_response(id, -32601, &format!("method not found: {method}"))),
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

fn tool_definitions() -> Value {
    let mut tools = json!([
        {
            "name": "list_traffic",
            "description": "List captured HTTP requests (newest first) as compact summaries. Filter by host, method, status or a search keyword.",
            "inputSchema": {"type": "object", "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIST_LIMIT, "description": "Max entries (default 50)"},
                "offset": {"type": "integer", "minimum": 0},
                "host": {"type": "string"},
                "method": {"type": "string", "description": "e.g. GET, POST"},
                "status": {"type": "integer", "description": "Exact status code"},
                "search": {"type": "string", "description": "Keyword matched against URL and headers"},
                "workspace": {"type": "string", "description": "Workspace name or id (see list_workspaces), or \"temporary\" for requests kept in memory without a workspace. Omit to search all saved workspaces."}
            }},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "get_traffic",
            "description": "Get one captured request/response in full: headers and bodies (text, truncated).",
            "inputSchema": {"type": "object", "properties": {
                "id": {"type": "string", "description": "Entry id from list_traffic"},
                "max_body_bytes": {"type": "integer", "minimum": 0, "description": "Truncate each body to this many bytes (default 4096)"}
            }, "required": ["id"]},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "get_stats",
            "description": "Aggregate statistics: request count, bytes, error count and top hosts, optionally for one workspace.",
            "inputSchema": {"type": "object", "properties": {
                "workspace": {"type": "string", "description": "Workspace name or id. Omit for all workspaces."}
            }},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "list_workspaces",
            "description": "List workspaces (named groups of captured traffic) with request counts. 'active' marks the workspace receiving new captures.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "clear_traffic",
            "description": "Permanently delete captured traffic: one workspace if given, otherwise ALL workspaces. Only use when the user explicitly asks.",
            "inputSchema": {"type": "object", "properties": {
                "workspace": {"type": "string", "description": "Workspace name or id. Omit to delete everything."}
            }},
            "annotations": {"readOnlyHint": false, "destructiveHint": true}
        }
    ]);
    let tools_array = tools.as_array_mut().unwrap();
    let mut search = tools_array[0].clone();
    search["name"] = json!("search_history");
    search["description"] = json!("Search HTTP History by URL/header keyword, host, method, status and workspace; supports pagination. IDs returned are internal traffic IDs, not display row numbers.");
    tools_array.push(search);
    for (name, description, required, properties, readonly) in [
        ("list_replay", "List saved Replay tabs and their editable requests in a saved workspace.", vec!["workspace"], json!({}), true),
        ("create_replay", "Create a Replay tab, optionally copying a history request by traffic_id. request fields override copied values. Does not send a request.", vec!["workspace"], json!({"traffic_id":{"type":"string"},"name":{"type":"string"},"request":{"type":"object","properties":{"method":{"type":"string"},"url":{"type":"string"},"headers":{"type":"object","additionalProperties":{"type":"string"}},"body":{"type":"string"}}}}), false),
        ("edit_replay", "Edit a Replay request or its tab name. Omitted fields are preserved; headers replaces the complete header object. Does not send.", vec!["workspace","tab_id"], json!({"tab_id":{"type":"integer","minimum":1},"name":{"type":"string"},"request":{"type":"object","properties":{"method":{"type":"string"},"url":{"type":"string"},"headers":{"type":"object","additionalProperties":{"type":"string"}},"body":{"type":"string"}}}}), false),
        ("rename_replay", "Rename a saved Replay tab without changing its request.", vec!["workspace","tab_id","name"], json!({"tab_id":{"type":"integer","minimum":1},"name":{"type":"string","minLength":1,"maxLength":200}}), false),
        ("send_replay", "Send the saved Replay request to its HTTP(S) target, including localhost, LAN and custom ports, without redirects; timeout at most 30 seconds, response at most 2 MB. Saves the result to this workspace and updates UI. May change remote data; only send when requested.", vec!["workspace","tab_id"], json!({"tab_id":{"type":"integer","minimum":1},"timeout_ms":{"type":"integer","minimum":1000,"maximum":30000},"max_body_bytes":{"type":"integer","minimum":0}}), false),
    ] {
        let mut props = properties.as_object().unwrap().clone();
        props.insert("workspace".into(), json!({"type":"string","description":"Saved workspace name or id. Temporary sessions do not persist Replay tabs."}));
        tools_array.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":props,"required":required},"annotations":{"readOnlyHint":readonly,"destructiveHint":name=="send_replay","openWorldHint":name=="send_replay"}}));
    }
    tools
}

async fn call_tool(backend: &Backend, name: &str, args: &Value) -> Result<String> {
    match name {
        "list_traffic" | "search_history" => {
            let mut q: Vec<(&str, String)> = Vec::new();
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50).clamp(1, MAX_LIST_LIMIT);
            q.push(("limit", limit.to_string()));
            if let Some(o) = args.get("offset").and_then(Value::as_u64) {
                q.push(("offset", o.to_string()));
            }
            for key in ["host", "method", "search"] {
                if let Some(v) = args.get(key).and_then(Value::as_str).filter(|v| !v.is_empty()) {
                    q.push((key, v.to_string()));
                }
            }
            if let Some(s) = args.get("status").and_then(Value::as_u64) {
                q.push(("status", s.to_string()));
            }
            if let Some(w) = workspace_arg(args) {
                q.push(("workspace", backend.resolve_workspace(w).await?));
            }
            let res = backend.get("/api/traffic", &q).await?;
            Ok(serde_json::to_string_pretty(&summarize_list(&res))?)
        }
        "get_traffic" => {
            let id = args.get("id").and_then(Value::as_str).filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow!("missing required argument: id"))?;
            // The id is interpolated into a URL path; reject anything that could alter it.
            if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(anyhow!("invalid id"));
            }
            let max = args.get("max_body_bytes").and_then(Value::as_u64).map(|n| n as usize).unwrap_or(DEFAULT_MAX_BODY);
            let entry = backend.get(&format!("/api/traffic/{id}"), &[]).await?;
            Ok(serde_json::to_string_pretty(&detail(&entry, max))?)
        }
        "list_replay" | "create_replay" | "edit_replay" | "rename_replay" | "send_replay" => {
            let workspace = workspace_arg(args).ok_or_else(||anyhow!("workspace is required"))?;
            let workspace = backend.resolve_workspace(workspace).await?;
            if workspace == "temporary" { return Err(anyhow!("Replay tools require a saved workspace")); }
            let path = format!("/api/workspaces/{workspace}/replay");
            if name == "list_replay" { return Ok(serde_json::to_string_pretty(&backend.get(&path,&[]).await?)?); }
            let result = if name == "create_replay" {
                backend.write(reqwest::Method::POST,&format!("{path}/tabs"),args).await?
            } else {
                let tab = args["tab_id"].as_u64().filter(|n|*n>0).ok_or_else(||anyhow!("tab_id must be a positive integer"))?;
                let path = format!("{path}/tabs/{tab}");
                if name == "send_replay" {
                    let entry = backend.write(reqwest::Method::POST,&format!("{path}/send"),args).await?;
                    detail(&entry,args["max_body_bytes"].as_u64().unwrap_or(DEFAULT_MAX_BODY as u64).min(100_000) as usize)
                } else {
                    if name == "rename_replay" && args["name"].as_str().is_none() { return Err(anyhow!("name is required")); }
                    let patch = if name == "rename_replay" { json!({"name":args["name"]}) } else { args.clone() };
                    backend.write(reqwest::Method::PATCH,&path,&patch).await?
                }
            };
            Ok(serde_json::to_string_pretty(&result)?)
        }
        "get_stats" => {
            let mut q: Vec<(&str, String)> = Vec::new();
            if let Some(w) = workspace_arg(args) {
                q.push(("workspace", backend.resolve_workspace(w).await?));
            }
            Ok(serde_json::to_string_pretty(&backend.get("/api/stats", &q).await?)?)
        }
        "list_workspaces" => Ok(serde_json::to_string_pretty(&backend.get("/api/workspaces", &[]).await?)?),
        "clear_traffic" => match workspace_arg(args) {
            Some(w) => {
                let id = backend.resolve_workspace(w).await?;
                backend.delete(&format!("/api/traffic?workspace={id}")).await?;
                Ok(format!("Traffic in workspace '{w}' deleted."))
            }
            None => {
                backend.delete("/api/traffic").await?;
                Ok("All captured traffic deleted.".into())
            }
        },
        other => Err(anyhow!("unknown tool: {other}")),
    }
}

fn workspace_arg(args: &Value) -> Option<&str> {
    args.get("workspace").and_then(Value::as_str).map(str::trim).filter(|v| !v.is_empty())
}

fn summarize_list(res: &Value) -> Value {
    let rows: Vec<Value> = res["data"].as_array().map(Vec::as_slice).unwrap_or(&[]).iter().map(|e| json!({
        "id": e["id"], "timestamp": e["timestamp"], "method": e["method"], "url": e["url"],
        "status": e["status_code"], "duration_ms": e["duration_ms"],
        "response_size": e["response_size"], "error": e["error"], "workspace_id": e["workspace_id"],
    })).collect();
    json!({"total": res["total"], "offset": res["offset"], "returned": rows.len(), "entries": rows})
}

/// Decode a JSON number array into text, truncated; binary bodies are described instead.
fn body_text(v: &Value, max: usize) -> Value {
    let bytes: Vec<u8> = v.as_array().map(|a| a.iter().filter_map(|n| n.as_u64().map(|n| n as u8)).collect()).unwrap_or_default();
    if bytes.is_empty() {
        return Value::Null;
    }
    if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() && String::from_utf8_lossy(&bytes).matches('\u{FFFD}').count() > bytes.len() / 20 {
        return json!(format!("<binary body, {} bytes>", bytes.len()));
    }
    let cut = bytes.len().min(max);
    let mut text = String::from_utf8_lossy(&bytes[..cut]).into_owned();
    if cut < bytes.len() {
        text.push_str(&format!("\n… [truncated, {} of {} bytes shown]", cut, bytes.len()));
    }
    json!(text)
}

fn parse_headers(v: &Value) -> Value {
    v.as_str().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null)
}

fn detail(e: &Value, max: usize) -> Value {
    json!({
        "id": e["id"], "timestamp": e["timestamp"], "duration_ms": e["duration_ms"], "error": e["error"],
        "workspace_id": e["workspace_id"],
        "request": {
            "method": e["method"], "url": e["url"], "headers": parse_headers(&e["request_headers"]),
            "content_type": e["request_content_type"], "size": e["request_size"],
            "body": body_text(&e["request_body"], max),
        },
        "response": {
            "status": e["status_code"], "headers": parse_headers(&e["response_headers"]),
            "content_type": e["response_content_type"], "size": e["response_size"],
            "body": body_text(&e["response_body"], max),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> Backend {
        Backend::new("http://127.0.0.1:1")
    }

    #[tokio::test]
    async fn initialize_negotiates_version() {
        let r = handle_message(&backend(), json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}})).await.unwrap();
        assert_eq!(r["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(r["id"], 1);
        let r = handle_message(&backend(), json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999"}})).await.unwrap();
        assert_eq!(r["result"]["protocolVersion"], DEFAULT_PROTOCOL);
    }

    #[tokio::test]
    async fn notifications_get_no_reply() {
        assert!(handle_message(&backend(), json!({"jsonrpc":"2.0","method":"notifications/initialized"})).await.is_none());
    }

    #[tokio::test]
    async fn lists_tools_and_rejects_unknown_method() {
        let r = handle_message(&backend(), json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})).await.unwrap();
        assert_eq!(r["result"]["tools"].as_array().unwrap().len(), 11);
        let r = handle_message(&backend(), json!({"jsonrpc":"2.0","id":2,"method":"nope"})).await.unwrap();
        assert_eq!(r["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn tool_errors_are_reported_in_result() {
        let r = handle_message(&backend(), json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_traffic","arguments":{"id":"../x"}}})).await.unwrap();
        assert_eq!(r["result"]["isError"], true);
        let r = handle_message(&backend(), json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_stats"}})).await.unwrap();
        assert_eq!(r["result"]["isError"], true); // backend unreachable
    }

    #[tokio::test]
    async fn replay_tools_work_through_the_rest_api() {
        use axum::{routing::{get,post,patch}, Router};
        let storage=proxy_core::TrafficStorage::new(":memory:",1024).unwrap();
        let entry=proxy_core::TrafficEntry::new_request("POST","https://example.com/checkout","example.com","/checkout","https","[]",b"original".to_vec(),None);
        storage.insert_in_workspace(&entry,"default").unwrap();
        let app=Router::new()
            .route("/local-login",post(|body: String| async move { body }))
            .route("/api/workspaces",get(web_server::api::list_workspaces))
            .route("/api/traffic",get(web_server::api::list_traffic))
            .route("/api/traffic/:id",get(web_server::api::get_traffic))
            .route("/api/workspaces/:id/replay",get(web_server::api::get_replay_tabs))
            .route("/api/workspaces/:id/replay/tabs",post(web_server::replay::create))
            .route("/api/workspaces/:id/replay/tabs/:tab",patch(web_server::replay::edit))
            .route("/api/workspaces/:id/replay/tabs/:tab/send",post(web_server::replay::send))
            .with_state(storage);
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_url=format!("http://{}/local-login",listener.local_addr().unwrap());
        let backend=Backend::new(&format!("http://{}",listener.local_addr().unwrap()));
        let server=tokio::spawn(async move {axum::serve(listener,app).await.unwrap()});
        let found:Value=serde_json::from_str(&call_tool(&backend,"search_history",&json!({"search":"checkout","workspace":"Default"})).await.unwrap()).unwrap();
        assert_eq!(found["returned"],1);
        let copied:Value=serde_json::from_str(&call_tool(&backend,"create_replay",&json!({"workspace":"Default","traffic_id":entry.id,"name":"Checkout"})).await.unwrap()).unwrap();
        assert_eq!(copied["request"]["body"],"original");
        call_tool(&backend,"edit_replay",&json!({"workspace":"default","tab_id":1,"request":{"body":"edited"}})).await.unwrap();
        call_tool(&backend,"rename_replay",&json!({"workspace":"default","tab_id":1,"name":"MCP test"})).await.unwrap();
        let tabs:Value=serde_json::from_str(&call_tool(&backend,"list_replay",&json!({"workspace":"default"})).await.unwrap()).unwrap();
        assert_eq!(tabs["tabs"][0]["name"],"MCP test");
        assert_eq!(tabs["tabs"][0]["request"]["body"],"edited");
        call_tool(&backend,"edit_replay",&json!({"workspace":"default","tab_id":1,"request":{"url":local_url}})).await.unwrap();
        let sent:Value=serde_json::from_str(&call_tool(&backend,"send_replay",&json!({"workspace":"default","tab_id":1})).await.unwrap()).unwrap();
        assert_eq!(sent["response"]["status"],200);
        assert_eq!(sent["response"]["body"],"edited");
        server.abort();
    }

    #[test]
    fn body_is_truncated_and_binary_detected() {
        let long: Vec<u8> = vec![b'a'; 10];
        let t = body_text(&json!(long), 4);
        assert!(t.as_str().unwrap().starts_with("aaaa\n… [truncated"));
        assert!(body_text(&json!([0u8, 1, 2]), 100).as_str().unwrap().contains("binary"));
        assert!(body_text(&json!([]), 100).is_null());
    }
}
