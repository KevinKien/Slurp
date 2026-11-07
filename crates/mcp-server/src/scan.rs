//! Headless scan execution for MCP clients.
//!
//! Scans are executed here and persisted through the Slurp REST API so MCP clients can run
//! passive and active checks without a browser. Evidence and findings follow the same run schema
//! the UI uses, and every run is validated by the server before it is stored.
use crate::Backend;
use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

pub const PASSIVE_CHECKS: &[&str] = &["security-headers", "cookie-flags", "error-disclosure"];
pub const ACTIVE_CHECKS: &[&str] = &["command-injection", "path-traversal", "file-inclusion", "oauth-redirect"];

pub trait Sender {
    async fn send(&self, request: &Value, timeout_ms: u64) -> Result<Value>;
}

impl Sender for Backend {
    async fn send(&self, request: &Value, timeout_ms: u64) -> Result<Value> {
        let mut data = request.clone();
        data["timeout"] = json!(timeout_ms);
        self.write(reqwest::Method::POST, "/api/replay/send", &data)
            .await
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn preview(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut out: String = text.chars().take(limit).collect();
    out.push_str(&format!("\n… [truncated, {limit} characters shown]"));
    out
}

fn body_bytes(raw: &Value) -> Vec<u8> {
    raw.as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_u64().map(|value| value as u8))
                .collect()
        })
        .unwrap_or_default()
}

fn body_string(raw: &Value) -> Result<String> {
    let bytes = body_bytes(raw);
    if bytes.contains(&0) {
        return Err(anyhow!("binary request bodies are not supported by MCP scans"));
    }
    String::from_utf8(bytes).map_err(|_| anyhow!("binary request bodies are not supported by MCP scans"))
}

fn header_object(entry: &Value, field: &str) -> Map<String, Value> {
    let raw = entry[field]
        .as_str()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or(Value::Null);
    let mut out = Map::new();
    if let Some(object) = raw.as_object() {
        for (name, value) in object {
            let text = if let Some(values) = value.as_array() {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                value.as_str().unwrap_or_default().to_string()
            };
            out.insert(name.to_ascii_lowercase(), json!(text));
        }
    }
    out
}

fn header_values(entry: &Value, field: &str, wanted: &str) -> Vec<String> {
    let raw = entry[field]
        .as_str()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or(Value::Null);
    raw.as_object()
        .and_then(|object| {
            object
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
        })
        .map(|(_, value)| {
            if let Some(values) = value.as_array() {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            } else {
                value
                    .as_str()
                    .map(|text| vec![text.to_string()])
                    .unwrap_or_default()
            }
        })
        .unwrap_or_default()
}

pub fn entry_request(entry: &Value) -> Result<Value> {
    let mut headers = header_object(entry, "request_headers");
    for name in ["content-length", "transfer-encoding", "expect"] {
        headers.remove(name);
    }
    Ok(json!({
        "method": entry["method"].as_str().unwrap_or("GET"),
        "url": entry["url"].as_str().ok_or_else(|| anyhow!("traffic entry has no URL"))?,
        "headers": headers,
        "body": body_string(&entry["request_body"])?,
    }))
}

fn observed(entry: &Value, request: &Value) -> Value {
    let body = String::from_utf8_lossy(&body_bytes(&entry["response_body"])).to_string();
    let mut headers = header_object(entry, "response_headers");
    headers.retain(|_, value| value.as_str().is_some_and(|text| text.len() <= 8192));
    let headers: Map<_, _> = headers.into_iter().take(200).collect();
    json!({
        "id": "observed",
        "label": "Captured response",
        "timestamp": now(),
        "request": request,
        "response": {
            "status": entry["status_code"].as_u64().unwrap_or(0),
            "responseHeaders": headers,
            "responseBody": preview(&body, 32000),
        },
        "setCookies": [],
        "duration": entry["duration_ms"].as_f64().unwrap_or(0.0).clamp(0.0, 3_600_000.0),
        "size": entry["response_size"].as_u64().unwrap_or(0).min(2_000_000),
        "truncated": body.chars().count() > 32000,
    })
}

fn sent_evidence(id: &str, label: &str, request: &Value, result: &Value) -> Value {
    if result["ok"] == true {
        let body = result["responseBody"].as_str().unwrap_or_default();
        let headers: Map<String, Value> = result["responseHeaders"]
            .as_object()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, value)| value.as_str().is_some_and(|text| text.len() <= 8192))
            .take(200)
            .collect();
        json!({
            "id": id,
            "label": label,
            "timestamp": now(),
            "request": request,
            "response": {
                "status": result["status"],
                "responseHeaders": headers,
                "responseBody": preview(body, 32000),
            },
            "setCookies": [],
            "duration": result["duration"].as_f64().unwrap_or(0.0).clamp(0.0, 3_600_000.0),
            "size": result["size"].as_u64().unwrap_or(0).min(2_000_000),
            "truncated": body.chars().count() > 32000,
        })
    } else {
        json!({
            "id": id,
            "label": label,
            "timestamp": now(),
            "request": request,
            "error": preview(result["error"].as_str().unwrap_or("request failed"), 4000),
            "setCookies": [],
            "duration": result["duration"].as_f64().unwrap_or(0.0).clamp(0.0, 3_600_000.0),
            "size": 0,
            "truncated": false,
        })
    }
}

fn finding(
    check: &str,
    id: &str,
    title: &str,
    summary: &str,
    evidence: &[&str],
    excerpts: Vec<String>,
    severity: &str,
    confidence: &str,
    method: &str,
) -> Value {
    json!({
        "id": id,
        "fingerprint": format!("{check}:{id}"),
        "checkId": check,
        "title": title,
        "summary": summary,
        "severity": severity,
        "confidence": confidence,
        "status": "needs_review",
        "evidenceIds": evidence,
        "excerpts": excerpts.into_iter().map(|text| text.chars().take(4000).collect::<String>()).collect::<Vec<_>>(),
        "remediation": "Enforce the intended server-side policy for this input and re-test after the fix. Validate the finding against the application context before reporting it.",
        "verification": {
            "method": method,
            "outcome": "inconclusive",
            "reason": "The differential evidence requires contextual confirmation; exploitability is not asserted."
        },
    })
}

fn check_result(check: &str, status: &str, message: &str, findings: &[Value]) -> Value {
    json!({
        "checkId": check,
        "status": status,
        "message": message,
        "findingIds": findings.iter().map(|finding| finding["id"].clone()).collect::<Vec<_>>(),
    })
}

struct RunParts {
    id: String,
    started: String,
    mode: &'static str,
    request: Value,
    evidence: Vec<Value>,
    findings: Vec<Value>,
    checks: Vec<Value>,
    sent: usize,
    max_requests: usize,
    baseline_ids: Vec<String>,
}

fn finish(parts: RunParts) -> Value {
    let bytes: u64 = parts
        .evidence
        .iter()
        .filter_map(|item| item["size"].as_u64())
        .sum();
    json!({
        "version": 1,
        "id": parts.id,
        "origin": "mcp",
        "startedAt": parts.started,
        "finishedAt": now(),
        "status": "completed",
        "message": format!("MCP {} scan", parts.mode),
        "plan": {
            "request": parts.request,
            "mode": parts.mode,
            "checks": parts.checks.iter().filter_map(|check| check["checkId"].as_str()).collect::<Vec<_>>(),
            "parameters": [],
            "allowSending": parts.mode == "active",
            "baselineSamples": 1,
            "maxRequests": parts.max_requests,
            "rate": 2,
            "delay": 0,
            "diffOptions": {},
        },
        "sent": parts.sent,
        "bytes": bytes,
        "baselineStable": true,
        "baselineIds": parts.baseline_ids,
        "evidence": parts.evidence,
        "findings": parts.findings,
        "checks": parts.checks,
    })
}

fn select_checks(requested: &[String], supported: &[&str], kind: &str) -> Result<Vec<String>> {
    if requested.is_empty() {
        return Ok(supported.iter().map(|name| name.to_string()).collect());
    }
    let mut checks = vec![];
    for check in requested {
        if !supported.contains(&check.as_str()) {
            return Err(anyhow!(
                "unsupported {kind} check '{check}'. Supported: {}",
                supported.join(", ")
            ));
        }
        if !checks.contains(check) {
            checks.push(check.clone());
        }
    }
    Ok(checks)
}

pub fn run_passive(id: &str, entry: &Value, requested: &[String]) -> Result<Value> {
    let checks = select_checks(requested, PASSIVE_CHECKS, "passive")?;
    let request = entry_request(entry)?;
    let status = entry["status_code"].as_u64().unwrap_or(0);
    if !(100..=599).contains(&status) {
        return Err(anyhow!("captured entry has no HTTP response"));
    }
    let response_headers = header_object(entry, "response_headers");
    let body = String::from_utf8_lossy(&body_bytes(&entry["response_body"])).to_string();
    let scheme = reqwest::Url::parse(entry["url"].as_str().unwrap_or_default())
        .map(|url| url.scheme().to_string())
        .unwrap_or_default();
    let mut findings = vec![];
    let mut results = vec![];
    for check in &checks {
        match check.as_str() {
            "security-headers" => {
                let present = |name: &str| response_headers.contains_key(name);
                let mut missing = vec![];
                for name in [
                    "content-security-policy",
                    "x-content-type-options",
                    "referrer-policy",
                    "permissions-policy",
                ] {
                    if !present(name) {
                        missing.push(name.to_string());
                    }
                }
                if !present("x-frame-options")
                    && !response_headers
                        .get("content-security-policy")
                        .and_then(Value::as_str)
                        .is_some_and(|value| value.to_ascii_lowercase().contains("frame-ancestors"))
                {
                    missing.push("x-frame-options or CSP frame-ancestors".into());
                }
                if scheme == "https" && !present("strict-transport-security") {
                    missing.push("strict-transport-security".into());
                }
                if missing.is_empty() {
                    results.push(check_result(check, "passed", "Required response headers are present.", &[]));
                } else {
                    let item = finding(
                        check,
                        "missing-security-headers",
                        "Missing security response headers",
                        "The captured response omits one or more defensive headers. Missing headers are configuration observations, not an exploit by themselves; their impact depends on the application.",
                        &["observed"],
                        missing.clone(),
                        "low",
                        "high",
                        "direct observation of the captured response headers",
                    );
                    results.push(check_result(
                        check,
                        "findings",
                        "One or more defensive headers are missing.",
                        std::slice::from_ref(&item),
                    ));
                    findings.push(item);
                }
            }
            "cookie-flags" => {
                let cookies = header_values(entry, "response_headers", "set-cookie");
                let mut cookie_findings = vec![];
                for cookie in &cookies {
                    let name = cookie
                        .split('=')
                        .next()
                        .unwrap_or("cookie")
                        .trim()
                        .chars()
                        .map(|character| {
                            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                                character
                            } else {
                                '-'
                            }
                        })
                        .collect::<String>();
                    let lower = cookie.to_ascii_lowercase();
                    let mut missing = vec![];
                    if scheme == "https" && !lower.contains("secure") {
                        missing.push("Secure".to_string());
                    }
                    if !lower.contains("httponly") {
                        missing.push("HttpOnly".to_string());
                    }
                    if !lower.contains("samesite") {
                        missing.push("SameSite".to_string());
                    }
                    if missing.is_empty() {
                        continue;
                    }
                    let item = finding(
                        check,
                        &format!("cookie-{name}"),
                        &format!("Cookie '{name}' lacks {}", missing.join(", ")),
                        "The captured Set-Cookie header omits defensive attributes. Cookie flags reduce script access, cross-site sending or cleartext transport; this is an observation, not proof of a vulnerability.",
                        &["observed"],
                        missing.clone(),
                        "low",
                        "high",
                        "direct observation of the captured Set-Cookie header",
                    );
                    cookie_findings.push(item);
                }
                if cookie_findings.is_empty() {
                    results.push(check_result(
                        check,
                        "passed",
                        "No missing cookie attributes were observed in captured Set-Cookie headers.",
                        &[],
                    ));
                } else {
                    results.push(check_result(
                        check,
                        "findings",
                        "Captured cookies omit defensive attributes.",
                        &cookie_findings,
                    ));
                    findings.extend(cookie_findings);
                }
            }
            "error-disclosure" => {
                let patterns = [
                    "Traceback (most recent call last)",
                    "SQLSTATE[",
                    "Fatal error:",
                    "java.lang.",
                    "You have an error in your SQL syntax",
                    "Microsoft OLE DB Provider for SQL Server",
                ];
                let matched: Vec<&str> = patterns
                    .iter()
                    .copied()
                    .filter(|pattern| body.contains(pattern))
                    .collect();
                if matched.is_empty() {
                    results.push(check_result(
                        check,
                        "passed",
                        "No supported error or stack marker was observed in the captured body.",
                        &[],
                    ));
                } else {
                    let item = finding(
                        check,
                        "error-signature",
                        "Error or stack trace disclosed",
                        "The captured body contains a framework or database error marker. Error disclosure can reveal internals; severity depends on the exposed detail and whether the path is reachable by untrusted users.",
                        &["observed"],
                        matched.iter().map(|pattern| format!("Marker: {pattern}")).collect(),
                        "medium",
                        "medium",
                        "direct observation of the captured response body",
                    );
                    results.push(check_result(
                        check,
                        "findings",
                        "Error or stack markers are present in the captured body.",
                        std::slice::from_ref(&item),
                    ));
                    findings.push(item);
                }
            }
            _ => unreachable!(),
        }
    }
    Ok(finish(RunParts {
        id: id.to_string(),
        started: now(),
        mode: "passive",
        request: request.clone(),
        evidence: vec![observed(entry, &request)],
        findings,
        checks: results,
        sent: 0,
        max_requests: 1,
        baseline_ids: vec![],
    }))
}

#[derive(Clone, Debug)]
enum Target {
    Query { name: String, occurrence: usize },
    Form { name: String, occurrence: usize },
    Json { field: String },
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
                if let Some(byte) = hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                    out.push(byte);
                    index += 3;
                    continue;
                }
                out.push(bytes[index]);
                index += 1;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encodes only characters that would break the query or form syntax.
/// `%` is preserved so callers can supply intentionally pre-encoded payloads.
fn encode_value(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b' ' => out.push_str("%20"),
            b'#' => out.push_str("%23"),
            b'&' => out.push_str("%26"),
            b'=' => out.push_str("%3D"),
            b'+' => out.push_str("%2B"),
            byte => out.push(byte as char),
        }
    }
    out
}

fn is_form(request: &Value) -> bool {
    request["headers"]
        .as_object()
        .into_iter()
        .flatten()
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && value
                    .as_str()
                    .is_some_and(|text| text.to_ascii_lowercase().contains("application/x-www-form-urlencoded"))
        })
}

fn form_fields(body: &str) -> Vec<String> {
    body.split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| percent_decode(segment.split('=').next().unwrap_or_default()))
        .collect()
}

fn json_field(request: &Value) -> Option<String> {
    let value: Value = serde_json::from_str(request["body"].as_str()?).ok()?;
    let object = value.as_object()?;
    object
        .iter()
        .find(|(_, value)| value.is_string())
        .map(|(name, _)| name.clone())
}

fn select_target(request: &Value, wanted: Option<&str>) -> Result<Target> {
    let url = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())?;
    let query: Vec<String> = url.query_pairs().map(|(name, _)| name.to_string()).collect();
    let body = request["body"].as_str().unwrap_or_default();
    let forms = if is_form(request) { form_fields(body) } else { vec![] };
    let json = json_field(request);
    let resolve = |name: &str| -> Option<Target> {
        if query.iter().any(|candidate| candidate == name) {
            return Some(Target::Query {
                name: name.to_string(),
                occurrence: 0,
            });
        }
        if forms.iter().any(|candidate| candidate == name) {
            return Some(Target::Form {
                name: name.to_string(),
                occurrence: 0,
            });
        }
        if json.as_deref() == Some(name) {
            return Some(Target::Json {
                field: name.to_string(),
            });
        }
        None
    };
    match wanted {
        Some(name) if name.starts_with("body.") => {
            let name = &name[5..];
            if forms.iter().any(|candidate| candidate == name) {
                Ok(Target::Form {
                    name: name.to_string(),
                    occurrence: 0,
                })
            } else if json.as_deref() == Some(name) {
                Ok(Target::Json {
                    field: name.to_string(),
                })
            } else {
                Err(anyhow!("body field '{name}' was not found"))
            }
        }
        Some(name) => resolve(name).ok_or_else(|| {
            anyhow!("parameter '{name}' was not found; pass a query name or body.<field>")
        }),
        None => resolve(query.first().map(String::as_str).unwrap_or_default())
            .or_else(|| resolve(forms.first().map(String::as_str).unwrap_or_default()))
            .or_else(|| {
                json.as_deref().map(|field| Target::Json {
                    field: field.to_string(),
                })
            })
            .ok_or_else(|| anyhow!("no mutable query, form or JSON string field was found")),
    }
}

fn mutate(request: &Value, target: &Target, value: &str) -> Result<Value> {
    let mut out = request.clone();
    match target {
        Target::Query { name, occurrence } => {
            let mut url = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())?;
            let raw = url.query().unwrap_or_default().to_string();
            let mut found = false;
            let mut seen = 0usize;
            let mut segments = vec![];
            for segment in raw.split('&').filter(|segment| !segment.is_empty()) {
                let raw_name = segment.split('=').next().unwrap_or(segment);
                if percent_decode(raw_name) == *name {
                    let current = seen;
                    seen += 1;
                    if current == *occurrence {
                        found = true;
                        segments.push(format!("{raw_name}={}", encode_value(value)));
                        continue;
                    }
                }
                segments.push(segment.to_string());
            }
            if !found {
                return Err(anyhow!("query parameter not found"));
            }
            url.set_query(Some(&segments.join("&")));
            out["url"] = json!(url.as_str());
        }
        Target::Form { name, occurrence } => {
            let mut found = false;
            let mut seen = 0usize;
            let mut segments = vec![];
            for segment in request["body"].as_str().unwrap_or_default().split('&') {
                let raw_name = segment.split('=').next().unwrap_or(segment);
                if percent_decode(raw_name) == *name {
                    let current = seen;
                    seen += 1;
                    if current == *occurrence {
                        found = true;
                        segments.push(format!("{raw_name}={}", encode_value(value)));
                        continue;
                    }
                }
                segments.push(segment.to_string());
            }
            if !found {
                return Err(anyhow!("form field not found"));
            }
            out["body"] = json!(segments.join("&"));
        }
        Target::Json { field } => {
            let mut root: Value = serde_json::from_str(request["body"].as_str().unwrap_or_default())?;
            let object = root
                .as_object_mut()
                .ok_or_else(|| anyhow!("JSON object body required"))?;
            if !object.get(field).is_some_and(Value::is_string) {
                return Err(anyhow!("JSON string field not found"));
            }
            object.insert(field.clone(), json!(value));
            out["body"] = json!(root.to_string());
        }
    }
    Ok(out)
}

fn upsert_query(request: &Value, name: &str, value: &str) -> Result<Value> {
    let mut out = request.clone();
    let mut url = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())?;
    let raw = url.query().unwrap_or_default().to_string();
    let mut found = false;
    let mut segments: Vec<String> = raw
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let raw_name = segment.split('=').next().unwrap_or(segment);
            if percent_decode(raw_name) == name {
                found = true;
                format!("{raw_name}={}", encode_value(value))
            } else {
                segment.to_string()
            }
        })
        .collect();
    if !found {
        segments.push(format!("{name}={}", encode_value(value)));
    }
    url.set_query(Some(&segments.join("&")));
    out["url"] = json!(url.as_str());
    Ok(out)
}

fn b64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 63) as usize] as char);
        out.push(TABLE[((triple >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(triple & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    let mut values = Vec::new();
    for character in input.bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            _ => return None,
        };
        values.push(value);
    }
    if values.len() < 2 {
        return None;
    }
    let mut out = Vec::new();
    for chunk in values.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let mut triple = (chunk[0] as u32) << 18;
        triple |= (chunk[1] as u32) << 12;
        if chunk.len() > 2 {
            triple |= (chunk[2] as u32) << 6;
        }
        if chunk.len() > 3 {
            triple |= chunk[3] as u32;
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

fn decoded_root(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let base64 = |byte: u8| {
            byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'='
        };
        if !base64(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && base64(bytes[index]) {
            index += 1;
        }
        if index - start >= 40 {
            if let Some(decoded) = b64_decode(&body[start..index]) {
                let text = String::from_utf8_lossy(&decoded);
                if text.contains("root:x:0:0:") || text.contains("root:*:0:0:") {
                    return true;
                }
            }
        }
    }
    false
}

fn uid_signature(body: &str) -> bool {
    let mut from = 0;
    while let Some(offset) = body[from..].find("uid=") {
        let index = from + offset;
        let rest = &body[index + 4..];
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        if digits > 0 && rest[digits..].starts_with('(') {
            return true;
        }
        from = index + 4;
    }
    false
}

fn file_signature(body: &str) -> bool {
    body.contains("root:x:0:0:")
        || body.contains("root:*:0:0:")
        || (body.contains("[extensions]") && body.contains("[fonts]"))
        || decoded_root(body)
}

enum Signature {
    Uid,
    File,
    Marker(String),
}

fn detected(body: &str, signature: &Signature) -> bool {
    match signature {
        Signature::Uid => uid_signature(body),
        Signature::File => file_signature(body),
        Signature::Marker(marker) => body.contains(marker),
    }
}

fn payloads(check: &str, nonce: &str) -> Vec<(String, Signature)> {
    match check {
        "command-injection" => [";id", "|id", "$(id)", "`id`"]
            .iter()
            .map(|payload| (payload.to_string(), Signature::Uid))
            .collect(),
        "path-traversal" => [
            "../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..\\..\\..\\..\\Windows\\win.ini",
            "....//....//....//....//etc/passwd",
        ]
        .iter()
        .map(|payload| (payload.to_string(), Signature::File))
        .collect(),
        "file-inclusion" => vec![
            (
                "php://filter/convert.base64-encode/resource=/etc/passwd".to_string(),
                Signature::File,
            ),
            (
                "php://filter/read=convert.base64-encode/resource=/etc/passwd".to_string(),
                Signature::File,
            ),
            ("file:///etc/passwd".to_string(), Signature::File),
            (
                format!(
                    "data://text/plain;base64,{}",
                    b64_encode(format!("SLURP-{nonce}").as_bytes())
                ),
                Signature::Marker(format!("SLURP-{nonce}")),
            ),
        ],
        _ => vec![],
    }
}


fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    let normalized = input.replace('-', "+").replace('_', "/");
    b64_decode(&normalized)
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

fn query_value(request: &Value, name: &str) -> Option<String> {
    reqwest::Url::parse(request["url"].as_str()?)
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.to_string())
}

fn id_token_claims(body: &str) -> Option<Value> {
    let index = body.find("\"id_token\"")?;
    let rest = &body[index..];
    let colon = rest.find(':')?;
    let rest = &rest[colon + 1..];
    let start = rest.find('"')? + 1;
    let token = &rest[start..];
    let end = token.find('"')?;
    let payload = token[..end].split('.').nth(1)?;
    let decoded = b64url_decode(payload)?;
    serde_json::from_str(&String::from_utf8_lossy(&decoded)).ok()
}

fn oauth_request(request: &Value) -> Option<(String, String)> {
    let url = reqwest::Url::parse(request["url"].as_str()?).ok()?;
    let client = url
        .query_pairs()
        .find(|(key, _)| key == "client_id")
        .map(|(_, value)| value.to_string());
    let redirect = url
        .query_pairs()
        .find(|(key, _)| key == "redirect_uri")
        .map(|(_, value)| value.to_string());
    let path = url.path().to_ascii_lowercase();
    let looks_like_authorize = path.contains("authorize");
    client?;
    let redirect = redirect?;
    if !looks_like_authorize
        && !url.query_pairs().any(|(key, _)| key == "response_type")
    {
        return None;
    }
    Some((redirect, path))
}

async fn oauth_evidence<S: Sender>(
    sender: &S,
    request: &Value,
    label: &str,
    nonce: &str,
    evidence: &mut Vec<Value>,
    sent: &mut usize,
) -> Result<Value> {
    let result = sender.send(request, 15000).await?;
    *sent += 1;
    evidence.push(sent_evidence(
        &format!("oauth-{nonce}-{}", label.replace(' ', "-")),
        &format!("OAuth {label}"),
        request,
        &result,
    ));
    Ok(result)
}

async fn oauth_probes<S: Sender>(
    sender: &S,
    request: &Value,
    nonce: &str,
    baseline_body: &str,
    evidence: &mut Vec<Value>,
    sent: &mut usize,
    max_requests: usize,
) -> Result<(Vec<Value>, bool)> {
    let Some((original_redirect, _)) = oauth_request(request) else {
        return Ok((vec![], true));
    };
    let authorize = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())?;
    let attacker = format!("slurp-{}.invalid", nonce.to_ascii_lowercase());
    let target_host = reqwest::Url::parse(&original_redirect)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
        .unwrap_or_default();
    let marker = format!("slurp-{nonce}");
    let mut findings = vec![];
    let mut incomplete = false;
    let redirect_request = |value: &str| upsert_query(request, "redirect_uri", value);

    let direct_value = format!("https://{attacker}/callback");
    if *sent + 2 > max_requests {
        return Ok((findings, true));
    }
    let direct = oauth_evidence(
        sender,
        &redirect_request(&direct_value)?,
        "redirect attacker origin",
        nonce,
        evidence,
        sent,
    )
    .await?;
    let direct_repeat = oauth_evidence(
        sender,
        &redirect_request(&direct_value)?,
        "redirect attacker origin repeat",
        nonce,
        evidence,
        sent,
    )
    .await?;
    let accepted = |result: &Value| {
        location_host(result, authorize.as_str()).is_some_and(|host| {
            host == attacker || host.ends_with(&format!(".{attacker}"))
        })
    };
    if accepted(&direct) && accepted(&direct_repeat) {
        findings.push(finding(
            "oauth-redirect",
            "redirect-attacker-origin",
            "redirect_uri accepts an attacker-controlled origin",
            "The authorization endpoint redirected to an origin the captured client does not own, twice and with the same destination. If the server issues codes or tokens to that redirect_uri, an attacker can receive them; no code or token was used by this check.",
            &[
                "observed",
                "baseline-1",
                &format!("oauth-{nonce}-redirect-attacker-origin"),
                &format!("oauth-{nonce}-redirect-attacker-origin-repeat"),
            ],
            vec![
                format!("redirect_uri: {direct_value}"),
                "Location host matched the attacker origin twice".into(),
            ],
            "high",
            "high",
            "repeated redirect to an attacker origin with a fresh baseline",
        ));
    } else {
        let variants = [
            (
                "userinfo prefix",
                format!("https://{target_host}@{attacker}/callback"),
            ),
            (
                "host suffix",
                format!("https://{target_host}.{attacker}/callback"),
            ),
            (
                "encoded userinfo",
                format!("https://{target_host}%40{attacker}/callback"),
            ),
            (
                "port userinfo",
                format!("https://{target_host}:443@{attacker}/callback"),
            ),
            ("protocol-relative", format!("//{attacker}/callback")),
        ];
        for (label, value) in variants {
            if *sent + 2 > max_requests {
                incomplete = true;
                break;
            }
            let candidate = oauth_evidence(
                sender,
                &redirect_request(&value)?,
                label,
                nonce,
                evidence,
                sent,
            )
            .await?;
            if !accepted(&candidate) {
                continue;
            }
            let repeat = oauth_evidence(
                sender,
                &redirect_request(&value)?,
                &format!("{label} repeat"),
                nonce,
                evidence,
                sent,
            )
            .await?;
            if !accepted(&repeat) {
                continue;
            }
            findings.push(finding(
                "oauth-redirect",
                &format!("redirect-{}", label.replace(' ', "-")),
                &format!("redirect_uri bypass accepted: {label}"),
                "The authorization endpoint rejected a plain attacker origin but redirected to the attacker host for a crafted redirect_uri that contains the legitimate host, twice and with the same destination. This indicates prefix or suffix validation instead of exact allowlisting; no code or token was used by this check.",
                &["observed", "baseline-1"],
                vec![
                    format!("redirect_uri: {value}"),
                    format!("Resolved Location host: {attacker}"),
                ],
                "high",
                "high",
                "repeated redirect to an attacker host using a validator bypass",
            ));
            break;
        }
    }

    if query_value(request, "state").is_none() {
        findings.push(finding(
            "oauth-redirect",
            "missing-state",
            "OAuth authorize request omits state",
            "The captured authorization request has no state parameter. Without state the authorization response is not bound to the initiating session, which enables login CSRF and makes mix-up attacks easier when more than one identity provider is trusted. Server-side enforcement cannot be proven without a second identity provider.",
            &["observed", "baseline-1"],
            vec!["No state parameter in the authorize request".into()],
            "low",
            "high",
            "captured authorize request inspection",
        ));
    }
    let response_type = query_value(request, "response_type").unwrap_or_default();
    if query_value(request, "nonce").is_none() && response_type.contains("token") {
        findings.push(finding(
            "oauth-redirect",
            "missing-nonce",
            "OAuth authorize request omits nonce",
            "The request can return tokens but carries no nonce. Missing nonce weakens ID-token replay and mix-up defenses; confirm whether the client validates the ID token in another way.",
            &["observed", "baseline-1"],
            vec![format!("response_type: {response_type}")],
            "low",
            "high",
            "captured authorize request inspection",
        ));
    }

    let injected = format!("\"><{marker}>");
    let form_request = upsert_query(
        &upsert_query(request, "response_mode", "form_post")?,
        "state",
        &injected,
    )?;
    if *sent + 2 <= max_requests {
        let first = oauth_evidence(sender, &form_request, "form_post injection", nonce, evidence, sent).await?;
        let repeat = oauth_evidence(
            sender,
            &form_request,
            "form_post injection repeat",
            nonce,
            evidence,
            sent,
        )
        .await?;
        let body = first["responseBody"].as_str().unwrap_or_default();
        let body_repeat = repeat["responseBody"].as_str().unwrap_or_default();
        if first["ok"] == true
            && repeat["ok"] == true
            && body.contains(&format!("<{marker}>"))
            && body_repeat.contains(&format!("<{marker}>"))
            && body.to_ascii_lowercase().contains("<form")
        {
            findings.push(finding(
                "oauth-redirect",
                "form-post-injection",
                "OAuth form_post response reflects unescaped state",
                "With response_mode=form_post, an injected state value appeared as a raw tag in a form response twice. A raw tag in an auto-submitting form page can execute script in the identity-provider origin, where authorization codes are processed. No script was executed by this check.",
                &[
                    "observed",
                    "baseline-1",
                    &format!("oauth-{nonce}-form_post-injection"),
                    &format!("oauth-{nonce}-form_post-injection-repeat"),
                ],
                vec![
                    format!("Injected marker: <{marker}>"),
                    "Raw tag present in a form_post HTML response twice".into(),
                ],
                "medium",
                "high",
                "repeated unescaped reflection in a form_post response",
            ));
        }
    } else {
        incomplete = true;
    }

    let callback_host = reqwest::Url::parse(&original_redirect)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
        .unwrap_or_default();
    if !callback_host.is_empty()
        && callback_host != authorize.host_str().unwrap_or_default()
        && *sent + 1 <= max_requests
    {
        let callback = json!({
            "method": "GET",
            "url": format!("https://{callback_host}/"),
            "headers": {"accept": "text/html"},
            "body": ""
        });
        let result = oauth_evidence(sender, &callback, "callback host fingerprint", nonce, evidence, sent).await?;
        let body = result["responseBody"].as_str().unwrap_or_default();
        let fingerprints = [
            "NoSuchBucket",
            "There isn't a GitHub Pages site here",
            "This domain is not configured",
            "no such app",
            "Fastly error: unknown domain",
            "The specified bucket does not exist",
            "Repository not found",
            "Site not found",
        ];
        if let Some(fingerprint) = fingerprints.iter().find(|value| body.contains(**value)) {
            findings.push(finding(
                "oauth-redirect",
                "callback-unclaimed",
                "OAuth callback host appears unclaimed",
                "The registered callback host returned a provider placeholder page. If that host can be claimed, authorization codes or tokens sent to it can be intercepted. Confirm the DNS and ownership state before reporting.",
                &["observed", "baseline-1", &format!("oauth-{nonce}-callback-host-fingerprint")],
                vec![
                    format!("Callback host: {callback_host}"),
                    format!("Fingerprint: {fingerprint}"),
                ],
                "medium",
                "medium",
                "provider placeholder fingerprint on the registered callback host",
            ));
        }
    }

    if let Some(claims) = id_token_claims(baseline_body) {
        let email = claims["email"].as_str();
        let verified = claims["email_verified"] == json!(true) || claims["email_verified"] == json!("true");
        if email.is_some() && !verified {
            findings.push(finding(
                "oauth-redirect",
                "unverified-email",
                "ID token carries an unverified email",
                "The captured ID token contains an email address without email_verified=true. An application that links accounts by email could let an attacker register the victim address first and inherit the account after SSO (pre-account takeover). The check did not attempt any registration.",
                &["observed", "baseline-1"],
                vec![format!(
                    "Email claim present; email_verified={}",
                    claims["email_verified"]
                )],
                "medium",
                "medium",
                "captured ID-token claim inspection",
            ));
        }
    }

    Ok((findings, incomplete))
}

pub async fn run_active<S: Sender>(
    id: &str,
    entry: &Value,
    requested: &[String],
    wanted: Option<&str>,
    max_requests: usize,
    sender: &S,
) -> Result<Value> {
    let checks = select_checks(requested, ACTIVE_CHECKS, "active")?;
    let request = entry_request(entry)?;
    let needs_target = checks.iter().any(|check| check != "oauth-redirect");
    let target = if needs_target {
        Some(select_target(&request, wanted)?)
    } else {
        None
    };
    let nonce = format!("{}", chrono::Utc::now().timestamp_millis());
    let mut evidence = vec![observed(entry, &request)];
    let mut sent = 0usize;
    let baseline = sender.send(&request, 15000).await?;
    sent += 1;
    evidence.push(sent_evidence("baseline-1", "Fresh baseline", &request, &baseline));
    if baseline["ok"] != true {
        return Err(anyhow!("baseline request failed: {}", baseline["error"]));
    }
    let baseline_body = baseline["responseBody"].as_str().unwrap_or_default().to_string();
    let mut findings = vec![];
    let mut results = vec![];
    for check in &checks {
        if check == "oauth-redirect" {
            let (items, oauth_incomplete) = oauth_probes(
                sender,
                &request,
                &nonce,
                &baseline_body,
                &mut evidence,
                &mut sent,
                max_requests,
            )
            .await?;
            if !items.is_empty() {
                results.push(check_result(
                    check,
                    "findings",
                    "OAuth redirect_uri, state/nonce, form_post or callback controls produced findings.",
                    &items,
                ));
                findings.extend(items);
            } else if oauth_incomplete {
                results.push(check_result(
                    check,
                    "inconclusive",
                    "A captured OAuth authorize request was not available, or the request budget was reached.",
                    &[],
                ));
            } else {
                results.push(check_result(
                    check,
                    "passed",
                    "No attacker redirect, bypass, form_post injection or callback fingerprint was reproduced.",
                    &[],
                ));
            }
            continue;
        }
        let target = target
            .as_ref()
            .ok_or_else(|| anyhow!("a parameter target is required for {check}"))?;
        let candidates = payloads(check, &nonce);
        let mut check_findings = vec![];
        let mut incomplete = false;
        for (index, (payload, signature)) in candidates.iter().enumerate() {
            if detected(&baseline_body, signature) {
                incomplete = true;
                break;
            }
            if sent + 3 > max_requests {
                incomplete = true;
                break;
            }
            let candidate_request = mutate(&request, &target, payload)?;
            let candidate_id = format!("{check}-{index}");
            let candidate = sender.send(&candidate_request, 15000).await?;
            sent += 1;
            evidence.push(sent_evidence(
                &format!("{candidate_id}-probe"),
                &format!("{check} probe"),
                &candidate_request,
                &candidate,
            ));
            let repeat = sender.send(&candidate_request, 15000).await?;
            sent += 1;
            evidence.push(sent_evidence(
                &format!("{candidate_id}-repeat"),
                &format!("{check} repeat"),
                &candidate_request,
                &repeat,
            ));
            let control_request = mutate(&request, &target, &format!("slurp-missing-{nonce}"))?;
            let control = sender.send(&control_request, 15000).await?;
            sent += 1;
            evidence.push(sent_evidence(
                &format!("{candidate_id}-control"),
                &format!("{check} missing-value control"),
                &control_request,
                &control,
            ));
            let candidate_body = candidate["responseBody"].as_str().unwrap_or_default();
            let repeat_body = repeat["responseBody"].as_str().unwrap_or_default();
            let control_body = control["responseBody"].as_str().unwrap_or_default();
            if candidate["ok"] != true || repeat["ok"] != true || control["ok"] != true {
                incomplete = true;
                continue;
            }
            if detected(candidate_body, signature)
                && detected(repeat_body, signature)
                && !detected(control_body, signature)
                && !detected(&baseline_body, signature)
            {
                let (title, summary, severity) = match check.as_str() {
                    "command-injection" => (
                        "Possible OS command injection",
                        "A repeated payload produced operating-system command output that was absent from the baseline and a same-value missing-command control. This indicates command execution through the selected input; confirm the executed identity and permissions before reporting impact.",
                        "high",
                    ),
                    "path-traversal" => (
                        "Possible path traversal: system-file signature returned",
                        "Repeated traversal values returned recognizable system-file content absent from baselines and a missing-file control. Confirm the file source and intended permissions.",
                        "high",
                    ),
                    _ => (
                        "Possible local/remote file inclusion",
                        "Repeated inclusion values returned system-file content, a decodable base64 copy, or the decoded data-wrapper marker, while baselines and a missing-resource control did not. Confirm which resource was included and whether the parameter is meant to accept a path or URL.",
                        "high",
                    ),
                };
                let item = finding(
                    check,
                    &candidate_id,
                    title,
                    summary,
                    &[
                        "observed",
                        "baseline-1",
                        &format!("{candidate_id}-probe"),
                        &format!("{candidate_id}-repeat"),
                        &format!("{candidate_id}-control"),
                    ],
                    vec![
                        format!("Payload: {payload}"),
                        format!("Location: {target:?}"),
                        "System/command signature reproduced twice; missing-value control clean".into(),
                    ],
                    severity,
                    "high",
                    "repeated differential payload with a same-value control and fresh baseline",
                );
                check_findings.push(item);
            }
        }
        if !check_findings.is_empty() {
            results.push(check_result(
                check,
                "findings",
                "Controlled differential signature reproduced for at least one payload.",
                &check_findings,
            ));
            findings.extend(check_findings);
        } else if incomplete {
            results.push(check_result(
                check,
                "inconclusive",
                "Baseline already matched the signature, evidence was incomplete, or the request budget was reached.",
                &[],
            ));
        } else {
            results.push(check_result(
                check,
                "passed",
                "No controlled command, traversal or inclusion signature was reproduced.",
                &[],
            ));
        }
    }
    if sent + 1 <= max_requests {
        let restore = sender.send(&request, 15000).await?;
        sent += 1;
        evidence.push(sent_evidence("restore-1", "Original request restore", &request, &restore));
    }
    Ok(finish(RunParts {
        id: id.to_string(),
        started: now(),
        mode: "active",
        request,
        evidence,
        findings,
        checks: results,
        sent,
        max_requests,
        baseline_ids: vec!["observed".into(), "baseline-1".into()],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(response_body: &str, response_headers: Value) -> Value {
        json!({
            "id": "entry-1",
            "method": "GET",
            "url": "https://example.test/api?q=test",
            "request_headers": "{}",
            "request_body": [],
            "status_code": 200,
            "response_headers": response_headers.to_string(),
            "response_body": response_body.as_bytes().iter().map(|byte| json!(byte)).collect::<Vec<_>>(),
            "response_size": response_body.len(),
            "duration_ms": 5
        })
    }

    #[test]
    fn passive_findings_validate_and_send_nothing() {
        let entry = entry(
            "<html>Traceback (most recent call last): boom</html>",
            json!({"content-type": ["text/html"]}),
        );
        let run = run_passive("mcp-passive-test", &entry, &[]).unwrap();
        web_server::scan::validate_run("mcp-passive-test", &run).unwrap();
        assert_eq!(run["sent"], 0);
        assert_eq!(run["plan"]["mode"], "passive");
        assert_eq!(run["plan"]["allowSending"], false);
        let checks = run["checks"].as_array().unwrap();
        assert!(checks.iter().any(|check| check["checkId"] == "error-disclosure" && check["status"] == "findings"));
        assert!(checks.iter().any(|check| check["checkId"] == "security-headers" && check["status"] == "findings"));
    }

    struct Fake {
        uid: bool,
    }
    impl Sender for Fake {
        async fn send(&self, request: &Value, _timeout: u64) -> Result<Value> {
            let url = request["url"].as_str().unwrap_or_default();
            let body = if self.uid && url.contains("id") {
                "uid=33(www-data) gid=33(www-data)"
            } else {
                "ok"
            };
            Ok(json!({
                "ok": true,
                "status": 200,
                "responseHeaders": {"content-type": "text/plain"},
                "responseBody": body,
                "duration": 1,
                "size": body.len(),
            }))
        }
    }

    #[tokio::test]
    async fn active_command_injection_validates_with_a_control() {
        let entry = entry("ok", json!({"content-type": ["text/plain"]}));
        let run = run_active(
            "mcp-active-test",
            &entry,
            &["command-injection".to_string()],
            Some("q"),
            40,
            &Fake { uid: true },
        )
        .await
        .unwrap();
        web_server::scan::validate_run("mcp-active-test", &run).unwrap();
        assert_eq!(run["plan"]["mode"], "active");
        assert_eq!(run["plan"]["allowSending"], true);
        assert_eq!(run["findings"].as_array().unwrap().len(), 4);
        assert!(run["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["checkId"] == "command-injection"
                && finding["severity"] == "high"
                && finding["evidenceIds"].as_array().unwrap().len() >= 4));
        assert_eq!(run["checks"][0]["status"], "findings");
    }

    #[tokio::test]
    async fn active_run_without_signatures_passes() {
        let entry = entry("ok", json!({"content-type": ["text/plain"]}));
        let run = run_active(
            "mcp-active-clean",
            &entry,
            &["command-injection".to_string()],
            Some("q"),
            40,
            &Fake { uid: false },
        )
        .await
        .unwrap();
        web_server::scan::validate_run("mcp-active-clean", &run).unwrap();
        assert!(run["findings"].as_array().unwrap().is_empty());
        assert_eq!(run["checks"][0]["status"], "passed");
    }

    #[test]
    fn mutation_preserves_other_query_segments_and_duplicate_occurrences() {
        let request = json!({
            "method": "GET",
            "url": "https://example.test/api?sig=a%2Fb&q=one&q=two#frag",
            "headers": {},
            "body": ""
        });
        let target = Target::Query {
            name: "q".into(),
            occurrence: 1,
        };
        let mutated = mutate(&request, &target, "../../etc/passwd").unwrap();
        assert_eq!(
            mutated["url"],
            "https://example.test/api?sig=a%2Fb&q=one&q=../../etc/passwd#frag"
        );
        assert_eq!(request["url"], "https://example.test/api?sig=a%2Fb&q=one&q=two#frag");
    }

    #[test]
    fn build_inclusion_payloads_keep_the_marker_encoded() {
        let payloads = payloads("file-inclusion", "abc123");
        let (value, signature) = payloads.last().unwrap();
        assert!(value.starts_with("data://text/plain;base64,"));
        assert!(!value.contains("SLURP-abc123"));
        match signature {
            Signature::Marker(marker) => assert_eq!(marker, "SLURP-abc123"),
            _ => panic!("expected a marker signature"),
        }
        let decoded = b64_decode(value.trim_start_matches("data://text/plain;base64,")).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "SLURP-abc123");
    }

    #[test]
    fn selects_query_form_and_json_targets_in_order() {
        let query = json!({"method": "GET", "url": "https://x.test/a?first=1&b=2", "headers": {}, "body": ""});
        assert!(matches!(select_target(&query, None).unwrap(), Target::Query { name, .. } if name == "first"));
        let form = json!({
            "method": "POST",
            "url": "https://x.test/a",
            "headers": {"content-type": "application/x-www-form-urlencoded"},
            "body": "a=1&b=2"
        });
        assert!(matches!(select_target(&form, Some("body.b")).unwrap(), Target::Form { name, .. } if name == "b"));
        let json_body = json!({
            "method": "POST",
            "url": "https://x.test/a",
            "headers": {"content-type": "application/json"},
            "body": "{\"name\":\"a\",\"count\":1}"
        });
        assert!(matches!(select_target(&json_body, None).unwrap(), Target::Json { field } if field == "name"));
        let mutated = mutate(&json_body, &Target::Json { field: "name".into() }, "x").unwrap();
        assert_eq!(mutated["body"], "{\"count\":1,\"name\":\"x\"}");
    }

    struct OAuthFake {
        strict: bool,
    }
    impl Sender for OAuthFake {
        async fn send(&self, request: &Value, _timeout: u64) -> Result<Value> {
            let url = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())?;
            if url.host_str() == Some("app.test") {
                let body = if self.strict { "app" } else { "NoSuchBucket" };
                return Ok(json!({"ok":true,"status":200,"responseHeaders":{},"responseBody":body,"duration":1,"size":body.len()}));
            }
            if url
                .query_pairs()
                .any(|(key, value)| key == "response_mode" && value == "form_post")
            {
                let state = url
                    .query_pairs()
                    .find(|(key, _)| key == "state")
                    .map(|(_, value)| value.to_string())
                    .unwrap_or_default();
                let body = if self.strict {
                    format!("<form method=\"post\"><input value=\"{}\"></form>", state.replace('<', "&lt;").replace('>', "&gt;"))
                } else {
                    format!("<form method=\"post\"><input value=\"{state}\"></form>")
                };
                return Ok(json!({"ok":true,"status":200,"responseHeaders":{"content-type":"text/html"},"responseBody":body,"duration":1,"size":body.len()}));
            }
            let redirect = url
                .query_pairs()
                .find(|(key, _)| key == "redirect_uri")
                .map(|(_, value)| value.to_string())
                .unwrap_or_default();
            let host = reqwest::Url::parse(&redirect)
                .ok()
                .and_then(|url| url.host_str().map(str::to_string))
                .unwrap_or_default();
            let attacker = host.ends_with(".invalid");
            if attacker && self.strict {
                return Ok(json!({"ok":true,"status":400,"responseHeaders":{},"responseBody":"invalid","duration":1,"size":7}));
            }
            let location = if attacker {
                redirect
            } else {
                "https://app.test/cb?code=x".to_string()
            };
            Ok(json!({"ok":true,"status":302,"responseHeaders":{"location":location},"responseBody":"","duration":1,"size":0}))
        }
    }

    fn oauth_entry(url: &str) -> Value {
        json!({
            "id": "oauth-1",
            "method": "GET",
            "url": url,
            "request_headers": "{}",
            "request_body": [],
            "status_code": 302,
            "response_headers": "{\"location\":[\"https://app.test/cb?code=x\"]}",
            "response_body": [],
            "response_size": 0,
            "duration_ms": 5
        })
    }

    #[tokio::test]
    async fn oauth_scans_redirect_bypass_state_and_callback() {
        let entry = oauth_entry("https://idp.test/oauth/authorize?client_id=app&response_type=code&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&state=xyz&nonce=n1");
        let run = run_active(
            "mcp-oauth-test",
            &entry,
            &["oauth-redirect".to_string()],
            None,
            40,
            &OAuthFake { strict: false },
        )
        .await
        .unwrap();
        web_server::scan::validate_run("mcp-oauth-test", &run).unwrap();
        let findings = run["findings"].as_array().unwrap();
        assert!(findings.iter().any(|finding| finding["id"] == "redirect-attacker-origin"));
        assert!(findings.iter().any(|finding| finding["id"] == "callback-unclaimed"));
        assert!(findings.iter().any(|finding| finding["id"] == "form-post-injection"));
        assert_eq!(run["checks"][0]["checkId"], "oauth-redirect");
        assert_eq!(run["checks"][0]["status"], "findings");
    }

    #[tokio::test]
    async fn oauth_strict_server_passes_and_missing_state_is_reported() {
        let strict = run_active(
            "mcp-oauth-strict",
            &oauth_entry("https://idp.test/oauth/authorize?client_id=app&response_type=code&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&state=xyz&nonce=n1"),
            &["oauth-redirect".to_string()],
            None,
            40,
            &OAuthFake { strict: true },
        )
        .await
        .unwrap();
        web_server::scan::validate_run("mcp-oauth-strict", &strict).unwrap();
        assert!(strict["findings"].as_array().unwrap().is_empty());
        assert_eq!(strict["checks"][0]["status"], "passed");

        let missing = run_active(
            "mcp-oauth-state",
            &oauth_entry("https://idp.test/oauth/authorize?client_id=app&response_type=code&redirect_uri=https%3A%2F%2Fapp.test%2Fcb"),
            &["oauth-redirect".to_string()],
            None,
            40,
            &OAuthFake { strict: true },
        )
        .await
        .unwrap();
        web_server::scan::validate_run("mcp-oauth-state", &missing).unwrap();
        assert!(missing["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "missing-state"));
    }

    #[test]
    fn signatures_require_structure() {
        assert!(uid_signature("uid=1000(user) gid=1000(user)"));
        assert!(!uid_signature("uid=abc"));
        assert!(detected("base64 " , &Signature::File) == false);
        assert!(file_signature("root:x:0:0:root:/root:/bin/bash"));
        assert!(!file_signature("<html>root directory</html>"));
        let encoded = b64_encode(b"root:x:0:0:root:/root:/bin/bash");
        assert!(file_signature(&format!("<pre>{encoded}</pre>")));
    }
}
