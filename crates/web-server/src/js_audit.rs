//! Passive, bounded JavaScript literal analysis. No JavaScript execution or URL fetching.
//! Design references: PortSwigger/js-link-finder and PortSwigger/js-miner.
//! This is an independent Rust implementation; no upstream source is embedded.
use crate::auto_audit::{finding, headers, observed, request, run};
use proxy_core::TrafficEntry;
use serde_json::{json, Value};
use std::collections::HashSet;

pub fn is_javascript(entry: &TrafficEntry) -> bool {
    let mime = entry
        .response_content_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = entry
        .path
        .split('?')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    (200..300).contains(&entry.status_code)
        && (mime.contains("javascript")
            || mime.contains("ecmascript")
            || path.ends_with(".js")
            || path.ends_with(".mjs")
            || path.ends_with(".cjs"))
}
struct Literal {
    start: usize,
    end: usize,
    value: String,
}
// A small lexical scanner handles escaped quotes, slash/unicode escapes, comments and
// template literals. Expressions inside templates stay literal and are never evaluated.
fn literals(source: &str) -> (Vec<Literal>, bool) {
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut out = vec![];
    let mut limited = false;
    while i < bytes.len() && out.len() < 20000 {
        if bytes.get(i..i + 2) == Some(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes.get(i..i + 2) == Some(b"/*") {
            i += 2;
            while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // Regex literals can contain quotes and comment-like text. Skip their
        // contents so they cannot desynchronize subsequent string extraction.
        if bytes[i] == b'/' {
            let before = source[..i].trim_end();
            let regex_context = before.is_empty()
                || before.ends_with(['(', '[', '{', '=', ':', ',', ';', '!', '?', '&', '|'])
                || before
                    .split_whitespace()
                    .last()
                    .is_some_and(|w| matches!(w, "return" | "throw" | "case" | "yield"));
            if regex_context {
                let mut j = i + 1;
                let mut class = false;
                let mut closed = false;
                while j < bytes.len() && ![b'\n', b'\r'].contains(&bytes[j]) {
                    match bytes[j] {
                        b'\\' => {
                            j = (j + 2).min(bytes.len());
                            continue;
                        }
                        b'[' => class = true,
                        b']' => class = false,
                        b'/' if !class => {
                            j += 1;
                            closed = true;
                            break;
                        }
                        _ => {}
                    }
                    j += 1;
                }
                if closed {
                    while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                        j += 1;
                    }
                    i = j;
                    continue;
                }
            }
        }
        let quote = bytes[i];
        if ![b'\'', b'"', b'`'].contains(&quote) {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        let mut value = Vec::new();
        let mut closed = false;
        while i < bytes.len() {
            if bytes[i] == quote {
                i += 1;
                closed = true;
                break;
            }
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 1;
                let escaped = bytes[i];
                if [b'u', b'x'].contains(&escaped) {
                    let width = if escaped == b'u' { 4 } else { 2 };
                    if let Some(hex) = bytes
                        .get(i + 1..i + 1 + width)
                        .and_then(|s| std::str::from_utf8(s).ok())
                    {
                        if let Some(ch) = u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                        {
                            let mut encoded = [0; 4];
                            value.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
                            i += width + 1;
                            continue;
                        }
                    }
                }
                value.push(match escaped {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    other => other,
                });
                i += 1;
            } else {
                value.push(bytes[i]);
                i += 1;
            }
            // Keep scanning to the closing quote, but never retain huge literals.
            if value.len() >= 8192 {
                limited = true;
                value.truncate(8192);
            }
        }
        if closed && !value.is_empty() && value.len() < 8192 {
            out.push(Literal {
                start,
                end: i,
                value: String::from_utf8_lossy(&value).into_owned(),
            });
        }
    }
    (out, limited || i < bytes.len())
}
fn prefix(source: &str, start: usize) -> String {
    source[..start]
        .chars()
        .rev()
        .take(160)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}
fn assignment(prefix: &str) -> String {
    let before = prefix.trim_end();
    let Some(before) = before
        .strip_suffix('=')
        .or_else(|| before.strip_suffix(':'))
    else {
        return String::new();
    };
    let before = before.trim_end();
    let key = if before.ends_with(['\'', '"']) {
        let quote = before.chars().last().unwrap();
        let rest = &before[..before.len() - 1];
        rest.rsplit(quote).next().unwrap_or("")
    } else {
        before
            .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .next()
            .unwrap_or("")
    };
    key.to_ascii_lowercase().replace(['_', '-'], "")
}
fn method(prefix: &str, tail: &str) -> Option<&'static str> {
    let lower = prefix.to_ascii_lowercase();
    for (name, method) in [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("patch", "PATCH"),
        ("delete", "DELETE"),
        ("head", "HEAD"),
        ("options", "OPTIONS"),
    ] {
        if lower.trim_end().ends_with(&format!(".{name}(")) {
            return Some(method);
        }
    }
    let fetch = lower.trim_end().ends_with("fetch(");
    if fetch || assignment(prefix) == "url" {
        let tail = tail
            .chars()
            .take(200)
            .collect::<String>()
            .to_ascii_lowercase();
        if let Some(index) = tail.find("method") {
            let value = tail[index + 6..].trim_start_matches(['\'', '"', ':', ' ', '\n']);
            for (name, method) in [
                ("get", "GET"),
                ("post", "POST"),
                ("put", "PUT"),
                ("patch", "PATCH"),
                ("delete", "DELETE"),
                ("head", "HEAD"),
                ("options", "OPTIONS"),
            ] {
                if value.starts_with(name) {
                    return Some(method);
                }
            }
        }
        if fetch {
            return Some("GET");
        }
    }
    if lower.contains(".open(") {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            if prefix.contains(&format!("\"{method}\"")) || prefix.contains(&format!("'{method}'"))
            {
                return Some(method);
            }
        }
    }
    None
}
fn endpoint(value: &str, prefix: &str) -> bool {
    if value.len() > 4096 || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let path = value
        .split('?')
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase();
    if [
        ".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2", ".map", ".ico",
    ]
    .iter()
    .any(|s| path.ends_with(s))
    {
        return false;
    }
    let network =
        value.starts_with("https://") || value.starts_with("http://") || value.starts_with("//");
    let relative = value.starts_with('/') || value.starts_with("./") || value.starts_with("../");
    let call = prefix.to_ascii_lowercase();
    network
        || relative && value.len() > 1
        || call.trim_end().ends_with("fetch(")
        || [".get(", ".post(", ".put(", ".patch(", ".delete("]
            .iter()
            .any(|s| call.trim_end().ends_with(s))
}
fn placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.len() < 3
        || value.contains("${")
        || value.starts_with('<')
        || value.chars().all(|c| c == '*')
        || [
            "password",
            "username",
            "token",
            "secret",
            "null",
            "undefined",
            "changeme",
            "your_api_key",
            "your_token",
            "example",
            "true",
            "false",
        ]
        .contains(&lower.as_str())
        || ["your_", "replace_", "example_"]
            .iter()
            .any(|s| lower.starts_with(s))
}
fn secret_kind(key: &str, value: &str) -> Option<&'static str> {
    if placeholder(value) {
        return None;
    }
    if value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----") {
        return Some("Private key");
    }
    if value.starts_with("Bearer ") && value.len() > 20 {
        return Some("Bearer token");
    }
    if value.starts_with("Basic ") && value.len() > 12 {
        return Some("Basic authentication credential");
    }
    if value.starts_with("eyJ") && value.len() > 40 && value.split('.').count() == 3 {
        return Some("JWT token");
    }
    if [
        "ghp_",
        "gho_",
        "github_pat_",
        "sk_live_",
        "sk_test_",
        "AIza",
        "AKIA",
        "ASIA",
    ]
    .iter()
    .any(|s| value.starts_with(s))
        && value.len() >= 20
    {
        return Some("API key");
    }
    if ["username", "user", "login", "clientid"].contains(&key) {
        return Some("Username / account identifier");
    }
    if ["password", "passwd", "pwd", "pass"].contains(&key) {
        return Some("Password");
    }
    if key.contains("apikey") || key == "accesskeyid" {
        return Some("API key");
    }
    if key.contains("secret") {
        return Some("Secret");
    }
    if key.contains("token") || key == "authorization" {
        return Some("Token");
    }
    None
}
fn entropy(value: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in value.bytes() {
        counts[b as usize] += 1;
    }
    counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / value.len().max(1) as f64;
            -p * p.log2()
        })
        .sum()
}
fn redact(value: &str) -> String {
    if value.chars().count() < 12 {
        return "[REDACTED]".into();
    }
    format!("{}…[REDACTED]", value.chars().take(4).collect::<String>())
}
fn safe_url(value: &str, base: &reqwest::Url) -> String {
    let Ok(mut url) = base.join(value) else {
        return "Dynamic endpoint (see captured source)".into();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, value)| {
            let sensitive = secret_kind(
                &key.to_ascii_lowercase().replace(['_', '-'], ""),
                "private-credential-value",
            )
            .is_some();
            (
                key.into_owned(),
                if sensitive {
                    "[REDACTED]".into()
                } else {
                    value.into_owned()
                },
            )
        })
        .collect();
    if url.query().is_some() {
        url.set_query(None);
        url.query_pairs_mut().extend_pairs(pairs);
    }
    url.set_fragment(None);
    url.into()
}
pub fn scan(entry: &TrafficEntry, id: &str) -> Option<Value> {
    let request = request(entry)?;
    // A truncated/compressed/binary source never silently counts as a clean JS scan.
    let source = std::str::from_utf8(&entry.response_body).ok()?;
    let source = source.get(..source.floor_char_boundary(source.len().min(2_000_000)))?;
    let source_truncated = source.len() < entry.response_size as usize;
    let encoding = headers(&entry.response_headers)
        .get("content-encoding")
        .and_then(Value::as_str)
        .unwrap_or("identity")
        .to_string();
    if encoding != "identity" {
        return None;
    }
    let base = reqwest::Url::parse(&entry.url).ok()?;
    let lines: Vec<usize> = source.match_indices('\n').map(|(i, _)| i).collect();
    let mut found = vec![];
    let mut seen = HashSet::new();
    let (literals, literal_limit) = literals(source);
    for literal in literals {
        if found.len() >= 400 {
            break;
        }
        let prefix = prefix(source, literal.start);
        let key = assignment(&prefix);
        let line = lines.partition_point(|&i| i < literal.start);
        let column = literal.start - lines.get(line.wrapping_sub(1)).map_or(0, |v| v + 1) + 1;
        let location = format!(
            "Line {}, byte column {} (offset {})",
            line + 1,
            column,
            literal.start
        );
        if let Some(kind) = secret_kind(&key, &literal.value) {
            if !seen.insert(format!("secret:{kind}:{}", literal.value)) {
                continue;
            }
            let finding_id = format!("js-secret-{}", found.len());
            let severity = if kind == "Username / account identifier" {
                "info"
            } else {
                "medium"
            };
            let mut value=finding("js-secrets",&finding_id,&format!("JavaScript: suspected {kind}"),
                format!("A credential-like literal was found in the captured JavaScript. It may be public configuration, a test value or an expired credential; validity was not tested. Source History ID: {}.",entry.id),vec!["observed"],
                vec![format!("Source: {}",safe_url(&entry.url,&base)),location,format!("{} = {}",if key.is_empty(){kind}else{&key},redact(&literal.value)),format!("Shannon entropy: {:.2} bits/byte",entropy(&literal.value))],severity);
            value["fingerprint"] = json!(format!("js-secret-v2:{kind}:{:?}", ring::digest::digest(&ring::digest::SHA256, literal.value.as_bytes())));
            value["status"] = json!("suspected");
            value["confidence"] = json!(if entropy(&literal.value) >= 3.5
                && literal.value.len() >= 20
            {
                "medium"
            } else {
                "low"
            });
            value["remediation"]=json!("Review whether the value is sensitive; remove private credentials from client code and rotate exposed secrets. Public client identifiers may be intentional.");
            found.push(value);
        } else if endpoint(&literal.value, &prefix) {
            let method = method(&prefix, &source[literal.end..]);
            let endpoint = safe_url(&literal.value, &base);
            if !seen.insert(format!("endpoint:{method:?}:{endpoint}")) {
                continue;
            }
            let finding_id = format!("js-endpoint-{}", found.len());
            let mut value=finding("js-endpoints",&finding_id,"JavaScript: API / endpoint discovered",
                format!("An endpoint-like literal was discovered without sending requests to it. Relative paths are resolved against the script URL as a candidate; application base URLs and dynamic expressions may change the actual destination. Source History ID: {}.",entry.id),
                vec!["observed"],vec![format!("Source: {}",safe_url(&entry.url,&base)),location,format!("Method: {}",method.unwrap_or("unknown")),format!("Endpoint candidate: {endpoint}")],"info");
            value["remediation"]=json!("Review the endpoint in the application's routing context and test only intended targets.");
            found.push(value);
        }
    }
    let limited = source_truncated || literal_limit || found.len() >= 400;
    let checks=["js-endpoints","js-secrets"].iter().map(|check| {
        let ids:Vec<_>=found.iter().filter(|f|f["checkId"]==*check).map(|f|f["id"].clone()).collect();
        json!({"checkId":check,"status":if !ids.is_empty(){"findings"}else if limited{"inconclusive"}else{"passed"},
            "message":if source_truncated {"Only the first 2 MB of source was analyzed"}else if found.len()>=400 {"Finding limit reached (400 per source)"}else if literal_limit {"Literal analysis limit reached; results are incomplete"}else{"Passive literal analysis; no source execution or discovered URL fetching"},"findingIds":ids})
    }).collect();
    Some(run(
        entry,
        id,
        &request,
        vec![observed(entry, &request)],
        found,
        checks,
        0,
        "passive",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn script(body: &str) -> TrafficEntry {
        let mut entry = TrafficEntry::new_request(
            "GET",
            "https://example.test/assets/app.js",
            "example.test",
            "/assets/app.js",
            "https",
            "{}",
            vec![],
            None,
        );
        entry.status_code = 200;
        entry.response_headers = "{}".into();
        entry.response_content_type = Some("application/javascript".into());
        entry.response_body = body.as_bytes().to_vec();
        entry.response_size = body.len() as u64;
        entry
    }
    #[test]
    fn workspace_dedup_keeps_only_new_endpoints_and_distinct_secrets() {
        let storage = proxy_core::TrafficStorage::new(":memory:", 1024).unwrap();
        let workspace = storage.create_workspace("JS audit").unwrap().id;
        let other = storage.create_workspace("Other audit").unwrap().id;
        let first = scan(&script(r#"fetch('/api/one'); const password='sameprefix-secret-one';"#), "first").unwrap();
        assert!(storage.put_unique_js_scan_run(&workspace, "first", &first).unwrap());
        let moved = scan(&script(r#"// source shifted
const password='sameprefix-secret-one'; fetch('/api/one');"#), "moved").unwrap();
        assert!(!storage.put_unique_js_scan_run(&workspace, "moved", &moved).unwrap());
        assert!(storage.get_scan_run(&workspace, "moved").unwrap().is_none());
        assert!(storage.put_unique_js_scan_run(&other, "moved", &moved).unwrap());
        let changed = scan(&script(r#"fetch('/api/one'); fetch('/api/two'); const password='sameprefix-secret-two';"#), "changed").unwrap();
        assert!(storage.put_unique_js_scan_run(&workspace, "changed", &changed).unwrap());
        let saved = storage.get_scan_run(&workspace, "changed").unwrap().unwrap();
        assert_eq!(saved["findings"].as_array().unwrap().len(), 2);
        assert!(saved["findings"].to_string().contains("/api/two"));
        assert!(!saved["findings"].to_string().contains("Endpoint candidate: https://example.test/api/one"));
        super::super::scan::validate_run("changed", &saved).unwrap();
        assert!(!storage.put_unique_js_scan_run(&workspace, "changed-again", &changed).unwrap());
    }
    #[test]
    fn legacy_endpoint_reports_and_restart_are_respected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit.db");
        let workspace;
        let next = scan(&script("fetch('/api/existing');"), "next").unwrap();
        {
            let storage = proxy_core::TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
            workspace = storage.create_workspace("Persisted JS").unwrap().id;
            let mut old = next.clone();
            old["id"] = json!("old");
            old["findings"][0]["fingerprint"] = json!("js-endpoints:js-endpoint-0");
            storage.put_scan_run(&workspace, "old", &old).unwrap();
        }
        let storage = proxy_core::TrafficStorage::new(path.to_str().unwrap(), 1024).unwrap();
        assert!(!storage.put_unique_js_scan_run(&workspace, "next", &next).unwrap());
    }
    #[test]
    fn discovers_fetch_axios_xhr_links_and_credentials_with_coordinates_and_redaction() {
        // Assemble a synthetic credential at runtime so the source contains no complete key.
        let api_key = ["sk", "live", &"a".repeat(26)].join("_");
        let source =
            r#"fetch('/api/me');
axios.post("/api/login", {});
xhr.open('PUT', '/api/profile');
const endpoint = "https:\/\/api.example.test\/v1\/orders";
const config={"username":"alice","password":"pa55-real-value","api_key":"__API_KEY_FIXTURE__","accessToken":"eyJabcdefghijk.eyJ1234567890abcdef.abcdef1234567890"};
const escaped = "\u002fapi\u002fescaped";
fetch(`/api/users/${userId}`);
const placeholder={apiKey:"YOUR_API_KEY",token:process.env.TOKEN};"#;
        let entry = script(&source.replace("__API_KEY_FIXTURE__", &api_key));
        let run = scan(&entry, "js-test").unwrap();
        crate::scan::validate_run("js-test", &run).unwrap();
        let findings = run["findings"].to_string();
        assert!(findings.contains("/api/me"));
        assert!(findings.contains("Method: POST"));
        assert!(findings.contains("Method: PUT"));
        assert!(findings.contains("/api/escaped"));
        assert!(findings.contains("Username / account identifier"));
        assert!(findings.contains("Password"));
        assert!(findings.contains("API key"));
        assert!(findings.contains("JWT token"));
        assert!(findings.contains("Line 5"));
        assert!(findings.contains("[REDACTED]"));
        assert!(!findings.contains("pa55-real-value"));
        assert!(!findings.contains(&api_key));
        assert!(!findings.contains("YOUR_API_KEY"));
        assert_eq!(run["sent"], 0);
    }
    #[test]
    fn ignores_comments_plain_labels_assets_and_duplicate_literals_and_bounds_large_source() {
        let entry = script(
            r#"// fetch('/api/comment')
/* const password="commented"; */
const words=['password','token','username','/assets/logo.png'];
fetch('/api/items');fetch('/api/items');"#,
        );
        let run = scan(&entry, "js-negative").unwrap();
        let findings = run["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0]["excerpts"].to_string().contains("/api/items"));
        let mut entry = script(&"a".repeat(2_000_001));
        entry.response_body.extend_from_slice(b"\xff");
        assert!(scan(&entry, "invalid").is_none());
        let entry = script(&"a".repeat(2_000_001));
        let run = scan(&entry, "limited").unwrap();
        assert_eq!(run["checks"][0]["status"], "inconclusive");
    }
    #[tokio::test]
    async fn automatically_saves_js_findings_in_temporary_memory_without_outbound_requests() {
        let directory = tempfile::tempdir().unwrap();
        let db = directory.path().join("audit.db");
        let storage = proxy_core::TrafficStorage::new(db.to_str().unwrap(), 3000000).unwrap();
        let intercept = proxy_core::Intercept::new(storage.clone());
        let (_state, _runtime) = crate::auto_audit::start(storage.clone(), intercept);
        let entry = script("const password='private-value';fetch('/api/private');");
        storage.insert(&entry).unwrap();
        let id = format!("auto-{}", entry.id);
        let run = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(run) = storage.get_scan_run("temporary", &id).unwrap() {
                    return run;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(run["sent"], 0);
        assert_eq!(
            storage
                .list_scan_findings("temporary", 0, "", "", "")
                .unwrap()
                .0,
            2
        );
        assert!(storage.list_scan_runs("default", 0).unwrap().is_empty());
        let reopened = proxy_core::TrafficStorage::new(db.to_str().unwrap(), 3000000).unwrap();
        assert!(reopened.list_scan_runs("temporary", 0).unwrap().is_empty());
    }
}

#[cfg(test)]
#[test]
fn regex_quotes_do_not_hide_subsequent_api_endpoints() {
    let source = r#"function escapeHtml(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    const regex = /['"/]/g;
    const ratio = total / count;
    fetch('/api/auth/login', { method: 'POST' });
    apiFetch('/api/wallet');"#;
    let mut entry = proxy_core::TrafficEntry::new_request(
        "GET",
        "http://localhost:8088/static/js/app.js",
        "localhost",
        "/static/js/app.js",
        "http",
        "{}",
        vec![],
        None,
    );
    entry.status_code = 200;
    entry.response_content_type = Some("text/javascript".into());
    entry.response_headers = "{}".into();
    entry.response_size = source.len() as u64;
    entry.response_body = source.as_bytes().to_vec();
    let result = scan(&entry, "regex-test").unwrap();
    crate::scan::validate_run("regex-test", &result).unwrap();
    let findings = result["findings"].to_string();
    assert!(findings.contains("/api/auth/login"));
    assert!(findings.contains("/api/wallet"));
}
