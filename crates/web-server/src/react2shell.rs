//! React2Shell (CVE-2025-55182): React Server Components deserialization.
//!
//! Two separate questions, answered separately:
//! 1. Is this a React Server Components deployment? Only strong evidence counts: a Flight response, an
//!    App Router page (`self.__next_f`), `Vary: RSC`, or an RSC request. A Pages Router app, a Vercel
//!    host or an `x-powered-by: Next.js` header is not evidence of RSC and is not audited.
//! 2. Is its version in the affected range? The Next.js version is read from the public client bundle
//!    (`window.next = { version }`) and compared with the vendor's patched releases. When the version
//!    cannot be read the result is "patch status unknown", never "vulnerable".
//!
//! Nothing here sends a Flight request, a Server Function payload or anything that reaches the
//! vulnerable deserializer: the audit only reads the captured response and fetches a few public
//! `/_next/static/*.js` files from the same origin, without cookies or credentials.
use super::auto_audit::{self as audit, AuditState};
use proxy_core::{Intercept, TrafficEntry};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use tokio::time::{sleep, Duration};

const ADVISORY_JSON: &str = include_str!("../data/react2shell-advisory.json");
const MAX_SCRIPTS: usize = 4;
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(15);

// ── Advisory data ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<String>,
}

impl Version {
    pub(super) fn parse(text: &str) -> Option<Self> {
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) if !pre.is_empty() => (core, Some(pre.to_string())),
            Some(_) => return None,
            None => (text, None),
        };
        let mut parts = core.split('.').map(|part| part.parse::<u64>().ok());
        let version = Self { major: parts.next()??, minor: parts.next()??, patch: parts.next()??, pre };
        parts.next().is_none().then_some(version)
    }
    fn branch(&self) -> (u64, u64) {
        (self.major, self.minor)
    }
    fn canary_number(&self) -> Option<u64> {
        self.pre.as_deref()?.strip_prefix("canary.")?.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        match &self.pre {
            Some(pre) => write!(f, "-{pre}"),
            None => Ok(()),
        }
    }
}

struct Advisory {
    cve: String,
    note: String,
    react_major: u64,
    react_patched: BTreeMap<(u64, u64), u64>,
    next_not_affected_below: u64,
    next_canary: BTreeMap<(u64, u64), u64>,
    next_patched: BTreeMap<(u64, u64), u64>,
}

fn branch_table(value: &Value) -> BTreeMap<(u64, u64), u64> {
    value
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(branch, fixed)| {
            let (major, minor) = branch.split_once('.')?;
            let fixed = Version::parse(fixed.as_str()?)?;
            Some(((major.parse().ok()?, minor.parse().ok()?), fixed.patch))
        })
        .collect()
}

fn advisory() -> &'static Advisory {
    static DATA: OnceLock<Advisory> = OnceLock::new();
    DATA.get_or_init(|| {
        let data: Value = serde_json::from_str(ADVISORY_JSON).expect("react2shell-advisory.json is valid JSON");
        Advisory {
            cve: data["cve"].as_str().unwrap_or("CVE-2025-55182").to_string(),
            note: data["note"].as_str().unwrap_or("").to_string(),
            react_major: data["react_server_dom"]["affected_major"].as_u64().unwrap_or(19),
            react_patched: branch_table(&data["react_server_dom"]["patched"]),
            next_not_affected_below: Version::parse(data["next"]["not_affected_below"].as_str().unwrap_or("15.0.0")).map_or(15, |v| v.major),
            next_canary: data["next"]["affected_canary"]
                .as_object()
                .into_iter()
                .flatten()
                .filter_map(|(branch, n)| {
                    let (major, minor) = branch.split_once('.')?;
                    Some(((major.parse().ok()?, minor.parse().ok()?), n.as_u64()?))
                })
                .collect(),
            next_patched: branch_table(&data["next"]["patched"]),
        }
    })
}

/// What a version means for this advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Verdict {
    /// In the affected range and below the patched release of its branch.
    Vulnerable { fixed: String },
    /// At or above the patched release of its branch.
    Patched { since: String },
    /// Outside the affected range (the reason is a short sentence).
    NotAffected(&'static str),
    /// A pre-release of an affected branch: the patch level cannot be decided from the version.
    Prerelease,
    Unknown,
}

fn assess(version: &Version, patched: &BTreeMap<(u64, u64), u64>) -> Verdict {
    if version.pre.is_some() {
        return Verdict::Prerelease;
    }
    match patched.get(&version.branch()) {
        Some(&fixed) if version.patch >= fixed => Verdict::Patched { since: format!("{}.{}.{fixed}", version.major, version.minor) },
        Some(&fixed) => Verdict::Vulnerable { fixed: format!("{}.{}.{fixed}", version.major, version.minor) },
        None => {
            let newest = patched.keys().filter(|(major, _)| *major == version.major).map(|(_, minor)| *minor).max();
            match newest {
                // A later minor of an affected major was released after the fix.
                Some(newest) if version.minor > newest => Verdict::Patched { since: "a release after the fixed versions".into() },
                None if patched.keys().any(|(major, _)| *major < version.major) => Verdict::Patched { since: "a release after the fixed versions".into() },
                _ => Verdict::Unknown,
            }
        }
    }
}

pub(super) fn assess_next(version: &Version) -> Verdict {
    let data = advisory();
    if version.major < data.next_not_affected_below {
        if let (Some(canary), Some(&first)) = (version.canary_number(), data.next_canary.get(&version.branch())) {
            if canary >= first {
                return Verdict::Prerelease;
            }
        }
        return Verdict::NotAffected("Next.js releases before 15 do not bundle the affected React Server Components build");
    }
    assess(version, &data.next_patched)
}

pub(super) fn assess_react(version: &Version) -> Verdict {
    let data = advisory();
    if version.major != data.react_major {
        return if version.major < data.react_major { Verdict::NotAffected("React before 19 has no affected Server Components packages") } else { Verdict::Patched { since: "a later major release".into() } };
    }
    assess(version, &data.react_patched)
}

// ── Evidence from the captured response ────────────────────────────────────────────────

/// One audit per origin: RSC support is a deployment property.
pub(super) fn key(request: &Value) -> String {
    let origin = reqwest::Url::parse(request["url"].as_str().unwrap_or_default())
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| request["url"].as_str().unwrap_or_default().to_string());
    let digest = ring::digest::digest(&ring::digest::SHA256, origin.as_bytes());
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("auto-react2shell-{hex}")
}

fn header_text(headers: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
    headers.get(name).and_then(Value::as_str).map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

fn is_rsc_type(content_type: &str) -> bool {
    content_type.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("text/x-component")
}

/// Flight rows are `<hex id>:<optional tag><JSON>`: `0:{"a":"$@1"}`, `1:I["chunk",...]`, `2:"$Sreact.suspense"`.
/// Plain text that merely starts with digits and a colon (`12:30 "Lunch"`) is not Flight.
pub(super) fn looks_like_flight(body: &str) -> bool {
    let line = body.trim_start().lines().next().unwrap_or("");
    let digits = line.chars().take_while(char::is_ascii_hexdigit).count();
    if digits == 0 || digits > 6 || line.chars().nth(digits) != Some(':') {
        return false;
    }
    let rest = &line[digits + 1..];
    let rest = rest.trim_start_matches(|c: char| c.is_ascii_uppercase()).trim();
    let tagged = rest.len() != line[digits + 1..].trim().len();
    serde_json::from_str::<Value>(rest).is_ok_and(|value| (value.is_array() || value.is_object() || value.is_string()) && (tagged || body.contains("\"$") || body.contains("$@") || body.contains("$L")))
}

/// Strong evidence that the deployment uses React Server Components.
pub(super) fn rsc_markers(entry: &TrafficEntry, headers: &serde_json::Map<String, Value>) -> Vec<&'static str> {
    let mut markers = vec![];
    let response_type = entry.response_content_type.as_deref().unwrap_or("");
    if is_rsc_type(response_type) || header_text(headers, "content-type").is_some_and(|value| is_rsc_type(&value)) {
        markers.push("header: text/x-component response");
    }
    if header_text(headers, "vary").is_some_and(|value| value.split(',').any(|token| token.trim().eq_ignore_ascii_case("rsc"))) {
        markers.push("header: Vary: RSC");
    }
    let sample = String::from_utf8_lossy(&entry.response_body[..entry.response_body.len().min(65_536)]);
    if sample.contains("self.__next_f.push") {
        markers.push("body: App Router flight data (self.__next_f)");
    }
    if is_rsc_type(response_type) && looks_like_flight(&sample) {
        markers.push("body: Flight rows");
    }
    markers.sort_unstable();
    markers.dedup();
    markers
}

/// Next.js specifically (other RSC frameworks exist and are reported without a Next.js version).
fn is_next(entry: &TrafficEntry, headers: &serde_json::Map<String, Value>) -> bool {
    let sample = String::from_utf8_lossy(&entry.response_body[..entry.response_body.len().min(65_536)]);
    sample.contains("self.__next_f") || sample.contains("/_next/") || header_text(headers, "x-powered-by").is_some_and(|value| value.to_ascii_lowercase().contains("next.js")) || headers.contains_key("x-nextjs-cache") || header_text(headers, "vary").is_some_and(|value| value.to_ascii_lowercase().contains("next-router-state-tree"))
}

fn request_rsc(headers: &serde_json::Map<String, Value>) -> bool {
    header_text(headers, "rsc").is_some_and(|value| value == "1") || header_text(headers, "next-action").is_some() || header_text(headers, "next-router-state-tree").is_some()
}

pub(super) fn eligible(entry: &TrafficEntry) -> bool {
    if entry.method != "GET" || !(200..400).contains(&entry.status_code) {
        return false;
    }
    let response = audit::headers(&entry.response_headers);
    let request = audit::headers(&entry.request_headers);
    request_rsc(&request) || !rsc_markers(entry, &response).is_empty()
}

// ── Reading the Next.js version from the client bundle ─────────────────────────────────

/// `/_next/static/**/*.js` URLs on the page's own origin, most likely carriers of the version first.
pub(super) fn script_urls(html: &str, base: &reqwest::Url) -> Vec<reqwest::Url> {
    let mut found: Vec<String> = vec![];
    let mut from = 0;
    while let Some(relative) = html[from..].find("/_next/static/") {
        let start = from + relative;
        let rest = &html[start..];
        let end = rest.find(|c: char| matches!(c, '"' | '\'' | '\\' | ' ' | '<' | '>' | ')' | '\n' | '\r' | '?')).unwrap_or(rest.len());
        let candidate = &rest[..end];
        from = start + end.max(1);
        // `/_next/...` as the whole reference. `https://cdn.example/_next/...` or `/prefix/_next/...` is
        // another host or an asset prefix, and the path alone would point at the wrong place.
        if !matches!(html[..start].chars().next_back(), None | Some('"' | '\'' | ' ' | '(' | '=' | '>' | '\n' | '\t')) {
            continue;
        }
        if candidate.ends_with(".js") && candidate.len() < 300 && !candidate.contains("..") && !found.iter().any(|known| known == candidate) && found.len() < 64 {
            found.push(candidate.to_string());
        }
    }
    let rank = |path: &str| {
        if path.contains("main-app") {
            0
        } else if path.contains("webpack") {
            1
        } else if path.contains("/main-") || path.contains("/main.") {
            2
        } else if path.contains("framework") {
            3
        } else if path.contains("polyfills") {
            9
        } else {
            5
        }
    };
    found.sort_by_key(|path| rank(path));
    found
        .iter()
        .filter(|path| rank(path) < 9)
        .filter_map(|path| base.join(path).ok())
        .filter(|url| url.origin() == base.origin())
        .take(MAX_SCRIPTS)
        .collect()
}

fn around(text: &str, start: usize, end: usize) -> String {
    let mut a = start.saturating_sub(24);
    while !text.is_char_boundary(a) {
        a -= 1;
    }
    let mut b = (end + 12).min(text.len());
    while !text.is_char_boundary(b) {
        b += 1;
    }
    text[a..b].to_string()
}

/// `window.next = { version: "15.1.2", appDir: true }`, minified or not. Returns the version and
/// the text around it.
pub(super) fn next_version_in_script(js: &str) -> Option<(Version, String)> {
    let bytes = js.as_bytes();
    let mut from = 0;
    while let Some(relative) = js[from..].find("version") {
        let at = from + relative;
        from = at + 7;
        let mut i = at + 7;
        let skip = |i: &mut usize| {
            while bytes.get(*i).is_some_and(u8::is_ascii_whitespace) {
                *i += 1;
            }
        };
        skip(&mut i);
        if bytes.get(i) != Some(&b':') {
            continue;
        }
        i += 1;
        skip(&mut i);
        let Some(&quote) = bytes.get(i).filter(|b| matches!(**b, b'"' | b'\'')) else { continue };
        let start = i + 1;
        let Some(length) = js[start..].find(quote as char) else { continue };
        let end = start + length;
        let Some(version) = Version::parse(&js[start..end]) else { continue };
        // The assignment: `<name>next = {` directly before the key.
        let before = js[..at].trim_end();
        let Some(before) = before.strip_suffix('{').map(str::trim_end) else { continue };
        let Some(before) = before.strip_suffix('=').map(str::trim_end) else { continue };
        if before.ends_with("next") {
            return Some((version, around(js, at, end)));
        }
    }
    None
}

// ── The audit ──────────────────────────────────────────────────────────────────────────

struct Found {
    version: Version,
    script: String,
    snippet: String,
}

fn evidence_item(n: usize, url: &str, result: &Value, snippet: Option<&str>) -> Value {
    let content_type = result["responseHeaders"]["content-type"].as_str().unwrap_or("");
    let mut item = json!({
        "id": format!("react2shell-script-{n}"),
        "label": "Public Next.js script fetched to read its version",
        "request": {"method":"GET","url":url,"headers":{"accept":"*/*"},"body":"","timeout":15000},
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "setCookies": [],
        "duration": result["duration"].as_u64().unwrap_or(0).min(3_600_000),
        "size": result["size"].as_u64().unwrap_or(0).min(2_000_000),
        "truncated": false
    });
    if result["ok"] == true {
        item["response"] = json!({"status": result["status"], "responseHeaders": {"content-type": content_type}, "responseBody": snippet.unwrap_or("")});
    } else {
        item["error"] = json!(audit::preview(result["error"].as_str().unwrap_or("Request failed"), 4000));
    }
    item
}

pub(super) async fn audit(entry: &TrafficEntry, id: &str, state: &AuditState, intercept: &Intercept) -> Option<Value> {
    if !state.enabled() || !intercept.scope().matches(&entry.host) {
        return None;
    }
    let original = audit::request(entry)?;
    let response_headers = audit::headers(&entry.response_headers);
    let markers = rsc_markers(entry, &response_headers);
    let mut evidence = vec![audit::observed(entry, &original)];
    let mut sent = 0;
    let mut checks = vec![];
    let mut findings = vec![];
    let data = advisory();

    if markers.is_empty() {
        checks.push(json!({"checkId":"react2shell","status":"inconclusive","message":"No React Server Components evidence in this response (no Flight data, self.__next_f, Vary: RSC). A Pages Router or non-React site is not affected by this advisory.","findingIds":[]}));
        return Some(finish(entry, id, &original, evidence, findings, checks, sent));
    }
    checks.push(json!({"checkId":"react2shell","status":"passed","message":format!("React Server Components confirmed from: {}.", markers.join("; ")),"findingIds":[]}));

    // Which version is this? Only Next.js bundles carry it in a place we can read.
    let next = is_next(entry, &response_headers);
    let mut found: Option<Found> = None;
    let mut tried = 0;
    if next {
        let html = String::from_utf8_lossy(&entry.response_body[..entry.response_body.len().min(262_144)]).into_owned();
        let base = reqwest::Url::parse(&entry.url).ok();
        for url in base.as_ref().map(|base| script_urls(&html, base)).unwrap_or_default() {
            if !state.enabled() || !intercept.scope().matches(&entry.host) {
                return None;
            }
            // One request start per half second, like the other automatic workers.
            sleep(Duration::from_millis(500)).await;
            let request = json!({"method":"GET","url":url.as_str(),"headers":{"accept":"*/*"},"body":"","timeout":15000});
            let result = tokio::time::timeout(SCRIPT_TIMEOUT, super::http_sender::send(axum::Json(request)))
                .await
                .map(|response| response.0)
                .unwrap_or_else(|_| json!({"ok":false,"error":"Script request timed out"}));
            sent += 1;
            tried += 1;
            let hit = (result["ok"] == true && result["status"] == 200)
                .then(|| result["responseBody"].as_str().and_then(next_version_in_script))
                .flatten();
            evidence.push(evidence_item(tried, url.as_str(), &result, hit.as_ref().map(|(_, snippet)| snippet.as_str())));
            if let Some((version, snippet)) = hit {
                found = Some(Found { version, script: url.path().to_string(), snippet });
                break;
            }
        }
    }

    let verdict = found.as_ref().map(|f| assess_next(&f.version));
    let (status, message, finding) = match (&found, &verdict) {
        (Some(f), Some(Verdict::Vulnerable { fixed })) => {
            let title = format!("React2Shell ({}): Next.js {} is below the patched release {fixed}", data.cve, f.version);
            let mut finding = audit::finding(
                "react2shell-version",
                "react2shell-version-1",
                &title,
                format!("The deployment uses React Server Components and its client bundle reports Next.js {} (read from `window.next.version` in {}). The vendor advisory for {} lists {fixed} as the first patched release of this branch, so this version is in the affected range. The audit only compared versions: it sent no Flight request or Server Function payload and did not test the deserializer, and a server whose React packages were upgraded separately may differ from the bundle. Confirm the installed `next`, `react` and `react-server-dom-*` versions on the server.", f.version, f.script, data.cve),
                vec!["observed", "react2shell-script-1"],
                vec![format!("Evidence: {}", markers.join("; ")), format!("Next.js version: {} (from {})", f.version, f.script), format!("Bundle text: {}", f.snippet), format!("Patched release for this branch: {fixed}"), format!("Advisory: {} ({})", data.cve, data.note)],
                "high",
            );
            finding["confidence"] = json!("high");
            finding["verification"] = json!({"method":"Version read from the public client bundle compared with the advisory's patched releases","outcome":"inconclusive","reason":"The version is strong evidence of the build but the deserializer was not exercised, and server-side packages may have been upgraded independently."});
            finding["remediation"] = json!(format!("Upgrade Next.js to {fixed} or later on this branch (or the newest release), and make sure react-server-dom-webpack, react-server-dom-parcel and react-server-dom-turbopack are 19.0.1, 19.1.2 or 19.2.1 or later. Rebuild and redeploy; WAF rules are not a substitute for the update."));
            ("findings", format!("Next.js {} is below the patched release {fixed}.", f.version), Some(finding))
        }
        (Some(f), Some(Verdict::Patched { since })) => ("passed", format!("Next.js {} is patched for this advisory ({since}).", f.version), None),
        (Some(f), Some(Verdict::NotAffected(reason))) => ("passed", format!("Next.js {} is outside the affected range: {reason}.", f.version), None),
        (Some(f), Some(Verdict::Prerelease)) => {
            let mut finding = audit::finding(
                "react2shell-version",
                "react2shell-version-1",
                &format!("React2Shell ({}): pre-release Next.js {} on an affected branch", data.cve, f.version),
                format!("The deployment uses React Server Components and reports the pre-release Next.js {} (from {}). Pre-releases of the affected branches may or may not contain the fix, so the patch level cannot be decided from the version. Check the installed versions on the server.", f.version, f.script),
                vec!["observed", "react2shell-script-1"],
                vec![format!("Evidence: {}", markers.join("; ")), format!("Next.js version: {}", f.version)],
                "medium",
            );
            finding["confidence"] = json!("medium");
            ("findings", format!("Pre-release Next.js {}: patch level cannot be decided.", f.version), Some(finding))
        }
        _ => {
            let (why, sentence) = if !next {
                ("The deployment serves React Server Components but is not identified as Next.js, so no Next.js version could be read.", "RSC framework other than Next.js: check the `react-server-dom-*` versions in the lockfile.")
            } else if tried == 0 {
                ("No same-origin /_next/static script was referenced by the captured page, so the Next.js version could not be read.", "No script to read the version from.")
            } else {
                ("The Next.js bundle scripts that were fetched did not contain a readable version.", "The version could not be read from the bundle.")
            };
            let mut finding = audit::finding(
                "react2shell-version",
                "react2shell-version-1",
                &format!("React Server Components detected; {} patch status unknown", data.cve),
                format!("{why} React Server Components are in use, which is the condition for {}, but whether the deployment is patched depends on the `react-server-dom-*` and Next.js versions on the server. Use the lockfile check in Tools (paste package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock) or confirm the installed versions. This audit sent no Flight request or Server Function payload and does not claim the deployment is vulnerable.", data.cve),
                vec!["observed"],
                vec![format!("Evidence: {}", markers.join("; ")), sentence.to_string(), format!("Advisory: {} ({})", data.cve, data.note)],
                "info",
            );
            finding["confidence"] = json!("high");
            finding["remediation"] = json!("Confirm the installed versions: Next.js 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7 or later, and react-server-dom-* 19.0.1, 19.1.2, 19.2.1 or later. Rebuild and redeploy after upgrading.");
            ("findings", "RSC confirmed; version not readable, patch status unknown.".to_string(), Some(finding))
        }
    };
    if let Some(finding) = finding {
        findings.push(finding);
    }
    checks.push(json!({"checkId":"react2shell-version","status":status,"message":message,"findingIds":findings.iter().map(|f| f["id"].clone()).collect::<Vec<_>>()}));
    Some(finish(entry, id, &original, evidence, findings, checks, sent))
}

fn finish(entry: &TrafficEntry, id: &str, original: &Value, evidence: Vec<Value>, findings: Vec<Value>, checks: Vec<Value>, sent: usize) -> Value {
    let mode = if sent > 0 { "active" } else { "passive" };
    let mut run = audit::run(entry, id, original, evidence, findings, checks, sent, mode);
    run["auditKey"] = json!(key(original));
    run["profileName"] = json!("Automatic React2Shell (CVE-2025-55182) audit");
    run["plan"]["maxRequests"] = json!(sent);
    run
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(response_headers: Value, body: &str, content_type: &str) -> TrafficEntry {
        let mut entry = TrafficEntry::new_request("GET", "http://localhost/page", "localhost", "/page", "http", "{}", vec![], None);
        entry.status_code = 200;
        entry.response_headers = response_headers.to_string();
        entry.response_body = body.as_bytes().to_vec();
        entry.response_size = entry.response_body.len() as u64;
        entry.response_content_type = Some(content_type.into());
        entry
    }
    fn markers(entry: &TrafficEntry) -> Vec<&'static str> {
        rsc_markers(entry, &audit::headers(&entry.response_headers))
    }
    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn only_strong_evidence_counts_as_react_server_components() {
        let app = entry(json!({}), "<script>self.__next_f.push([1,\"x\"])</script>", "text/html");
        assert!(markers(&app).iter().any(|m| m.contains("self.__next_f")));
        assert!(markers(&entry(json!({"vary":["RSC, Next-Router-State-Tree"]}), "", "text/html")).iter().any(|m| m.contains("Vary: RSC")));
        assert!(markers(&entry(json!({}), "0:{\"a\":\"$@1\"}", "text/x-component")).len() >= 2);
        // Not RSC: Pages Router, an x-powered-by banner, Vercel hosting, static asset references.
        for weak in [
            entry(json!({"x-powered-by":["Next.js"]}), "<p>hi</p>", "text/html"),
            entry(json!({"x-vercel-id":["fra1::abc"]}), "<p>hi</p>", "text/html"),
            entry(json!({"x-nextjs-cache":["HIT"]}), "<p>hi</p>", "text/html"),
            entry(json!({}), "<script id=\"__NEXT_DATA__\" type=\"application/json\">{}</script>", "text/html"),
            entry(json!({}), "<script src=\"/_next/static/chunks/main.js\"></script>", "text/html"),
        ] {
            assert!(markers(&weak).is_empty(), "{:?}", String::from_utf8_lossy(&weak.response_body));
            assert!(!eligible(&weak));
        }
    }

    #[test]
    fn flight_rows_need_real_flight_structure() {
        assert!(looks_like_flight("0:{\"a\":\"$@1\"}\n1:[\"$\",\"div\",null,{}]"));
        assert!(looks_like_flight("1:I[\"chunk\",[\"a\"],\"default\"]\n"));
        assert!(looks_like_flight("a:\"$Sreact.suspense\""));
        for text in ["<html><body>app</body></html>", "0:no quotes here", "12:30 \"Lunch\"", "3:00 pm \"standup\"", "1:{\"level\":\"info\"}", "", "ab:cd"] {
            assert!(!looks_like_flight(text), "{text}");
        }
        assert!(is_rsc_type("text/x-component; charset=utf-8"));
        assert!(!is_rsc_type("text/html"));
    }

    #[test]
    fn eligibility_needs_rsc_evidence_a_get_and_a_success_or_redirect() {
        let page = entry(json!({"vary":["RSC"]}), "", "text/html");
        assert!(eligible(&page));
        let mut post = page.clone();
        post.method = "POST".into();
        assert!(!eligible(&post));
        let mut failed = page.clone();
        failed.status_code = 500;
        assert!(!eligible(&failed));
        let mut navigation = entry(json!({}), "<p>x</p>", "text/html");
        navigation.request_headers = json!({"RSC":["1"]}).to_string();
        assert!(eligible(&navigation));
    }

    #[test]
    fn versions_are_judged_against_the_patched_release_of_their_branch() {
        for (version, fixed) in [("15.0.4", "15.0.5"), ("15.1.8", "15.1.9"), ("15.2.0", "15.2.6"), ("15.5.6", "15.5.7"), ("16.0.6", "16.0.7")] {
            assert_eq!(assess_next(&v(version)), Verdict::Vulnerable { fixed: fixed.into() }, "{version}");
        }
        for version in ["15.0.5", "15.1.9", "15.5.7", "15.5.10", "16.0.7", "16.0.11", "16.1.5", "16.2.0", "17.0.0", "15.6.0"] {
            assert!(matches!(assess_next(&v(version)), Verdict::Patched { .. }), "{version}");
        }
        for version in ["13.5.6", "14.2.35", "14.0.0", "12.3.4"] {
            assert!(matches!(assess_next(&v(version)), Verdict::NotAffected(_)), "{version}");
        }
        assert_eq!(assess_next(&v("14.3.0-canary.77")), Verdict::Prerelease);
        assert_eq!(assess_next(&v("14.3.0-canary.76")).clone(), Verdict::NotAffected("Next.js releases before 15 do not bundle the affected React Server Components build"));
        assert_eq!(assess_next(&v("15.2.0-canary.4")), Verdict::Prerelease);
        assert_eq!(assess_next(&v("16.0.0-rc.1")), Verdict::Prerelease);
    }

    #[test]
    fn react_packages_are_judged_by_their_release_line() {
        for version in ["19.0.0", "19.1.0", "19.1.1", "19.2.0"] {
            assert!(matches!(assess_react(&v(version)), Verdict::Vulnerable { .. }), "{version}");
        }
        for version in ["19.0.1", "19.1.2", "19.2.1", "19.2.4", "19.3.0", "20.0.0"] {
            assert!(matches!(assess_react(&v(version)), Verdict::Patched { .. }), "{version}");
        }
        assert!(matches!(assess_react(&v("18.3.1")), Verdict::NotAffected(_)));
        assert_eq!(assess_react(&v("19.1.0-rc.1")), Verdict::Prerelease);
    }

    #[test]
    fn versions_parse_strictly() {
        assert_eq!(v("15.1.2").to_string(), "15.1.2");
        assert_eq!(v("15.0.0-canary.5").to_string(), "15.0.0-canary.5");
        for bad in ["15.1", "15.1.2.3", "a.b.c", "15.1.x", "15.1.2-", "", "v15.1.2"] {
            assert!(Version::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn reads_the_next_version_from_minified_and_plain_bundles() {
        let (version, snippet) = next_version_in_script("!function(){window.next={version:\"15.1.2\",appDir:!0}}()").unwrap();
        assert_eq!(version, v("15.1.2"));
        assert!(snippet.contains("version"));
        assert_eq!(next_version_in_script("self.next = {\n  version: '14.2.3',\n  appDir: true\n};").unwrap().0, v("14.2.3"));
        assert_eq!(next_version_in_script("var n=window.next={version:\"15.0.0-canary.7\",appDir:!0}").unwrap().0, v("15.0.0-canary.7"));
        // Other `version` keys are not the Next.js version.
        for other in [
            "var react={version:\"19.1.0\"}",
            "window.other={version:\"1.2.3\"}",
            "window.next={router:1,version:\"15.1.2\"}",
            "window.next={version:\"not-a-version\"}",
            "version: \"15.1.2\"",
            "package.json: {\"version\":\"15.1.2\"}",
        ] {
            assert!(next_version_in_script(other).is_none(), "{other}");
        }
        assert!(next_version_in_script("é".repeat(10).as_str()).is_none());
    }

    #[test]
    fn picks_same_origin_next_scripts_and_prefers_the_ones_that_carry_the_version() {
        let html = r#"<script src="/_next/static/chunks/polyfills-abc.js" nomodule></script>
            <script src="/_next/static/chunks/webpack-111.js"></script>
            <script src="/_next/static/chunks/main-app-222.js?v=1"></script>
            <script src="https://cdn.example.net/_next/static/chunks/main-app-evil.js"></script>
            <script src="/_next/static/chunks/../../etc/x.js"></script>
            <link href="/_next/static/css/app.css" rel="stylesheet">
            <script src="/_next/static/chunks/main-app-222.js"></script>"#;
        let base = reqwest::Url::parse("https://app.example/page").unwrap();
        let urls: Vec<String> = script_urls(html, &base).iter().map(|u| u.path().to_string()).collect();
        assert_eq!(urls[0], "/_next/static/chunks/main-app-222.js");
        assert_eq!(urls[1], "/_next/static/chunks/webpack-111.js");
        assert!(urls.iter().all(|u| !u.contains("polyfills") && !u.contains("..") && !u.ends_with(".css")));
        assert_eq!(urls.len(), 2);
        assert!(script_urls("<p>no scripts</p>", &base).is_empty());
    }

    #[test]
    fn audits_each_origin_once_regardless_of_path() {
        let first = key(&json!({"url":"https://app.example/page"}));
        assert_eq!(first, key(&json!({"url":"https://app.example/other?x=1"})));
        assert_ne!(first, key(&json!({"url":"https://app.example:8443/page"})));
        assert!(first.starts_with("auto-react2shell-"));
    }

    /// A Next.js App Router page whose main bundle carries `bundle_version` (or nothing).
    async fn fixture(bundle: Option<&'static str>) -> (TrafficEntry, std::sync::Arc<proxy_core::TrafficStorage>, std::sync::Arc<Intercept>, std::sync::Arc<std::sync::Mutex<Vec<(String, bool)>>>) {
        use axum::{http::HeaderMap, routing::get, Router};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let app = Router::new().route(
            "/_next/static/chunks/main-app-1.js",
            get(move |headers: HeaderMap| {
                let log = log.clone();
                async move {
                    log.lock().unwrap().push(("script".into(), headers.contains_key("cookie") || headers.contains_key("authorization")));
                    ([("content-type", "application/javascript")], bundle.map(|v| format!("!function(){{window.next={{version:\"{v}\",appDir:!0}}}}()")).unwrap_or_else(|| "console.log(1)".into()))
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut entry = TrafficEntry::new_request("GET", &format!("http://{address}/page"), "127.0.0.1", "/page", "http", &json!({"cookie":["sid=secret"],"authorization":["Bearer t"]}).to_string(), vec![], None);
        entry.status_code = 200;
        entry.response_headers = json!({"vary":["RSC, Next-Router-State-Tree"],"content-type":["text/html"]}).to_string();
        entry.response_body = b"<html><script src=\"/_next/static/chunks/main-app-1.js\"></script><script>self.__next_f.push([1,\"x\"])</script></html>".to_vec();
        entry.response_size = entry.response_body.len() as u64;
        entry.response_content_type = Some("text/html".into());
        let storage = proxy_core::TrafficStorage::new(":memory:", 100_000).unwrap();
        let intercept = Intercept::new(storage.clone());
        (entry, storage, intercept, seen)
    }

    #[tokio::test]
    async fn reports_a_vulnerable_next_version_read_from_the_bundle_without_credentials() {
        let (entry, storage, intercept, seen) = fixture(Some("15.1.2")).await;
        let (state, _runtime) = audit::start(storage, intercept.clone());
        let run = audit(&entry, "react-vuln", &state, &intercept).await.unwrap();
        assert_eq!(run["sent"], 1);
        let finding = &run["findings"][0];
        assert_eq!(finding["checkId"], "react2shell-version");
        assert_eq!(finding["severity"], "high");
        assert!(finding["title"].as_str().unwrap().contains("15.1.9"));
        assert!(finding["summary"].as_str().unwrap().contains("sent no Flight request"));
        let checks = run["checks"].as_array().unwrap();
        assert_eq!(checks[0]["checkId"], "react2shell");
        assert_eq!(checks[0]["status"], "passed");
        assert_eq!(checks[1]["status"], "findings");
        assert_eq!(*seen.lock().unwrap(), vec![("script".to_string(), false)], "the script is fetched without cookies or credentials");
        assert!(super::super::scan::validate_run("react-vuln", &run).is_ok());
    }

    #[tokio::test]
    async fn a_patched_version_produces_no_finding() {
        for version in ["15.1.9", "16.1.5", "14.2.35"] {
            let (entry, storage, intercept, _) = fixture(Some(version)).await;
            let (state, _runtime) = audit::start(storage, intercept.clone());
            let run = audit(&entry, "react-ok", &state, &intercept).await.unwrap();
            assert!(run["findings"].as_array().unwrap().is_empty(), "{version}");
            assert_eq!(run["checks"][1]["status"], "passed", "{version}");
            assert!(super::super::scan::validate_run("react-ok", &run).is_ok());
        }
    }

    #[tokio::test]
    async fn an_unreadable_version_is_reported_as_unknown_not_vulnerable() {
        let (entry, storage, intercept, _) = fixture(None).await;
        let (state, _runtime) = audit::start(storage, intercept.clone());
        let run = audit(&entry, "react-unknown", &state, &intercept).await.unwrap();
        let finding = &run["findings"][0];
        assert_eq!(finding["severity"], "info");
        assert!(finding["title"].as_str().unwrap().contains("patch status unknown"));
        assert!(!finding["title"].as_str().unwrap().to_lowercase().contains("below"));
        assert!(super::super::scan::validate_run("react-unknown", &run).is_ok());
    }

    #[tokio::test]
    async fn a_page_without_rsc_evidence_is_inconclusive_and_sends_nothing() {
        let (mut entry, storage, intercept, seen) = fixture(Some("15.1.2")).await;
        entry.response_headers = json!({"x-powered-by":["Next.js"],"content-type":["text/html"]}).to_string();
        entry.response_body = b"<script id=\"__NEXT_DATA__\">{}</script><script src=\"/_next/static/chunks/main-app-1.js\"></script>".to_vec();
        let (state, _runtime) = audit::start(storage, intercept.clone());
        let run = audit(&entry, "react-pages", &state, &intercept).await.unwrap();
        assert_eq!(run["sent"], 0);
        assert!(run["findings"].as_array().unwrap().is_empty());
        assert_eq!(run["checks"][0]["status"], "inconclusive");
        assert!(seen.lock().unwrap().is_empty());
        assert!(super::super::scan::validate_run("react-pages", &run).is_ok());
    }

    #[test]
    fn the_bundled_advisory_data_is_complete() {
        let data = advisory();
        assert_eq!(data.cve, "CVE-2025-55182");
        assert!(!data.note.is_empty());
        assert_eq!(data.react_major, 19);
        assert_eq!(data.next_not_affected_below, 15);
        assert_eq!(data.next_patched.len(), 7);
        assert_eq!(data.react_patched.len(), 3);
        assert_eq!(data.next_canary.get(&(14, 3)), Some(&77));
    }
}
