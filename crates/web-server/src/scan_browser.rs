//! Isolated Chromium response renderer. It never fetches the scanned origin:
//! the sole main document is fulfilled from the shared Replay sender's response.
use axum::Json;
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf, process::Stdio, time::Duration};
use tokio::{net::TcpStream, process::Command, sync::Semaphore};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

static BROWSERS: Semaphore = Semaphore::const_new(2);
static BROWSER_JOBS: Semaphore = Semaphore::const_new(8);
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    url: String,
    body: String,
    headers: BTreeMap<String, String>,
    marker: String,
    #[serde(default)]
    resources: Vec<ScriptResource>,
    #[serde(default)]
    interaction: Option<Interaction>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Interaction {
    selector: Option<String>,
    value: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptResource {
    url: String,
    body: String,
    headers: BTreeMap<String, String>,
}
#[derive(Serialize)]
struct SinkTrace {
    sink: String,
    value: String,
    stack: String,
}
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Observation {
    executed: bool,
    sinks: Vec<String>,
    csp_violations: Vec<String>,
    blocked_requests: usize,
    browser: String,
    sink_traces: Vec<SinkTrace>,
    requested_scripts: Vec<String>,
    interactions: Vec<String>,
}
fn executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SLURP_BROWSER_PATH") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let mut paths = vec![
        PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        PathBuf::from("/usr/bin/chromium"),
        PathBuf::from("/usr/bin/chromium-browser"),
        PathBuf::from("/usr/bin/google-chrome"),
        PathBuf::from("/usr/bin/google-chrome-stable"),
    ];
    for key in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
        if let Some(root) = std::env::var_os(key) {
            paths.push(PathBuf::from(&root).join("Google/Chrome/Application/chrome.exe"));
            paths.push(PathBuf::from(root).join("Microsoft/Edge/Application/msedge.exe"));
        }
    }
    paths.into_iter().find(|p| p.is_file())
}
fn validate(snapshot: &Snapshot) -> Result<(), String> {
    if snapshot.interaction.as_ref().is_some_and(|i| {
        i.selector.as_ref().is_some_and(|s| s.is_empty() || s.len() > 1000)
            || i.value.as_ref().is_some_and(|s| s.len() > 6000)
            || i.selector.is_some() != i.value.is_some()
    }) {
        return Err("Invalid browser interaction".into());
    }
    let url = reqwest::Url::parse(&snapshot.url).map_err(|_| "Invalid browser URL")?;
    super::http_target::validate(&url)?;
    let mut seen = std::collections::HashSet::new();
    let mut total = 0;
    if snapshot.resources.len() > 16 {
        return Err("At most 16 captured scripts are allowed".into());
    }
    for resource in &snapshot.resources {
        let url = reqwest::Url::parse(&resource.url).map_err(|_| "Invalid script URL")?;
        super::http_target::validate(&url)?;
        total += resource.body.len();
        if resource.url.len() > 4096
            || url.fragment().is_some()
            || !seen.insert(url.as_str().to_string())
            || resource.body.len() > 256_000
            || total > 1_000_000
            || resource.headers.len() > 200
            || serde_json::to_vec(&resource.headers).unwrap().len() > 256_000
            || resource
                .headers
                .iter()
                .any(|(k, v)| k.contains(['\r', '\n']) || v.contains(['\r', '\n']))
            || !utf8_headers(&resource.headers)
        {
            return Err("Invalid captured script or script byte limit exceeded".into());
        }
    }
    if snapshot.body.len() > 256_000
        || snapshot.headers.len() > 200
        || serde_json::to_vec(&snapshot.headers).unwrap().len() > 256_000
        || !(16..=100).contains(&snapshot.marker.len())
        || !snapshot.marker.bytes().all(|b| b.is_ascii_alphanumeric())
        || snapshot
            .headers
            .iter()
            .any(|(k, v)| k.contains(['\r', '\n']) || v.contains(['\r', '\n']))
    {
        return Err("Invalid browser snapshot (256 KB body/header limits)".into());
    }
    let content_type = snapshot
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();
    if !content_type
        .split(';')
        .next()
        .is_some_and(|v| v.trim() == "text/html")
    {
        return Err("Browser checks require a text/html response".into());
    }
    if content_type.split(';').skip(1).any(|p| {
        p.trim().split_once('=').is_some_and(|(key, value)| {
            key.trim() == "charset"
                && !["utf-8", "utf8", "us-ascii"].contains(&value.trim().trim_matches(['\'', '"']))
        })
    }) {
        return Err("Browser snapshots support UTF-8/ASCII HTML only".into());
    }
    Ok(())
}
fn utf8_headers(headers: &BTreeMap<String, String>) -> bool {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .all(|(_, v)| {
            !v.to_ascii_lowercase().split(';').skip(1).any(|p| {
                p.trim().split_once('=').is_some_and(|(key, value)| {
                    key.trim() == "charset"
                        && !["utf-8", "utf8", "us-ascii"]
                            .contains(&value.trim().trim_matches(['\'', '"']))
                })
            })
        })
}
struct Cdp {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    session: String,
    id: u64,
    initial_url: String,
    expected_origin: String,
    main_frame: String,
    main_context: Option<i64>,
    served: bool,
    marker: String,
    body: String,
    headers: Vec<Value>,
    observation: Observation,
    resources: BTreeMap<String, ScriptResource>,
}
impl Cdp {
    async fn send(&mut self, method: &str, params: Value) -> Result<u64, String> {
        self.id += 1;
        let mut msg = json!({"id":self.id,"method":method,"params":params});
        if !self.session.is_empty() {
            msg["sessionId"] = json!(self.session);
        }
        self.socket
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| e.to_string())?;
        Ok(self.id)
    }
    async fn next(&mut self) -> Result<Value, String> {
        loop {
            let message = self
                .socket
                .next()
                .await
                .ok_or("Browser disconnected")?
                .map_err(|e| e.to_string())?;
            let Message::Text(text) = message else {
                continue;
            };
            let event: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let p = &event["params"];
            match event["method"].as_str().unwrap_or("") {
                "Runtime.executionContextCreated" => {
                    let context = &p["context"];
                    if context["auxData"]["frameId"] == self.main_frame
                        && context["auxData"]["isDefault"] == true
                        && context["origin"] == self.expected_origin
                    {
                        self.main_context = context["id"].as_i64();
                    }
                }
                "Runtime.executionContextDestroyed" => {
                    if p["executionContextId"].as_i64() == self.main_context {
                        self.main_context = None;
                    }
                }
                "Runtime.executionContextsCleared" => {
                    self.main_context = None;
                }
                "Fetch.requestPaused" => {
                    if !self.served
                        && p["resourceType"] == "Document"
                        && p["request"]["url"] == self.initial_url
                    {
                        self.served = true;
                        self.send(
                            "Fetch.fulfillRequest",
                            json!({"requestId":p["requestId"],"responseCode":200,
                            "responseHeaders":self.headers,"body":self.body}),
                        )
                        .await?;
                    } else if self.served
                        && p["resourceType"] == "Script"
                        && p["frameId"] == self.main_frame
                        && p["request"]["method"] == "GET"
                    {
                        if let Some(resource) = p["request"]["url"]
                            .as_str()
                            .and_then(|url| self.resources.get(url))
                        {
                            let body = STANDARD.encode(&resource.body);
                            let headers = response_headers(&resource.headers, false);
                            self.send(
                                "Fetch.fulfillRequest",
                                json!({"requestId":p["requestId"],"responseCode":200,
                                "responseHeaders":headers,"body":body}),
                            )
                            .await?;
                        } else {
                            // Discovery only: never fetch a runtime dependency in Chromium.
                            // The scan engine may capture this GET through the shared sender
                            // after applying its origin, scope and evidence limits.
                            if p["request"]["method"] == "GET" {
                                if let Some(url) = p["request"]["url"].as_str() {
                                    if let Ok(parsed) = reqwest::Url::parse(url) {
                                        if url.len() <= 4096
                                            && super::http_target::validate(&parsed).is_ok()
                                            && parsed.fragment().is_none()
                                            && self.observation.requested_scripts.len() < 16
                                            && !self.observation.requested_scripts.iter().any(|s| s == url)
                                        {
                                            self.observation.requested_scripts.push(url.to_string());
                                        }
                                    }
                                }
                            }
                            self.observation.blocked_requests += 1;
                            self.send(
                                "Fetch.failRequest",
                                json!({"requestId":p["requestId"],"errorReason":"BlockedByClient"}),
                            )
                            .await?;
                        }
                    } else {
                        self.observation.blocked_requests += 1;
                        self.send(
                            "Fetch.failRequest",
                            json!({"requestId":p["requestId"],"errorReason":"BlockedByClient"}),
                        )
                        .await?;
                    }
                }
                "Runtime.bindingCalled"
                    if p["name"] == "__slurpXss"
                        && self.main_context.is_some()
                        && p["executionContextId"].as_i64() == self.main_context =>
                {
                    if p["payload"].as_str() == Some(&self.marker) {
                        self.observation.executed = true;
                    }
                }
                "Runtime.bindingCalled"
                    if p["name"] == "__slurpSink"
                        && self.main_context.is_some()
                        && p["executionContextId"].as_i64() == self.main_context =>
                {
                    if let Some(payload) = p["payload"].as_str() {
                        if let Ok(data) = serde_json::from_str::<Value>(payload) {
                            if data["marker"] == self.marker && self.observation.sinks.len() < 12 {
                                let description = data["sink"].as_str().unwrap_or("");
                                if description.len() <= 100 {
                                    self.observation.sinks.push(description.to_string());
                                    self.observation.sink_traces.push(SinkTrace {
                                        sink: description.to_string(),
                                        value: data["value"]
                                            .as_str()
                                            .unwrap_or("")
                                            .chars()
                                            .take(500)
                                            .collect(),
                                        stack: data["stack"]
                                            .as_str()
                                            .unwrap_or("")
                                            .chars()
                                            .take(1500)
                                            .collect(),
                                    });
                                }
                            }
                        }
                    }
                }
                "Log.entryAdded" if p["entry"]["source"] == "security" => {
                    if self.observation.csp_violations.len() < 6 {
                        self.observation.csp_violations.push(
                            p["entry"]["text"]
                                .as_str()
                                .unwrap_or("")
                                .chars()
                                .take(500)
                                .collect(),
                        );
                    }
                }
                "Page.javascriptDialogOpening" => {
                    self.send("Page.handleJavaScriptDialog", json!({"accept":false}))
                        .await?;
                }
                _ => {}
            }
            return Ok(event);
        }
    }
    async fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.send(method, params).await?;
        loop {
            let event = self.next().await?;
            if event["id"] == id {
                if let Some(error) = event.get("error") {
                    return Err(format!("Browser protocol: {error}"));
                }
                return Ok(event["result"].clone());
            }
        }
    }
}
// No injected script executes the payload. Only the response's own script/handler
// can invoke __slurpXss. This observer records marker-bearing HTML sinks separately.
fn instrumentation(marker: &str) -> String {
    format!(
        r#"(()=>{{const m={marker:?};const notify=(s,v)=>{{try{{const text=String(v),at=text.indexOf(m);if(at>=0) __slurpSink(JSON.stringify({{marker:m,sink:s,value:text.slice(Math.max(0,at-150),at+250),stack:String(new Error().stack||'').slice(0,1500)}}));}}catch(_){{}}}};
for(const [proto,key] of [[Element.prototype,'innerHTML'],[Element.prototype,'outerHTML'],[HTMLIFrameElement.prototype,'srcdoc']]){{const d=Object.getOwnPropertyDescriptor(proto,key);if(d&&d.set)Object.defineProperty(proto,key,{{...d,set(v){{notify(key,v);return d.set.call(this,v)}}}});}}
for(const key of ['write','writeln']){{const f=Document.prototype[key];Document.prototype[key]=function(...v){{notify('document.'+key,v.join(''));return f.apply(this,v)}};}}
const f=Element.prototype.insertAdjacentHTML;Element.prototype.insertAdjacentHTML=function(p,v){{notify('insertAdjacentHTML',v);return f.call(this,p,v)}};
}})();"#
    )
}
fn response_headers(headers: &BTreeMap<String, String>, html: bool) -> Vec<Value> {
    let mut values: Vec<_> = headers
        .iter()
        .filter(|(k, _)| {
            ![
                "content-encoding",
                "content-length",
                "set-cookie",
                "connection",
                "transfer-encoding",
                "refresh",
            ]
            .contains(&k.to_ascii_lowercase().as_str())
                && !(html && k.eq_ignore_ascii_case("content-type"))
        })
        .map(|(k, v)| json!({"name":k,"value":v}))
        .collect();
    if html {
        values.push(json!({"name":"Content-Type","value":"text/html; charset=utf-8"}));
    }
    values
}
// Only native value setters and DOM event dispatch are used. The payload is
// serialized as data, never evaluated by this driver. All network stays denied.
fn interaction_script(options: &Interaction) -> String {
    format!(r#"(()=>{{
      const options={options}; const actions=[];
      document.addEventListener('submit',e=>e.preventDefault(),true);
      const label=e=>(e.tagName+'#'+e.id).slice(0,150);
      if(options.selector){{
        let e;try{{e=document.querySelector(options.selector)}}catch(_){{}}
        if(e && ((e instanceof HTMLInputElement && ['text','search','email','url','tel'].includes(e.type)) || e instanceof HTMLTextAreaElement)){{
          const proto=e instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
          Object.getOwnPropertyDescriptor(proto,'value').set.call(e,options.value);
          e.dispatchEvent(new Event('input',{{bubbles:true}}));e.dispatchEvent(new Event('change',{{bubbles:true}}));
          actions.push('fill/input/change '+label(e));
        }}else actions.push('input unavailable '+options.selector.slice(0,150));
      }}
      const nodes=[...document.querySelectorAll("button,[role=button],a[href^='javascript:'],[onclick],[onmouseover],[onfocus],input:not([type=password]):not([type=hidden]),textarea,select")].slice(0,12);
      for(const e of nodes){{
        try{{ e.dispatchEvent(new MouseEvent('mouseover',{{bubbles:true}}));e.focus();
          if(e.matches('button,[role=button],a,[onclick],input[type=button],input[type=submit]')) e.click();
          else {{e.dispatchEvent(new Event('input',{{bubbles:true}}));e.dispatchEvent(new Event('change',{{bubbles:true}}));}}
          actions.push('mouseover/focus/events '+label(e));
        }}catch(_){{actions.push('interaction failed '+label(e))}}
      }}
      return actions;
    }})()"#,options=serde_json::to_string(options).unwrap())
}
async fn inspect(snapshot: Snapshot) -> Result<Observation, String> {
    let binary = executable().ok_or(
        "Chrome/Chromium not found. Install it or set SLURP_BROWSER_PATH to its executable.",
    )?;
    let profile = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut child = Command::new(binary)
        .args([
            "--headless=new",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-extensions",
            "--disable-sync",
            "--disable-default-apps",
            "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--proxy-server=http://127.0.0.1:9",
            "--proxy-bypass-list=<-loopback>",
            "--host-resolver-rules=MAP * ~NOTFOUND",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
        ])
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("about:blank")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Could not start browser: {e}"))?;
    let result = tokio::time::timeout(Duration::from_secs(12), async {
        let active = loop {
            if let Ok(active) =
                tokio::fs::read_to_string(profile.path().join("DevToolsActivePort")).await
            {
                break active;
            }
            if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err(
                    "Browser exited during startup (its OS sandbox must be enabled)".into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        };
        let mut lines = active.lines();
        let port = lines
            .next()
            .and_then(|v| v.parse::<u16>().ok())
            .ok_or("Invalid browser port")?;
        let path = lines
            .next()
            .filter(|v| v.starts_with("/devtools/browser/"))
            .ok_or("Invalid browser socket")?;
        let (socket, _) = connect_async(format!("ws://127.0.0.1:{port}{path}"))
            .await
            .map_err(|e| e.to_string())?;
        let mut url = reqwest::Url::parse(&snapshot.url).unwrap();
        url.set_fragment(None);
        let headers = response_headers(&snapshot.headers, true);
        let mut cdp = Cdp {
            socket,
            session: String::new(),
            id: 0,
            initial_url: url.to_string(),
            expected_origin: url.origin().ascii_serialization(),
            main_frame: String::new(),
            main_context: None,
            served: false,
            marker: snapshot.marker.clone(),
            body: STANDARD.encode(snapshot.body),
            headers,
            observation: Observation::default(),
            resources: snapshot
                .resources
                .into_iter()
                .map(|r| (r.url.clone(), r))
                .collect(),
        };
        let version = cdp.call("Browser.getVersion", json!({})).await?;
        cdp.observation.browser = version["product"]
            .as_str()
            .unwrap_or("Chromium")
            .to_string();
        let target = cdp
            .call("Target.createTarget", json!({"url":"about:blank"}))
            .await?;
        let session = cdp
            .call(
                "Target.attachToTarget",
                json!({"targetId":target["targetId"],"flatten":true}),
            )
            .await?;
        cdp.session = session["sessionId"]
            .as_str()
            .ok_or("Missing browser session")?
            .into();
        cdp.call("Page.enable", json!({})).await?;
        let tree = cdp.call("Page.getFrameTree", json!({})).await?;
        cdp.main_frame = tree["frameTree"]["frame"]["id"]
            .as_str()
            .ok_or("Missing main browser frame")?
            .into();
        for method in ["Runtime.enable", "Log.enable"] {
            cdp.call(method, json!({})).await?;
        }
        cdp.call(
            "Fetch.enable",
            json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}),
        )
        .await?;
        cdp.call("Runtime.addBinding", json!({"name":"__slurpXss"}))
            .await?;
        cdp.call("Runtime.addBinding", json!({"name":"__slurpSink"}))
            .await?;
        cdp.call(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({"source":instrumentation(&snapshot.marker)}),
        )
        .await?;
        // Keep the original URL including its fragment for location-based DOM sources.
        cdp.call("Page.navigate", json!({"url":snapshot.url}))
            .await?;
        let finish = tokio::time::Instant::now() + Duration::from_millis(1200);
        while let Ok(event) = tokio::time::timeout_at(finish, cdp.next()).await {
            event?;
        }
        if let Some(interaction) = snapshot.interaction {
            let evaluation = cdp.call("Runtime.evaluate", json!({
                "expression": interaction_script(&interaction), "returnByValue":true,
                "contextId":cdp.main_context.ok_or("Main browser context unavailable for interaction")?
            })).await?;
            if evaluation.get("exceptionDetails").is_some() {
                return Err("Browser interaction failed; no XSS conclusion".into());
            }
            cdp.observation.interactions = evaluation["result"]["value"].as_array()
                .ok_or("Browser interaction returned no trace")?.iter()
                .filter_map(|v|v.as_str().map(|s|s.chars().take(200).collect())).take(16).collect();
            let finish = tokio::time::Instant::now() + Duration::from_millis(600);
            while let Ok(event) = tokio::time::timeout_at(finish, cdp.next()).await { event?; }
        }
        if !cdp.served {
            return Err("The browser could not render the supplied document".into());
        }
        cdp.session.clear();
        let _ = cdp.send("Browser.close", json!({})).await;
        Ok(cdp.observation)
    })
    .await
    .unwrap_or_else(|_| Err("Browser validation timed out; no XSS conclusion".into()));
    let _ = child.kill().await;
    let _ = child.wait().await;
    result
}
pub async fn render(Json(snapshot): Json<Snapshot>) -> Json<Value> {
    if let Err(error) = validate(&snapshot) {
        return Json(json!({"ok":false,"error":error}));
    }
    let Ok(_job) = BROWSER_JOBS.try_acquire() else {
        return Json(
            json!({"ok":false,"error":"Browser workers are busy; retry this check later"}),
        );
    };
    let Ok(Ok(_permit)) = tokio::time::timeout(Duration::from_secs(30), BROWSERS.acquire()).await
    else {
        return Json(
            json!({"ok":false,"error":"Browser worker queue timed out; no XSS conclusion"}),
        );
    };
    Json(match inspect(snapshot).await {
        Ok(observation) => json!({"ok":true,"observation":observation}),
        Err(error) => json!({"ok":false,"error":error}),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(body: &str) -> Snapshot {
        Snapshot {
            url: "http://localhost:8088/test".into(),
            body: body.into(),
            headers: BTreeMap::from([("Content-Type".into(), "text/html".into())]),
            marker: "slurpBrowserTest123456".into(),
            resources: Vec::new(),
            interaction: None,
        }
    }
    #[test]
    fn validates_snapshots_without_network_access() {
        let mut s = snapshot("ok");
        assert!(validate(&s).is_ok());
        s.url = "file:///etc/passwd".into();
        assert!(validate(&s).is_err());
        s.url = "https://example.test".into();
        s.marker = "bad();".into();
        assert!(validate(&s).is_err());
        s.marker = "slurpBrowserTest123456".into();
        s.headers.insert("x-test".into(), "a\r\nb".into());
        assert!(validate(&s).is_err());
    }
    #[tokio::test]
    #[ignore = "requires installed Chrome/Chromium and permission to launch its sandbox"]
    async fn browser_executes_html_but_not_escaped_text_and_obeys_csp() {
        let x = inspect(snapshot(
            "<svg onload=\"__slurpXss('slurpBrowserTest123456')\"></svg>",
        ))
        .await
        .unwrap();
        assert!(x.executed);
        let x = inspect(snapshot(
            "&lt;svg onload=\"__slurpXss('slurpBrowserTest123456')\"&gt;",
        ))
        .await
        .unwrap();
        assert!(!x.executed);
        let mut s = snapshot("<svg onload=\"__slurpXss('slurpBrowserTest123456')\"></svg>");
        s.headers
            .insert("Content-Security-Policy".into(), "script-src 'none'".into());
        let x = inspect(s).await.unwrap();
        assert!(!x.executed);
        assert!(!x.csp_violations.is_empty());
    }
    #[tokio::test]
    #[ignore = "requires installed Chrome/Chromium and permission to launch its sandbox"]
    async fn browser_observes_dom_sink_and_blocks_secondary_requests() {
        let x=inspect(snapshot(r#"<script>document.write('<svg onload="__slurpXss(\'slurpBrowserTest123456\')"></svg>');fetch('http://127.0.0.1:5174/api/info');</script>"#)).await.unwrap();
        assert!(x.executed);
        assert!(x.sinks.contains(&"document.write".into()));
        assert!(x.blocked_requests > 0);
    }
    #[tokio::test]
    #[ignore = "requires installed Chrome/Chromium and permission to launch its sandbox"]
    async fn browser_does_not_attribute_sandboxed_frame_execution_to_the_page() {
        let s = snapshot(
            r#"<iframe sandbox="allow-scripts" srcdoc="&lt;script&gt;__slurpXss('slurpBrowserTest123456')&lt;/script&gt;"></iframe>"#,
        );
        assert!(!inspect(s).await.unwrap().executed);
    }
    #[tokio::test]
    #[ignore = "requires installed Chrome/Chromium and permission to launch its sandbox"]
    async fn browser_checks_fragment_sources_and_never_reaches_live_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut s = snapshot(&format!(
            r#"<div id="target"></div><script>
            target.innerHTML=decodeURIComponent(location.hash.slice(1));
            fetch('http://{address}/fetch');
            new WebSocket('ws://{address}/socket');
            navigator.sendBeacon('http://{address}/beacon','test');
            </script><img src="http://{address}/image"><iframe src="http://{address}/frame"></iframe>
            <script src="http://{address}/script"></script>"#
        ));
        s.url = format!(
            "http://{address}/initial#{}",
            reqwest::Url::parse("http://example.test")
                .unwrap()
                .query_pairs_mut()
                .append_pair(
                    "v",
                    "<svg onload=\"__slurpXss('slurpBrowserTest123456')\"></svg>"
                )
                .finish()
                .query()
                .unwrap()
                .strip_prefix("v=")
                .unwrap()
                .replace('+', "%20")
        );
        let x = inspect(s).await.unwrap();
        assert!(x.executed);
        assert!(x.sinks.contains(&"innerHTML".into()));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "The browser must never contact even a loopback target"
        );
    }
    #[tokio::test]
    #[ignore = "requires installed Chrome/Chromium and permission to launch its sandbox"]
    async fn browser_runs_captured_module_graph_and_preserves_script_policy() {
        let mut s =
            snapshot(r#"<div id="target"></div><script type="module" src="/main.js"></script>"#);
        s.url="http://localhost:8088/test?q=%3Csvg%20onload%3D%22__slurpXss(%27slurpBrowserTest123456%27)%22%3E%3C%2Fsvg%3E".into();
        s.resources=vec![
            ScriptResource{url:"http://localhost:8088/main.js".into(),body:"import { render } from './render.js';render(new URLSearchParams(location.search).get('q'));".into(),headers:BTreeMap::from([("Content-Type".into(),"application/javascript".into())])},
            ScriptResource{url:"http://localhost:8088/render.js".into(),body:"export function render(value) { document.getElementById('target').innerHTML=value; }".into(),headers:BTreeMap::from([("Content-Type".into(),"application/javascript".into())])}
        ];
        let x = inspect(s).await.unwrap();
        assert!(x.executed);
        assert!(x
            .sink_traces
            .iter()
            .any(|t| t.sink == "innerHTML" && t.stack.contains("render.js")));
        let mut s = snapshot(r#"<script src="/blocked.js"></script>"#);
        s.resources = vec![ScriptResource {
            url: "http://localhost:8088/blocked.js".into(),
            body: "__slurpXss('slurpBrowserTest123456')".into(),
            headers: BTreeMap::from([
                ("Content-Type".into(), "text/plain".into()),
                ("X-Content-Type-Options".into(), "nosniff".into()),
            ]),
        }];
        assert!(!inspect(s).await.unwrap().executed);
    }
    #[tokio::test]
    #[ignore = "requires installed Chrome/Chromium and permission to launch its sandbox"]
    async fn browser_confirms_code_and_navigation_contexts_with_controls() {
        for (code, parameter, payload) in [
            (
                "eval(new URLSearchParams(location.search).get('input'))",
                "input",
                "__slurpXss(/slurpBrowserTest123456/.source)",
            ),
            (
                "location.href=new URLSearchParams(location.search).get('next')",
                "next",
                "javascript:__slurpXss(/slurpBrowserTest123456/.source)",
            ),
        ] {
            for (value, expected) in [(payload, true), ("slurpBrowserTest123456", false)] {
                let mut s = snapshot(&format!("<script>{code}</script>"));
                let mut url = reqwest::Url::parse("http://localhost:8088/test").unwrap();
                url.query_pairs_mut().append_pair(parameter, value);
                s.url = url.to_string();
                assert_eq!(inspect(s).await.unwrap().executed, expected, "{code}");
            }
        }
    }
    #[tokio::test]
    #[ignore = "requires installed Chrome/Chromium and permission to launch its sandbox"]
    async fn browser_discovers_computed_dependencies_without_live_network() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let html = r#"<div id="target"></div><script>
            const chunk='lazy';const script=document.createElement('script');
            script.src='/'+chunk+'.js';document.head.append(script);
            fetch('/not-a-script');
            </script>"#;
        let make = |resources| {
            let mut s = snapshot(html);
            let mut url = reqwest::Url::parse(&format!("{origin}/test")).unwrap();
            url.query_pairs_mut().append_pair("q", "<img src=x onerror=\"__slurpXss('slurpBrowserTest123456')\">");
            s.url = url.to_string();
            s.resources = resources;
            s
        };
        let first = inspect(make(vec![])).await.unwrap();
        assert!(!first.executed);
        assert_eq!(first.requested_scripts, vec![format!("{origin}/lazy.js")]);
        let lazy = || ScriptResource {
            url: format!("{origin}/lazy.js"),
            body: "const dependency='render';import('/'+dependency+'.js').then(m=>m.render())".into(),
            headers: BTreeMap::from([("Content-Type".into(), "application/javascript".into())]),
        };
        let second = inspect(make(vec![lazy()])).await.unwrap();
        assert!(!second.executed);
        assert_eq!(second.requested_scripts, vec![format!("{origin}/render.js")]);
        let third = inspect(make(vec![lazy(), ScriptResource {
            url: format!("{origin}/render.js"),
            body: "export function render(){document.getElementById('target').innerHTML=new URLSearchParams(location.search).get('q')}".into(),
            headers: BTreeMap::from([("Content-Type".into(), "application/javascript".into())]),
        }])).await.unwrap();
        assert!(third.executed, "{}", serde_json::to_string(&third).unwrap());
        assert!(third.requested_scripts.is_empty());
        assert!(third.sink_traces.iter().any(|t|t.stack.contains("render.js")));
        assert!(tokio::time::timeout(Duration::from_millis(100), listener.accept()).await.is_err());
    }
    #[tokio::test]
    #[ignore = "requires installed Chrome/Chromium and permission to launch its sandbox"]
    async fn browser_interaction_confirms_input_click_flow_without_submitting_forms() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address=listener.local_addr().unwrap();
        let html=format!(r#"<form action="http://{address}/submit"><input id="search"><button onclick="document.getElementById('target').innerHTML=document.getElementById('search').value">Apply</button></form><div id="target"></div>"#);
        let payload="<img src=x onerror=\"__slurpXss('slurpBrowserTest123456')\">";
        assert!(!inspect(snapshot(&html)).await.unwrap().executed);
        for (value, expected) in [(payload,true),("slurpBrowserTest123456",false)] {
            let mut s=snapshot(&html);
            s.interaction=Some(Interaction{selector:Some("#search".into()),value:Some(value.into())});
            validate(&s).unwrap();
            let observed=inspect(s).await.unwrap();
            assert_eq!(observed.executed,expected);
            assert!(observed.interactions.iter().any(|a|a.contains("fill/input/change")));
        }
        let mut s=snapshot(&html);
        s.interaction=Some(Interaction{selector:Some("#search".into()),value:Some(payload.into())});
        s.headers.insert("Content-Security-Policy".into(),"script-src 'none'".into());
        assert!(!inspect(s).await.unwrap().executed);
        assert!(tokio::time::timeout(Duration::from_millis(100),listener.accept()).await.is_err());
    }
}
