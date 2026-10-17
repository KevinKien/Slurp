/// Intercept engine: hold requests/responses passing through the proxy so a user
/// can review or edit them before they are forwarded (or dropped).
///
/// The proxy calls `hold_request` / `hold_response`. With interception off these return
/// immediately. With it on they park the message in a queue, announce it to the UI over the
/// traffic event channel, and wait for `resolve` (forward / edit / drop) or the
/// client going away.
use crate::storage::{TrafficEvent, TrafficStorage};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::uri::PathAndQuery;
use hyper::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tokio::sync::oneshot;
use uuid::Uuid;

/// Bodies above this size (or that are not valid UTF-8) are shown but cannot be edited as text.
const MAX_EDITABLE_BODY: usize = 1024 * 1024;

/// Which kinds of message are currently held. Both are off when the proxy starts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptSettings {
    pub requests: bool,
    pub responses: bool,
}

/// Partial update for `InterceptSettings`; absent fields are left unchanged.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct SettingsUpdate {
    pub requests: Option<bool>,
    pub responses: Option<bool>,
}

/// Exact hostnames shared by History filtering and interception.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeSettings {
    pub enabled: bool,
    pub domains: Vec<String>,
}
impl ScopeSettings {
    pub fn matches(&self, host: &str) -> bool {
        !self.enabled || self.domains.is_empty() || self.domains.iter().any(|domain| domain.eq_ignore_ascii_case(host.trim_end_matches('.')))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Request,
    Response,
}

/// An HTTP request as it will be sent upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestParts {
    pub method: String,
    /// Path and query, e.g. `/api/items?limit=2`.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// An HTTP response as it will be returned to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseParts {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Where the held message is going, used for display and for response-phase context.
#[derive(Debug, Clone)]
pub struct HoldContext {
    pub request: Option<RequestParts>,
    pub scheme: String,
    pub host: String,
    /// Display URL of the request, e.g. `https://api.example.com/v1/items`.
    pub url: String,
    pub method: String,
    pub path: String,
}

/// Original request for actions on a response held before history has been written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSnapshot {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// A held message as shown to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldItem {
    #[serde(default, skip_serializing_if="Option::is_none")]
    pub websocket: Option<crate::websocket::Frame>,
    pub request: Option<RequestSnapshot>,
    pub id: String,
    pub phase: Phase,
    pub created_at: DateTime<Utc>,
    pub scheme: String,
    pub host: String,
    pub url: String,
    /// Request method (for responses: the method of the request that produced it).
    pub method: String,
    /// Request path and query (for responses: of the originating request).
    pub path: String,
    /// Response status; `None` for requests.
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    /// Body text, present only when `body_editable`.
    pub body: Option<String>,
    pub body_size: usize,
    /// False for binary or very large bodies: they are forwarded unchanged.
    pub body_editable: bool,
}

/// Edits submitted by the user. Absent fields keep the original value.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Edit {
    // request
    pub method: Option<String>,
    pub path: Option<String>,
    // response
    pub status: Option<u16>,
    // both
    pub headers: Option<Vec<(String, String)>>,
    pub body: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Action {
    /// Forward, applying the edit if there is one.
    Forward(Option<Edit>),
    Drop,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    NotFound,
    /// The edit is not a valid HTTP message; the item stays held so it can be fixed.
    Invalid(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "this item is no longer held (it may have timed out or been forwarded)"),
            Self::Invalid(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ResolveError {}

enum Kind {
    WebSocket { tx: oneshot::Sender<bool> },
    Request {
        base: RequestParts,
        tx: oneshot::Sender<Option<RequestParts>>,
    },
    Response {
        base: ResponseParts,
        tx: oneshot::Sender<Option<ResponseParts>>,
    },
}

struct Held {
    item: HeldItem,
    kind: Kind,
}

pub struct Intercept {
    storage: Arc<TrafficStorage>,
    settings: RwLock<InterceptSettings>,
    scope: RwLock<ScopeSettings>,
    held: DashMap<String, Held>,
}

/// Removes the held entry when the waiting proxy task ends for any reason
/// (resolved, or the client disconnected and the task was cancelled).
struct ReleaseGuard<'a> {
    owner: &'a Intercept,
    id: String,
}

impl Drop for ReleaseGuard<'_> {
    fn drop(&mut self) {
        // `resolve` removes first and announces itself; only announce if we were the one to remove.
        if self.owner.held.remove(&self.id).is_some() {
            self.owner.announce_resolved(&self.id);
        }
    }
}

impl Intercept {
    pub fn new(storage: Arc<TrafficStorage>) -> Arc<Self> {
        Arc::new(Self {
            storage,
            settings: RwLock::new(InterceptSettings::default()),
            scope: RwLock::new(ScopeSettings::default()),
            held: DashMap::new(),
        })
    }

    pub fn settings(&self) -> InterceptSettings {
        self.settings.read().map(|s| *s).unwrap_or_default()
    }

    pub fn scope(&self) -> ScopeSettings {
        self.scope.read().unwrap_or_else(|e|e.into_inner()).clone()
    }

    pub fn update_scope(&self, mut scope: ScopeSettings) -> Result<ScopeSettings, String> {
        if scope.domains.len() > 100 { return Err("At most 100 scope domains".into()); }
        for domain in &mut scope.domains {
            *domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if domain.is_empty() || domain.len()>253 || domain.split('.').any(|label|label.is_empty() || label.len()>63 || label.starts_with('-') || label.ends_with('-') || !label.bytes().all(|c|c.is_ascii_alphanumeric() || c==b'-')) {
                return Err("Enter valid hostnames only".into());
            }
        }
        scope.domains.sort();scope.domains.dedup();
        *self.scope.write().unwrap_or_else(|e|e.into_inner())=scope.clone();
        self.storage.publish(TrafficEvent::ScopeChanged { scope:scope.clone() });
        // Release traffic excluded by the new scope unchanged, rather than hiding held items.
        let ids:Vec<_>=self.held.iter().filter(|item|!scope.matches(&item.item.host)).map(|item|item.key().clone()).collect();
        for id in ids { let _=self.resolve(&id,Action::Forward(None)); }
        Ok(scope)
    }

    /// Currently held items, oldest first.
    pub fn list(&self) -> Vec<HeldItem> {
        let mut items: Vec<HeldItem> = self.held.iter().map(|e| e.item.clone()).collect();
        items.sort_by_key(|i| i.created_at);
        items
    }

    /// Update the settings. Turning a kind off releases everything of that kind that is
    /// still held (unchanged), so no client is left waiting on a feature that is now off.
    pub fn update_settings(&self, update: SettingsUpdate) -> InterceptSettings {
        let new = {
            let mut s = self.settings.write().unwrap_or_else(|e| e.into_inner());
            if let Some(v) = update.requests {
                s.requests = v;
            }
            if let Some(v) = update.responses {
                s.responses = v;
            }
            *s
        };
        self.storage.publish(TrafficEvent::InterceptSettings {
            requests: new.requests,
            responses: new.responses,
        });
        for phase in [Phase::Request, Phase::Response] {
            let off = match phase {
                Phase::Request => !new.requests,
                Phase::Response => !new.responses,
            };
            if off {
                self.release_phase(phase);
            }
        }
        new
    }

    /// Forward every held item unchanged.
    pub fn forward_all(&self) {
        self.release_phase(Phase::Request);
        self.release_phase(Phase::Response);
    }

    fn release_phase(&self, phase: Phase) {
        let ids: Vec<String> = self.held.iter().filter(|e| e.item.phase == phase).map(|e| e.key().clone()).collect();
        for id in ids {
            let _ = self.resolve(&id, Action::Forward(None));
        }
    }

    fn announce_resolved(&self, id: &str) {
        self.storage.publish(TrafficEvent::InterceptResolved { id: id.to_string() });
    }

    /// Hold a request if request interception is on. Returns the request to forward
    /// (possibly edited), or `None` if it was dropped or the client went away.
    pub async fn hold_request(&self, ctx: &HoldContext, parts: RequestParts) -> Option<RequestParts> {
        if !self.settings().requests || !self.scope().matches(&ctx.host) {
            return Some(parts);
        }
        let (tx, rx) = oneshot::channel();
        let id = Uuid::new_v4().to_string();
        let item = request_item(&id, ctx, &parts);
        self.held.insert(id.clone(), Held { item: item.clone(), kind: Kind::Request { base: parts.clone(), tx } });
        let _guard = ReleaseGuard { owner: self, id: id.clone() };
        self.storage.publish(TrafficEvent::InterceptQueued { item });
        // Interception may have been switched off between the check above and the insert.
        if !self.settings().requests || !self.scope().matches(&ctx.host) {
            return Some(parts);
        }
        match rx.await {
            Ok(decision) => decision,
            _ => None,
        }
    }

    /// Hold a response if response interception is on. See `hold_request`.
    pub async fn hold_response(&self, ctx: &HoldContext, parts: ResponseParts) -> Option<ResponseParts> {
        if !self.settings().responses || !self.scope().matches(&ctx.host) {
            return Some(parts);
        }
        let (tx, rx) = oneshot::channel();
        let id = Uuid::new_v4().to_string();
        let item = response_item(&id, ctx, &parts);
        self.held.insert(id.clone(), Held { item: item.clone(), kind: Kind::Response { base: parts.clone(), tx } });
        let _guard = ReleaseGuard { owner: self, id: id.clone() };
        self.storage.publish(TrafficEvent::InterceptQueued { item });
        if !self.settings().responses || !self.scope().matches(&ctx.host) {
            return Some(parts);
        }
        match rx.await {
            Ok(decision) => decision,
            _ => None,
        }
    }

    /// Hold a frame preview before any of its wire bytes reach the peer.
    pub async fn hold_websocket_frame(&self, ctx: &HoldContext, frame: crate::websocket::Frame) -> bool {
        let phase=if frame.direction=="client_to_server" {Phase::Request}else{Phase::Response};
        let enabled=|| match phase {Phase::Request=>self.settings().requests,Phase::Response=>self.settings().responses} && self.scope().matches(&ctx.host);
        if !enabled() {return true;}
        let id=Uuid::new_v4().to_string();let(tx,rx)=oneshot::channel();
        let item=HeldItem {websocket:Some(frame.clone()),request:ctx.request.as_ref().map(|r|RequestSnapshot{method:r.method.clone(),url:ctx.url.clone(),headers:r.headers.clone(),body:body_view(&r.body).0}),id:id.clone(),phase,created_at:Utc::now(),scheme:ctx.scheme.clone(),host:ctx.host.clone(),url:ctx.url.clone(),method:"WS".into(),path:ctx.path.clone(),status:None,headers:vec![],body:frame.text.clone(),body_size:usize::try_from(frame.size).unwrap_or(usize::MAX),body_editable:false};
        self.held.insert(id.clone(),Held{item:item.clone(),kind:Kind::WebSocket{tx}});
        let _guard=ReleaseGuard{owner:self,id:id.clone()};self.storage.publish(TrafficEvent::InterceptQueued{item});
        if !enabled() {return true;}
        rx.await.unwrap_or(false)
    }

    /// Forward (optionally edited) or drop a held item. An invalid edit is rejected and the
    /// item stays held.
    pub fn resolve(&self, id: &str, action: Action) -> Result<(), ResolveError> {
        // Validate against the held item first, without removing it.
        enum Prepared {
            WebSocket,
            Drop,
            Request(RequestParts),
            Response(ResponseParts),
        }
        let prepared = {
            let held = self.held.get(id).ok_or(ResolveError::NotFound)?;
            match (&held.kind, &action) {
                (_, Action::Drop) => Prepared::Drop,
                (Kind::WebSocket {..}, Action::Forward(edit)) => {
                    if edit.is_some() {return Err(ResolveError::Invalid("WebSocket frames can be forwarded unchanged or dropped; send edits through Replay".into()));}
                    Prepared::WebSocket
                },
                (Kind::Request { base, .. }, Action::Forward(edit)) => {
                    Prepared::Request(match edit {
                        Some(e) => apply_request_edit(base, e).map_err(ResolveError::Invalid)?,
                        None => base.clone(),
                    })
                }
                (Kind::Response { base, .. }, Action::Forward(edit)) => {
                    Prepared::Response(match edit {
                        Some(e) => apply_response_edit(base, e).map_err(ResolveError::Invalid)?,
                        None => base.clone(),
                    })
                }
            }
        };

        let (_, held) = self.held.remove(id).ok_or(ResolveError::NotFound)?;
        // The receiver is gone if the client disconnected meanwhile; nothing more to do then.
        match (held.kind, prepared) {
            (Kind::WebSocket {tx}, Prepared::WebSocket)=>{let _=tx.send(true);},
            (Kind::WebSocket {tx}, Prepared::Drop)=>{let _=tx.send(false);},
            (Kind::Request { tx, .. }, Prepared::Request(p)) => {
                let _ = tx.send(Some(p));
            }
            (Kind::Request { tx, .. }, Prepared::Drop) => {
                let _ = tx.send(None);
            }
            (Kind::Response { tx, .. }, Prepared::Response(p)) => {
                let _ = tx.send(Some(p));
            }
            (Kind::Response { tx, .. }, Prepared::Drop) => {
                let _ = tx.send(None);
            }
            // Prepared always matches the kind it was built from.
            _ => {}
        }
        self.announce_resolved(id);
        Ok(())
    }
}

fn body_view(body: &[u8]) -> (Option<String>, bool) {
    if body.len() <= MAX_EDITABLE_BODY {
        if let Ok(text) = std::str::from_utf8(body) {
            return (Some(text.to_string()), true);
        }
    }
    (None, false)
}

fn request_item(id: &str, ctx: &HoldContext, parts: &RequestParts) -> HeldItem {
    let (body, body_editable) = body_view(&parts.body);
    HeldItem {
        websocket: None,
        id: id.to_string(),
        phase: Phase::Request,
        request: None,
        created_at: Utc::now(),
        scheme: ctx.scheme.clone(),
        host: ctx.host.clone(),
        url: ctx.url.clone(),
        method: parts.method.clone(),
        path: parts.path.clone(),
        status: None,
        headers: parts.headers.clone(),
        body,
        body_size: parts.body.len(),
        body_editable,
    }
}

fn response_item(id: &str, ctx: &HoldContext, parts: &ResponseParts) -> HeldItem {
    let (body, body_editable) = body_view(&parts.body);
    HeldItem {
        websocket: None,
        id: id.to_string(),
        phase: Phase::Response,
        request: ctx.request.as_ref().map(|request|RequestSnapshot {
            method:request.method.clone(),url:ctx.url.clone(),headers:request.headers.clone(),body:body_view(&request.body).0,
        }),
        created_at: Utc::now(),
        scheme: ctx.scheme.clone(),
        host: ctx.host.clone(),
        url: ctx.url.clone(),
        method: ctx.method.clone(),
        path: ctx.path.clone(),
        status: Some(parts.status),
        headers: parts.headers.clone(),
        body,
        body_size: parts.body.len(),
        body_editable,
    }
}

/// Check that every header can actually be put on the wire.
fn validate_headers(headers: &[(String, String)]) -> Result<(), String> {
    for (name, value) in headers {
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| format!("Invalid header name: \"{name}\""))?;
        HeaderValue::from_bytes(value.as_bytes()).map_err(|_| format!("Invalid value for header \"{name}\""))?;
    }
    Ok(())
}

pub fn apply_request_edit(base: &RequestParts, edit: &Edit) -> Result<RequestParts, String> {
    let mut out = base.clone();
    if let Some(method) = &edit.method {
        let method = method.trim().to_ascii_uppercase();
        let parsed = Method::from_bytes(method.as_bytes()).map_err(|_| format!("Invalid method: \"{method}\""))?;
        if parsed == Method::CONNECT {
            return Err("CONNECT cannot be sent as a replacement method".into());
        }
        out.method = method;
    }
    if let Some(path) = &edit.path {
        if !path.starts_with('/') {
            return Err("The request path must start with /".into());
        }
        path.parse::<PathAndQuery>().map_err(|_| format!("Invalid request path: \"{path}\""))?;
        out.path = path.clone();
    }
    if let Some(headers) = &edit.headers {
        validate_headers(headers)?;
        out.headers = headers.clone();
    }
    if let Some(body) = &edit.body {
        out.body = body.clone().into_bytes();
    }
    Ok(out)
}

pub fn apply_response_edit(base: &ResponseParts, edit: &Edit) -> Result<ResponseParts, String> {
    let mut out = base.clone();
    if let Some(status) = edit.status {
        if !(200..=599).contains(&status) || StatusCode::from_u16(status).is_err() {
            return Err(format!("Invalid status code: {status} (use 200-599)"));
        }
        out.status = status;
    }
    if let Some(headers) = &edit.headers {
        validate_headers(headers)?;
        out.headers = headers.clone();
    }
    if let Some(body) = &edit.body {
        out.body = body.clone().into_bytes();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::TrafficStorage;
    use std::time::Duration;

    fn setup() -> (Arc<TrafficStorage>, Arc<Intercept>) {
        let storage = TrafficStorage::new(":memory:", 1024).unwrap();
        let intercept = Intercept::new(storage.clone());
        (storage, intercept)
    }

    fn ctx() -> HoldContext {
        HoldContext {
            request: None,
            scheme: "https".into(),
            host: "api.example.com".into(),
            url: "https://api.example.com/v1/items".into(),
            method: "GET".into(),
            path: "/v1/items".into(),
        }
    }

    fn req() -> RequestParts {
        RequestParts {
            method: "GET".into(),
            path: "/v1/items".into(),
            headers: vec![("host".into(), "api.example.com".into()), ("x-a".into(), "1".into())],
            body: b"hello".to_vec(),
        }
    }

    fn res() -> ResponseParts {
        ResponseParts { status: 200, headers: vec![("content-type".into(), "text/plain".into())], body: b"ok".to_vec() }
    }

    /// Wait until an item is held and return its id.
    async fn held_id(i: &Arc<Intercept>) -> String {
        for _ in 0..200 {
            if let Some(item) = i.list().first() {
                return item.id.clone();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("nothing was held");
    }

    #[tokio::test]
    async fn passes_straight_through_when_off() {
        let (_s, i) = setup();
        assert_eq!(i.hold_request(&ctx(), req()).await, Some(req()));
        assert_eq!(i.hold_response(&ctx(), res()).await, Some(res()));
        assert!(i.list().is_empty());
    }

    #[tokio::test]
    async fn holds_until_forwarded_unchanged() {
        let (_s, i) = setup();
        i.update_settings(SettingsUpdate { requests: Some(true), responses: None });
        let i2 = i.clone();
        let task = tokio::spawn(async move { i2.hold_request(&ctx(), req()).await });
        let id = held_id(&i).await;
        let item = &i.list()[0];
        assert_eq!(item.phase, Phase::Request);
        assert_eq!(item.body.as_deref(), Some("hello"));

        i.resolve(&id, Action::Forward(None)).unwrap();
        assert_eq!(task.await.unwrap(), Some(req()));
        assert!(i.list().is_empty());
    }

    #[tokio::test]
    async fn applies_request_edits() {
        let (_s, i) = setup();
        i.update_settings(SettingsUpdate { requests: Some(true), responses: None });
        let i2 = i.clone();
        let task = tokio::spawn(async move { i2.hold_request(&ctx(), req()).await });
        let id = held_id(&i).await;
        let edit = Edit {
            method: Some("post".into()),
            path: Some("/v2/other?x=1".into()),
            headers: Some(vec![("x-b".into(), "2".into())]),
            body: Some("changed".into()),
            ..Default::default()
        };
        i.resolve(&id, Action::Forward(Some(edit))).unwrap();
        let got = task.await.unwrap().unwrap();
        assert_eq!(got.method, "POST");
        assert_eq!(got.path, "/v2/other?x=1");
        assert_eq!(got.headers, vec![("x-b".to_string(), "2".to_string())]);
        assert_eq!(got.body, b"changed");
    }

    #[tokio::test]
    async fn applies_response_edits_and_keeps_unedited_fields() {
        let (_s, i) = setup();
        i.update_settings(SettingsUpdate { requests: None, responses: Some(true) });
        let i2 = i.clone();
        let task = tokio::spawn(async move { i2.hold_response(&ctx(), res()).await });
        let id = held_id(&i).await;
        assert_eq!(i.list()[0].status, Some(200));
        let edit = Edit { status: Some(418), body: Some("teapot".into()), ..Default::default() };
        i.resolve(&id, Action::Forward(Some(edit))).unwrap();
        let got = task.await.unwrap().unwrap();
        assert_eq!(got.status, 418);
        assert_eq!(got.body, b"teapot");
        assert_eq!(got.headers, res().headers);
    }

    #[tokio::test]
    async fn drop_returns_none() {
        let (_s, i) = setup();
        i.update_settings(SettingsUpdate { requests: Some(true), responses: None });
        let i2 = i.clone();
        let task = tokio::spawn(async move { i2.hold_request(&ctx(), req()).await });
        let id = held_id(&i).await;
        i.resolve(&id, Action::Drop).unwrap();
        assert_eq!(task.await.unwrap(), None);
    }

    #[tokio::test]
    async fn invalid_edit_is_rejected_and_item_stays_held() {
        let (_s, i) = setup();
        i.update_settings(SettingsUpdate { requests: Some(true), responses: None });
        let i2 = i.clone();
        let task = tokio::spawn(async move { i2.hold_request(&ctx(), req()).await });
        let id = held_id(&i).await;

        for bad in [
            Edit { path: Some("no-slash".into()), ..Default::default() },
            Edit { method: Some("BAD METHOD".into()), ..Default::default() },
            Edit { method: Some("CONNECT".into()), ..Default::default() },
            Edit { headers: Some(vec![("bad name".into(), "v".into())]), ..Default::default() },
            Edit { headers: Some(vec![("ok".into(), "line\r\nbreak".into())]), ..Default::default() },
        ] {
            assert!(matches!(i.resolve(&id, Action::Forward(Some(bad))), Err(ResolveError::Invalid(_))));
        }
        assert_eq!(i.list().len(), 1, "still held after rejected edits");

        i.resolve(&id, Action::Forward(None)).unwrap();
        assert_eq!(task.await.unwrap(), Some(req()));
    }

    #[tokio::test]
    async fn response_status_must_be_valid() {
        let base = res();
        assert!(apply_response_edit(&base, &Edit { status: Some(99), ..Default::default() }).is_err());
        assert!(apply_response_edit(&base, &Edit { status: Some(600), ..Default::default() }).is_err());
        assert_eq!(apply_response_edit(&base, &Edit { status: Some(503), ..Default::default() }).unwrap().status, 503);
    }

    #[tokio::test]
    async fn unknown_or_already_resolved_ids_are_not_found() {
        let (_s, i) = setup();
        assert_eq!(i.resolve("nope", Action::Drop), Err(ResolveError::NotFound));
    }

    #[tokio::test(start_paused = true)]
    async fn requests_and_responses_stay_held_beyond_the_previous_timeout() {
        let (_s, i) = setup();
        i.update_settings(SettingsUpdate { requests: Some(true), responses: Some(true) });
        let a = i.clone();
        let request = tokio::spawn(async move { a.hold_request(&ctx(), req()).await });
        let request_id = held_id(&i).await;
        let b = i.clone();
        let response = tokio::spawn(async move { b.hold_response(&ctx(), res()).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3600)).await;
        tokio::task::yield_now().await;
        assert!(!request.is_finished());
        assert!(!response.is_finished());
        assert_eq!(i.list().len(), 2);
        let response_id = i.list().into_iter().find(|item| item.phase == Phase::Response).unwrap().id;
        i.resolve(&request_id, Action::Forward(None)).unwrap();
        i.resolve(&response_id, Action::Forward(None)).unwrap();
        assert_eq!(request.await.unwrap(), Some(req()));
        assert_eq!(response.await.unwrap(), Some(res()));
        assert!(i.list().is_empty());
    }

    #[tokio::test]
    async fn scope_only_holds_matching_requests_and_responses() {
        let (_s, i) = setup();
        i.update_settings(SettingsUpdate { requests:Some(true),responses:Some(true) });
        i.update_scope(ScopeSettings {enabled:true,domains:vec![" API.EXAMPLE.COM. ".into()]}).unwrap();
        let mut outside=ctx();outside.host="other.example.com".into();
        assert_eq!(i.hold_request(&outside,req()).await,Some(req()));
        assert_eq!(i.hold_response(&outside,res()).await,Some(res()));
        assert!(i.list().is_empty());
        let a=i.clone();let request=tokio::spawn(async move{a.hold_request(&ctx(),req()).await});
        let _=held_id(&i).await;
        let b=i.clone();let response=tokio::spawn(async move{b.hold_response(&ctx(),res()).await});
        tokio::task::yield_now().await;
        assert_eq!(i.list().len(),2);
        i.update_scope(ScopeSettings {enabled:true,domains:vec!["other.example.com".into()]}).unwrap();
        assert_eq!(request.await.unwrap(),Some(req()));
        assert_eq!(response.await.unwrap(),Some(res()));
        assert!(i.list().is_empty());
    }

    #[test]
    fn held_response_carries_the_originating_request_for_context_actions() {
        let request=req();
        let mut context=ctx(); context.request=Some(request.clone());
        let held=response_item("response",&context,&res());
        let snapshot=held.request.unwrap();
        assert_eq!(snapshot.method,request.method);
        assert_eq!(snapshot.headers,request.headers);
        assert_eq!(snapshot.url,context.url);
        assert_eq!(snapshot.body,Some(String::from_utf8(request.body).unwrap()));
    }

    #[test]
    fn scope_validation_and_disabled_scope() {
        let (_s,i)=setup();
        assert!(i.update_scope(ScopeSettings {enabled:true,domains:vec!["https://example.com".into()]}).is_err());
        assert_eq!(i.scope(),ScopeSettings::default());
        assert!(ScopeSettings {enabled:false,domains:vec!["example.com".into()]}.matches("other.example.com"));
        assert!(ScopeSettings {enabled:true,domains:vec![]}.matches("any.example.com"));
        assert!(!ScopeSettings {enabled:true,domains:vec!["example.com".into()]}.matches("sub.example.com"));
    }

    #[tokio::test]
    async fn client_disconnect_removes_the_held_item() {
        let (_s, i) = setup();
        i.update_settings(SettingsUpdate { requests: Some(true), responses: None });
        let i2 = i.clone();
        let task = tokio::spawn(async move { i2.hold_request(&ctx(), req()).await });
        let _ = held_id(&i).await;
        task.abort(); // hyper cancels the service future when the client hangs up
        let _ = task.await;
        assert!(i.list().is_empty());
    }

    #[tokio::test]
    async fn turning_a_kind_off_releases_its_held_items_unchanged() {
        let (_s, i) = setup();
        i.update_settings(SettingsUpdate { requests: Some(true), responses: Some(true) });
        let (a, b) = (i.clone(), i.clone());
        let t_req = tokio::spawn(async move { a.hold_request(&ctx(), req()).await });
        let t_res = tokio::spawn(async move { b.hold_response(&ctx(), res()).await });
        for _ in 0..200 {
            if i.list().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(i.list().len(), 2);

        i.update_settings(SettingsUpdate { requests: Some(false), responses: None });
        assert_eq!(t_req.await.unwrap(), Some(req()));
        assert_eq!(i.list().len(), 1, "responses are still held");

        i.forward_all();
        assert_eq!(t_res.await.unwrap(), Some(res()));
        assert!(i.list().is_empty());
    }

    #[tokio::test]
    async fn binary_and_oversized_bodies_are_not_editable() {
        let mut p = req();
        p.body = vec![0xff, 0xfe, 0x00];
        let item = request_item("x", &ctx(), &p);
        assert!(!item.body_editable && item.body.is_none() && item.body_size == 3);
        p.body = vec![b'a'; MAX_EDITABLE_BODY + 1];
        assert!(!request_item("x", &ctx(), &p).body_editable);
    }

    #[tokio::test]
    async fn publishes_events() {
        let (s, i) = setup();
        let mut rx = s.subscribe();
        i.update_settings(SettingsUpdate { requests: Some(true), responses: None });
        assert!(matches!(rx.recv().await.unwrap(), TrafficEvent::InterceptSettings { requests: true, responses: false }));
        let i2 = i.clone();
        let task = tokio::spawn(async move { i2.hold_request(&ctx(), req()).await });
        assert!(matches!(rx.recv().await.unwrap(), TrafficEvent::InterceptQueued { .. }));
        let id = held_id(&i).await;
        i.resolve(&id, Action::Drop).unwrap();
        let _ = task.await;
        match rx.recv().await.unwrap() {
            TrafficEvent::InterceptResolved { id: got } => assert_eq!(got, id),
            other => panic!("unexpected event {other:?}"),
        }
    }
}
