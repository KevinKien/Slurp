//! Reverse-proxy mode: a listener that forwards every request to one fixed upstream, capturing it
//! like any other traffic. For clients that cannot be given a proxy (change the URL instead), an
//! API or webhook under test, or a service whose address you can only redirect.
use crate::ca::CertificateAuthority;
use crate::proxy::Shared;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

const MAX_RULES: usize = 32;

/// A saved reverse proxy: connections to `listen` are forwarded to `upstream`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub listen: SocketAddr,
    /// `http://host[:port]` or `https://host[:port]`, nothing else.
    pub upstream: String,
    /// Serve HTTPS on `listen`, with a certificate from Slurp's CA for the requested name.
    pub tls: bool,
    /// Send the upstream's own host as `Host`, which virtual hosts and most APIs require.
    pub rewrite_host: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleStatus {
    #[serde(flatten)]
    pub rule: Rule,
    pub running: bool,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRule {
    pub name: String,
    pub listen: SocketAddr,
    pub upstream: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default = "yes")]
    pub rewrite_host: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug)]
pub enum ReverseError {
    Invalid(String),
    NotFound,
    /// The listen address is taken or the rule would forward to itself.
    Conflict(String),
    Other(anyhow::Error),
}

impl std::fmt::Display for ReverseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) | Self::Conflict(m) => write!(f, "{m}"),
            Self::NotFound => write!(f, "reverse proxy not found"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReverseError {}

impl From<anyhow::Error> for ReverseError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

/// What a connection needs to know about its rule.
#[derive(Clone)]
pub(crate) struct Route {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub rewrite_host: bool,
    /// Certificate name when a TLS client sends no SNI (it connected by IP address).
    pub fallback_name: String,
}

/// Split and check an upstream URL.
pub(crate) fn parse_upstream(upstream: &str) -> Result<(bool, String, u16), ReverseError> {
    let bad = |m: &str| ReverseError::Invalid(m.to_string());
    let url = url::Url::parse(upstream.trim()).map_err(|_| bad("upstream must be a URL such as https://api.example.com"))?;
    let https = match url.scheme() {
        "https" => true,
        "http" => false,
        _ => return Err(bad("upstream must start with http:// or https://")),
    };
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
        return Err(bad("upstream must be scheme://host[:port] with no credentials, path or query"));
    }
    let host = url.host_str().filter(|h| !h.is_empty()).ok_or_else(|| bad("upstream has no host"))?.to_string();
    let port = url.port_or_known_default().filter(|p| *p != 0).ok_or_else(|| bad("upstream port must be 1-65535"))?;
    Ok((https, host, port))
}

/// Would an upstream of `host:port` land on this very listener?
fn points_at(listen: SocketAddr, host: &str, port: u16) -> bool {
    let host = host.trim_matches(['[', ']']);
    port == listen.port()
        && (host.eq_ignore_ascii_case("localhost")
            || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified() || ip == listen.ip() || listen.ip().is_unspecified()))
}

struct Inner {
    rules: Vec<Rule>,
    running: HashMap<String, JoinHandle<()>>,
    errors: HashMap<String, String>,
}

pub struct ReverseProxies {
    ca: Arc<CertificateAuthority>,
    shared: Shared,
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl Drop for ReverseProxies {
    /// Dropping the manager stops its listeners (open connections finish on their own).
    fn drop(&mut self) {
        for task in self.inner.get_mut().running.values() {
            task.abort();
        }
    }
}

static INSTALLED: StdMutex<Option<Arc<ReverseProxies>>> = StdMutex::new(None);

/// Make the manager reachable from the web API.
pub fn install(manager: Arc<ReverseProxies>) {
    *INSTALLED.lock().unwrap_or_else(|e| e.into_inner()) = Some(manager);
}

pub fn installed() -> Option<Arc<ReverseProxies>> {
    INSTALLED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

impl ReverseProxies {
    pub(crate) fn new(ca: Arc<CertificateAuthority>, shared: Shared, path: PathBuf) -> Arc<Self> {
        let rules = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<Vec<Rule>>(&text).unwrap_or_else(|e| {
                warn!("Ignoring {}: {e}", path.display());
                Vec::new()
            }),
            Err(_) => Vec::new(),
        };
        Arc::new(Self { ca, shared, path, inner: Mutex::new(Inner { rules, running: HashMap::new(), errors: HashMap::new() }) })
    }

    /// Start every enabled saved rule. A rule that cannot bind is reported, not fatal.
    pub async fn start_all(&self) {
        let mut inner = self.inner.lock().await;
        let ids: Vec<String> = inner.rules.iter().filter(|r| r.enabled).map(|r| r.id.clone()).collect();
        for id in ids {
            self.start_locked(&mut inner, &id).await;
        }
    }

    pub async fn list(&self) -> Vec<RuleStatus> {
        let inner = self.inner.lock().await;
        inner
            .rules
            .iter()
            .map(|rule| RuleStatus { running: inner.running.get(&rule.id).is_some_and(|t| !t.is_finished()), error: inner.errors.get(&rule.id).cloned(), rule: rule.clone() })
            .collect()
    }

    pub async fn add(&self, new: NewRule) -> Result<RuleStatus, ReverseError> {
        let name = new.name.trim().to_string();
        if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
            return Err(ReverseError::Invalid("name must be 1-60 characters".into()));
        }
        if new.listen.port() == 0 {
            return Err(ReverseError::Invalid("listen port must be 1-65535".into()));
        }
        let (_, host, port) = parse_upstream(&new.upstream)?;
        let mut inner = self.inner.lock().await;
        if inner.rules.len() >= MAX_RULES {
            return Err(ReverseError::Invalid(format!("at most {MAX_RULES} reverse proxies")));
        }
        if inner.rules.iter().any(|r| r.listen.port() == new.listen.port() && (r.listen.ip() == new.listen.ip() || r.listen.ip().is_unspecified() || new.listen.ip().is_unspecified())) {
            return Err(ReverseError::Conflict("another reverse proxy already uses this address".into()));
        }
        if points_at(new.listen, &host, port) || inner.rules.iter().any(|r| points_at(r.listen, &host, port)) {
            return Err(ReverseError::Conflict("the upstream is a Slurp reverse proxy listener: that would forward in a loop".into()));
        }
        let rule = Rule { id: uuid::Uuid::new_v4().to_string(), name, listen: new.listen, upstream: new.upstream.trim().trim_end_matches('/').to_string(), tls: new.tls, rewrite_host: new.rewrite_host, enabled: true };
        inner.rules.push(rule.clone());
        // Bind first so an address in use is reported to the caller instead of being saved.
        if let Err(error) = self.bind_locked(&mut inner, &rule).await {
            inner.rules.pop();
            return Err(ReverseError::Conflict(error));
        }
        self.save(&inner.rules)?;
        Ok(RuleStatus { running: true, error: None, rule })
    }

    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<RuleStatus, ReverseError> {
        let mut inner = self.inner.lock().await;
        let index = inner.rules.iter().position(|r| r.id == id).ok_or(ReverseError::NotFound)?;
        if enabled {
            let rule = inner.rules[index].clone();
            inner.errors.remove(id);
            if !inner.running.get(id).is_some_and(|t| !t.is_finished()) {
                self.bind_locked(&mut inner, &rule).await.map_err(ReverseError::Conflict)?;
            }
        } else if let Some(task) = inner.running.remove(id) {
            task.abort();
        }
        inner.rules[index].enabled = enabled;
        self.save(&inner.rules)?;
        let rule = inner.rules[index].clone();
        Ok(RuleStatus { running: enabled, error: None, rule })
    }

    pub async fn remove(&self, id: &str) -> Result<(), ReverseError> {
        let mut inner = self.inner.lock().await;
        let index = inner.rules.iter().position(|r| r.id == id).ok_or(ReverseError::NotFound)?;
        if let Some(task) = inner.running.remove(id) {
            task.abort();
        }
        inner.errors.remove(id);
        inner.rules.remove(index);
        self.save(&inner.rules)?;
        Ok(())
    }

    async fn start_locked(&self, inner: &mut Inner, id: &str) {
        let Some(rule) = inner.rules.iter().find(|r| r.id == id).cloned() else { return };
        match self.bind_locked(inner, &rule).await {
            Ok(()) => {}
            Err(error) => {
                warn!("Reverse proxy “{}” is not running: {error}", rule.name);
                inner.errors.insert(rule.id, error);
            }
        }
    }

    /// Bind the rule's address and serve it until aborted.
    async fn bind_locked(&self, inner: &mut Inner, rule: &Rule) -> Result<(), String> {
        let (https, host, port) = parse_upstream(&rule.upstream).map_err(|e| e.to_string())?;
        let listener = TcpListener::bind(rule.listen).await.map_err(|e| format!("cannot listen on {}: {e}", rule.listen))?;
        let route = Route { https, host, port, tls: rule.tls, rewrite_host: rule.rewrite_host, fallback_name: rule.listen.ip().to_string() };
        let (ca, shared, name) = (self.ca.clone(), self.shared.clone(), rule.name.clone());
        info!("🔁 Reverse proxy “{}”: {} → {}{}", rule.name, rule.listen, rule.upstream, if rule.tls { " (HTTPS listener)" } else { "" });
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else { break };
                let (route, ca, shared, name) = (route.clone(), ca.clone(), shared.clone(), name.clone());
                tokio::spawn(async move {
                    if let Err(e) = crate::proxy::handle_reverse(stream, route, ca, shared).await {
                        debug!("Reverse proxy “{name}” connection from {peer}: {e}");
                    }
                });
            }
        });
        if let Some(old) = inner.running.insert(rule.id.clone(), task) {
            old.abort();
        }
        Ok(())
    }

    fn save(&self, rules: &[Rule]) -> Result<(), ReverseError> {
        let write = || -> Result<()> {
            let temporary = self.path.with_extension("tmp");
            let _ = std::fs::remove_file(&temporary);
            crate::private_files::create(&temporary, serde_json::to_string_pretty(rules)?.as_bytes())?;
            std::fs::rename(&temporary, &self.path).with_context(|| format!("Cannot save {}", self.path.display()))?;
            Ok(())
        };
        write().map_err(ReverseError::Other)
    }
}
