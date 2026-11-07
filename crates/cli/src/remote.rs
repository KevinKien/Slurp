//! `slurp server` and `slurp client`: capture on one machine, review on another.
use anyhow::{bail, Context, Result};
use proxy_core::{CertificateAuthority, Intercept, ProxyConfig, ProxyServer, TrafficStorage, DEFAULT_WORKSPACE_ID};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use web_server::capture_client::{self, ClientConfig};

pub const SERVER_USAGE: &str = "usage: slurp server [--bind HOST:PORT] [--public-url https://HOST] [--allow-insecure-http]";
pub const CLIENT_USAGE: &str = "usage: slurp client --server https://HOST (--scope host,*.domain | --all) [--token TOKEN] [--redact] [--proxy HOST:PORT] [--ca-cert FILE] [--allow-insecure-http]\n       the token can also be given as SLURP_CLIENT_TOKEN";

fn init_logging() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?).add_directive("hyper=warn".parse()?).add_directive("rustls=warn".parse()?))
        .init();
    Ok(())
}

/// Splits `--flag value` / `--switch` arguments; every flag must be listed.
fn parse<'a>(args: &'a [String], with_value: &[&str], switches: &[&str], usage: &str) -> Result<(std::collections::HashMap<&'a str, &'a str>, Vec<&'a str>)> {
    let mut values = std::collections::HashMap::new();
    let mut flags = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if with_value.contains(&arg.as_str()) {
            let value = iter.next().with_context(|| format!("{arg} needs a value\n{usage}"))?;
            values.insert(arg.as_str(), value.as_str());
        } else if switches.contains(&arg.as_str()) {
            flags.push(arg.as_str());
        } else {
            bail!("unknown argument: {arg}\n{usage}");
        }
    }
    Ok((values, flags))
}

pub async fn server(args: &[String]) -> Result<()> {
    let (values, flags) = parse(args, &["--bind", "--public-url"], &["--allow-insecure-http"], SERVER_USAGE)?;
    init_logging()?;
    let bind: std::net::SocketAddr = match values.get("--bind") {
        Some(value) => value.parse().with_context(|| format!("--bind {value:?} is not a valid host:port address"))?,
        None => crate::env_addr("SLURP_API_ADDR", "127.0.0.1:5174")?,
    };
    if let Some(url) = values.get("--public-url") {
        // The Host/Origin guard reads this to accept requests that arrive via the public address.
        std::env::set_var("SLURP_PUBLIC_URL", url);
    }
    let public_url = std::env::var("SLURP_PUBLIC_URL").ok().filter(|v| !v.trim().is_empty());
    if !bind.ip().is_loopback() && !public_url.as_deref().is_some_and(|u| u.starts_with("https://")) && !flags.contains(&"--allow-insecure-http") {
        bail!(
            "Refusing to listen on {bind} without HTTPS: tokens and captured traffic would cross the network in clear text.\n\
             Put a TLS reverse proxy (Caddy, nginx) in front and pass --public-url https://your.domain,\n\
             or bind to 127.0.0.1 behind a tunnel. Use --allow-insecure-http only on a trusted network."
        );
    }

    println!("\n    Slurp server\n");
    let dir = crate::data_dir(&crate::dirs_home()?)?;
    proxy_core::trust::init(dir.join("trusted-cas"))?;
    let access = web_server::access::ApiAccess::load(&dir)?;
    let storage = TrafficStorage::new(dir.join("traffic.db").to_str().unwrap_or(":memory:"), 10 * 1024 * 1024)?;
    // Nothing is captured here, so there is no workspace prompt: uploads go to each client's workspace.
    storage.set_active_workspace(DEFAULT_WORKSPACE_ID)?;
    let intercept = Intercept::new(storage.clone());
    let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("Failed to bind to {bind}"))?;
    let address = listener.local_addr()?;
    let mut browser = address;
    if browser.ip().is_unspecified() {
        browser.set_ip(if browser.is_ipv4() { std::net::Ipv4Addr::LOCALHOST.into() } else { std::net::Ipv6Addr::LOCALHOST.into() });
    }
    let base = public_url.as_deref().map(|u| u.trim_end_matches('/').to_string()).unwrap_or_else(|| format!("http://{browser}"));
    println!("🚀 Slurp server is running (no proxy; capture clients upload traffic here)");
    println!("   UI:      {base}/dashboard#slurp-token={}", access.token());
    println!("   Listen:  http://{address}");
    println!("   Create capture clients under Workspaces → Capture clients.");
    println!("   Keep the token in the UI link private: it grants full access to this server.\n");
    web_server::serve(listener, storage, intercept, proxy_core::ProxyControl::disabled(), web_server::certificate::PublicCaCertificate(Arc::from(Vec::new())), access).await
}

pub async fn client(args: &[String]) -> Result<()> {
    let (values, flags) = parse(args, &["--server", "--token", "--scope", "--proxy", "--ca-cert"], &["--all", "--redact", "--allow-insecure-http"], CLIENT_USAGE)?;
    let server = values.get("--server").context(format!("--server is required\n{CLIENT_USAGE}"))?.to_string();
    let token = match values.get("--token") {
        Some(token) => token.to_string(),
        None => std::env::var("SLURP_CLIENT_TOKEN").ok().filter(|t| !t.is_empty()).context(format!("a capture token is required (--token or SLURP_CLIENT_TOKEN)\n{CLIENT_USAGE}"))?,
    };
    let scope = match (values.get("--scope"), flags.contains(&"--all")) {
        (Some(_), true) => bail!("use either --scope or --all\n{CLIENT_USAGE}"),
        (Some(list), false) => {
            let hosts: Vec<String> = list.split(',').map(|h| h.trim().to_string()).filter(|h| !h.is_empty()).collect();
            if hosts.is_empty() {
                bail!("--scope needs at least one host\n{CLIENT_USAGE}");
            }
            Some(hosts)
        }
        (None, true) => None,
        (None, false) => bail!("choose what to upload: --scope host1,*.domain2 or --all (everything this machine proxies)\n{CLIENT_USAGE}"),
    };
    init_logging()?;
    let ca_cert = match values.get("--ca-cert") {
        Some(path) => Some(std::fs::read(path).with_context(|| format!("Cannot read --ca-cert {path}"))?),
        None => None,
    };
    let config = ClientConfig { server, token, scope, redact: flags.contains(&"--redact"), allow_insecure: flags.contains(&"--allow-insecure-http"), ca_cert };

    println!("\n    Slurp client\n");
    proxy_core::trust::init(crate::data_dir(&crate::dirs_home()?)?.join("trusted-cas"))?;
    let hello = capture_client::hello(&config).await?;

    let dir = crate::data_dir(&crate::dirs_home()?)?;
    let ca = Arc::new(CertificateAuthority::load_or_create(&dir)?);
    ca.print_install_instructions();
    // Separate from the standalone database so local history is never uploaded by accident.
    let spool_dir = dir.join("client");
    proxy_core::private_files::directory(&spool_dir)?;
    let storage = TrafficStorage::new(spool_dir.join("spool.db").to_str().unwrap_or(":memory:"), 10 * 1024 * 1024)?;
    storage.set_active_workspace(DEFAULT_WORKSPACE_ID)?;
    let intercept = Intercept::new(storage.clone());

    let proxy_addr: std::net::SocketAddr = match values.get("--proxy") {
        Some(value) => value.parse().with_context(|| format!("--proxy {value:?} is not a valid host:port address"))?,
        None => crate::env_addr("SLURP_PROXY_ADDR", "127.0.0.1:8888")?,
    };
    let (listener, _control) = proxy_core::ProxyListener::bind(proxy_addr, spool_dir.join("proxy-address")).await?;
    let proxy = ProxyServer::new(ProxyConfig { listen_addr: proxy_addr, management_addr: None, max_body_size: 10 * 1024 * 1024 }, ca, storage.clone(), intercept);

    println!("🚀 Slurp client is running as “{}”", hello.client);
    println!("   Proxy:     http://{proxy_addr}   (point the browser or tool here)");
    println!("   Uploading: {} → workspace “{}”", config.server, hello.workspace);
    match &config.scope {
        Some(scope) => println!("   Scope:     only {} (everything else stays on this machine)", scope.join(", ")),
        None => println!("   Scope:     all traffic"),
    }
    if config.redact {
        println!("   Redaction: Authorization, Cookie and token-like header values are masked before upload");
    }
    println!("   Not forwarded yet: WebSocket traffic and interception.");
    let pending = storage.spool_len(DEFAULT_WORKSPACE_ID).unwrap_or(0);
    if pending > 0 {
        println!("   Resuming {pending} request(s) saved from the previous run.");
    }
    println!();

    tokio::select! {
        result = proxy.run_managed(listener) => result?,
        result = capture_client::run_uploader(storage, config, DEFAULT_WORKSPACE_ID.to_string()) => result?,
        result = tokio::signal::ctrl_c() => result?,
    }
    Ok(())
}
