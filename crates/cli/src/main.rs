use anyhow::Result;
use proxy_core::{CertificateAuthority, Intercept, ProxyConfig, ProxyServer, TrafficStorage};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // `slurp mcp [--api URL]`: MCP server over stdio for AI clients.
    // stdout is reserved for protocol messages, so logs go to stderr and no banner is printed.
    if args.first().map(String::as_str) == Some("mcp") {
        let api = match args.get(1).map(String::as_str) {
            Some("--api") => args.get(2).cloned().ok_or_else(|| anyhow::anyhow!("--api needs a URL"))?,
            Some(other) => anyhow::bail!("unknown argument: {other}\nusage: slurp mcp [--api URL]"),
            None => format!("http://{}", env_addr("SLURP_API_ADDR", "127.0.0.1:5174")?),
        };
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env().add_directive("warn".parse()?))
            .with_writer(std::io::stderr)
            .init();
        return mcp_server::run_stdio(&api).await;
    }

    if args.iter().any(|arg| arg != "--no-open") {
        anyhow::bail!("usage: slurp [--no-open] | slurp mcp [--api URL]");
    }

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("info".parse()?)
                .add_directive("hyper=warn".parse()?)
                .add_directive("rustls=warn".parse()?),
        )
        .init();

    println!("\n    Slurp — Sip traffic\n");

    // 1. Setup CA
    // Migrate the legacy directory once, retaining the trusted CA and saved workspaces.
    let ca_dir = data_dir(&dirs_home()?)?;
    let ca = Arc::new(CertificateAuthority::load_or_create(&ca_dir)?);
    ca.print_install_instructions();

    // 2. Setup storage (shared between proxy and web server)
    let db_path = ca_dir.join("traffic.db");
    let storage = TrafficStorage::new(
        db_path.to_str().unwrap_or(":memory:"),
        10 * 1024 * 1024, // 10 MB max body
    )?;

    // 3. Intercept engine (off until switched on from the UI), shared by proxy and web server
    let intercept = Intercept::new(storage.clone());

    // Explicit environment configuration overrides the saved listener address.
    let proxy_settings = ca_dir.join("proxy-address");
    let proxy_addr = if std::env::var_os("SLURP_PROXY_ADDR").is_some() || std::env::var_os("HTTPDEBUGGER_PROXY_ADDR").is_some() {
        env_addr("SLURP_PROXY_ADDR", "127.0.0.1:8888")?
    } else {
        match std::fs::read_to_string(&proxy_settings) {
            Ok(value) => value.trim().parse().map_err(|e| anyhow::anyhow!("Invalid saved proxy address: {e}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => "127.0.0.1:8888".parse()?,
            Err(e) => return Err(e.into()),
        }
    };
    let (listener, proxy_control) = proxy_core::ProxyListener::bind(proxy_addr, proxy_settings).await?;

    // 4. Start web server (API + WebSocket) in background
    let web_addr = env_addr("SLURP_API_ADDR", "127.0.0.1:5174")?;
    let web_listener = tokio::net::TcpListener::bind(web_addr).await?;
    let web_addr = web_listener.local_addr()?;
    let web_storage = storage.clone();
    let web_intercept = intercept.clone();
    let web_task = tokio::spawn(async move {
        web_server::serve(web_listener, web_storage, web_intercept, proxy_control).await
    });

    // 5. Start proxy server (foreground)
    let proxy_config = ProxyConfig {
        listen_addr: proxy_addr,
        max_body_size: 10 * 1024 * 1024,
    };
    let proxy = ProxyServer::new(proxy_config, ca.clone(), storage.clone(), intercept);

    println!("🚀 Slurp is running!");
    println!("   Proxy:    http://{proxy_addr}");
    let mut browser_addr = web_addr;
    if browser_addr.ip().is_unspecified() { browser_addr.set_ip(if browser_addr.is_ipv4() { std::net::Ipv4Addr::LOCALHOST.into() } else { std::net::Ipv6Addr::LOCALHOST.into() }); }
    let ui_url = format!("http://{browser_addr}/dashboard");
    println!("   UI:       {ui_url}");
    println!("   API:      http://{web_addr}/api/traffic");
    println!("   WebSocket: ws://{web_addr}/api/ws");
    println!();
    println!("   Traffic is kept in memory (lost on exit) until a workspace is chosen in the UI.");
    println!();
    println!("   Test HTTP:  curl -x http://{proxy_addr} http://httpbin.org/get");
    println!(
        "   Test HTTPS: curl -x http://{proxy_addr} --cacert \"{}\" https://httpbin.org/get",
        ca_dir.join("ca.crt").display()
    );
    println!();

    #[cfg(feature = "embedded-ui")]
    if !args.iter().any(|arg| arg == "--no-open") { open_browser(&ui_url); }
    tokio::select! {
        result = proxy.run_managed(listener) => result?,
        result = web_task => result??,
        result = tokio::signal::ctrl_c() => result?,
    }


    Ok(())
}

/// Read a socket address from an environment variable, falling back to `default`.
/// Lets the proxy and API move when another tool already uses the default ports.
fn env_addr(var: &str, default: &str) -> Result<std::net::SocketAddr> {
    let raw = std::env::var(var)
        .or_else(|_| std::env::var(var.replacen("SLURP_", "HTTPDEBUGGER_", 1)))
        .unwrap_or_else(|_| default.to_string());
    raw.parse()
        .map_err(|e| anyhow::anyhow!("{var}={raw:?} is not a valid host:port address ({e})"))
}

fn data_dir(home: &std::path::Path) -> Result<std::path::PathBuf> {
    let current = home.join(".slurp");
    let legacy = home.join(".httpdebugger");
    if !current.exists() && legacy.is_dir() {
        std::fs::rename(&legacy, &current).map_err(|e| {
            anyhow::anyhow!("Cannot migrate {} to {}: {e}", legacy.display(), current.display())
        })?;
        tracing::info!("Migrated existing data to {}", current.display());
    }
    Ok(current)
}

fn dirs_home() -> Result<std::path::PathBuf> {
    #[cfg(target_os = "windows")]
    let variable = "USERPROFILE";
    #[cfg(not(target_os = "windows"))]
    let variable = "HOME";

    std::env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("{variable} is not set; cannot locate the Slurp data directory"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_directory_migrates_legacy_and_preserves_existing_destination() -> Result<()> {
        let home = std::env::temp_dir().join(format!("slurp-data-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()));
        std::fs::create_dir_all(&home)?;
        let result = (|| -> Result<()> {
            assert_eq!(data_dir(&home)?, home.join(".slurp"));
            let legacy = home.join(".httpdebugger");
            std::fs::create_dir(&legacy)?;
            std::fs::write(legacy.join("ca.key"), "existing key")?;
            std::fs::write(legacy.join("traffic.db"), "existing database")?;
            let current = data_dir(&home)?;
            assert!(!legacy.exists());
            assert_eq!(std::fs::read_to_string(current.join("ca.key"))?, "existing key");
            assert_eq!(std::fs::read_to_string(current.join("traffic.db"))?, "existing database");
            std::fs::create_dir(&legacy)?;
            std::fs::write(legacy.join("ca.key"), "other key")?;
            assert_eq!(data_dir(&home)?, current);
            assert_eq!(std::fs::read_to_string(current.join("ca.key"))?, "existing key");
            assert_eq!(std::fs::read_to_string(legacy.join("ca.key"))?, "other key");
            Ok(())
        })();
        std::fs::remove_dir_all(&home)?;
        result
    }
}

#[cfg(feature = "embedded-ui")]
fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("xdg-open");
    #[cfg(target_os = "windows")]
    let mut command = { let mut command = std::process::Command::new("rundll32.exe"); command.arg("url.dll,FileProtocolHandler"); command };
    if let Err(error) = command.arg(url).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn() {
        tracing::warn!("Could not open browser ({error}); open {url} manually");
    }
}
