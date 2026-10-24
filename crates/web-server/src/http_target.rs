//! HTTP(S) destinations shared by browser and saved Replay senders.
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

pub(crate) fn validate(url: &reqwest::Url) -> Result<(), String> {
    if !["http", "https"].contains(&url.scheme())
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default().is_none_or(|port| port == 0)
    {
        return Err(
            "Expected HTTP(S) URL without credentials and a port between 1 and 65535".into(),
        );
    }
    Ok(())
}

pub(crate) async fn resolve(url: &reqwest::Url) -> Result<Vec<SocketAddr>, String> {
    validate(url)?;
    let host = url.host_str().unwrap().trim_matches(['[', ']']);
    let port = url.port_or_known_default().unwrap();
    let literal = host.parse::<IpAddr>().ok();
    let addresses: Vec<SocketAddr> = if let Some(ip) = literal {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((host, port)),
        )
        .await
        .map_err(|_| "DNS lookup timed out".to_string())?
        .map_err(|e| e.to_string())?
        .collect()
    };
    if addresses.is_empty()
        || addresses.iter().any(|a| {
            a.ip().is_unspecified()
                || a.ip().is_multicast()
                || matches!(a.ip(), IpAddr::V4(ip) if ip.is_broadcast())
        })
    {
        return Err("Host does not resolve to a usable unicast address".into());
    }
    Ok(addresses)
}

pub(crate) async fn client(url: &reqwest::Url, timeout: u64) -> Result<reqwest::Client, String> {
    client_options(url, timeout, false).await
}
pub(crate) async fn client_options(url: &reqwest::Url, timeout:u64, http1:bool)->Result<reqwest::Client,String>{
    let addresses = resolve(url).await?;
    let host = url.host_str().unwrap().trim_matches(['[', ']']);
    let literal = host.parse::<IpAddr>().ok();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(timeout));
    if http1 { builder = builder.http1_only(); }
    if literal.is_none() {
        builder = builder.resolve_to_addrs(host, &addresses);
    }
    builder.build().map_err(|e| e.to_string())
}
