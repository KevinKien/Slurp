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
    for der in proxy_core::trust::extra_certificates() {
        if let Ok(certificate) = reqwest::Certificate::from_der(&der) {
            builder = builder.add_root_certificate(certificate);
        }
    }
    if http1 { builder = builder.http1_only(); }
    if literal.is_none() {
        builder = builder.resolve_to_addrs(host, &addresses);
    }
    builder.build().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Replay, Flows, Intruder and scans share this client: a private CA works once it is trusted.
    #[tokio::test]
    async fn https_target_with_a_private_ca_is_reachable_only_after_trusting_it() {
        let data = tempfile::tempdir().unwrap();
        proxy_core::trust::init(data.path().join("trusted-cas")).unwrap();
        let ca_dir = tempfile::tempdir().unwrap();
        let ca = proxy_core::CertificateAuthority::load_or_create(ca_dir.path()).unwrap();
        let mut server = (*ca.get_server_config("localhost").unwrap()).clone();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else { return };
                    let mut buffer = [0u8; 4096];
                    let _ = tls.read(&mut buffer).await;
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        let url = reqwest::Url::parse(&format!("https://localhost:{port}/")).unwrap();
        let attempt = || async { client(&url, 5000).await.unwrap().get(url.clone()).send().await.map(|r| r.status().as_u16()) };
        assert!(attempt().await.is_err(), "an unknown private CA is refused");
        proxy_core::trust::add_pem("replay-private-ca", ca.ca_cert_pem().as_ref()).unwrap();
        assert_eq!(attempt().await.unwrap(), 200);
    }
}
