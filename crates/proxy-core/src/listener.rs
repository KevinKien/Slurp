//! Runtime listener control. Changes are serialized by the proxy accept loop.
use anyhow::{Context, Result};
use std::{net::SocketAddr, path::PathBuf};
use tokio::{net::TcpListener, sync::{mpsc, oneshot}};

pub(crate) struct Change {
    pub address: Option<SocketAddr>,
    pub reply: oneshot::Sender<Result<SocketAddr, String>>,
}

#[derive(Clone)]
pub struct ProxyControl(pub(crate) mpsc::Sender<Change>);

impl ProxyControl {
    pub async fn address(&self) -> Result<SocketAddr, String> { self.request(None).await }
    pub async fn set_address(&self, address: SocketAddr) -> Result<SocketAddr, String> {
        if address.port() == 0 { return Err("Port must be between 1 and 65535".into()); }
        self.request(Some(address)).await
    }
    async fn request(&self, address: Option<SocketAddr>) -> Result<SocketAddr, String> {
        let (reply, result) = oneshot::channel();
        self.0.send(Change { address, reply }).await.map_err(|_| "Proxy listener is unavailable".to_string())?;
        result.await.map_err(|_| "Proxy listener is unavailable".to_string())?
    }
}

pub struct ProxyListener {
    pub(crate) listener: Option<TcpListener>,
    pub(crate) changes: mpsc::Receiver<Change>,
    pub(crate) config_path: PathBuf,
}

// REUSEADDR allows rebinding after closing a listener with established connections.
// Do not enable REUSEPORT: another listening process must still cause a conflict.
fn bind_listener(address: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if address.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(1024)
}

impl ProxyListener {
    pub async fn bind(address: SocketAddr, config_path: PathBuf) -> Result<(Self, ProxyControl)> {
        let listener = bind_listener(address).with_context(|| format!("Failed to bind to {address}"))?;
        let (sender, changes) = mpsc::channel(16);
        Ok((Self { listener: Some(listener), changes, config_path }, ProxyControl(sender)))
    }

    fn current(&self) -> Result<SocketAddr, String> {
        self.listener.as_ref().ok_or_else(|| "Proxy is not listening; apply a valid IP and port to recover".to_string())?
            .local_addr().map_err(|e| e.to_string())
    }

    pub(crate) async fn change(&mut self, address: Option<SocketAddr>) -> Result<SocketAddr, String> {
        let Some(address) = address else { return self.current(); };
        if address.port() == 0 { return Err("Port must be between 1 and 65535".into()); }
        let current = self.current().ok();
        if current == Some(address) {
            self.persist(address)?;
            return Ok(address);
        }
        // Validate IP ownership and permissions before touching the existing listener.
        let probe = bind_listener(SocketAddr::new(address.ip(), 0))
            .map_err(|e| format!("Cannot listen on {address}: {e}"))?;
        drop(probe);
        let overlaps = current.is_some_and(|old| old.port() == address.port()
            && (old.ip().is_unspecified() || address.ip().is_unspecified()));
        // Specific-IP and wildcard listeners cannot share the same port. Close only the
        // listening socket for this transition; accepted connections remain alive.
        if overlaps { self.listener.take(); }
        let replacement = match bind_listener(address) {
            Ok(listener) => listener,
            Err(error) => return Err(self.restore(current, format!("Cannot listen on {address}: {error}"))),
        };
        if let Err(error) = self.persist(address) {
            drop(replacement);
            return Err(self.restore(current, error));
        }
        self.listener = Some(replacement);
        Ok(address)
    }

    fn persist(&self, address: SocketAddr) -> Result<(), String> {
        let temporary = self.config_path.with_extension("tmp");
        std::fs::write(&temporary, address.to_string()).map_err(|e| format!("Cannot save proxy settings: {e}"))?;
        std::fs::rename(&temporary, &self.config_path).map_err(|e| format!("Cannot save proxy settings: {e}"))
    }

    fn restore(&mut self, previous: Option<SocketAddr>, error: String) -> String {
        if self.listener.is_none() {
            if let Some(previous) = previous {
                match bind_listener(previous) {
                    Ok(listener) => self.listener = Some(listener),
                    Err(rollback) => return format!("{error}. Could not restore {previous}: {rollback}. Apply a valid IP and port to recover."),
                }
            }
        }
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn changes_are_persisted_and_failures_keep_original_listener() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy-address");
        let (mut managed, _) = ProxyListener::bind("127.0.0.1:0".parse().unwrap(), path.clone()).await.unwrap();
        let original = managed.current().unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(managed.change(Some(occupied.local_addr().unwrap())).await.is_err());
        assert_eq!(managed.change(None).await.unwrap(), original);
        assert!(managed.change(Some(SocketAddr::new(original.ip(), 0))).await.is_err());
        let candidate = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = candidate.local_addr().unwrap();
        drop(candidate);
        assert_eq!(managed.change(Some(address)).await.unwrap(), address);
        assert_eq!(std::fs::read_to_string(path).unwrap(), address.to_string());
        assert!(TcpListener::bind(original).await.is_ok());
        assert!(TcpListener::bind(address).await.is_err());
        let candidate = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let next = candidate.local_addr().unwrap();
        drop(candidate);
        managed.config_path = dir.path().join("missing").join("config");
        assert!(managed.change(Some(next)).await.is_err());
        assert_eq!(managed.change(None).await.unwrap(), address);
        assert!(TcpListener::bind(next).await.is_ok());
        // A failed save during a same-port wildcard switch also restores localhost.
        let wildcard = SocketAddr::new("0.0.0.0".parse().unwrap(), address.port());
        assert!(managed.change(Some(wildcard)).await.is_err());
        assert_eq!(managed.change(None).await.unwrap(), address);

    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, time::{timeout, Duration}};

    #[tokio::test]
    async fn control_switches_listener_and_keeps_existing_connections() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(crate::CertificateAuthority::load_or_create(dir.path()).unwrap());
        let storage = crate::TrafficStorage::new(":memory:", 1024).unwrap();
        let intercept = crate::Intercept::new(storage.clone());
        let server = crate::ProxyServer::new(crate::ProxyConfig::default(), ca, storage, intercept);
        let (listener, control) = ProxyListener::bind("127.0.0.1:0".parse().unwrap(), dir.path().join("proxy-address")).await.unwrap();
        let address = listener.current().unwrap();
        let task = tokio::spawn(async move { server.run_managed(listener).await });
        let mut existing = TcpStream::connect(address).await.unwrap();
        // A response proves this connection was accepted before switching listeners.
        existing.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut bytes = [0; 4096];
        let count = timeout(Duration::from_secs(3), existing.read(&mut bytes)).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&bytes[..count]).contains("400"));
        assert_eq!(control.address().await.unwrap(), address);
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let next = reserved.local_addr().unwrap();
        drop(reserved);
        assert_eq!(control.set_address(next).await.unwrap(), next);
        assert!(TcpStream::connect(address).await.is_err());
        let mut on_new = TcpStream::connect(next).await.unwrap();
        on_new.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        timeout(Duration::from_secs(3), on_new.read(&mut bytes)).await.unwrap().unwrap();
        let wildcard = SocketAddr::new("0.0.0.0".parse().unwrap(), next.port());
        assert_eq!(control.set_address(wildcard).await.unwrap(), wildcard);
        assert!(TcpStream::connect(next).await.is_ok());
        on_new.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut after_switch = Vec::new();
        timeout(Duration::from_secs(3), on_new.read_to_end(&mut after_switch)).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&after_switch).contains("400"));
        assert_eq!(control.set_address(next).await.unwrap(), next);
        existing.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut rest = Vec::new();
        timeout(Duration::from_secs(3), existing.read_to_end(&mut rest)).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&rest).contains("400"));
        task.abort();
    }
}
