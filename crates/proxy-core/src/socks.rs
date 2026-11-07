//! SOCKS5 on the proxy port (RFC 1928): no authentication, CONNECT only.
//!
//! SOCKS carries no HTTP, so after the handshake the proxy looks at the first bytes the client
//! sends to decide what the connection is: TLS (decrypted like CONNECT, using the SNI name when
//! the client gave an IP address), plain HTTP, or anything else (relayed unchanged).
use anyhow::{bail, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const VERSION: u8 = 5;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the client asked to connect.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Destination {
    pub host: String,
    pub port: u16,
    /// The client sent an address instead of a name (it resolved DNS itself).
    pub is_ip: bool,
}

async fn reply(stream: &mut TcpStream, code: u8) -> std::io::Result<()> {
    // VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
    stream.write_all(&[VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

/// Negotiate the method, read the request and answer success. The success reply is sent before
/// any upstream connection exists because what to connect depends on what the client sends next.
pub(crate) async fn handshake(stream: &mut TcpStream) -> Result<Destination> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        if head[0] != VERSION {
            bail!("not a SOCKS5 client");
        }
        let mut methods = vec![0u8; head[1] as usize];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            stream.write_all(&[VERSION, 0xFF]).await?;
            bail!("SOCKS5 client offers no supported authentication method");
        }
        stream.write_all(&[VERSION, 0]).await?;

        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await?;
        if request[0] != VERSION {
            bail!("invalid SOCKS5 request");
        }
        let (host, is_ip) = match request[3] {
            1 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                (std::net::Ipv4Addr::from(octets).to_string(), true)
            }
            3 => {
                let mut length = [0u8; 1];
                stream.read_exact(&mut length).await?;
                let mut name = vec![0u8; length[0] as usize];
                stream.read_exact(&mut name).await?;
                match String::from_utf8(name).ok().filter(|n| !n.is_empty() && n.is_ascii() && !n.chars().any(|c| c.is_control() || c.is_whitespace())) {
                    Some(name) => (name, false),
                    None => {
                        reply(stream, 8).await?;
                        bail!("invalid SOCKS5 domain name");
                    }
                }
            }
            4 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).await?;
                (format!("[{}]", std::net::Ipv6Addr::from(octets)), true)
            }
            _ => {
                reply(stream, 8).await?;
                bail!("unsupported SOCKS5 address type");
            }
        };
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        let port = u16::from_be_bytes(port);
        if request[1] != 1 || port == 0 {
            // BIND and UDP ASSOCIATE (and port 0) are not supported.
            reply(stream, 7).await?;
            bail!("unsupported SOCKS5 command {}", request[1]);
        }
        reply(stream, 0).await?;
        Ok(Destination { host, port, is_ip })
    })
    .await
    .map_err(|_| anyhow::anyhow!("SOCKS5 handshake timed out"))?
}

/// What the first bytes of a connection look like.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A complete TLS ClientHello record, with its SNI host name if present.
    Tls(Option<String>),
    Http,
    /// More bytes are needed to decide.
    Incomplete,
    Other,
}

const METHODS: &[&[u8]] = &[b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI", b"TRAC"];

pub(crate) fn classify(bytes: &[u8]) -> Kind {
    match bytes.first() {
        None => Kind::Incomplete,
        Some(0x16) => {
            if bytes.len() < 5 {
                return Kind::Incomplete;
            }
            let record = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
            if record == 0 || record > 16384 || bytes[1] != 3 {
                return Kind::Other;
            }
            if bytes.len() < 5 + record {
                return Kind::Incomplete;
            }
            Kind::Tls(sni(&bytes[5..5 + record]))
        }
        Some(_) if bytes.len() < 4 => {
            if METHODS.iter().any(|m| m.starts_with(bytes)) {
                Kind::Incomplete
            } else {
                Kind::Other
            }
        }
        Some(_) => {
            if METHODS.iter().any(|m| bytes.starts_with(m)) {
                Kind::Http
            } else {
                Kind::Other
            }
        }
    }
}

/// The server_name from a ClientHello handshake message (the TLS record payload).
fn sni(handshake: &[u8]) -> Option<String> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let (head, rest) = self.0.split_at_checked(n)?;
            self.0 = rest;
            Some(head)
        }
        fn u8(&mut self) -> Option<usize> {
            Some(self.take(1)?[0] as usize)
        }
        fn u16(&mut self) -> Option<usize> {
            let b = self.take(2)?;
            Some(u16::from_be_bytes([b[0], b[1]]) as usize)
        }
    }
    let mut r = Reader(handshake);
    if r.u8()? != 1 {
        return None; // not a ClientHello
    }
    r.take(3)?; // handshake length
    r.take(2 + 32)?; // version, random
    let session = r.u8()?;
    r.take(session)?;
    let suites = r.u16()?;
    r.take(suites)?;
    let compression = r.u8()?;
    r.take(compression)?;
    let extensions_len = r.u16()?;
    let mut extensions = Reader(r.take(extensions_len)?);
    while let (Some(kind), Some(len)) = (extensions.u16(), extensions.u16()) {
        let body = extensions.take(len)?;
        if kind == 0 {
            let mut list = Reader(body);
            let _total = list.u16()?;
            while let (Some(name_type), Some(name_len)) = (list.u8(), list.u16()) {
                let name = list.take(name_len)?;
                if name_type == 0 {
                    let name = std::str::from_utf8(name).ok()?;
                    let valid = !name.is_empty() && name.len() <= 253 && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
                    return valid.then(|| name.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(name: &str) -> Vec<u8> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let config = rustls::ClientConfig::builder().with_root_certificates(rustls::RootCertStore::empty()).with_no_client_auth();
        let mut connection = rustls::ClientConnection::new(std::sync::Arc::new(config), rustls::pki_types::ServerName::try_from(name.to_string()).unwrap()).unwrap();
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn reads_the_sni_name_from_a_real_client_hello_only_once_it_is_complete() {
        let hello = client_hello("Api.Example.com");
        assert_eq!(classify(&hello), Kind::Tls(Some("api.example.com".into())));
        assert_eq!(classify(&hello[..hello.len() - 1]), Kind::Incomplete);
        assert_eq!(classify(&hello[..3]), Kind::Incomplete);
        // An IP address has no SNI.
        assert_eq!(classify(&client_hello("127.0.0.1")), Kind::Tls(None));
    }

    #[test]
    fn classifies_http_requests_and_unknown_protocols() {
        assert_eq!(classify(b"GET / HTTP/1.1\r\n"), Kind::Http);
        assert_eq!(classify(b"POST /x"), Kind::Http);
        assert_eq!(classify(b"PO"), Kind::Incomplete);
        assert_eq!(classify(b"SSH-2.0-OpenSSH"), Kind::Other);
        assert_eq!(classify(&[0x00, 0x01, 0x02, 0x03, 0x04]), Kind::Other);
        assert_eq!(classify(&[]), Kind::Incomplete);
        // Truncated, oversized and corrupt TLS records never panic.
        assert_eq!(classify(&[0x16, 3, 1, 0xFF, 0xFF, 0]), Kind::Other);
        let mut corrupt = client_hello("example.com");
        for i in 5..corrupt.len() {
            corrupt[i] = 0xFF;
            let _ = classify(&corrupt);
        }
    }
}
