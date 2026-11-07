//! Which certificate authorities Slurp trusts when it talks to real servers.
//!
//! Besides the built-in public roots, a server with a private CA (an internal site, a development
//! or staging environment, a corporate TLS-inspecting proxy) is reached by trusting that CA:
//! drop its PEM file into `~/.slurp/trusted-cas/`, upload it in Settings, point
//! `SLURP_UPSTREAM_CA_FILE` at it, or trust the operating system's certificate store.
//! Certificate verification is never switched off.
use crate::private_files;
use anyhow::{Context, Result};
use rustls::pki_types::CertificateDer;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

const MAX_CAS: usize = 64;
const MAX_FILE: u64 = 1024 * 1024;
const SYSTEM_MARKER: &str = ".trust-system";

struct Entry {
    name: String,
    source: &'static str,
    ders: Vec<Vec<u8>>,
}

struct State {
    dir: Option<PathBuf>,
    entries: Vec<Entry>,
    system: bool,
    system_locked: bool,
    system_ders: Vec<Vec<u8>>,
}

static STATE: RwLock<State> = RwLock::new(State { dir: None, entries: Vec::new(), system: false, system_locked: false, system_ders: Vec::new() });
static GENERATION: AtomicU64 = AtomicU64::new(1);
static CONFIG: Mutex<Option<(u64, Arc<rustls::ClientConfig>)>> = Mutex::new(None);

#[derive(Debug)]
pub enum TrustError {
    Invalid(String),
    Exists,
    Unavailable,
    Other(anyhow::Error),
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "{message}"),
            Self::Exists => write!(f, "a trusted CA with this name already exists"),
            Self::Unavailable => write!(f, "trusted CA storage is not available"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TrustError {}

impl From<anyhow::Error> for TrustError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}
impl From<std::io::Error> for TrustError {
    fn from(e: std::io::Error) -> Self {
        Self::Other(e.into())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustedCa {
    pub name: String,
    /// `file` (managed in Settings or the folder) or `env` (SLURP_UPSTREAM_CA_FILE, read-only).
    pub source: String,
    pub subject: String,
    pub issuer: String,
    pub fingerprint_sha256: String,
    pub not_before: i64,
    pub not_after: i64,
    pub is_ca: bool,
    pub expired: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustStatus {
    /// Trust the operating system's certificate store as well.
    pub system: bool,
    /// The system store is forced on by SLURP_UPSTREAM_TRUST_SYSTEM and cannot be switched off here.
    pub system_locked: bool,
    pub system_certificates: usize,
    pub cas: Vec<TrustedCa>,
}

/// Parse every certificate in `pem`, keeping only those rustls accepts as trust anchors.
fn parse_pem(pem: &[u8]) -> Vec<Vec<u8>> {
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
        .filter_map(Result::ok)
        .filter(|der| rustls::RootCertStore::empty().add(der.clone()).is_ok())
        .map(|der| der.as_ref().to_vec())
        .collect()
}

fn describe(name: &str, source: &str, der: &[u8]) -> Option<TrustedCa> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let fingerprint = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
    let not_after = cert.validity().not_after.timestamp();
    Some(TrustedCa {
        name: name.to_string(),
        source: source.to_string(),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        fingerprint_sha256: fingerprint,
        not_before: cert.validity().not_before.timestamp(),
        not_after,
        is_ca: cert.is_ca(),
        expired: not_after < chrono::Utc::now().timestamp(),
    })
}

fn is_pem_name(path: &Path) -> bool {
    let hidden = path.file_name().and_then(|n| n.to_str()).is_none_or(|n| n.starts_with('.'));
    let extension = path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase);
    !hidden && matches!(extension.as_deref(), Some("pem" | "crt" | "cer"))
}

fn read_bundle(path: &Path) -> Option<Vec<Vec<u8>>> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    let ders = parse_pem(&std::fs::read(path).ok()?);
    (!ders.is_empty()).then_some(ders)
}

/// Set the folder used for trusted CAs (created with private permissions) and load everything.
pub fn init(dir: PathBuf) -> Result<()> {
    private_files::directory(&dir)?;
    STATE.write().map_err(|_| anyhow::anyhow!("trust store lock poisoned"))?.dir = Some(dir);
    reload()
}

/// Re-read the folder, the environment and (when enabled) the operating system store.
pub fn reload() -> Result<()> {
    let (dir, system_marker) = {
        let state = STATE.read().map_err(|_| anyhow::anyhow!("trust store lock poisoned"))?;
        let marker = state.dir.as_ref().is_some_and(|d| d.join(SYSTEM_MARKER).exists());
        (state.dir.clone(), marker)
    };
    let mut entries = Vec::new();
    if let Some(dir) = &dir {
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| is_pem_name(p)).collect();
        files.sort();
        for path in files.into_iter().take(MAX_CAS) {
            match read_bundle(&path) {
                Some(ders) => entries.push(Entry { name: path.file_stem().and_then(|n| n.to_str()).unwrap_or("ca").to_string(), source: "file", ders }),
                None => tracing::warn!("Ignoring {}: not a usable PEM certificate file", path.display()),
            }
        }
    }
    if let Ok(list) = std::env::var("SLURP_UPSTREAM_CA_FILE") {
        for path in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match read_bundle(Path::new(path)) {
                Some(ders) => entries.push(Entry { name: Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or(path).to_string(), source: "env", ders }),
                None => tracing::warn!("SLURP_UPSTREAM_CA_FILE: {path} is not a usable PEM certificate file"),
            }
        }
    }
    let locked = std::env::var("SLURP_UPSTREAM_TRUST_SYSTEM").is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes"));
    let system = system_marker || locked;
    let system_ders = if system {
        let loaded = rustls_native_certs::load_native_certs();
        for error in &loaded.errors {
            tracing::warn!("System certificate store: {error}");
        }
        loaded.certs.into_iter().map(|c| c.as_ref().to_vec()).collect()
    } else {
        Vec::new()
    };
    {
        let mut state = STATE.write().map_err(|_| anyhow::anyhow!("trust store lock poisoned"))?;
        state.entries = entries;
        state.system = system;
        state.system_locked = locked;
        state.system_ders = system_ders;
    }
    GENERATION.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

/// Public roots plus every extra trusted CA.
pub fn root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for der in extra_certificates() {
        let _ = roots.add(CertificateDer::from(der));
    }
    roots
}

/// DER bytes of every extra trusted CA (for clients that take certificates one at a time).
pub fn extra_certificates() -> Vec<Vec<u8>> {
    let Ok(state) = STATE.read() else { return Vec::new() };
    state.entries.iter().flat_map(|e| e.ders.iter()).chain(state.system_ders.iter()).cloned().collect()
}

/// TLS settings for talking to real servers (HTTP/2 and HTTP/1.1). Rebuilt when the trust changes.
pub fn client_config() -> Arc<rustls::ClientConfig> {
    let generation = GENERATION.load(Ordering::SeqCst);
    let mut cache = CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((built, config)) = cache.as_ref() {
        if *built == generation {
            return config.clone();
        }
    }
    let mut config = rustls::ClientConfig::builder().with_root_certificates(root_store()).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config = Arc::new(config);
    *cache = Some((generation, config.clone()));
    config
}

pub fn status() -> TrustStatus {
    let Ok(state) = STATE.read() else {
        return TrustStatus { system: false, system_locked: false, system_certificates: 0, cas: Vec::new() };
    };
    let cas = state.entries.iter().flat_map(|e| e.ders.iter().filter_map(|der| describe(&e.name, e.source, der))).collect();
    TrustStatus { system: state.system, system_locked: state.system_locked, system_certificates: state.system_ders.len(), cas }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 60 && !name.starts_with('.') && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn directory() -> Result<PathBuf, TrustError> {
    STATE.read().ok().and_then(|s| s.dir.clone()).ok_or(TrustError::Unavailable)
}

/// Trust the certificate(s) in `pem` under `name` and keep them across restarts.
pub fn add_pem(name: &str, pem: &[u8]) -> Result<Vec<TrustedCa>, TrustError> {
    let name = name.trim().trim_end_matches(".pem");
    if !valid_name(name) {
        return Err(TrustError::Invalid("name must be 1-60 letters, digits, '-', '_' or '.'".into()));
    }
    if pem.len() as u64 > MAX_FILE {
        return Err(TrustError::Invalid("certificate file is too large".into()));
    }
    let dir = directory()?;
    let ders = parse_pem(pem);
    if ders.is_empty() {
        return Err(TrustError::Invalid("no usable PEM certificate found (expected -----BEGIN CERTIFICATE-----)".into()));
    }
    let added: Vec<TrustedCa> = ders.iter().filter_map(|der| describe(name, "file", der)).collect();
    if added.len() != ders.len() {
        return Err(TrustError::Invalid("the file contains a certificate that cannot be read".into()));
    }
    let total = STATE.read().map(|s| s.entries.len()).unwrap_or(0);
    if total >= MAX_CAS {
        return Err(TrustError::Invalid(format!("at most {MAX_CAS} trusted CA files")));
    }
    // Normalized PEM, so unrelated text in the uploaded file is not stored.
    let mut normalized = String::new();
    for der in &ders {
        normalized.push_str(&pem_encode(der));
    }
    let path = dir.join(format!("{name}.pem"));
    if path.exists() {
        return Err(TrustError::Exists);
    }
    private_files::create(&path, normalized.as_bytes()).map_err(TrustError::Other)?;
    reload()?;
    Ok(added)
}

fn pem_encode(der: &[u8]) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Stop trusting a CA added through the folder or Settings. Returns whether one was removed.
pub fn remove(name: &str) -> Result<bool, TrustError> {
    if !valid_name(name) {
        return Ok(false);
    }
    let dir = directory()?;
    let path = dir.join(format!("{name}.pem"));
    // Accept the other extensions the folder is scanned for.
    let found = ["pem", "crt", "cer"].iter().map(|e| dir.join(format!("{name}.{e}"))).find(|p| p.is_file()).unwrap_or(path);
    if !found.is_file() {
        return Ok(false);
    }
    std::fs::remove_file(&found).with_context(|| format!("Cannot remove {}", found.display())).map_err(TrustError::Other)?;
    reload()?;
    Ok(true)
}

/// Turn trust of the operating system's certificate store on or off.
pub fn set_system(enabled: bool) -> Result<(), TrustError> {
    let dir = directory()?;
    let marker = dir.join(SYSTEM_MARKER);
    if enabled && !marker.exists() {
        private_files::create(&marker, b"1\n").map_err(TrustError::Other)?;
    } else if !enabled && marker.exists() {
        std::fs::remove_file(&marker)?;
    }
    reload()?;
    Ok(())
}

/// The trust store is process-wide, so tests that change it run one at a time.
#[cfg(test)]
pub(crate) static TEST_SERIAL: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use super::TEST_SERIAL;
    use crate::CertificateAuthority;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};


    fn test_ca() -> (CertificateAuthority, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (CertificateAuthority::load_or_create(dir.path()).unwrap(), dir)
    }

    async fn connects(config: Arc<rustls::ClientConfig>, ca: &CertificateAuthority) -> bool {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = TlsAcceptor::from(ca.get_server_config("localhost").unwrap());
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = server.accept(stream).await;
            }
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        TlsConnector::from(config).connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(), stream).await.is_ok()
    }

    #[tokio::test]
    async fn a_private_ca_is_rejected_until_it_is_trusted_and_again_after_removal() {
        let _guard = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let data = tempfile::tempdir().unwrap();
        init(data.path().join("trusted-cas")).unwrap();
        let (ca, _ca_dir) = test_ca();

        assert!(!connects(client_config(), &ca).await, "unknown private CA must not be trusted by default");
        let added = add_pem("staging-ca", ca.ca_cert_pem().as_ref()).unwrap();
        assert_eq!(added.len(), 1);
        assert!(added[0].is_ca && !added[0].expired && added[0].fingerprint_sha256.matches(':').count() == 31);
        assert!(connects(client_config(), &ca).await, "trusted private CA is accepted without disabling verification");

        // Survives a restart: it is read back from the folder.
        init(data.path().join("trusted-cas")).unwrap();
        assert_eq!(status().cas.len(), 1);
        assert!(connects(client_config(), &ca).await);

        assert!(remove("staging-ca").unwrap());
        assert!(!connects(client_config(), &ca).await);
        assert!(!remove("staging-ca").unwrap());
    }

    #[tokio::test]
    async fn a_self_signed_server_certificate_can_be_trusted_directly_too() {
        let _guard = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let data = tempfile::tempdir().unwrap();
        init(data.path().join("trusted-cas")).unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let der = certified.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::try_from(certified.key_pair.serialize_der()).unwrap();
        let server = TlsAcceptor::from(Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![der], key).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let server = server.clone();
                tokio::spawn(async move { let _ = server.accept(stream).await; });
            }
        });
        let attempt = || async {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            TlsConnector::from(client_config()).connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(), stream).await.is_ok()
        };
        assert!(!attempt().await);
        add_pem("dev-server", certified.cert.pem().as_bytes()).unwrap();
        assert!(attempt().await);
    }

    #[test]
    fn uploads_are_validated_and_names_are_restricted() {
        let _guard = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let data = tempfile::tempdir().unwrap();
        init(data.path().join("trusted-cas")).unwrap();
        let (ca, _ca_dir) = test_ca();
        assert!(matches!(add_pem("x", b"not a certificate"), Err(TrustError::Invalid(_))));
        for bad in ["", "../escape", "a/b", ".hidden", &"n".repeat(61)] {
            assert!(matches!(add_pem(bad, ca.ca_cert_pem().as_ref()), Err(TrustError::Invalid(_))), "{bad:?}");
        }
        add_pem("one.pem", ca.ca_cert_pem().as_ref()).unwrap();
        assert!(matches!(add_pem("one", ca.ca_cert_pem().as_ref()), Err(TrustError::Exists)));
        assert!(!remove("../one").unwrap());
        assert_eq!(std::fs::read_dir(data.path().join("trusted-cas")).unwrap().count(), 1);
        assert!(remove("one").unwrap());
    }

    #[test]
    fn the_system_store_can_be_switched_on_and_off() {
        let _guard = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let data = tempfile::tempdir().unwrap();
        init(data.path().join("trusted-cas")).unwrap();
        assert!(!status().system);
        set_system(true).unwrap();
        assert!(status().system);
        set_system(false).unwrap();
        assert!(!status().system && status().system_certificates == 0);
    }
}
