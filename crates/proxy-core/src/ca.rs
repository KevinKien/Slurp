/// Certificate Authority management for HTTPS MITM interception.
///
/// This module handles:
/// 1. Generating a self-signed Root CA (first run)
/// 2. Loading existing CA from disk
/// 3. Dynamically signing per-domain certificates
/// 4. Caching generated certificates
use anyhow::{Context, Result};
use chrono::Utc;
use dashmap::DashMap;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;

/// Manages the Root CA and per-domain certificate generation.
pub struct CertificateAuthority {
    /// CA certificate in DER format
    ca_cert_der: CertificateDer<'static>,
    /// CA certificate params (needed to sign child certs)
    ca_cert: rcgen::Certificate,
    /// CA key pair
    ca_key_pair: KeyPair,
    /// Directory where CA files are stored
    ca_dir: PathBuf,
    /// Cache of generated server configs per domain
    cert_cache: DashMap<String, Arc<ServerConfig>>,
}

impl CertificateAuthority {
    /// Load existing CA or generate a new one.
    ///
    /// CA files are stored in `ca_dir`:
    /// - `ca.key` — PEM-encoded private key (KEEP SECRET!)
    /// - `ca.crt` — PEM-encoded certificate (install this in OS/browser)
    pub fn load_or_create(ca_dir: &Path) -> Result<Self> {
        crate::private_files::directory(ca_dir)
            .with_context(|| format!("Failed to create CA directory: {}", ca_dir.display()))?;

        let key_path = ca_dir.join("ca.key");
        let cert_path = ca_dir.join("ca.crt");

        if key_path.exists() && cert_path.exists() {
            info!("Loading existing CA from {}", ca_dir.display());
            Self::load_existing(ca_dir, &key_path, &cert_path)
        } else {
            info!("Generating new CA in {}", ca_dir.display());
            Self::generate_new(ca_dir, &key_path, &cert_path)
        }
    }

    /// Generate a brand-new Root CA.
    fn generate_new(ca_dir: &Path, key_path: &Path, cert_path: &Path) -> Result<Self> {
        // 1. Generate CA key pair (ECDSA P-256 — fast + small certs)
        let ca_key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate CA key pair")?;

        // 2. Build CA certificate parameters
        let mut ca_params = CertificateParams::default();

        // Distinguished Name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Slurp CA");
        dn.push(DnType::OrganizationName, "Slurp");
        dn.push(
            DnType::OrganizationalUnitName,
            "MITM Proxy — FOR DEVELOPMENT USE ONLY",
        );
        ca_params.distinguished_name = dn;

        // This IS a CA certificate
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Key usage: can sign other certificates
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Valid for 10 years
        let now = Utc::now();
        ca_params.not_before = to_offset(now);
        ca_params.not_after = to_offset(now + chrono::Duration::days(3650));

        // 3. Self-sign the CA certificate
        let ca_cert = ca_params
            .self_signed(&ca_key_pair)
            .context("Failed to self-sign CA certificate")?;

        // 4. Save to disk
        let key_pem = ca_key_pair.serialize_pem();
        crate::private_files::create(key_path, key_pem.as_bytes()).context("Failed to write CA private key")?;

        let cert_pem = ca_cert.pem();
        crate::private_files::create(cert_path, cert_pem.as_bytes()).context("Failed to write CA certificate")?;

        // Set restrictive permissions on the private key
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
        }

        info!("✅ CA certificate generated!");
        info!("📄 Certificate: {}", cert_path.display());
        info!("🔑 Private key: {}", key_path.display());
        info!("");
        info!("⚠️  To intercept HTTPS, install the CA certificate:");
        info!("   macOS:  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}", cert_path.display());
        info!("   Linux:  sudo cp {} /usr/local/share/ca-certificates/slurp.crt && sudo update-ca-certificates", cert_path.display());
        info!("   Windows: certutil -addstore Root {}", cert_path.display());

        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        Ok(Self {
            ca_cert_der,
            ca_cert,
            ca_key_pair,
            ca_dir: ca_dir.to_path_buf(),
            cert_cache: DashMap::new(),
        })
    }

    /// Load an existing CA from PEM files on disk.
    fn load_existing(ca_dir: &Path, key_path: &Path, cert_path: &Path) -> Result<Self> {
        // Read and parse the private key
        let key_pem = std::fs::read_to_string(key_path).context("Failed to read CA key")?;
        let ca_key_pair = KeyPair::from_pem(&key_pem).context("Failed to parse CA key")?;

        // Read and parse the certificate
        let cert_pem = std::fs::read_to_string(cert_path).context("Failed to read CA cert")?;
        let ca_params =
            CertificateParams::from_ca_cert_pem(&cert_pem).context("Failed to parse CA cert")?;
        let ca_cert = ca_params
            .self_signed(&ca_key_pair)
            .context("Failed to re-sign CA cert")?;

        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        info!("✅ Loaded existing CA from {}", ca_dir.display());

        Ok(Self {
            ca_cert_der,
            ca_cert,
            ca_key_pair,
            ca_dir: ca_dir.to_path_buf(),
            cert_cache: DashMap::new(),
        })
    }

    /// Generate a TLS ServerConfig for a specific domain.
    ///
    /// This creates a certificate signed by our CA that is valid for
    /// the given domain. Results are cached.
    pub fn get_server_config(&self, domain: &str) -> Result<Arc<ServerConfig>> {
        // Check cache first
        if let Some(config) = self.cert_cache.get(domain) {
            return Ok(config.clone());
        }

        // Generate a new certificate for this domain
        let config = self.generate_domain_cert(domain)?;
        let config = Arc::new(config);

        // Cache it
        self.cert_cache
            .insert(domain.to_string(), config.clone());

        Ok(config)
    }

    /// Generate a certificate for a specific domain, signed by our CA.
    fn generate_domain_cert(&self, domain: &str) -> Result<ServerConfig> {
        // 1. Generate a key pair for this domain
        let domain_key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate domain key pair")?;

        // 2. Build certificate parameters
        let mut params = CertificateParams::default();

        // Distinguished Name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;

        // Subject Alternative Names (critical for modern browsers)
        params.subject_alt_names = vec![SanType::DnsName(domain.try_into()?)];

        // Not a CA
        params.is_ca = IsCa::NoCa;

        // Key usage for a TLS server cert
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Valid for 1 year
        let now = Utc::now();
        params.not_before = to_offset(now);
        params.not_after = to_offset(now + chrono::Duration::days(365));

        // 3. Sign with our CA
        let domain_cert = params
            .signed_by(&domain_key_pair, &self.ca_cert, &self.ca_key_pair)
            .context("Failed to sign domain certificate")?;

        // 4. Build rustls ServerConfig
        let cert_chain = vec![
            CertificateDer::from(domain_cert.der().to_vec()),
            self.ca_cert_der.clone(),
        ];

        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(domain_key_pair.serialize_der()));

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("Failed to build TLS ServerConfig")?;

        info!("🔐 Generated cert for: {}", domain);

        Ok(config)
    }

    /// Get the path to the CA certificate file (for users to install).
    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca_dir.join("ca.crt")
    }

    /// Get the CA certificate in PEM format.
    pub fn ca_cert_pem(&self) -> String {
        self.ca_cert.pem()
    }

    /// Number of cached domain certificates.
    pub fn cache_size(&self) -> usize {
        self.cert_cache.len()
    }

    /// Print instructions for installing the CA certificate.
    pub fn print_install_instructions(&self) {
        let cert_path = self.ca_cert_path();
        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║  📜 Install CA Certificate to intercept HTTPS              ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║                                                            ║");
        println!("║  Certificate: {:<44} ║", cert_path.display());
        println!("║                                                            ║");
        println!("║  macOS:                                                    ║");
        println!("║    sudo security add-trusted-cert -d -r trustRoot \\       ║");
        println!("║      -k /Library/Keychains/System.keychain ca.crt          ║");
        println!("║                                                            ║");
        println!("║  Linux (Ubuntu/Debian):                                    ║");
        println!("║    sudo cp ca.crt /usr/local/share/ca-certificates/        ║");
        println!("║    sudo update-ca-certificates                             ║");
        println!("║                                                            ║");
        println!("║  Windows (Admin PowerShell):                               ║");
        println!("║    certutil -addstore Root ca.crt                          ║");
        println!("║                                                            ║");
        println!("║  Firefox (uses own cert store):                            ║");
        println!("║    Settings → Privacy → Certificates → Import → ca.crt    ║");
        println!("║                                                            ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_and_load_ca() -> Result<()> {
        let tmp = TempDir::new()?;
        let ca_dir = tmp.path();

        // First call: generate new CA
        let ca1 = CertificateAuthority::load_or_create(ca_dir)?;
        assert!(ca_dir.join("ca.key").exists());
        assert!(ca_dir.join("ca.crt").exists());

        // Second call: load existing CA
        let ca2 = CertificateAuthority::load_or_create(ca_dir)?;

        // Both should produce valid PEM
        assert!(ca1.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca2.ca_cert_pem().contains("BEGIN CERTIFICATE"));

        Ok(())
    }

    #[test]
    fn test_generate_domain_cert() -> Result<()> {
        let tmp = TempDir::new()?;
        let ca = CertificateAuthority::load_or_create(tmp.path())?;

        // Generate cert for a domain
        let config = ca.get_server_config("example.com")?;
        assert_eq!(ca.cache_size(), 1);

        // Second call should hit cache
        let config2 = ca.get_server_config("example.com")?;
        assert_eq!(ca.cache_size(), 1);

        // Different domain = new cert
        let config3 = ca.get_server_config("api.example.com")?;
        assert_eq!(ca.cache_size(), 2);

        Ok(())
    }
}

/// Convert a chrono timestamp to the `time` type rcgen expects.
fn to_offset(t: chrono::DateTime<Utc>) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(t.timestamp()).expect("timestamp in range")
}
