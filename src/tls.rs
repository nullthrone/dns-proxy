//! rustls configuration (ring provider, rustls' safe defaults: TLS 1.2/1.3,
//! AEAD-only cipher suites).

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::path::Path;
use std::sync::{Arc, OnceLock};

pub fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

/// Cryptographically secure random u16 (for upstream query IDs).
pub fn random_u16() -> u16 {
    let mut b = [0u8; 2];
    // Failure of the system RNG is not recoverable in any meaningful way.
    provider().secure_random.fill(&mut b).expect("system RNG failure");
    u16::from_ne_bytes(b)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{}: no certificates found", path.display()));
    }
    Ok(certs)
}

pub fn server_config(cert: &Path, key: &Path, alpn: &[&[u8]]) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(cert)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(cfg))
}

pub fn client_config(ca_file: Option<&Path>, alpn: &[&[u8]]) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    match ca_file {
        Some(p) => {
            for c in load_certs(p)? {
                roots.add(c).map_err(|e| format!("{}: {e}", p.display()))?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(cfg))
}
