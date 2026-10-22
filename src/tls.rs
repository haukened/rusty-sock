//! TLS listener configuration (rustls, ring provider, TLS 1.2+).

use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

/// Errors building the TLS acceptor.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A PEM file could not be read or parsed.
    #[error("{path}: {source}")]
    Pem {
        /// The offending file.
        path: String,
        /// Underlying error.
        source: rustls_pki_types::pem::Error,
    },
    /// The certificate file held no certificates.
    #[error("{0}: no certificates found")]
    NoCertificates(String),
    /// rustls rejected the configuration (e.g. key/cert mismatch).
    #[error("tls: {0}")]
    Rustls(#[from] rustls::Error),
}

fn pem_err(path: &Path) -> impl FnOnce(rustls_pki_types::pem::Error) -> TlsError + '_ {
    move |source| TlsError::Pem {
        path: path.display().to_string(),
        source,
    }
}

/// Build a TLS acceptor from PEM certificate chain and key files.
///
/// # Errors
/// Unreadable or invalid PEM files, or an inconsistent key/certificate.
pub fn acceptor(config: &TlsConfig) -> Result<TlsAcceptor, TlsError> {
    let certs = CertificateDer::pem_file_iter(&config.cert)
        .map_err(pem_err(&config.cert))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(pem_err(&config.cert))?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(config.cert.display().to_string()));
    }
    let key = PrivateKeyDer::from_pem_file(&config.key).map_err(pem_err(&config.key))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(server)))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Write a self-signed cert for `localhost` into a fresh temp dir.
    pub(crate) fn self_signed(tag: &str) -> (TlsConfig, String) {
        let dir = std::env::temp_dir().join(format!("rusty-sock-tls-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cfg = TlsConfig {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
        };
        std::fs::write(&cfg.cert, cert.pem()).unwrap();
        std::fs::write(&cfg.key, key.serialize_pem()).unwrap();
        (cfg, cert.pem())
    }

    #[test]
    fn builds_acceptor() {
        let (cfg, _) = self_signed("ok");
        assert!(acceptor(&cfg).is_ok());
    }

    #[test]
    fn reports_errors() {
        let (cfg, _) = self_signed("err");
        let missing = TlsConfig {
            cert: PathBuf::from("/nonexistent/c.pem"),
            key: cfg.key.clone(),
        };
        assert!(matches!(acceptor(&missing), Err(TlsError::Pem { .. })));

        let empty = cfg.cert.with_file_name("empty.pem");
        std::fs::write(&empty, "").unwrap();
        let no_certs = TlsConfig {
            cert: empty.clone(),
            key: cfg.key.clone(),
        };
        assert!(matches!(
            acceptor(&no_certs),
            Err(TlsError::NoCertificates(_))
        ));

        let no_key = TlsConfig {
            cert: cfg.cert.clone(),
            key: empty,
        };
        assert!(matches!(acceptor(&no_key), Err(TlsError::Pem { .. })));

        let (other, _) = self_signed("other");
        let mismatch = TlsConfig {
            cert: cfg.cert.clone(),
            key: other.key,
        };
        assert!(matches!(acceptor(&mismatch), Err(TlsError::Rustls(_))));
    }

    #[test]
    fn corrupt_cert_pem() {
        let (cfg, _) = self_signed("corrupt");
        std::fs::write(
            &cfg.cert,
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(matches!(acceptor(&cfg), Err(TlsError::Pem { .. })));
    }
}
