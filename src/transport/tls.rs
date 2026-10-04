// FRD: specs/frds/FRD-DPI001.md
// FRD: specs/frds/FRD-DPI003.md
// FRD: specs/frds/FRD-DPI004.md

//! Shared TLS certificate verification and PEM loading for QUIC/MASQUE connections.
//!
//! Provides [`build_cert_verifier`] for client-side certificate verification,
//! and [`load_pem_cert_and_key`] for server-side CA-signed certificate loading.

use std::{io::BufReader, path::Path, sync::Arc};

use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

use super::TransportError;

/// A TLS certificate verifier that accepts any server certificate.
///
/// Only for dev/test with self-signed certificates.
#[derive(Debug)]
pub(crate) struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Create an [`Arc`]-wrapped [`SkipServerVerification`] for use with rustls
/// client configs.
pub(crate) fn skip_server_verification() -> Arc<dyn ServerCertVerifier> {
    Arc::new(SkipServerVerification)
}

/// Build a certificate verifier based on the `insecure` flag.
///
/// - `insecure = false` (production): verifies server certificates against the
///   Mozilla CA root store via [`webpki_roots::TLS_SERVER_ROOTS`].
/// - `insecure = true` (dev/test): accepts any certificate via
///   [`SkipServerVerification`].
pub(crate) fn build_cert_verifier(insecure: bool) -> Arc<dyn ServerCertVerifier> {
    if insecure {
        skip_server_verification()
    } else {
        let root_store = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("webpki root store is valid")
    }
}

/// Load a PEM-encoded certificate chain and private key from disk.
///
/// `cert_path` should point to a PEM file containing one or more certificates
/// (e.g. fullchain.pem from Let's Encrypt). `key_path` should point to a PEM
/// file containing the private key (e.g. privkey.pem).
///
/// Returns the certificate chain and private key suitable for
/// `rustls::ServerConfig::with_single_cert`.
pub(crate) fn load_pem_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TransportError> {
    // Load certificate chain
    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| TransportError::TlsConfig(format!("failed to open cert file {}: {e}", cert_path.display())))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TransportError::TlsConfig(format!("failed to parse PEM certs from {}: {e}", cert_path.display())))?;

    if certs.is_empty() {
        return Err(TransportError::TlsConfig(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }

    // Load private key
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| TransportError::TlsConfig(format!("failed to open key file {}: {e}", key_path.display())))?;
    let mut key_reader = BufReader::new(key_file);
    let key = PrivateKeyDer::pem_reader_iter(&mut key_reader)
        .next()
        .transpose()
        .map_err(|e| TransportError::TlsConfig(format!("failed to parse PEM key from {}: {e}", key_path.display())))?
        .ok_or_else(|| TransportError::TlsConfig(format!("no private key found in {}", key_path.display())))?;

    Ok((certs, key))
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-DPI003.md
    // FRD: specs/frds/FRD-DPI004.md
    use super::*;

    #[test]
    fn build_cert_verifier_insecure_returns_skip() {
        let verifier = build_cert_verifier(true);
        // SkipServerVerification accepts any cert — verify it returns Ok
        // for a dummy self-signed certificate.
        let dummy_cert = rustls::pki_types::CertificateDer::from(vec![0u8; 32]);
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let result = verifier.verify_server_cert(&dummy_cert, &[], &server_name, &[], rustls::pki_types::UnixTime::now());
        assert!(result.is_ok(), "insecure verifier should accept any cert");
    }

    #[test]
    fn build_cert_verifier_secure_rejects_dummy_cert() {
        let verifier = build_cert_verifier(false);
        let dummy_cert = rustls::pki_types::CertificateDer::from(vec![0u8; 32]);
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let result = verifier.verify_server_cert(&dummy_cert, &[], &server_name, &[], rustls::pki_types::UnixTime::now());
        assert!(result.is_err(), "secure verifier should reject dummy cert");
    }

    #[test]
    fn skip_server_verification_accepts_any_cert() {
        let verifier = skip_server_verification();
        let dummy_cert = rustls::pki_types::CertificateDer::from(vec![0u8; 32]);
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        let result = verifier.verify_server_cert(&dummy_cert, &[], &server_name, &[], rustls::pki_types::UnixTime::now());
        assert!(result.is_ok());
    }

    /// Helper: generate a self-signed cert + key and write them as PEM files.
    fn write_test_pem_files(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("generate cert");
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("write cert pem");
        std::fs::write(&key_path, signing_key.serialize_pem()).expect("write key pem");
        (cert_path, key_path)
    }

    #[test]
    fn load_pem_cert_and_key_valid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path) = write_test_pem_files(dir.path());
        let (certs, _key) = load_pem_cert_and_key(&cert_path, &key_path).expect("load should succeed");
        assert!(!certs.is_empty(), "should load at least one certificate");
    }

    #[test]
    fn load_pem_cert_and_key_missing_cert_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_, key_path) = write_test_pem_files(dir.path());
        let missing = dir.path().join("nonexistent.pem");
        let err = load_pem_cert_and_key(&missing, &key_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to open cert file"), "error: {msg}");
    }

    #[test]
    fn load_pem_cert_and_key_missing_key_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_path, _) = write_test_pem_files(dir.path());
        let missing = dir.path().join("nonexistent.pem");
        let err = load_pem_cert_and_key(&cert_path, &missing).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to open key file"), "error: {msg}");
    }

    #[test]
    fn load_pem_cert_and_key_empty_cert_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_, key_path) = write_test_pem_files(dir.path());
        let empty_cert = dir.path().join("empty.pem");
        std::fs::write(&empty_cert, "").expect("write empty");
        let err = load_pem_cert_and_key(&empty_cert, &key_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no certificates found"), "error: {msg}");
    }

    #[test]
    fn load_pem_cert_and_key_no_key_in_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_path, _) = write_test_pem_files(dir.path());
        // Write a file with cert content but no key
        let no_key = dir.path().join("no_key.pem");
        std::fs::write(&no_key, "not a pem key\n").expect("write");
        let err = load_pem_cert_and_key(&cert_path, &no_key).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no private key found"), "error: {msg}");
    }
}
