//! Native local-lab HTTPS certificate preparation.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use axum_server::tls_rustls::RustlsConfig;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::{extensions::GeneralName, pem::parse_x509_pem};
use zeroize::Zeroizing;

use crate::operations::{LabHttpsCertificateConfig, LabHttpsConfig};

const MAX_CERTIFICATE_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;

/// Prepared native HTTPS material safe to hand to the listener.
pub struct PreparedLabHttps {
    /// Rustls server configuration.
    pub rustls: RustlsConfig,
    /// SHA-256 fingerprint of the leaf DER certificate.
    pub fingerprint_sha256: String,
    /// Leaf certificate expiration as a Unix timestamp.
    pub not_after_unix_seconds: i64,
    /// Safe source label.
    pub source_label: &'static str,
}

/// Native HTTPS certificate preparation failure.
#[derive(Debug, Error)]
pub enum LabHttpsError {
    /// Persistent certificate state is absent on only one side or cannot be
    /// safely created.
    #[error("native HTTPS certificate state is incomplete or unavailable")]
    Persistence,
    /// A certificate or key path has unsafe type, ownership, mode, or size.
    #[error("native HTTPS certificate custody is unsafe")]
    Custody,
    /// The certificate is malformed, expired, not yet valid, or lacks the
    /// configured SAN.
    #[error("native HTTPS certificate identity is invalid")]
    Certificate,
    /// Rustls rejected the certificate chain or private key.
    #[error("native HTTPS certificate and private key cannot be loaded")]
    Tls,
}

/// Installs the only compiled rustls crypto provider.
///
/// Calling this more than once is harmless; rustls retains the first provider.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Creates or loads the configured certificate and builds rustls state.
///
/// # Errors
///
/// Fails closed for unsafe custody, invalid certificate identity, incomplete
/// generated state, or a certificate/private-key mismatch.
pub async fn prepare(config: &LabHttpsConfig) -> Result<PreparedLabHttps, LabHttpsError> {
    install_crypto_provider();
    if let LabHttpsCertificateConfig::Generated {
        certificate_path,
        private_key_path,
    } = &config.certificate
    {
        ensure_generated_pair(certificate_path, private_key_path, &config.server_name)?;
    }
    let (certificate_path, private_key_path) = config.certificate.paths();
    let certificate_pem = read_secure_file(certificate_path, MAX_CERTIFICATE_BYTES)?;
    let private_key_pem =
        Zeroizing::new(read_secure_file(private_key_path, MAX_PRIVATE_KEY_BYTES)?);
    let certificate = inspect_leaf(&certificate_pem, &config.server_name)?;
    let rustls = RustlsConfig::from_pem(certificate_pem, private_key_pem.to_vec())
        .await
        .map_err(|_| LabHttpsError::Tls)?;
    Ok(PreparedLabHttps {
        rustls,
        fingerprint_sha256: certificate.fingerprint_sha256,
        not_after_unix_seconds: certificate.not_after_unix_seconds,
        source_label: config.certificate.source_label(),
    })
}

struct InspectedCertificate {
    fingerprint_sha256: String,
    not_after_unix_seconds: i64,
}

fn inspect_leaf(
    certificate_pem: &[u8],
    server_name: &str,
) -> Result<InspectedCertificate, LabHttpsError> {
    let (_, pem) = parse_x509_pem(certificate_pem).map_err(|_| LabHttpsError::Certificate)?;
    if pem.label != "CERTIFICATE" {
        return Err(LabHttpsError::Certificate);
    }
    let certificate = pem.parse_x509().map_err(|_| LabHttpsError::Certificate)?;
    if !certificate.validity().is_valid() {
        return Err(LabHttpsError::Certificate);
    }
    let alternatives = certificate
        .subject_alternative_name()
        .map_err(|_| LabHttpsError::Certificate)?
        .ok_or(LabHttpsError::Certificate)?;
    let expected_ip = server_name.parse::<IpAddr>().ok();
    let identity_matches = alternatives
        .value
        .general_names
        .iter()
        .any(|name| match name {
            GeneralName::DNSName(value) => {
                expected_ip.is_none() && value.eq_ignore_ascii_case(server_name)
            }
            GeneralName::IPAddress(value) => expected_ip.is_some_and(|address| match address {
                IpAddr::V4(address) => *value == address.octets(),
                IpAddr::V6(address) => *value == address.octets(),
            }),
            _ => false,
        });
    if !identity_matches {
        return Err(LabHttpsError::Certificate);
    }
    let digest = Sha256::digest(&pem.contents);
    let fingerprint_sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok(InspectedCertificate {
        fingerprint_sha256,
        not_after_unix_seconds: certificate.validity().not_after.timestamp(),
    })
}

fn ensure_generated_pair(
    certificate_path: &Path,
    private_key_path: &Path,
    server_name: &str,
) -> Result<(), LabHttpsError> {
    let certificate_exists = certificate_path
        .try_exists()
        .map_err(|_| LabHttpsError::Persistence)?;
    let private_key_exists = private_key_path
        .try_exists()
        .map_err(|_| LabHttpsError::Persistence)?;
    match (certificate_exists, private_key_exists) {
        (true, true) => return Ok(()),
        (true, false) | (false, true) => return Err(LabHttpsError::Persistence),
        (false, false) => {}
    }

    let mut params = CertificateParams::new(vec![server_name.to_owned()])
        .map_err(|_| LabHttpsError::Certificate)?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(365);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "SMCV local lab");
    let key = KeyPair::generate().map_err(|_| LabHttpsError::Certificate)?;
    let certificate = params
        .self_signed(&key)
        .map_err(|_| LabHttpsError::Certificate)?;
    let private_key_pem = Zeroizing::new(key.serialize_pem());
    let certificate_pem = certificate.pem();

    create_restrictive_file(private_key_path, private_key_pem.as_bytes())?;
    if let Err(error) = create_restrictive_file(certificate_path, certificate_pem.as_bytes()) {
        let _ = fs::remove_file(private_key_path);
        return Err(error);
    }
    sync_parent(certificate_path)?;
    Ok(())
}

#[cfg(unix)]
fn create_restrictive_file(path: &Path, contents: &[u8]) -> Result<(), LabHttpsError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).map_err(|_| LabHttpsError::Persistence)?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        let _ = error;
        return Err(LabHttpsError::Persistence);
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_restrictive_file(_path: &Path, _contents: &[u8]) -> Result<(), LabHttpsError> {
    Err(LabHttpsError::Custody)
}

fn sync_parent(path: &Path) -> Result<(), LabHttpsError> {
    let parent = path.parent().ok_or(LabHttpsError::Persistence)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| LabHttpsError::Persistence)
}

#[cfg(unix)]
fn read_secure_file(path: &Path, maximum_size: u64) -> Result<Vec<u8>, LabHttpsError> {
    let maximum_size_usize = usize::try_from(maximum_size).map_err(|_| LabHttpsError::Custody)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|_| LabHttpsError::Custody)?;
    let metadata = file.metadata().map_err(|_| LabHttpsError::Custody)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != current_effective_uid()?
        || metadata.len() == 0
        || metadata.len() > maximum_size
    {
        return Err(LabHttpsError::Custody);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| LabHttpsError::Custody)?;
    let mut contents = Vec::with_capacity(capacity);
    file.take(maximum_size.saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|_| LabHttpsError::Custody)?;
    if contents.len() > capacity || contents.len() > maximum_size_usize {
        return Err(LabHttpsError::Custody);
    }
    Ok(contents)
}

#[cfg(not(unix))]
fn read_secure_file(_path: &Path, _maximum_size: u64) -> Result<Vec<u8>, LabHttpsError> {
    Err(LabHttpsError::Custody)
}

#[cfg(unix)]
fn current_effective_uid() -> Result<u32, LabHttpsError> {
    let status = fs::read_to_string("/proc/self/status").map_err(|_| LabHttpsError::Custody)?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|values| values.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or(LabHttpsError::Custody)
}

#[cfg(test)]
mod tests {
    use std::{fs, net::SocketAddr};

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    use rcgen::{CertificateParams, KeyPair};
    use tempfile::TempDir;

    use super::{LabHttpsError, inspect_leaf, prepare};
    use crate::operations::{LabHttpsCertificateConfig, LabHttpsConfig};

    fn generated(root: &TempDir, server_name: &str) -> LabHttpsConfig {
        LabHttpsConfig {
            listen_address: SocketAddr::from(([127, 0, 0, 1], 8443)),
            server_name: server_name.to_owned(),
            certificate: LabHttpsCertificateConfig::Generated {
                certificate_path: root.path().join("cert.pem"),
                private_key_path: root.path().join("key.pem"),
            },
        }
    }

    #[cfg(unix)]
    fn supplied(
        root: &TempDir,
        certificate_name: &str,
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> LabHttpsConfig {
        let mut params = CertificateParams::new(vec![certificate_name.to_owned()])
            .unwrap_or_else(|error| panic!("certificate parameters: {error}"));
        params.not_before = not_before;
        params.not_after = not_after;
        let key = KeyPair::generate().unwrap_or_else(|error| panic!("private key: {error}"));
        let certificate = params
            .self_signed(&key)
            .unwrap_or_else(|error| panic!("certificate: {error}"));
        let certificate_path = root.path().join("supplied-cert.pem");
        let private_key_path = root.path().join("supplied-key.pem");
        fs::write(&certificate_path, certificate.pem())
            .unwrap_or_else(|error| panic!("certificate fixture: {error}"));
        fs::write(&private_key_path, key.serialize_pem())
            .unwrap_or_else(|error| panic!("key fixture: {error}"));
        fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("certificate fixture mode: {error}"));
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("key fixture mode: {error}"));
        LabHttpsConfig {
            listen_address: SocketAddr::from(([127, 0, 0, 1], 8443)),
            server_name: String::from("vault.lab.test"),
            certificate: LabHttpsCertificateConfig::Supplied {
                certificate_path,
                private_key_path,
            },
        }
    }

    #[tokio::test]
    async fn generated_identity_is_restrictive_and_stable() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let config = generated(&root, "vault.lab.test");
        let first = prepare(&config)
            .await
            .unwrap_or_else(|error| panic!("first prepare: {error}"));
        let certificate_before = fs::read(config.certificate.paths().0)
            .unwrap_or_else(|error| panic!("read certificate: {error}"));
        let second = prepare(&config)
            .await
            .unwrap_or_else(|error| panic!("second prepare: {error}"));
        let certificate_after = fs::read(config.certificate.paths().0)
            .unwrap_or_else(|error| panic!("read certificate: {error}"));
        assert_eq!(first.fingerprint_sha256, second.fingerprint_sha256);
        assert_eq!(certificate_before, certificate_after);
        #[cfg(unix)]
        for path in [config.certificate.paths().0, config.certificate.paths().1] {
            let mode = fs::metadata(path)
                .unwrap_or_else(|error| panic!("metadata: {error}"))
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn persisted_identity_cannot_be_reinterpreted_for_another_name() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let original = generated(&root, "vault.lab.test");
        prepare(&original)
            .await
            .unwrap_or_else(|error| panic!("prepare: {error}"));
        let changed = generated(&root, "other.lab.test");
        assert!(matches!(
            prepare(&changed).await,
            Err(LabHttpsError::Certificate)
        ));
    }

    #[tokio::test]
    async fn incomplete_or_permissive_generated_state_fails_closed() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let config = generated(&root, "127.0.0.1");
        fs::write(config.certificate.paths().0, b"one-sided")
            .unwrap_or_else(|error| panic!("fixture: {error}"));
        assert!(matches!(
            prepare(&config).await,
            Err(LabHttpsError::Persistence)
        ));

        fs::remove_file(config.certificate.paths().0)
            .unwrap_or_else(|error| panic!("remove fixture: {error}"));
        prepare(&config)
            .await
            .unwrap_or_else(|error| panic!("prepare: {error}"));
        #[cfg(unix)]
        {
            fs::set_permissions(
                config.certificate.paths().1,
                fs::Permissions::from_mode(0o644),
            )
            .unwrap_or_else(|error| panic!("mode fixture: {error}"));
            assert!(matches!(
                prepare(&config).await,
                Err(LabHttpsError::Custody)
            ));
        }
    }

    #[test]
    #[cfg(unix)]
    fn symlinked_material_is_rejected() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let target = root.path().join("target");
        fs::write(&target, b"not a certificate")
            .unwrap_or_else(|error| panic!("target fixture: {error}"));
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("target mode: {error}"));
        let link = root.path().join("link");
        symlink(&target, &link).unwrap_or_else(|error| panic!("symlink fixture: {error}"));
        assert!(matches!(
            super::read_secure_file(&link, 1024),
            Err(LabHttpsError::Custody)
        ));
    }

    #[test]
    fn generated_certificate_contains_exact_ip_san() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let config = generated(&root, "127.0.0.1");
        super::ensure_generated_pair(
            config.certificate.paths().0,
            config.certificate.paths().1,
            &config.server_name,
        )
        .unwrap_or_else(|error| panic!("generation: {error}"));
        let bytes = fs::read(config.certificate.paths().0)
            .unwrap_or_else(|error| panic!("read certificate: {error}"));
        assert!(inspect_leaf(&bytes, "127.0.0.1").is_ok());
        assert!(inspect_leaf(&bytes, "127.0.0.2").is_err());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn supplied_certificate_requires_current_exact_san() {
        let now = time::OffsetDateTime::now_utc();
        let valid_root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let valid = supplied(
            &valid_root,
            "vault.lab.test",
            now - time::Duration::minutes(1),
            now + time::Duration::days(1),
        );
        assert!(prepare(&valid).await.is_ok());

        let wrong_name_root =
            TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let wrong_name = supplied(
            &wrong_name_root,
            "other.lab.test",
            now - time::Duration::minutes(1),
            now + time::Duration::days(1),
        );
        assert!(matches!(
            prepare(&wrong_name).await,
            Err(LabHttpsError::Certificate)
        ));

        let expired_root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let expired = supplied(
            &expired_root,
            "vault.lab.test",
            now - time::Duration::days(2),
            now - time::Duration::days(1),
        );
        assert!(matches!(
            prepare(&expired).await,
            Err(LabHttpsError::Certificate)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn oversized_certificate_material_is_rejected_before_read() {
        let root = TempDir::new().unwrap_or_else(|error| panic!("temporary root: {error}"));
        let path = root.path().join("oversized");
        let file =
            fs::File::create(&path).unwrap_or_else(|error| panic!("oversized fixture: {error}"));
        file.set_len(super::MAX_PRIVATE_KEY_BYTES + 1)
            .unwrap_or_else(|error| panic!("oversized fixture length: {error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("oversized fixture mode: {error}"));
        assert!(matches!(
            super::read_secure_file(&path, super::MAX_PRIVATE_KEY_BYTES),
            Err(LabHttpsError::Custody)
        ));
    }
}
