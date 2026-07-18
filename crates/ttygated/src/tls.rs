use std::{path::Path, sync::Arc};

use axum_server::tls_rustls::RustlsConfig;
use rustls::{
    Error as RustlsError, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use thiserror::Error;

use crate::config::TlsConfig;

const MAX_CERTIFICATE_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TlsError {
    #[error("TLS certificate path is unsafe; use an absolute regular non-symlink file")]
    CertificatePathUnsafe,
    #[error("TLS private-key path is unsafe; use a restricted absolute regular non-symlink file")]
    PrivateKeyPathUnsafe,
    #[error("TLS certificate file is not readable")]
    CertificateUnreadable,
    #[error("TLS private-key file is not readable")]
    PrivateKeyUnreadable,
    #[error("TLS certificate file is malformed")]
    CertificateMalformed,
    #[error("TLS private-key file is malformed or contains multiple keys")]
    PrivateKeyMalformed,
    #[error("TLS certificate and private key do not match")]
    KeyMismatch,
}

#[derive(Clone, Copy)]
enum MaterialKind {
    Certificate,
    PrivateKey,
}

pub async fn load(config: &TlsConfig) -> Result<RustlsConfig, TlsError> {
    inspect(
        &config.certificate,
        MaterialKind::Certificate,
        MAX_CERTIFICATE_BYTES,
    )
    .await?;
    inspect(
        &config.private_key,
        MaterialKind::PrivateKey,
        MAX_PRIVATE_KEY_BYTES,
    )
    .await?;

    let certificate = tokio::fs::read(&config.certificate)
        .await
        .map_err(|_| TlsError::CertificateUnreadable)?;
    let private_key = tokio::fs::read(&config.private_key)
        .await
        .map_err(|_| TlsError::PrivateKeyUnreadable)?;

    let certificates = CertificateDer::pem_slice_iter(&certificate)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::CertificateMalformed)?;
    if certificates.is_empty() {
        return Err(TlsError::CertificateMalformed);
    }
    let mut private_keys = PrivateKeyDer::pem_slice_iter(&private_key);
    let private_key = private_keys
        .next()
        .ok_or(TlsError::PrivateKeyMalformed)?
        .map_err(|_| TlsError::PrivateKeyMalformed)?;
    if private_keys.next().is_some() {
        return Err(TlsError::PrivateKeyMalformed);
    }

    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(classify_rustls_error)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

async fn inspect(path: &Path, kind: MaterialKind, maximum: u64) -> Result<(), TlsError> {
    if !path.is_absolute() {
        return Err(path_error(kind));
    }
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| unreadable_error(kind))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(path_error(kind));
    }
    #[cfg(unix)]
    if matches!(kind, MaterialKind::PrivateKey) {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(TlsError::PrivateKeyPathUnsafe);
        }
    }
    Ok(())
}

fn path_error(kind: MaterialKind) -> TlsError {
    match kind {
        MaterialKind::Certificate => TlsError::CertificatePathUnsafe,
        MaterialKind::PrivateKey => TlsError::PrivateKeyPathUnsafe,
    }
}

fn unreadable_error(kind: MaterialKind) -> TlsError {
    match kind {
        MaterialKind::Certificate => TlsError::CertificateUnreadable,
        MaterialKind::PrivateKey => TlsError::PrivateKeyUnreadable,
    }
}

fn classify_rustls_error(error: RustlsError) -> TlsError {
    match error {
        RustlsError::InconsistentKeys(_) => TlsError::KeyMismatch,
        RustlsError::InvalidCertificate(_) | RustlsError::NoCertificatesPresented => {
            TlsError::CertificateMalformed
        }
        _ => TlsError::PrivateKeyMalformed,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tempfile::TempDir;

    use crate::config::TlsConfig;

    use super::{TlsError, load};

    struct Material {
        directory: TempDir,
        certificate: PathBuf,
        private_key: PathBuf,
    }

    impl Material {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let certificate = directory.path().join("certificate.pem");
            let private_key = directory.path().join("private-key.pem");
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(["localhost".to_owned()]).unwrap();
            write(&certificate, cert.pem().as_bytes(), 0o644);
            write(&private_key, signing_key.serialize_pem().as_bytes(), 0o600);
            Self {
                directory,
                certificate,
                private_key,
            }
        }

        fn config(&self) -> TlsConfig {
            TlsConfig {
                certificate: self.certificate.clone(),
                private_key: self.private_key.clone(),
            }
        }
    }

    fn write(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        set_mode(path, mode);
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_mode(_path: &Path, _mode: u32) {}

    #[tokio::test]
    async fn loads_a_matching_certificate_and_private_key() {
        let material = Material::new();
        let loaded = load(&material.config()).await.unwrap();
        assert_eq!(
            loaded.get_inner().alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[tokio::test]
    async fn missing_or_unreadable_tls_files_have_stable_non_reflecting_errors() {
        let material = Material::new();
        let missing = material
            .directory
            .path()
            .join("missing-private-sentinel.pem");
        let error = load(&TlsConfig {
            certificate: material.certificate.clone(),
            private_key: missing,
        })
        .await
        .unwrap_err();
        assert_eq!(error, TlsError::PrivateKeyUnreadable);
        assert!(!error.to_string().contains("missing-private-sentinel"));

        set_mode(&material.certificate, 0o000);
        let error = load(&material.config()).await.unwrap_err();
        assert_eq!(error, TlsError::CertificateUnreadable);
        assert!(
            !error
                .to_string()
                .contains(material.directory.path().to_str().unwrap())
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_directory_empty_and_oversize_tls_paths_are_unsafe() {
        use std::os::unix::fs::symlink;

        let material = Material::new();
        let symlink_path = material.directory.path().join("symlink.pem");
        symlink(&material.certificate, &symlink_path).unwrap();
        for (path, expected) in [
            (symlink_path, TlsError::CertificatePathUnsafe),
            (
                material.directory.path().to_path_buf(),
                TlsError::CertificatePathUnsafe,
            ),
        ] {
            let error = load(&TlsConfig {
                certificate: path,
                private_key: material.private_key.clone(),
            })
            .await
            .unwrap_err();
            assert_eq!(error, expected);
        }

        write(&material.certificate, b"", 0o644);
        assert_eq!(
            load(&material.config()).await.unwrap_err(),
            TlsError::CertificatePathUnsafe
        );

        let oversize = material.directory.path().join("oversize.pem");
        let file = fs::File::create(&oversize).unwrap();
        file.set_len(1_048_577).unwrap();
        assert_eq!(
            load(&TlsConfig {
                certificate: oversize,
                private_key: material.private_key.clone(),
            })
            .await
            .unwrap_err(),
            TlsError::CertificatePathUnsafe
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_private_key_permissions_must_exclude_group_and_other() {
        let material = Material::new();
        for mode in [0o640, 0o604, 0o666] {
            set_mode(&material.private_key, mode);
            assert_eq!(
                load(&material.config()).await.unwrap_err(),
                TlsError::PrivateKeyPathUnsafe,
                "mode {mode:o} was accepted"
            );
        }
        set_mode(&material.private_key, 0o600);
        load(&material.config()).await.unwrap();
    }

    #[tokio::test]
    async fn malformed_certificate_and_private_key_are_distinct() {
        let material = Material::new();
        write(
            &material.certificate,
            b"certificate-private-sentinel",
            0o644,
        );
        let error = load(&material.config()).await.unwrap_err();
        assert_eq!(error, TlsError::CertificateMalformed);
        assert!(!error.to_string().contains("certificate-private-sentinel"));

        let material = Material::new();
        write(&material.private_key, b"key-private-sentinel", 0o600);
        let error = load(&material.config()).await.unwrap_err();
        assert_eq!(error, TlsError::PrivateKeyMalformed);
        assert!(!error.to_string().contains("key-private-sentinel"));
    }

    #[tokio::test]
    async fn mismatched_certificate_and_private_key_are_rejected() {
        let first = Material::new();
        let second = Material::new();
        let error = load(&TlsConfig {
            certificate: first.certificate.clone(),
            private_key: second.private_key.clone(),
        })
        .await
        .unwrap_err();
        assert_eq!(error, TlsError::KeyMismatch);
    }

    #[tokio::test]
    async fn multiple_private_keys_are_rejected() {
        let material = Material::new();
        let key = fs::read(&material.private_key).unwrap();
        let mut multiple = key.clone();
        multiple.extend_from_slice(&key);
        write(&material.private_key, &multiple, 0o600);
        assert_eq!(
            load(&material.config()).await.unwrap_err(),
            TlsError::PrivateKeyMalformed
        );
    }
}
