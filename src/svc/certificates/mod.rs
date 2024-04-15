//! # Certificates module
//!
//! This module provides helpers around the management of certificates

use std::{
    collections::{HashMap, HashSet},
    io,
    path::PathBuf,
};

use sozu_command_lib::{
    certificate::{
        calculate_fingerprint, get_cn_and_san_attributes, parse_pem, parse_x509, split_certificate_chain, CertificateError, Fingerprint
    },
    proto::command::CertificateAndKey,
};
use tokio::{
    fs,
    task::{spawn_blocking as blocking, JoinError},
};
use tracing::{debug, warn};

pub mod diff;
pub mod message;
pub mod watcher;

// -------------------------------------------------------------------------------------
// Error

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to read directory '{0}', {1}")]
    ReadDir(PathBuf, io::Error),
    #[error("failed to read entry, '{0}'")]
    ReadEntry(io::Error),
    #[error("failed to retrieve directory name of path '{0}'")]
    DirectoryName(PathBuf),
    #[error("failed to read path '{0}', {1}")]
    Read(PathBuf, io::Error),
    #[error("failed to parse pem, '{0}'")]
    ParsePem(CertificateError),
    #[error("failed to parse x509 from pem, '{0}'")]
    ParseX509(CertificateError),
    #[error("failed to compute fingerprint, {0}")]
    Fingerprint(Box<dyn std::error::Error + Send + Sync>),
    #[error("failed to join on task, {0}")]
    Join(JoinError),
}

impl From<JoinError> for Error {
    fn from(err: JoinError) -> Self {
        Self::Join(err)
    }
}

// -------------------------------------------------------------------------------------
// Metadata

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Metadata {
    pub fingerprint: Fingerprint,
    pub names: HashSet<String>,
    pub path: PathBuf,
    pub chain_fingerprints: HashSet<Fingerprint>,
}

impl Metadata {
    #[tracing::instrument]
    pub fn new(
        path: PathBuf,
        fingerprint: Fingerprint,
        names: HashSet<String>,
        chain_fingerprints: HashSet<Fingerprint>,
    ) -> Self {
        Self {
            path,
            names,
            fingerprint,
            chain_fingerprints,
        }
    }
}

// -------------------------------------------------------------------------------------
// Helpers

#[tracing::instrument]
pub async fn find(path: &PathBuf) -> Result<HashMap<PathBuf, CertificateAndKey>, Error> {
    let mut scanner = fs::read_dir(path)
        .await
        .map_err(|err| Error::ReadDir(path.to_owned(), err))?;

    let mut acc = HashMap::new();
    while let Some(entry) = scanner.next_entry().await.map_err(Error::ReadEntry)? {
        let path = entry.path();

        if path.is_dir() {
            debug!(
                path = path.display().to_string(),
                "Found certificate directory"
            );

            // Read certificates and key from path
            let certificate_and_key = match read(path.to_owned()).await {
                Ok(Some(certificate_and_key)) => certificate_and_key,
                Ok(None) => {
                    warn!(
                        path = path.display().to_string(),
                        "Could not read certificates and key"
                    );

                    continue;
                }
                Err(err) => {
                    warn!(
                        error = err.to_string(),
                        path = path.display().to_string(),
                        "Could not read certificates and key"
                    );

                    continue;
                }
            };

            // Compute there metadata
            acc.insert(path, certificate_and_key);
        } else {
            warn!(
                path = path.display().to_string(),
                "Found a path in certificate directory which is not a directory"
            );
        }
    }

    Ok(acc)
}

#[tracing::instrument]
pub async fn read(path: PathBuf) -> Result<Option<CertificateAndKey>, Error> {
    // ---------------------------------------------------------------------------------
    // Retrieve name of the current directory
    let name = path
        .file_name()
        .ok_or_else(|| Error::DirectoryName(path.to_owned()))?
        .to_string_lossy();

    // ---------------------------------------------------------------------------------
    // Compute path to certificate and key
    let certificates_path = path.join(format!("{name}.crt"));
    let key_path = path.join(format!("{name}.key"));
    let tls_path = path.join("options.json");

    // ---------------------------------------------------------------------------------
    // Load certificates, key and optional options
    let certificates = split_certificate_chain(
        fs::read_to_string(&certificates_path)
            .await
            .map_err(|err| Error::Read(certificates_path, err))?,
    );

    // Skip if there is no certificate
    let (certificate, certificate_chain) = match certificates.len() {
        0 => {
            warn!(
                error = "there is no certificate",
                path = path.display().to_string(),
                "Could not parse certificates"
            );

            return Ok(None);
        }
        1 => (certificates[0].to_string(), vec![]),
        _ => (certificates[0].to_string(), certificates[1..].to_vec()),
    };

    let key = fs::read_to_string(&key_path)
        .await
        .map_err(|err| Error::Read(key_path, err))?;

    // Check if the path exists, see [std::path::Path::exists] method
    let mut versions = vec![];
    if fs::metadata(&tls_path).await.is_ok() {
        let options = fs::read_to_string(&tls_path)
            .await
            .map_err(|err| Error::Read(tls_path.to_owned(), err))?;

        match blocking(move || serde_json::from_str(&options)).await? {
            Ok(options) => {
                versions = options;
            }
            Err(err) => {
                warn!(
                    error = err.to_string(),
                    path = tls_path.display().to_string(),
                    "Could not deserialize TLS versions, skip it.."
                );
            }
        }
    }

    // ---------------------------------------------------------------------------------
    // Parse certificate to retrieve SAN and CN attributes from pem
    let pem = parse_pem(certificate.as_bytes()).map_err(Error::ParsePem)?;
    let x509 = parse_x509(&pem.contents).map_err(Error::ParseX509)?;
    let names = get_cn_and_san_attributes(&x509);

    Ok(Some(CertificateAndKey {
        certificate,
        certificate_chain,
        key,
        versions,
        names: names.into_iter().collect(),
    }))
}

#[tracing::instrument(skip(certificate_and_key))]
pub async fn metadata(
    path: PathBuf,
    certificate_and_key: &CertificateAndKey,
) -> Result<Metadata, Error> {
    let names = certificate_and_key.names.iter().cloned().collect();

    // ---------------------------------------------------------------------------------
    // Compute fingerprints
    let fingerprint = calculate_fingerprint(certificate_and_key.certificate.as_bytes())
        .map(Fingerprint)
        .map_err(|err| Error::Fingerprint(err.into()))?;

    let mut chain_fingerprints = HashSet::new();
    for certificate in &certificate_and_key.certificate_chain {
        chain_fingerprints.insert(
            calculate_fingerprint(certificate.as_bytes())
                .map(Fingerprint)
                .map_err(|err| Error::Fingerprint(err.into()))?,
        );
    }

    Ok(Metadata::new(path, fingerprint, names, chain_fingerprints))
}
