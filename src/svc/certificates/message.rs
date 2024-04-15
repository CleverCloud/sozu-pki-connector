//! # Message module
//!
//! This module provides helpers to generate messages to send to Sōzu

use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use sozu_command_lib::proto::command::{
    request::RequestType, AddCertificate, CertificateAndKey, RemoveCertificate, ReplaceCertificate,
};
use tracing::{trace, Level};

use crate::svc::certificates::{self, Metadata};

// -------------------------------------------------------------------------------------
// Error

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to retrieve pki at '{0}'")]
    NoPKIAt(PathBuf),
    #[error("failed to retrieve metadata for '{0}'")]
    NoMetadataFor(PathBuf),
}

// -------------------------------------------------------------------------------------
// Helpers

#[tracing::instrument(skip_all)]
pub fn create(
    https_listener: SocketAddr,
    current: &HashMap<PathBuf, Metadata>,
    new: &HashMap<PathBuf, Metadata>,
    pki: &HashMap<PathBuf, CertificateAndKey>,
) -> Result<Vec<(PathBuf, RequestType)>, Error> {
    let diff = certificates::diff::create(current, new);

    // ---------------------------------------------------------------------------------
    // Create messages to add new certificates
    let mut acc = vec![];
    for added in diff.added.into_iter() {
        let metadata = new
            .get(&added)
            .ok_or_else(|| Error::NoMetadataFor(added.to_owned()))?;

        let names = metadata.names.iter().cloned().collect::<Vec<_>>();
        trace!(
            address = https_listener.to_string(),
            names = names.join(", "),
            fingerprint = metadata.fingerprint.to_string(),
            "Create a message to add certificate to proxy for the given listener"
        );

        let request_type = RequestType::AddCertificate(AddCertificate {
            address: https_listener.into(),
            certificate: pki
                .get(&added)
                .ok_or_else(|| Error::NoPKIAt(added.to_owned()))?
                .to_owned(),
            expired_at: None,
        });

        acc.push((added, request_type))
    }

    // ---------------------------------------------------------------------------------
    // Create messages to delete old certificates
    for deleted in diff.deleted.into_iter() {
        let metadata = current
            .get(&deleted)
            .ok_or_else(|| Error::NoMetadataFor(deleted.to_owned()))?;

        trace!(
            address = https_listener.to_string(),
            fingerprint = metadata.fingerprint.to_string(),
            "Create a message to delete certificate from proxy for the given listener"
        );

        let request_type = RequestType::RemoveCertificate(RemoveCertificate {
            address: https_listener.into(),
            fingerprint: metadata.fingerprint.to_string(),
        });

        acc.push((deleted, request_type))
    }

    // -----------------------------------------------------------------------------
    // Create messages to replace modified certificates
    for modified in diff.modified {
        let metadata = current
            .get(&modified)
            .ok_or_else(|| Error::NoMetadataFor(modified.to_owned()))?;

        let new_names = metadata.names.iter().cloned().collect::<Vec<_>>();
        if tracing::enabled!(Level::TRACE) {
            trace!(
                address = https_listener.to_string(),
                names = new_names.join(", "),
                new_fingerprint = new
                    .get(&modified)
                    .ok_or_else(|| Error::NoMetadataFor(modified.to_owned()))?
                    .fingerprint
                    .to_string(),
                old_fingerprint = metadata.fingerprint.to_string(),
                "Create a message to replace certificate of proxy for the given listener"
            );
        }

        let request_type = RequestType::ReplaceCertificate(ReplaceCertificate {
            address: https_listener.into(),
            new_certificate: pki
                .get(&modified)
                .ok_or_else(|| Error::NoPKIAt(modified.to_owned()))?
                .to_owned(),
            old_fingerprint: metadata.fingerprint.to_string(),
            new_expired_at: None,
        });

        acc.push((modified, request_type))
    }

    Ok(acc)
}
