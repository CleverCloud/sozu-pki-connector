//! # Watcher module
//!
//! This module provides a watcher to handle certificates refreshment

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, IntCounterVec};
use sozu_client::{
    channel::ConnectionProperties, config::canonicalize_command_socket, Client, Sender,
};
use sozu_command_lib::proto::display::format_request_type;
use tokio::time::interval;
use tracing::{debug, error, info, trace, warn};

use crate::svc::{
    certificates::{self, message, Metadata},
    config::ConnectorConfiguration,
};

// -----------------------------------------------------------------------------
// Telemetry

static CERTIFICATE_REQUEST_EMITTED: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "proxy_manager_certificate_request_emitted",
        "Number of request emitted by the certificate daemon",
        &["kind"]
    )
    .expect("'proxy_manager_certificate_request_emitted' to not be already registered")
});

static CERTIFICATE_REQUEST_EMITTED_ERROR: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "proxy_manager_certificate_request_emitted_error",
        "Number of request emitted by the certificate daemon in error",
        &["kind"]
    )
    .expect("'proxy_manager_certificate_request_emitted_error' to not be already registered")
});

// -----------------------------------------------------------------------------
// Error

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to find certificates at '{0}', {1}")]
    FindCertificates(PathBuf, certificates::Error),
    #[error("failed to compute metadata from certificate '{0}', {1}")]
    ComputeMetadata(PathBuf, certificates::Error),
    #[error("failed to compute message, {0}")]
    ComputeMessage(message::Error),
    #[error("failed to send request to update Sōzu certificate, {0}")]
    Send(sozu_client::Error),
    #[error("failed to load sōzu configuration, {0}")]
    SozuConfiguration(sozu_client::config::Error),
    #[error("failed to create Sōzu client, {0}")]
    CreateClient(sozu_client::Error),
    #[error("failed to canonicalize path to command socket, {0}")]
    CanonicalizeSocket(sozu_client::config::Error),
}

// -----------------------------------------------------------------------------
// Watcher

pub struct Watcher {
    /// Configuration of the connector
    config: Arc<ConnectorConfiguration>,
    /// Sōzu client
    client: Client,
    /// Current state of certificates
    metadata: HashMap<PathBuf, Metadata>,
}

impl Watcher {
    #[tracing::instrument(skip_all)]
    pub async fn try_new(config: Arc<ConnectorConfiguration>) -> Result<Self, Error> {
        // -------------------------------------------------------------------------
        // Load Sōzu configuration
        info!(
            path = config.sozu.configuration.display().to_string(),
            "Load Sōzu configuration"
        );

        let sozu_config = Arc::new(
            sozu_client::config::try_from(&config.sozu.configuration)
                .map_err(Error::SozuConfiguration)?,
        );

        // -------------------------------------------------------------------------
        // Create Sōzu client
        info!("Create Sōzu client");
        let mut opts = ConnectionProperties::from(&*sozu_config);
        if opts.socket.is_relative() {
            opts.socket = canonicalize_command_socket(&config.sozu.configuration, &sozu_config)
                .map_err(Error::CanonicalizeSocket)?;
        }

        let client = Client::try_new(opts).await.map_err(Error::CreateClient)?;

        Ok(Self {
            config,
            client,
            metadata: HashMap::new(),
        })
    }

    #[tracing::instrument(skip_all)]
    pub async fn lookup(&mut self) -> Result<(), Error> {
        // -----------------------------------------------------------------------------
        // Retrieve certificates and keys on disk
        info!(
            path = self.config.sozu.pki.to_string_lossy().to_string(),
            "Load pki from disk"
        );

        let pki = certificates::find(&self.config.sozu.pki)
            .await
            .map_err(|err| Error::FindCertificates(self.config.sozu.pki.to_owned(), err))?;

        info!(number = pki.len(), "Compute metadata for pki");
        let mut metadata = HashMap::new();
        for (path, certificate_and_key) in &pki {
            metadata.insert(
                path.to_owned(),
                certificates::metadata(path.to_owned(), certificate_and_key)
                    .await
                    .map_err(|err| Error::ComputeMetadata(self.config.sozu.pki.to_owned(), err))?,
            );
        }

        // -----------------------------------------------------------------------------
        // Create messages to update Sōzu and send them
        debug!("Create diff and messages to send to the proxy");
        let requests = message::create(self.config.sozu.listener, &self.metadata, &metadata, &pki)
            .map_err(Error::ComputeMessage)?;

        let len = requests.len();
        debug!(number = len, "Number of requests to send to the proxy");

        if !requests.is_empty() {
            info!(number = len, "Send certificates requests to the proxy");
            for (idx, (path, request)) in requests.into_iter().enumerate() {
                trace!(
                    number = idx + 1,
                    total = len,
                    "Send certificate request to Sōzu"
                );

                match self.client.send(request.to_owned()).await {
                    Ok(_) => {
                        let kind = format_request_type(&request);
                        CERTIFICATE_REQUEST_EMITTED
                            .with_label_values(&[&kind])
                            .inc();

                        if 0 == idx % 1000 {
                            info!(
                                number = idx + 1,
                                total = len,
                                "Successfully sent request to Sōzu"
                            );
                        }

                        trace!(
                            number = idx + 1,
                            total = len,
                            "Successfully sent request to Sōzu"
                        );
                    }
                    Err(err) if matches!(err, sozu_client::Error::Failure(..)) => {
                        // This will be retried in the next iteration
                        match self.metadata.get(&path) {
                            Some(meta) => {
                                metadata.insert(path.to_owned(), meta.to_owned());
                            }
                            None => {
                                metadata.remove(&path);
                            }
                        }

                        let kind = format_request_type(&request);
                        CERTIFICATE_REQUEST_EMITTED_ERROR
                            .with_label_values(&[&kind])
                            .inc();

                        error!(
                            error = err.to_string(),
                            number = idx + 1,
                            total = len,
                            path = path.display().to_string(),
                            kind = kind,
                            "Could not send certificate request to Sōzu"
                        );
                    }
                    Err(err) => {
                        return Err(Error::Send(err));
                    }
                }
            }

            info!(
                number = len,
                "Successfully sent certificates requests to the proxy"
            );
        }

        // -----------------------------------------------------------------------------
        // Update the current metadata
        self.metadata = metadata;

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// helpers

#[tracing::instrument(skip_all)]
pub async fn lookup_every(config: Arc<ConnectorConfiguration>) -> Result<(), Error> {
    // -------------------------------------------------------------------------
    // Start the watcher
    let mut ticker = interval(Duration::from_millis(config.interval));
    let mut watcher = Watcher::try_new(config).await?;

    loop {
        if let Err(err) = watcher.lookup().await {
            warn!(
                error = err.to_string(),
                "Could not lookup into pki directory and send updates to Sōzu"
            );
        }

        // -----------------------------------------------------------------------------
        // Wait for the next iteration to come
        info!("Waiting for next iteration to lookup certificates directory");
        ticker.tick().await;
    }
}
