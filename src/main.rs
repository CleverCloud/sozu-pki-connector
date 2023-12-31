//! # Sozu pki connector
//!
//! This application retrieve pki on a directory and load them into Sōzu

use std::{path::PathBuf, sync::Arc};

use clap::{ArgAction, Parser};
use tracing::{error, info};

use crate::svc::{
    certificates::watcher,
    config::{self, ConnectorConfiguration},
    http,
    logging::{self, LoggingInitGuard},
};

pub mod svc;

// -----------------------------------------------------------------------------
// Error

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to load configuration, {0}")]
    Configuration(config::Error),
    #[error("failed to initialize the logging system, {0}")]
    Logging(logging::Error),
    #[error("failed to create handler on termination signal, {0}")]
    Termination(std::io::Error),
    #[error("failed to serve http server, {0}")]
    HttpServer(http::server::Error),
    #[error("failed to watch pki directory, {0}")]
    Watcher(watcher::Error),
}

// -----------------------------------------------------------------------------
// Args

/// A connector that watch a directory at regular interval that contains pki to
/// load incoming certificates.
#[derive(Parser, PartialEq, Eq, Clone, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Increase verbosity
    #[clap(short = 'v', global = true, action = ArgAction::Count)]
    pub verbosity: u8,
    /// Path to the configuration file of the prometheus connector,
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
}

impl paw::ParseArgs for Args {
    type Error = Error;

    fn parse_args() -> Result<Self, Self::Error> {
        Ok(Self::parse())
    }
}

// -----------------------------------------------------------------------------
// main

#[paw::main]
#[tokio::main(flavor = "current_thread")]
pub async fn main(args: Args) -> Result<(), Error> {
    // -------------------------------------------------------------------------
    // Retrieve configuration
    let config = Arc::new(match &args.config {
        Some(path) => {
            ConnectorConfiguration::try_from(path.to_owned()).map_err(Error::Configuration)?
        }
        None => ConnectorConfiguration::try_new().map_err(Error::Configuration)?,
    });

    // -------------------------------------------------------------------------
    // Initialize logging system
    let _guard = match &config.sentry {
        Some(sentry_ctx) => {
            logging::initialize_with_sentry(args.verbosity as usize, sentry_ctx.to_owned())
                .map_err(Error::Logging)?
        }
        None => logging::initialize(args.verbosity as usize)
            .map(|_| LoggingInitGuard::default())
            .map_err(Error::Logging)?,
    };

    // -------------------------------------------------------------------------
    // Start HTTP server and listener to termination signals concurrently and
    // not in parallel

    let result = tokio::select! {
        r = tokio::signal::ctrl_c() => r.map_err(Error::Termination),
        r = http::server::serve(config.to_owned()) => r.map_err(Error::HttpServer),
        r = watcher::lookup_every(config) => r.map_err(Error::Watcher),
    };

    if let Err(err) = result {
        error!(
            error = err.to_string(),
            "Could not execute {} properly",
            env!("CARGO_PKG_NAME")
        );

        return Err(err);
    }

    info!("Gracefully halted {}!", env!("CARGO_PKG_NAME"));
    Ok(())
}
