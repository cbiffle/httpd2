//! Error union type.

use std::io;
use thiserror::Error;

/// Error union type for the server.
#[derive(Debug, Error)]
pub enum ServeError {
    /// Errors coming from within Hyper.
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    /// I/O-related errors.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Errors in the Nix syscall interface.
    #[error(transparent)]
    Nix(#[from] nix::Error),
    /// Errors in the TLS subsystem.
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    /// Errors generated defensively to force a connection to close.
    #[error(transparent)]
    Defense(#[from] DefenseError),
}

#[derive(Debug, Error)]
#[error("defense mechanism triggered")]
pub struct DefenseError;
