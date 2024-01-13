//! Error union type.

use std::io;

/// Error union type for the server.
#[derive(Debug)]
pub enum ServeError {
    /// Errors coming from within Hyper.
    Hyper(hyper::Error),
    /// I/O-related errors.
    Io(io::Error),
    /// Errors in the Nix syscall interface.
    Nix(nix::Error),
    /// Errors in the TLS subsystem.
    Tls(rustls::Error),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ServeError::Hyper(e) => write!(f, "{}", e),
            ServeError::Io(e) => write!(f, "{}", e),
            ServeError::Nix(e) => write!(f, "{}", e),
            ServeError::Tls(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServeError::Hyper(e) => Some(e),
            ServeError::Io(e) => Some(e),
            ServeError::Nix(e) => Some(e),
            ServeError::Tls(e) => Some(e),
        }
    }
}

impl From<rustls::Error> for ServeError {
    fn from(x: rustls::Error) -> Self {
        ServeError::Tls(x)
    }
}

impl From<hyper::Error> for ServeError {
    fn from(x: hyper::Error) -> Self {
        ServeError::Hyper(x)
    }
}

impl From<nix::Error> for ServeError {
    fn from(x: nix::Error) -> Self {
        ServeError::Nix(x)
    }
}

impl From<io::Error> for ServeError {
    fn from(x: io::Error) -> Self {
        ServeError::Io(x)
    }
}
