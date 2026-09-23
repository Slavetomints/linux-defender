//! The crate's error type.
//!
//! Every check returns [`Result`], whose success type defaults to `()`.
//! `main` converts these into `anyhow::Error` so the operator sees a readable
//! chain rather than a panic.

/// Anything that can go wrong while running a check.
#[derive(Debug, thiserror::Error)]
pub enum DefenderError {
    /// A filesystem or stdio operation failed.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// An external command could not be run, or failed.
    #[error("Command failed: {0}")]
    Command(String),

    /// The check needs root and the process does not have it.
    #[error("This module requires root privileges")]
    NotRoot,

    /// Anything that does not fit the cases above.
    #[error("{0}")]
    Other(String),
}

/// Result alias defaulting to `()`, used by every check.
pub type Result<T = ()> = std::result::Result<T, DefenderError>;
