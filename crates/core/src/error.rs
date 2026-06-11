//! Error types for the core crate.

use thiserror::Error;

/// Errors produced by core type construction and validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A quorum specification is logically invalid.
    #[error("invalid quorum: {reason}")]
    InvalidQuorum { reason: String },

    /// A canonical serialization step failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// An identifier was malformed or had an unexpected length.
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
}
