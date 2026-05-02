//! Core domain types for the TLS attestation system.
//!
//! This crate has no I/O, no async, and no protocol logic.
//! Everything here is safe to use from any context.

pub mod error;
pub mod hash;
pub mod ids;
pub mod types;

pub use error::CoreError;
pub use hash::{CanonicalHasher, DigestBytes, sha256, sha256_tagged};
pub use ids::{ProverId, RandomnessId, SessionId, VerifierId};
pub use types::{Epoch, Nonce, QuorumSpec, UnixTimestamp};
