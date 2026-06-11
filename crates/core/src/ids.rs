//! Strongly-typed identifiers for the attestation protocol.
//!
//! All IDs are newtype wrappers around fixed-size byte arrays. This prevents
//! accidental confusion between same-sized values that carry different semantics
//! (e.g., `VerifierId` vs `ProverId`, which are both 32 bytes at runtime).
//!
//! # Identity derivation
//!
//! In production, `VerifierId` and `ProverId` should be derived from
//! long-term public keys via `from_public_key()`. This ties identity to
//! cryptographic capability and prevents impersonation.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Unique identifier for an attestation session.
///
/// Derived from a UUID v4, providing 122 bits of entropy.
/// Sessions MUST NOT be reused. A new `SessionId` must be generated per request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// Generate a new random session ID using the OS CSPRNG.
    pub fn new_random() -> Self {
        Self(*Uuid::new_v4().as_bytes())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session:{}", hex::encode(self.0))
    }
}

/// Identifier for a verifier node (coordinator or auxiliary).
///
/// In production, derive this from the verifier's long-term public key:
/// `SHA-256(serialized_public_key)`. This makes identity self-authenticating.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerifierId([u8; 32]);

impl VerifierId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a `VerifierId` from a public key's byte representation.
    pub fn from_public_key(pk_bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self(Sha256::digest(pk_bytes).into())
    }
}

impl fmt::Display for VerifierId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "verifier:{}", hex::encode(&self.0[..8]))
    }
}

/// Identifier for the entity requesting attestation (the prover / client).
///
/// Binding the `ProverId` to a session prevents one prover's attested session
/// from being repurposed for a different prover's benefit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProverId([u8; 32]);

impl ProverId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a `ProverId` from a public key's byte representation.
    pub fn from_public_key(pk_bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self(Sha256::digest(pk_bytes).into())
    }
}

impl fmt::Display for ProverId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prover:{}", hex::encode(&self.0[..8]))
    }
}

/// Identifier for a distributed randomness generation round.
///
/// Each session's randomness is bound to a unique `RandomnessId` to prevent
/// randomness from being reused across sessions or epochs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RandomnessId([u8; 16]);

impl RandomnessId {
    pub fn new_random() -> Self {
        Self(*Uuid::new_v4().as_bytes())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for RandomnessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rng:{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_unique() {
        let a = SessionId::new_random();
        let b = SessionId::new_random();
        assert_ne!(a, b);
    }

    #[test]
    fn session_id_roundtrip() {
        let id = SessionId::new_random();
        let bytes = *id.as_bytes();
        let id2 = SessionId::from_bytes(bytes);
        assert_eq!(id, id2);
    }

    #[test]
    fn verifier_id_from_public_key_is_deterministic() {
        let pk = b"fake-public-key-material";
        let a = VerifierId::from_public_key(pk);
        let b = VerifierId::from_public_key(pk);
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_produce_different_ids() {
        let a = VerifierId::from_public_key(b"key-one");
        let b = VerifierId::from_public_key(b"key-two");
        assert_ne!(a, b);
    }
}
