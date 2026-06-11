//! Layer 3: node identity and key registry for authenticated transports.
//!
//! # Components
//!
//! - `NodeIdentity` — holds a node's ed25519 signing key and verifier ID.
//!   Used to sign outgoing `SignedEnvelope`s.
//!
//! - `NodeKeyRegistry` — maps `VerifierId` → `VerifyingKey`.
//!   Used to verify incoming `SignedEnvelope`s.
//!   Wraps `EnvelopeKeyRegistry` with convenient construction helpers.
//!
//! # Usage pattern
//!
//! At startup, each node:
//! 1. Creates a `NodeIdentity` (generates or loads a signing key).
//! 2. Distributes its `VerifyingKey` to all peers out-of-band (e.g. via DKG,
//!    `ParticipantRegistry`, or a config file).
//! 3. Builds a `NodeKeyRegistry` with all peer public keys.
//! 4. Passes `(&identity, &registry)` to `AuthTcpNodeTransport` or `AuthTcpAuxServer`.
//!
//! # Key derivation
//!
//! For integration with the existing DKG ceremony, a node's `VerifierId` can
//! be derived from its ed25519 verifying key via
//! `VerifierId::from_public_key(verifying_key.as_bytes())`.  This ties the
//! transport identity to the cryptographic identity used in FROST signing.

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use tls_attestation_core::ids::VerifierId;
use tls_attestation_network::signed_envelope::EnvelopeKeyRegistry;

// ── NodeIdentity ──────────────────────────────────────────────────────────────

/// A node's signing identity: a `VerifierId` and its corresponding ed25519
/// `SigningKey`.
///
/// Used to produce `SignedEnvelope`s for outgoing messages.
///
/// # Key management
///
/// For production, load the signing key from a secret store (HSM, sealed file,
/// etc.) using `NodeIdentity::from_signing_key`. Key generation at each startup
/// (`NodeIdentity::generate`) is only appropriate for ephemeral test nodes.
pub struct NodeIdentity {
    /// The node's protocol-level identity.
    pub verifier_id: VerifierId,
    /// The ed25519 signing key (secret).
    pub signing_key: SigningKey,
}

impl NodeIdentity {
    /// Generate a fresh ed25519 key pair from the OS CSPRNG.
    ///
    /// The `VerifierId` is derived from the verifying key bytes.
    /// This creates an ephemeral identity — do not use in production without
    /// persisting the signing key.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let verifier_id = VerifierId::from_public_key(verifying_key.as_bytes());
        Self { verifier_id, signing_key }
    }

    /// Construct from an existing `SigningKey` (e.g. loaded from a key store).
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let verifier_id = VerifierId::from_public_key(verifying_key.as_bytes());
        Self { verifier_id, signing_key }
    }

    /// The corresponding `VerifyingKey` (public key).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

// ── NodeKeyRegistry ───────────────────────────────────────────────────────────

/// Registry of known node public keys, used to verify incoming envelopes.
///
/// Wraps `EnvelopeKeyRegistry` with a convenient builder API.
///
/// # Thread safety
///
/// `NodeKeyRegistry` is `Clone` and cheap to share via `Arc`. The registry is
/// immutable after construction — rebuild it when the participant set changes
/// (e.g. after a key rotation or DKG ceremony).
#[derive(Clone)]
pub struct NodeKeyRegistry {
    inner: Arc<EnvelopeKeyRegistry>,
}

impl NodeKeyRegistry {
    /// Build a registry from a list of `(VerifierId, VerifyingKey)` pairs.
    pub fn new(entries: impl IntoIterator<Item = (VerifierId, VerifyingKey)>) -> Self {
        Self {
            inner: Arc::new(EnvelopeKeyRegistry::new(entries)),
        }
    }

    /// Build a registry from a slice of `NodeIdentity` references.
    ///
    /// Convenient for tests: collect all peer identities and pass them here.
    pub fn from_identities<'a>(
        identities: impl IntoIterator<Item = &'a NodeIdentity>,
    ) -> Self {
        let entries = identities
            .into_iter()
            .map(|id| (id.verifier_id.clone(), id.verifying_key()));
        Self::new(entries)
    }

    /// Access the underlying `EnvelopeKeyRegistry` for direct use with
    /// `SignedEnvelope::open`.
    pub fn as_envelope_registry(&self) -> &EnvelopeKeyRegistry {
        &self.inner
    }

    /// Number of registered keys.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if the registry contains no keys.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_consistent_verifier_id() {
        let identity = NodeIdentity::generate();
        let vk = identity.verifying_key();
        let expected_id = VerifierId::from_public_key(vk.as_bytes());
        assert_eq!(identity.verifier_id, expected_id);
    }

    #[test]
    fn from_signing_key_matches_generate_behaviour() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let identity = NodeIdentity::from_signing_key(sk);
        assert_eq!(identity.verifier_id, VerifierId::from_public_key(vk.as_bytes()));
    }

    #[test]
    fn registry_from_identities_contains_all() {
        let ids: Vec<NodeIdentity> = (0..3).map(|_| NodeIdentity::generate()).collect();
        let registry = NodeKeyRegistry::from_identities(&ids);
        assert_eq!(registry.len(), 3);
        for id in &ids {
            assert!(registry.as_envelope_registry().lookup(&id.verifier_id).is_some());
        }
    }

    #[test]
    fn registry_lookup_unknown_returns_none() {
        let registry = NodeKeyRegistry::new([]);
        let unknown = VerifierId::from_bytes([0u8; 32]);
        assert!(registry.as_envelope_registry().lookup(&unknown).is_none());
    }
}