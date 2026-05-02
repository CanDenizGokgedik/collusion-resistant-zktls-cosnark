use thiserror::Error;
use tls_attestation_attestation::error::AttestationError;
use tls_attestation_crypto::error::CryptoError;
use tls_attestation_network::error::NetworkError;
use tls_attestation_storage::error::StorageError;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("attestation error: {0}")]
    Attestation(#[from] AttestationError),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("quorum not met: received {received} of {required} approvals")]
    QuorumNotMet { received: usize, required: usize },

    #[error("no response from verifier: {0}")]
    NoResponse(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// FROST distributed-protocol violations that are distinct from
    /// cryptographic failures (e.g. nonce missing after restart, signer-set
    /// drift between rounds, duplicate round participation).
    #[error("FROST protocol violation: {0}")]
    FrostProtocol(String),

    /// DKG ceremony protocol violations: invalid sequencing, duplicate participants,
    /// incompatible participant sets, or group key mismatch after ceremony.
    /// Distinct from `Crypto` (which wraps library-level rejections) so that
    /// lifecycle misuse and configuration errors have clear, actionable messages.
    #[error("DKG protocol error: {0}")]
    DkgProtocol(String),

    /// DKG key-announcement verification failure: coordinator key substitution,
    /// wrong signing key, participant ID mismatch, missing or duplicate announcement,
    /// or stale ceremony binding.
    ///
    /// Distinct from `DkgProtocol` (lifecycle/sequencing) and `Crypto`
    /// (library-level rejections) so that pre-ceremony key-distribution errors
    /// are clearly identifiable in tests and operational logs.
    #[error("DKG key-announcement error: {0}")]
    DkgKeyAnnouncement(String),

    /// FROST signing session admission failure.
    ///
    /// Returned when a participant is rejected at Round 1 or when the
    /// coordinator-level registry admission check fails before any round
    /// request is sent.
    ///
    /// Distinct from `FrostProtocol` (sequencing/crypto violations) and
    /// `DkgKeyAnnouncement` (pre-ceremony key distribution) so that
    /// registry-based signing admission rejections are clearly identifiable.
    ///
    /// Possible causes:
    /// - Registry epoch mismatch between coordinator and aux node.
    /// - Revoked participant included in the signer set.
    /// - Retired participant included in the signer set.
    /// - Participant unknown to the registry.
    /// - Mixed-epoch signing session.
    #[error("signing admission error: {0}")]
    SigningAdmission(String),
}
