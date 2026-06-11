use thiserror::Error;

/// Errors from cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("randomness verification failed: {reason}")]
    RandomnessVerificationFailed { reason: String },

    #[error("insufficient contributions: need {need}, got {got}")]
    InsufficientContributions { need: usize, got: usize },

    #[error("signature verification failed: {reason}")]
    SignatureVerificationFailed { reason: String },

    #[error("insufficient partial signatures: need {need}, got {got}")]
    InsufficientSignatures { need: usize, got: usize },

    #[error("unknown verifier: {0}")]
    UnknownVerifier(String),

    #[error("transcript commitment mismatch")]
    TranscriptMismatch,

    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),

    /// A signer failed to produce a partial signature.
    ///
    /// Returned by `FrostParticipant::round2` when the FROST round-2 protocol
    /// rejects the inputs (e.g., nonces inconsistent with the signing package).
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// The coordinator failed to aggregate partial signatures into a threshold approval.
    ///
    /// Returned by `frost_collect_approval` when fewer than `threshold` valid
    /// shares are provided, or when the FROST aggregation math fails.
    #[error("threshold aggregation failed: {0}")]
    AggregationFailed(String),

    /// A DKG key-announcement error: wrong ceremony binding, bad signature,
    /// missing/duplicate announcement, or unknown participant.
    ///
    /// Distinct from `SignatureVerificationFailed` (which covers FROST/AEAD
    /// authentication failures) so that announcement-layer errors have clear,
    /// actionable messages.
    #[error("DKG key-announcement error: {0}")]
    DkgAnnouncement(String),
}
