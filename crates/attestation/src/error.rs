use thiserror::Error;
use tls_attestation_core::CoreError;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("session error: {0}")]
    Core(#[from] CoreError),

    #[error("invalid state transition: cannot move from {from} to {to}")]
    InvalidTransition { from: String, to: String },

    #[error("session expired")]
    SessionExpired,

    #[error("randomness binding mismatch: {reason}")]
    RandomnessBindingMismatch { reason: String },

    #[error("transcript commitment mismatch: {reason}")]
    TranscriptMismatch { reason: String },

    #[error("statement digest mismatch")]
    StatementDigestMismatch,

    #[error("package digest mismatch")]
    PackageDigestMismatch,

    #[error("evidence verification failed: {reason}")]
    EvidenceVerificationFailed { reason: String },

    #[error("quorum not satisfied: need {need}, have {have}")]
    QuorumNotSatisfied { need: usize, have: usize },

    #[error("unknown session")]
    UnknownSession,

    // ── Replay-protection errors ──────────────────────────────────────────────

    /// A session with this ID already exists in the store.
    ///
    /// Returned when a coordinator attempts to create a session whose ID
    /// was previously used. Session IDs must be globally unique and are
    /// never recycled, even after expiry or finalization.
    #[error("replay detected: session ID already exists")]
    DuplicateSession,

    /// Attempted to finalize or modify a session that is already terminal.
    ///
    /// Once a session reaches `Finalized`, `Expired`, or `Failed` state,
    /// no further protocol steps may be applied to it. This error fires
    /// if the coordinator or any other actor tries to re-process such a
    /// session.
    #[error("replay detected: session is already in a terminal state")]
    SessionAlreadyTerminal,

    /// A verifier has already submitted an approval for this session.
    ///
    /// Each verifier may contribute at most one partial approval per session.
    /// Duplicate submission by the same verifier is rejected here so that
    /// the aggregation step cannot be gamed by repeated signing.
    #[error("replay detected: verifier '{verifier_id}' already approved this session")]
    DuplicateVerifierApproval { verifier_id: String },

    // ── Layer 1: TLS connection errors ────────────────────────────────────────

    /// A real TLS connection attempt failed.
    ///
    /// Produced by `TlsAttestationEngine` when it cannot establish or
    /// complete a TLS session to the target server.
    #[error("TLS connection error: {reason}")]
    TlsConnection { reason: String },

    // ── Cryptographic operation errors ────────────────────────────────────────

    /// A cryptographic operation failed (DKG, DVRF, FROST, co-SNARK).
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
}
