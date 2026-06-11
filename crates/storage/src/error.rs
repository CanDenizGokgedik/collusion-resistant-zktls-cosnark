use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    /// The requested session does not exist.
    #[error("session not found")]
    NotFound,

    /// A session with this ID already exists. Returned by `insert()`.
    ///
    /// # Replay protection invariant
    ///
    /// Session IDs are globally unique. Once a session is created, its ID
    /// must never be reused — even after the session expires or is finalized.
    /// This error is the primary enforcement point for `SessionId` replay
    /// protection at the storage layer.
    #[error("session already exists (replay protection)")]
    AlreadyExists,

    /// Attempted to mutate a session that is already in a terminal state
    /// (`Finalized`, `Expired`, or `Failed`).
    ///
    /// # Replay protection invariant
    ///
    /// Terminal sessions are immutable. No state update is allowed after a
    /// session reaches a terminal state. This prevents an attacker from
    /// re-opening a finalized session to collect additional approvals or
    /// modify its outcome.
    #[error("session is in a terminal state and cannot be modified")]
    SessionTerminated,

    /// A verifier has already submitted an approval for this session.
    ///
    /// # Replay protection invariant
    ///
    /// Each verifier may approve a given session at most once. Duplicate
    /// approvals are silently ignored or explicitly rejected depending on
    /// whether they appear in the same batch or across incremental calls.
    /// This error is returned by `record_approval` when a duplicate is detected.
    #[error("verifier '{verifier_id}' has already approved this session")]
    DuplicateApproval { verifier_id: String },

    /// Storage I/O or backend error (e.g., SQLite failure).
    #[error("storage I/O error: {0}")]
    Io(String),
}
