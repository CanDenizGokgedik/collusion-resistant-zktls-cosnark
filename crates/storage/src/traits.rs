//! Session store trait.
//!
//! # Replay protection invariants
//!
//! The `SessionStore` is the authoritative enforcement point for several
//! replay-protection invariants:
//!
//! 1. **SessionId uniqueness**: `insert` fails with `AlreadyExists` if the ID
//!    has ever been used, even after the session expires. Session IDs are never
//!    recycled.
//!
//! 2. **Terminal immutability**: `update_state` fails with `SessionTerminated`
//!    if the session is already in a terminal state (`Finalized`, `Expired`,
//!    `Failed`). No protocol step may re-open a terminal session.
//!
//! 3. **Per-verifier approval uniqueness**: `record_approval` fails with
//!    `DuplicateApproval` if the same verifier has already approved the session.
//!    This prevents a malicious or replaying verifier from inflating the
//!    approval count.
//!
//! # Session retention
//!
//! Sessions MUST NOT be removed from the store while they are within their
//! validity window (`expires_at` has not passed). Removing a session before
//! expiry would allow `SessionId` reuse during the validity window, which is
//! a replay vulnerability. In a production deployment, the `remove` method
//! should only be called after a configurable retention period following
//! session expiry.

use crate::error::StorageError;
use tls_attestation_attestation::session::{Session, SessionState};
use tls_attestation_core::ids::{SessionId, VerifierId};

/// Persistent store for session lifecycle state.
///
/// All methods must be safe to call concurrently. Implementations must hold
/// the listed invariants under concurrent access.
pub trait SessionStore: Send + Sync {
    /// Insert a new session. Fails with `AlreadyExists` if the session ID
    /// has previously been used, regardless of that session's current state.
    ///
    /// # Replay invariant
    ///
    /// This is the primary `SessionId` replay-protection gate. The check must
    /// be atomic with the insert (no TOCTOU window).
    fn insert(&self, session: Session) -> Result<(), StorageError>;

    /// Retrieve a session by ID. Returns `StorageError::NotFound` if absent.
    fn get(&self, id: &SessionId) -> Result<Session, StorageError>;

    /// Update the state of an existing session.
    ///
    /// Returns `StorageError::SessionTerminated` if the session is already
    /// in a terminal state (`Finalized`, `Expired`, `Failed`). Terminal
    /// sessions are immutable — this is a replay-protection invariant.
    ///
    /// Returns `StorageError::NotFound` if the session does not exist.
    fn update_state(&self, id: &SessionId, state: SessionState) -> Result<(), StorageError>;

    /// Record that a verifier has approved a session.
    ///
    /// Returns `StorageError::DuplicateApproval` if this verifier has already
    /// approved this session. This is an idempotency guard: each verifier may
    /// contribute at most one approval per session.
    ///
    /// Returns `StorageError::NotFound` if the session does not exist.
    /// Returns `StorageError::SessionTerminated` if the session is already terminal
    /// (no new approvals can be recorded for a finalized session).
    fn record_approval(&self, id: &SessionId, verifier_id: &VerifierId) -> Result<(), StorageError>;

    /// Return `true` if `verifier_id` has already submitted an approval for
    /// the given session. Returns `false` if the session does not exist.
    fn has_approved(&self, id: &SessionId, verifier_id: &VerifierId) -> bool;

    /// Remove a session. No-op if absent.
    ///
    /// # Warning
    ///
    /// Do not call this during the session's validity window. See module-level
    /// documentation for the retention policy invariant.
    fn remove(&self, id: &SessionId) -> Result<(), StorageError>;

    /// Check whether a session ID has been seen (for replay detection).
    ///
    /// Returns `true` even for sessions in terminal states. Session IDs are
    /// considered "seen" for the lifetime of the store.
    fn contains(&self, id: &SessionId) -> bool;
}
