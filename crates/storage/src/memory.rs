//! In-memory session store backed by `RwLock<HashMap>`.
//!
//! Suitable for testing and single-process deployments.
//! Not durable across restarts.
//!
//! # Replay protection
//!
//! This implementation enforces all three replay-protection invariants
//! documented in `traits.rs`:
//!
//! 1. `insert` rejects duplicate `SessionId` via the `sessions` map.
//! 2. `update_state` rejects writes to terminal sessions.
//! 3. `record_approval` rejects duplicate approvals via the `approvals` map.

use crate::{error::StorageError, traits::SessionStore};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use tls_attestation_attestation::session::{Session, SessionState};
use tls_attestation_core::ids::{SessionId, VerifierId};

/// Thread-safe in-memory session store with approval tracking.
///
/// Two separate lock-protected maps are used to avoid holding a write lock
/// on sessions while checking approvals — preventing potential deadlocks
/// in future async adaptations.
#[derive(Default)]
pub struct InMemorySessionStore {
    /// Primary session store: SessionId → Session.
    sessions: RwLock<HashMap<SessionId, Session>>,
    /// Per-session verifier approval tracking: SessionId → set of VerifierId.
    ///
    /// A verifier is added here by `record_approval` when they successfully
    /// contribute a partial signature. The set is checked by `has_approved`
    /// before accepting any further partial from the same verifier.
    approvals: RwLock<HashMap<SessionId, HashSet<VerifierId>>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for InMemorySessionStore {
    fn insert(&self, session: Session) -> Result<(), StorageError> {
        // Acquire both locks in a consistent order (sessions first, then approvals)
        // to prevent deadlocks if this is ever called concurrently.
        let mut sessions = self.sessions.write().unwrap();
        let mut approvals = self.approvals.write().unwrap();

        if sessions.contains_key(&session.context.session_id) {
            // Replay protection: session ID has been used before.
            return Err(StorageError::AlreadyExists);
        }

        approvals.entry(session.context.session_id.clone()).or_default();
        sessions.insert(session.context.session_id.clone(), session);
        Ok(())
    }

    fn get(&self, id: &SessionId) -> Result<Session, StorageError> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(id).cloned().ok_or(StorageError::NotFound)
    }

    fn update_state(&self, id: &SessionId, state: SessionState) -> Result<(), StorageError> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions.get_mut(id).ok_or(StorageError::NotFound)?;

        // Replay protection: terminal sessions are immutable.
        // Returning SessionTerminated rather than silently succeeding ensures the
        // caller discovers any logic bug that attempts to re-open a closed session.
        if session.state.is_terminal() {
            return Err(StorageError::SessionTerminated);
        }

        session.state = state;
        Ok(())
    }

    fn record_approval(&self, id: &SessionId, verifier_id: &VerifierId) -> Result<(), StorageError> {
        // Check terminal state first (read lock on sessions).
        {
            let sessions = self.sessions.read().unwrap();
            let session = sessions.get(id).ok_or(StorageError::NotFound)?;
            if session.state.is_terminal() {
                return Err(StorageError::SessionTerminated);
            }
        }

        // Now record the approval (write lock on approvals).
        let mut approvals = self.approvals.write().unwrap();
        let set = approvals.get_mut(id).ok_or(StorageError::NotFound)?;

        if set.contains(verifier_id) {
            return Err(StorageError::DuplicateApproval {
                verifier_id: verifier_id.to_string(),
            });
        }

        set.insert(verifier_id.clone());
        Ok(())
    }

    fn has_approved(&self, id: &SessionId, verifier_id: &VerifierId) -> bool {
        let approvals = self.approvals.read().unwrap();
        approvals
            .get(id)
            .map(|set| set.contains(verifier_id))
            .unwrap_or(false)
    }

    fn remove(&self, id: &SessionId) -> Result<(), StorageError> {
        let mut sessions = self.sessions.write().unwrap();
        let mut approvals = self.approvals.write().unwrap();
        sessions.remove(id);
        approvals.remove(id);
        Ok(())
    }

    fn contains(&self, id: &SessionId) -> bool {
        self.sessions.read().unwrap().contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_attestation::session::{Session, SessionContext, SessionState};
    use tls_attestation_core::{
        ids::{ProverId, SessionId, VerifierId},
        types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
    };

    fn make_session(id_byte: u8) -> Session {
        let quorum = QuorumSpec::new(vec![VerifierId::from_bytes([1u8; 32])], 1).unwrap();
        let ctx = SessionContext::new(
            SessionId::from_bytes([id_byte; 16]),
            ProverId::from_bytes([0u8; 32]),
            VerifierId::from_bytes([1u8; 32]),
            quorum,
            Epoch::GENESIS,
            UnixTimestamp(100),
            UnixTimestamp(200),
            Nonce::from_bytes([0u8; 32]),
        );
        Session::new(ctx)
    }

    fn verifier(b: u8) -> VerifierId {
        VerifierId::from_bytes([b; 32])
    }

    // ── Basic CRUD ────────────────────────────────────────────────────────────

    #[test]
    fn insert_and_get() {
        let store = InMemorySessionStore::new();
        let s = make_session(1);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.context.session_id, id);
    }

    #[test]
    fn duplicate_insert_fails() {
        let store = InMemorySessionStore::new();
        let s = make_session(2);
        store.insert(s.clone()).unwrap();
        assert!(matches!(store.insert(s), Err(StorageError::AlreadyExists)));
    }

    #[test]
    fn update_state_non_terminal_succeeds() {
        let store = InMemorySessionStore::new();
        let s = make_session(3);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Active).unwrap();
        let updated = store.get(&id).unwrap();
        assert_eq!(updated.state, SessionState::Active);
    }

    #[test]
    fn contains_and_remove() {
        let store = InMemorySessionStore::new();
        let s = make_session(4);
        let id = s.context.session_id.clone();
        assert!(!store.contains(&id));
        store.insert(s).unwrap();
        assert!(store.contains(&id));
        store.remove(&id).unwrap();
        assert!(!store.contains(&id));
    }

    // ── Replay protection: terminal state immutability ────────────────────────

    #[test]
    fn update_state_on_finalized_session_fails() {
        let store = InMemorySessionStore::new();
        let s = make_session(5);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();

        // Advance through states to Finalized.
        store.update_state(&id, SessionState::Active).unwrap();
        store.update_state(&id, SessionState::Attesting).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();
        store.update_state(&id, SessionState::Finalized).unwrap();

        // Any further update must be rejected.
        let result = store.update_state(&id, SessionState::Active);
        assert!(
            matches!(result, Err(StorageError::SessionTerminated)),
            "expected SessionTerminated, got {result:?}"
        );
    }

    #[test]
    fn update_state_on_expired_session_fails() {
        let store = InMemorySessionStore::new();
        let s = make_session(6);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Expired).unwrap();

        let result = store.update_state(&id, SessionState::Active);
        assert!(matches!(result, Err(StorageError::SessionTerminated)));
    }

    #[test]
    fn update_state_on_failed_session_fails() {
        let store = InMemorySessionStore::new();
        let s = make_session(7);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store
            .update_state(&id, SessionState::Failed { reason: "test".into() })
            .unwrap();

        let result = store.update_state(&id, SessionState::Active);
        assert!(matches!(result, Err(StorageError::SessionTerminated)));
    }

    // ── Replay protection: session ID uniqueness persists after finalization ──

    #[test]
    fn session_id_rejected_after_finalization() {
        // Invariant: even after a session is finalized, its ID cannot be reused.
        let store = InMemorySessionStore::new();
        let s = make_session(8);
        let id = s.context.session_id.clone();
        store.insert(s.clone()).unwrap();
        store.update_state(&id, SessionState::Active).unwrap();
        store.update_state(&id, SessionState::Attesting).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();
        store.update_state(&id, SessionState::Finalized).unwrap();

        // Attempting to insert a new session with the same ID must fail.
        assert!(matches!(store.insert(s), Err(StorageError::AlreadyExists)));
    }

    // ── Replay protection: per-verifier approval deduplication ───────────────

    #[test]
    fn record_approval_succeeds_first_time() {
        let store = InMemorySessionStore::new();
        let s = make_session(9);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();

        assert!(!store.has_approved(&id, &verifier(1)));
        store.record_approval(&id, &verifier(1)).unwrap();
        assert!(store.has_approved(&id, &verifier(1)));
    }

    #[test]
    fn record_approval_duplicate_fails() {
        let store = InMemorySessionStore::new();
        let s = make_session(10);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();

        store.record_approval(&id, &verifier(2)).unwrap();
        let result = store.record_approval(&id, &verifier(2));
        assert!(
            matches!(result, Err(StorageError::DuplicateApproval { .. })),
            "expected DuplicateApproval, got {result:?}"
        );
    }

    #[test]
    fn different_verifiers_can_both_approve() {
        let store = InMemorySessionStore::new();
        let s = make_session(11);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();

        store.record_approval(&id, &verifier(3)).unwrap();
        store.record_approval(&id, &verifier(4)).unwrap();
        assert!(store.has_approved(&id, &verifier(3)));
        assert!(store.has_approved(&id, &verifier(4)));
    }

    #[test]
    fn record_approval_on_terminal_session_fails() {
        let store = InMemorySessionStore::new();
        let s = make_session(12);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Active).unwrap();
        store.update_state(&id, SessionState::Attesting).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();
        store.update_state(&id, SessionState::Finalized).unwrap();

        // Approvals after finalization must be rejected.
        let result = store.record_approval(&id, &verifier(5));
        assert!(
            matches!(result, Err(StorageError::SessionTerminated)),
            "expected SessionTerminated, got {result:?}"
        );
    }

    #[test]
    fn has_approved_returns_false_for_unknown_session() {
        let store = InMemorySessionStore::new();
        let unknown_id = SessionId::from_bytes([0xFFu8; 16]);
        assert!(!store.has_approved(&unknown_id, &verifier(1)));
    }
}
