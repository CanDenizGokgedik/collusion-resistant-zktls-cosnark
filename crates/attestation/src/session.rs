//! Session model and state machine.
//!
//! Every attestation flows through a `SessionContext` with an explicit
//! `SessionState` enum. State transitions are checked — you cannot, for
//! example, mark a session as `Finalized` without first having it in
//! `Collecting` state.
//!
//! # Security invariants
//!
//! - Sessions are immutable after creation except for state transitions.
//! - The session nonce and expiry are set at creation and never modified.
//! - A session in `Expired` or `Failed` state cannot be advanced.

use crate::error::AttestationError;
use serde::{Deserialize, Serialize};
use tls_attestation_core::{
    hash::{CanonicalHasher, DigestBytes},
    ids::{ProverId, SessionId, VerifierId},
    types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
};

/// The lifecycle state of an attestation session.
///
/// Transitions (allowed):
/// ```text
/// Pending     → Active      (session init acknowledged by verifier set)
/// Active      → Attesting   (DVRF randomness generated)
/// Attesting   → Collecting  (attestation engine produced evidence)
/// Collecting  → Finalized   (threshold approval assembled)
/// Any state   → Expired     (expiry timestamp passed)
/// Any state   → Failed      (unrecoverable error)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session created, waiting for verifier set acknowledgement.
    Pending,
    /// Verifier set online, DVRF randomness being generated.
    Active,
    /// Randomness ready, attestation engine running.
    Attesting,
    /// Evidence produced, collecting threshold approvals from aux verifiers.
    Collecting,
    /// Threshold approval assembled; envelope produced and delivered.
    Finalized,
    /// Session passed its expiry deadline before finalizing.
    Expired,
    /// Session encountered an unrecoverable error.
    Failed { reason: String },
}

impl SessionState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Finalized | Self::Expired | Self::Failed { .. })
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Active => "Active",
            Self::Attesting => "Attesting",
            Self::Collecting => "Collecting",
            Self::Finalized => "Finalized",
            Self::Expired => "Expired",
            Self::Failed { .. } => "Failed",
        }
    }

    /// Check whether a transition to `next` is valid from the current state.
    pub fn can_transition_to(&self, next: &SessionState) -> bool {
        if self.is_terminal() {
            return false;
        }
        matches!(
            (self, next),
            (Self::Pending, Self::Active)
                | (Self::Active, Self::Attesting)
                | (Self::Attesting, Self::Collecting)
                | (Self::Collecting, Self::Finalized)
                | (_, Self::Expired)
                | (_, Self::Failed { .. })
        )
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// All metadata defining an attestation session.
///
/// Immutable after construction. The `session_digest` commits to all
/// fields in canonical order, binding the session identity to every
/// artifact produced during the protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub session_id: SessionId,
    pub prover_id: ProverId,
    pub coordinator_id: VerifierId,
    pub quorum: QuorumSpec,
    pub epoch: Epoch,
    pub created_at: UnixTimestamp,
    pub expires_at: UnixTimestamp,
    pub nonce: Nonce,
    /// Canonical digest of all session fields.
    /// Computed at construction time; never updated.
    pub session_digest: DigestBytes,
}

impl SessionContext {
    /// Construct a new session context and compute its canonical digest.
    ///
    /// # Canonical digest field order
    ///
    /// 1. session_id (16 bytes fixed)
    /// 2. prover_id  (32 bytes fixed)
    /// 3. coordinator_id (32 bytes fixed)
    /// 4. epoch (u64)
    /// 5. created_at (u64)
    /// 6. expires_at (u64)
    /// 7. nonce (32 bytes fixed)
    /// 8. threshold (u64)
    /// 9. verifier_count (u64)
    /// 10. each verifier_id in order (32 bytes each)
    pub fn new(
        session_id: SessionId,
        prover_id: ProverId,
        coordinator_id: VerifierId,
        quorum: QuorumSpec,
        epoch: Epoch,
        created_at: UnixTimestamp,
        expires_at: UnixTimestamp,
        nonce: Nonce,
    ) -> Self {
        // Clamp expires_at to be at least 1 second after created_at.
        // A session context with expires_at ≤ created_at would appear
        // immediately expired, causing spurious failures in downstream
        // `is_expired()` checks with no useful diagnostic.
        let expires_at = if expires_at.0 <= created_at.0 {
            // Warn rather than panic — coordinator misconfiguration, not a
            // security invariant violation.
            eprintln!(
                "WARN SessionContext::new: expires_at({}) <= created_at({}); \
                 clamping to created_at + 1",
                expires_at.0, created_at.0,
            );
            UnixTimestamp(created_at.0.saturating_add(1))
        } else {
            expires_at
        };

        let session_digest =
            Self::compute_digest(&session_id, &prover_id, &coordinator_id, &quorum, epoch, created_at, expires_at, &nonce);

        Self {
            session_id,
            prover_id,
            coordinator_id,
            quorum,
            epoch,
            created_at,
            expires_at,
            nonce,
            session_digest,
        }
    }

    fn compute_digest(
        session_id: &SessionId,
        prover_id: &ProverId,
        coordinator_id: &VerifierId,
        quorum: &QuorumSpec,
        epoch: Epoch,
        created_at: UnixTimestamp,
        expires_at: UnixTimestamp,
        nonce: &Nonce,
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/session-context/v1");
        h.update_fixed(session_id.as_bytes());
        h.update_fixed(prover_id.as_bytes());
        h.update_fixed(coordinator_id.as_bytes());
        h.update_u64(epoch.0);
        h.update_u64(created_at.0);
        h.update_u64(expires_at.0);
        h.update_fixed(nonce.as_bytes());
        h.update_u64(quorum.threshold as u64);
        h.update_u64(quorum.verifiers.len() as u64);
        for v in &quorum.verifiers {
            h.update_fixed(v.as_bytes());
        }
        h.finalize()
    }

    /// Check whether this session has expired as of `now`.
    pub fn is_expired(&self, now: UnixTimestamp) -> bool {
        self.expires_at.has_expired(now)
    }
}

/// A session together with its current lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub context: SessionContext,
    pub state: SessionState,
}

impl Session {
    pub fn new(context: SessionContext) -> Self {
        Self {
            context,
            state: SessionState::Pending,
        }
    }

    /// Attempt to transition to `next_state`, enforcing valid transitions.
    pub fn transition(&mut self, next_state: SessionState) -> Result<(), AttestationError> {
        if !self.state.can_transition_to(&next_state) {
            return Err(AttestationError::InvalidTransition {
                from: self.state.to_string(),
                to: next_state.to_string(),
            });
        }
        self.state = next_state;
        Ok(())
    }

    pub fn expire(&mut self) {
        if !self.state.is_terminal() {
            self.state = SessionState::Expired;
        }
    }

    pub fn fail(&mut self, reason: String) {
        if !self.state.is_terminal() {
            self.state = SessionState::Failed { reason };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::ids::VerifierId;

    fn make_session() -> Session {
        let quorum = QuorumSpec::new(
            vec![VerifierId::from_bytes([1u8; 32]), VerifierId::from_bytes([2u8; 32])],
            2,
        )
        .unwrap();
        let ctx = SessionContext::new(
            SessionId::new_random(),
            ProverId::from_bytes([10u8; 32]),
            VerifierId::from_bytes([1u8; 32]),
            quorum,
            Epoch::GENESIS,
            UnixTimestamp(1000),
            UnixTimestamp(2000),
            Nonce::from_bytes([99u8; 32]),
        );
        Session::new(ctx)
    }

    #[test]
    fn happy_path_transitions() {
        let mut s = make_session();
        s.transition(SessionState::Active).unwrap();
        s.transition(SessionState::Attesting).unwrap();
        s.transition(SessionState::Collecting).unwrap();
        s.transition(SessionState::Finalized).unwrap();
        assert_eq!(s.state, SessionState::Finalized);
    }

    #[test]
    fn cannot_skip_states() {
        let mut s = make_session();
        assert!(s.transition(SessionState::Attesting).is_err());
    }

    #[test]
    fn terminal_state_cannot_transition() {
        let mut s = make_session();
        s.transition(SessionState::Active).unwrap();
        s.expire();
        assert!(s.transition(SessionState::Attesting).is_err());
    }

    #[test]
    fn session_digest_is_deterministic() {
        let quorum = QuorumSpec::new(vec![VerifierId::from_bytes([1u8; 32])], 1).unwrap();
        let ctx1 = SessionContext::new(
            SessionId::from_bytes([0u8; 16]),
            ProverId::from_bytes([0u8; 32]),
            VerifierId::from_bytes([1u8; 32]),
            quorum.clone(),
            Epoch::GENESIS,
            UnixTimestamp(100),
            UnixTimestamp(200),
            Nonce::from_bytes([0u8; 32]),
        );
        let ctx2 = SessionContext::new(
            SessionId::from_bytes([0u8; 16]),
            ProverId::from_bytes([0u8; 32]),
            VerifierId::from_bytes([1u8; 32]),
            quorum,
            Epoch::GENESIS,
            UnixTimestamp(100),
            UnixTimestamp(200),
            Nonce::from_bytes([0u8; 32]),
        );
        assert_eq!(ctx1.session_digest, ctx2.session_digest);
    }

    #[test]
    fn different_nonces_produce_different_digests() {
        let quorum = QuorumSpec::new(vec![VerifierId::from_bytes([1u8; 32])], 1).unwrap();
        let make = |nonce_byte: u8| {
            SessionContext::new(
                SessionId::from_bytes([0u8; 16]),
                ProverId::from_bytes([0u8; 32]),
                VerifierId::from_bytes([1u8; 32]),
                quorum.clone(),
                Epoch::GENESIS,
                UnixTimestamp(100),
                UnixTimestamp(200),
                Nonce::from_bytes([nonce_byte; 32]),
            )
        };
        assert_ne!(make(1).session_digest, make(2).session_digest);
    }
}
