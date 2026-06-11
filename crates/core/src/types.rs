//! Core protocol types: nonces, epochs, timestamps, and quorum specifications.

use crate::{error::CoreError, ids::VerifierId};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// A 32-byte cryptographic nonce, used to ensure session freshness.
///
/// # Security requirements
///
/// - MUST be unique per session (guaranteed by random generation).
/// - MUST be unpredictable (generated via a CSPRNG).
/// - MUST be included in the session commitment so that the nonce is
///   bound to this specific session and cannot be extracted and reused.
///
/// Anti-replay: the coordinator's storage layer tracks seen nonces and
/// must reject reuse within the nonce retention window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce([u8; 32]);

impl Nonce {
    /// Generate a fresh random nonce using the OS CSPRNG.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Construct from raw bytes. Use only in tests for determinism.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Epoch counter for verifier key material and randomness rotation.
///
/// All verifier public keys and DVRF secrets are scoped to an epoch.
/// When the verifier set rotates, the epoch increments. Attestations
/// are bound to their epoch at production time to prevent cross-epoch reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Epoch(pub u64);

impl Epoch {
    pub const GENESIS: Self = Self(0);
}

impl std::fmt::Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch:{}", self.0)
    }
}

/// Unix timestamp in seconds since the Unix epoch.
///
/// Used for session creation time, expiration, and freshness checks.
/// Precision: seconds (not milliseconds), sufficient for protocol timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnixTimestamp(pub u64);

impl UnixTimestamp {
    /// Current time from the system clock.
    ///
    /// # Panics
    ///
    /// Panics if the system clock is set before the Unix epoch (1970-01-01).
    /// This is an irrecoverable misconfiguration.
    pub fn now() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before unix epoch")
            .as_secs();
        Self(secs)
    }

    /// Return true if this timestamp is strictly in the past relative to `now`.
    pub fn has_expired(&self, now: UnixTimestamp) -> bool {
        now.0 > self.0
    }
}

/// Specifies the quorum requirement for a verifier set.
///
/// A quorum is satisfied when at least `threshold` verifiers from the
/// `verifiers` list have provided valid approvals.
///
/// # Security
///
/// The threshold determines the minimum collusion required to forge an
/// attestation. A threshold of `n` (all verifiers) is maximally secure
/// but has zero fault tolerance. A threshold of `ceil(n/2) + 1` is a
/// common starting point for Byzantine fault tolerance.
///
/// The verifier list is ordered but the threshold check is set-based
/// (each verifier counts at most once, regardless of how many times
/// they appear in the approvals list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumSpec {
    /// The full set of eligible verifiers for this session.
    /// Order is significant for canonical hashing.
    pub verifiers: Vec<VerifierId>,
    /// Minimum number of distinct verifier approvals required.
    pub threshold: usize,
}

impl QuorumSpec {
    /// Construct a new `QuorumSpec`, validating the threshold.
    pub fn new(verifiers: Vec<VerifierId>, threshold: usize) -> Result<Self, CoreError> {
        if verifiers.is_empty() {
            return Err(CoreError::InvalidQuorum {
                reason: "verifier set must not be empty".into(),
            });
        }
        if threshold == 0 {
            return Err(CoreError::InvalidQuorum {
                reason: "threshold must be at least 1".into(),
            });
        }
        if threshold > verifiers.len() {
            return Err(CoreError::InvalidQuorum {
                reason: format!(
                    "threshold {} exceeds verifier count {}",
                    threshold,
                    verifiers.len()
                ),
            });
        }
        Ok(Self { verifiers, threshold })
    }

    /// Return true if the given set of approvers satisfies this quorum.
    ///
    /// Only verifiers present in the original `verifiers` list are counted.
    /// Each eligible verifier is counted at most once (set semantics).
    pub fn is_satisfied_by(&self, approvers: &[VerifierId]) -> bool {
        let count = self
            .verifiers
            .iter()
            .filter(|id| approvers.contains(id))
            .count();
        count >= self.threshold
    }

    pub fn verifier_count(&self) -> usize {
        self.verifiers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::VerifierId;

    fn verifier(b: u8) -> VerifierId {
        VerifierId::from_bytes([b; 32])
    }

    #[test]
    fn quorum_construction_validates_threshold() {
        let vs = vec![verifier(1), verifier(2), verifier(3)];
        assert!(QuorumSpec::new(vs.clone(), 2).is_ok());
        assert!(QuorumSpec::new(vs.clone(), 3).is_ok());
        assert!(QuorumSpec::new(vs.clone(), 4).is_err());
        assert!(QuorumSpec::new(vs.clone(), 0).is_err());
        assert!(QuorumSpec::new(vec![], 1).is_err());
    }

    #[test]
    fn quorum_satisfied_by_threshold() {
        let v1 = verifier(1);
        let v2 = verifier(2);
        let v3 = verifier(3);
        let q = QuorumSpec::new(vec![v1.clone(), v2.clone(), v3.clone()], 2).unwrap();

        assert!(q.is_satisfied_by(&[v1.clone(), v2.clone()]));
        assert!(q.is_satisfied_by(&[v1.clone(), v2.clone(), v3.clone()]));
        assert!(!q.is_satisfied_by(&[v1.clone()]));
        assert!(!q.is_satisfied_by(&[]));
    }

    #[test]
    fn quorum_only_counts_eligible_verifiers() {
        let v1 = verifier(1);
        let v2 = verifier(2);
        let outsider = verifier(99);
        let q = QuorumSpec::new(vec![v1.clone(), v2.clone()], 2).unwrap();

        // outsider's approval does not count
        assert!(!q.is_satisfied_by(&[v1.clone(), outsider]));
    }

    #[test]
    fn nonce_random_is_unique() {
        let a = Nonce::random();
        let b = Nonce::random();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn timestamp_expiry() {
        let t = UnixTimestamp(1000);
        assert!(t.has_expired(UnixTimestamp(1001)));
        assert!(!t.has_expired(UnixTimestamp(1000)));
        assert!(!t.has_expired(UnixTimestamp(999)));
    }
}
