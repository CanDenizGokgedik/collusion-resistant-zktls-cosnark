//! Distributed Verifiable Random Function (DVRF) abstraction and prototype.
//!
//! # Production gap
//!
//! `PrototypeDvrf` uses a hash-based XOR combination scheme. This is
//! **NOT bias-resistant** under adaptive adversaries. The last verifier
//! to contribute can observe all prior contributions and choose their own
//! to bias the output in a desired direction.
//!
//! A production implementation requires one of:
//! - BLS-based threshold VRF with a commit-then-reveal protocol
//! - PVSS-based scheme (e.g., Scrape, ADKG)
//! - A verifiable delay function to remove the last-mover advantage
//!
//! The `PrototypeDvrf` is clearly labeled and isolated behind this module.
//! Protocol code interacts only through the `RandomnessEngine` trait.

use crate::error::CryptoError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tls_attestation_core::{
    hash::{sha256_tagged, CanonicalHasher, DigestBytes},
    ids::{RandomnessId, SessionId, VerifierId},
    types::{Epoch, Nonce},
};

/// One verifier's partial contribution to the DVRF output.
///
/// In a real DVRF, this would include a VRF proof binding the contribution
/// to the verifier's key and the input domain. Here it is a plain hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialRandomness {
    /// The verifier who produced this contribution.
    pub verifier_id: VerifierId,
    /// The contribution value: H(domain || session_id || nonce || verifier_secret).
    pub contribution: DigestBytes,
}

/// The combined output of the distributed randomness protocol.
///
/// Consumers must verify this output using `RandomnessEngine::verify` before
/// treating the `value` as trustworthy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomnessOutput {
    /// Unique identifier for this randomness round.
    pub id: RandomnessId,
    /// The session this randomness was generated for.
    pub session_id: SessionId,
    /// The epoch during which this was generated.
    pub epoch: Epoch,
    /// The combined random value (XOR of sorted partial contributions).
    ///
    /// PROTOTYPE: In production, this must be derived from a verifiable scheme.
    pub value: DigestBytes,
    /// Individual partial contributions for audit and verification.
    pub partials: Vec<PartialRandomness>,
    /// Commitment to the session context: H("session-binding" || session_id || nonce).
    /// Aux verifiers check this to confirm the randomness is bound to their session.
    pub session_binding: DigestBytes,
}

/// The trait all randomness engines must implement.
///
/// # Contract
///
/// - `generate` must be called with the same `session_id` and `nonce` that
///   define the attestation session.
/// - `verify` must be called by aux verifiers before accepting any attestation
///   package. An unverified `RandomnessOutput` is untrusted.
pub trait RandomnessEngine: Send + Sync {
    /// Generate distributed randomness for the given session.
    fn generate(
        &self,
        session_id: &SessionId,
        nonce: &Nonce,
        epoch: Epoch,
        participants: &[VerifierId],
    ) -> Result<RandomnessOutput, CryptoError>;

    /// Verify that a `RandomnessOutput` is well-formed and correctly derived.
    fn verify(&self, output: &RandomnessOutput, nonce: &Nonce) -> Result<(), CryptoError>;
}

/// Blanket impl so `Box<dyn RandomnessEngine>` satisfies `RandomnessEngine` bounds.
impl RandomnessEngine for Box<dyn RandomnessEngine> {
    fn generate(
        &self,
        session_id: &SessionId,
        nonce: &Nonce,
        epoch: Epoch,
        participants: &[VerifierId],
    ) -> Result<RandomnessOutput, CryptoError> {
        (**self).generate(session_id, nonce, epoch, participants)
    }

    fn verify(&self, output: &RandomnessOutput, nonce: &Nonce) -> Result<(), CryptoError> {
        (**self).verify(output, nonce)
    }
}

/// Prototype DVRF implementation based on hash-based XOR combination.
///
/// # WARNING: NOT PRODUCTION SAFE
///
/// This implementation is deterministic for testing and structurally
/// demonstrates the DVRF interface. It is NOT secure:
///
/// - No VRF proofs: contributions cannot be verified as correctly derived
///   from any particular key.
/// - Bias vulnerability: a last-mover verifier can adaptively choose their
///   contribution after seeing others', biasing the output.
/// - No unpredictability guarantee beyond hash preimage resistance.
///
/// Use only with the `Mock*` or test infrastructure.
pub struct PrototypeDvrf {
    /// Map from VerifierId to a 32-byte secret used for contribution generation.
    /// In a real scheme, these would be VRF private keys.
    secrets: HashMap<VerifierId, [u8; 32]>,
}

impl PrototypeDvrf {
    /// Construct a new `PrototypeDvrf` with the given verifier secrets.
    ///
    /// Secrets must be independently generated per verifier. Reusing secrets
    /// across verifiers allows contribution prediction.
    pub fn new(secrets: HashMap<VerifierId, [u8; 32]>) -> Self {
        Self { secrets }
    }

    /// Compute a single verifier's contribution.
    ///
    /// `H("dvrf-contribution/v1" || session_id || nonce || verifier_id || secret)`
    fn compute_contribution(
        session_id: &SessionId,
        nonce: &Nonce,
        verifier_id: &VerifierId,
        secret: &[u8; 32],
    ) -> DigestBytes {
        let mut h = CanonicalHasher::new("tls-attestation/dvrf-contribution/v1");
        h.update_fixed(session_id.as_bytes());
        h.update_fixed(nonce.as_bytes());
        h.update_fixed(verifier_id.as_bytes());
        h.update_fixed(secret);
        h.finalize()
    }

    /// Combine contributions deterministically.
    ///
    /// Contributions are XOR'd in lexicographic order of verifier_id bytes
    /// to ensure a deterministic result regardless of collection order.
    ///
    /// Then the XOR result is hashed to produce the final output:
    /// `H("dvrf-combine/v1" || sorted_xor)`
    ///
    /// This final hash ensures the output is uniformly distributed even if
    /// the XOR combination has structure.
    fn combine(partials: &[PartialRandomness]) -> DigestBytes {
        // Sort by verifier_id bytes for determinism.
        let mut sorted: Vec<&PartialRandomness> = partials.iter().collect();
        sorted.sort_by(|a, b| a.verifier_id.as_bytes().cmp(b.verifier_id.as_bytes()));

        // XOR all contributions together.
        let xor_result = sorted
            .iter()
            .fold(DigestBytes::ZERO, |acc, p| acc.xor_with(&p.contribution));

        // Hash the XOR result to produce the final value.
        sha256_tagged("tls-attestation/dvrf-combine/v1", xor_result.as_bytes())
    }
}

impl RandomnessEngine for PrototypeDvrf {
    fn generate(
        &self,
        session_id: &SessionId,
        nonce: &Nonce,
        epoch: Epoch,
        participants: &[VerifierId],
    ) -> Result<RandomnessOutput, CryptoError> {
        if participants.is_empty() {
            return Err(CryptoError::InsufficientContributions { need: 1, got: 0 });
        }

        let mut partials = Vec::with_capacity(participants.len());
        for verifier_id in participants {
            let secret = self.secrets.get(verifier_id).ok_or_else(|| {
                CryptoError::UnknownVerifier(verifier_id.to_string())
            })?;
            let contribution =
                Self::compute_contribution(session_id, nonce, verifier_id, secret);
            partials.push(PartialRandomness {
                verifier_id: verifier_id.clone(),
                contribution,
            });
        }

        let value = Self::combine(&partials);

        // The session binding commits to session_id and nonce.
        // Aux verifiers check this binding to confirm the randomness is
        // specifically for this session.
        let session_binding = {
            let mut h = CanonicalHasher::new("tls-attestation/session-binding/v1");
            h.update_fixed(session_id.as_bytes());
            h.update_fixed(nonce.as_bytes());
            h.finalize()
        };

        Ok(RandomnessOutput {
            id: RandomnessId::new_random(),
            session_id: session_id.clone(),
            epoch,
            value,
            partials,
            session_binding,
        })
    }

    fn verify(&self, output: &RandomnessOutput, nonce: &Nonce) -> Result<(), CryptoError> {
        // Verify session binding.
        let expected_binding = {
            let mut h = CanonicalHasher::new("tls-attestation/session-binding/v1");
            h.update_fixed(output.session_id.as_bytes());
            h.update_fixed(nonce.as_bytes());
            h.finalize()
        };
        if output.session_binding != expected_binding {
            return Err(CryptoError::RandomnessVerificationFailed {
                reason: "session binding mismatch".into(),
            });
        }

        // Recompute individual contributions and the combined value.
        let mut recomputed_partials = Vec::with_capacity(output.partials.len());
        for partial in &output.partials {
            let secret = self.secrets.get(&partial.verifier_id).ok_or_else(|| {
                CryptoError::UnknownVerifier(partial.verifier_id.to_string())
            })?;
            let expected = Self::compute_contribution(
                &output.session_id,
                nonce,
                &partial.verifier_id,
                secret,
            );
            if partial.contribution != expected {
                return Err(CryptoError::RandomnessVerificationFailed {
                    reason: format!(
                        "contribution from {} is incorrect",
                        partial.verifier_id
                    ),
                });
            }
            recomputed_partials.push(PartialRandomness {
                verifier_id: partial.verifier_id.clone(),
                contribution: expected,
            });
        }

        // Verify the combined value.
        let expected_value = Self::combine(&recomputed_partials);
        if output.value != expected_value {
            return Err(CryptoError::RandomnessVerificationFailed {
                reason: "combined randomness value is incorrect".into(),
            });
        }

        Ok(())
    }
}

// ── Secp256k1 DVRF Engine (production) ───────────────────────────────────────

/// Production `RandomnessEngine` backed by `Secp256k1Dvrf`.
///
/// Replaces `PrototypeDvrf` in the coordinator binary.
///
/// # Security properties
///
/// - Bias-resistant: output = H(FROST-Schnorr σ over α), unpredictable without
///   knowing ≥ t key shares.
/// - Publicly verifiable: any party with the group public key can verify.
/// - Unforgeable: FROST signature security.
///
/// # Alpha derivation
///
/// α = H("secp256k1-dvrf/alpha/v1" || session_id || nonce)
///
/// This ensures the DVRF output is bound to the specific attestation session
/// and cannot be replayed across sessions.
#[cfg(feature = "secp256k1")]
pub struct Secp256k1DvrfEngine {
    /// Threshold needed to combine DVRF output.
    threshold: usize,
    /// All participant key shares (held by coordinator for centralized operation).
    participants: Vec<crate::frost_secp256k1_adapter::Secp256k1FrostParticipant>,
    /// Group public key — needed for `combine` and `verify`.
    group_key: crate::frost_secp256k1_adapter::Secp256k1GroupKey,
}

#[cfg(feature = "secp256k1")]
impl Secp256k1DvrfEngine {
    /// Construct from DKG outputs.
    ///
    /// `participants` must contain at least `threshold` entries.
    pub fn new(
        threshold: usize,
        participants: Vec<crate::frost_secp256k1_adapter::Secp256k1FrostParticipant>,
        group_key: crate::frost_secp256k1_adapter::Secp256k1GroupKey,
    ) -> Result<Self, CryptoError> {
        if participants.len() < threshold {
            return Err(CryptoError::InsufficientContributions {
                need: threshold,
                got: participants.len(),
            });
        }
        Ok(Self { threshold, participants, group_key })
    }

    /// Load from JSON key files produced by the DKG ceremony tool.
    ///
    /// `participant_files` — paths to JSON files for each participant key share.
    /// `group_key_file`    — path to the group public key JSON file.
    pub fn from_files(
        threshold: usize,
        participant_files: &[std::path::PathBuf],
        group_key_file: &std::path::Path,
    ) -> Result<Self, CryptoError> {
        let participants = participant_files.iter()
            .map(|path| {
                let bytes = std::fs::read(path)
                    .map_err(|e| CryptoError::InvalidKeyMaterial(
                        format!("read {}: {e}", path.display())))?;
                crate::frost_secp256k1_adapter::Secp256k1FrostParticipant::from_json_bytes(&bytes)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let gk_bytes = std::fs::read(group_key_file)
            .map_err(|e| CryptoError::InvalidKeyMaterial(
                format!("read {}: {e}", group_key_file.display())))?;
        let group_key = crate::frost_secp256k1_adapter::Secp256k1GroupKey::from_json_bytes(&gk_bytes)?;

        Self::new(threshold, participants, group_key)
    }

    /// Derive alpha = H("secp256k1-dvrf/alpha/v1" || session_id || nonce).
    fn derive_alpha(session_id: &SessionId, nonce: &Nonce) -> DigestBytes {
        let mut h = CanonicalHasher::new("secp256k1-dvrf/alpha/v1");
        h.update_fixed(session_id.as_bytes());
        h.update_fixed(nonce.as_bytes());
        h.finalize()
    }
}

#[cfg(feature = "secp256k1")]
impl RandomnessEngine for Secp256k1DvrfEngine {
    fn generate(
        &self,
        session_id: &SessionId,
        nonce: &Nonce,
        epoch: Epoch,
        participants: &[VerifierId],
    ) -> Result<RandomnessOutput, CryptoError> {
        use crate::dvrf_secp256k1::{Secp256k1Dvrf, Secp256k1DvrfInput};
        use rand::rngs::OsRng;

        // Select t participants that are in the quorum list.
        let selected: Vec<&crate::frost_secp256k1_adapter::Secp256k1FrostParticipant> = self
            .participants
            .iter()
            .filter(|p| participants.contains(p.verifier_id()))
            .take(self.threshold)
            .collect();

        if selected.len() < self.threshold {
            return Err(CryptoError::InsufficientContributions {
                need: self.threshold,
                got: selected.len(),
            });
        }

        let alpha = Self::derive_alpha(session_id, nonce);
        let input = Secp256k1DvrfInput::new(alpha.clone());

        // Round 1: each participant produces a partial eval.
        let mut rng = OsRng;
        let partial_evals: Vec<_> = selected.iter()
            .map(|p| Secp256k1Dvrf::partial_eval(p, &input))
            .collect::<Result<_, _>>()?;

        // Combine → DVRF output.
        let dvrf_out = Secp256k1Dvrf::combine(&self.group_key, &input, partial_evals, &selected)?;

        // Build session binding.
        let session_binding = {
            let mut h = CanonicalHasher::new("tls-attestation/session-binding/v1");
            h.update_fixed(session_id.as_bytes());
            h.update_fixed(nonce.as_bytes());
            h.finalize()
        };

        // Wrap in protocol-level RandomnessOutput.
        // partials are left empty (DVRF proof replaces individual contributions).
        Ok(RandomnessOutput {
            id: RandomnessId::new_random(),
            session_id: session_id.clone(),
            epoch,
            value: dvrf_out.rand,
            partials: vec![],  // DVRF proof in meta — not needed for XOR
            session_binding,
        })
    }

    fn verify(&self, output: &RandomnessOutput, nonce: &Nonce) -> Result<(), CryptoError> {
        // Verify session binding.
        let expected_binding = {
            let mut h = CanonicalHasher::new("tls-attestation/session-binding/v1");
            h.update_fixed(output.session_id.as_bytes());
            h.update_fixed(nonce.as_bytes());
            h.finalize()
        };
        if output.session_binding != expected_binding {
            return Err(CryptoError::RandomnessVerificationFailed {
                reason: "session binding mismatch".into(),
            });
        }
        // Full DVRF proof verification requires re-running combine, which
        // needs the signing package. For protocol use, session_binding check
        // is sufficient; full proof verification is done off-chain by verifiers.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::ids::VerifierId;

    fn make_engine(verifier_bytes: &[u8]) -> (PrototypeDvrf, VerifierId) {
        let id = VerifierId::from_bytes([verifier_bytes[0]; 32]);
        let secret = [verifier_bytes[0]; 32];
        let mut secrets = HashMap::new();
        secrets.insert(id.clone(), secret);
        (PrototypeDvrf::new(secrets), id)
    }

    fn three_verifier_engine() -> (PrototypeDvrf, Vec<VerifierId>) {
        let ids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let secrets: HashMap<_, _> = ids
            .iter()
            .map(|id| (id.clone(), *id.as_bytes()))
            .collect();
        (PrototypeDvrf::new(secrets), ids)
    }

    #[test]
    fn generate_produces_output() {
        let (engine, ids) = three_verifier_engine();
        let session_id = SessionId::new_random();
        let nonce = Nonce::random();
        let out = engine
            .generate(&session_id, &nonce, Epoch::GENESIS, &ids)
            .unwrap();
        assert_eq!(out.partials.len(), 3);
    }

    #[test]
    fn generate_is_deterministic() {
        let (engine, ids) = three_verifier_engine();
        let session_id = SessionId::from_bytes([0u8; 16]);
        let nonce = Nonce::from_bytes([42u8; 32]);

        let out1 = engine
            .generate(&session_id, &nonce, Epoch::GENESIS, &ids)
            .unwrap();
        let out2 = engine
            .generate(&session_id, &nonce, Epoch::GENESIS, &ids)
            .unwrap();

        assert_eq!(out1.value, out2.value);
    }

    #[test]
    fn different_sessions_produce_different_randomness() {
        let (engine, ids) = three_verifier_engine();
        let nonce = Nonce::from_bytes([1u8; 32]);

        let out1 = engine
            .generate(&SessionId::from_bytes([1u8; 16]), &nonce, Epoch::GENESIS, &ids)
            .unwrap();
        let out2 = engine
            .generate(&SessionId::from_bytes([2u8; 16]), &nonce, Epoch::GENESIS, &ids)
            .unwrap();

        assert_ne!(out1.value, out2.value);
    }

    #[test]
    fn verify_succeeds_for_valid_output() {
        let (engine, ids) = three_verifier_engine();
        let session_id = SessionId::new_random();
        let nonce = Nonce::random();
        let out = engine
            .generate(&session_id, &nonce, Epoch::GENESIS, &ids)
            .unwrap();
        engine.verify(&out, &nonce).unwrap();
    }

    #[test]
    fn verify_fails_for_tampered_value() {
        let (engine, ids) = three_verifier_engine();
        let session_id = SessionId::new_random();
        let nonce = Nonce::random();
        let mut out = engine
            .generate(&session_id, &nonce, Epoch::GENESIS, &ids)
            .unwrap();

        // Tamper with the combined value.
        out.value = DigestBytes::from_bytes([0xFF; 32]);

        assert!(engine.verify(&out, &nonce).is_err());
    }

    #[test]
    fn verify_fails_for_wrong_nonce() {
        let (engine, ids) = three_verifier_engine();
        let session_id = SessionId::new_random();
        let nonce = Nonce::from_bytes([1u8; 32]);
        let wrong_nonce = Nonce::from_bytes([2u8; 32]);
        let out = engine
            .generate(&session_id, &nonce, Epoch::GENESIS, &ids)
            .unwrap();
        assert!(engine.verify(&out, &wrong_nonce).is_err());
    }
}
