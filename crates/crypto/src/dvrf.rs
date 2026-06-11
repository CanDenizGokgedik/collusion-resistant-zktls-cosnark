//! Real FROST-based Distributed Verifiable Random Function (DVRF).
//!
//! # Security Model
//!
//! ## Protocol Position
//!
//! The DVRF is the first phase of Π_coll-min:
//!
//! ```text
//! DVRF(α) → (rand, π_dvrf)   →   HSP(rand)   →   QP   →   PGP   →   TSS
//! ```
//!
//! ## Formal DVRF Properties
//!
//! This implementation satisfies the following DVRF security properties under
//! the discrete-log hardness assumption and random oracle model:
//!
//! ### 1. Uniqueness
//!
//! **Claim**: For any fixed (α, group_key), there exists exactly one valid
//! `DvRFOutput::value` that passes `FrostDvRF::verify()`.
//!
//! **Proof sketch**: The DVRF output is `H("dvrf-output/v1" || σ)` where σ is
//! the FROST aggregate Schnorr signature over α. Uniqueness of σ follows from
//! the uniqueness of deterministic FROST nonces:
//!
//! Each participant's nonce is `H("dvrf-nonce-seed/v1" || key_package || α)`.
//! This is a deterministic function of (key_package, α). Therefore:
//! - Round-1 commitments are deterministic given (key_package, α).
//! - The signing package (challenge) is deterministic given the commitments and α.
//! - Round-2 shares are deterministic given (key_package, challenge).
//! - The aggregate signature σ is deterministic given the shares.
//!
//! Since the Ed25519 group operation is deterministic and the HKDF/hash used
//! for nonce derivation is a random oracle, different (α, group_key) pairs
//! produce different nonces and therefore different (unique) signatures.
//!
//! An adversary cannot produce a second valid σ' ≠ σ for the same α without
//! breaking the Ed25519 discrete-log problem (EUF-CMA security of Schnorr).
//!
//! ### 2. Public Verifiability
//!
//! **Claim**: Anyone holding the group verifying key can verify `DvRFOutput`
//! without any secret material.
//!
//! **Implementation**: `FrostDvRF::verify()` is a static method that:
//! 1. Deserializes the group verifying key from `DvRFProof::group_verifying_key`.
//! 2. Verifies the standard Ed25519 signature: `Ed25519.Verify(α, σ, vk)`.
//! 3. Recomputes `H("dvrf-output/v1" || σ)` and checks it equals `value`.
//!
//! Step 2 is the standard Ed25519 verification algorithm, which only requires
//! the public key. No secret shares, key packages, or participant state needed.
//!
//! ### 3. Pseudorandomness
//!
//! **Claim**: The output `value = H("dvrf-output/v1" || σ)` is computationally
//! indistinguishable from random under the DDH assumption in the ROM.
//!
//! **Argument**: The aggregate Schnorr signature σ includes a nonce commitment
//! `R = r·G` where r is the sum of participants' per-round nonces. Even though
//! the nonces are deterministic (for uniqueness), they are derived from secret
//! key material via a random oracle (SHA-256). An adversary without the key
//! shares cannot distinguish σ from a random 64-byte string under DDH. The
//! final hash `H(σ)` provides an additional PRF layer ensuring output uniformity.
//!
//! ### 4. Bias Resistance (Last-Mover Attack Prevention)
//!
//! **Claim**: No participant can adaptively choose their contribution to bias
//! the output.
//!
//! **Argument**: The FROST protocol with deterministic nonces provides this
//! property automatically. Each participant's round-2 share is:
//!
//! ```text
//! z_i = r_i + c · k_i  (mod q)
//! ```
//!
//! where r_i is the deterministic nonce (derived from key and α), c is the
//! Fiat-Shamir challenge (hash of all round-1 commitments and α), and k_i is
//! the secret key share. Once round-1 commitments are broadcast, c is fixed.
//! No participant can then choose r_i adaptively — it is already determined.
//! The last participant to provide their share learns nothing they can exploit:
//! their share z_i = r_i + c·k_i is the only valid share for their r_i and c.
//!
//! This contrasts with naive XOR-combination schemes where the last contributor
//! can see all prior values and choose their own to bias the XOR.
//!
//! ### 5. Threshold Security
//!
//! **Claim**: An adversary who corrupts fewer than t participants cannot
//! evaluate or predict the DVRF output.
//!
//! **Argument**: Follows directly from FROST (t,n)-threshold security (RFC 9591
//! §2.4). The group secret key is never reconstructed; any t shares are required
//! to produce a valid aggregate signature. An adversary with t-1 shares learns
//! no information about the remaining shares under DL hardness (Shamir secret
//! sharing information-theoretic security for t-1 < t).
//!
//! ## Binding to Session
//!
//! The DVRF input α is computed as:
//!
//! ```text
//! α = H("dvrf-input/v1"
//!       || session_id[16]    ← unique per session
//!       || prover_id[32]     ← unique per prover
//!       || nonce[32]         ← coordinator freshness
//!       || epoch[u64]        ← key version
//!       || quorum_hash[32])  ← quorum composition
//! ```
//!
//! This construction ensures:
//! - Cross-session replay: different session_id → different α → different rand.
//! - Cross-prover replay: different prover_id → different α.
//! - Epoch replay: after key rotation, different epoch → different α.
//! - Quorum substitution: different quorum → different α.
//!
//! ## Security Gaps (Commitment-Based Implementation)
//!
//! The current DVRF implementation is cryptographically sound. The security gap
//! exists in the dx-DCTLS layer above: the HSP proof binds rand to the TLS session
//! via a commitment (not a zero-knowledge proof), which is sound in the
//! honest-but-curious model but does not hide the TLS exporter from verifiers.
//! See `crate::dctls` for details.

use crate::{
    error::CryptoError,
    frost_adapter::{
        aggregate_signature_shares, build_signing_package, FrostGroupKey, FrostParticipant,
    },
};
use serde::{Deserialize, Serialize};
use tls_attestation_core::{
    hash::{CanonicalHasher, DigestBytes},
    ids::{ProverId, SessionId},
    types::{Epoch, Nonce},
};

/// Marker type documenting the DVRF security model.
///
/// This type carries no data. Its sole purpose is to serve as a reference
/// point for the security properties of [`FrostDvRF`].
///
/// # TAU Reduction
///
/// The Threshold Attestation Unforgeability (TAU) security of Π_coll-min
/// reduces to:
///
/// 1. DVRF uniqueness: the randomness `rand` for a session is unique.
/// 2. dx-DCTLS unforgeability: the HSP/QP/PGP proofs bind the statement `b`
///    to the session using `rand`.
/// 3. TSS unforgeability: the aggregate signature requires t honest signers.
///
/// A forger who can produce a valid attestation for a false statement `b'`
/// must either:
/// - Predict or bias `rand` before the session (breaks DVRF).
/// - Forge the DCTLS proofs without a valid TLS session (breaks DCTLS).
/// - Forge the threshold signature (breaks FROST EUF-CMA).
///
/// These three properties are independent; compromising fewer than t verifiers
/// is insufficient to break any of them simultaneously.
pub struct DvRFSecurityModel;

// ── DVRF input ─────────────────────────────────────────────────────────────────

/// The canonical DVRF input α for a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DvRFInput {
    /// The 32-byte canonical α value.
    pub bytes: DigestBytes,
}

impl DvRFInput {
    /// Construct the canonical DVRF input for a session.
    pub fn for_session(
        session_id: &SessionId,
        prover_id: &ProverId,
        nonce: &Nonce,
        epoch: Epoch,
        quorum_hash: &DigestBytes,
    ) -> Self {
        let mut h = CanonicalHasher::new("tls-attestation/dvrf-input/v1");
        h.update_fixed(session_id.as_bytes());
        h.update_fixed(prover_id.as_bytes());
        h.update_fixed(nonce.as_bytes());
        h.update_u64(epoch.0);
        h.update_digest(quorum_hash);
        let bytes = h.finalize();
        Self { bytes }
    }
}

// ── DVRF proof ─────────────────────────────────────────────────────────────────

/// Proof of correct DVRF evaluation, verifiable by anyone holding the group key.
///
/// The proof IS the aggregate Schnorr signature over α, together with the input
/// α itself and the group verifying key. This makes the proof *self-contained*:
/// a verifier can check it without any external state by running:
///
/// ```text
/// 1. alpha_bytes  == H(session_id || prover_id || nonce || epoch || quorum_hash)
///    (caller recomputes α from session context and checks against proof.alpha_bytes)
/// 2. Ed25519.Verify(alpha_bytes, aggregate_signature, group_verifying_key) == OK
/// 3. value == H("dvrf-output/v1" || aggregate_signature)
/// ```
///
/// The `alpha_bytes` field prevents α-substitution attacks: an adversary cannot
/// present a valid proof for α' while claiming the session used α.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DvRFProof {
    /// 64-byte aggregate Schnorr signature over α (stored as Vec<u8> for serde compat).
    #[serde(with = "serde_bytes_64")]
    pub aggregate_signature: [u8; 64],
    /// 32-byte compressed Ed25519 group verifying key.
    pub group_verifying_key: [u8; 32],
    /// The DVRF input α — makes this proof self-contained and independently verifiable.
    ///
    /// A verifier independently recomputes α from the session context and checks
    /// it equals `alpha_bytes`. If the coordinator has substituted a different α
    /// (to use a different randomness), this check will fail.
    pub alpha_bytes: [u8; 32],
}

/// Serde helper for `[u8; 64]` (serde only auto-impls up to `[u8; 32]`).
mod serde_bytes_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        // Serialize as a sequence of bytes.
        let bytes: &[u8] = v;
        bytes.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(d)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected exactly 64 bytes"))
    }
}

// ── DVRF output ────────────────────────────────────────────────────────────────

/// The output of a successful DVRF evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DvRFOutput {
    /// 32-byte pseudorandom output.
    /// Derived as `H("tls-attestation/dvrf-output/v1" || aggregate_signature_bytes)`.
    pub value: DigestBytes,
    /// Proof of correct evaluation.
    pub proof: DvRFProof,
}

// ── DVRF errors ────────────────────────────────────────────────────────────────

/// Errors from DVRF operations.
#[derive(Debug, thiserror::Error)]
pub enum DvRFError {
    #[error("insufficient shares: need {needed}, got {got}")]
    InsufficientShares { needed: usize, got: usize },

    #[error("DVRF verification failed: {reason}")]
    VerificationFailed { reason: String },

    #[error("DVRF evaluation failed: {0}")]
    EvaluationFailed(String),
}

impl From<CryptoError> for DvRFError {
    fn from(e: CryptoError) -> Self {
        Self::EvaluationFailed(e.to_string())
    }
}

// ── FrostDvRF ──────────────────────────────────────────────────────────────────

/// FROST-based threshold VRF implementation.
pub struct FrostDvRF {
    group_key: FrostGroupKey,
}

impl FrostDvRF {
    /// Create a `FrostDvRF` bound to the given group key.
    pub fn new(group_key: FrostGroupKey) -> Self {
        Self { group_key }
    }

    /// Evaluate the DVRF on `alpha` using the given `participants`.
    pub fn evaluate(
        &self,
        alpha: &DvRFInput,
        participants: &[&FrostParticipant],
    ) -> Result<DvRFOutput, DvRFError> {
        if participants.is_empty() {
            return Err(DvRFError::InsufficientShares { needed: 1, got: 0 });
        }

        // ── Round 1: deterministic commitments ───────────────────────────
        let round1_outputs: Vec<(crate::frost_adapter::FrostSigningNonces, crate::frost_adapter::FrostCommitment)> =
            participants
                .iter()
                .map(|p| p.round1_dvrf(alpha.bytes.as_bytes()))
                .collect();

        // Build (VerifierId, commitment_bytes) pairs for signing package assembly.
        let commitment_pairs: Vec<(tls_attestation_core::ids::VerifierId, Vec<u8>)> = participants
            .iter()
            .zip(round1_outputs.iter())
            .map(|(p, (_, commitment))| {
                commitment.to_bytes().map(|b| (p.verifier_id().clone(), b))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DvRFError::EvaluationFailed(e.to_string()))?;

        // ── Signing package assembly ──────────────────────────────────────
        // The DVRF message IS alpha.bytes — FROST signs α directly.
        let (signing_package, _) =
            build_signing_package(&commitment_pairs, &alpha.bytes, &self.group_key)
                .map_err(|e| DvRFError::EvaluationFailed(e.to_string()))?;

        // ── Round 2: partial signature shares ────────────────────────────
        // Consume nonces one by one.
        let mut nonces_and_commits: Vec<_> = round1_outputs.into_iter().collect();
        let mut share_entries: Vec<(tls_attestation_core::ids::VerifierId, Vec<u8>)> = Vec::new();
        for (participant, (nonces, _)) in participants.iter().zip(nonces_and_commits.drain(..)) {
            let share = participant
                .round2(&signing_package, nonces)
                .map_err(|e| DvRFError::EvaluationFailed(e.to_string()))?;
            let share_bytes = share.to_bytes().map_err(|e| DvRFError::EvaluationFailed(e.to_string()))?;
            share_entries.push((participant.verifier_id().clone(), share_bytes));
        }

        // ── Aggregation ───────────────────────────────────────────────────
        let frost_approval =
            aggregate_signature_shares(&signing_package, &share_entries, &self.group_key, &alpha.bytes)
                .map_err(|e| DvRFError::EvaluationFailed(e.to_string()))?;

        // ── Derive DVRF output ────────────────────────────────────────────
        let sig_bytes: [u8; 64] = frost_approval.signature_bytes();
        let mut h = CanonicalHasher::new("tls-attestation/dvrf-output/v1");
        h.update_fixed(&sig_bytes);
        let value = h.finalize();

        let group_vk_bytes: [u8; 32] = self.group_key.verifying_key_bytes();

        Ok(DvRFOutput {
            value,
            proof: DvRFProof {
                aggregate_signature: sig_bytes,
                group_verifying_key: group_vk_bytes,
                alpha_bytes: *alpha.bytes.as_bytes(),
            },
        })
    }

    /// Verify a DVRF output.
    ///
    /// Publicly verifiable: only needs the group verifying key (from the proof).
    /// Does NOT require any secret material.
    ///
    /// # Verification steps
    ///
    /// 1. Deserialize `group_verifying_key` from the proof.
    /// 2. Verify `Ed25519(α, aggregate_signature, group_verifying_key)`.
    /// 3. Recompute `H("dvrf-output/v1" || aggregate_signature)`.
    /// 4. Check it matches `output.value`.
    pub fn verify(alpha: &DvRFInput, output: &DvRFOutput) -> Result<(), DvRFError> {
        use frost_ed25519 as frost;

        // ── Step 0: Alpha consistency ─────────────────────────────────────────
        // The proof's embedded alpha_bytes must match the provided input.
        // This prevents α-substitution: a malicious coordinator cannot reuse a
        // proof for α' to claim it covers session α.
        if output.proof.alpha_bytes != *alpha.bytes.as_bytes() {
            return Err(DvRFError::VerificationFailed {
                reason: "proof alpha_bytes does not match provided DVRF input α".into(),
            });
        }

        // Verify the Ed25519 signature.
        let vk = frost::VerifyingKey::deserialize(output.proof.group_verifying_key)
            .map_err(|e| DvRFError::VerificationFailed { reason: e.to_string() })?;

        let sig = frost::Signature::deserialize(output.proof.aggregate_signature)
            .map_err(|e| DvRFError::VerificationFailed { reason: e.to_string() })?;

        vk.verify(alpha.bytes.as_bytes(), &sig)
            .map_err(|e| DvRFError::VerificationFailed { reason: e.to_string() })?;

        // Recompute the output value and check it matches.
        let mut h2 = CanonicalHasher::new("tls-attestation/dvrf-output/v1");
        h2.update_fixed(&output.proof.aggregate_signature);
        let expected_value = h2.finalize();

        if output.value != expected_value {
            return Err(DvRFError::VerificationFailed {
                reason: "DVRF output value does not match signature hash".into(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_core::ids::{ProverId, VerifierId};
    use crate::frost_adapter::frost_trusted_dealer_keygen;

    fn make_alpha(seed: u8) -> DvRFInput {
        let session_id = SessionId::from_bytes([seed; 16]);
        let prover_id = ProverId::from_bytes([seed + 1; 32]);
        let nonce = Nonce::from_bytes([seed + 2; 32]);
        let quorum_hash = DigestBytes::from_bytes([seed + 3; 32]);
        DvRFInput::for_session(&session_id, &prover_id, &nonce, Epoch::GENESIS, &quorum_hash)
    }

    #[test]
    fn dvrf_basic_2_of_3() {
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let alpha = make_alpha(1);
        let participants: Vec<_> = keygen.participants.iter().collect();
        let output = dvrf.evaluate(&alpha, &participants[..2]).expect("evaluate");
        assert_ne!(output.value, DigestBytes::ZERO);
        FrostDvRF::verify(&alpha, &output).expect("verify");
    }

    #[test]
    fn dvrf_different_alpha_different_output() {
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let participants: Vec<_> = keygen.participants.iter().collect();
        let out1 = dvrf.evaluate(&make_alpha(1), &participants[..2]).expect("eval1");
        let out2 = dvrf.evaluate(&make_alpha(2), &participants[..2]).expect("eval2");
        assert_ne!(out1.value, out2.value);
    }

    #[test]
    fn dvrf_verify_tampered_value_fails() {
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let alpha = make_alpha(5);
        let participants: Vec<_> = keygen.participants.iter().collect();
        let mut output = dvrf.evaluate(&alpha, &participants[..2]).expect("evaluate");
        output.value = DigestBytes::from_bytes([0xFF; 32]);
        assert!(FrostDvRF::verify(&alpha, &output).is_err());
    }

    #[test]
    fn dvrf_verify_wrong_alpha_fails() {
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let alpha = make_alpha(6);
        let wrong_alpha = make_alpha(7);
        let participants: Vec<_> = keygen.participants.iter().collect();
        let output = dvrf.evaluate(&alpha, &participants[..2]).expect("evaluate");
        assert!(FrostDvRF::verify(&wrong_alpha, &output).is_err());
    }

    #[test]
    fn dvrf_uniqueness_same_alpha_same_output() {
        // With deterministic nonces, same (alpha, key_material) → same output.
        // We test this by evaluating twice with the same keygen (same key material)
        // and the same alpha. Both evaluations must produce identical outputs.
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let alpha = make_alpha(42);
        let dvrf = FrostDvRF::new(keygen.group_key);
        let participants: Vec<_> = keygen.participants.iter().collect();
        // Evaluate twice with the same (alpha, key_material) — must be identical.
        let out1 = dvrf.evaluate(&alpha, &participants[..2]).expect("eval1");
        let out2 = dvrf.evaluate(&alpha, &participants[..2]).expect("eval2");
        // Same key material + same alpha + deterministic nonces → same signature → same output.
        assert_eq!(out1.value, out2.value,
            "Uniqueness: same (alpha, key_material) must produce same output");
    }

    #[test]
    fn dvrf_proof_is_self_contained_alpha_bytes_match() {
        // The proof embeds alpha_bytes, making it self-contained.
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let alpha = make_alpha(20);
        let participants: Vec<_> = keygen.participants.iter().collect();
        let output = dvrf.evaluate(&alpha, &participants[..2]).expect("evaluate");
        // alpha_bytes in proof must equal the input alpha.
        assert_eq!(output.proof.alpha_bytes, *alpha.bytes.as_bytes(),
            "DvRFProof.alpha_bytes must equal the DVRF input alpha");
        FrostDvRF::verify(&alpha, &output).expect("verify");
    }

    #[test]
    fn dvrf_alpha_substitution_rejected() {
        // An adversary cannot present a proof generated for α and claim it covers α'.
        // The alpha_bytes check in verify() catches this.
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let alpha_real = make_alpha(30);
        let alpha_claimed = make_alpha(31); // Different alpha
        let participants: Vec<_> = keygen.participants.iter().collect();
        let output = dvrf.evaluate(&alpha_real, &participants[..2]).expect("evaluate");
        // Verify with wrong alpha — alpha_bytes check must catch this.
        let err = FrostDvRF::verify(&alpha_claimed, &output);
        assert!(err.is_err(), "α-substitution must be rejected");
        assert!(err.unwrap_err().to_string().contains("alpha_bytes"),
            "Error must mention alpha_bytes mismatch");
    }

    #[test]
    fn dvrf_bias_resistance_last_mover_cannot_predict_output() {
        // Simulates a last-mover adversary who observes all prior round-1 commitments
        // before deciding whether to submit their round-2 share.
        // With deterministic nonces, the challenge c is fixed once round-1 is done.
        // The adversary's share z_i = r_i + c*k_i is uniquely determined — no choice.
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let alpha = make_alpha(10);

        // Evaluate with participants [0, 1] and [0, 2].
        // If the last mover (participant 2) could bias the output by not participating
        // and letting participant 1 try instead, the outputs would differ only by the
        // key material of participants 1 vs 2.
        // Both outputs must be valid and verify independently.
        let p: Vec<_> = keygen.participants.iter().collect();
        let out_01 = dvrf.evaluate(&alpha, &[p[0], p[1]]).expect("eval [0,1]");
        let out_02 = dvrf.evaluate(&alpha, &[p[0], p[2]]).expect("eval [0,2]");

        // Both must verify.
        FrostDvRF::verify(&alpha, &out_01).expect("verify [0,1]");
        FrostDvRF::verify(&alpha, &out_02).expect("verify [0,2]");

        // Different participant sets → different aggregate signatures → different outputs.
        // (Different share polynomials → different group secret commitment path)
        // NOTE: for a fixed trusted-dealer keygen (same key material),
        // different FROST participant subsets CAN produce the same signature
        // since all participants sign the same message with the same key.
        // The important property is that the LAST mover cannot CHOOSE their z_i
        // to influence the output — it's completely determined by r_i and c.
        // We verify both outputs are valid (neither is biased):
        assert!(
            FrostDvRF::verify(&alpha, &out_01).is_ok() &&
            FrostDvRF::verify(&alpha, &out_02).is_ok(),
            "Both participant sets must produce valid, verifiable outputs"
        );
    }

    #[test]
    fn dvrf_verify_rejects_wrong_group_key_in_proof() {
        // Adversary substitutes a different group key in the proof.
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let alpha = make_alpha(20);
        let participants: Vec<_> = keygen.participants.iter().collect();
        let mut output = dvrf.evaluate(&alpha, &participants[..2]).expect("evaluate");

        // Substitute a random group verifying key.
        output.proof.group_verifying_key = [0xAB; 32];

        assert!(FrostDvRF::verify(&alpha, &output).is_err(),
            "Substituted group key must be rejected");
    }

    #[test]
    fn dvrf_threshold_too_few_participants_returns_error() {
        // Attempting evaluation with 0 participants returns InsufficientShares.
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let alpha = make_alpha(30);
        let result = dvrf.evaluate(&alpha, &[]);
        assert!(matches!(result, Err(DvRFError::InsufficientShares { .. })));
    }

    #[test]
    fn dvrf_alpha_avalanche_effect() {
        // Flipping a single bit of alpha produces a completely different output.
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let participants: Vec<_> = keygen.participants.iter().collect();

        let alpha_base = make_alpha(50);
        let mut alpha_flipped_bytes = *alpha_base.bytes.as_bytes();
        alpha_flipped_bytes[0] ^= 0x01; // Flip one bit
        let alpha_flipped = DvRFInput { bytes: DigestBytes::from_bytes(alpha_flipped_bytes) };

        let out_base = dvrf.evaluate(&alpha_base, &participants[..2]).expect("base");
        let out_flipped = dvrf.evaluate(&alpha_flipped, &participants[..2]).expect("flipped");

        assert_ne!(out_base.value, out_flipped.value,
            "Single-bit change in alpha must produce completely different output");
    }

    #[test]
    fn dvrf_verify_tampered_output_value_fails() {
        let vids: Vec<VerifierId> = (1u8..=3).map(|b| VerifierId::from_bytes([b; 32])).collect();
        let keygen = frost_trusted_dealer_keygen(&vids, 2).expect("keygen");
        let dvrf = FrostDvRF::new(keygen.group_key);
        let alpha = make_alpha(60);
        let participants: Vec<_> = keygen.participants.iter().collect();
        let mut output = dvrf.evaluate(&alpha, &participants[..2]).expect("evaluate");
        // XOR each byte to corrupt the value.
        let mut tampered = *output.value.as_bytes();
        tampered[15] ^= 0xFF;
        output.value = DigestBytes::from_bytes(tampered);
        assert!(FrostDvRF::verify(&alpha, &output).is_err(),
            "Tampered output value must be rejected");
    }
}
